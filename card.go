// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"sort"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

// Card represents a YubiKey smart card.
// For more information see https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
type Card struct {
	name    string
	serial  string
	version piv.Version
	pin     string
	puk     string
	manKey  [24]byte
	keyAuth piv.KeyAuth
}

// Name returns the card name.
func (card *Card) Name() string {
	return card.name
}

// Serial returns the card serial number.
func (card *Card) Serial() string {
	return card.serial
}

// Version returns the card firmware version.
func (card *Card) Version() string {
	return fmt.Sprintf("%d.%d.%d", card.version.Major, card.version.Minor, card.version.Patch)
}

// SetPIN sets the card pin.
func (card *Card) SetPIN(pin string) {
	card.pin = pin
}

// SetPUK sets the card puk.
func (card *Card) SetPUK(puk string) {
	card.puk = puk
}

// SetManKey sets the management key
func (card *Card) SetManKey(manKey []byte) {
	copy(card.manKey[:], manKey)
}

// SlotKeys returns the card slot keys.
func (card *Card) SlotKeys() []string {
	var slotKeys []string
	for k := range slotMap {
		slotKeys = append(slotKeys, k)
	}
	return slotKeys
}

// Slots returns the card slots.
func (card *Card) Slots() ([]*Slot, error) {
	return card.SlotsByKey(card.SlotKeys())
}

// SlotsByKey returns the card slots by the given slot keys.
func (card *Card) SlotsByKey(slotKeys []string) ([]*Slot, error) {
	openMu.Lock()
	defer openMu.Unlock()

	// Connect to the smart card
	yk, err := piv.Open(card.name)
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", card.serial, err)
	}
	defer yk.Close()

	// Iterate over the slots and initialize the slot instances
	var slots []*Slot
	for _, slotKey := range slotKeys {
		// Check the slot name
		smv, ok := slotMap[slotKey]
		if !ok {
			continue
		}

		// Init the slot instance
		slot := Slot{key: slotKey, card: card, slot: smv}

		// Attest method checks keys which have been generated, not imported
		cert, err := yk.Attest(slot.slot)
		if err != nil {
			if strings.Contains(err.Error(), "data object or application not found") {
				// Certificate method checks imported keys/certificates which may not be secured
				certImp, err := yk.Certificate(slot.slot)
				if err != nil {
					if strings.Contains(err.Error(), "data object or application not found") {
						// No cert found
					} else {
						return nil, fmt.Errorf("couldn't access to the key slot (%s): %s", slotKey, err)
					}
				} else {
					slot.isImported = true
					cert = certImp
				}
			} else {
				return nil, fmt.Errorf("couldn't access to the key slot (%s): %s", slotKey, err)
			}
		} else {
			slot.isGenerated = true
		}
		if cert == nil {
			slots = append(slots, &slot)
			continue
		} else if cert != nil && cert.PublicKey == nil {
			return nil, fmt.Errorf("slot certificate has no public key (%s): %s", slotKey, err)
		}
		slot.hasKey = true

		// Determine the slot PIN and touch policies
		aCert, err := yk.AttestationCertificate()
		if err != nil {
			return nil, fmt.Errorf("couldn't access to the key attestation certificate (%s): %s", slotKey, err)
		}
		sAttestation, err := piv.Verify(aCert, cert)
		if err != nil {
			return nil, fmt.Errorf("couldn't access to the slot attestation (%s): %s", slotKey, err)
		}
		// We could simply cast PIN and touch policies but that would be bad if the upstream ever changes
		switch sAttestation.PINPolicy {
		case piv.PINPolicyAlways:
			slot.pinPolicy = PINPolicyAlways
		case piv.PINPolicyNever:
			slot.pinPolicy = PINPolicyNever
		case piv.PINPolicyOnce:
			slot.pinPolicy = PINPolicyOnce
		}
		switch sAttestation.TouchPolicy {
		case piv.TouchPolicyAlways:
			slot.touchPolicy = TouchPolicyAlways
		case piv.TouchPolicyCached:
			slot.touchPolicy = TouchPolicyCached
		case piv.TouchPolicyNever:
			slot.touchPolicy = TouchPolicyNever
		}

		// Get the private key object
		privateKey, err := yk.PrivateKey(slot.slot, cert.PublicKey, card.keyAuth)
		if err != nil {
			return nil, fmt.Errorf("couldn't get the slot key (%s): %s", slotKey, err)
		}
		privateKeyECDSA, ok := privateKey.(*piv.ECDSAPrivateKey)
		if !ok {
			// For now only ECDSA keys are allowed
			continue
		}
		// Set the public key
		slot.publicKeyECDSA, ok = privateKeyECDSA.Public().(*ecdsa.PublicKey)
		if !ok {
			// This shouldn't happen since private key is checked above
			continue
		}
		slot.publicKey = elliptic.MarshalCompressed(slot.publicKeyECDSA.Curve, slot.publicKeyECDSA.X, slot.publicKeyECDSA.Y)
		switch slot.publicKeyECDSA.Curve {
		case elliptic.P256():
			slot.publicKeyAlg = AlgorithmEC256
		case elliptic.P384():
			slot.publicKeyAlg = AlgorithmEC384
		default:
			slot.publicKeyAlg = AlgorithmUnknown
		}

		slots = append(slots, &slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].key < slots[j].key })

	return slots, nil
}

// VerifyPIN attempts to authenticate against the card with the provided PIN.
func (card *Card) VerifyPIN(pin string) error {
	// Connect to the smart card
	openMu.Lock()
	defer openMu.Unlock()
	yk, err := piv.Open(card.name)
	if err != nil {
		return fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", card.name, err)
	}
	defer yk.Close()

	return yk.VerifyPIN(pin)
}

// Unblock unblocks the PIN, setting it to a new value.
func (card *Card) Unblock(puk, newPIN string) error {
	// Connect to the smart card
	openMu.Lock()
	defer openMu.Unlock()
	yk, err := piv.Open(card.name)
	if err != nil {
		return fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", card.name, err)
	}
	defer yk.Close()

	return yk.Unblock(puk, newPIN)
}
