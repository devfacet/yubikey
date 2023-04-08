// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

var (
	// ErrInvalidPIN represents an invalid PIN error.
	ErrInvalidPIN = errors.New("invalid PIN")
	// ErrMissingPIN represents a missing PIN error.
	ErrMissingPIN = errors.New("missing PIN")
	// ErrAuthError represents an authentication error.
	ErrAuthError = errors.New("authentication error")
	// ErrAuthBlocked represents an authentication block error.
	ErrAuthBlocked = errors.New("authentication method blocked")

	// slotMap holds the YubiKey slot mapping.
	// Ref:
	// 	https://docs.yubico.com/yesdk/users-manual/application-piv/slots.html
	//	https://developers.yubico.com/PIV/Introduction/Certificate_slots.html
	//	https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32
	slotMap = map[string]piv.Slot{
		"9a": piv.SlotAuthentication,
		"9c": piv.SlotSignature,
		"9d": piv.SlotKeyManagement,
		"9e": piv.SlotCardAuthentication,
		"82": {Key: 0x82, Object: 0x5FC10D},
		"83": {Key: 0x83, Object: 0x5FC10E},
		"84": {Key: 0x84, Object: 0x5FC10F},
		"85": {Key: 0x85, Object: 0x5FC110},
		"86": {Key: 0x86, Object: 0x5FC111},
		"87": {Key: 0x87, Object: 0x5FC112},
		"88": {Key: 0x88, Object: 0x5FC113},
		"89": {Key: 0x89, Object: 0x5FC114},
		"8a": {Key: 0x8a, Object: 0x5FC115},
		"8b": {Key: 0x8b, Object: 0x5FC116},
		"8c": {Key: 0x8c, Object: 0x5FC117},
		"8d": {Key: 0x8d, Object: 0x5FC118},
		"8e": {Key: 0x8e, Object: 0x5FC119},
		"8f": {Key: 0x8f, Object: 0x5FC11A},
		"90": {Key: 0x90, Object: 0x5FC11B},
		"91": {Key: 0x91, Object: 0x5FC11C},
		"92": {Key: 0x92, Object: 0x5FC11D},
		"93": {Key: 0x93, Object: 0x5FC11E},
		"94": {Key: 0x94, Object: 0x5FC11F},
		"95": {Key: 0x95, Object: 0x5FC120},
		//"9b": {Key: 0x9b}, // Management
		//"f9": {Key: 0xf9, Object: 0x5fff01}, // It is not part of the standard.
	}
)

// Slot represents a YubiKey smart card slot.
type Slot struct {
	key            string
	card           *Card
	slot           piv.Slot
	pinPolicy      PINPolicy
	touchPolicy    TouchPolicy
	hasKey         bool
	isGenerated    bool
	isImported     bool
	publicKey      []byte
	publicKeyAlg   Algorithm
	publicKeyECDSA *ecdsa.PublicKey
}

// Key returns the slot key.
func (slot *Slot) Key() string {
	return slot.key
}

// PINPolicy returns the slot PIN policy.
func (slot *Slot) PINPolicy() PINPolicy {
	return slot.pinPolicy
}

// TouchPolicy returns the slot touch policy.
func (slot *Slot) TouchPolicy() TouchPolicy {
	return slot.touchPolicy
}

// HasKey returns whether the slot has a key or not.
func (slot *Slot) HasKey() bool {
	return slot.hasKey
}

// IsGenerated returns whether the slot key is generated (secure) or not.
func (slot *Slot) IsGenerated() bool {
	return slot.isGenerated
}

// IsImported returns whether the slot key is imported (may not be secure) or not.
func (slot *Slot) IsImported() bool {
	return slot.isImported
}

// PublicKey returns the public key of the slot if any.
func (slot *Slot) PublicKey() []byte {
	return slot.publicKey
}

// PublicKeyAlgorithm returns the public key algorithm of the slot.
func (slot *Slot) PublicKeyAlgorithm() Algorithm {
	return slot.publicKeyAlg
}

// SharedKey returns a shared key by the given peer public key (compressed).
func (slot *Slot) SharedKey(peerPublicKey []byte) ([]byte, error) {
	// Check the slot key
	if !slot.hasKey {
		return nil, errors.New("slot has no key")
	}

	// Connect to the smartcard
	openMu.Lock()
	defer openMu.Unlock()
	yk, err := piv.Open(slot.card.name)
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", slot.card.name, err)
	}
	defer yk.Close()

	// Determine the curve
	var curve elliptic.Curve
	switch l := len(peerPublicKey); {
	case l == 33:
		curve = elliptic.P256()
	case l == 49:
		curve = elliptic.P384()
	default:
		return nil, errors.New("unsupported public key")
	}

	// Unmarshal the peer public key and generate the ECDSA public key instance
	x, y := elliptic.UnmarshalCompressed(curve, peerPublicKey)
	if x == nil {
		return nil, errors.New("invalid public key size")
	}
	peerPublicKeyECDSA := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Get private key object
	privateKey, err := yk.PrivateKey(slot.slot, slot.publicKeyECDSA, slot.card.keyAuth)
	if err != nil {
		return nil, fmt.Errorf("couldn't get the slot key (%s): %s", slot.key, err)
	}
	privateKeyECDSA, ok := privateKey.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("slot doesn't have an ECDSA key")
	}

	// Get the shared key
	// PIN and Touch policies are enforced in this call
	sharedKey, err := privateKeyECDSA.SharedKey(&peerPublicKeyECDSA)
	if err != nil {
		if strings.Contains(err.Error(), "63c") {
			// verify pin: smart card error 63c2: verification failed (2 retries remaining)
			// verify pin: smart card error 63c1: verification failed (1 retry remaining)
			return nil, ErrInvalidPIN
		} else if strings.Contains(err.Error(), "6982") {
			// auth challenge: smart card error 6982: security status not satisfied
			return nil, ErrAuthError
		} else if strings.Contains(err.Error(), "6983") {
			// verify pin: smart card error 6983: authentication method blocked
			return nil, ErrAuthBlocked
		} else if strings.Contains(err.Error(), "pin required but wasn't provided") {
			return nil, ErrMissingPIN
		}
		return nil, err
	}

	return sharedKey, nil
}

// GenerateKeyOpts represents the options which can be used for generating a key.
type GenerateKeyOpts struct {
	Overwrite   bool
	Algorithm   Algorithm
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	ManKey      []byte
}

// GenerateKey generates an asymmetric key by the given slot name and options.
func (slot *Slot) GenerateKey(opts GenerateKeyOpts) error {
	if slot == nil || slot.card == nil {
		return errors.New("invalid slot")
	} else if slot.hasKey && !opts.Overwrite {
		return errors.New("slot has already a key")
	}

	// Connect to the smart card
	openMu.Lock()
	defer openMu.Unlock()
	yk, err := piv.Open(slot.card.name)
	if err != nil {
		return fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", slot.card.serial, err)
	}
	defer yk.Close()

	// Generate a key
	manKey := slot.card.manKey
	if len(opts.ManKey) > 0 {
		copy(manKey[:], opts.ManKey)
	}
	_, err = yk.GenerateKey(
		manKey,
		slot.slot,
		piv.Key{
			Algorithm:   opts.Algorithm.piv(),
			PINPolicy:   opts.PINPolicy.piv(),
			TouchPolicy: opts.TouchPolicy.piv(),
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "6982") {
			// auth challenge: smart card error 6982: security status not satisfied
			return ErrAuthError
		}
		return err
	}

	return nil
}
