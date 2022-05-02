// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

// Package yubikey provides PIV smart card interface for YubiKey security keys.
package yubikey

import (
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/piv"
)

var (
	// DefaultPIN holds the default card PIN.
	DefaultPIN = piv.DefaultPIN
	// DefaultPUK holds the default card PUK.
	DefaultPUK = piv.DefaultPUK
	// DefaultManagementKey holds the default card management key.
	DefaultManagementKey = piv.DefaultManagementKey
)

// Cards returns the connected YubiKey smart cards.
func Cards() ([]*Card, error) {
	// Get the card list
	pivCards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("couldn't get the smart card list: %s", err)
	}

	// Iterate over the card list and initialize the card instances
	var cards []*Card
	for _, v := range pivCards {
		card := Card{
			name:   v,
			pin:    DefaultPIN,
			puk:    DefaultPUK,
			manKey: DefaultManagementKey,
		}
		card.keyAuth = piv.KeyAuth{
			PINPrompt: func() (string, error) {
				return card.pin, nil
			},
		}

		// Connect to the smart card and set the card info
		yk, err := piv.Open(card.name)
		if err != nil {
			return nil, fmt.Errorf("couldn't connect to the YubiKey smart card (%s): %s", card.serial, err)
		}
		s, err := yk.Serial()
		if err != nil {
			return nil, fmt.Errorf("couldn't determined the YubiKey serial (%s): %s", card.serial, err)
		}
		card.serial = fmt.Sprintf("%d", s)
		card.version = yk.Version()

		// Check the version
		// Ref: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
		if card.version.Major < 4 || (card.version.Major == 4 && card.version.Minor < 3) {
			return nil, fmt.Errorf("version of the YubiKey (%s) is not supported: %s", card.serial, card.Version())
		}

		// Add it into the list and close the card.
		cards = append(cards, &card)
		yk.Close()
	}

	return cards, nil
}

// CardSlots returns the card slots by the given card serials, slots and pins.
// It doesn't return error if the given serial or slot not found.
func CardSlots(serials, slots, pins []string) (map[string]map[string]*Slot, error) {
	// Get the card list
	cards, err := Cards()
	if err != nil {
		return nil, err
	}

	// Iterate over the given serial numbers
	result := make(map[string]map[string]*Slot)
	for k, serial := range serials {
		// Iterate over the connected cards
		for _, card := range cards {
			if card.Serial() != serial {
				continue
			}
			if result[serial] == nil {
				result[serial] = make(map[string]*Slot)
			}
			// TODO: Check https://github.com/go-piv/piv-go/issues/47
			if k < len(pins) {
				card.SetPIN(pins[k])
			}
			// Get the card slots
			cardSlots, err := card.SlotsByKey(slots)
			if err != nil {
				return nil, err
			}
			// Iterate over the card slots
			for _, slot := range cardSlots {
				result[serial][slot.key] = slot
			}
		}
	}

	return result, nil
}

// CardSlot returns a card slot by the given card serial, slot and pin.
func CardSlot(serial, slot, pin string) (*Slot, error) {
	// Check args
	if serial == "" || slot == "" {
		return nil, errors.New("missing key serial or slot")
	}

	// Get the card slots
	slots, err := CardSlots([]string{serial}, []string{slot}, []string{pin})
	if err != nil {
		return nil, fmt.Errorf("couldn't retrieve slot list: %s", err)
	}
	if len(slots) > 0 {
		for k, v := range slots {
			if k == serial {
				if slot, ok := v[slot]; ok {
					return slot, nil
				}
				break
			}
		}
		return nil, fmt.Errorf("key slot not found: %s:%s", serial, slot)
	}
	return nil, fmt.Errorf("key not found: %s", serial)
}
