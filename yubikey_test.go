// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey_test

import (
	"testing"

	"github.com/devfacet/yubikey"
)

func TestCards(t *testing.T) {
	_, err := yubikey.Cards()
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestCardSlots(t *testing.T) {
	cards, err := yubikey.Cards()
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
	for _, card := range cards {
		slotKeys := []string{"82", "9e"}
		cardSlots, err := yubikey.CardSlots([]string{card.Serial()}, slotKeys, nil)
		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
		for _, cardSlot := range cardSlots {
			for _, key := range slotKeys {
				if v := cardSlot[key].Key(); v != key {
					t.Errorf("got %v, want %v", v, key)
				}
			}
		}
	}
}

func TestCardSlot(t *testing.T) {
	cards, err := yubikey.Cards()
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
	for _, card := range cards {
		slotKey := "82"
		cardSlot, err := yubikey.CardSlot(card.Serial(), slotKey, "")
		if err != nil {
			t.Errorf("got %v, want nil", err)
		}
		if cardSlot != nil {
			if v := cardSlot.Key(); v != slotKey {
				t.Errorf("got %v, want %v", v, slotKey)
			}
		}
	}
}
