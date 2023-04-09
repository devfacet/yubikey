// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey_test

import (
	"testing"

	"github.com/devfacet/yubikey"
)

func TestCard(t *testing.T) {
	cards, err := yubikey.Cards()
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
	for _, card := range cards {
		if v := card.Name(); v == "" {
			t.Error("invalid name")
		} else if v := card.Serial(); v == "" {
			t.Error("invalid serial number")
		} else if v := card.Version(); v == "" {
			t.Error("invalid version")
		} else if l := len(card.SlotKeys()); l == 0 {
			t.Error("no slot key found")
		}
		slots, err := card.Slots()
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if l := len(slots); l == 0 {
			t.Error("no slot found")
		}
		if err := card.VerifyPIN(yubikey.DefaultPIN); err != nil {
			t.Errorf("got %v, want nil", err)
		}
		if err := card.Unblock(yubikey.DefaultPUK, yubikey.DefaultPIN); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	}
}
