// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/devfacet/yubikey"
)

func TestSlot(t *testing.T) {
	cards, err := yubikey.Cards()
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
	for _, card := range cards {
		slots, err := card.SlotsByKey([]string{"82", "9e"})
		if err != nil {
			t.Errorf("got %v, want nil", err)
		} else if len(slots) == 0 {
			t.Error("no slot found")
		}
		for _, slot := range slots {
			if !slot.HasKey() {
				continue
			}
			if v := slot.Key(); v == "" {
				t.Errorf("got %v, want a slot key", v)
			}
			if v := slot.PINPolicy(); v == yubikey.PINPolicyUnknown {
				t.Errorf("got %v, want a known pin policy", v)
			}
			if v := slot.TouchPolicy(); v == yubikey.TouchPolicyUnknown {
				t.Errorf("got %v, want a known touch policy", v)
			}
			if v := slot.HasKey(); v == false {
				t.Errorf("got %v, want true", v)
			}
			if v := slot.IsGenerated(); v == false {
				t.Errorf("got %v, want true", v)
			}
			if v := slot.IsImported(); v == true {
				t.Errorf("got %v, want false", v)
			}
			if v := slot.PublicKey(); len(v) == 0 {
				t.Errorf("got %v, want a public key", v)
			}
			if v := slot.PublicKeyAlgorithm(); v == yubikey.AlgorithmUnknown {
				t.Errorf("got %v, want a public key algorithm", v)
			}
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Errorf("got %v, want nil", err)
			}
			publicKey := elliptic.MarshalCompressed(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
			sk, err := slot.SharedKey(publicKey)
			if err != nil {
				t.Errorf("got %v, want nil", err)
			} else if len(sk) == 0 {
				t.Errorf("got %v, want a shared key", sk)
			}
		}
	}
}
