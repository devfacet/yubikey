// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey_test

import (
	"testing"

	"github.com/devfacet/yubikey"
)

func TestPINPolicyString(t *testing.T) {
	table := []struct {
		policy yubikey.PINPolicy
		want   string
	}{
		{yubikey.PINPolicyUnknown, ""},
		{yubikey.PINPolicyNever, "Never"},
		{yubikey.PINPolicyOnce, "Once"},
		{yubikey.PINPolicyAlways, "Always"},
	}
	for _, v := range table {
		if s := v.policy.String(); s != v.want {
			t.Errorf("got %v, want %v", s, v.want)
		}
	}
}

func TestTouchPolicyString(t *testing.T) {
	table := []struct {
		policy yubikey.TouchPolicy
		want   string
	}{
		{yubikey.TouchPolicyUnknown, ""},
		{yubikey.TouchPolicyNever, "Never"},
		{yubikey.TouchPolicyAlways, "Always"},
		{yubikey.TouchPolicyCached, "Cached"},
	}
	for _, v := range table {
		if s := v.policy.String(); s != v.want {
			t.Errorf("got %v, want %v", s, v.want)
		}
	}
}
