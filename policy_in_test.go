// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
)

func TestPINPolicyPIV(t *testing.T) {
	table := []struct {
		policy PINPolicy
		want   piv.PINPolicy
	}{
		{PINPolicyUnknown, 0},
		{PINPolicyNever, piv.PINPolicyNever},
		{PINPolicyOnce, piv.PINPolicyOnce},
		{PINPolicyAlways, piv.PINPolicyAlways},
	}
	for _, v := range table {
		if p := v.policy.piv(); p != v.want {
			t.Errorf("got %v, want %v", p, v.want)
		}
	}
}

func TestTouchPolicyPIV(t *testing.T) {
	table := []struct {
		policy TouchPolicy
		want   piv.TouchPolicy
	}{
		{TouchPolicyUnknown, 0},
		{TouchPolicyNever, piv.TouchPolicyNever},
		{TouchPolicyAlways, piv.TouchPolicyAlways},
		{TouchPolicyCached, piv.TouchPolicyCached},
	}
	for _, v := range table {
		if p := v.policy.piv(); p != v.want {
			t.Errorf("got %v, want %v", p, v.want)
		}
	}
}
