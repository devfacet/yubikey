// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"github.com/go-piv/piv-go/piv"
)

const (
	// PINPolicyUnknown represents the unknown PIN policy.
	PINPolicyUnknown PINPolicy = 0
	// PINPolicyNever represents the "never" PIN policy.
	PINPolicyNever PINPolicy = 1
	// PINPolicyOnce represents the "once" PIN policy.
	PINPolicyOnce PINPolicy = 2
	// PINPolicyAlways represents the "always" PIN policy.
	PINPolicyAlways PINPolicy = 3
)

// PINPolicy represents a slot PIN policy.
type PINPolicy int

// String returns the policy name.
func (pinPolicy PINPolicy) String() string {
	switch pinPolicy {
	case PINPolicyNever:
		return "Never"
	case PINPolicyOnce:
		return "Once"
	case PINPolicyAlways:
		return "Always"
	default:
		return ""
	}
}

// piv returns the PIV representation of the policy.
func (pinPolicy PINPolicy) piv() piv.PINPolicy {
	switch pinPolicy {
	case PINPolicyNever:
		return piv.PINPolicyNever
	case PINPolicyOnce:
		return piv.PINPolicyOnce
	case PINPolicyAlways:
		return piv.PINPolicyAlways
	default:
		return piv.PINPolicy(0)
	}
}

const (
	// TouchPolicyUnknown represents the unknown touch policy.
	TouchPolicyUnknown TouchPolicy = 0
	// TouchPolicyNever represents the "never" touch policy.
	TouchPolicyNever TouchPolicy = 1
	// TouchPolicyAlways represents the "always" touch policy.
	TouchPolicyAlways TouchPolicy = 2
	// TouchPolicyCached represents the "cached" touch policy.
	TouchPolicyCached TouchPolicy = 3
)

// TouchPolicy represents a slot touch policy.
type TouchPolicy int

// String returns the policy name.
func (touchPolicy TouchPolicy) String() string {
	switch touchPolicy {
	case TouchPolicyNever:
		return "Never"
	case TouchPolicyAlways:
		return "Always"
	case TouchPolicyCached:
		return "Cached"
	default:
		return ""
	}
}

// piv returns the PIV representation of the policy.
func (touchPolicy TouchPolicy) piv() piv.TouchPolicy {
	switch touchPolicy {
	case TouchPolicyNever:
		return piv.TouchPolicyNever
	case TouchPolicyAlways:
		return piv.TouchPolicyAlways
	case TouchPolicyCached:
		return piv.TouchPolicyCached
	default:
		return piv.TouchPolicy(0)
	}
}
