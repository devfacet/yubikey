// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"github.com/go-piv/piv-go/piv"
)

const (
	// AlgorithmUnknown represents the unknown algorithm.
	AlgorithmUnknown Algorithm = 0
	// AlgorithmEC256 represents the EC256 algorithm.
	AlgorithmEC256 Algorithm = 1
	// AlgorithmEC384 represents the EC384 algorithm.
	AlgorithmEC384 Algorithm = 2
	// AlgorithmEd25519 represents the Ed25519 algorithm.
	AlgorithmEd25519 Algorithm = 3
	// AlgorithmRSA1024 represents the RSA1024 algorithm.
	AlgorithmRSA1024 Algorithm = 4
	// AlgorithmRSA2048 represents the RSA2048 algorithm.
	AlgorithmRSA2048 Algorithm = 5
)

// Algorithm represents an algorithm.
type Algorithm int

// String returns the algorithm name.
func (alg Algorithm) String() string {
	switch alg {
	case AlgorithmEC256:
		return "p256"
	case AlgorithmEC384:
		return "p384"
	case AlgorithmEd25519:
		return "ed25519"
	case AlgorithmRSA1024:
		return "rsa1024"
	case AlgorithmRSA2048:
		return "rsa2048"
	default:
		return ""
	}
}

// piv returns the PIV representation of the algorithm.
func (alg Algorithm) piv() piv.Algorithm {
	switch alg {
	case AlgorithmEC256:
		return piv.AlgorithmEC256
	case AlgorithmEC384:
		return piv.AlgorithmEC384
	case AlgorithmEd25519:
		return piv.AlgorithmEd25519
	case AlgorithmRSA1024:
		return piv.AlgorithmRSA1024
	case AlgorithmRSA2048:
		return piv.AlgorithmRSA2048
	default:
		return piv.Algorithm(0)
	}
}
