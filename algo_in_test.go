// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
)

func TestAlgorithmPIV(t *testing.T) {
	table := []struct {
		alg  Algorithm
		want piv.Algorithm
	}{
		{AlgorithmUnknown, 0},
		{AlgorithmEC256, piv.AlgorithmEC256},
		{AlgorithmEC384, piv.AlgorithmEC384},
		{AlgorithmEd25519, piv.AlgorithmEd25519},
		{AlgorithmRSA1024, piv.AlgorithmRSA1024},
		{AlgorithmRSA2048, piv.AlgorithmRSA2048},
	}
	for _, v := range table {
		if p := v.alg.piv(); p != v.want {
			t.Errorf("got %v, want %v", p, v.want)
		}
	}
}
