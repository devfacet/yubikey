// YubiKey
// For the full copyright and license information, please view the LICENSE.txt file.

package yubikey_test

import (
	"testing"

	"github.com/devfacet/yubikey"
)

func TestAlgorithmString(t *testing.T) {
	table := []struct {
		alg  yubikey.Algorithm
		want string
	}{
		{yubikey.AlgorithmUnknown, ""},
		{yubikey.AlgorithmEC256, "p256"},
		{yubikey.AlgorithmEC384, "p384"},
		{yubikey.AlgorithmEd25519, "ed25519"},
		{yubikey.AlgorithmRSA1024, "rsa1024"},
		{yubikey.AlgorithmRSA2048, "rsa2048"},
	}
	for _, v := range table {
		if s := v.alg.String(); s != v.want {
			t.Errorf("got %v, want %v", s, v.want)
		}
	}
}
