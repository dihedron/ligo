package pluginsdk

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GeneratePassword returns n characters of [A-Za-z0-9] from crypto/rand, so
// that no quoting is needed; n is at least 32 (§5.8 rule 3).
func GeneratePassword(n int) (string, error) {
	if n < 32 {
		return "", fmt.Errorf("password length %d: at least 32", n)
	}
	max := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, n)
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[k.Int64()]
	}
	return string(out), nil
}
