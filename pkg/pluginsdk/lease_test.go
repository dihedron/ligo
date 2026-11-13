package pluginsdk

import (
	"testing"
	"time"
)

func TestCredentialTTL(t *testing.T) {
	for _, ok := range [][2]time.Duration{{0, 0}, {time.Minute, 0}, {0, 720 * time.Hour}, {time.Hour, time.Hour}, {90 * time.Second, 24 * time.Hour}} {
		if err := CredentialTTL(ok[0], ok[1]); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][2]time.Duration{{59 * time.Second, 0}, {0, 721 * time.Hour}, {-time.Hour, 0}, {2 * time.Hour, time.Hour}} {
		if err := CredentialTTL(bad[0], bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
