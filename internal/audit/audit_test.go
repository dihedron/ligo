package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/sealing"
)

// TestHash checks entry_hash against a value computed independently (Python
// json.dumps with sorted keys and hashlib), which equals JCS for this entry.
func TestHash(t *testing.T) {
	cr := uuid.MustParse("01928a10-55e1-7c3a-8f00-2a6b4c1d9e01")
	rev := int64(1)
	e := Entry{
		ResourceType:    "BINDING",
		ResourceName:    "fin-01-payments-ledger",
		ChangeRequestID: &cr,
		Action:          "CR_CREATED",
		Actor:           "alice",
		ActorGroups:     []string{"cn=ops"},
		Revision:        &rev,
		RequestID:       "req-1",
		Snapshot:        json.RawMessage(`{"b": 1, "a": "x"}`),
		OccurredAt:      time.Date(2026, 10, 25, 20, 0, 0, 123456789, time.FixedZone("CEST", 2*3600)),
	}
	got, err := e.hash(Genesis)
	if err != nil {
		t.Fatal(err)
	}
	if want := "6c67878d62aa0ef70eb64ce174eff05b885256957e61b1b3bbdfb9638081920f"; got != want {
		t.Errorf("hash = %s, want %s", got, want)
	}
	// the timestamp is UTC with microseconds: a different representation of
	// the same instant hashes the same
	e.OccurredAt = time.Date(2026, 10, 25, 18, 0, 0, 123456000, time.UTC)
	if again, _ := e.hash(Genesis); again != got {
		t.Error("the hash depends on the time realm or on nanoseconds")
	}
	if other, _ := e.hash("1" + Genesis[1:]); other == got {
		t.Error("the hash does not depend on the previous hash")
	}
}

func TestValidate(t *testing.T) {
	for name, e := range map[string]Entry{
		"no action":   {Actor: "a", ResourceType: "SOURCE", ResourceName: "s"},
		"no actor":    {Action: "SOURCE_CREATED", ResourceType: "SOURCE", ResourceName: "s"},
		"no resource": {Action: "SOURCE_CREATED", Actor: "a"},
		"bad JSON":    {Action: "SYSTEM_X", Actor: "a", Snapshot: json.RawMessage(`{`)},
	} {
		if _, err := e.hash(Genesis); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (&Entry{Action: "SESSION_REVOKED", Actor: "a"}).hash(Genesis); err != nil {
		t.Errorf("session action without resource: %v", err)
	}
}

// TestVerifyFileMalformed: change request lines that cannot be read, or
// that come after the entries, make the file an error, not a verdict.
func TestVerifyFileMalformed(t *testing.T) {
	sum := sha256.Sum256([]byte(Genesis + "{}"))
	head := `{"kind":"header","from":1,"through":1,"prevHash":"` + Genesis + `"}` + "\n"
	entry := `{"kind":"entry","id":1,"prevHash":"` + Genesis + `","entryHash":"` + hex.EncodeToString(sum[:]) + `","row":{}}` + "\n"
	for name, file := range map[string]string{
		"a row that is not an object":   head + `{"kind":"change_request","changeRequestId":"c1","row":"x"}` + "\n",
		"a request without its payload": head + `{"kind":"change_request","changeRequestId":"c1","row":{}}` + "\n",
		"a request after the entries":   head + entry + `{"kind":"change_request","changeRequestId":"c1","row":{"payload":{}}}` + "\n",
	} {
		if _, err := VerifyFile(strings.NewReader(file), sealing.KeySet{}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
