package audit

import (
	"encoding/json"
	"testing"
	"time"
	"uuid"
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
		t.Error("the hash depends on the time zone or on nanoseconds")
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
