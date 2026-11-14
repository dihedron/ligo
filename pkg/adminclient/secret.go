package adminclient

import (
	"fmt"
	"log/slog"
)

// Secret is a string that prints as [redacted] with every verb and in logs,
// so that a password in a Config does not leak through %v, an error or a
// log line (T-A2). Convert with string(s) to use it.
type Secret string

const redacted = "[redacted]"

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Format prints [redacted] with every verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// BasicAuth is a user of the server's LDAP directory (allow_basic_auth). The
// package never prompts for the password, reads it from a file or logs it.
type BasicAuth struct {
	Username string
	Password Secret
}
