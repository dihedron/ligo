package pluginsdk

import (
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// LiteralSPIFFEID is the SPIFFE ID a regex matches when it matches one only:
// ^spiffe://…$ with escaped dots and no other metacharacter. A store that
// binds exact subjects can release a credential only to such a source (OI-1,
// .specs/ligo-vault-plugin.md §4).
func LiteralSPIFFEID(regex string) (string, bool) {
	body, anchored := strings.CutPrefix(regex, "^")
	body, ended := strings.CutSuffix(body, "$")
	if !anchored || !ended || !strings.HasPrefix(body, "spiffe://") {
		return "", false
	}
	var id strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body) && body[i+1] == '.':
			id.WriteByte('.')
			i++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("/:-_", c) >= 0:
			id.WriteByte(c)
		default:
			return "", false
		}
	}
	if _, err := spiffeid.FromString(id.String()); err != nil {
		return "", false
	}
	return id.String(), true
}
