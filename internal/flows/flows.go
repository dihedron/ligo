// Package flows implements declared network flows (ADR-16): the flow schema,
// the endpoint allowlist of platforms and the effective flows of a binding.
package flows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/dihedron/ligo/api/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrInvalidFlow is returned for a flow that breaks the schema of §3.3.
var ErrInvalidFlow = errors.New("invalid network flow")

// Flow is a network flow (§3.3). JSON uses the API's field names, YAML those
// of server.yaml.
type Flow struct {
	Name        string `json:"name" yaml:"name"`
	Purpose     string `json:"purpose" yaml:"purpose"`
	Protocol    string `json:"protocol" yaml:"protocol"`
	Destination string `json:"destination" yaml:"destination"`
	Ports       []Port `json:"ports" yaml:"ports"`
	TLS         bool   `json:"tls" yaml:"tls"`
	ServerName  string `json:"serverName,omitempty" yaml:"server_name,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// DeclaredBy is set only in computed lists.
	DeclaredBy string `json:"declaredBy,omitempty" yaml:"-"`
}

// UnmarshalJSON rejects unknown fields, as the schema does.
func (f *Flow) UnmarshalJSON(data []byte) error {
	type plain Flow
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode((*plain)(f))
}

// Port is a single port (Low == High) or an inclusive range.
type Port struct {
	Low, High int
	isRange   bool // written as "low-high", even if Low == High
}

// MarshalJSON writes a single port as a number and a range as "low-high".
func (p Port) MarshalJSON() ([]byte, error) {
	if !p.isRange {
		return json.Marshal(p.Low)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", p.Low, p.High))
}

// UnmarshalJSON reads a number or a "low-high" string; bounds are checked
// by Validate.
func (p *Port) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*p = Port{Low: n, High: n}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("port must be a number or a \"low-high\" string: %w", err)
	}
	low, high, ok := strings.Cut(s, "-")
	l, errL := strconv.Atoi(low)
	h, errH := strconv.Atoi(high)
	if !ok || errL != nil || errH != nil {
		return fmt.Errorf("port range %q must be \"low-high\"", s)
	}
	*p = Port{Low: l, High: h, isRange: true}
	return nil
}

var flowSchema = func() *jsonschema.Schema {
	const loc = "network-flow.json"
	data, err := schemas.FS.ReadFile("v1alpha2/" + loc)
	if err != nil {
		panic(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(loc, doc); err != nil {
		panic(err)
	}
	return c.MustCompile(loc)
}()

// Validate checks a declared flow against the schema of §3.3 and the rules
// the schema states in prose.
func (f Flow) Validate() error {
	if f.DeclaredBy != "" {
		return fmt.Errorf("%w %q: declaredBy is output only", ErrInvalidFlow, f.Name)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidFlow, f.Name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidFlow, f.Name, err)
	}
	if err := flowSchema.Validate(doc); err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidFlow, f.Name, err)
	}
	for _, p := range f.Ports {
		if p.isRange && (p.Low < 1 || p.High > 65535 || p.Low >= p.High) {
			return fmt.Errorf("%w %q: port range %d-%d must be within 1..65535 with low < high", ErrInvalidFlow, f.Name, p.Low, p.High)
		}
	}
	if _, _, err := parseDestination(f.Destination); err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidFlow, f.Name, err)
	}
	if f.ServerName != "" && (!f.TLS || !validDNSName(f.ServerName)) {
		return fmt.Errorf("%w %q: serverName must be a DNS name, and only with tls", ErrInvalidFlow, f.Name)
	}
	return nil
}

// ValidateList checks every flow of a declaration, at most max of them,
// with unique names.
func ValidateList(flows []Flow, max int) error {
	if len(flows) > max {
		return fmt.Errorf("%w: at most %d flows", ErrInvalidFlow, max)
	}
	seen := make(map[string]bool, len(flows))
	for _, f := range flows {
		if seen[f.Name] {
			return fmt.Errorf("%w: duplicate name %q", ErrInvalidFlow, f.Name)
		}
		seen[f.Name] = true
		if err := f.Validate(); err != nil {
			return err
		}
	}
	return nil
}

var dnsLabelRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validDNSName reports whether s is a DNS name of RFC 1123 labels.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// parseDestination returns the destination as a prefix (an address is a
// full-length prefix) or, for a DNS name, ok == false.
func parseDestination(dest string) (prefix netip.Prefix, isIP bool, err error) {
	if p, err := netip.ParsePrefix(dest); err == nil {
		return p.Masked(), true, nil
	}
	if a, err := netip.ParseAddr(dest); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true, nil
	}
	if strings.Contains(dest, "/") || !validDNSName(dest) {
		return netip.Prefix{}, false, fmt.Errorf("destination %q is not a DNS name, an IP address or a CIDR", dest)
	}
	return netip.Prefix{}, false, nil
}
