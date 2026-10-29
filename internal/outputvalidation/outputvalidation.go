// Package outputvalidation checks the client-facing outputs of platform
// providers and secret stores before they are persisted (§5.7, INV-13):
// their size, their schema, and every network endpoint they carry against
// the instance's allowed_endpoints.
package outputvalidation

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/message"
)

// ErrFailed is the terminal OUTPUT_VALIDATION_FAILED error.
var ErrFailed = errors.New("OUTPUT_VALIDATION_FAILED")

// MaxOutput is the largest output accepted.
const MaxOutput = 64 << 10

// keyword annotates the schema properties that carry network endpoints.
const keyword = "x-ligo-endpoint"

// Validator validates the outputs of one plugin instance.
type Validator struct {
	schema *jsonschema.Schema
	allow  flows.Allowlist
}

// New compiles a plugin's output schema (JSON Schema, 2020-12 unless it
// says otherwise) for an instance with the allowlist allow.
func New(schema string, allow flows.Allowlist) (*Validator, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertVocabs()
	c.RegisterVocabulary(vocabulary(allow))
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	s, err := c.Compile("schema.json")
	if err != nil {
		return nil, err
	}
	return &Validator{schema: s, allow: allow}, nil
}

// Validate checks output, then the endpoints the plugin declared (§5.7).
func (v *Validator) Validate(output []byte, declared []*pluginv1.Endpoint) error {
	if len(output) > MaxOutput {
		return fmt.Errorf("%w: output of %d bytes, over 64 KiB", ErrFailed, len(output))
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(output))
	if err != nil {
		return fmt.Errorf("%w: not JSON: %w", ErrFailed, err)
	}
	if err := v.schema.Validate(doc); err != nil {
		return fmt.Errorf("%w: %s", ErrFailed, brief(err))
	}
	for _, e := range declared {
		if err := v.allow.CheckEndpoint(e.GetHost(), int(e.GetPort())); err != nil {
			return fmt.Errorf("%w: declared %w", ErrFailed, err)
		}
	}
	return nil
}

// brief is a schema failure as the locations in the output and what failed
// there, without the schema's own URL: it may reach status messages.
func brief(err error) string {
	ve := (*jsonschema.ValidationError)(nil)
	if !errors.As(err, &ve) {
		return err.Error()
	}
	var out []string
	var walk func(u jsonschema.OutputUnit)
	walk = func(u jsonschema.OutputUnit) {
		if u.Error != nil {
			out = append(out, fmt.Sprintf("at '%s': %s", u.InstanceLocation, u.Error))
		}
		for _, e := range u.Errors {
			walk(e)
		}
	}
	walk(*ve.BasicOutput())
	return strings.Join(out, "; ")
}

// vocabulary checks the values of annotated properties against allow while
// the schema validates.
func vocabulary(allow flows.Allowlist) *jsonschema.Vocabulary {
	const url = "https://ligo.dihedron.org/schemas/vocab/endpoint"
	meta, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"properties":{"` + keyword + `":{"type":"boolean"}}}`))
	if err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, meta); err != nil {
		panic(err)
	}
	return &jsonschema.Vocabulary{
		URL:    url,
		Schema: c.MustCompile(url),
		Compile: func(_ *jsonschema.CompilerContext, obj map[string]any) (jsonschema.SchemaExt, error) {
			if on, _ := obj[keyword].(bool); on {
				return endpointExt{allow}, nil
			}
			return nil, nil
		},
	}
}

type endpointExt struct{ allow flows.Allowlist }

func (x endpointExt) Validate(ctx *jsonschema.ValidatorContext, v any) {
	s, ok := v.(string)
	if !ok {
		ctx.AddError(endpointError("an endpoint must be a string"))
		return
	}
	host, port, err := parseEndpoint(s)
	if err == nil {
		err = x.allow.CheckEndpoint(host, port)
	}
	if err != nil {
		ctx.AddError(endpointError(err.Error()))
	}
}

// parseEndpoint splits a host, a host:port or an absolute URL; port 0
// means none was given, since a URL scheme implies no default port.
func parseEndpoint(s string) (host string, port int, err error) {
	var p string
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0, err
		}
		host, p = u.Hostname(), u.Port()
	} else if h, hp, err := net.SplitHostPort(s); err == nil {
		host, p = h, hp
	} else {
		host = s
	}
	if p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("port %q must be within 1..65535", p)
		}
	}
	return host, port, nil
}

type endpointError string

func (endpointError) KeywordPath() []string { return []string{keyword} }

func (e endpointError) LocalizedString(*message.Printer) string { return string(e) }
