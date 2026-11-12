package instances

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

// ParseManifest reads the definitions of a manifest: YAML documents, or a
// JSON array, of the kinds IdentityProvider, SecretStore and Platform. Each
// is normalized; checks against the configuration are the caller's.
func ParseManifest(data []byte) ([]*Definition, error) {
	var raw []any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		if list, ok := v.([]any); ok {
			raw = append(raw, list...)
		} else if v != nil {
			raw = append(raw, v)
		}
	}
	var defs []*Definition
	for i, v := range raw {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("manifest: document %d: %w", i+1, err)
		}
		d, err := Decode(data)
		if err != nil {
			return nil, fmt.Errorf("manifest: document %d: %w", i+1, err)
		}
		if _, err := d.KindOf(); err != nil {
			return nil, fmt.Errorf("manifest: document %d: %w", i+1, err)
		}
		d.Normalize()
		defs = append(defs, d)
	}
	return defs, nil
}

// LoadManifest reads a manifest file into a set, for tools and tests; its
// definitions are not checked against a configuration.
func LoadManifest(path string) (*Set, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the caller's file
	if err != nil {
		return nil, err
	}
	defs, err := ParseManifest(data)
	if err != nil {
		return nil, err
	}
	return NewSet(defs...), nil
}
