package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/dihedron/ligo/internal/client"
	"go.yaml.in/yaml/v3"
)

// document is one manifest document (§8.4 "Manifests"): its kind and the
// body the API takes for it.
type document struct {
	kind, name string
	body       map[string]any
}

// order is the order ligo apply submits kinds in.
var order = map[string]int{"Source": 0, "Target": 1, "Binding": 2}

// readManifest reads the documents of file ("-" for stdin): YAML documents
// separated by ---, or a JSON array, sorted Source, Target, Binding.
func readManifest(file string) ([]document, error) {
	var r io.Reader = os.Stdin
	if file != "-" {
		f, err := os.Open(file) //nolint:gosec // the operator's manifest
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	var raw []any
	dec := yaml.NewDecoder(r)
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("manifest %s: %w", file, err)
		}
		if list, ok := v.([]any); ok {
			raw = append(raw, list...)
		} else if v != nil {
			raw = append(raw, v)
		}
	}
	var docs []document
	for i, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("manifest %s: document %d is not an object", file, i+1)
		}
		kind, _ := m["kind"].(string)
		if _, ok := order[kind]; !ok {
			return nil, fmt.Errorf("manifest %s: document %d: kind must be Source, Target or Binding, not %q", file, i+1, kind)
		}
		if v, ok := m["apiVersion"]; ok && v != "ligo.dihedron.org/v1alpha1" {
			return nil, fmt.Errorf("manifest %s: document %d: apiVersion %v is not ligo.dihedron.org/v1alpha1", file, i+1, v)
		}
		delete(m, "apiVersion")
		d := document{kind: kind, body: m}
		if kind == "Binding" {
			delete(m, "kind") // the API sets a binding's kind
			d.name, _ = m["name"].(string)
		} else {
			d.name, _ = client.Lookup(m, "metadata.name").(string)
		}
		if d.name == "" {
			return nil, fmt.Errorf("manifest %s: document %d (%s) has no name", file, i+1, kind)
		}
		docs = append(docs, d)
	}
	slices.SortStableFunc(docs, func(a, b document) int { return order[a.kind] - order[b.kind] })
	return docs, nil
}

// creates reports whether d is a creation: it states no expectedRevision
// (§8.4 "Create or update in ligo apply").
func (d document) creates() bool { _, ok := d.body["expectedRevision"]; return !ok }

// inlineSources pairs the bindings with the sources created in the same
// file, which they register inline (§7.2.4); a new source may be named by
// one binding only, since the others need it to exist.
func inlineSources(docs []document) (map[string]document, error) {
	created := map[string]document{}
	for _, d := range docs {
		if d.kind == "Source" && d.creates() {
			created[d.name] = d
		}
	}
	inline := map[string]document{} // binding name -> its new source
	users := map[string][]string{}
	for _, d := range docs {
		if src, _ := d.body["source"].(string); d.kind == "Binding" && d.creates() {
			if s, ok := created[src]; ok {
				inline[d.name] = s
				users[src] = append(users[src], d.name)
			}
		}
	}
	for src, bs := range users {
		if len(bs) > 1 {
			return nil, fmt.Errorf("source %s is created in this file and named by %d bindings (%s): one registers it inline; apply the others once it is applied",
				src, len(bs), strings.Join(bs, ", "))
		}
	}
	return inline, nil
}

// filed is the answer to a filed change: the change request and, once
// applied, the resource.
type filed struct {
	ChangeRequest map[string]any `json:"changeRequest"`
	Resource      map[string]any `json:"resource"`
}

// report prints what §8.4 "CLI Output Behavior" asks for a filed change,
// in table format; JSON and YAML print the answers as they are.
func (b *Base) report(what string, answers []filed) error {
	out := b.writer()
	if b.format() != "table" {
		return client.Print(out, b.format(), answers)
	}
	for _, a := range answers {
		cr := a.ChangeRequest
		_, _ = fmt.Fprintf(out, "%s %s: change request %v %v\n", what, cr["resourceName"], cr["id"], cr["status"])
		switch cr["status"] {
		case "APPLIED":
			if st, ok := a.Resource["status"].(map[string]any); ok && cr["resourceType"] == "BINDING" {
				_, _ = fmt.Fprintf(out, "  phase %v, workflow %v\n", st["phase"], st["workflowId"])
			} else if rev := client.Lookup(a.Resource, "metadata.revision"); rev != nil {
				_, _ = fmt.Fprintf(out, "  revision %v\n", rev)
			}
		case "PENDING":
			sides, _ := cr["sides"].([]any)
			for _, s := range sides {
				sd, _ := s.(map[string]any)
				if sd["decision"] != nil {
					continue
				}
				_, _ = fmt.Fprintf(out, "  awaiting side %v (scope %v): ligo cr approve %v --sha256 %v --side %v -m \"<comment>\"\n",
					sd["side"], sd["scope"], cr["id"], cr["payloadSha256"], sd["side"])
			}
		}
	}
	return nil
}

func (b *Base) writer() io.Writer {
	if b.out == nil {
		return os.Stdout
	}
	return b.out
}

// existing explains a create refused because the resource exists: its
// current revision, and that replacing it needs expectedRevision.
func existing(ctx context.Context, c *client.Client, err error, kind, name string) error {
	var p *client.Problem
	if !errors.As(err, &p) || p.Status != 409 || kind == "binding" && p.Type != "urn:ligo:problem:binding-exists" && p.Type != "urn:ligo:problem:invalid-transition" {
		return err
	}
	var v map[string]any
	if c.Do(ctx, "GET", path(kind+"s", name), nil, nil, &v) != nil {
		return err
	}
	return fmt.Errorf("%w; %s %s exists at revision %v: add expectedRevision: %v to replace it", err, kind, name, client.Lookup(v, "metadata.revision"),
		client.Lookup(v, "metadata.revision"))
}

// automation adds the flags' approvalReference and automationContext to a
// body that does not set them.
func automation(body map[string]any, ref, context string) error {
	if _, ok := body["approvalReference"]; !ok && ref != "" {
		body["approvalReference"] = ref
	}
	if _, ok := body["automationContext"]; !ok && context != "" {
		var v map[string]any
		if err := json.Unmarshal([]byte(context), &v); err != nil {
			return fmt.Errorf("--automation-context: a JSON object: %w", err)
		}
		body["automationContext"] = v
	}
	return nil
}
