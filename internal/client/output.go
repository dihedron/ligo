package client

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"go.yaml.in/yaml/v3"
)

// Globals is §8.4 GlobalOptions.
type Globals struct {
	LogLevel string `short:"l" long:"log-level" env:"LIGO_LOG_LEVEL" default:"info" choice:"debug" choice:"info" choice:"warn" choice:"error" description:"Set logging verbosity."`
	Format   string `short:"o" long:"output" env:"LIGO_OUTPUT" default:"table" choice:"table" choice:"json" choice:"yaml" description:"Output format for CLI commands."`
}

// Column is a table column: its header and the dotted path of its value in
// each item, such as metadata.name.
type Column struct {
	Header, Path string
}

// Print writes v, a decoded JSON answer, in format: as JSON or YAML as it
// is, or as a table with columns of the items of v's "items" (or of v
// itself when it has none).
func Print(w io.Writer, format string, v any, columns ...Column) error {
	switch format {
	case "json":
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(v)
	case "yaml":
		return yaml.NewEncoder(w).Encode(v)
	}
	rows := []any{v}
	if m, ok := v.(map[string]any); ok {
		if items, ok := m["items"].([]any); ok {
			rows = items
		}
	}
	if len(columns) == 0 { // nothing tabular: YAML reads best
		return yaml.NewEncoder(w).Encode(v)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	headers := make([]string, len(columns))
	for i, c := range columns {
		headers[i] = c.Header
	}
	_, _ = fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, r := range rows {
		cells := make([]string, len(columns))
		for i, c := range columns {
			cells[i] = cell(lookup(r, c.Path))
		}
		_, _ = fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	if m, ok := v.(map[string]any); ok && m["nextPageToken"] != nil {
		_, _ = fmt.Fprintf(tw, "\nnext page: --page-token %v\n", m["nextPageToken"])
	}
	return tw.Flush()
}

// lookup follows a dotted path through maps.
func lookup(v any, path string) any {
	for _, k := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// cell renders one value on one line: nil as "-", lists joined by commas.
func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		if x == "" {
			return "-"
		}
		return strings.ReplaceAll(x, "\n", " ")
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = cell(e)
		}
		return strings.Join(parts, ",")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	case float64:
		return fmt.Sprint(x)
	}
	return fmt.Sprint(v)
}
