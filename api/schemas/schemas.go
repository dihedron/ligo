// Package schemas embeds the normative JSON schemas of the API.
package schemas

import "embed"

// FS holds the schemas, by version: v1alpha2/network-flow.json (§3.3).
//
//go:embed v1alpha2/*.json
var FS embed.FS
