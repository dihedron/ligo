// Package web holds the admin UI's static files, embedded in the binary
// (§7.4); the templates join them with the UI frame.
package web

import "embed"

// FS holds static/.
//
//go:embed static
var FS embed.FS
