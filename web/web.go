// Package web holds the admin UI's templates and static files, embedded in
// the binary (§7.4).
package web

import "embed"

// FS holds templates/ and static/.
//
//go:embed templates static
var FS embed.FS
