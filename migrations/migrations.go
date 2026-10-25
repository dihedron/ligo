// Package migrations embeds the database migrations, applied in order by
// internal/store/migrate. 001_init_schema.sql is the schema of §4.2.
package migrations

import "embed"

// FS holds the migrations, named NNN_description.sql.
//
//go:embed *.sql
var FS embed.FS
