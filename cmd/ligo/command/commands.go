package command

import (
	"github.com/dihedron/ligo/internal/client"
	"github.com/dihedron/ligo/internal/command/admin"
	"github.com/dihedron/ligo/internal/command/migrate"
	"github.com/dihedron/ligo/internal/command/serve"
	"github.com/dihedron/ligo/internal/command/version"
)

// Commands is the set of root command groups (§8.4 Options).
type Commands struct {
	client.Globals

	// Version prints the program version information.
	Version version.Version `command:"version" alias:"v" description:"Print program version information."`
	// Serve runs the control-plane daemon.
	Serve    serve.Serve         `command:"serve" description:"Run the ligo control-plane daemon."`
	Get      admin.Get           `command:"get" description:"Display a source, target or binding."`
	List     admin.List          `command:"list" alias:"ls" description:"List sources, targets or bindings."`
	Platform admin.Platform      `command:"platform" description:"Inspect configured platforms and their UI schemas."`
	Catalog  admin.Catalog       `command:"catalog" description:"Search the catalog of targets and show their flows."`
	Flows    admin.Flows         `command:"flows" description:"Show the effective network flows of a binding (JSON for the verification tool)."`
	CR       admin.ChangeRequest `command:"cr" description:"Manage change requests (list, get, approve, decline, withdraw)."`
	Audit    admin.Audit         `command:"audit" description:"Query and verify the cryptographic audit log."`
	Maint    admin.Maintenance   `command:"maintenance" description:"Show, enable or disable cluster-wide maintenance mode."`
	BG       admin.BreakGlass    `command:"break-glass" description:"Emergency changes in approval-required scopes (ADR-12)."`
	Gov      admin.Governance    `command:"governance" description:"Show the governance policy and evaluate a planned change (ADR-13, ADR-14)."`
	Migrate  migrate.Migrate     `command:"migrate" description:"Apply the database migrations as ligo_migrator (before a rollout, §10.3)."`
}
