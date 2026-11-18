package command

import (
	"github.com/dihedron/ligo/internal/client"
	"github.com/dihedron/ligo/internal/command/admin"
	"github.com/dihedron/ligo/internal/command/completion"
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
	Serve    serve.Serve            `command:"serve" description:"Run the ligo control-plane daemon."`
	Binding  admin.Binding          `command:"binding" description:"Bindings: list, show, delete, release, retry, rotate, flows."`
	IdP      admin.IdentityProvider `command:"identity-provider" description:"Identity provider instances: list, show, delete."`
	Store    admin.SecretStore      `command:"secret-store" description:"Secret store instances: list, show, delete."`
	Platform admin.Platform         `command:"platform" description:"Inspect configured platforms and their UI schemas."`
	Catalog  admin.Catalog          `command:"catalog" description:"Search the catalog of targets and show their flows."`
	Apply    admin.Apply            `command:"apply" description:"Submit create or update change requests from a YAML/JSON manifest (kind Source, Target or Binding)."`
	Source   admin.Source           `command:"source" description:"Sources: list, show, delete, release, test a regex, deprecate, reactivate."`
	Target   admin.Target           `command:"target" description:"Targets: list, show, delete, release, deprecate, reactivate, access levels, bulk revocation."`
	CR       admin.ChangeRequest    `command:"cr" description:"Manage change requests (list, show, approve, decline, withdraw, ratify, revert, review)."`
	Audit    admin.Audit            `command:"audit" description:"Query and verify the cryptographic audit log."`
	Maint    admin.Maintenance      `command:"maintenance" description:"Show, enable or disable cluster-wide maintenance mode."`
	Exec     admin.Executors        `command:"executors" description:"Show the executors' pending workflows, and recover those of a replica gone for good (§10.2)."`
	BG       admin.BreakGlass       `command:"break-glass" description:"Emergency changes in approval-required jurisdictions (ADR-12)."`
	Hold     admin.Hold             `command:"hold" description:"List and lift the holds left by emergency removals of managed bindings."`
	Account  admin.Account          `command:"account" description:"Manage the registry of accounts (tenants): list, show, register, retire."`
	Gov      admin.Charter          `command:"charter" description:"Show the charter and evaluate a planned change (ADR-13, ADR-14)."`
	Compl    completion.Completion  `command:"completion" description:"Print the shell completion script: bash, zsh, fish or powershell."`
	Migrate  migrate.Migrate        `command:"migrate" description:"Apply the database migrations as ligo_migrator (before a rollout, §10.3)."`
}
