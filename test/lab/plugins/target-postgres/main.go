// Command target-postgres is a lab plugin (test tooling, never shipped,
// not hardened): a stand-in for the postgres.v1 platform provider, so that
// phase 6 runs its workflows against a real database. It manages roles in
// one database of the lab's PostgreSQL, connecting as the admin its
// bootstrap credential names (.specs/ligo-test-environment.md, "Plugins on
// ligo1").
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/dihedron/ligo/test/lab/plugins/labkit"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
)

const typ = "postgres.v1"

// Identifier grammars (§5.8 rule 3): nothing else reaches SQL unquoted, and
// identifiers are quoted anyway.
var (
	nameRE      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	roleRE      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,62}$`)
	principalRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,19}$`)
)

// config is an instance's config_json.
type config struct {
	labkit.Common
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Database       string   `json:"database"`
	GrantableRoles []string `json:"grantable_roles"` // the privilege bounds
}

type instance struct {
	*labkit.Instance
	config
	strategy string // the platform's secret storage strategy (§5.6)
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedPlatformProviderPluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

const configSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
"required":["host","port","database","grantable_roles","ca_file","bootstrap_credential"],
"properties":{"host":{"type":"string"},"port":{"type":"integer"},"database":{"type":"string"},
"grantable_roles":{"type":"array","items":{"type":"string"}},"ca_file":{"type":"string"},"bootstrap_credential":{"type":"object"}}}`

const outputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
"required":["endpoint","database"],
"properties":{"endpoint":{"type":"string","x-ligo-endpoint":true},"database":{"type":"string"},"user":{"type":"string"}}}`

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, PluginProtocolVersion: 1,
		PluginVersion: "lab", InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_PlatformProvider{PlatformProvider: &pluginv1.PlatformProviderCapabilities{
			AcceptedIdentityModes:  []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC},
			ClientOutputSchemaJson: outputSchema,
		}},
	}, nil
}

func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	kits, out, err := labkit.Configure(ctx, r)
	if err != nil {
		return nil, err
	}
	instances := map[string]*instance{}
	for _, in := range r.GetInstances() {
		inst := &instance{Instance: kits[in.GetName()], strategy: in.GetSecretStorageStrategy()}
		if err := json.Unmarshal([]byte(in.GetConfigJson()), &inst.config); err != nil || !nameRE.MatchString(inst.Database) {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": config", false)
		}
		instances[in.GetName()] = inst
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

func (p *plugin) Health(context.Context, *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	return &pluginv1.HealthResponse{Serving: true}, nil
}

func (p *plugin) instance(name string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in := p.instances[name]; in != nil {
		return in, nil
	}
	return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+name, false)
}

// connect opens a connection to the instance's database as its admin.
func (in *instance) connect(ctx context.Context) (*pgx.Conn, error) {
	cred, err := in.Credential.Get(ctx)
	if err != nil {
		return nil, pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_UNAVAILABLE", "cannot read the bootstrap credential", true)
	}
	cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s sslmode=verify-full", in.Host, in.Port, in.Database))
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Password = cred.Username, cred.Password.Reveal()
	cfg.TLSConfig.RootCAs = in.Roots
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, pluginsdk.Error(codes.Unavailable, "TARGET_UNAVAILABLE", "cannot connect to the target database", true)
	}
	return conn, nil
}

func invalid(msg string) (*pluginv1.ValidateTargetResponse, error) {
	return &pluginv1.ValidateTargetResponse{Errors: []string{msg}}, nil
}

// definition is a target's definition: a schema of the instance's database.
type definition struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// roles checks a level's grants against the privilege bounds and returns
// its roles, sorted and without duplicates.
func (in *instance) roles(grants []byte) ([]string, error) {
	var g struct {
		Roles []string `json:"roles"`
	}
	if err := strict(grants, &g); err != nil || len(g.Roles) == 0 {
		return nil, fmt.Errorf("grants must be {\"roles\": [...]}")
	}
	slices.Sort(g.Roles)
	g.Roles = slices.Compact(g.Roles)
	for _, r := range g.Roles {
		if !roleRE.MatchString(r) || !slices.Contains(in.GrantableRoles, r) {
			return nil, fmt.Errorf("role %q is not in grantable_roles", r)
		}
	}
	return g.Roles, nil
}

func privileges(roles []string) []string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = "role:" + r
	}
	return out
}

// ValidateTarget checks a definition and its levels; it changes nothing,
// and with check_existence reads that the schema and the roles exist.
func (p *plugin) ValidateTarget(ctx context.Context, r *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	var d definition
	if err := strict(r.GetDefinitionJson(), &d); err != nil || d.Database != in.Database || !nameRE.MatchString(d.Schema) {
		return invalid("definition must be {\"database\": \"" + in.Database + "\", \"schema\": <identifier>}")
	}
	resp := &pluginv1.ValidateTargetResponse{Valid: true}
	resp.NormalizedDefinitionJson, _ = json.Marshal(d)
	var all []string
	for _, l := range r.GetAccessLevels() {
		roles, err := in.roles(l.GetGrantsJson())
		if err != nil {
			return invalid("accessLevels." + l.GetName() + ": " + err.Error())
		}
		grants, _ := json.Marshal(map[string][]string{"roles": roles})
		resp.AccessLevels = append(resp.AccessLevels, &pluginv1.NormalizedAccessLevel{Name: l.GetName(), GrantsJson: grants, Privileges: privileges(roles)})
		all = append(all, roles...)
	}
	if r.GetCheckExistence() {
		conn, err := in.connect(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close(ctx) }()
		var schema, roles int
		if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = $1),
			(SELECT count(*) FROM pg_roles WHERE rolname = ANY($2))`, d.Schema, slices.Compact(slices.Sorted(slices.Values(all)))).Scan(&schema, &roles); err != nil {
			return nil, pluginsdk.Error(codes.Unavailable, "TARGET_UNAVAILABLE", "cannot read the target database", true)
		}
		if schema == 0 {
			return invalid("definition.schema: " + d.Schema + " does not exist")
		}
		if roles != len(slices.Compact(slices.Sorted(slices.Values(all)))) {
			return invalid("accessLevels: a role does not exist")
		}
	}
	return resp, nil
}

// spec is a binding's requested spec, composed by ValidateBinding.
type spec struct {
	Database        string   `json:"database"`
	Schema          string   `json:"schema"`
	Roles           []string `json:"roles"`
	ConnectionLimit int      `json:"connectionLimit"`
}

// ValidateBinding checks the parameters, which never add privilege, and
// composes the requested spec (§5.8 rule 8).
func (p *plugin) ValidateBinding(_ context.Context, r *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	refuse := func(msg string) (*pluginv1.ValidateBindingResponse, error) {
		return &pluginv1.ValidateBindingResponse{Errors: []string{msg}}, nil
	}
	var d definition
	if err := strict(r.GetDefinitionJson(), &d); err != nil {
		return refuse("definition: " + err.Error())
	}
	roles, err := in.roles(r.GetAccessLevelGrantsJson())
	if err != nil {
		return refuse("accessLevel: " + err.Error())
	}
	var params struct {
		ConnectionLimit int `json:"connectionLimit"`
	}
	if len(r.GetParametersJson()) > 0 {
		if err := strict(r.GetParametersJson(), &params); err != nil || params.ConnectionLimit < 0 || params.ConnectionLimit > 1000 {
			return refuse("parameters must be {\"connectionLimit\": 0..1000}")
		}
	}
	normalized, _ := json.Marshal(params)
	requested, _ := json.Marshal(spec{Database: d.Database, Schema: d.Schema, Roles: roles, ConnectionLimit: params.ConnectionLimit})
	return &pluginv1.ValidateBindingResponse{Valid: true, NormalizedParametersJson: normalized, RequestedSpecJson: requested, Privileges: privileges(roles)}, nil
}

func tag(b *pluginv1.BindingContext) string { return "ligo:binding_id=" + b.GetBindingId() }

// owner reads whether a role exists and the binding its comment names.
func owner(ctx context.Context, conn *pgx.Conn, role string) (exists bool, comment string, err error) {
	err = conn.QueryRow(ctx, "SELECT coalesce(shobj_description(oid, 'pg_authid'), '') FROM pg_roles WHERE rolname = $1", role).Scan(&comment)
	if err == pgx.ErrNoRows {
		return false, "", nil
	}
	return err == nil, comment, err
}

// failed reports a statement the database refused: the error goes to
// stderr, which the host's redacting logger receives (§5.8 rule 6), the
// caller gets a public message only.
func failed(err error) error {
	fmt.Fprintln(os.Stderr, "target-postgres:", err)
	return pluginsdk.Error(codes.Unavailable, "TARGET_ERROR", "the target database refused a statement", true)
}

// EnsureTarget converges the binding's role: a login role with a password
// in TARGET_LOCAL, a parent role and OpenBao's statements in
// DELEGATED_DYNAMIC; the role has exactly the requested roles (§5.8 rule 1).
func (p *plugin) EnsureTarget(ctx context.Context, r *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	var s spec
	if err := strict(r.GetRequestedSpecJson(), &s); err != nil {
		return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_SPEC", "requested spec", false)
	}
	roles, err := in.roles(mustJSON(map[string][]string{"roles": s.Roles}))
	if err != nil { // a bound tightened since the level was published (§5.8 rule 3)
		return nil, pluginsdk.Error(codes.FailedPrecondition, "PRIVILEGE_OUT_OF_BOUNDS", err.Error(), false)
	}
	b := r.GetBinding()
	principal := b.GetDerivedPrincipalName()
	if !principalRE.MatchString(principal) {
		return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "principal name", false)
	}
	mode := r.GetIdentity().GetMode()
	if mode != pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL && mode != pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "TARGET_LOCAL or DELEGATED_DYNAMIC only", false)
	}
	conn, err := in.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(ctx) }()
	exists, comment, err := owner(ctx, conn, principal)
	if err != nil {
		return nil, failed(err)
	}
	if exists && comment != tag(b) {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "RESOURCE_OWNED_BY_OTHER_BINDING", "the role belongs to another binding", false)
	}
	ident := pgx.Identifier{principal}.Sanitize()
	limit := s.ConnectionLimit
	if limit == 0 {
		limit = -1
	}
	payload := &pluginv1.SecretProvisioningPayload{Mode: mode}
	clientSpec := map[string]any{"endpoint": net.JoinHostPort(in.Host, strconv.Itoa(in.Port)), "database": in.Database}
	if mode == pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL {
		clientSpec["user"] = principal
		length := minPassword(r.GetIdentity().GetMetadata()["password_length"])
		switch {
		case !exists || b.GetRotateStaticSecrets():
			password, err := pluginsdk.GeneratePassword(length)
			if err != nil {
				return nil, err
			}
			stmt := "ALTER ROLE " + ident
			if !exists {
				stmt = "CREATE ROLE " + ident
			}
			// the password's alphabet is [A-Za-z0-9]: no quoting needed (§5.8 rule 3)
			if _, err := conn.Exec(ctx, fmt.Sprintf("%s LOGIN PASSWORD '%s' CONNECTION LIMIT %d", stmt, password, limit)); err != nil {
				return nil, failed(err)
			}
			payload.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: principal, Password: password}}
		default:
			if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s CONNECTION LIMIT %d", ident, limit)); err != nil {
				return nil, failed(err)
			}
			payload.SecretUnchanged = true
		}
	} else {
		if !exists {
			if _, err := conn.Exec(ctx, "CREATE ROLE "+ident+" NOLOGIN"); err != nil {
				return nil, failed(err)
			}
		}
		roleType := "database-dynamic"
		if in.strategy == "vault-static-rotated" {
			roleType = "database-static-rotated"
		}
		payload.Payload = &pluginv1.SecretProvisioningPayload_DelegatedRole{DelegatedRole: &pluginv1.DelegatedRoleSpec{
			RoleType: roleType, TargetConnectionRef: r.GetInstance(), TargetUsername: principal,
			CreationStatements:   []string{fmt.Sprintf(`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT %d IN ROLE %s`, limit, ident)},
			RevocationStatements: []string{`DROP ROLE IF EXISTS "{{name}}"`},
			DefaultTtlSeconds:    3600, MaxTtlSeconds: 86400,
		}}
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("COMMENT ON ROLE %s IS '%s'", ident, tag(b))); err != nil { // the tag is "ligo:binding_id=" and a UUID
		return nil, failed(err)
	}
	if err := grants(ctx, conn, principal, ident, roles); err != nil {
		return nil, failed(err)
	}
	spec, _ := json.Marshal(clientSpec)
	return &pluginv1.EnsureTargetResponse{FinalizedClientSpecJson: spec, SecretPayload: payload,
		DeclaredEndpoints: []*pluginv1.Endpoint{{Host: in.Host, Port: uint32(in.Port), Scheme: "postgresql"}}}, nil // #nosec G115 -- a port
}

// grants makes the role's memberships exactly roles.
func grants(ctx context.Context, conn *pgx.Conn, principal, ident string, roles []string) error {
	rows, err := conn.Query(ctx, `SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
		JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1`, principal)
	if err != nil {
		return err
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, r := range roles {
		if !slices.Contains(have, r) {
			if _, err := conn.Exec(ctx, "GRANT "+pgx.Identifier{r}.Sanitize()+" TO "+ident); err != nil {
				return err
			}
		}
	}
	for _, r := range have {
		if !slices.Contains(roles, r) {
			if _, err := conn.Exec(ctx, "REVOKE "+pgx.Identifier{r}.Sanitize()+" FROM "+ident); err != nil {
				return err
			}
		}
	}
	return nil
}

func minPassword(length string) int {
	if n, err := strconv.Atoi(length); err == nil && n >= 32 {
		return n
	}
	return 32
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

// CleanupTarget drops the binding's role if this binding owns it; a role
// gone is success, a foreign one is skipped (§5.8 rules 1 and 2).
func (p *plugin) CleanupTarget(ctx context.Context, r *pluginv1.CleanupTargetRequest) (*pluginv1.CleanupTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	principal := r.GetBinding().GetDerivedPrincipalName()
	if !principalRE.MatchString(principal) {
		return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "principal name", false)
	}
	conn, err := in.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(ctx) }()
	exists, comment, err := owner(ctx, conn, principal)
	switch {
	case err != nil:
		return nil, failed(err)
	case !exists:
		return &pluginv1.CleanupTargetResponse{}, nil
	case comment != tag(r.GetBinding()):
		return &pluginv1.CleanupTargetResponse{SkippedNotOwner: true}, nil
	}
	// the role owns nothing; its memberships go with it
	if _, err := conn.Exec(ctx, "DROP ROLE "+pgx.Identifier{principal}.Sanitize()); err != nil {
		return nil, failed(err)
	}
	return &pluginv1.CleanupTargetResponse{}, nil
}

func (p *plugin) GetUISchemas(_ context.Context, r *pluginv1.GetUISchemasRequest) (*pluginv1.GetUISchemasResponse, error) {
	return &pluginv1.GetUISchemasResponse{PluginType: typ, Instance: r.GetInstance()}, nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(labkit.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Platform: p})
}
