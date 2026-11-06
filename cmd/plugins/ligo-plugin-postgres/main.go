// Command ligo-plugin-postgres is the postgres.v1 platform provider: one role
// per binding in one database (.specs/ligo-postgres-plugin.md).
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/command/version"
	"github.com/dihedron/ligo/pkg/metadata"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
)

const (
	typ            = "postgres.v1"
	connectTimeout = 10 * time.Second
	scramRounds    = 4096
)

// Grammars (§4): nothing else reaches SQL, and identifiers are quoted anyway.
var (
	identRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	principalRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)
	uuidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

//go:embed schemas/config.json
var configSchema string

//go:embed schemas/output.json
var outputSchema string

// config is an instance's checked config_json.
type config struct {
	Host                string                              `json:"host"`
	Port                int                                 `json:"port"`
	Database            string                              `json:"database"`
	GrantableRoles      []string                            `json:"grantable_roles"`
	AllowedEndpoints    []string                            `json:"allowed_endpoints"`
	CAFile              string                              `json:"ca_file"`
	DirectoryGroup      string                              `json:"directory_group"`
	BootstrapCredential pluginsdk.BootstrapCredentialConfig `json:"bootstrap_credential"`

	roots *x509.CertPool // nil: the system roots
}

// parseConfig checks an instance's configuration (§3); errors name the field.
func parseConfig(data []byte, mode pluginv1.IdentityMode) (*config, error) {
	var c config
	if err := strict(data, &c); err != nil {
		return nil, err
	}
	if c.Host == "" {
		return nil, errors.New("host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	if !identRE.MatchString(c.Database) {
		return nil, errors.New("database is not a valid identifier")
	}
	if len(c.GrantableRoles) == 0 {
		return nil, errors.New("grantable_roles is required")
	}
	for _, r := range c.GrantableRoles {
		if !identRE.MatchString(r) {
			return nil, fmt.Errorf("grantable_roles: %q is not a valid identifier", r)
		}
	}
	if endpoint := net.JoinHostPort(c.Host, strconv.Itoa(c.Port)); !slices.Contains(c.AllowedEndpoints, endpoint) {
		return nil, fmt.Errorf("allowed_endpoints must contain %s", endpoint)
	}
	switch {
	case c.DirectoryGroup != "" && !identRE.MatchString(c.DirectoryGroup):
		return nil, errors.New("directory_group is not a valid identifier")
	case c.DirectoryGroup == "" && mode == pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR:
		return nil, errors.New("directory_group is required with EXTERNAL_DIR")
	case c.BootstrapCredential.Source == "":
		return nil, errors.New("bootstrap_credential is required")
	case c.BootstrapCredential.KVPath == "":
		return nil, errors.New("bootstrap_credential.kv_path is required")
	}
	if err := c.BootstrapCredential.Validate(); err != nil {
		return nil, err
	}
	var err error
	c.roots, err = pluginsdk.LoadRoots(c.CAFile)
	return &c, err
}

type instance struct {
	config
	dial func(context.Context) (*pgx.Conn, error)
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedPlatformProviderPluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, PluginProtocolVersion: 1,
		PluginVersion: metadata.Version, InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_PlatformProvider{PlatformProvider: &pluginv1.PlatformProviderCapabilities{
			AcceptedIdentityModes: []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC,
				pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR},
			ClientOutputSchemaJson: outputSchema,
			NamespaceField:         "schema",
		}},
	}, nil
}

// ConfigureInstances checks every instance's configuration, then selects its
// SVID and prepares its bootstrap credential (§5.4, §5.5).
func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	configs := map[string]*config{}
	for _, in := range r.GetInstances() {
		c, err := parseConfig([]byte(in.GetConfigJson()), in.GetIdentityMode())
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		configs[in.GetName()] = c
	}
	selectors, out, err := pluginsdk.SelectInstances(ctx, r)
	if err != nil {
		return nil, err
	}
	instances := map[string]*instance{}
	for name, c := range configs {
		cred, err := pluginsdk.NewBootstrapCredential(c.BootstrapCredential, selectors[name], pluginsdk.HTTPClient(c.roots))
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+name+": "+err.Error(), false)
		}
		instances[name] = &instance{config: *c, dial: dialer(c, cred)}
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

// errCredential is a bootstrap credential that cannot be read.
var errCredential = errors.New("bootstrap credential")

// dialer connects as the admin, always verifying the server.
func dialer(c *config, cred *pluginsdk.BootstrapCredential) func(context.Context) (*pgx.Conn, error) {
	return func(ctx context.Context) (*pgx.Conn, error) {
		admin, err := cred.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errCredential, err)
		}
		cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s sslmode=verify-full", c.Host, c.Port, c.Database))
		if err != nil {
			return nil, err
		}
		cfg.User, cfg.Password, cfg.ConnectTimeout = admin.Username, admin.Password.Reveal(), connectTimeout
		cfg.TLSConfig.RootCAs = c.roots
		return pgx.ConnectConfig(ctx, cfg)
	}
}

func (p *plugin) instance(name string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in := p.instances[name]; in != nil {
		return in, nil
	}
	return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+name, false)
}

// Health connects with the bootstrap credential.
func (p *plugin) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	conn, err := in.dial(ctx)
	if err == nil {
		defer func() { _ = conn.Close(ctx) }()
		var one int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	if err != nil {
		report(err)
		return &pluginv1.HealthResponse{PublicMessage: "the database cannot be reached with the bootstrap credential"}, nil
	}
	return &pluginv1.HealthResponse{Serving: true}, nil
}

// sqlstate is an error's SQLSTATE, "" if PostgreSQL did not answer.
func sqlstate(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// report logs what is safe: PostgreSQL's text can echo a statement (§7).
func report(err error) {
	slog.Warn("the target refused or failed", "sqlstate", sqlstate(err))
}

// failure maps an error to §7's codes, with fixed messages.
func failure(err error) error {
	report(err)
	state := sqlstate(err)
	unavailable := pluginsdk.Error(codes.Unavailable, "TARGET_UNAVAILABLE", "the target database cannot be reached", true)
	switch {
	case errors.Is(err, errCredential):
		return pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_UNAVAILABLE", "cannot read the bootstrap credential", true)
	case state == "":
		return unavailable
	case state == "28P01", state == "28000":
		return pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_REJECTED", "the database refused the bootstrap credential", true)
	case strings.HasPrefix(state, "08"), strings.HasPrefix(state, "57P0"), strings.HasPrefix(state, "53"):
		return unavailable
	case strings.HasPrefix(state, "40"), strings.HasPrefix(state, "55"), state == "42710", state == "23505":
		return pluginsdk.Error(codes.Unavailable, "TARGET_BUSY", "a concurrent change on the target database", true)
	case state == "42704":
		return pluginsdk.Error(codes.FailedPrecondition, "ROLE_NOT_FOUND", "a granted role does not exist", false)
	case state == "42501":
		return pluginsdk.Error(codes.PermissionDenied, "TARGET_ACCESS_DENIED", "the bootstrap credential may not do this", false)
	case state == "2BP01":
		return pluginsdk.Error(codes.FailedPrecondition, "ROLE_OWNS_OBJECTS", "the role owns objects: reassign them, then retry", false)
	}
	return pluginsdk.Error(codes.FailedPrecondition, "TARGET_REJECTED", "the target database refused a statement", false)
}

// definition is a target's definition: a schema of the instance's database.
type definition struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// roles checks a level's grants against the privilege bounds and returns its
// roles, sorted and without duplicates.
func (in *instance) roles(grants []byte) ([]string, error) {
	var g struct {
		Roles []string `json:"roles"`
	}
	if err := strict(grants, &g); err != nil || len(g.Roles) == 0 {
		return nil, errors.New("grants must be {\"roles\": [...]}")
	}
	slices.Sort(g.Roles)
	g.Roles = slices.Compact(g.Roles)
	for _, r := range g.Roles {
		if !identRE.MatchString(r) || !slices.Contains(in.GrantableRoles, r) {
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

func invalid(msg string) (*pluginv1.ValidateTargetResponse, error) {
	return &pluginv1.ValidateTargetResponse{Errors: []string{msg}}, nil
}

// ValidateTarget checks a definition and its levels; it changes nothing, and
// with check_existence reads that the schema and the roles exist.
func (p *plugin) ValidateTarget(ctx context.Context, r *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	var d definition
	if err := strict(r.GetDefinitionJson(), &d); err != nil || d.Database != in.Database || !identRE.MatchString(d.Schema) {
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
	if !r.GetCheckExistence() {
		return resp, nil
	}
	conn, err := in.dial(ctx)
	if err != nil {
		return nil, failure(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	all = slices.Compact(slices.Sorted(slices.Values(all)))
	var schema, roles int
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_namespace WHERE nspname = $1),
		(SELECT count(*) FROM pg_roles WHERE rolname = ANY($2))`, d.Schema, all).Scan(&schema, &roles); err != nil {
		return nil, failure(err)
	}
	if schema == 0 {
		return invalid("definition.schema: " + d.Schema + " does not exist")
	}
	if roles != len(all) {
		return invalid("accessLevels: a role does not exist")
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
		return refuse("definition: not a valid definition")
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

// checkBinding refuses a principal or a binding ID outside the grammar (§4)
// and returns the role's quoted name and ownership tag.
func checkBinding(b *pluginv1.BindingContext) (ident, tag string, err error) {
	if !principalRE.MatchString(b.GetDerivedPrincipalName()) {
		return "", "", pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "the principal name is outside the plugin's grammar", false)
	}
	if !uuidRE.MatchString(b.GetBindingId()) {
		return "", "", pluginsdk.Error(codes.InvalidArgument, "INVALID_BINDING", "the binding id is not a UUID", false)
	}
	return pgx.Identifier{b.GetDerivedPrincipalName()}.Sanitize(), "ligo:binding_id=" + b.GetBindingId(), nil
}

// querier is what the plugin reads and writes through: a connection or a
// transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// owner reads whether a role exists and the binding its comment names.
func owner(ctx context.Context, q querier, role string) (exists bool, comment string, err error) {
	err = q.QueryRow(ctx, "SELECT coalesce(shobj_description(oid, 'pg_authid'), '') FROM pg_roles WHERE rolname = $1", role).Scan(&comment)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	return err == nil, comment, err
}

// scramVerifier is the form PostgreSQL keeps of a password. The plugin sends
// this, so that no statement log ever holds the password (§6).
func scramVerifier(password string, salt []byte) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, scramRounds, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, text string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(text))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramRounds, b64(salt), b64(stored[:]), b64(mac(salted, "Server Key"))), nil
}

// newPassword is a generated password and its verifier.
func newPassword(length int) (password, verifier string, err error) {
	if password, err = pluginsdk.GeneratePassword(length); err != nil {
		return "", "", err
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // crypto/rand.Read never fails
	verifier, err = scramVerifier(password, salt)
	return password, verifier, err
}

// EnsureTarget converges the binding's role, in one transaction: a role is
// never left without its tag (§6). Its memberships are exactly the level's.
func (p *plugin) EnsureTarget(ctx context.Context, r *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	var s spec
	if err := strict(r.GetRequestedSpecJson(), &s); err != nil {
		return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_SPEC", "the requested spec is not valid", false)
	}
	grants, _ := json.Marshal(map[string][]string{"roles": s.Roles})
	roles, err := in.roles(grants)
	if err != nil { // a bound tightened since the level was published (§5.8 rule 3)
		return nil, pluginsdk.Error(codes.FailedPrecondition, "PRIVILEGE_OUT_OF_BOUNDS", err.Error(), false)
	}
	b := r.GetBinding()
	ident, tag, err := checkBinding(b)
	if err != nil {
		return nil, err
	}
	mode := r.GetIdentity().GetMode()
	if mode != pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL && mode != pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC &&
		mode != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "TARGET_LOCAL, DELEGATED_DYNAMIC or EXTERNAL_DIR only", false)
	}
	if mode == pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR {
		roles = append(roles, in.DirectoryGroup)
	}
	conn, err := in.dial(ctx)
	if err != nil {
		return nil, failure(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	payload := &pluginv1.SecretProvisioningPayload{Mode: mode}
	clientSpec := map[string]any{"endpoint": net.JoinHostPort(in.Host, strconv.Itoa(in.Port)), "database": in.Database}
	if mode != pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC {
		clientSpec["user"] = b.GetDerivedPrincipalName()
	}
	var refused error
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		exists, comment, err := owner(ctx, tx, b.GetDerivedPrincipalName())
		if err != nil {
			return err
		}
		if exists && comment != tag {
			refused = pluginsdk.Error(codes.FailedPrecondition, "RESOURCE_OWNED_BY_OTHER_BINDING", "the role belongs to another binding", false)
			return refused
		}
		if err := converge(ctx, tx, r, s.ConnectionLimit, ident, exists, payload); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf("COMMENT ON ROLE %s IS '%s'", ident, tag)); err != nil { // the tag's grammar: checkBinding
			return err
		}
		return memberships(ctx, tx, b.GetDerivedPrincipalName(), ident, roles)
	})
	if refused != nil {
		return nil, refused
	}
	if err != nil {
		return nil, failure(err)
	}
	finalized, _ := json.Marshal(clientSpec)
	return &pluginv1.EnsureTargetResponse{FinalizedClientSpecJson: finalized, SecretPayload: payload,
		DeclaredEndpoints: []*pluginv1.Endpoint{{Host: in.Host, Port: uint32(in.Port), Scheme: "postgresql"}}}, nil // #nosec G115 -- checked by parseConfig
}

// converge creates or alters the role for its identity mode, and fills the
// payload for Stage 3.
func converge(ctx context.Context, tx pgx.Tx, r *pluginv1.EnsureTargetRequest, connectionLimit int, ident string, exists bool, payload *pluginv1.SecretProvisioningPayload) error {
	limit := connectionLimit
	if limit == 0 {
		limit = -1
	}
	verb := "ALTER ROLE " + ident
	if !exists {
		verb = "CREATE ROLE " + ident
	}
	b := r.GetBinding()
	switch r.GetIdentity().GetMode() {
	case pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR:
		// no password: the directory verifies it, and the engine forwards Stage 1's secret (§5.6)
		_, err := tx.Exec(ctx, fmt.Sprintf("%s LOGIN CONNECTION LIMIT %d", verb, limit))
		return err
	case pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL:
		if exists && !b.GetRotateStaticSecrets() {
			payload.SecretUnchanged = true
			_, err := tx.Exec(ctx, fmt.Sprintf("%s LOGIN CONNECTION LIMIT %d", verb, limit))
			return err
		}
		password, verifier, err := newPassword(minPassword(r.GetIdentity().GetMetadata()["password_length"]))
		if err != nil {
			return err
		}
		// a verifier's alphabet is base64's and $:- no quoting needed (§5.8 rule 3)
		if _, err := tx.Exec(ctx, fmt.Sprintf("%s LOGIN PASSWORD '%s' CONNECTION LIMIT %d", verb, verifier, limit)); err != nil {
			return err
		}
		payload.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: b.GetDerivedPrincipalName(), Password: password}}
		return nil
	}
	if !exists {
		if _, err := tx.Exec(ctx, fmt.Sprintf("%s NOLOGIN", verb)); err != nil {
			return err
		}
	}
	payload.Payload = &pluginv1.SecretProvisioningPayload_DelegatedRole{DelegatedRole: &pluginv1.DelegatedRoleSpec{
		RoleType: "database-dynamic", TargetConnectionRef: r.GetInstance(), TargetUsername: b.GetDerivedPrincipalName(),
		CreationStatements:   []string{fmt.Sprintf(`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT %d IN ROLE %s`, limit, ident)},
		RevocationStatements: []string{`DROP ROLE IF EXISTS "{{name}}"`},
		DefaultTtlSeconds:    3600, MaxTtlSeconds: 86400,
	}}
	return nil
}

// memberships makes the role's memberships exactly roles.
func memberships(ctx context.Context, q querier, principal, ident string, roles []string) error {
	rows, err := q.Query(ctx, `SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
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
			if _, err := q.Exec(ctx, "GRANT "+pgx.Identifier{r}.Sanitize()+" TO "+ident); err != nil {
				return err
			}
		}
	}
	for _, r := range have {
		if !slices.Contains(roles, r) {
			if _, err := q.Exec(ctx, "REVOKE "+pgx.Identifier{r}.Sanitize()+" FROM "+ident); err != nil {
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

// CleanupTarget ends the sessions of the binding's role and drops it, if this
// binding owns it; a role gone is success, a foreign one is skipped (§6).
func (p *plugin) CleanupTarget(ctx context.Context, r *pluginv1.CleanupTargetRequest) (*pluginv1.CleanupTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	ident, tag, err := checkBinding(r.GetBinding())
	if err != nil {
		return nil, err
	}
	principal := r.GetBinding().GetDerivedPrincipalName()
	conn, err := in.dial(ctx)
	if err != nil {
		return nil, failure(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	exists, comment, err := owner(ctx, conn, principal)
	switch {
	case err != nil:
		return nil, failure(err)
	case !exists:
		return &pluginv1.CleanupTargetResponse{}, nil
	case comment != tag:
		return &pluginv1.CleanupTargetResponse{SkippedNotOwner: true}, nil
	}
	if _, err := conn.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", principal); err != nil {
		return nil, failure(err)
	}
	if _, err := conn.Exec(ctx, "DROP ROLE "+ident); err != nil {
		return nil, failure(err)
	}
	return &pluginv1.CleanupTargetResponse{}, nil
}

// GetUISchemas gives the forms of §4, with the bounds as the role options.
func (p *plugin) GetUISchemas(_ context.Context, r *pluginv1.GetUISchemasRequest) (*pluginv1.GetUISchemasResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	options := make([]*pluginv1.UIFieldOption, len(in.GrantableRoles))
	for i, role := range in.GrantableRoles {
		options[i] = &pluginv1.UIFieldOption{Value: role, Label: role}
	}
	return &pluginv1.GetUISchemasResponse{PluginType: typ, Instance: r.GetInstance(),
		TargetDefinition: &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{
			{JsonKey: "database", Label: "Database", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT, Required: true, DefaultValue: in.Database},
			{JsonKey: "schema", Label: "Schema", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT, Required: true, ValidationRegex: identRE.String()},
		}},
		AccessLevelGrants: &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{
			{JsonKey: "roles", Label: "Roles", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_MULTISELECT, Required: true, Options: options},
		}},
		BindingParameters: &pluginv1.UIForm{Fields: []*pluginv1.UIFieldDescriptor{
			{JsonKey: "connectionLimit", Label: "Connection limit", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_NUMBER, HelpText: "0 for no limit, at most 1000"},
		}},
	}, nil
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		os.Exit(version.Run(os.Args[2:]))
	}
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(pluginsdk.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Platform: p})
}
