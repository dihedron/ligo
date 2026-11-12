package pluginmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/outputvalidation"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Spec is one plugin process: a plugin type in one realm, with that realm's
// instances (ADR-03). A builtin is served in-process instead (§5.1).
type Spec struct {
	Type      string
	Kind      pluginv1.PluginKind
	Builtin   bool
	Binary    string // a file name in plugins.directory; not for a builtin
	SHA256    []byte
	Realm     config.Realm
	Instances []*pluginv1.InstanceDescriptor
	// Env is the plugin's whole environment: ligo's own is never passed on.
	Env []string
}

// Options are the plugins settings (§8.1 plugins).
type Options struct {
	Directory                    string
	Owner                        Owner
	RPCTimeout                   time.Duration
	MaxConcurrentRPCsPerInstance int
	Backoff                      config.Backoff
	Logger                       *slog.Logger
	// Templates are the plugin types a process may be started for at run
	// time, by type, and Realms the realms, by name: a Spec without
	// instances. The types and realms of New's specs are added.
	Templates map[string]Spec
	Realms    map[string]config.Realm
	// Debounce is how long Notify waits for more changes before it
	// reconciles (.specs/ligo-instances.md §7.2); 2s when zero.
	Debounce time.Duration
}

// exitPoll is how often a supervisor checks that its process is alive.
const exitPoll = 50 * time.Millisecond

type key struct {
	kind     pluginv1.PluginKind
	instance string
}

// Manager runs the plugin processes, restarts them when they crash, keeps
// them in line with the instances in force, and mediates every RPC (§5.2,
// §5.3, .specs/ligo-instances.md §7).
type Manager struct {
	opts Options
	log  *slog.Logger

	// mu guards the processes, the routing maps and the types' descriptions.
	mu         sync.RWMutex
	procs      []*process
	byKey      map[key]*process
	sems       map[key]chan struct{}
	validators map[key]*outputvalidation.Validator // the outputs of platform and store instances (§5.7)
	types      map[string]*pluginv1.DescribeResponse

	reconciling sync.Mutex // one reconcile at a time
	pendingMu   sync.Mutex
	pending     []Spec
	kick        chan struct{}

	stop chan struct{}
	wg   sync.WaitGroup
}

type process struct {
	described *pluginv1.DescribeResponse // at the first start; Describe is static (§5.2)
	stop      chan struct{}              // closed when the process is retired
	mu        sync.RWMutex
	spec      Spec    // its instances change at run time
	client    *Client // nil while the process is down
	resolved  map[string]string
}

// instances is the process's current instances.
func (p *process) instances() []*pluginv1.InstanceDescriptor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.spec.Instances
}

// New prepares a manager; Start launches the processes.
func New(specs []Spec, opts Options) *Manager {
	m := &Manager{
		opts:  opts,
		log:   slog.New(pluginsdk.NewRedactingHandler(opts.Logger.Handler())),
		byKey: map[key]*process{}, sems: map[key]chan struct{}{}, validators: map[key]*outputvalidation.Validator{},
		types: map[string]*pluginv1.DescribeResponse{}, kick: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	if m.opts.Templates == nil {
		m.opts.Templates = map[string]Spec{}
	}
	if m.opts.Realms == nil {
		m.opts.Realms = map[string]config.Realm{}
	}
	if m.opts.Debounce == 0 {
		m.opts.Debounce = 2 * time.Second
	}
	for _, s := range specs {
		template := s
		template.Instances = nil
		if _, ok := m.opts.Templates[s.Type]; !ok {
			m.opts.Templates[s.Type] = template
		}
		m.opts.Realms[s.Realm.Name] = s.Realm
		p := &process{spec: s, stop: make(chan struct{})}
		place(s)
		m.procs = append(m.procs, p)
		m.route(p, s.Instances, nil)
	}
	return m
}

// place gives each instance its process's realm.
func place(s Spec) {
	for _, in := range s.Instances {
		in.Realm, in.TrustDomain = s.Realm.Name, s.Realm.TrustDomain
	}
}

// route points the routing maps at p for its instances, and drops those of
// the instances it no longer serves; the caller holds mu, or owns m alone.
func (m *Manager) route(p *process, added, removed []*pluginv1.InstanceDescriptor) {
	for _, in := range removed {
		k := key{p.spec.Kind, in.GetName()}
		delete(m.byKey, k)
		delete(m.sems, k)
		delete(m.validators, k)
	}
	for _, in := range added {
		k := key{p.spec.Kind, in.GetName()}
		m.byKey[k] = p
		if _, ok := m.sems[k]; !ok {
			m.sems[k] = make(chan struct{}, max(m.opts.MaxConcurrentRPCsPerInstance, 1))
		}
	}
}

// Start launches every process in two passes (§5.2): it spawns and
// describes them all, checks every instance's config against its plugin's
// schema (rule 8) and every platform's wiring (rule 3), and compiles the
// output validators of platforms and stores (§5.7), then configures their instances and checks the SVIDs
// they resolved: one each, in the realm's trust domain (INV-10), distinct
// unless every instance sharing one allows it (ADR-03). Any failure is fatal
// and names the instance (AC-15).
func (m *Manager) Start(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.Stop()
		}
	}()
	for _, p := range m.procs {
		c, d, err := m.spawn(ctx, p.spec)
		if err != nil {
			return err
		}
		p.client, p.described = c, d
	}
	for _, p := range m.procs {
		if err := checkConfigs(p.described, p.spec.Instances); err != nil {
			return fmt.Errorf("%s: %w", what(p.spec), err)
		}
	}
	for _, p := range m.procs {
		if err := m.wire(p.spec.Kind, p.described, p.spec.Instances); err != nil {
			return err
		}
		v, err := validatorsFor(p.described, p.spec)
		if err != nil {
			return err
		}
		copyValidators(m.validators, v)
	}
	for _, p := range m.procs {
		resolved, err := m.configure(ctx, p.client, p.spec)
		if err != nil {
			return fmt.Errorf("%s: %w", what(p.spec), err)
		}
		p.resolved = resolved
	}
	if err := m.sharedSVIDs(nil, nil, nil); err != nil {
		return err
	}
	for _, p := range m.procs {
		m.supervised(p)
	}
	return nil
}

func copyValidators(into, from map[key]*outputvalidation.Validator) {
	for k, v := range from {
		into[k] = v
	}
}

// supervised starts p's supervisor: builtins cannot crash apart from ligo.
func (m *Manager) supervised(p *process) {
	if !p.spec.Builtin {
		m.wg.Go(func() { m.supervise(p) })
	}
}

// sharedSVIDs checks that no two instances resolve one SVID unless each
// allows it (ADR-03), across every process; for a process being changed,
// its proposed instances and resolution replace its current ones.
func (m *Manager) sharedSVIDs(changed *process, ins []*pluginv1.InstanceDescriptor, resolved map[string]string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	owners := map[string][]*pluginv1.InstanceDescriptor{}
	add := func(builtin bool, ins []*pluginv1.InstanceDescriptor, resolved map[string]string) {
		for _, in := range ins {
			if !builtin { // builtins hold no SVID
				owners[resolved[in.GetName()]] = append(owners[resolved[in.GetName()]], in)
			}
		}
	}
	for _, p := range m.procs {
		if p != changed {
			p.mu.RLock()
			add(p.spec.Builtin, p.spec.Instances, p.resolved)
			p.mu.RUnlock()
		}
	}
	if changed != nil {
		add(changed.spec.Builtin, ins, resolved)
	}
	for id, ins := range owners {
		for _, in := range ins {
			if len(ins) > 1 && !in.GetAllowSharedSvid() {
				return fmt.Errorf("instance %q: SVID %s is resolved by %d instances and allow_shared_svid is not set", in.GetName(), id, len(ins))
			}
		}
	}
	return nil
}

func what(s Spec) string { return fmt.Sprintf("plugin %s in realm %s", s.Type, s.Realm.Name) }

// spawn starts one process from its checked binary, or a builtin, and
// checks what it describes; the type's description is kept.
func (m *Manager) spawn(ctx context.Context, s Spec) (*Client, *pluginv1.DescribeResponse, error) {
	var c *Client
	if s.Builtin {
		var err error
		if c, err = startBuiltin(s.Type, s.Kind); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", what(s), err)
		}
	} else {
		b, err := OpenBinary(m.opts.Directory, s.Binary, s.SHA256, m.opts.Owner)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", what(s), err)
		}
		cmd := b.Command()
		cmd.Env = s.Env
		w := &hclogWriter{log: m.log.With("plugin", s.Type, "realm", s.Realm.Name)}
		c, err = Start(cmd, s.Kind, b.Checksum(), newHCLogger(w), w)
		_ = b.Close() // the process holds the binary now
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", what(s), err)
		}
	}
	d, err := m.describe(ctx, c, s)
	if err != nil {
		c.Kill()
		return nil, nil, fmt.Errorf("%s: %w", what(s), err)
	}
	m.mu.Lock()
	if _, ok := m.types[s.Type]; !ok {
		m.types[s.Type] = d
	}
	m.mu.Unlock()
	return c, d, nil
}

func (m *Manager) describe(ctx context.Context, c *Client, s Spec) (*pluginv1.DescribeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	d, err := c.Control.Describe(ctx, &pluginv1.DescribeRequest{})
	if err != nil {
		return nil, fmt.Errorf("describe: %w", err)
	}
	if d.GetPluginType() != s.Type || d.GetKind() != s.Kind || d.GetPluginProtocolVersion() != 2 {
		return nil, fmt.Errorf("describes itself as %s, kind %v, protocol %d", d.GetPluginType(), d.GetKind(), d.GetPluginProtocolVersion())
	}
	if !capabilitiesOfKind(d) {
		return nil, fmt.Errorf("describes capabilities %T for kind %v", d.GetCapabilities(), d.GetKind())
	}
	if d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER && d.GetIdentityProvider().GetProducedIdentityMode() == pluginv1.IdentityMode_IDENTITY_MODE_UNSPECIFIED {
		return nil, errors.New("produces identity mode IDENTITY_MODE_UNSPECIFIED")
	}
	return d, nil
}

func (m *Manager) configure(ctx context.Context, c *Client, s Spec) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	r, err := c.Control.ConfigureInstances(ctx, &pluginv1.ConfigureInstancesRequest{
		Realm: s.Realm.Name, SpiffeWorkloadSocket: s.Realm.SPIFFEWorkloadSocket, Instances: s.Instances,
	})
	if err != nil {
		_, detail := pluginsdk.FromError(err)
		return nil, fmt.Errorf("configuring instances: %s: %s", detail.GetCode(), detail.GetPublicMessage())
	}
	resolved := map[string]string{}
	for _, ri := range r.GetResolved() {
		resolved[ri.GetInstance()] = ri.GetSpiffeId()
	}
	if s.Builtin {
		return resolved, nil
	}
	for _, in := range s.Instances {
		id, err := spiffeid.FromString(resolved[in.GetName()])
		if err != nil {
			return nil, fmt.Errorf("instance %q: no SPIFFE ID resolved", in.GetName())
		}
		if id.TrustDomain().Name() != s.Realm.TrustDomain {
			return nil, fmt.Errorf("instance %q: resolved %s, outside the realm's trust domain %s", in.GetName(), id, s.Realm.TrustDomain)
		}
		m.log.Info("plugin instance resolved", "plugin", s.Type, "realm", s.Realm.Name, "instance", in.GetName(), "spiffe_id", id.String())
	}
	return resolved, nil
}

// described is what each type described, by kind and type (the instance
// field of the key holds the type).
func (m *Manager) described() map[key]*pluginv1.DescribeResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[key]*pluginv1.DescribeResponse{}
	for typ, d := range m.types {
		out[key{d.GetKind(), typ}] = d
	}
	return out
}

// wire checks the wiring of a process's platforms against what their
// plugins describe and fills each descriptor's identity mode and secret
// storage strategy (§5.6, §8.2 rule 3). Processes of one type describe the
// same, whatever the realm.
func (m *Manager) wire(kind pluginv1.PluginKind, d *pluginv1.DescribeResponse, ins []*pluginv1.InstanceDescriptor) error {
	if kind != pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER {
		return nil
	}
	described := m.described()
	for _, in := range ins {
		if err := wirePlatform(in, d.GetPlatformProvider(), described); err != nil {
			return fmt.Errorf("platform %q: %w", in.GetName(), err)
		}
	}
	return nil
}

func wirePlatform(in *pluginv1.InstanceDescriptor, platform *pluginv1.PlatformProviderCapabilities, described map[key]*pluginv1.DescribeResponse) error {
	idp, ok := described[key{pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, in.GetIdentityProviderType()}]
	if !ok {
		return fmt.Errorf("no identity provider of type %q", in.GetIdentityProviderType())
	}
	mode := idp.GetIdentityProvider().GetProducedIdentityMode()
	if !slices.Contains(platform.GetAcceptedIdentityModes(), mode) {
		return fmt.Errorf("identity provider %s produces %v, which the platform does not accept (%v)", in.GetIdentityProviderType(), mode, platform.GetAcceptedIdentityModes())
	}
	store, ok := described[key{pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, in.GetSecretStoreType()}]
	if !ok {
		return fmt.Errorf("no secret store of type %q", in.GetSecretStoreType())
	}
	var fit []string // the store's strategies for the mode
	for _, st := range store.GetSecretStore().GetSecretStorageStrategies() {
		if slices.Contains(st.GetIdentityModes(), mode) {
			fit = append(fit, st.GetName())
		}
	}
	switch strategy := in.GetSecretStorageStrategy(); {
	case strategy == "" && len(fit) == 1:
		in.SecretStorageStrategy = fit[0]
	case strategy == "":
		return fmt.Errorf("secret_storage_strategy omitted, and secret store %s declares %d for %v %v: set one", in.GetSecretStoreType(), len(fit), mode, fit)
	case !slices.Contains(fit, strategy):
		return fmt.Errorf("secret store %s does not declare secret_storage_strategy %q for %v %v", in.GetSecretStoreType(), strategy, mode, fit)
	}
	in.IdentityMode = mode
	return nil
}

// describedOf is what a type described, or nil.
func (m *Manager) describedOf(typ string) *pluginv1.DescribeResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.types[typ]
}

// Strategies returns the secret storage strategies a secret store type
// declared in Describe, for the startup check of existing bindings (§8.2
// rule 10).
func (m *Manager) Strategies(storeType string) []string {
	var out []string
	if d := m.describedOf(storeType); d != nil && d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE {
		for _, st := range d.GetSecretStore().GetSecretStorageStrategies() {
			out = append(out, st.GetName())
		}
	}
	return out
}

// NamespaceField is the definition field that holds a target's namespace on
// platforms of platformType, or "" if it has none (.specs/ligo-tenancy.md §5).
func (m *Manager) NamespaceField(platformType string) string {
	if d := m.describedOf(platformType); d != nil && d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER {
		return d.GetPlatformProvider().GetNamespaceField()
	}
	return ""
}

// ExactSubject reports whether a store's strategy binds one exact SPIFFE ID
// (OI-1, .specs/ligo-vault-plugin.md §4).
func (m *Manager) ExactSubject(storeType, strategy string) bool {
	if d := m.describedOf(storeType); d != nil && d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE {
		for _, st := range d.GetSecretStore().GetSecretStorageStrategies() {
			if st.GetName() == strategy && st.GetSubjectMatch() == pluginv1.SubjectMatch_SUBJECT_MATCH_EXACT {
				return true
			}
		}
	}
	return false
}

// validatorsFor compiles, for each platform and store instance of a
// process, its plugin's output schema with the instance's allowed_endpoints
// (§5.7).
func validatorsFor(d *pluginv1.DescribeResponse, s Spec) (map[key]*outputvalidation.Validator, error) {
	out := map[key]*outputvalidation.Validator{}
	var schema string
	switch c := d.GetCapabilities().(type) {
	case *pluginv1.DescribeResponse_PlatformProvider:
		schema = c.PlatformProvider.GetClientOutputSchemaJson()
	case *pluginv1.DescribeResponse_SecretStore:
		schema = c.SecretStore.GetClientOutputSchemaJson()
	default:
		return out, nil
	}
	for _, in := range s.Instances {
		var cfg struct {
			AllowedEndpoints []string `json:"allowed_endpoints"`
		}
		if err := json.Unmarshal([]byte(in.GetConfigJson()), &cfg); err != nil {
			return nil, fmt.Errorf("%s: instance %q: config: %w", what(s), in.GetName(), err)
		}
		allow, err := flows.ParseAllowlist(cfg.AllowedEndpoints)
		if err != nil {
			return nil, fmt.Errorf("%s: instance %q: %w", what(s), in.GetName(), err)
		}
		v, err := outputvalidation.New(schema, allow)
		if err != nil {
			return nil, fmt.Errorf("%s: output schema: %w", what(s), err)
		}
		out[key{s.Kind, in.GetName()}] = v
	}
	return out, nil
}

// OutputValidator is the output validator of a platform or store
// instance, or nil (§5.7).
func (m *Manager) OutputValidator(kind pluginv1.PluginKind, instance string) *outputvalidation.Validator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validators[key{kind, instance}]
}

// checkConfigs validates every instance's config against the plugin's
// instance configuration schema (§8.2 rule 8).
func checkConfigs(d *pluginv1.DescribeResponse, instances []*pluginv1.InstanceDescriptor) error {
	for _, in := range instances {
		if err := checkConfig(d, in); err != nil {
			return fmt.Errorf("instance %q: %w", in.GetName(), err)
		}
	}
	return nil
}

// compileSchema compiles a JSON Schema, 2020-12 unless it says otherwise.
func compileSchema(text string) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

// capabilitiesOfKind: Describe carries exactly its kind's capabilities (§5.9).
func capabilitiesOfKind(d *pluginv1.DescribeResponse) bool {
	switch d.GetCapabilities().(type) {
	case *pluginv1.DescribeResponse_IdentityProvider:
		return d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER
	case *pluginv1.DescribeResponse_PlatformProvider:
		return d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER
	case *pluginv1.DescribeResponse_SecretStore:
		return d.GetKind() == pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE
	}
	return false
}

// supervise restarts the process when it exits, with exponential backoff,
// until it is retired or the manager stops; a restarted process must
// resolve the same SVIDs as before.
func (m *Manager) supervise(p *process) {
	backoff := m.opts.Backoff.Initial
	for {
		select {
		case <-m.stop:
			return
		case <-p.stop:
			return
		case <-time.After(exitPoll):
		}
		p.mu.RLock()
		down := p.client == nil || p.client.exited()
		p.mu.RUnlock()
		if !down {
			continue
		}
		p.mu.Lock()
		if p.client != nil {
			m.log.Warn("plugin process exited", "plugin", p.spec.Type, "realm", p.spec.Realm.Name)
			p.client.Kill()
			p.client = nil
		}
		spec := p.spec
		p.mu.Unlock()
		select {
		case <-m.stop:
			return
		case <-p.stop:
			return
		case <-time.After(backoff):
		}
		c, d, err := m.spawn(context.Background(), spec)
		if err == nil {
			err = m.reconfigure(c, d, p)
		}
		if err != nil {
			m.log.Error("plugin restart failed", "plugin", spec.Type, "realm", spec.Realm.Name, "error", err, "retry_in", backoff)
			backoff = min(backoff*2, m.opts.Backoff.Max)
			continue
		}
		p.mu.Lock()
		p.client = c
		p.mu.Unlock()
		backoff = m.opts.Backoff.Initial
		metrics.PluginRestarts.WithLabelValues(spec.Type, spec.Realm.Name).Inc()
		m.log.Info("plugin process restarted", "plugin", spec.Type, "realm", spec.Realm.Name)
	}
}

// reconfigure checks that a restarted process describes itself as at the
// first start, configures it with the current instances, and checks that
// it resolves the same SVIDs; on failure it kills the process.
func (m *Manager) reconfigure(c *Client, d *pluginv1.DescribeResponse, p *process) error {
	p.mu.RLock()
	spec, before := p.spec, p.resolved
	p.mu.RUnlock()
	err := errors.New("the restarted process describes itself differently")
	if proto.Equal(d, p.described) {
		var resolved map[string]string
		if resolved, err = m.configure(context.Background(), c, spec); err == nil && !sameResolution(resolved, before) {
			err = errors.New("the restarted process resolved other SVIDs")
		}
	}
	if err != nil {
		c.Kill()
	}
	return err
}

func sameResolution(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// errUnavailable is the retryable error of an RPC to a process that is down
// or died during the call (§5.2).
var errUnavailable = pluginsdk.Error(codes.Unavailable, "PLUGIN_UNAVAILABLE", "the plugin process is unavailable", true)

// Call runs fn with the client of the process serving the instance of kind,
// under the rpc_timeout deadline and, for mutating RPCs (Ensure*, Cleanup*),
// the instance's concurrency limit (§5.3 rules 6-7).
func (m *Manager) Call(ctx context.Context, kind pluginv1.PluginKind, instance string, mutating bool, fn func(context.Context, *Client) error) error {
	k := key{kind, instance}
	m.mu.RLock()
	p, ok := m.byKey[k]
	sem := m.sems[k]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no plugin instance %q of kind %v", instance, kind)
	}
	if mutating {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.RLock()
	c, typ := p.client, p.spec.Type
	p.mu.RUnlock()
	if c == nil {
		return errUnavailable
	}
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, calledKey{}, called{typ, instance}), m.opts.RPCTimeout)
	defer cancel()
	err := fn(ctx, c)
	if status.Code(err) == codes.Unavailable {
		if _, d := pluginsdk.FromError(err); d.GetCode() == "PLUGIN_ERROR" { // the transport's, not the plugin's
			return errUnavailable
		}
	}
	return err
}

// Resolved is the SPIFFE ID an instance resolved.
func (m *Manager) Resolved(kind pluginv1.PluginKind, instance string) string {
	m.mu.RLock()
	p, ok := m.byKey[key{kind, instance}]
	m.mu.RUnlock()
	if !ok {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.resolved[instance]
}

// Stop kills every process and ends the supervisors.
func (m *Manager) Stop() {
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	m.wg.Wait()
	m.mu.RLock()
	procs := slices.Clone(m.procs)
	m.mu.RUnlock()
	for _, p := range procs {
		p.mu.Lock()
		if p.client != nil {
			p.client.Kill()
			p.client = nil
		}
		p.mu.Unlock()
	}
}
