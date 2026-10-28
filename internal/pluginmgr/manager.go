package pluginmgr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Spec is one plugin process: a plugin type in one zone, with that zone's
// instances (ADR-03). A builtin is served in-process instead (§5.1).
type Spec struct {
	Type      string
	Kind      pluginv2.PluginKind
	Builtin   bool
	Binary    string // a file name in plugins.directory; not for a builtin
	SHA256    []byte
	Zone      config.Zone
	Instances []*pluginv2.InstanceDescriptor
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
}

// exitPoll is how often a supervisor checks that its process is alive.
const exitPoll = 50 * time.Millisecond

type key struct {
	kind     pluginv2.PluginKind
	instance string
}

// Manager runs the plugin processes, restarts them when they crash, and
// mediates every RPC (§5.2, §5.3).
type Manager struct {
	opts  Options
	log   *slog.Logger
	procs []*process
	byKey map[key]*process
	sems  map[key]chan struct{}
	stop  chan struct{}
	wg    sync.WaitGroup
}

type process struct {
	spec      Spec
	described *pluginv2.DescribeResponse // at the first start; Describe is static (§5.2)
	mu        sync.RWMutex
	client    *Client // nil while the process is down
	resolved  map[string]string
}

// New prepares a manager; Start launches the processes.
func New(specs []Spec, opts Options) *Manager {
	m := &Manager{
		opts:  opts,
		log:   slog.New(pluginsdk.NewRedactingHandler(opts.Logger.Handler())),
		byKey: map[key]*process{}, sems: map[key]chan struct{}{}, stop: make(chan struct{}),
	}
	for _, s := range specs {
		p := &process{spec: s}
		m.procs = append(m.procs, p)
		for _, in := range s.Instances {
			in.Zone, in.TrustDomain = s.Zone.Name, s.Zone.TrustDomain // the process's zone is its instances'
			k := key{s.Kind, in.GetName()}
			m.byKey[k] = p
			m.sems[k] = make(chan struct{}, max(opts.MaxConcurrentRPCsPerInstance, 1))
		}
	}
	return m
}

// Start launches every process in two passes (§5.2): it spawns and
// describes them all, checks every instance's config against its plugin's
// schema (rule 8) and every platform's wiring (rule 3), then configures their instances and checks the SVIDs
// they resolved: one each, in the zone's trust domain (INV-10), distinct
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
	if err := m.wire(); err != nil {
		return err
	}
	owners := map[string][]*pluginv2.InstanceDescriptor{}
	for _, p := range m.procs {
		resolved, err := m.configure(ctx, p.client, p.spec)
		if err != nil {
			return fmt.Errorf("%s: %w", what(p.spec), err)
		}
		p.resolved = resolved
		for _, in := range p.spec.Instances {
			if !p.spec.Builtin { // builtins hold no SVID
				owners[resolved[in.GetName()]] = append(owners[resolved[in.GetName()]], in)
			}
		}
	}
	for id, ins := range owners {
		for _, in := range ins {
			if len(ins) > 1 && !in.GetAllowSharedSvid() {
				return fmt.Errorf("instance %q: SVID %s is resolved by %d instances and allow_shared_svid is not set", in.GetName(), id, len(ins))
			}
		}
	}
	for _, p := range m.procs {
		if !p.spec.Builtin { // builtins cannot crash apart from ligo
			m.wg.Go(func() { m.supervise(p) })
		}
	}
	return nil
}

func what(s Spec) string { return fmt.Sprintf("plugin %s in zone %s", s.Type, s.Zone.Name) }

// spawn starts one process from its checked binary, or a builtin, and
// checks what it describes.
func (m *Manager) spawn(ctx context.Context, s Spec) (*Client, *pluginv2.DescribeResponse, error) {
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
		w := &hclogWriter{log: m.log.With("plugin", s.Type, "zone", s.Zone.Name)}
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
	return c, d, nil
}

func (m *Manager) describe(ctx context.Context, c *Client, s Spec) (*pluginv2.DescribeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	d, err := c.Control.Describe(ctx, &pluginv2.DescribeRequest{})
	if err != nil {
		return nil, fmt.Errorf("describe: %w", err)
	}
	if d.GetPluginType() != s.Type || d.GetKind() != s.Kind || d.GetPluginProtocolVersion() != 1 {
		return nil, fmt.Errorf("describes itself as %s, kind %v, protocol %d", d.GetPluginType(), d.GetKind(), d.GetPluginProtocolVersion())
	}
	if !capabilitiesOfKind(d) {
		return nil, fmt.Errorf("describes capabilities %T for kind %v", d.GetCapabilities(), d.GetKind())
	}
	if d.GetKind() == pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER && d.GetIdentityProvider().GetProducedIdentityMode() == pluginv2.IdentityMode_IDENTITY_MODE_UNSPECIFIED {
		return nil, errors.New("produces identity mode IDENTITY_MODE_UNSPECIFIED")
	}
	return d, nil
}

func (m *Manager) configure(ctx context.Context, c *Client, s Spec) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	r, err := c.Control.ConfigureInstances(ctx, &pluginv2.ConfigureInstancesRequest{
		Zone: s.Zone.Name, SpiffeWorkloadSocket: s.Zone.SPIFFEWorkloadSocket, Instances: s.Instances,
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
		if id.TrustDomain().Name() != s.Zone.TrustDomain {
			return nil, fmt.Errorf("instance %q: resolved %s, outside the zone's trust domain %s", in.GetName(), id, s.Zone.TrustDomain)
		}
		m.log.Info("plugin instance resolved", "plugin", s.Type, "zone", s.Zone.Name, "instance", in.GetName(), "spiffe_id", id.String())
	}
	return resolved, nil
}

// wire checks every platform's wiring against what its plugins describe and
// fills its descriptor's identity mode and secret storage strategy (§5.6,
// §8.2 rule 3). Processes of one type describe the same, whatever the zone.
func (m *Manager) wire() error {
	described := map[key]*pluginv2.DescribeResponse{} // the instance field holds the type
	for _, p := range m.procs {
		described[key{p.spec.Kind, p.spec.Type}] = p.described
	}
	for _, p := range m.procs {
		if p.spec.Kind != pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER {
			continue
		}
		for _, in := range p.spec.Instances {
			if err := wirePlatform(in, p.described.GetPlatformProvider(), described); err != nil {
				return fmt.Errorf("platform %q: %w", in.GetName(), err)
			}
		}
	}
	return nil
}

func wirePlatform(in *pluginv2.InstanceDescriptor, platform *pluginv2.PlatformProviderCapabilities, described map[key]*pluginv2.DescribeResponse) error {
	idp, ok := described[key{pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, in.GetIdentityProviderType()}]
	if !ok {
		return fmt.Errorf("no identity provider of type %q", in.GetIdentityProviderType())
	}
	mode := idp.GetIdentityProvider().GetProducedIdentityMode()
	if !slices.Contains(platform.GetAcceptedIdentityModes(), mode) {
		return fmt.Errorf("identity provider %s produces %v, which the platform does not accept (%v)", in.GetIdentityProviderType(), mode, platform.GetAcceptedIdentityModes())
	}
	store, ok := described[key{pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE, in.GetSecretStoreType()}]
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

// checkConfigs validates every instance's config against the plugin's
// instance configuration schema (§8.2 rule 8).
func checkConfigs(d *pluginv2.DescribeResponse, instances []*pluginv2.InstanceDescriptor) error {
	schema, err := compileSchema(d.GetInstanceConfigSchemaJson())
	if err != nil {
		return fmt.Errorf("instance configuration schema: %w", err)
	}
	for _, in := range instances {
		cfg, err := jsonschema.UnmarshalJSON(strings.NewReader(in.GetConfigJson()))
		if err != nil {
			return fmt.Errorf("instance %q: config: %w", in.GetName(), err)
		}
		if err := schema.Validate(cfg); err != nil {
			return fmt.Errorf("instance %q: config: %w", in.GetName(), err)
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
func capabilitiesOfKind(d *pluginv2.DescribeResponse) bool {
	switch d.GetCapabilities().(type) {
	case *pluginv2.DescribeResponse_IdentityProvider:
		return d.GetKind() == pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER
	case *pluginv2.DescribeResponse_PlatformProvider:
		return d.GetKind() == pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER
	case *pluginv2.DescribeResponse_SecretStore:
		return d.GetKind() == pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE
	}
	return false
}

// supervise restarts the process when it exits, with exponential backoff;
// a restarted process must resolve the same SVIDs as before.
func (m *Manager) supervise(p *process) {
	backoff := m.opts.Backoff.Initial
	for {
		select {
		case <-m.stop:
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
			m.log.Warn("plugin process exited", "plugin", p.spec.Type, "zone", p.spec.Zone.Name)
			p.client.Kill()
			p.client = nil
		}
		p.mu.Unlock()
		select {
		case <-m.stop:
			return
		case <-time.After(backoff):
		}
		c, d, err := m.spawn(context.Background(), p.spec)
		if err == nil {
			err = m.reconfigure(c, d, p)
		}
		if err != nil {
			m.log.Error("plugin restart failed", "plugin", p.spec.Type, "zone", p.spec.Zone.Name, "error", err, "retry_in", backoff)
			backoff = min(backoff*2, m.opts.Backoff.Max)
			continue
		}
		p.mu.Lock()
		p.client = c
		p.mu.Unlock()
		backoff = m.opts.Backoff.Initial
		m.log.Info("plugin process restarted", "plugin", p.spec.Type, "zone", p.spec.Zone.Name)
	}
}

// reconfigure checks that a restarted process describes itself as at the
// first start, configures it, and checks that it resolves the same SVIDs;
// on failure it kills the process.
func (m *Manager) reconfigure(c *Client, d *pluginv2.DescribeResponse, p *process) error {
	err := errors.New("the restarted process describes itself differently")
	if proto.Equal(d, p.described) {
		var resolved map[string]string
		if resolved, err = m.configure(context.Background(), c, p.spec); err == nil && !sameResolution(resolved, p.resolved) {
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
func (m *Manager) Call(ctx context.Context, kind pluginv2.PluginKind, instance string, mutating bool, fn func(context.Context, *Client) error) error {
	k := key{kind, instance}
	p, ok := m.byKey[k]
	if !ok {
		return fmt.Errorf("no plugin instance %q of kind %v", instance, kind)
	}
	if mutating {
		select {
		case m.sems[k] <- struct{}{}:
			defer func() { <-m.sems[k] }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.RLock()
	c := p.client
	p.mu.RUnlock()
	if c == nil {
		return errUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	err := fn(ctx, c)
	if status.Code(err) == codes.Unavailable {
		if _, d := pluginsdk.FromError(err); d.GetCode() == "PLUGIN_ERROR" { // the transport's, not the plugin's
			return errUnavailable
		}
	}
	return err
}

// Resolved is the SPIFFE ID an instance resolved at startup.
func (m *Manager) Resolved(kind pluginv2.PluginKind, instance string) string {
	p, ok := m.byKey[key{kind, instance}]
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
	for _, p := range m.procs {
		p.mu.Lock()
		if p.client != nil {
			p.client.Kill()
			p.client = nil
		}
		p.mu.Unlock()
	}
}
