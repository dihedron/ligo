package pluginmgr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Spec is one plugin process: an external plugin type in one zone, with
// that zone's instances (ADR-03).
type Spec struct {
	Type      string
	Kind      pluginv2.PluginKind
	Binary    string // a file name in plugins.directory
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
	spec     Spec
	mu       sync.RWMutex
	client   *Client // nil while the process is down
	resolved map[string]string
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

// Start launches every process and checks the SVIDs its instances resolved:
// one each, in the zone's trust domain (INV-10), distinct unless every
// instance sharing one allows it (ADR-03). Any failure is fatal and names
// the instance (AC-15).
func (m *Manager) Start(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.Stop()
		}
	}()
	owners := map[string][]*pluginv2.InstanceDescriptor{}
	for _, p := range m.procs {
		c, resolved, err := m.launch(ctx, p.spec)
		if err != nil {
			return err
		}
		p.client, p.resolved = c, resolved
		for _, in := range p.spec.Instances {
			owners[resolved[in.GetName()]] = append(owners[resolved[in.GetName()]], in)
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
		m.wg.Go(func() { m.supervise(p) })
	}
	return nil
}

// launch starts one process from its checked binary, checks what it
// describes, and configures its instances.
func (m *Manager) launch(ctx context.Context, s Spec) (*Client, map[string]string, error) {
	what := fmt.Sprintf("plugin %s in zone %s", s.Type, s.Zone.Name)
	b, err := OpenBinary(m.opts.Directory, s.Binary, s.SHA256, m.opts.Owner)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	cmd := b.Command()
	cmd.Env = s.Env
	w := &hclogWriter{log: m.log.With("plugin", s.Type, "zone", s.Zone.Name)}
	c, err := Start(cmd, s.Kind, b.Checksum(), newHCLogger(w), w)
	_ = b.Close() // the process holds the binary now
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	resolved, err := m.configure(ctx, c, s)
	if err != nil {
		c.Kill()
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	return c, resolved, nil
}

func (m *Manager) configure(ctx context.Context, c *Client, s Spec) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.opts.RPCTimeout)
	defer cancel()
	d, err := c.Control.Describe(ctx, &pluginv2.DescribeRequest{})
	if err != nil {
		return nil, fmt.Errorf("describe: %w", err)
	}
	if d.GetPluginType() != s.Type || d.GetKind() != s.Kind || d.GetPluginProtocolVersion() != 1 {
		return nil, fmt.Errorf("describes itself as %s, kind %v, protocol %d", d.GetPluginType(), d.GetKind(), d.GetPluginProtocolVersion())
	}
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
		down := p.client == nil || p.client.process.Exited()
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
		c, resolved, err := m.launch(context.Background(), p.spec)
		if err == nil && !sameResolution(resolved, p.resolved) {
			c.Kill()
			err = errors.New("the restarted process resolved other SVIDs")
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
