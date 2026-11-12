package pluginmgr

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/metrics"
	"google.golang.org/protobuf/proto"
)

// processKey names the process of a type in a realm.
func processKey(s Spec) string { return s.Type + "\x00" + s.Realm.Name }

// Reconcile brings the processes in line with specs, the instances in force
// grouped by type and realm (.specs/ligo-instances.md §7.2): a process is
// started for a new (type, realm), configured again when its instances
// change, and stopped when none is left. A process that refuses its new
// instances keeps its old ones, is counted in
// ligo_plugin_reconfigure_failures_total, and is tried again at the next
// reconcile; the errors are joined.
func (m *Manager) Reconcile(ctx context.Context, specs []Spec) error {
	m.reconciling.Lock()
	defer m.reconciling.Unlock()
	desired := map[string]Spec{}
	for _, s := range specs {
		place(s)
		desired[processKey(s)] = s
	}
	m.mu.RLock()
	current := slices.Clone(m.procs)
	m.mu.RUnlock()
	var errs []error
	for _, p := range current {
		k := processKey(p.spec) // type and realm never change
		s, ok := desired[k]
		delete(desired, k)
		if !ok {
			m.retire(p)
			continue
		}
		if err := m.wire(s.Kind, p.described, s.Instances); err != nil { // fills what the current descriptors hold
			errs = append(errs, m.failed(s, err))
			continue
		}
		if sameInstances(p.instances(), s.Instances) {
			continue
		}
		if err := m.apply(ctx, p, s.Instances); err != nil {
			errs = append(errs, m.failed(s, err))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(desired)) {
		if err := m.add(ctx, desired[k]); err != nil {
			errs = append(errs, m.failed(desired[k], err))
		}
	}
	return errors.Join(errs...)
}

// failed counts and logs a process that did not take its instances.
func (m *Manager) failed(s Spec, err error) error {
	metrics.ReconfigureFailures.WithLabelValues(s.Type, s.Realm.Name).Inc()
	m.log.Error("plugin instances not reconfigured: the process keeps its previous instances", "plugin", s.Type, "realm", s.Realm.Name, "error", err)
	return fmt.Errorf("%s: %w", what(s), err)
}

func sameInstances(a, b []*pluginv1.InstanceDescriptor) bool {
	return slices.EqualFunc(a, b, func(x, y *pluginv1.InstanceDescriptor) bool { return proto.Equal(x, y) })
}

// apply configures a running process with a new set of instances; on any
// refusal the process keeps serving the old set.
func (m *Manager) apply(ctx context.Context, p *process, ins []*pluginv1.InstanceDescriptor) error {
	p.mu.RLock()
	old, c := p.spec, p.client
	p.mu.RUnlock()
	if c == nil {
		return errors.New("the process is down")
	}
	spec := old
	spec.Instances = ins
	if err := checkConfigs(p.described, ins); err != nil {
		return err
	}
	v, err := validatorsFor(p.described, spec)
	if err != nil {
		return err
	}
	resolved, err := m.configure(ctx, c, spec)
	if err != nil {
		return err // the plugin keeps serving its previous set (protocol v2)
	}
	if err := m.sharedSVIDs(p, ins, resolved); err != nil {
		if _, restore := m.configure(ctx, c, old); restore != nil {
			m.log.Error("plugin instances: the previous set could not be restored", "plugin", old.Type, "realm", old.Realm.Name, "error", restore)
		}
		return err
	}
	p.mu.Lock()
	p.spec.Instances, p.resolved = ins, resolved
	p.mu.Unlock()
	var removed []*pluginv1.InstanceDescriptor
	for _, in := range old.Instances {
		if !slices.ContainsFunc(ins, func(x *pluginv1.InstanceDescriptor) bool { return x.GetName() == in.GetName() }) {
			removed = append(removed, in)
		}
	}
	m.mu.Lock()
	m.route(p, ins, removed)
	copyValidators(m.validators, v)
	m.mu.Unlock()
	m.log.Info("plugin instances reconfigured", "plugin", spec.Type, "realm", spec.Realm.Name, "instances", len(ins))
	return nil
}

// add starts the process of a new (type, realm) with its instances.
func (m *Manager) add(ctx context.Context, s Spec) (err error) {
	c, d, err := m.spawn(ctx, s)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			c.Kill()
		}
	}()
	if err := checkConfigs(d, s.Instances); err != nil {
		return err
	}
	if err := m.wire(s.Kind, d, s.Instances); err != nil {
		return err
	}
	v, err := validatorsFor(d, s)
	if err != nil {
		return err
	}
	resolved, err := m.configure(ctx, c, s)
	if err != nil {
		return err
	}
	p := &process{spec: s, described: d, client: c, resolved: resolved, stop: make(chan struct{})}
	if err := m.sharedSVIDs(p, s.Instances, resolved); err != nil {
		return err
	}
	m.mu.Lock()
	m.procs = append(m.procs, p)
	m.route(p, s.Instances, nil)
	copyValidators(m.validators, v)
	m.mu.Unlock()
	m.supervised(p)
	m.log.Info("plugin process started", "plugin", s.Type, "realm", s.Realm.Name, "instances", len(s.Instances))
	return nil
}

// retire stops a process none of whose instances is left.
func (m *Manager) retire(p *process) {
	close(p.stop)
	m.mu.Lock()
	m.procs = slices.DeleteFunc(m.procs, func(x *process) bool { return x == p })
	m.route(p, nil, p.instances())
	m.mu.Unlock()
	p.mu.Lock()
	if p.client != nil {
		p.client.Kill()
		p.client = nil
	}
	p.mu.Unlock()
	m.log.Info("plugin process stopped: no instance left", "plugin", p.spec.Type, "realm", p.spec.Realm.Name)
}

// Notify hands the manager the instances now in force; Run reconciles them
// once no change has come for Options.Debounce.
func (m *Manager) Notify(specs []Spec) {
	m.pendingMu.Lock()
	m.pending = specs
	m.pendingMu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Run reconciles what Notify hands over, debounced, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
		}
		timer := time.NewTimer(m.opts.Debounce)
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-m.kick:
				timer.Reset(m.opts.Debounce)
			case <-timer.C:
				waiting = false
			}
		}
		m.pendingMu.Lock()
		specs := m.pending
		m.pendingMu.Unlock()
		_ = m.Reconcile(ctx, specs) // logged and counted per process
	}
}

// transient starts a process of typ in realm that serves no instance, for
// checks; the caller kills it.
func (m *Manager) transient(ctx context.Context, typ, realm string) (*Client, *pluginv1.DescribeResponse, Spec, error) {
	t, ok := m.opts.Templates[typ]
	if !ok {
		return nil, nil, Spec{}, fmt.Errorf("plugin type %s is not configured", typ)
	}
	z, ok := m.opts.Realms[realm]
	if !ok {
		return nil, nil, Spec{}, fmt.Errorf("realm %s is not configured", realm)
	}
	s := t
	s.Realm = z
	c, d, err := m.spawn(ctx, s)
	return c, d, s, err
}
