// Package serve is ligo serve: the control-plane daemon, started and
// stopped in the normative order of §8.2.
package serve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/identity"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/server/adminhttp"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/startup"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/dihedron/ligo/internal/workflows"
	"github.com/dihedron/ligo/pkg/pluginsdk"
)

// drain is how long shutdown waits for active requests (§8.2).
const drain = 15 * time.Second

// Serve runs the daemon (§8.4 ServeCommand).
type Serve struct {
	ConfigFile            string `short:"c" long:"config" env:"LIGO_CONFIG" default:"/etc/ligo/server.yaml" description:"Path to server.yaml configuration file."`
	InsecureDev           bool   `long:"insecure-dev" description:"Allow local-kek secret sealer for local development ONLY."`
	AllowOrphanedBindings bool   `long:"allow-orphaned-bindings" description:"Allow startup even if existing DB bindings reference removed provider instances."`
	MaintenanceMode       bool   `long:"maintenance" env:"LIGO_MAINTENANCE_MODE" description:"Turn maintenance mode ON at startup (stored in the database, applies to all replicas; turn it off with 'ligo maintenance off')."`
	AcceptScopeChanges    bool   `long:"accept-scope-changes" description:"Re-scope sources, targets and bindings whose stored scopes no longer match the configuration (§8.2 rule 17; audited, pending change requests fail)."`

	insecureDB bool // the tests' database container has no TLS; never set by a flag
}

// Execute runs until SIGINT or SIGTERM, then shuts down in order.
func (cmd *Serve) Execute([]string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log := slog.New(pluginsdk.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	if err := cmd.run(ctx, log); err != nil {
		log.Error("ligo serve", "error", err)
		return err
	}
	return nil
}

// env reads the value of the environment variable a configuration key
// names.
func env(key, name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("serve: %s: environment variable %q is not set", key, name)
}

// run is the startup sequence of §8.2; its deferred calls are the shutdown
// sequence, in reverse: listeners, background loops, DBOS, plugins, SPIRE
// and the database pools.
func (cmd *Serve) run(ctx context.Context, log *slog.Logger) error {
	// 1. configuration and static checks
	cfg, sum, err := config.Load(cmd.ConfigFile)
	if err != nil {
		return err
	}
	log.Info("configuration", "path", cmd.ConfigFile, "sha256", sum)
	if err := config.Validate(cfg, config.Options{InsecureDev: cmd.InsecureDev}); err != nil {
		return err
	}

	// 2. database, and the checks that need it
	pg := cfg.Storage.Postgres
	appDSN, err := env("storage.postgres.app_dsn_env", pg.AppDSNEnv)
	if err != nil {
		return err
	}
	readerDSN, err := env("storage.postgres.reader_dsn_env", pg.ReaderDSNEnv)
	if err != nil {
		return err
	}
	dbosDSN, err := env("storage.postgres.dbos_dsn_env", pg.DBOSDSNEnv)
	if err != nil {
		return err
	}
	pools, err := store.Open(ctx, appDSN, readerDSN, cmd.insecureDB)
	if err != nil {
		return err
	}
	defer pools.Close()
	srcRules, err := sources.NewRules(cfg)
	if err != nil {
		return err
	}
	checks := &startup.Checks{DB: pools.App, Config: cfg, ConfigSHA256: sum, Extractors: srcRules.Extractors,
		AllowOrphanedBindings: cmd.AllowOrphanedBindings, AcceptScopeChanges: cmd.AcceptScopeChanges, Logger: log}
	if err := checks.Run(ctx); err != nil {
		return err
	}
	if cmd.MaintenanceMode {
		if err := changerequests.SetMaintenance(ctx, pools.App, "system:startup", nil, true, "set at startup by ligo serve --maintenance"); err != nil {
			return err
		}
		log.Warn("maintenance mode is on")
	}

	// 3. SPIRE: every zone, the composite bundle source, the core identity
	zones, err := identity.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = zones.Close() }()

	// 4. the sealer
	sealer, err := cmd.sealer(ctx, cfg, zones)
	if err != nil {
		return err
	}

	// 5. the plugins, and the checks that need them
	specs, err := pluginmgr.Specs(cfg)
	if err != nil {
		return err
	}
	p := cfg.Plugins
	plugins := pluginmgr.New(specs, pluginmgr.Options{Directory: p.Directory, Owner: pluginmgr.Root, RPCTimeout: p.RPCTimeout,
		MaxConcurrentRPCsPerInstance: p.MaxConcurrentRPCsPerInstance, Backoff: p.RestartBackoff, Logger: log})
	defer plugins.Stop()
	if err := plugins.Start(ctx); err != nil {
		return err
	}
	if err := checks.Strategies(ctx, plugins.Strategies); err != nil {
		return err
	}
	if err := checks.Platforms(ctx, targets.Plugins(plugins)); err != nil {
		return err
	}
	engine := &workflows.Engine{DB: pools.App, Plugins: workflows.Manager(plugins), Sealer: sealer,
		Backoff: workflows.Backoff{Attempts: p.Retry.MaxAttempts, Initial: p.Retry.InitialBackoff, Max: p.Retry.MaxBackoff}}
	health(ctx, log, cfg, engine.Plugins)

	// 6. DBOS: every dependency of the workflow steps is ready
	d, err := dbos.NewContext(ctx, dbos.Config{AppName: "ligo", DatabaseURL: dbosDSN, DatabaseSchema: "dbos",
		ApplicationVersion: cfg.Service.ApplicationVersion, ExecutorID: os.Getenv(cfg.Service.InstanceIDEnv), Logger: log})
	if err != nil {
		return fmt.Errorf("serve: DBOS: %w", err)
	}
	engine.DBOS = d
	engine.Register()
	if err := dbos.Launch(d); err != nil {
		return fmt.Errorf("serve: DBOS: %w", err)
	}
	defer func() {
		if err := dbos.Shutdown(d, drain); err != nil {
			log.Warn("DBOS shutdown", "error", err)
		}
	}()

	s, err := services(cfg, pools, srcRules, plugins, engine)
	if err != nil {
		return err
	}

	// 7. the workload resolution cache starts with the workload listener (phase 8)

	// 8. the background loops
	loops, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	run := func(f func(context.Context)) { wg.Go(func() { f(loops) }) }
	rotation := map[string]time.Duration{}
	for _, pp := range cfg.PlatformProviders {
		for _, pl := range pp.Platforms {
			rotation[pl.Name] = pl.RotationInterval
		}
	}
	run((&workflows.Sweeper{Engine: engine, Retention: cfg.Storage.DBOS.WorkflowRetention, Bindings: s.Bindings,
		ExpiryWarning: cfg.Bindings.ExpiryWarning}).Run)
	if rc := cfg.Reconciliation; rc.Enabled {
		run((&workflows.Reconciler{Engine: engine, Interval: rc.Interval, Jitter: rc.Jitter, MaxConcurrent: rc.MaxConcurrent, Rotation: rotation}).Run)
	}
	run((&bindings.Propagator{Service: s.Bindings, Interval: cfg.Propagation.Interval, MaxConcurrent: cfg.Propagation.MaxConcurrent}).Run)

	// 9. the admin listener (the workload listener comes in phase 8)
	return cmd.listen(ctx, log, cfg, zones, s)
}

// sealer is secret_sealing's provider, checked for key availability.
func (cmd *Serve) sealer(ctx context.Context, cfg *config.Config, zones *identity.Zones) (*sealing.Sealer, error) {
	var kek sealing.KEK
	var err error
	switch ss := cfg.SecretSealing; ss.Provider {
	case "vault-transit":
		kek, err = sealing.NewTransitKEK(ss.VaultTransit, zones, &http.Client{Timeout: 10 * time.Second})
	case "local-kek":
		kek, err = sealing.NewLocalKEK(ss.LocalKEKFile, cmd.InsecureDev)
	default:
		err = fmt.Errorf("unknown provider %q", ss.Provider)
	}
	if err == nil {
		err = kek.Check(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("serve: secret_sealing: %w", err)
	}
	return sealing.NewSealer(kek), nil
}

// health runs the initial Health check of every instance; a plugin that
// does not serve yet is logged, and the workflows check it again before
// each stage (§6.2).
func health(ctx context.Context, log *slog.Logger, cfg *config.Config, p workflows.Plugins) {
	check := func(kind pluginv1.PluginKind, name string) {
		if err := p.Health(ctx, kind, name); err != nil {
			log.Warn("a plugin instance is not healthy", "kind", kind, "instance", name, "error", err)
		}
	}
	for _, pp := range cfg.PlatformProviders {
		for _, pl := range pp.Platforms {
			check(pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, pl.Name)
		}
	}
	for kind, group := range map[pluginv1.PluginKind][]config.InstanceProvider{
		pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER: cfg.IdentityProviders, pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE: cfg.SecretStores} {
		for _, ip := range group {
			for _, in := range ip.Instances {
				check(kind, in.Name)
			}
		}
	}
}

// services wires the resources and their change requests.
func services(cfg *config.Config, pools *store.Pools, srcRules *sources.Rules, plugins *pluginmgr.Manager, engine *workflows.Engine) (*adminhttp.Server, error) {
	bindingRules, err := bindings.NewRules(cfg)
	if err != nil {
		return nil, err
	}
	targetRules, err := targets.NewRules(cfg)
	if err != nil {
		return nil, err
	}
	requests := &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: cfg.Authorization.Approval.ChangeRequestTTL,
		Resources: map[string]changerequests.Resource{}, BreakGlassRules: cfg.BreakGlass}
	ss := &sources.Service{DB: pools.App, Rules: srcRules, Requests: requests}
	ts := &targets.Service{DB: pools.App, Rules: targetRules, Requests: requests, Validate: targets.Plugins(plugins)}
	bs := &bindings.Service{DB: pools.App, Rules: bindingRules, Requests: requests, Validate: bindings.Plugins(plugins), Sources: ss,
		Start: func(ctx context.Context, id uuid.UUID) error { _, err := engine.Start(ctx, id); return err }}
	requests.Resources["SOURCE"], requests.Resources["TARGET"], requests.Resources["BINDING"] = ss, ts, bs
	az, err := authz.New(cfg.Authorization.Bindings)
	if err != nil {
		return nil, err
	}
	return &adminhttp.Server{Listener: cfg.Server.AdminListener, Config: cfg, Authz: az, DB: pools.App, Requests: requests,
		Bindings: bs, Sources: ss, Targets: ts, Workflows: engine, Catalog: &catalog.Reader{DB: pools.App, Policy: requests.Policy},
		Plugins: adminhttp.PlatformPlugins(plugins)}, nil
}

// listen serves the admin API until ctx ends, then drains it; SIGHUP
// reloads the certificate files, everything else needs a restart.
func (cmd *Serve) listen(ctx context.Context, log *slog.Logger, cfg *config.Config, zones *identity.Zones, s *adminhttp.Server) error {
	l := cfg.Server.AdminListener
	s.Bundles, s.Logger = zones, log
	var directory *adminauth.LDAP
	if l.AllowBasicAuth {
		var err error
		if directory, err = ldap(cfg); err != nil {
			return err
		}
		s.LDAP = directory
	}
	cert, reloadCert, err := certificate(l, zones)
	if err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	srv := &http.Server{Addr: l.ListenAddress, Handler: s.Handler(), TLSConfig: s.TLSConfig(cert), ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServeTLS("", "") }()
	log.Info("serving", "admin", l.ListenAddress)
	for done := false; !done; {
		select {
		case err := <-failed:
			return fmt.Errorf("serve: admin listener: %w", err)
		case <-hup:
			reload(log, cfg, reloadCert, directory)
		case <-ctx.Done():
			done = true
		}
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("admin listener drain", "error", err)
	}
	return nil
}

// reload is SIGHUP: it reloads the admin listener's certificate files and
// the directory's CA file; a file that fails to load keeps the old one.
func reload(log *slog.Logger, cfg *config.Config, reloadCert func() error, directory *adminauth.LDAP) {
	if reloadCert != nil {
		if err := reloadCert(); err != nil {
			log.Error("SIGHUP: the admin certificate is unchanged", "error", err)
		} else {
			log.Info("SIGHUP: admin certificate reloaded", "file", cfg.Server.AdminListener.TLSCertFile)
		}
	}
	if file := cfg.AdminAuth.LDAP.CACertFile; directory != nil && file != "" {
		roots, err := caPool(file)
		if err != nil {
			log.Error("SIGHUP: the directory's CA is unchanged", "error", err)
			return
		}
		directory.SetRootCAs(roots)
		log.Info("SIGHUP: directory CA reloaded", "file", file)
	}
}

// certificate is the admin listener's: the core identity's SVID, rotated
// by SPIRE, or the configured files, which the returned function reloads
// (nil for SPIRE).
func certificate(l config.AdminListener, zones *identity.Zones) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), func() error, error) {
	if l.TLSSource == "file" {
		var current atomic.Pointer[tls.Certificate]
		load := func() error {
			pair, err := tls.LoadX509KeyPair(l.TLSCertFile, l.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("serve: admin_listener: %w", err)
			}
			current.Store(&pair)
			return nil
		}
		if err := load(); err != nil {
			return nil, nil, err
		}
		return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil }, load, nil
	}
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		svid, err := zones.GetX509SVID()
		if err != nil {
			return nil, err
		}
		chain := make([][]byte, 0, len(svid.Certificates))
		for _, c := range svid.Certificates {
			chain = append(chain, c.Raw)
		}
		return &tls.Certificate{Certificate: chain, PrivateKey: svid.PrivateKey, Leaf: svid.Certificates[0]}, nil
	}, nil, nil
}

// caPool reads a PEM file of CA certificates.
func caPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file) //nolint:gosec // the path comes from the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("serve: admin_auth.ldap.ca_cert_file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("serve: admin_auth.ldap.ca_cert_file %s: no certificate", file)
	}
	return roots, nil
}

// ldap is the directory of admin_auth.ldap, for allow_basic_auth.
func ldap(cfg *config.Config) (*adminauth.LDAP, error) {
	c := cfg.AdminAuth.LDAP
	password, err := env("admin_auth.ldap.service_bind_password_env", c.ServiceBindPasswordEnv)
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if c.CACertFile != "" {
		if roots, err = caPool(c.CACertFile); err != nil {
			return nil, err
		}
	}
	var groups []string
	for _, b := range cfg.Authorization.Bindings {
		if b.LDAPGroupDN != "" {
			groups = append(groups, b.LDAPGroupDN)
		}
	}
	return &adminauth.LDAP{Config: c, BindPassword: password, RootCAs: roots, Groups: groups}, nil
}
