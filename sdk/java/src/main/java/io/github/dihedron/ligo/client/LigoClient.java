// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.exception.JwtSourceException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import io.spiffe.workloadapi.DefaultJwtSource;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import java.io.Closeable;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * The client of ligo's workload API (.specs/ligo-client-sdk-java.md §3). It is thread-safe. The builder validates
 * and calls nothing; the default SPIFFE source (the Workload API on SPIFFE_ENDPOINT_SOCKET) is opened on first use and
 * closed by {@link #close()}. A source the caller gives is the caller's to close.
 */
public final class LigoClient implements AutoCloseable {
    /** How the client talks to ligo: both verify the server's SPIFFE ID in the handshake and give the same answers. */
    public enum Transport { REST, GRPC }

    static final Duration MIN_POLL = Duration.ofSeconds(5); // T-C6
    static final Duration DEFAULT_POLL = Duration.ofSeconds(30);

    private record Cached(String etag, List<com.fasterxml.jackson.databind.JsonNode> items) {}

    private final String host;
    private final int port;
    private final SpiffeId serverId;
    private final Duration pollInterval;
    private final Executor executor;
    private final ExecutorService ownedExecutor;
    private final Map<String, Cached> bindings = new ConcurrentHashMap<>();
    private final Map<String, Cached> flows = new ConcurrentHashMap<>();
    private final Set<String> allowedStores;
    private final List<X509Certificate> storeRoots;
    private final Transport transport;
    private final Clock clock;
    private final System.Logger log;
    private final Set<Watch> watches = new CopyOnWriteArraySet<>();
    private final Watcher.Sleeper sleeper;
    private final AtomicInteger watchCount = new AtomicInteger();
    private final Map<TokenKey, Token> tokens = new ConcurrentHashMap<>();

    /** Where a store token was got: the same store, namespace, mount and role share one. */
    private record TokenKey(String address, String namespace, String mount, String role) {}

    private record Token(String value, Instant until) {}

    private X509Source source;
    private boolean ownsSource;
    private JwtSvidSource jwtSource;
    private Closeable ownedJwt;
    private Wire wire;
    private Store store;
    private volatile boolean closed;

    private LigoClient(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.serverId = b.serverId;
        this.pollInterval = b.pollInterval;
        this.source = b.x509Source;
        this.jwtSource = b.jwtSource;
        this.allowedStores = Set.copyOf(b.allowedStores);
        this.storeRoots = List.copyOf(b.storeRoots);
        this.transport = b.transport;
        this.clock = b.clock;
        this.sleeper = b.sleeper;
        this.log = b.logger;
        if (b.executor != null) {
            this.executor = b.executor;
            this.ownedExecutor = null;
        } else {
            AtomicInteger n = new AtomicInteger();
            this.ownedExecutor = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "ligo-client-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            });
            this.executor = ownedExecutor;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The workload's bindings. A not-modified answer returns the remembered list; none is not an error. */
    public List<Binding> bindings(Filter filter) {
        Map<String, String> query = new LinkedHashMap<>();
        if (!filter.target().isEmpty()) {
            query.put("target", filter.target());
        }
        if (!filter.platformType().isEmpty()) {
            query.put("platformType", filter.platformType());
        }
        return get(Wire.Kind.BINDINGS, query, bindings, filter.target() + "\u0000" + filter.platformType()).stream()
                .map(Documents::binding).toList();
    }

    public CompletableFuture<List<Binding>> bindingsAsync(Filter filter) {
        return Async.run(executor, () -> bindings(filter));
    }

    /** The network flows of the workload's bindings, for one target or all. Data only. */
    public List<BindingFlows> flows(String target) {
        String t = target == null ? "" : target;
        return get(Wire.Kind.FLOWS, t.isEmpty() ? Map.of() : Map.of("target", t), flows, t).stream()
                .map(Documents::flows).toList();
    }

    public CompletableFuture<List<BindingFlows>> flowsAsync(String target) {
        return Async.run(executor, () -> flows(target));
    }

    /**
     * Reads the binding's credential from its secret store, logging in with a JWT-SVID. Every call reads the store:
     * with {@code vault-dynamic} each read makes a new credential, so read once and keep it until it expires.
     *
     * @throws NoCredentialException the strategy is {@code svid}: the SVID is the credential
     * @throws UnsupportedStrategy the strategy is not known to this SDK
     * @throws StoreNotAllowed the store's address is not https://host:port, or is not in {@code allowedStores}
     * @throws StoreError the store refused, answered badly or could not be reached
     * @throws Unauthorized no JWT-SVID could be fetched
     */
    public Credential credential(Binding binding) {
        try {
            return readCredential(binding);
        } catch (LigoException e) {
            throw withBinding(e, binding);
        }
    }

    public CompletableFuture<Credential> credentialAsync(Binding binding) {
        return Async.run(executor, () -> credential(binding));
    }

    /** Forgets the store login of the binding: call it when the target refuses the credential. */
    public void invalidate(Binding binding) {
        Map<String, String> cfg = binding.auth().config();
        try {
            tokens.remove(new TokenKey(Store.address(cfg.getOrDefault("address", "")), cfg.getOrDefault("namespace", ""),
                    cfg.getOrDefault("authMount", ""), cfg.getOrDefault("role", "")));
        } catch (IllegalArgumentException e) {
            // no such store address, so no remembered token
        }
    }

    /**
     * An mTLS connection with the workload's SVID, TLS 1.3, to a server that presents {@code serverId} and no other
     * ID. The handshake is done and the ID checked when this returns.
     */
    public SSLSocket connect(String address, String serverId, Duration timeout) {
        Address a = Address.parse(address);
        SpiffeId id = parseId(serverId);
        X509Source s = source();
        Tls.check(s, id);
        SSLContext ctx = Tls.context(s, id);
        try {
            SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket();
            try {
                socket.setSSLParameters(Tls.parameters());
                socket.setSoTimeout((int) timeout.toMillis());
                socket.connect(new java.net.InetSocketAddress(a.host, a.port), (int) timeout.toMillis());
                socket.startHandshake();
            } catch (IOException | RuntimeException e) {
                socket.close();
                throw e;
            }
            return socket;
        } catch (IOException e) {
            throw Rest.failure(e);
        }
    }

    /**
     * Reads the flows of the bindings and tests them (see {@link FlowCheck}). The defaults come from what the client
     * knows: a flow declared by ligo is verified as an X509-SVID against the client's own bundle, and a flow of a
     * PostgreSQL binding that a target or a platform declares asks for TLS inside the protocol. It runs when called,
     * never on its own, and its unstarted checks are skipped when the client is closed.
     */
    public FlowResults checkFlows(String target, FlowOptions options) {
        List<BindingFlows> flows = flows(target);
        FlowOptions.Builder b = options.toBuilder();
        if (options.platforms.isEmpty()) {
            Map<String, String> platforms = new LinkedHashMap<>();
            for (Binding binding : bindings(target == null || target.isEmpty() ? Filter.all() : Filter.target(target))) {
                platforms.put(binding.name(), binding.platformType());
            }
            b.platforms(platforms);
        }
        return checkFlowData(flows, b.build());
    }

    public CompletableFuture<FlowResults> checkFlowsAsync(String target, FlowOptions options) {
        return Async.run(executor, () -> checkFlows(target, options));
    }

    /** Tests flows obtained elsewhere, with the client's own bundle for the flows of ligo. */
    public FlowResults checkFlowData(List<BindingFlows> flows, FlowOptions options) {
        FlowOptions.Builder b = options.toBuilder().stop(() -> closed);
        if (options.spiffeBundle == null) {
            X509Source s = source();
            try {
                b.spiffeBundle(s.getBundleForTrustDomain(serverId.getTrustDomain()));
            } catch (io.spiffe.exception.BundleNotFoundException e) {
                throw new Unauthorized("the SPIFFE source has no bundle for the server's trust domain");
            }
        }
        return FlowCheck.run(flows, b.build());
    }

    public CompletableFuture<FlowResults> checkFlowDataAsync(List<BindingFlows> flows, FlowOptions options) {
        return Async.run(executor, () -> checkFlowData(flows, options));
    }

    /**
     * Polls the bindings that match and reports every change, blocking between polls; with
     * {@code WatchOptions.withCredentials()} it also reads the credential of each new or changed binding, and again at two
     * thirds of a lease. A failed poll keeps the state and is tried again later, with a backoff up to five minutes and
     * the server's Retry-After. The watch ends when it or the client is closed.
     */
    public Watch watch(Filter filter, WatchOptions options) {
        return startWatch(filter, options, null);
    }

    /** As {@link #watch(Filter, WatchOptions)}, with the events delivered to {@code listener} in order, on the watch's thread. */
    public Subscription watch(Filter filter, WatchOptions options, Consumer<Event> listener) {
        return startWatch(filter, options, Objects.requireNonNull(listener, "listener"));
    }

    private Watch startWatch(Filter filter, WatchOptions options, Consumer<Event> listener) {
        synchronized (this) {
            if (closed) {
                throw new LigoException("the client is closed");
            }
        }
        Watcher.Backend backend = new Watcher.Backend() {
            @Override
            public List<Binding> bindings() {
                return LigoClient.this.bindings(filter);
            }

            @Override
            public Credential credential(Binding binding) {
                return LigoClient.this.credential(binding);
            }
        };
        Watch[] holder = new Watch[1];
        Watch w = new Watch("ligo-watch-" + watchCount.incrementAndGet(), backend, clock, pollInterval, log,
                options.credentials(), listener, sleeper, () -> {
                    Watch self = holder[0];
                    if (self != null) {
                        watches.remove(self);
                    }
                });
        holder[0] = w;
        watches.add(w);
        return w;
    }

    /** Stops the watches and waits for their threads, forgets the store tokens, closes what the client opened. */
    @Override
    public void close() {
        for (Watch w : watches) {
            w.cancel(); // outside the lock: a watch in a call needs it to finish
        }
        watches.clear();
        closeResources();
    }

    private synchronized void closeResources() {
        closed = true;
        bindings.clear();
        flows.clear();
        tokens.clear();
        if (wire != null) {
            wire.close();
            wire = null;
        }
        store = null;
        if (ownedJwt != null) {
            try {
                ownedJwt.close();
            } catch (IOException e) {
                // nothing to do: the source is gone either way
            }
            ownedJwt = null;
            jwtSource = null;
        }
        if (ownsSource && source != null) {
            try {
                source.close();
            } catch (IOException e) {
                // nothing to do: the source is gone either way
            }
            source = null;
        }
        if (ownedExecutor != null) {
            ownedExecutor.shutdownNow();
        }
    }

    // -- internals

    private Credential readCredential(Binding b) {
        Auth auth = b.auth();
        Map<String, String> cfg = auth.config();
        String strategy = auth.strategy();
        if (strategy.isEmpty() || strategy.equals(Store.NONE)) {
            throw new NoCredentialException("the binding has no credential");
        }
        if (!strategy.equals(Store.STATIC) && !strategy.equals(Store.DYNAMIC)) {
            throw new UnsupportedStrategy("unsupported secret storage strategy \"" + strategy + "\"");
        }
        String path = cfg.getOrDefault(strategy.equals(Store.DYNAMIC) ? "credsPath" : "secretPath", "");
        String address;
        try {
            address = Store.address(cfg.getOrDefault("address", ""));
        } catch (IllegalArgumentException e) {
            throw new StoreNotAllowed("store address not allowed: " + e.getMessage());
        }
        if (!allowedStores.isEmpty() && !allowedStores.contains(address)) {
            throw new StoreNotAllowed("store address not allowed: " + address + " is not in allowedStores");
        }
        for (String k : List.of("audience", "authMount", "role")) {
            if (cfg.getOrDefault(k, "").isEmpty()) {
                throw new StoreError("the binding names no " + k);
            }
        }
        if (path.isEmpty()) {
            throw new StoreError("the binding names no path");
        }
        TokenKey key = new TokenKey(address, cfg.getOrDefault("namespace", ""), cfg.get("authMount"), cfg.get("role"));
        Store s = store();
        boolean fresh = false;
        Token token = tokens.get(key);
        if (token == null || !clock.instant().isBefore(token.until())) {
            token = login(s, b, key, cfg.get("audience"));
            fresh = true;
        }
        byte[] body;
        try {
            body = s.call(address, "GET", path, token.value(), key.namespace(), null);
        } catch (Store.CallException e) {
            if (e.status != 403 || fresh) {
                throw new StoreError("read: " + e.getMessage());
            }
            tokens.remove(key); // the remembered token may be revoked: one new login
            token = login(s, b, key, cfg.get("audience"));
            try {
                body = s.call(address, "GET", path, token.value(), key.namespace(), null);
            } catch (Store.CallException e2) {
                throw new StoreError("read: " + e2.getMessage());
            }
        }
        return Store.parseSecret(strategy, body, clock.instant());
    }

    private Token login(Store s, Binding b, TokenKey key, String audience) {
        String jwt = jwt(audience);
        byte[] data;
        try {
            data = s.call(key.address(), "POST", "auth/" + key.mount() + "/login", "", key.namespace(),
                    Store.loginBody(key.role(), jwt));
        } catch (Store.CallException e) {
            throw new StoreError("login: " + e.getMessage());
        }
        Store.Login l;
        try {
            l = Store.parseLogin(data);
        } catch (StoreError e) {
            throw new StoreError("login: " + e.getMessage());
        }
        log.log(System.Logger.Level.DEBUG, "store login: binding {0}, target {1}, store {2}", b.name(), b.target(),
                key.address());
        Token t = new Token(l.token(), clock.instant().plusMillis((long) (l.ttl().toMillis() * 0.8)));
        tokens.put(key, t);
        return t;
    }

    /** A JWT-SVID for the audience, with the identity of the X.509-SVID that fetched the bindings. */
    private String jwt(String audience) {
        JwtSvidSource j = jwtSource();
        try {
            JwtSvid svid = j.fetchJwtSvid(source().getX509Svid().getSpiffeId(), audience);
            String token = svid == null ? null : svid.getToken();
            if (token != null && !token.isEmpty()) {
                return token;
            }
        } catch (Exception e) { // the agent's errors may carry anything
            throw new Unauthorized("no JWT-SVID could be fetched: " + e.getClass().getSimpleName());
        }
        throw new Unauthorized("no JWT-SVID could be fetched");
    }

    private static LigoException withBinding(LigoException e, Binding b) {
        String m = "the credential of binding " + b.name() + ": " + e.getMessage();
        if (e instanceof NoCredentialException) {
            return new NoCredentialException(m);
        } else if (e instanceof UnsupportedStrategy) {
            return new UnsupportedStrategy(m);
        } else if (e instanceof StoreNotAllowed) {
            return new StoreNotAllowed(m);
        } else if (e instanceof StoreError) {
            return new StoreError(m);
        } else if (e instanceof Unauthorized) {
            return new Unauthorized(m);
        }
        return e;
    }

    private synchronized Store store() {
        if (closed) {
            throw new LigoException("the client is closed");
        }
        if (store == null) {
            store = new Store(storeRoots);
        }
        return store;
    }

    private synchronized JwtSvidSource jwtSource() {
        if (closed) {
            throw new LigoException("the client is closed");
        }
        if (jwtSource == null) {
            try {
                io.spiffe.workloadapi.JwtSource opened = DefaultJwtSource.newSource();
                ownedJwt = opened;
                jwtSource = opened;
            } catch (SocketEndpointAddressException | JwtSourceException e) {
                throw new Unavailable("cannot open the SPIFFE source: " + e.getClass().getSimpleName(), null, e);
            }
        }
        return jwtSource;
    }

    private List<com.fasterxml.jackson.databind.JsonNode> get(Wire.Kind kind, Map<String, String> query,
            Map<String, Cached> cache, String key) {
        Cached known = cache.get(key);
        Wire.Answer a = wire().get(kind, query, known == null ? "" : known.etag());
        if (a.notModified() && known != null) {
            return known.items();
        }
        if (a.notModified()) {
            throw new LigoException("ligo answered not modified to a request with no ETag");
        }
        cache.put(key, new Cached(a.etag(), a.items()));
        return a.items();
    }

    private synchronized Wire wire() {
        if (closed) {
            throw new LigoException("the client is closed");
        }
        if (wire == null) {
            X509Source s = source();
            Tls.check(s, serverId);
            if (transport == Transport.GRPC) {
                wire = new Grpc(host, port, s, serverId);
            } else {
                HttpClient http = HttpClient.newBuilder().sslContext(Tls.context(s, serverId))
                        .sslParameters(Tls.parameters()).connectTimeout(Rest.CALL_TIMEOUT)
                        .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
                wire = new Rest(http, host, port);
            }
        }
        return wire;
    }

    private synchronized X509Source source() {
        if (closed) {
            throw new LigoException("the client is closed");
        }
        if (source == null) {
            try {
                source = DefaultX509Source.newSource();
            } catch (SocketEndpointAddressException | X509SourceException e) {
                throw new Unavailable("cannot open the SPIFFE source: " + e.getClass().getSimpleName(), null, e);
            }
            ownsSource = true;
        }
        return source;
    }

    private static SpiffeId parseId(String id) {
        try {
            return SpiffeId.parse(id);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("serverId: " + e.getMessage(), e);
        }
    }

    private record Address(String host, int port) {
        static Address parse(String address) {
            Objects.requireNonNull(address, "address");
            int i = address.lastIndexOf(':');
            String h = i < 0 ? "" : address.substring(0, i).replaceAll("(?:^\\[|]$)", "");
            String p = i < 0 ? "" : address.substring(i + 1);
            if (h.isEmpty() || !p.matches("[0-9]{1,5}") || Integer.parseInt(p) > 65535 || address.contains("/")) {
                throw new IllegalArgumentException("address \"" + address + "\": host:port is required, with no scheme");
            }
            return new Address(h, Integer.parseInt(p));
        }
    }

    public static final class Builder {
        private String host;
        private int port;
        private SpiffeId serverId;
        private X509Source x509Source;
        private Duration pollInterval = DEFAULT_POLL;
        private Executor executor;
        private JwtSvidSource jwtSource;
        private Transport transport = Transport.REST;
        private Set<String> allowedStores = Set.of();
        private List<X509Certificate> storeRoots = List.of();
        private Clock clock = Clock.systemUTC();
        private Watcher.Sleeper sleeper;
        private System.Logger logger = System.getLogger("io.github.dihedron.ligo.client");

        private Builder() {}

        /** REST (the default) or gRPC. */
        public Builder transport(Transport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /** The JWT-SVIDs for the stores; the default is the Workload API on SPIFFE_ENDPOINT_SOCKET. */
        public Builder jwtSource(JwtSvidSource jwtSource) {
            this.jwtSource = jwtSource;
            return this;
        }

        /** The only stores {@code credential} logs in to, as https://host:port; empty (the default) allows any. */
        public Builder allowedStores(Collection<String> stores) {
            Set<String> set = new LinkedHashSet<>();
            for (String s : stores) {
                try {
                    set.add(Store.address(s));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("allowedStores: " + e.getMessage(), e);
                }
            }
            this.allowedStores = set;
            return this;
        }

        /** The trust anchors for the stores' certificates; the default is the JDK's. */
        public Builder storeRoots(Collection<X509Certificate> roots) {
            this.storeRoots = List.copyOf(roots);
            return this;
        }

        /** The trust anchors for the stores' certificates, from a PEM file. */
        public Builder storeRoots(Path pem) {
            try (var in = Files.newInputStream(pem)) {
                this.storeRoots = CertificateFactory.getInstance("X.509").generateCertificates(in).stream()
                        .map(X509Certificate.class::cast).toList();
            } catch (IOException | CertificateException e) {
                throw new IllegalArgumentException("storeRoots " + pem + ": " + e.getMessage(), e);
            }
            return this;
        }

        /** Where the client logs (store logins at DEBUG, never a secret); the default is the platform logger. */
        public Builder logger(System.Logger logger) {
            this.logger = Objects.requireNonNull(logger, "logger");
            return this;
        }

        /** How a watch waits; for tests. */
        Builder sleeper(Watcher.Sleeper sleeper) {
            this.sleeper = sleeper;
            return this;
        }

        /** The clock of the token cache and of the leases; for tests. */
        Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /** {@code host:port} of ligo's workload API; TLS always, no scheme. */
        public Builder address(String address) {
            Address a = Address.parse(address);
            this.host = a.host;
            this.port = a.port;
            return this;
        }

        /** The only SPIFFE ID the client accepts from the server. */
        public Builder serverId(String serverId) {
            this.serverId = parseId(serverId);
            return this;
        }

        /** The workload's SVID and bundles; the default is the Workload API on SPIFFE_ENDPOINT_SOCKET. */
        public Builder x509Source(X509Source x509Source) {
            this.x509Source = x509Source;
            return this;
        }

        /** How often {@code watch} polls; at least 5 seconds. */
        public Builder pollInterval(Duration pollInterval) {
            if (pollInterval.compareTo(MIN_POLL) < 0) {
                throw new IllegalArgumentException("pollInterval " + pollInterval + ": at least " + MIN_POLL);
            }
            this.pollInterval = pollInterval;
            return this;
        }

        /** Runs the async calls; the default is a daemon pool the client owns and shuts down in close(). */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor");
            return this;
        }

        public LigoClient build() {
            if (host == null) {
                throw new IllegalArgumentException("address: host:port is required");
            }
            if (serverId == null) {
                throw new IllegalArgumentException("serverId: a SPIFFE ID is required");
            }
            return new LigoClient(this);
        }
    }
}
