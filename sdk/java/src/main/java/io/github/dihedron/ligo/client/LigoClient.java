// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

    private X509Source source;
    private boolean ownsSource;
    private Rest rest;
    private boolean closed;

    private LigoClient(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.serverId = b.serverId;
        this.pollInterval = b.pollInterval;
        this.source = b.x509Source;
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
        return get("/v1/bindings", query, bindings, filter.target() + "\u0000" + filter.platformType()).stream()
                .map(Documents::binding).toList();
    }

    public CompletableFuture<List<Binding>> bindingsAsync(Filter filter) {
        return CompletableFuture.supplyAsync(() -> bindings(filter), executor);
    }

    /** The network flows of the workload's bindings, for one target or all. Data only. */
    public List<BindingFlows> flows(String target) {
        String t = target == null ? "" : target;
        return get("/v1/flows", t.isEmpty() ? Map.of() : Map.of("target", t), flows, t).stream()
                .map(Documents::flows).toList();
    }

    public CompletableFuture<List<BindingFlows>> flowsAsync(String target) {
        return CompletableFuture.supplyAsync(() -> flows(target), executor);
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

    @Override
    public synchronized void close() {
        closed = true;
        bindings.clear();
        flows.clear();
        rest = null;
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

    private List<com.fasterxml.jackson.databind.JsonNode> get(String path, Map<String, String> query,
            Map<String, Cached> cache, String key) {
        Cached known = cache.get(key);
        Rest.Answer a = rest().get(path, query, known == null ? "" : known.etag());
        if (a.notModified() && known != null) {
            return known.items();
        }
        if (a.notModified()) {
            throw new LigoException("ligo answered not modified to a request with no ETag");
        }
        cache.put(key, new Cached(a.etag(), a.items()));
        return a.items();
    }

    private synchronized Rest rest() {
        if (closed) {
            throw new LigoException("the client is closed");
        }
        if (rest == null) {
            X509Source s = source();
            Tls.check(s, serverId);
            HttpClient http = HttpClient.newBuilder().sslContext(Tls.context(s, serverId))
                    .sslParameters(Tls.parameters()).connectTimeout(Rest.CALL_TIMEOUT)
                    .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
            rest = new Rest(http, host, port);
        }
        return rest;
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
            String h = i < 0 ? "" : address.substring(0, i).replaceAll("^\\[|]$", "");
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

        private Builder() {}

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
