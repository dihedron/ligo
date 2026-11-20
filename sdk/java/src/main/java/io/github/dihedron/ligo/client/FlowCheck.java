// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.bundle.x509bundle.X509Bundle;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Testing the flows of the bindings (.specs/ligo-client-sdk-java.md §5, .specs/ligo-network-checks.md §9), in the JDK
 * alone: a TCP connect, a TLS handshake verified by name, PostgreSQL's SSLRequest, an X509-SVID verified against a
 * trust bundle, and a UDP datagram. Nothing runs unless {@link #run} is called. A TCP flow is a connection test, or a
 * TLS handshake when the flow says tls; a UDP flow passes when no ICMP error comes back, which means "not refused",
 * not "the service is up"; a CIDR destination or a port range is skipped, with its reason. The check connects to an
 * address it has vetted against the denied networks, never to a name again (T-J8). ICMP is not supported.
 */
public final class FlowCheck {
    /** The most checks one call runs. */
    public static final int MAX_CHECKS = 1024;

    private static final byte[] SSL_REQUEST = {0, 0, 0, 8, 0x04, (byte) 0xD2, 0x16, 0x2F}; // PostgreSQL's SSLRequest
    private static final String TCP = "tcp";
    private static final String TLS = "tls";
    private static final String UDP = "udp";

    private FlowCheck() {}

    /** How TLS starts, from the binding that owns the flow. */
    interface Chooser {
        String choose(String binding, Flow flow, int port);
    }

    /** A flow declared by ligo is an SVID; a PostgreSQL binding's target or platform flow is PostgreSQL's. */
    static Chooser defaultChooser(Map<String, String> platforms) {
        return (binding, f, port) -> {
            if ("ligo".equals(f.declaredBy())) {
                return Handshake.SPIRE;
            }
            String platform = platforms.getOrDefault(binding, "");
            if ((platform.equals("postgres") || platform.startsWith("postgres."))
                    && (f.declaredBy().startsWith("target:") || f.declaredBy().startsWith("platform:"))) {
                return Handshake.POSTGRESQL;
            }
            return null;
        };
    }

    private record Key(String kind, String host, int port, String name) {}

    private record Item(FlowResult result, Key key) {}

    private static final class Denied extends Exception {
        private static final long serialVersionUID = 1L;

        Denied() {
            super(null, null, false, false);
        }
    }

    /** Tests the flows; raises {@link TooManyFlows} above {@link #MAX_CHECKS} checks. */
    public static FlowResults run(List<BindingFlows> flows, FlowOptions o) {
        Chooser choose = o.handshake != null ? (b, f, p) -> o.handshake.choose(f, p) : defaultChooser(o.platforms);
        List<Item> items = new ArrayList<>();
        for (BindingFlows bf : flows) {
            plan(bf, choose, o, items);
        }
        if (items.size() > MAX_CHECKS) {
            throw new TooManyFlows("too many flows to check: " + items.size() + " checks, at most " + MAX_CHECKS);
        }
        Map<Key, Item> unique = new LinkedHashMap<>();
        for (Item it : items) {
            if (it.key() != null) {
                unique.putIfAbsent(it.key(), it);
            }
        }
        Map<Key, FlowResult> done = new LinkedHashMap<>();
        if (!unique.isEmpty()) {
            Context ctx = new Context(o);
            AtomicInteger n = new AtomicInteger();
            ExecutorService pool = Executors.newFixedThreadPool(Math.min(o.concurrency, unique.size()), r -> {
                Thread t = new Thread(r, "ligo-flowcheck-" + n.incrementAndGet());
                t.setDaemon(true);
                return t;
            });
            try {
                Map<Key, Future<FlowResult>> futures = new LinkedHashMap<>();
                unique.forEach((k, it) -> futures.put(k, pool.submit(() -> check(it, ctx))));
                for (Map.Entry<Key, Future<FlowResult>> e : futures.entrySet()) {
                    done.put(e.getKey(), e.getValue().get());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new Unavailable("the flow check was interrupted");
            } catch (ExecutionException e) {
                throw new LigoException("a flow check failed: " + e.getCause().getClass().getSimpleName());
            } finally {
                pool.shutdownNow();
            }
        }
        List<FlowResult> out = new ArrayList<>();
        for (Item it : items) {
            FlowResult r = it.result();
            if (it.key() != null) {
                FlowResult d = done.get(it.key());
                r = new FlowResult(r.binding(), r.target(), r.flow(), r.destination(), d.port(), d.protocol(), d.status(),
                        d.reason(), d.error(), d.latency(), d.attempts());
            }
            out.add(r);
            if (o.logger != null) {
                o.logger.log(System.Logger.Level.DEBUG,
                        "flow checked: binding={0} flow={1} destination={2} port={3} protocol={4} status={5} reason={6}",
                        r.binding(), r.flow(), r.destination(), String.valueOf(r.port()), r.protocol(),
                        r.status().name().toLowerCase(Locale.ROOT), r.reason());
            }
        }
        return new FlowResults(out);
    }

    // -- planning

    private static InetAddress ip(String host) {
        if (!Cidr.Literal.is(host)) {
            return null;
        }
        try {
            return Cidr.Literal.of(host);
        } catch (IllegalArgumentException e) {
            return null; // not an address after all: a name
        }
    }

    private static boolean denies(List<Cidr> denied, InetAddress ip) {
        return denied.stream().anyMatch(n -> n.contains(ip));
    }

    private static void plan(BindingFlows bf, Chooser choose, FlowOptions o, List<Item> items) {
        for (Flow f : bf.flows()) {
            FlowResult base = new FlowResult(bf.binding(), bf.target(), f.name(), f.destination(), 0, "",
                    FlowStatus.SKIPPED, "", null, Duration.ZERO, 0);
            String proto = f.protocol().toUpperCase(Locale.ROOT);
            if (!proto.equals("TCP") && !proto.equals("UDP")) {
                items.add(skip(base, 0, "protocol \"" + f.protocol() + "\" is not checkable"));
                continue;
            }
            if (f.destination().contains("/")) {
                items.add(skip(base, 0, "a CIDR destination has no single host to check"));
                continue;
            }
            if (f.destination().isEmpty()) {
                items.add(skip(base, 0, "no destination"));
                continue;
            }
            if (f.ports().isEmpty()) {
                items.add(skip(base, 0, "no ports"));
                continue;
            }
            InetAddress ip = ip(f.destination());
            for (PortRange p : f.ports()) {
                if (p.low() != p.high()) {
                    items.add(skip(base, p.low(), "the port range " + p.low() + "-" + p.high() + " is not probed"));
                    continue;
                }
                if (p.low() < 1 || p.low() > 65535) {
                    items.add(skip(base, p.low(), "port " + p.low() + " is not valid"));
                    continue;
                }
                if (ip != null && denies(o.denied, ip)) {
                    items.add(skip(base, p.low(), "the destination is in a denied network"));
                    continue;
                }
                String host = f.destination().replaceAll("^\\[|]$", "");
                String kind;
                String name = "";
                if (proto.equals("UDP")) {
                    kind = UDP;
                } else if (f.tls() && Handshake.SPIRE.equals(choose.choose(bf.binding(), f, p.low()))) {
                    kind = Handshake.SPIRE; // an SVID has no name to verify
                } else if (f.tls()) {
                    name = !f.serverName().isEmpty() ? f.serverName() : ip != null ? "" : f.destination();
                    if (name.isEmpty()) {
                        items.add(skip(base, p.low(), "tls with a bare IP address and no server name: there is no name to verify"));
                        continue;
                    }
                    kind = Handshake.POSTGRESQL.equals(choose.choose(bf.binding(), f, p.low())) ? Handshake.POSTGRESQL : TLS;
                } else {
                    kind = TCP;
                }
                FlowResult r = new FlowResult(base.binding(), base.target(), base.flow(), base.destination(), p.low(), kind,
                        FlowStatus.SKIPPED, "", null, Duration.ZERO, 0);
                items.add(new Item(r, new Key(kind, host, p.low(), name)));
            }
        }
    }

    private static Item skip(FlowResult base, int port, String why) {
        return new Item(new FlowResult(base.binding(), base.target(), base.flow(), base.destination(), port, "",
                FlowStatus.SKIPPED, why, null, Duration.ZERO, 0), null);
    }

    // -- checking

    /** What the checks of one call share. */
    private static final class Context {
        final FlowOptions o;
        final int timeout;
        final SSLContext tls;

        Context(FlowOptions o) {
            this.o = o;
            this.timeout = (int) Math.min(Integer.MAX_VALUE, o.timeout.toMillis());
            try {
                if (o.roots.isEmpty()) {
                    tls = SSLContext.getDefault();
                } else {
                    tls = SSLContext.getInstance("TLS");
                    tls.init(null, trustManagers(o.roots), null);
                }
            } catch (GeneralSecurityException e) {
                throw new LigoException("cannot build the TLS context", e);
            }
        }
    }

    private static javax.net.ssl.TrustManager[] trustManagers(Iterable<X509Certificate> roots) throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            int i = 0;
            for (X509Certificate c : roots) {
                ks.setCertificateEntry("root" + i++, c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            return tmf.getTrustManagers();
        } catch (IOException e) {
            throw new java.security.KeyStoreException(e);
        }
    }

    private static FlowResult with(FlowResult r, FlowStatus status, String reason, Throwable error, Duration latency,
            int attempts) {
        return new FlowResult(r.binding(), r.target(), r.flow(), r.destination(), r.port(), r.protocol(), status, reason,
                error, latency, attempts);
    }

    private static FlowResult check(Item item, Context c) {
        FlowResult r = item.result();
        FlowOptions o = c.o;
        Throwable last = null;
        long start = System.nanoTime();
        int attempts = 0;
        for (int attempt = 1; attempt <= o.tries; attempt++) {
            if (o.stop.getAsBoolean() || Thread.currentThread().isInterrupted()) {
                return with(r, FlowStatus.SKIPPED, "interrupted", null, Duration.ZERO, attempts);
            }
            attempts = attempt;
            start = System.nanoTime();
            try {
                String note = once(item.key(), c);
                return with(r, FlowStatus.REACHABLE, note, null, Duration.ofNanos(System.nanoTime() - start), attempt);
            } catch (Denied e) {
                return with(r, FlowStatus.SKIPPED, "the destination is in a denied network", null, Duration.ZERO, 0);
            } catch (IOException | RuntimeException e) {
                last = e;
                if (attempt < o.tries && !o.retryDelay.isZero()) {
                    try {
                        Thread.sleep(o.retryDelay.toMillis());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
        return with(r, FlowStatus.UNREACHABLE, reason(last), last, Duration.ofNanos(System.nanoTime() - start), attempts);
    }

    private static String reason(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateException && t.getMessage() != null) {
                return t.getMessage();
            }
        }
        return e.getMessage() != null && !e.getMessage().isEmpty() ? e.getMessage() : e.getClass().getSimpleName();
    }

    /** One attempt; throws when the flow is unreachable. Returns a note for the reason of a pass. */
    private static String once(Key k, Context c) throws IOException, Denied {
        if (k.kind().equals(UDP)) {
            InetAddress a = resolve(k.host(), c).get(0);
            try (DatagramSocket s = new DatagramSocket()) {
                s.setSoTimeout(c.timeout);
                s.connect(new InetSocketAddress(a, k.port()));
                s.send(new DatagramPacket(new byte[] {0}, 1));
                try {
                    s.receive(new DatagramPacket(new byte[1], 1));
                } catch (SocketTimeoutException e) {
                    return "no ICMP error came back; a silent peer passes";
                } catch (PortUnreachableException e) {
                    throw e; // the peer refused: this is the unreachable case
                }
                return "";
            }
        }
        try (Socket sock = connect(resolve(k.host(), c), k.port(), c.timeout)) {
            switch (k.kind()) {
                case TCP:
                    return "";
                case Handshake.SPIRE:
                    spire(sock, k, c);
                    return "";
                default:
                    if (k.kind().equals(Handshake.POSTGRESQL)) {
                        sock.getOutputStream().write(SSL_REQUEST);
                        sock.getOutputStream().flush();
                        InputStream in = sock.getInputStream();
                        int answer = in.read();
                        if (answer == 'E') {
                            throw new IOException("the server answered the SSLRequest with an error");
                        }
                        if (answer != 'S') {
                            throw new IOException("the server does not offer TLS");
                        }
                    }
                    handshake(sock, k, c);
                    return "";
            }
        }
    }

    private static void handshake(Socket sock, Key k, Context c) throws IOException {
        try (SSLSocket ssl = (SSLSocket) c.tls.getSocketFactory().createSocket(sock, k.name(), k.port(), true)) {
            SSLParameters p = ssl.getSSLParameters();
            p.setEndpointIdentificationAlgorithm("HTTPS");
            if (ip(k.name()) == null) {
                p.setServerNames(List.of(new SNIHostName(k.name())));
            }
            ssl.setSSLParameters(p);
            ssl.startHandshake();
        }
    }

    /** The server's chain is verified against the bundle; its ID must belong to the bundle's trust domain. */
    private static void spire(Socket sock, Key k, Context c) throws IOException {
        X509Bundle bundle = c.o.spiffeBundle;
        if (bundle == null) {
            throw new IOException("no trust bundle to verify the SVID with");
        }
        if (bundle.getX509Authorities().isEmpty()) {
            throw new IOException("the trust bundle has no authorities");
        }
        try {
            SSLContext ctx = SSLContext.getInstance("TLS"); // no host name rule: an SVID has no DNS name, the ID is checked
            ctx.init(null, trustManagers(bundle.getX509Authorities()), null);
            try (SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(sock, k.host(), k.port(), true)) {
                ssl.startHandshake();
                X509Certificate leaf = (X509Certificate) ssl.getSession().getPeerCertificates()[0];
                List<String> uris = new ArrayList<>();
                if (leaf.getSubjectAlternativeNames() != null) {
                    for (List<?> san : leaf.getSubjectAlternativeNames()) {
                        if ((Integer) san.get(0) == 6) {
                            uris.add((String) san.get(1));
                        }
                    }
                }
                if (uris.size() != 1) {
                    throw new IOException("the certificate is not an X509-SVID: it has no single URI SAN");
                }
                String id = uris.get(0);
                if (!id.startsWith("spiffe://" + bundle.getTrustDomain().getName() + "/")) {
                    throw new IOException("the SPIFFE ID is not in the bundle's trust domain");
                }
                if (c.o.spiffeId != null && !id.equals(c.o.spiffeId)) {
                    throw new IOException("the SPIFFE ID is not the expected one");
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot verify the SVID: " + e.getClass().getSimpleName(), e);
        }
    }

    /** The addresses of host that are not denied. The check connects to these, never to the name again. */
    private static List<InetAddress> resolve(String host, Context c) throws IOException, Denied {
        InetAddress ip = ip(host);
        if (ip != null) {
            return List.of(ip);
        }
        List<InetAddress> all;
        try {
            all = c.o.resolver.apply(host);
        } catch (RuntimeException e) {
            throw new IOException("cannot resolve " + host);
        }
        List<InetAddress> ok = new ArrayList<>();
        for (InetAddress a : all) {
            if (!denies(c.o.denied, a) && !ok.contains(a)) {
                ok.add(a);
            }
        }
        if (ok.isEmpty()) {
            throw new Denied();
        }
        return ok;
    }

    private static Socket connect(List<InetAddress> addresses, int port, int timeout) throws IOException {
        IOException last = null;
        for (InetAddress a : addresses) {
            Socket s = new Socket();
            try {
                s.setSoTimeout(timeout);
                s.connect(new InetSocketAddress(a, port), timeout);
                return s;
            } catch (IOException e) {
                s.close();
                last = e;
            }
        }
        throw last == null ? new IOException("no address to connect to") : last;
    }
}
