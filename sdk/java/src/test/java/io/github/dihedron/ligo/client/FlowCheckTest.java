// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.spiffeid.TrustDomain;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** JV-F1 to JV-F9: flow testing (.specs/ligo-client-sdk-java.md §5, .specs/ligo-network-checks.md §9). */
class FlowCheckTest {
    static final String NAME = "db.test";
    static final String SVID = "spiffe://prod.lab/ns/sys/sa/ligo";

    Pki pki;
    NetServers net;

    @BeforeEach
    void setUp() {
        pki = new Pki();
        net = new NetServers();
    }

    @AfterEach
    void tearDown() {
        net.close();
    }

    static Flow flow(int port, String name, String protocol, boolean tls, String serverName, String destination) {
        return new Flow(name, "", protocol, destination, List.of(new PortRange(port, port)), tls, serverName, "", "");
    }

    static Flow flow(int port) {
        return flow(port, "f", "TCP", false, "", "127.0.0.1");
    }

    static List<BindingFlows> bf(Flow... flows) {
        return List.of(new BindingFlows("b", "s", "t", List.of(flows)));
    }

    static FlowOptions.Builder fast() {
        return FlowOptions.builder().timeout(Duration.ofSeconds(2)).tries(1);
    }

    static FlowResult one(List<BindingFlows> flows, FlowOptions o) {
        FlowResults r = FlowCheck.run(flows, o);
        assertThat(r).hasSize(1);
        return r.get(0);
    }

    // JV-F1
    @Test
    void tcpReachableAndUnreachable() {
        NetServers.Listener ln = net.tcp();
        FlowResults res = FlowCheck.run(bf(flow(ln.port(), "open", "TCP", false, "", "127.0.0.1"),
                flow(NetServers.closedTcpPort(), "closed", "TCP", false, "", "127.0.0.1")), fast().build());
        Map<String, FlowResult> by = res.stream().collect(Collectors.toMap(FlowResult::flow, r -> r));
        FlowResult open = by.get("open");
        assertThat(open.status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(open.protocol()).isEqualTo("tcp");
        assertThat(open.port()).isEqualTo(ln.port());
        assertThat(open.attempts()).isEqualTo(1);
        assertThat(List.of(open.binding(), open.target(), open.destination())).containsExactly("b", "t", "127.0.0.1");
        FlowResult closed = by.get("closed");
        assertThat(closed.status()).isEqualTo(FlowStatus.UNREACHABLE);
        assertThat(closed.error()).isNotNull();
        assertThat(closed.reason()).isNotEmpty();
        assertThat(res.ok()).isFalse();
        assertThat(res.unreachable().stream().map(FlowResult::flow)).containsExactly("closed");
        assertThat(new FlowResults(List.of(open)).ok()).isTrue();
    }

    @Test
    void eachPortIsAResult() {
        NetServers.Listener a = net.tcp();
        NetServers.Listener b = net.tcp();
        Flow f = new Flow("two", "", "TCP", "127.0.0.1", List.of(new PortRange(a.port(), a.port()),
                new PortRange(b.port(), b.port())), false, "", "", "");
        FlowResults res = FlowCheck.run(bf(f), fast().build());
        assertThat(res.stream().map(FlowResult::port)).containsExactlyInAnyOrder(a.port(), b.port());
        assertThat(res.ok()).isTrue();
    }

    @Test
    void retriesAreCounted() {
        FlowResult r = one(bf(flow(NetServers.closedTcpPort())),
                FlowOptions.builder().timeout(Duration.ofSeconds(1)).tries(3).retryDelay(Duration.ZERO).build());
        assertThat(r.attempts()).isEqualTo(3);
        assertThat(r.status()).isEqualTo(FlowStatus.UNREACHABLE);
    }

    // JV-F2
    @Test
    void tlsTrustedUntrustedWrongName() {
        NetServers.Listener ln = net.tls(NetServers.context(pki.dnsServer(NAME)));
        Flow f = flow(ln.port(), "f", "TCP", true, NAME, "127.0.0.1");
        FlowOptions trusted = fast().roots(List.of(pki.ca)).build();
        assertThat(one(bf(f), trusted).status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(one(bf(f), trusted).protocol()).isEqualTo("tls");
        assertThat(one(bf(f), fast().build()).status()).isEqualTo(FlowStatus.UNREACHABLE); // the JDK's roots do not know the CA
        assertThat(one(bf(flow(ln.port(), "f", "TCP", true, "other.test", "127.0.0.1")), trusted).status())
                .isEqualTo(FlowStatus.UNREACHABLE);
        NetServers.Listener stranger = net.tls(NetServers.context(new Pki().dnsServer(NAME)));
        assertThat(one(bf(flow(stranger.port(), "f", "TCP", true, NAME, "127.0.0.1")), trusted).status())
                .isEqualTo(FlowStatus.UNREACHABLE);
    }

    @Test
    void tlsToABareIpIsSkipped() {
        FlowResult r = one(bf(flow(net.tcp().port(), "f", "TCP", true, "", "127.0.0.1")), fast().build());
        assertThat(r.status()).isEqualTo(FlowStatus.SKIPPED);
        assertThat(r.reason()).contains("no name to verify");
    }

    // JV-F3
    @Test
    void postgresqlHandshake() {
        NetServers.Listener pg = net.postgres(NetServers.context(pki.dnsServer(NAME)), (byte) 'S');
        Flow f = flow(pg.port(), "f", "TCP", true, NAME, "127.0.0.1");
        FlowOptions trusted = fast().roots(List.of(pki.ca)).build();
        assertThat(one(bf(f), trusted).status()).isEqualTo(FlowStatus.UNREACHABLE); // a plain TLS check of a PostgreSQL port fails
        FlowOptions asPg = fast().roots(List.of(pki.ca)).handshake((fl, p) -> Handshake.POSTGRESQL).build();
        FlowResult r = one(bf(f), asPg);
        assertThat(r.status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(r.protocol()).isEqualTo("postgresql");
        assertThat(one(bf(f), fast().handshake((fl, p) -> Handshake.POSTGRESQL).build()).status())
                .isEqualTo(FlowStatus.UNREACHABLE);
        NetServers.Listener noTls = net.postgres(NetServers.context(pki.dnsServer(NAME)), (byte) 'N');
        FlowResult refused = one(bf(flow(noTls.port(), "f", "TCP", true, NAME, "127.0.0.1")), asPg);
        assertThat(refused.status()).isEqualTo(FlowStatus.UNREACHABLE);
        assertThat(refused.reason()).contains("TLS");
    }

    // JV-F4
    @Test
    void spiffeHandshake() {
        NetServers.Listener ln = net.tls(NetServers.context(pki.svid(SVID)));
        Flow f = flow(ln.port(), "f", "TCP", true, "", "127.0.0.1");
        X509Bundle bundle = new X509Bundle(TrustDomain.parse("prod.lab"), Set.of(pki.ca));
        Handshake spire = (fl, p) -> Handshake.SPIRE;
        FlowResult r = one(bf(f), fast().handshake(spire).spiffeBundle(bundle).build());
        assertThat(r.status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(r.protocol()).isEqualTo("spire");
        assertThat(one(bf(f), fast().handshake(spire).spiffeBundle(bundle).spiffeId(SVID).build()).status())
                .isEqualTo(FlowStatus.REACHABLE);
        assertThat(one(bf(f), fast().handshake(spire).spiffeBundle(bundle).spiffeId("spiffe://prod.lab/ns/sys/sa/other").build())
                .status()).isEqualTo(FlowStatus.UNREACHABLE);
        FlowResult none = one(bf(f), fast().handshake(spire).build());
        assertThat(none.status()).isEqualTo(FlowStatus.UNREACHABLE);
        assertThat(none.reason()).contains("no trust bundle");
        X509Bundle other = new X509Bundle(TrustDomain.parse("prod.lab"), Set.of(new Pki().ca));
        assertThat(one(bf(f), fast().handshake(spire).spiffeBundle(other).build()).status()).isEqualTo(FlowStatus.UNREACHABLE);
        // an ID of another trust domain, signed by this CA: not a member
        NetServers.Listener foreign = net.tls(NetServers.context(pki.svid("spiffe://elsewhere.lab/x")));
        assertThat(one(bf(flow(foreign.port(), "f", "TCP", true, "", "127.0.0.1")),
                fast().handshake(spire).spiffeBundle(bundle).build()).status()).isEqualTo(FlowStatus.UNREACHABLE);
    }

    // JV-F5
    @Test
    void udp() {
        DatagramSocket quiet = net.udpSilent();
        FlowResult r = one(bf(flow(quiet.getLocalPort(), "quiet", "UDP", false, "", "127.0.0.1")),
                FlowOptions.builder().timeout(Duration.ofMillis(500)).tries(1).build());
        assertThat(r.status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(r.protocol()).isEqualTo("udp");
        assertThat(r.reason()).contains("silent peer passes");
        FlowResult refused = one(bf(flow(NetServers.closedUdpPort(), "f", "UDP", false, "", "127.0.0.1")),
                FlowOptions.builder().timeout(Duration.ofSeconds(1)).tries(1).build());
        assertThat(refused.status()).isEqualTo(FlowStatus.UNREACHABLE);
    }

    // JV-F6
    @Test
    void skippedFlows() {
        record Case(Flow f, String why) {}
        List<Case> cases = List.of(
                new Case(new Flow("x", "", "SCTP", "127.0.0.1", List.of(new PortRange(1, 1)), false, "", "", ""), "not checkable"),
                new Case(new Flow("x", "", "TCP", "10.0.0.0/8", List.of(new PortRange(5432, 5432)), false, "", "", ""), "CIDR"),
                new Case(new Flow("x", "", "TCP", "", List.of(new PortRange(5432, 5432)), false, "", "", ""), "no destination"),
                new Case(new Flow("x", "", "TCP", "127.0.0.1", List.of(), false, "", "", ""), "no ports"),
                new Case(new Flow("x", "", "TCP", "127.0.0.1", List.of(new PortRange(6000, 6010)), false, "", "", ""), "range"),
                new Case(new Flow("x", "", "TCP", "127.0.0.1", List.of(new PortRange(0, 0)), false, "", "", ""), "not valid"));
        for (Case c : cases) {
            FlowResult r = one(bf(c.f()), fast().build());
            assertThat(r.status()).as(c.why()).isEqualTo(FlowStatus.SKIPPED);
            assertThat(r.reason()).contains(c.why());
            assertThat(new FlowResults(List.of(r)).ok()).isTrue(); // skipped is not a failure
        }
    }

    // JV-F7
    @ParameterizedTest
    @ValueSource(strings = {"169.254.169.254", "fe80::1", "fd00:ec2::254", "::ffff:169.254.169.254"})
    void deniedNetworksGetNoPacket(String dest) {
        long start = System.nanoTime();
        FlowResult r = one(bf(flow(80, "f", "TCP", false, "", dest)), fast().build());
        assertThat(r.status()).isEqualTo(FlowStatus.SKIPPED);
        assertThat(r.reason()).contains("denied");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(900)); // no connect was tried
    }

    @Test
    void aNameThatResolvesToADeniedAddress() throws Exception {
        InetAddress metadata = InetAddress.getByName("169.254.169.254");
        FlowOptions o = fast().resolver(h -> List.of(metadata)).build();
        FlowResult r = one(bf(flow(80, "f", "TCP", false, "", "metadata.internal")), o);
        assertThat(r.status()).isEqualTo(FlowStatus.SKIPPED);
        assertThat(r.reason()).contains("denied");
    }

    @Test
    void theCheckConnectsToTheAddressItVetted() {
        NetServers.Listener ln = net.tcp();
        List<String> calls = new ArrayList<>();
        FlowOptions o = fast().resolver(h -> {
            calls.add(h);
            return List.of(InetAddress.getLoopbackAddress());
        }).build();
        FlowResult r = one(bf(flow(ln.port(), "f", "TCP", false, "", "db.internal")), o);
        assertThat(r.status()).isEqualTo(FlowStatus.REACHABLE);
        assertThat(calls).containsExactly("db.internal"); // one resolution, used for the connection
    }

    @Test
    void deniedNetworksCanBeReplaced() {
        NetServers.Listener ln = net.tcp();
        assertThat(one(bf(flow(ln.port())), fast().deniedNetworks(List.of("127.0.0.0/8")).build()).status())
                .isEqualTo(FlowStatus.SKIPPED);
        assertThat(one(bf(flow(ln.port())), fast().deniedNetworks(List.of()).build()).status()).isEqualTo(FlowStatus.REACHABLE);
        assertThatThrownBy(() -> fast().deniedNetworks(List.of("not-a-network"))).isInstanceOf(IllegalArgumentException.class);
    }

    // JV-F8
    @Test
    void tooManyChecks() {
        List<PortRange> ports = new ArrayList<>();
        for (int p = 1; p <= 1025; p++) {
            ports.add(new PortRange(p, p));
        }
        Flow many = new Flow("m", "", "TCP", "127.0.0.1", ports, false, "", "", "");
        assertThatThrownBy(() -> FlowCheck.run(bf(many), FlowOptions.builder().build())).isInstanceOf(TooManyFlows.class)
                .isInstanceOf(LigoException.class);
    }

    @Test
    void aStoppedCallSkipsTheRest() {
        FlowResult r = one(bf(flow(net.tcp().port())), fast().stop(() -> true).build());
        assertThat(r.status()).isEqualTo(FlowStatus.SKIPPED);
        assertThat(r.reason()).isEqualTo("interrupted");
    }

    @Test
    void equalChecksRunOnce() throws Exception {
        NetServers.Listener ln = net.tcp();
        FlowResults res = FlowCheck.run(bf(flow(ln.port(), "a", "TCP", false, "", "127.0.0.1"),
                flow(ln.port(), "b", "TCP", false, "", "127.0.0.1")), fast().build());
        assertThat(res.stream().map(FlowResult::status)).containsExactly(FlowStatus.REACHABLE, FlowStatus.REACHABLE);
        assertThat(res.stream().map(FlowResult::flow)).containsExactly("a", "b");
        Thread.sleep(100);
        assertThat(ln.accepted.get()).isEqualTo(1);
    }

    // JV-F9
    @Test
    void logsNameTheFlowAndHoldNothingElse() {
        List<String> captured = new ArrayList<>();
        System.Logger log = new CredentialTest.Recording() {
            @Override
            public void log(Level level, java.util.ResourceBundle bundle, String format, Object... params) {
                captured.add(java.text.MessageFormat.format(format, params == null ? new Object[0] : params));
            }
        };
        FlowCheck.run(bf(flow(net.tcp().port()), flow(NetServers.closedTcpPort(), "closed", "TCP", false, "", "127.0.0.1")),
                fast().logger(log).build());
        assertThat(captured).anySatisfy(l -> assertThat(l).contains("flow checked"));
        assertThat(captured).allSatisfy(l -> assertThat(l.toLowerCase()).doesNotContain("private key").doesNotContain("token"));
    }

    @Test
    void theDefaultsChooseTheHandshakes() {
        FlowCheck.Chooser h = FlowCheck.defaultChooser(Map.of("b", "postgres", "c", "redis", "d", "postgres.16"));
        Flow ligo = new Flow("l", "", "TCP", "x", List.of(), true, "", "", "ligo");
        Flow target = new Flow("t", "", "TCP", "x", List.of(), true, "", "", "target:pg");
        Flow secret = new Flow("s", "", "TCP", "x", List.of(), true, "", "", "secret-store:v");
        assertThat(h.choose("b", ligo, 1)).isEqualTo(Handshake.SPIRE);
        assertThat(h.choose("b", target, 1)).isEqualTo(Handshake.POSTGRESQL);
        assertThat(h.choose("d", target, 1)).isEqualTo(Handshake.POSTGRESQL);
        assertThat(h.choose("b", secret, 1)).isNull();
        assertThat(h.choose("c", target, 1)).isNull();
    }
}
