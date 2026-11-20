// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Stream;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** JV-1 to JV-4, JV-13 and JV-T1 (.specs/ligo-client-sdk-java.md §6). */
class ClientTest {
    static final String LIGO_ID = "spiffe://prod.lab/ns/sys/sa/ligo";
    static final String WORKER_ID = "spiffe://prod.lab/ns/e2e/sa/worker";

    static final String BINDINGS = """
            {"callerSpiffeId": "%s", "items": [{
              "id": "0192", "name": "workers-ledger", "source": "workers", "target": "ledger", "accessLevel": "write",
              "platformType": "postgres", "platform": "pg-prod", "revision": 4, "updatedAt": "2026-10-16T07:02:11Z",
              "description": "Ledger posting", "annotations": {"change": "CHG0012345"},
              "auth": {"secretStorageStrategy": "vault-static", "secretStoreType": "vault", "secretStoreInstance": "vault-prod",
                "config": {"address": "https://vault.lab:8200", "audience": "https://vault.lab", "authMount": "jwt",
                           "role": "binding-0192", "secretPath": "kv/data/bindings/0192"}},
              "spec": {"endpoint": "db.lab:5432", "database": "ledger", "port": 5432}}]}
            """.formatted(WORKER_ID);

    Pki pki;
    StaticSource source;
    final java.util.List<AutoCloseable> open = new java.util.ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new Pki();
        source = new StaticSource(pki, WORKER_ID);
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    static TestServer.Response ok(String doc) {
        return new TestServer.Response(200, Map.of("Content-Type", "application/json", "ETag", "\"sha256:aa\""),
                doc.getBytes(StandardCharsets.UTF_8));
    }

    TestServer serve(Function<TestServer.Request, TestServer.Response> handler) {
        return serve(LIGO_ID, handler);
    }

    TestServer serve(String id, Function<TestServer.Request, TestServer.Response> handler) {
        TestServer s = new TestServer(pki, id, pki, handler);
        open.add(s);
        return s;
    }

    LigoClient client(TestServer s) {
        LigoClient c = LigoClient.builder().address(s.address()).serverId(LIGO_ID).x509Source(source).build();
        open.add(c);
        return c;
    }

    // JV-1
    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            |LIGO_ID|address
            https://ligo.lab:8443|LIGO_ID|address
            ligo.lab|LIGO_ID|address
            ligo.lab:99999|LIGO_ID|address
            :8443|LIGO_ID|address
            ligo.lab:8443||serverId
            ligo.lab:8443|ligo|serverId
            """)
    void builderRefuses(String address, String serverId, String want) {
        String id = "LIGO_ID".equals(serverId) ? LIGO_ID : serverId == null ? "" : serverId;
        String addr = address == null ? "" : address;
        assertThatThrownBy(() -> LigoClient.builder().address(addr).serverId(id).x509Source(source).build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(want);
    }

    @Test
    void builderRefusesAShortPollAndAMissingPart() {
        assertThatThrownBy(() -> LigoClient.builder().pollInterval(Duration.ofSeconds(4)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("pollInterval");
        assertThatThrownBy(() -> LigoClient.builder().serverId(LIGO_ID).build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("address");
        assertThatThrownBy(() -> LigoClient.builder().address("ligo.lab:8443").build())
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("serverId");
    }

    @Test
    void buildingDoesNotCallLigo() {
        // no server listens on this port, and nothing is dialed
        LigoClient c = LigoClient.builder().address("127.0.0.1:1").serverId(LIGO_ID).x509Source(source).build();
        c.close();
        assertThat(source.closed()).isFalse(); // a source the caller gave is the caller's to close
    }

    // JV-2
    @Test
    void bindingsDecode() {
        TestServer s = serve(r -> ok(BINDINGS));
        List<Binding> got = client(s).bindings(new Filter("ledger", "postgres"));
        assertThat(s.requests.get(0).target()).isEqualTo("/v1/bindings?target=ledger&platformType=postgres");
        assertThat(s.requests.get(0).peer()).isEqualTo(WORKER_ID);
        assertThat(got).hasSize(1);
        Binding b = got.get(0);
        assertThat(List.of(b.id(), b.name(), b.source(), b.target(), b.accessLevel()))
                .containsExactly("0192", "workers-ledger", "workers", "ledger", "write");
        assertThat(List.of(b.platformType(), b.platform())).containsExactly("postgres", "pg-prod");
        assertThat(b.revision()).isEqualTo(4);
        assertThat(b.updatedAt()).hasToString("2026-10-16T07:02:11Z");
        assertThat(b.spec()).containsEntry("endpoint", "db.lab:5432").containsEntry("port", 5432);
        assertThat(b.endpoint()).isEqualTo("db.lab:5432");
        assertThat(b.description()).isEqualTo("Ledger posting");
        assertThat(b.annotations()).isEqualTo(Map.of("change", "CHG0012345"));
        assertThat(b.auth().strategy()).isEqualTo("vault-static");
        assertThat(b.auth().storeType()).isEqualTo("vault");
        assertThat(b.auth().storeInstance()).isEqualTo("vault-prod");
        assertThat(b.auth().config()).containsEntry("secretPath", "kv/data/bindings/0192");
    }

    @Test
    void anEmptyListIsNotAnError() {
        TestServer s = serve(r -> ok("{\"callerSpiffeId\": \"x\", \"items\": []}"));
        assertThat(client(s).bindings(Filter.all())).isEmpty();
    }

    @Test
    void theMapsAreCopies() {
        TestServer s = serve(r -> ok(BINDINGS));
        LigoClient c = client(s);
        Binding first = c.bindings(Filter.all()).get(0);
        assertThatThrownBy(() -> first.annotations().put("change", "changed"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> first.spec().put("endpoint", "evil:1")).isInstanceOf(UnsupportedOperationException.class);
        assertThat(c.bindings(Filter.all()).get(0).annotations()).containsEntry("change", "CHG0012345");
    }

    @Test
    void absentTextIsEmpty() {
        String doc = BINDINGS.replace("\"description\": \"Ledger posting\", \"annotations\": {\"change\": \"CHG0012345\"},", "");
        TestServer s = serve(r -> ok(doc));
        Binding b = client(s).bindings(Filter.all()).get(0);
        assertThat(b.description()).isEmpty();
        assertThat(b.annotations()).isEmpty();
    }

    @Test
    void endpointWithoutOne() {
        TestServer s = serve(r -> ok(BINDINGS.replace("\"endpoint\": \"db.lab:5432\", ", "")));
        assertThat(client(s).bindings(Filter.all()).get(0).endpoint()).isEmpty();
    }

    @Test
    void flowsDecode() {
        String doc = """
                {"callerSpiffeId": "x", "items": [{"binding": "b", "source": "s", "target": "t", "flows": [
                  {"name": "db", "purpose": "DATA", "protocol": "TCP", "destination": "db.lab", "ports": [5432, "6000-6010"],
                   "tls": true, "serverName": "db.lab", "description": "d", "declaredBy": "target:t"}]}]}
                """;
        TestServer s = serve(r -> ok(doc));
        BindingFlows bf = client(s).flows("t").get(0);
        assertThat(s.requests.get(0).target()).isEqualTo("/v1/flows?target=t");
        assertThat(List.of(bf.binding(), bf.source(), bf.target())).containsExactly("b", "s", "t");
        Flow f = bf.flows().get(0);
        assertThat(f.ports()).containsExactly(new PortRange(5432, 5432), new PortRange(6000, 6010));
        assertThat(f.tls()).isTrue();
        assertThat(List.of(f.serverName(), f.declaredBy(), f.purpose())).containsExactly("db.lab", "target:t", "DATA");
    }

    @Test
    void aBadPortIsRefused() {
        TestServer s = serve(r -> ok("{\"items\": [{\"binding\": \"b\", \"flows\": [{\"name\": \"x\", \"ports\": [\"nope\"]}]}]}"));
        assertThatThrownBy(() -> client(s).flows(null)).isInstanceOf(LigoException.class);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            not json
            {"items": 3}
            {"nothing": []}
            {"items": [3]}
            {"items": [{"revision": "x"}]}
            {"items": [{"updatedAt": "yesterday"}]}
            {"items": [{"name": 7}]}
            {"items": [{"spec": []}]}
            """)
    void aMalformedDocumentIsRefused(String body) {
        TestServer s = serve(r -> ok(body));
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(LigoException.class)
                .isNotInstanceOf(Unauthorized.class).isNotInstanceOf(Unavailable.class);
    }

    // JV-3
    @Test
    void etagAndNotModified() {
        TestServer s = serve(r -> "\"sha256:aa\"".equals(r.headers().get("if-none-match"))
                ? new TestServer.Response(304, Map.of(), new byte[0]) : ok(BINDINGS));
        LigoClient c = client(s);
        List<Binding> first = c.bindings(Filter.target("ledger"));
        List<Binding> again = c.bindings(Filter.target("ledger"));
        List<Binding> other = c.bindings(Filter.target("other")); // another filter has its own ETag
        assertThat(s.requests.stream().map(r -> r.headers().get("if-none-match")).toList())
                .containsExactly(null, "\"sha256:aa\"", null);
        assertThat(again).isEqualTo(first);
        assertThat(other).hasSize(1);
    }

    // JV-4
    @Test
    void aServerWithAnotherIdGetsNoRequest() {
        TestServer s = serve("spiffe://prod.lab/ns/sys/sa/impostor", r -> ok(BINDINGS));
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(Unauthorized.class);
        assertThat(s.requests).isEmpty();
    }

    @Test
    void aServerOfAnotherCaGetsNoRequest() {
        Pki other = new Pki();
        TestServer s = new TestServer(other, LIGO_ID, pki, r -> ok(BINDINGS));
        open.add(s);
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(Unauthorized.class);
        assertThat(s.requests).isEmpty();
    }

    @Test
    void unavailableCarriesRetryAfter() {
        TestServer s = serve(r -> new TestServer.Response(503, Map.of("Retry-After", "7"), new byte[0]));
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOfSatisfying(Unavailable.class,
                e -> assertThat(e.retryAfter()).isEqualTo(Duration.ofSeconds(7)));
        TestServer t = serve(r -> new TestServer.Response(429, Map.of("Retry-After", "99999"), new byte[0]));
        assertThatThrownBy(() -> client(t).bindings(Filter.all())).isInstanceOfSatisfying(Unavailable.class,
                e -> assertThat(e.retryAfter()).isNull()); // longer than an hour is ignored
    }

    @Test
    void aRefusalIsUnauthorizedAndOtherStatusesAreErrors() {
        TestServer s = serve(r -> new TestServer.Response(403, Map.of(), new byte[0]));
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(Unauthorized.class);
        TestServer t = serve(r -> new TestServer.Response(500, Map.of(), new byte[0]));
        assertThatThrownBy(() -> client(t).bindings(Filter.all())).isExactlyInstanceOf(LigoException.class);
    }

    @Test
    void nothingListeningIsUnavailable() {
        LigoClient c = LigoClient.builder().address("127.0.0.1:1").serverId(LIGO_ID).x509Source(source).build();
        open.add(c);
        assertThatThrownBy(() -> c.bindings(Filter.all())).isInstanceOf(Unavailable.class);
    }

    // JV-13
    @Test
    void anAnswerOver8MiBIsRefused() {
        byte[] big = ("{\"items\": [], \"pad\": \"" + "x".repeat(Rest.MAX_BODY) + "\"}").getBytes(StandardCharsets.UTF_8);
        TestServer s = serve(r -> new TestServer.Response(200, Map.of(), big));
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(LigoException.class)
                .hasMessageContaining("larger than");
    }

    // JV-A1, in short: the async twins are the blocking calls on the executor
    @Test
    void asyncTwins() throws Exception {
        TestServer s = serve(r -> ok(BINDINGS));
        LigoClient c = client(s);
        assertThat(c.bindingsAsync(Filter.all()).get()).hasSize(1);
        TestServer bad = serve("spiffe://prod.lab/ns/sys/sa/impostor", r -> ok(BINDINGS));
        assertThatThrownBy(() -> client(bad).bindingsAsync(Filter.all()).get()).isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(Unauthorized.class);
    }

    @Test
    void aClosedClientRefuses() {
        TestServer s = serve(r -> ok(BINDINGS));
        LigoClient c = client(s);
        c.close();
        assertThatThrownBy(() -> c.bindings(Filter.all())).isInstanceOf(LigoException.class);
    }

    @Test
    void connectChecksTheId() throws Exception {
        TestServer s = serve(r -> ok(BINDINGS));
        int port = Integer.parseInt(s.address().substring(s.address().indexOf(':') + 1));
        LigoClient c = client(s);
        try (SSLSocket socket = c.connect("127.0.0.1:" + port, LIGO_ID, Duration.ofSeconds(5))) {
            assertThat(socket.getSession().getProtocol()).isEqualTo("TLSv1.3");
        }
        assertThatThrownBy(() -> c.connect("127.0.0.1:" + port, "spiffe://prod.lab/ns/sys/sa/other", Duration.ofSeconds(5)))
                .isInstanceOf(Unauthorized.class);
    }

    // JV-T1
    @Test
    void connectingCreatesNoFile() throws IOException {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        Set<Path> before = listing(tmp);
        TestServer s = serve(r -> ok(BINDINGS));
        client(s).bindings(Filter.all());
        assertThat(listing(tmp)).containsExactlyInAnyOrderElementsOf(before);
    }

    private static Set<Path> listing(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().startsWith("ligo")).collect(java.util.stream.Collectors.toSet());
        }
    }
}
