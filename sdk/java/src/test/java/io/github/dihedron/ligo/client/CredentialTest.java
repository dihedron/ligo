// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** JV-6 to JV-10 and JV-15 (.specs/ligo-client-sdk-java.md §6): the credential from a Vault-compatible store. */
class CredentialTest {
    static final String PASSWORD = "s3cr3t-Passw0rd";
    static final String TOKEN = "hvs.store-token";
    static final ObjectMapper JSON = new ObjectMapper();
    static final String JSON_CHARS = "{}[]\",:0-9e.tfn";

    /** A clock the tests move. */
    static final class Ticking extends Clock {
        Instant now = Instant.parse("2026-11-20T10:00:00Z");

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** A logger that keeps what it is given. */
    static final class Recording implements System.Logger {
        final List<String> lines = new ArrayList<>();

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, java.util.ResourceBundle bundle, String msg, Throwable thrown) {
            lines.add(msg + (thrown == null ? "" : " " + thrown));
        }

        @Override
        public void log(Level level, java.util.ResourceBundle bundle, String format, Object... params) {
            lines.add(params == null || params.length == 0 ? format : java.text.MessageFormat.format(format, params));
        }
    }

    Pki pki;
    StaticSource source;
    FakeJwt jwt;
    Ticking clock;
    final List<AutoCloseable> open = new ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new Pki();
        source = new StaticSource(pki, ClientTest.WORKER_ID);
        jwt = new FakeJwt();
        clock = new Ticking();
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    static StoreServer.Response login() {
        return new StoreServer.Response(200, "{\"auth\":{\"client_token\":\"" + TOKEN + "\",\"lease_duration\":100}}");
    }

    static StoreServer.Response kv() {
        return new StoreServer.Response(200, "{\"data\":{\"data\":{\"username\":\"svc_ledger\",\"password\":\""
                + PASSWORD + "\"},\"metadata\":{\"version\":3}}}");
    }

    static StoreServer.Response dynamic(long lease) {
        return new StoreServer.Response(200, "{\"lease_duration\":" + lease
                + ",\"data\":{\"username\":\"v-user-1\",\"password\":\"" + PASSWORD + "\"}}");
    }

    static Function<StoreServer.Request, StoreServer.Response> routes(Supplier<StoreServer.Response> read) {
        return r -> r.method().equals("POST") && r.path().endsWith("/login") ? login() : read.get();
    }

    static Function<StoreServer.Request, StoreServer.Response> routes() {
        return routes(CredentialTest::kv);
    }

    StoreServer store(Function<StoreServer.Request, StoreServer.Response> handler) {
        StoreServer s = new StoreServer(pki, handler);
        open.add(s);
        return s;
    }

    LigoClient.Builder builder() {
        return LigoClient.builder().address("127.0.0.1:1").serverId(ClientTest.LIGO_ID).x509Source(source)
                .jwtSource(jwt).storeRoots(List.of(pki.ca)).clock(clock);
    }

    LigoClient client(LigoClient.Builder b) {
        LigoClient c = b.build();
        open.add(c);
        return c;
    }

    LigoClient client() {
        return client(builder());
    }

    static Binding binding(String url, String strategy, Map<String, String> overrides) {
        Map<String, String> cfg = new HashMap<>(Map.of("address", url, "audience", "https://vault.lab", "authMount", "jwt",
                "role", "binding-0192", "secretPath", "kv/data/bindings/0192", "credsPath", "database/creds/binding-0192"));
        cfg.putAll(overrides);
        cfg.values().removeIf(String::isEmpty);
        return new Binding("0192", "workers-ledger", "workers", "ledger", "write", "postgres", "pg-prod", 1,
                Instant.EPOCH, Map.of(), new Auth(strategy, "vault", "vault-prod", cfg), "", Map.of());
    }

    static Binding binding(String url) {
        return binding(url, "vault-static", Map.of());
    }

    // JV-6
    @Test
    void vaultStatic() {
        StoreServer s = store(routes());
        Credential cred = client().credential(binding(s.url()));
        assertThat(cred.username()).isEqualTo("svc_ledger");
        assertThat(cred.password()).isEqualTo(PASSWORD);
        assertThat(cred.expires()).isNull();
        assertThat(s.requests).hasSize(2);
        StoreServer.Request login = s.requests.get(0);
        StoreServer.Request read = s.requests.get(1);
        assertThat(login.method() + " " + login.path()).isEqualTo("POST /v1/auth/jwt/login");
        assertThat(login.body()).contains("\"role\":\"binding-0192\"")
                .contains("\"jwt\":\"" + FakeJwt.token("https://vault.lab", ClientTest.WORKER_ID) + "\"");
        assertThat(read.method() + " " + read.path()).isEqualTo("GET /v1/kv/data/bindings/0192");
        assertThat(read.headers()).containsEntry("x-vault-token", TOKEN);
        assertThat(jwt.calls).hasSize(1);
        assertThat(jwt.calls.get(0).audience()).isEqualTo("https://vault.lab");
        assertThat(jwt.calls.get(0).subject()).hasToString(ClientTest.WORKER_ID); // the identity of the X.509-SVID
    }

    // JV-7
    @Test
    void vaultDynamic() {
        StoreServer s = store(routes(() -> dynamic(90)));
        Credential cred = client().credential(binding(s.url(), "vault-dynamic", Map.of()));
        assertThat(s.requests.get(1).path()).isEqualTo("/v1/database/creds/binding-0192");
        assertThat(cred.username()).isEqualTo("v-user-1");
        assertThat(cred.expires()).isEqualTo(clock.now.plusSeconds(90));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -5, 1_000_000_000_000L})
    void dynamicLeaseOutOfRange(long lease) {
        StoreServer s = store(routes(() -> dynamic(lease)));
        LigoClient c = client();
        Binding b = binding(s.url(), "vault-dynamic", Map.of());
        assertThatThrownBy(() -> c.credential(b)).isInstanceOf(StoreError.class);
    }

    // JV-8
    @Test
    void tokenReuseExpiryAndInvalidate() {
        StoreServer s = store(routes());
        LigoClient c = client();
        Binding b = binding(s.url());
        c.credential(b);
        c.credential(b);
        assertThat(logins(s)).isEqualTo(1); // the token is reused
        clock.now = clock.now.plusSeconds(79);
        c.credential(b);
        assertThat(logins(s)).isEqualTo(1); // 80 % of 100 s is not over
        clock.now = clock.now.plusSeconds(2);
        c.credential(b);
        assertThat(logins(s)).isEqualTo(2); // over
        c.invalidate(b);
        c.credential(b);
        assertThat(logins(s)).isEqualTo(3);
    }

    static long logins(StoreServer s) {
        return s.requests.stream().filter(r -> r.path().endsWith("/login")).count();
    }

    @Test
    void a403OnARememberedTokenLogsInOnceMore() {
        int[] reads = {0};
        StoreServer s = store(routes(() -> ++reads[0] == 2 ? new StoreServer.Response(403, "permission denied") : kv()));
        LigoClient c = client();
        Binding b = binding(s.url());
        c.credential(b); // login 1, read 1
        c.credential(b); // remembered token, read 2 is a 403, login 2, read 3
        assertThat(s.requests.stream().map(r -> r.method() + " " + r.path().substring(r.path().lastIndexOf('/') + 1)))
                .containsExactly("POST login", "GET 0192", "GET 0192", "POST login", "GET 0192");
    }

    @Test
    void a403OnAFreshTokenIsFinal() {
        StoreServer s = store(routes(() -> new StoreServer.Response(403, "permission denied " + PASSWORD)));
        LigoClient c = client();
        assertThatThrownBy(() -> c.credential(binding(s.url()))).isInstanceOf(StoreError.class)
                .hasMessageContaining("403").hasMessageNotContaining(PASSWORD);
        assertThat(s.requests).hasSize(2);
    }

    // JV-9
    @ParameterizedTest
    @ValueSource(strings = {"svid", ""})
    void noCredential(String strategy) {
        assertThatThrownBy(() -> client().credential(binding("https://vault.lab:8200", strategy, Map.of())))
                .isInstanceOf(NoCredentialException.class);
    }

    @Test
    void unsupportedStrategy() {
        assertThatThrownBy(() -> client().credential(binding("https://vault.lab:8200", "vault-magic", Map.of())))
                .isInstanceOf(UnsupportedStrategy.class).hasMessageContaining("vault-magic");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://vault.lab:8200", "vault.lab:8200", "https://u:p@vault.lab", "https://vault.lab/x",
            "https://vault.lab/?q=1", "https://vault.lab#f", "https://"})
    void storeAddressMustBeHttpsHostPort(String address) {
        assertThatThrownBy(() -> client().credential(binding(address))).isInstanceOf(StoreNotAllowed.class);
        assertThat(jwt.calls).isEmpty();
    }

    @Test
    void allowedStores() {
        StoreServer s = store(routes());
        assertThatThrownBy(() -> client(builder().allowedStores(List.of("https://other.lab:8200"))).credential(binding(s.url())))
                .isInstanceOf(StoreNotAllowed.class);
        assertThat(s.requests).isEmpty(); // no JWT-SVID goes to a store that is not allowed
        assertThat(jwt.calls).isEmpty();
        assertThat(client(builder().allowedStores(List.of(s.url().toUpperCase().replace("HTTPS", "https")))).credential(binding(s.url()))
                .username()).isEqualTo("svc_ledger");
    }

    @Test
    void allowedStoresAreValidated() {
        assertThatThrownBy(() -> builder().allowedStores(List.of("http://vault.lab")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("allowedStores");
    }

    @Test
    void storeCertificateOutsideStoreRoots() {
        StoreServer s = store(routes());
        LigoClient c = client(builder().storeRoots(List.of(new Pki().ca))); // another CA
        assertThatThrownBy(() -> c.credential(binding(s.url()))).isInstanceOf(StoreError.class)
                .hasMessageContaining("not trusted");
        assertThat(s.requests).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"address", "audience", "authMount", "role", "secretPath"})
    void bindingThatDoesNotSayHow(String missing) {
        Binding b = binding("https://vault.lab:8200", "vault-static", Map.of(missing, ""));
        assertThatThrownBy(() -> client().credential(b)).isInstanceOfAny(StoreError.class, StoreNotAllowed.class);
    }

    @Test
    void aRedirectIsNotFollowed() {
        StoreServer s = store(r -> new StoreServer.Response(307, Map.of("Location", "https://elsewhere.example/"), new byte[0]));
        assertThatThrownBy(() -> client().credential(binding(s.url()))).isInstanceOf(StoreError.class);
        assertThat(s.requests).hasSize(1); // the JWT-SVID went to the store and nowhere else
    }

    // JV-13 for the store
    @Test
    void storeBodyOverTheLimit() {
        byte[] big = new byte[(8 << 20) + 1];
        java.util.Arrays.fill(big, (byte) ' ');
        StoreServer s = store(r -> new StoreServer.Response(200, Map.of(), big));
        assertThatThrownBy(() -> client().credential(binding(s.url()))).isInstanceOf(StoreError.class)
                .hasMessageContaining("larger");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{}", "[]", "{\"auth\":{}}", "{\"auth\":{\"client_token\":\"\"}}",
            "{\"auth\":{\"client_token\":\"t\",\"lease_duration\":-1}}", "{\"auth\":{\"client_token\":5}}"})
    void badLoginAnswers(String body) {
        StoreServer s = store(r -> new StoreServer.Response(200, body));
        assertThatThrownBy(() -> client().credential(binding(s.url()))).isInstanceOf(StoreError.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{}", "{\"data\":{\"data\":{\"username\":\"u\"}}}", "{\"data\":{\"data\":{\"password\":\"p\"}}}",
            "{\"data\":{\"data\":{\"username\":\"\",\"password\":\"p\"}}}", "{\"data\":[]}"})
    void badSecrets(String body) {
        StoreServer s = store(routes(() -> new StoreServer.Response(200, body)));
        assertThatThrownBy(() -> client().credential(binding(s.url()))).isInstanceOf(StoreError.class);
    }

    @Test
    void theJwtSourceFailingIsUnauthorized() {
        FakeJwt broken = new FakeJwt() {
            @Override
            public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extra) throws JwtSvidException {
                throw new JwtSvidException("the agent is gone: " + PASSWORD);
            }
        };
        StoreServer s = store(routes());
        LigoClient c = client(builder().jwtSource(broken));
        assertThatThrownBy(() -> c.credential(binding(s.url()))).isInstanceOf(Unauthorized.class)
                .hasMessageNotContaining(PASSWORD);
        assertThat(s.requests).isEmpty();
    }

    // JV-15
    @Test
    void namespaceGoesOnTheLoginAndTheRead() {
        StoreServer s = store(routes());
        client().credential(binding(s.url(), "vault-static", Map.of("namespace", "team-a")));
        assertThat(s.requests.stream().map(r -> r.headers().get("x-vault-namespace"))).containsExactly("team-a", "team-a");
        StoreServer s2 = store(routes());
        client().credential(binding(s2.url()));
        assertThat(s2.requests).allSatisfy(r -> assertThat(r.headers()).doesNotContainKey("x-vault-namespace"));
    }

    // JV-10
    @Test
    void noSecretIsPrintedLoggedOrSerialized() throws Exception {
        Recording log = new Recording();
        StoreServer s = store(routes());
        Credential cred = client(builder().logger(log)).credential(binding(s.url()));
        List<String> shown = List.of(cred.toString(), String.valueOf(cred), "" + cred, "%s".formatted(cred),
                "%-40s".formatted(cred), List.of(cred).toString(), Map.of("c", cred).toString(),
                java.util.Optional.of(cred).toString());
        for (String text : shown) {
            assertThat(text).doesNotContain(PASSWORD).contains("svc_ledger"); // the user name is not secret
        }
        assertThat(log.lines).isNotEmpty().allSatisfy(l -> assertThat(l).doesNotContain(PASSWORD, TOKEN, "eyJ"));
        assertThatThrownBy(() -> new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(cred))
                .isInstanceOf(java.io.NotSerializableException.class);
        assertThat(cred).isEqualTo(new Credential("svc_ledger", PASSWORD, null))
                .isNotEqualTo(new Credential("svc_ledger", PASSWORD + "x", null))
                .hasSameHashCodeAs(new Credential("svc_ledger", PASSWORD, null));
    }

    @Test
    void errorsNeverHoldABodyATokenOrAJwt() {
        String leak = PASSWORD + " " + TOKEN + " " + FakeJwt.token("https://vault.lab", ClientTest.WORKER_ID);
        List<Function<StoreServer.Request, StoreServer.Response>> handlers = List.of(
                r -> new StoreServer.Response(500, leak), r -> new StoreServer.Response(200, leak));
        for (Function<StoreServer.Request, StoreServer.Response> h : handlers) {
            StoreServer s = store(h);
            Throwable e = org.assertj.core.api.Assertions.catchThrowable(() -> client().credential(binding(s.url())));
            assertThat(e).isInstanceOf(StoreError.class);
            java.io.StringWriter w = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(w));
            assertThat(w.toString()).doesNotContain(PASSWORD, TOKEN, "eyJ");
        }
    }

    @Test
    void closeForgetsTheTokensAndLeavesTheCallersSources() {
        StoreServer s = store(routes());
        LigoClient c = builder().build();
        Binding b = binding(s.url());
        c.credential(b);
        c.close();
        assertThat(source.closed()).isFalse(); // the caller's source is the caller's to close
        assertThatThrownBy(() -> c.credential(b)).isInstanceOf(LigoException.class).hasMessageContaining("closed");
    }

    @Test
    void theAsyncTwinGivesTheSameCredentialAndTheSameErrors() throws Exception {
        StoreServer s = store(routes());
        LigoClient c = client();
        assertThat(c.credentialAsync(binding(s.url())).get().username()).isEqualTo("svc_ledger");
        Binding none = binding(s.url(), "svid", Map.of());
        assertThatThrownBy(() -> c.credentialAsync(none).join()).isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(NoCredentialException.class);
    }

    @Test
    void theErrorsNameTheBinding() {
        assertThatThrownBy(() -> client().credential(binding("http://vault.lab:8200")))
                .hasMessageContaining("workers-ledger");
    }

    // a seeded fuzz of the two parsers: whatever the store sends, a credential or a StoreError, nothing else
    @Test
    void parsersSurviveMutatedAnswers() {
        Random rnd = new Random(20261120);
        List<byte[]> seeds = List.of(login().body(), kv().body(), dynamic(90).body());
        for (int i = 0; i < 20_000; i++) {
            byte[] doc = seeds.get(rnd.nextInt(seeds.size())).clone();
            int cut = rnd.nextInt(4) == 0 ? rnd.nextInt(doc.length + 1) : doc.length;
            byte[] m = java.util.Arrays.copyOf(doc, cut);
            for (int k = rnd.nextInt(4); k > 0 && m.length > 0; k--) {
                m[rnd.nextInt(m.length)] = (byte) (rnd.nextBoolean() ? JSON_CHARS.charAt(rnd.nextInt(JSON_CHARS.length())) : rnd.nextInt(256));
            }
            for (String strategy : List.of("vault-static", "vault-dynamic")) {
                try {
                    Store.parseSecret(strategy, m, clock.now);
                } catch (StoreError expected) {
                    // refused, as it should be
                }
            }
            try {
                Store.parseLogin(m);
            } catch (StoreError expected) {
                // refused, as it should be
            }
        }
        assertThat(new String(login().body(), StandardCharsets.UTF_8)).contains(TOKEN);
    }

    @Test
    void aLeaseIsAWholeNumberOfSeconds() {
        assertThatThrownBy(() -> Store.parseSecret("vault-dynamic",
                "{\"lease_duration\":90.5,\"data\":{\"username\":\"u\",\"password\":\"p\"}}".getBytes(StandardCharsets.UTF_8), clock.now))
                .isInstanceOf(StoreError.class);
        assertThat(Store.parseLogin("{\"auth\":{\"client_token\":\"t\",\"lease_duration\":7}}".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo(new Store.Login("t", Duration.ofSeconds(7)));
    }
}
