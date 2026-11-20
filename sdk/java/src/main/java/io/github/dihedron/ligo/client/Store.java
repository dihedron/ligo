// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/** Reading a binding's credential from a Vault-compatible secret store (.specs/ligo-client-sdk.md §3.3). */
final class Store {
    static final int MAX_BODY = 8 << 20; // T-C7
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(15);
    static final long MAX_LEASE = 100L * 365 * 24 * 3600; // seconds

    static final String STATIC = "vault-static";
    static final String DYNAMIC = "vault-dynamic";
    static final String NONE = "svid"; // of the builtin none.v1 store: the SVID is the credential

    private static final ObjectMapper JSON = new ObjectMapper();

    /** A failed call to a store: the status when there was an answer, never its body. */
    static final class CallException extends Exception {
        private static final long serialVersionUID = 1L;
        final int status;

        CallException(String message, int status) {
            super(message);
            this.status = status;
        }
    }

    record Login(String token, Duration ttl) {}

    private final HttpClient http;

    /** @param roots the store's trust anchors; empty means the JDK's */
    Store(Collection<X509Certificate> roots) {
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(CALL_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1) // T-C2
                .sslParameters(parameters());
        if (!roots.isEmpty()) {
            b.sslContext(context(roots));
        }
        this.http = b.build();
    }

    /** TLS 1.2 or later, with the name verified: the store has a DNS or IP name, unlike ligo. */
    private static SSLParameters parameters() {
        SSLParameters p = new SSLParameters();
        p.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        p.setEndpointIdentificationAlgorithm("HTTPS");
        return p;
    }

    private static SSLContext context(Collection<X509Certificate> roots) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            int i = 0;
            for (X509Certificate c : roots) {
                ks.setCertificateEntry("root" + i++, c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException("storeRoots: " + e.getMessage(), e);
        }
    }

    /** Checks a store address and returns it as https://host:port. */
    static String address(String raw) {
        URI u;
        try {
            u = new URI(raw);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("\"" + raw + "\": https://host:port is required");
        }
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        if (!"https".equals(u.getScheme()) || u.getHost() == null || u.getRawUserInfo() != null
                || !path.replace("/", "").isEmpty() || u.getRawQuery() != null || u.getRawFragment() != null) {
            throw new IllegalArgumentException("\"" + raw + "\": https://host:port is required");
        }
        String host = u.getHost().toLowerCase(Locale.ROOT).replaceAll("(?:^\\[|]$)", "");
        return "https://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + (u.getPort() < 0 ? 443 : u.getPort());
    }

    /** One call to a store; returns the body of a 200. Redirects are never followed (T-C2). */
    byte[] call(String address, String method, String path, String token, String namespace, String body)
            throws CallException {
        URI uri;
        try {
            URI base = URI.create(address);
            uri = new URI("https", null, base.getHost(), base.getPort(), "/v1/" + path.replaceFirst("^/+", ""), null, null);
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new CallException("the path is not valid", 0);
        }
        HttpRequest.Builder r = HttpRequest.newBuilder(uri).timeout(CALL_TIMEOUT).header("Accept", "application/json");
        if (body != null) {
            r.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            r.method(method, HttpRequest.BodyPublishers.noBody());
        }
        if (!token.isEmpty()) {
            r.header("X-Vault-Token", token);
        }
        if (!namespace.isEmpty()) {
            r.header("X-Vault-Namespace", namespace);
        }
        try {
            HttpResponse<InputStream> resp = http.send(r.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = resp.body()) {
                if (resp.statusCode() != 200) {
                    throw new CallException("status " + resp.statusCode(), resp.statusCode());
                }
                byte[] data = in.readNBytes(MAX_BODY + 1);
                if (data.length > MAX_BODY) {
                    throw new CallException("the answer is larger than " + MAX_BODY + " bytes", 200);
                }
                return data;
            }
        } catch (IOException e) {
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof CertificateException) {
                    throw new CallException("the store's certificate is not trusted", 0);
                }
            }
            throw new CallException("the call failed: " + e.getClass().getSimpleName(), 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CallException("the call was interrupted", 0);
        }
    }

    static String loginBody(String role, String jwt) {
        try {
            return JSON.writeValueAsString(Map.of("role", role, "jwt", jwt));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e); // strings always serialize
        }
    }

    private static JsonNode object(byte[] data, String what) {
        try {
            JsonNode doc = JSON.readTree(data);
            if (doc != null && doc.isObject()) {
                return doc;
            }
        } catch (IOException e) {
            // not JSON: the same refusal as a document of another shape
        }
        throw new StoreError("the answer is not " + what);
    }

    private static long lease(JsonNode v) {
        if (v == null || !v.isIntegralNumber() || !v.canConvertToLong() || v.asLong() < 0 || v.asLong() > MAX_LEASE) {
            throw new StoreError("the answer's lease is out of range");
        }
        return v.asLong();
    }

    private static String text(JsonNode v) {
        return v != null && v.isTextual() ? v.asText() : "";
    }

    /** The token of a login answer, and its TTL. */
    static Login parseLogin(byte[] data) {
        JsonNode auth = object(data, "a login").get("auth");
        String token = auth != null && auth.isObject() ? text(auth.get("client_token")) : "";
        if (token.isEmpty()) {
            throw new StoreError("the answer has no token");
        }
        JsonNode ttl = auth.get("lease_duration");
        return new Login(token, Duration.ofSeconds(ttl == null ? 0 : lease(ttl)));
    }

    /** A KV version 2 secret (vault-static) or database credentials (vault-dynamic). */
    static Credential parseSecret(String strategy, byte[] data, Instant now) {
        JsonNode doc = object(data, "a secret");
        Instant expires = null;
        JsonNode inner;
        if (STATIC.equals(strategy)) {
            JsonNode outer = doc.get("data");
            inner = outer != null && outer.isObject() ? outer.get("data") : null;
        } else {
            long lease = lease(doc.get("lease_duration"));
            if (lease <= 0) {
                throw new StoreError("the answer's lease is out of range");
            }
            expires = now.plusSeconds(lease);
            inner = doc.get("data");
        }
        String user = inner != null && inner.isObject() ? text(inner.get("username")) : "";
        String password = inner != null && inner.isObject() ? text(inner.get("password")) : "";
        if (user.isEmpty() || password.isEmpty()) {
            throw new StoreError("the answer has no username and password");
        }
        return new Credential(user, password, expires);
    }
}
