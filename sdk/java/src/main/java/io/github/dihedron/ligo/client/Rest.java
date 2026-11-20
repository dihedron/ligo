// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** One conditional GET of the workload API, over mTLS, with the server's ID checked in the handshake. */
final class Rest implements Wire {
    static final int MAX_BODY = 8 << 20; // T-C7
    static final Duration MAX_RETRY_AFTER = Duration.ofHours(1); // a longer one is ignored
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient http;
    private final String host;
    private final int port;

    Rest(HttpClient http, String host, int port) {
        this.http = http;
        this.host = host;
        this.port = port;
    }

    @Override
    public Answer get(Kind kind, Map<String, String> query, String etag) {
        String path = kind == Kind.BINDINGS ? "/v1/bindings" : "/v1/flows";
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path, query)).timeout(CALL_TIMEOUT)
                .header("Accept", "application/json").GET();
        if (!etag.isEmpty()) {
            request.header("If-None-Match", etag);
        }
        try {
            HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = response.body()) {
                return answer(response, in, etag);
            }
        } catch (IOException e) {
            throw failure(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Unavailable("the call to ligo was interrupted");
        }
    }

    @Override
    public void close() {
        // the JDK's HttpClient has no close before Java 21: its connections end with it
    }

    private Answer answer(HttpResponse<InputStream> response, InputStream in, String etag) throws IOException {
        int status = response.statusCode();
        if (status == 304) {
            return new Answer(List.of(), etag, true);
        }
        if (status == 401 || status == 403) {
            throw new Unauthorized("ligo refused the workload: " + status);
        }
        if (status == 503 || status == 429) {
            throw new Unavailable("ligo is unavailable: " + status,
                    retryAfter(response.headers().firstValue("Retry-After").orElse(null)), null);
        }
        if (status != 200) {
            throw new LigoException("unexpected answer: " + status);
        }
        byte[] body = in.readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) {
            throw new LigoException("the answer is larger than " + MAX_BODY + " bytes");
        }
        return new Answer(Documents.items(body), response.headers().firstValue("ETag").orElse(""), false);
    }

    private URI uri(String path, Map<String, String> query) {
        String q = query.isEmpty() ? null : query.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        try {
            URI u = new URI("https", null, host, port, path, null, null);
            return q == null ? u : URI.create(u + "?" + q);
        } catch (URISyntaxException e) {
            throw new LigoException("the address is not valid: " + host);
        }
    }

    /** A refused certificate is the server's ID or chain being wrong; anything else is a network failure. */
    static LigoException failure(IOException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateException) {
                return new Unauthorized("the server is not the one this client accepts", e);
            }
        }
        return new Unavailable("the call to ligo failed: " + e.getClass().getSimpleName(), null, e);
    }

    static Duration retryAfter(String value) {
        if (value == null) {
            return null;
        }
        try {
            Duration d = Duration.ofSeconds(Long.parseLong(value.trim()));
            return !d.isZero() && !d.isNegative() && d.compareTo(MAX_RETRY_AFTER) <= 0 ? d : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

}
