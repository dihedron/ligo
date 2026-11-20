// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** An in-process Vault: server authentication only, a certificate for 127.0.0.1, every request recorded. */
final class StoreServer implements AutoCloseable {
    record Request(String method, String path, Map<String, String> headers, String body) {}

    record Response(int status, Map<String, String> headers, byte[] body) {
        Response(int status, String body) {
            this(status, Map.of(), body.getBytes(StandardCharsets.UTF_8));
        }
    }

    final List<Request> requests = new CopyOnWriteArrayList<>();
    private final HttpsServer server;

    StoreServer(Pki pki, Function<Request, Response> handler) {
        try {
            Pki.Leaf leaf = pki.server("127.0.0.1");
            char[] pw = new char[0];
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("store", leaf.key(), pw, new Certificate[] {leaf.certificate()});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, pw);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(ctx));
            server.createContext("/", ex -> serve(ex, handler));
            server.start();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String url() {
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    private void serve(HttpExchange ex, Function<Request, Response> handler) throws IOException {
        try (ex) {
            Map<String, String> headers = new java.util.HashMap<>();
            ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), v.get(0)));
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Request r = new Request(ex.getRequestMethod(), ex.getRequestURI().getRawPath(), headers, body);
            requests.add(r);
            Response resp = handler.apply(r);
            resp.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
            if (resp.body().length == 0) {
                ex.sendResponseHeaders(resp.status(), -1);
            } else {
                ex.sendResponseHeaders(resp.status(), resp.body().length);
                ex.getResponseBody().write(resp.body());
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
