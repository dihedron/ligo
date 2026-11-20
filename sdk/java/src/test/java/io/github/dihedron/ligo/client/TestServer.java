// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** An in-process ligo: TLS 1.3, a client certificate required, an SVID with a URI SAN and no DNS name. */
final class TestServer implements AutoCloseable {
    record Request(String target, Map<String, String> headers, String peer) {}

    record Response(int status, Map<String, String> headers, byte[] body) {}

    final List<Request> requests = new CopyOnWriteArrayList<>();
    private final HttpsServer server;

    TestServer(Pki serverPki, String serverId, Pki clientTrust, Function<Request, Response> handler) {
        try {
            Pki.Leaf leaf = serverPki.svid(serverId);
            char[] pw = new char[0];
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("svid", leaf.key(), pw, new Certificate[] {leaf.certificate()});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, pw);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("ca", clientTrust.ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
                @Override
                public void configure(HttpsParameters params) {
                    javax.net.ssl.SSLParameters sp = ctx.getDefaultSSLParameters();
                    sp.setProtocols(new String[] {"TLSv1.3"});
                    sp.setNeedClientAuth(true);
                    params.setSSLParameters(sp);
                }
            });
            server.createContext("/", ex -> serve(ex, handler));
            server.start();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String address() {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    private void serve(com.sun.net.httpserver.HttpExchange ex, Function<Request, Response> handler) throws IOException {
        try (ex) {
            Map<String, String> headers = new java.util.HashMap<>();
            ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), v.get(0)));
            Request r = new Request(ex.getRequestURI().toString(), headers, peer((HttpsExchange) ex));
            requests.add(r);
            Response resp = handler.apply(r);
            resp.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
            if (resp.status() == 304 || resp.body().length == 0) {
                ex.sendResponseHeaders(resp.status(), -1);
            } else {
                ex.sendResponseHeaders(resp.status(), resp.body().length);
                ex.getResponseBody().write(resp.body());
            }
        }
    }

    private static String peer(HttpsExchange ex) {
        try {
            X509Certificate leaf = (X509Certificate) ex.getSSLSession().getPeerCertificates()[0];
            for (List<?> san : leaf.getSubjectAlternativeNames()) {
                if ((Integer) san.get(0) == 6) {
                    return (String) san.get(1);
                }
            }
        } catch (Exception e) {
            // no peer certificate
        }
        return "";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
