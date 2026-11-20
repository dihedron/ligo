// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** The servers the flow checks talk to: TCP, TLS, PostgreSQL's SSLRequest, and UDP that never answers. */
final class NetServers implements AutoCloseable {
    /** A TCP listener that counts what it accepts and, with a TLS context, does a handshake (after a PostgreSQL answer). */
    final class Listener implements AutoCloseable {
        final ServerSocket socket;
        final AtomicInteger accepted = new AtomicInteger();

        Listener(SSLContext tls, byte[] postgres) {
            try {
                socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            Thread t = new Thread(() -> loop(tls, postgres), "test-listener-" + socket.getLocalPort());
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        private void loop(SSLContext tls, byte[] postgres) {
            while (!socket.isClosed()) {
                try {
                    Socket c = socket.accept();
                    accepted.incrementAndGet();
                    Thread h = new Thread(() -> handle(c, tls, postgres));
                    h.setDaemon(true);
                    h.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handle(Socket c, SSLContext tls, byte[] postgres) {
            try (c) {
                c.setSoTimeout(5000);
                Socket s = c;
                if (postgres != null) {
                    InputStream in = c.getInputStream();
                    in.readNBytes(8); // the SSLRequest
                    OutputStream out = c.getOutputStream();
                    out.write(postgres);
                    out.flush();
                    if (postgres[0] != 'S') {
                        return;
                    }
                }
                if (tls != null) {
                    SSLSocket ssl = (SSLSocket) tls.getSocketFactory().createSocket(s, (InputStream) null, true);
                    ssl.setUseClientMode(false);
                    ssl.startHandshake();
                    ssl.getInputStream().read();
                } else if (postgres == null) {
                    c.getInputStream().read();
                }
            } catch (IOException e) {
                // a client that gave up or failed the handshake
            }
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException e) {
                // gone
            }
        }
    }

    private final List<AutoCloseable> open = new ArrayList<>();

    Listener tcp() {
        return add(new Listener(null, null));
    }

    Listener tls(SSLContext ctx) {
        return add(new Listener(ctx, null));
    }

    /** A fake PostgreSQL: answers the SSLRequest with {@code answer} ('S' or 'N' or 'E'), then TLS when 'S'. */
    Listener postgres(SSLContext ctx, byte answer) {
        return add(new Listener(ctx, new byte[] {answer}));
    }

    private Listener add(Listener l) {
        open.add(l);
        return l;
    }

    /** A UDP socket that reads and never answers. */
    DatagramSocket udpSilent() {
        try {
            DatagramSocket s = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            Thread t = new Thread(() -> {
                byte[] buf = new byte[16];
                while (!s.isClosed()) {
                    try {
                        s.receive(new DatagramPacket(buf, buf.length));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            open.add(s::close);
            return s;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static int closedTcpPort() {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static int closedUdpPort() {
        try (DatagramSocket s = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A TLS context for a server: the leaf of {@code leaf}, no client certificate asked. */
    static SSLContext context(Pki.Leaf leaf) {
        try {
            char[] pw = new char[0];
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            keys.setKeyEntry("k", leaf.key(), pw, new Certificate[] {leaf.certificate()});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keys, pw);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        for (AutoCloseable c : open) {
            try {
                c.close();
            } catch (Exception e) {
                // gone
            }
        }
    }
}
