// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.provider.SpiffeKeyManager;
import io.spiffe.provider.SpiffeTrustManager;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.X509Source;
import java.security.GeneralSecurityException;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;

/**
 * mTLS with the workload's SVID, and the check of the server's SPIFFE ID (.specs/ligo-client-sdk-java.md §3.4).
 * The key and the chain are read from the source in memory, on every handshake: nothing touches the disk (T-J1)
 * and a rotated SVID or bundle applies to the next connection.
 */
final class Tls {
    static final String[] PROTOCOLS = {"TLSv1.3"};

    private Tls() {}

    /**
     * A client context that presents the source's SVID and accepts a server of the given ID only. The JDK's host
     * name check does not apply: an SVID has no DNS name, and the trust manager checks the chain against the bundle
     * of the server's trust domain and its ID against {@code serverId}, during the handshake (T-J2).
     */
    static SSLContext context(X509Source source, SpiffeId serverId) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(new KeyManager[] {new SpiffeKeyManager(source)},
                    new TrustManager[] {new SpiffeTrustManager(source, () -> Set.of(serverId))}, null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new LigoException("cannot build the TLS context", e);
        }
    }

    static SSLParameters parameters() {
        SSLParameters p = new SSLParameters();
        p.setProtocols(PROTOCOLS);
        return p;
    }

    /** The bundle of the server's trust domain must exist before the first handshake. */
    static void check(X509Source source, SpiffeId serverId) {
        try {
            if (source.getX509Svid() == null) {
                throw new Unauthorized("the SPIFFE source has no SVID");
            }
            source.getBundleForTrustDomain(serverId.getTrustDomain());
        } catch (BundleNotFoundException e) {
            throw new Unauthorized("the SPIFFE source has no bundle for the server's trust domain");
        }
    }
}
