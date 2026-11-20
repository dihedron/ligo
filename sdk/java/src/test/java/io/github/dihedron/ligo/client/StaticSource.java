// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.X509Source;
import java.io.StringWriter;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/** An X509Source with a fixed SVID and bundle, as the tests of the other SDKs have. */
final class StaticSource implements X509Source {
    private final X509Svid svid;
    private final X509Bundle bundle;
    private final AtomicBoolean closed = new AtomicBoolean();

    StaticSource(Pki pki, String spiffeId) {
        try {
            Pki.Leaf leaf = pki.svid(spiffeId);
            svid = X509Svid.parse(pem(leaf.certificate()).getBytes(), pem(leaf.key()).getBytes());
            bundle = new X509Bundle(svid.getSpiffeId().getTrustDomain(), Set.of(pki.ca));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    boolean closed() {
        return closed.get();
    }

    @Override
    public X509Svid getX509Svid() {
        return svid;
    }

    @Override
    public X509Bundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
        return bundle.getBundleForTrustDomain(trustDomain);
    }

    @Override
    public void close() {
        closed.set(true);
    }

    static String pem(Object o) throws Exception {
        StringWriter w = new StringWriter();
        try (JcaPEMWriter p = new JcaPEMWriter(w)) {
            // java-spiffe reads a key as PKCS#8, not as the traditional "EC PRIVATE KEY"
            p.writeObject(o instanceof java.security.PrivateKey k ? new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(k, null) : o);
        }
        return w.toString();
    }

}
