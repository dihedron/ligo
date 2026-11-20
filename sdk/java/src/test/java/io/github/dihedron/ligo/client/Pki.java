// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** An in-memory CA and its SVIDs, strict enough for the JDK: SKI, AKI, a URI SAN and no DNS name. */
final class Pki {
    record Leaf(X509Certificate certificate, PrivateKey key) {}

    final X509Certificate ca;
    private final KeyPair caKey;
    private long serial = 1;

    Pki() {
        try {
            caKey = keys();
            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            JcaX509v3CertificateBuilder b = builder(new X500Name("CN=test CA"), new X500Name("CN=test CA"),
                    caKey.getPublic());
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            b.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(caKey.getPublic()));
            ca = sign(b, caKey.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    Leaf svid(String spiffeId) {
        try {
            KeyPair key = keys();
            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            JcaX509v3CertificateBuilder b = builder(new X500Name("CN=test CA"), new X500Name("O=SPIRE"), key.getPublic());
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            b.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
            b.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, spiffeId)));
            b.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(key.getPublic()));
            b.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(ca));
            return new Leaf(sign(b, caKey.getPrivate()), key.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private JcaX509v3CertificateBuilder builder(X500Name issuer, X500Name subject, java.security.PublicKey key) {
        long now = System.currentTimeMillis();
        return new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial++), new Date(now - 3_600_000),
                new Date(now + 3_600_000), subject, key);
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder b, PrivateKey key) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key)));
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }
}
