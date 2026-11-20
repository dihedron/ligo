// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/**
 * A flow does not say how its TLS starts: this chooses it per flow and port.
 */
@FunctionalInterface
public interface Handshake {
    /** TLS inside PostgreSQL's protocol, after its SSLRequest. */
    String POSTGRESQL = "postgresql";
    /** An X509-SVID, verified against the trust bundle: it has no name. */
    String SPIRE = "spire";

    /** {@link #POSTGRESQL}, {@link #SPIRE}, or null for plain TLS. */
    String choose(Flow flow, int port);
}
