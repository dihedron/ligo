// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** What a watch saw. */
public enum EventKind {
    /** A binding appeared; also every binding at the first poll. */
    ADDED,
    /** A known binding has another revision. */
    CHANGED,
    /** A known binding is gone: revoked or expired. */
    REMOVED,
    /** A credential was read for the binding. */
    CREDENTIAL_ROTATED
}
