// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The binding has no credential to read: its strategy is svid, so the SVID is the credential. */
public class NoCredentialException extends LigoException {
    private static final long serialVersionUID = 1L;

    public NoCredentialException(String message) {
        super(message);
    }

    public NoCredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
