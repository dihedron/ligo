// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The base of every error the SDK raises on purpose. A message holds a status, never a body, a token or a password. */
public class LigoException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public LigoException(String message) {
        super(message);
    }

    public LigoException(String message, Throwable cause) {
        super(message, cause);
    }
}
