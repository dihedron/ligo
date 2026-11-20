// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The secret store answered with an error, or with something that is not a credential. */
public class StoreError extends LigoException {
    private static final long serialVersionUID = 1L;

    public StoreError(String message) {
        super(message);
    }

    public StoreError(String message, Throwable cause) {
        super(message, cause);
    }
}
