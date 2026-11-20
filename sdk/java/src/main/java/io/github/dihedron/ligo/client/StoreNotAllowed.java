// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The secret store of the binding is not one the client may log in to. */
public class StoreNotAllowed extends LigoException {
    private static final long serialVersionUID = 1L;

    public StoreNotAllowed(String message) {
        super(message);
    }

    public StoreNotAllowed(String message, Throwable cause) {
        super(message, cause);
    }
}
