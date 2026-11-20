// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** ligo or a store refused the workload, or the server is not the one the client accepts. */
public class Unauthorized extends LigoException {
    private static final long serialVersionUID = 1L;

    public Unauthorized(String message) {
        super(message);
    }

    public Unauthorized(String message, Throwable cause) {
        super(message, cause);
    }
}
