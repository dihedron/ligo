// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The binding's strategy is one this SDK does not know. */
public class UnsupportedStrategy extends LigoException {
    private static final long serialVersionUID = 1L;

    public UnsupportedStrategy(String message) {
        super(message);
    }

    public UnsupportedStrategy(String message, Throwable cause) {
        super(message, cause);
    }
}
