// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The flows add up to more checks than one call runs ({@link FlowCheck#MAX_CHECKS}). */
public class TooManyFlows extends LigoException {
    private static final long serialVersionUID = 1L;

    public TooManyFlows(String message) {
        super(message);
    }
}
