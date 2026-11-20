// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.time.Duration;

/** ligo or a store cannot answer now: try again, after {@link #retryAfter()} when it is set. */
public class Unavailable extends LigoException {
    private static final long serialVersionUID = 1L;

    private final Duration retryAfter;

    public Unavailable(String message, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.retryAfter = retryAfter;
    }

    public Unavailable(String message) {
        this(message, null, null);
    }

    /** What the server asked for in Retry-After, or null. */
    public Duration retryAfter() {
        return retryAfter;
    }
}
