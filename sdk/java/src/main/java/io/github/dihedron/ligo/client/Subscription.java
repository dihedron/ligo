// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** A running watch that delivers to a callback; {@link #cancel()} stops it and waits for its thread. */
public interface Subscription extends AutoCloseable {
    void cancel();

    @Override
    default void close() {
        cancel();
    }
}
