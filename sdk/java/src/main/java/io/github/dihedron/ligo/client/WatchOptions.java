// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/**
 * What a watch does besides reporting bindings.
 *
 * @param credentials also read the credential of each new or changed binding, and again at two thirds of a lease
 */
public record WatchOptions(boolean credentials) {
    public static WatchOptions bindingsOnly() {
        return new WatchOptions(false);
    }

    public static WatchOptions withCredentials() {
        return new WatchOptions(true);
    }
}
