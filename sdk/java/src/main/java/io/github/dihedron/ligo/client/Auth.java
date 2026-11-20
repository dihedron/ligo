// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.Map;

/**
 * Where the binding's credential is kept.
 *
 * @param strategy {@code vault-static}, {@code vault-dynamic}, or {@code svid} when the SVID is the credential
 * @param config address, audience, authMount, role, secretPath or credsPath
 */
public record Auth(String strategy, String storeType, String storeInstance, Map<String, String> config) {
    public Auth {
        config = Map.copyOf(config);
    }
}
