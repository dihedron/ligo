// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Objects;

/**
 * What a workload presents to its target. The password is hidden from {@code toString} and every formatting of it,
 * and the record is not {@code Serializable}: no log line, exception or dump of state holds it.
 *
 * @param expires when the lease ends, or null when the store gives none
 */
public record Credential(String username, String password, Instant expires) {
    public Credential {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
    }

    @Override
    public String toString() {
        return "Credential[username=" + username + ", password=[hidden], expires=" + expires + "]";
    }

    /** The secret is compared in constant time. */
    @Override
    public boolean equals(Object o) {
        return o instanceof Credential c && username.equals(c.username) && Objects.equals(expires, c.expires)
                && MessageDigest.isEqual(password.getBytes(StandardCharsets.UTF_8), c.password.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, expires);
    }
}
