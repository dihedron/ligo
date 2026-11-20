// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** What to ask for: a target, a platform type, or both; null or empty means all. */
public record Filter(String target, String platformType) {
    public Filter {
        target = target == null ? "" : target;
        platformType = platformType == null ? "" : platformType;
    }

    public static Filter all() {
        return new Filter("", "");
    }

    public static Filter target(String target) {
        return new Filter(target, "");
    }
}
