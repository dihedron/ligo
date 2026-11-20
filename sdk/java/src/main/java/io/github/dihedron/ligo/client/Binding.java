// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One binding of the calling workload. The maps are unmodifiable copies; {@code description} and
 * {@code annotations} are text, never interpreted by the SDK.
 *
 * @param spec differs per platform type
 */
public record Binding(String id, String name, String source, String target, String accessLevel, String platformType,
        String platform, long revision, Instant updatedAt, Map<String, Object> spec, Auth auth, String description,
        Map<String, String> annotations) {
    public Binding {
        spec = Collections.unmodifiableMap(new LinkedHashMap<>(spec));
        annotations = Map.copyOf(annotations);
    }

    /** The spec's "endpoint", or "" when the platform type has none. */
    public String endpoint() {
        return spec.get("endpoint") instanceof String e ? e : "";
    }
}
