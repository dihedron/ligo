// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

/** One transport to ligo's workload API: REST or gRPC. Both answer with the same JSON items, so one decoder serves. */
interface Wire extends AutoCloseable {
    enum Kind { BINDINGS, FLOWS }

    /** What came back: the items and the ETag, or notModified. */
    record Answer(List<JsonNode> items, String etag, boolean notModified) {}

    /** One conditional read; {@code query} holds {@code target} and {@code platformType}. */
    Answer get(Kind kind, Map<String, String> query, String etag);

    @Override
    void close();
}
