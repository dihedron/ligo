// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The JSON of the workload API as the SDK's records. Default typing is off: a document is data, never a class (T-J5). */
final class Documents {
    private static final ObjectMapper JSON = new ObjectMapper();

    private Documents() {}

    /** The "items" of an answer. */
    static List<JsonNode> items(byte[] body) {
        JsonNode doc;
        try {
            doc = JSON.readTree(body);
        } catch (IOException e) {
            throw new LigoException("the answer is not a JSON document");
        }
        if (doc == null || !doc.path("items").isArray()) {
            throw new LigoException("the answer has no list of items");
        }
        List<JsonNode> items = new ArrayList<>();
        doc.get("items").forEach(items::add);
        return items;
    }

    static Binding binding(JsonNode d) {
        object(d, "an item of a bindings document");
        JsonNode auth = object(d.path("auth"), "auth");
        JsonNode config = object(auth.path("config"), "auth.config");
        JsonNode revision = d.path("revision");
        if (!revision.isMissingNode() && !revision.isNull() && !revision.isIntegralNumber()) {
            throw new LigoException("the answer is not a bindings document: revision is not an integer");
        }
        Map<String, String> configuration = new LinkedHashMap<>();
        config.fields().forEachRemaining(e -> configuration.put(e.getKey(), e.getValue().asText())); // the store plugins write strings
        Map<String, String> annotations = new LinkedHashMap<>();
        object(d.path("annotations"), "annotations").fields().forEachRemaining(e -> {
            if (e.getValue().isTextual()) {
                annotations.put(e.getKey(), e.getValue().asText());
            }
        });
        return new Binding(text(d, "id"), text(d, "name"), text(d, "source"), text(d, "target"), text(d, "accessLevel"),
                text(d, "platformType"), text(d, "platform"), revision.asLong(0), instant(d.path("updatedAt")),
                map(object(d.path("spec"), "spec")),
                new Auth(text(auth, "secretStorageStrategy"), text(auth, "secretStoreType"),
                        text(auth, "secretStoreInstance"), configuration),
                text(d, "description"), annotations);
    }

    static BindingFlows flows(JsonNode d) {
        object(d, "an item of a flows document");
        List<Flow> flows = new ArrayList<>();
        JsonNode list = d.path("flows");
        if (!list.isMissingNode() && !list.isNull() && !list.isArray()) {
            throw new LigoException("the answer is not a flows document: flows is not a list");
        }
        for (JsonNode f : list) {
            object(f, "a flow");
            List<PortRange> ports = new ArrayList<>();
            JsonNode portList = f.path("ports");
            if (!portList.isMissingNode() && !portList.isNull() && !portList.isArray()) {
                throw new LigoException("the answer is not a flows document: ports is not a list");
            }
            portList.forEach(p -> ports.add(port(p)));
            flows.add(new Flow(text(f, "name"), text(f, "purpose"), text(f, "protocol"), text(f, "destination"), ports,
                    f.path("tls").asBoolean(false), text(f, "serverName"), text(f, "description"),
                    text(f, "declaredBy")));
        }
        return new BindingFlows(text(d, "binding"), text(d, "source"), text(d, "target"), flows);
    }

    /** A port as ligo writes it: a number, or "low-high". */
    private static PortRange port(JsonNode p) {
        if (p.isIntegralNumber() && p.canConvertToInt()) {
            return new PortRange(p.intValue(), p.intValue());
        }
        if (p.isTextual()) {
            String[] parts = p.asText().split("-", -1);
            if (parts.length == 2 && parts[0].matches("[0-9]{1,5}") && parts[1].matches("[0-9]{1,5}")) {
                return new PortRange(Integer.parseInt(parts[0]), Integer.parseInt(parts[1]));
            }
        }
        throw new LigoException("the answer is not a flows document: a port is a number or \"low-high\"");
    }

    private static String text(JsonNode d, String key) {
        JsonNode v = d.path(key);
        if (v.isMissingNode() || v.isNull()) {
            return "";
        }
        if (!v.isTextual()) {
            throw new LigoException("the answer is not a bindings or flows document: " + key + " is not a string");
        }
        return v.asText();
    }

    private static JsonNode object(JsonNode v, String what) {
        if (v.isMissingNode() || v.isNull()) {
            return JSON.createObjectNode();
        }
        if (!v.isObject()) {
            throw new LigoException("the answer is not a bindings or flows document: " + what + " is not an object");
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(JsonNode v) {
        return JSON.convertValue(v, Map.class);
    }

    private static Instant instant(JsonNode v) {
        if (!v.isTextual()) {
            return null;
        }
        try {
            return Instant.parse(v.asText());
        } catch (DateTimeParseException e) {
            throw new LigoException("the answer is not a bindings document: updatedAt is not a time");
        }
    }
}
