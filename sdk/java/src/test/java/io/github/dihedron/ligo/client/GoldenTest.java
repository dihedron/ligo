// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** JV-G: the documents of api/testdata/workload decode to the values the Go and Python SDKs' tests expect. */
class GoldenTest {
    static final Path DIR = Path.of("..", "..", "api", "testdata", "workload");
    static final ObjectMapper JSON = new ObjectMapper();

    static byte[] read(String name) throws IOException {
        return Files.readAllBytes(DIR.resolve(name));
    }

    /** Through text, so that numbers have the node types the parser gives them. */
    static JsonNode tree(Object o) throws IOException {
        return JSON.readTree(JSON.writeValueAsString(o));
    }

    @Test
    void bindingsAndFlowsEqualTheExpectedValues() throws IOException {
        JsonNode want = JSON.readTree(read("expected.json"));
        List<Object> bindings = new ArrayList<>();
        for (JsonNode d : Documents.items(read("bindings.json"))) {
            Binding b = Documents.binding(d);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", b.id());
            m.put("name", b.name());
            m.put("source", b.source());
            m.put("target", b.target());
            m.put("accessLevel", b.accessLevel());
            m.put("platformType", b.platformType());
            m.put("platform", b.platform());
            m.put("revision", b.revision());
            m.put("updatedAt", b.updatedAt() == null ? 0 : b.updatedAt().getEpochSecond());
            m.put("description", b.description());
            m.put("annotations", b.annotations());
            m.put("endpoint", b.endpoint());
            m.put("auth", Map.of("strategy", b.auth().strategy(), "storeType", b.auth().storeType(),
                    "storeInstance", b.auth().storeInstance(), "config", b.auth().config()));
            bindings.add(m);
        }
        assertThat(tree(bindings)).isEqualTo(want.get("bindings"));

        List<Object> flows = new ArrayList<>();
        for (JsonNode d : Documents.items(read("flows.json"))) {
            BindingFlows bf = Documents.flows(d);
            List<Object> fl = new ArrayList<>();
            for (Flow f : bf.flows()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", f.name());
                m.put("purpose", f.purpose());
                m.put("protocol", f.protocol());
                m.put("destination", f.destination());
                m.put("ports", f.ports().stream().map(p -> List.of(p.low(), p.high())).toList());
                m.put("tls", f.tls());
                m.put("serverName", f.serverName());
                m.put("description", f.description());
                m.put("declaredBy", f.declaredBy());
                fl.add(m);
            }
            flows.add(Map.of("binding", bf.binding(), "source", bf.source(), "target", bf.target(), "flows", fl));
        }
        assertThat(tree(flows)).isEqualTo(want.get("flows"));
    }

    @Test
    void storeDocumentsEqualTheExpectedValues() throws IOException {
        JsonNode want = JSON.readTree(read("expected.json"));
        Store.Login login = Store.parseLogin(read("store-login.json"));
        assertThat(tree(Map.of("token", login.token(), "ttlSeconds", login.ttl().toSeconds()))).isEqualTo(want.get("login"));
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        for (String kind : List.of("static", "dynamic")) {
            Credential c = Store.parseSecret("vault-" + kind, read("store-" + kind + ".json"), now);
            long lease = c.expires() == null ? 0 : c.expires().getEpochSecond() - now.getEpochSecond();
            assertThat(tree(Map.of("username", c.username(), "password", c.password(), "leaseSeconds", lease)))
                    .isEqualTo(want.get(kind));
        }
    }
}
