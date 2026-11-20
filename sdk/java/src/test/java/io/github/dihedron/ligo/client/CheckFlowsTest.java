// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JV-F: the client chooses the handshakes from what it knows. */
class CheckFlowsTest {
    Pki pki;
    NetServers net;
    final List<AutoCloseable> open = new ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new Pki();
        net = new NetServers();
        open.add(net);
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    @Test
    void checkFlowsChoosesTheHandshakes() throws Exception {
        NetServers.Listener pg = net.postgres(NetServers.context(pki.dnsServer("db.test")), (byte) 'S');
        NetServers.Listener svid = net.tls(NetServers.context(pki.svid(ClientTest.LIGO_ID)));
        String flows = """
                {"items": [{"binding": "workers-ledger", "source": "workers", "target": "ledger", "flows": [
                  {"name": "db", "protocol": "TCP", "destination": "127.0.0.1", "ports": [%d], "tls": true,
                   "serverName": "db.test", "declaredBy": "target:ledger"},
                  {"name": "ligo", "protocol": "TCP", "destination": "127.0.0.1", "ports": [%d], "tls": true,
                   "declaredBy": "ligo"}]}]}
                """.formatted(pg.port(), svid.port());
        TestServer s = new TestServer(pki, ClientTest.LIGO_ID, pki,
                r -> ClientTest.ok(r.target().startsWith("/v1/flows") ? flows : ClientTest.BINDINGS));
        open.add(s);
        LigoClient c = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID)
                .x509Source(new StaticSource(pki, ClientTest.WORKER_ID)).build();
        open.add(c);
        FlowOptions o = FlowOptions.builder().roots(List.of(pki.ca)).timeout(Duration.ofSeconds(2)).tries(1).build();
        FlowResults res = c.checkFlows("ledger", o);
        assertThat(res).hasSize(2);
        assertThat(res.get(0).protocol()).isEqualTo("postgresql");
        assertThat(res.get(1).protocol()).isEqualTo("spire");
        assertThat(res.ok()).as(res.toString()).isTrue();
        assertThat(c.checkFlowsAsync("ledger", o).get().ok()).isTrue();
    }
}
