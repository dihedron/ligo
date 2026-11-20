// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JV-11, JV-12 and JV-T2 through a client, a server and real threads. */
class WatchClientTest {
    static final Duration WAIT = Duration.ofSeconds(10);

    Pki pki;
    StaticSource source;
    final List<AutoCloseable> open = new ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new Pki();
        source = new StaticSource(pki, ClientTest.WORKER_ID);
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    static Thread[] ligoThreads() {
        return Thread.getAllStackTraces().keySet().stream().filter(t -> t.getName().startsWith("ligo-") && t.isAlive())
                .toArray(Thread[]::new);
    }

    @Test
    void anIteratorSeesAddedThenRemovedAndEndsOnClose() throws Exception {
        AtomicReference<String> doc = new AtomicReference<>(ClientTest.BINDINGS);
        TestServer s = new TestServer(pki, ClientTest.LIGO_ID, pki, r -> ClientTest.ok(doc.get()));
        open.add(s);
        Semaphore step = new Semaphore(0);
        CredentialTest.Ticking clock = new CredentialTest.Ticking();
        LigoClient c = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID).x509Source(source)
                .clock(clock).sleeper(d -> { // a sleep is a step of the test, and moves the clock
                    try {
                        step.acquire();
                    } catch (InterruptedException e) {
                        return true; // the watch is closed
                    }
                    clock.now = clock.now.plus(d);
                    return false;
                }).build();
        open.add(c);
        Watch w = c.watch(Filter.target("ledger"), WatchOptions.bindingsOnly());
        Event added = w.poll(WAIT).orElseThrow();
        assertThat(added.kind()).isEqualTo(EventKind.ADDED);
        assertThat(added.binding().name()).isEqualTo("workers-ledger");
        assertThat(w.poll(Duration.ofMillis(200))).isEmpty(); // nothing changed yet
        doc.set("{\"items\":[]}");
        step.release();
        Event removed = w.poll(WAIT).orElseThrow();
        assertThat(removed.kind()).isEqualTo(EventKind.REMOVED);
        assertThat(removed.previous().name()).isEqualTo("workers-ledger");
        c.close();
        assertThat(w.iterator().hasNext()).isFalse();
        assertThat(ligoThreads()).isEmpty(); // JV-T2
    }

    @Test
    void aListenerGetsTheEventsInOrderAndCancelStopsIt() throws Exception {
        TestServer s = new TestServer(pki, ClientTest.LIGO_ID, pki, r -> ClientTest.ok(ClientTest.BINDINGS));
        open.add(s);
        List<EventKind> got = new CopyOnWriteArrayList<>();
        LigoClient c = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID).x509Source(source).build();
        open.add(c);
        Subscription sub = c.watch(Filter.all(), WatchOptions.bindingsOnly(), e -> {
            got.add(e.kind());
            throw new IllegalStateException("a failing listener does not end the watch");
        });
        long end = System.nanoTime() + WAIT.toNanos();
        while (got.isEmpty() && System.nanoTime() < end) {
            Thread.sleep(20);
        }
        sub.cancel();
        assertThat(got).containsExactly(EventKind.ADDED);
        assertThat(ligoThreads()).isEmpty();
    }

    @Test
    void closingTheClientEndsTheWatchesAndTheThreads() throws Exception {
        TestServer s = new TestServer(pki, ClientTest.LIGO_ID, pki, r -> ClientTest.ok("{\"items\":[]}"));
        open.add(s);
        LigoClient c = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID).x509Source(source).build();
        Watch a = c.watch(Filter.all(), WatchOptions.withCredentials());
        Watch b = c.watch(Filter.all(), WatchOptions.bindingsOnly());
        assertThat(a.poll(Duration.ofMillis(300))).isEmpty();
        c.close();
        assertThat(a.iterator().hasNext()).isFalse();
        assertThat(b.iterator().hasNext()).isFalse();
        assertThat(ligoThreads()).isEmpty();
        assertThatThrownBy(() -> c.watch(Filter.all(), WatchOptions.bindingsOnly())).isInstanceOf(LigoException.class);
    }
}
