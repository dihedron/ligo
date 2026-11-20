// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JV-A1 to JV-A4: the async twins (.specs/ligo-client-sdk-java.md §6). */
class AsyncTest {
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

    TestServer serve(String id, java.util.function.Function<TestServer.Request, TestServer.Response> h) {
        TestServer s = new TestServer(pki, id, pki, h);
        open.add(s);
        return s;
    }

    LigoClient client(TestServer s, java.util.concurrent.Executor ex) {
        LigoClient.Builder b = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID).x509Source(source);
        LigoClient c = (ex == null ? b : b.executor(ex)).build();
        open.add(c);
        return c;
    }

    // JV-A1
    @Test
    void sameResultsAsTheBlockingCalls() throws Exception {
        TestServer s = serve(ClientTest.LIGO_ID, r -> ClientTest.ok(r.target().startsWith("/v1/flows") ? "{\"items\":[]}" : ClientTest.BINDINGS));
        LigoClient c = client(s, null);
        assertThat(c.bindingsAsync(Filter.all()).get(10, TimeUnit.SECONDS)).isEqualTo(c.bindings(Filter.all()));
        assertThat(c.flowsAsync("").get(10, TimeUnit.SECONDS)).isEqualTo(c.flows(""));
    }

    // JV-A2
    @Test
    void failuresCompleteExceptionallyWithTheSameTypes() {
        TestServer other = serve("spiffe://prod.lab/ns/sys/sa/impostor", r -> ClientTest.ok(ClientTest.BINDINGS));
        assertThatThrownBy(() -> client(other, null).bindingsAsync(Filter.all()).join()).isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(Unauthorized.class);
        TestServer busy = serve(ClientTest.LIGO_ID, r -> new TestServer.Response(503, java.util.Map.of("Retry-After", "3"), new byte[0]));
        assertThatThrownBy(() -> client(busy, null).flowsAsync("t").join()).hasCauseInstanceOf(Unavailable.class);
    }

    // JV-A3
    @Test
    void cancellingAFutureFreesTheThread() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        TestServer s = serve(ClientTest.LIGO_ID, r -> {
            inside.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return ClientTest.ok(ClientTest.BINDINGS);
        });
        ExecutorService one = Executors.newSingleThreadExecutor();
        try {
            LigoClient c = client(s, one);
            CompletableFuture<List<Binding>> f = c.bindingsAsync(Filter.all());
            assertThat(inside.await(10, TimeUnit.SECONDS)).isTrue();
            assertThat(f.cancel(true)).isTrue();
            assertThatThrownBy(f::join).isInstanceOf(CancellationException.class);
            // the only thread of the executor is free again: the call was interrupted, not left to finish
            assertThat(one.submit(() -> "free").get(10, TimeUnit.SECONDS)).isEqualTo("free");
        } finally {
            release.countDown();
            one.shutdownNow();
        }
    }

    // JV-A4
    @Test
    void closeWithACallInFlight() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        TestServer s = serve(ClientTest.LIGO_ID, r -> {
            inside.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return ClientTest.ok(ClientTest.BINDINGS);
        });
        try {
            LigoClient c = client(s, null);
            CompletableFuture<List<Binding>> f = c.bindingsAsync(Filter.all());
            assertThat(inside.await(10, TimeUnit.SECONDS)).isTrue();
            c.close();
            assertThatThrownBy(() -> f.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(LigoException.class);
            assertThatThrownBy(() -> c.bindingsAsync(Filter.all()).join()).hasCauseInstanceOf(LigoException.class)
                    .hasMessageContaining("closed");
        } finally {
            release.countDown();
        }
    }
}
