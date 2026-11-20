// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * {@code bindings} answered 304, over TLS 1.3 to an in-process server (.specs/ligo-client-sdk-java.md §6).
 * Not part of the normal build: {@code ./mvnw -Pbench test-compile exec:exec} or {@code make java-bench}.
 */
@State(Scope.Benchmark)
@BenchmarkMode({Mode.AverageTime, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 3)
@Fork(1)
public class BindingsBenchmark {
    private TestServer server;
    private LigoClient client;

    @Setup(Level.Trial)
    public void up() {
        Pki pki = new Pki();
        server = new TestServer(pki, ClientTest.LIGO_ID, pki, r -> r.headers().containsKey("if-none-match")
                ? new TestServer.Response(304, Map.of(), new byte[0])
                : new TestServer.Response(200, Map.of("Content-Type", "application/json", "ETag", "\"sha256:aa\""),
                        "{\"items\":[]}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        client = LigoClient.builder().address(server.address()).serverId(ClientTest.LIGO_ID)
                .x509Source(new StaticSource(pki, ClientTest.WORKER_ID)).build();
        client.bindings(Filter.all()); // the first answer is 200 and fills the cache
    }

    @TearDown(Level.Trial)
    public void down() {
        client.close();
        server.close();
    }

    @Benchmark
    public Object bindings304() {
        return client.bindings(Filter.all());
    }

    public static void main(String[] args) throws Exception {
        new Runner(new OptionsBuilder().include(BindingsBenchmark.class.getSimpleName()).build()).run();
    }
}
