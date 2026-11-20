// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/** The async twins: the blocking call on the executor, and cancelling the future interrupts it (T-J6). */
final class Async {
    private Async() {}

    static <T> CompletableFuture<T> run(Executor executor, Supplier<T> body) {
        CompletableFuture<T> future = new CompletableFuture<>();
        Object lock = new Object();
        Thread[] runner = new Thread[1];
        try {
            executor.execute(() -> {
                synchronized (lock) {
                    if (future.isDone()) {
                        return; // cancelled before it started
                    }
                    runner[0] = Thread.currentThread();
                }
                try {
                    future.complete(body.get());
                } catch (RuntimeException | Error e) {
                    future.completeExceptionally(e);
                } finally {
                    synchronized (lock) {
                        runner[0] = null;
                        Thread.interrupted(); // the interrupt of a cancel is not for the next task of the pool
                    }
                }
        
            });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            future.completeExceptionally(new LigoException("the client is closed", e)); // its executor is shut down
        }
        future.whenComplete((v, e) -> {
            if (future.isCancelled()) {
                synchronized (lock) {
                    if (runner[0] != null) {
                        runner[0].interrupt();
                    }
                }
            }
        });
        return future;
    }
}
