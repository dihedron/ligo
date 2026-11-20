// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * A running watch on its own daemon thread (T-J7). As an {@link Iterable} it hands out the events in order, blocking
 * between them, and the iteration ends when the watch is closed. With a callback the events go to it, in order, on
 * the watch's thread. {@link #close()} stops the thread and waits for it (T-J6).
 */
public final class Watch implements Subscription, Iterable<Event> {
    private static final Event END = new Event(null, null, null, null);
    private static final int QUEUE = 1024;
    private static final long JOIN_MILLIS = 5000;

    private final BlockingQueue<Event> queue = new LinkedBlockingQueue<>(QUEUE);
    private final Object lock = new Object();
    private final Thread thread;
    private volatile boolean stopped;
    private boolean ended; // END was taken from the queue

    Watch(String name, Watcher.Backend backend, Clock clock, Duration poll, System.Logger log, boolean credentials,
            Consumer<Event> callback, Watcher.Sleeper sleeper, Runnable onEnd) {
        Consumer<Event> sink = callback != null ? e -> {
            try {
                callback.accept(e);
            } catch (RuntimeException ex) { // a callback that fails must not end the watch
                log.log(System.Logger.Level.WARNING, "watch: the callback failed: {0}", ex.getClass().getSimpleName());
            }
        } : this::put;
        Watcher watcher = new Watcher(backend, clock, poll, sleeper != null ? sleeper : this::sleep, log, sink,
                credentials, () -> stopped);
        thread = new Thread(() -> {
            try {
                watcher.run();
            } finally {
                stopped = true;
                queue.offer(END);
                onEnd.run();
            }
        }, name);
        thread.setDaemon(true);
        thread.start();
    }

    private void put(Event e) {
        try {
            queue.put(e);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new Watcher.Stopped();
        }
    }

    private boolean sleep(Duration d) {
        long end = System.nanoTime() + d.toNanos();
        synchronized (lock) {
            try {
                while (!stopped) {
                    long left = end - System.nanoTime();
                    if (left <= 0) {
                        return false;
                    }
                    lock.wait(left / 1_000_000, (int) (left % 1_000_000));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return true;
    }

    /** The next event, or empty after {@code timeout} or when the watch has ended. */
    public synchronized Optional<Event> poll(Duration timeout) throws InterruptedException {
        if (ended) {
            return Optional.empty();
        }
        Event e = queue.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
        return take(e);
    }

    private synchronized Optional<Event> take(Event e) {
        if (e == null) {
            return Optional.empty();
        }
        if (e == END) {
            ended = true;
            queue.offer(END);
            return Optional.empty();
        }
        return Optional.of(e);
    }

    /** True once the watch has stopped and its events are read. */
    public boolean ended() {
        return ended;
    }

    /** The events in order; {@code next} blocks. One iterator at a time should read. */
    @Override
    public Iterator<Event> iterator() {
        return new Iterator<>() {
            private Event ahead;

            @Override
            public boolean hasNext() {
                if (ahead != null) {
                    return true;
                }
                if (ended) {
                    return false;
                }
                try {
                    ahead = take(queue.take()).orElse(null);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                return ahead != null;
            }

            @Override
            public Event next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                Event e = ahead;
                ahead = null;
                return e;
            }
        };
    }

    /** Stops the watch, waits for its thread and ends the iteration. */
    @Override
    public void cancel() {
        stopped = true;
        synchronized (lock) {
            lock.notifyAll();
        }
        if (Thread.currentThread() != thread) { // a callback may cancel its own watch
            thread.interrupt();
            try {
                thread.join(JOIN_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        queue.clear();
        queue.offer(END);
    }
}
