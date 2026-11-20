// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * The loop of a watch (.specs/ligo-client-sdk.md §3.5): polls the bindings, reports each change, reads credentials
 * at two thirds of their lease, and backs off when a poll fails. The state is kept through failed polls.
 */
final class Watcher {
    static final Duration MAX_BACKOFF = Duration.ofMinutes(5);
    private static final Comparator<Binding> BY_NAME = Comparator.comparing(Binding::name).thenComparing(Binding::id);

    interface Backend {
        List<Binding> bindings();

        Credential credential(Binding binding);
    }

    /** Waits; true when the watch must end. */
    interface Sleeper {
        boolean sleep(Duration d);
    }

    /** Thrown by a sink that cannot take more events: the watch is over. */
    static final class Stopped extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Stopped() {
            super(null, null, false, false);
        }
    }

    private final Backend backend;
    private final Clock clock;
    private final Duration poll;
    private final Sleeper sleeper;
    private final System.Logger log;
    private final Consumer<Event> sink;
    private final boolean credentials;
    private final BooleanSupplier stopped;
    private final Map<String, Binding> known = new LinkedHashMap<>();
    private final Map<String, Instant> due = new HashMap<>(); // when to read a binding's credential

    Watcher(Backend backend, Clock clock, Duration poll, Sleeper sleeper, System.Logger log, Consumer<Event> sink,
            boolean credentials, BooleanSupplier stopped) {
        this.backend = backend;
        this.clock = clock;
        this.poll = poll;
        this.sleeper = sleeper;
        this.log = log;
        this.sink = sink;
        this.credentials = credentials;
        this.stopped = stopped;
    }

    void run() {
        try {
            loop();
        } catch (Stopped e) {
            // the consumer is gone
        }
    }

    private void loop() {
        int failures = 0;
        Instant nextPoll = clock.instant();
        while (!stopped.getAsBoolean()) {
            Instant now = clock.instant();
            if (!now.isBefore(nextPoll)) {
                Duration wait = jitter(poll);
                try {
                    List<Binding> items = backend.bindings();
                    failures = 0;
                    diff(items, now);
                } catch (LigoException e) {
                    if (stopped.getAsBoolean()) {
                        return;
                    }
                    wait = poll.multipliedBy(1L << Math.min(failures, 10));
                    if (wait.compareTo(MAX_BACKOFF) > 0) {
                        wait = MAX_BACKOFF;
                    }
                    if (e instanceof Unavailable u && u.retryAfter() != null && u.retryAfter().compareTo(wait) > 0) {
                        wait = u.retryAfter();
                    }
                    failures++;
                    log.log(System.Logger.Level.WARNING, "watch: poll failed, retry in {0} s: {1}", wait.toSeconds(),
                            e.getMessage());
                }
                nextPoll = now.plus(wait);
            }
            Instant wake = nextPoll;
            for (Binding b : known.values().stream().sorted(BY_NAME).toList()) {
                Instant at = due.get(b.id());
                if (at == null) {
                    continue;
                }
                if (at.isAfter(now)) {
                    wake = at.isBefore(wake) ? at : wake;
                    continue;
                }
                try {
                    Credential cred = backend.credential(b);
                    due.remove(b.id());
                    if (cred.expires() != null) {
                        Instant next = now.plusMillis(Duration.between(now, cred.expires()).toMillis() * 2 / 3);
                        due.put(b.id(), next);
                        wake = next.isBefore(wake) ? next : wake;
                    }
                    sink.accept(new Event(EventKind.CREDENTIAL_ROTATED, b, null, cred));
                } catch (NoCredentialException e) {
                    due.remove(b.id());
                } catch (LigoException e) {
                    due.put(b.id(), nextPoll);
                    log.log(System.Logger.Level.WARNING, "watch: credential not read: binding {0}, target {1}: {2}",
                            b.name(), b.target(), e.getMessage());
                }
            }
            Duration left = Duration.between(clock.instant(), wake);
            if (sleeper.sleep(left.isNegative() ? Duration.ZERO : left)) {
                return;
            }
        }
    }

    private void diff(List<Binding> items, Instant now) {
        Set<String> seen = new HashSet<>();
        for (Binding b : items.stream().sorted(BY_NAME).toList()) {
            seen.add(b.id());
            Binding old = known.get(b.id());
            if (old != null && old.revision() == b.revision()) {
                continue;
            }
            known.put(b.id(), b);
            if (credentials) {
                due.put(b.id(), now);
            }
            sink.accept(old != null ? new Event(EventKind.CHANGED, b, old, null) : new Event(EventKind.ADDED, b, null, null));
        }
        for (Binding old : known.values().stream().sorted(BY_NAME).toList()) {
            if (!seen.contains(old.id())) {
                known.remove(old.id());
                due.remove(old.id());
                sink.accept(new Event(EventKind.REMOVED, null, old, null));
            }
        }
    }

    /** The wait between two polls: the interval and up to a tenth more. */
    static Duration jitter(Duration poll) {
        return poll.plusMillis((long) (ThreadLocalRandom.current().nextDouble() * poll.toMillis() / 10));
    }
}
