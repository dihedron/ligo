// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/** JV-11 and JV-12: the watch loop, with a scripted server and a clock the sleeps move (.specs/ligo-client-sdk-java.md §6). */
class WatchTest {
    static Binding b(String id, String name, long revision) {
        return new Binding(id, name, "", "t", "", "", "", revision, null, Map.of(), new Auth("", "", "", Map.of()), "", Map.of());
    }

    static Binding b(String id, String name) {
        return b(id, name, 1);
    }

    /** A scripted server and clock: each poll takes the next answer; each sleep moves the clock. */
    static final class Script implements Watcher.Backend {
        final Deque<Object> polls;
        final CredentialTest.Ticking clock = new CredentialTest.Ticking();
        final List<Duration> sleeps = new ArrayList<>();
        final AtomicBoolean stop = new AtomicBoolean();
        final List<Event> events = new ArrayList<>();
        final List<String> log = new ArrayList<>();
        Function<Binding, Credential> credentials = b -> {
            throw new AssertionError("not asked for");
        };
        int polled;

        Script(List<Object> polls) {
            this.polls = new ArrayDeque<>(polls);
        }

        @Override
        @SuppressWarnings("unchecked")
        public List<Binding> bindings() {
            polled++;
            if (polls.isEmpty()) {
                stop.set(true);
                return List.of();
            }
            Object answer = polls.poll();
            if (polls.isEmpty()) {
                stop.set(true); // the last answer: the watch ends at its next sleep
            }
            if (answer instanceof RuntimeException e) {
                throw e;
            }
            return (List<Binding>) answer;
        }

        @Override
        public Credential credential(Binding b) {
            return credentials.apply(b);
        }

        boolean sleep(Duration d) {
            sleeps.add(d);
            clock.now = clock.now.plus(d);
            return stop.get();
        }

        Script run(Duration poll, boolean credentials) {
            System.Logger logger = new CredentialTest.Recording() {
                @Override
                public void log(Level level, java.util.ResourceBundle bundle, String format, Object... params) {
                    log.add(java.text.MessageFormat.format(format, params == null ? new Object[0] : params));
                }
            };
            new Watcher(this, clock, poll, this::sleep, logger, events::add, credentials, stop::get).run();
            return this;
        }

        Script run() {
            return run(Duration.ofSeconds(30), false);
        }
    }

    static Credential cred(Instant now, Long lease) {
        return new Credential("u", "p", lease == null ? null : now.plusSeconds(lease));
    }

    static List<Object> polls(Object... p) {
        return List.of(p);
    }

    static double seconds(Duration d) {
        return d.toMillis() / 1000.0;
    }

    // JV-11
    @Test
    void addedChangedRemovedInOrder() {
        Binding a = b("2", "b-two");
        Binding bb = b("1", "a-one");
        Script s = new Script(polls(
                List.of(a, bb), // both appear: by name
                List.of(a, bb), // nothing changed
                List.of(b("2", "b-two", 2), bb), // a revision
                List.of(bb))).run(); // one is gone
        assertThat(s.events.stream().map(e -> e.kind() + " " + (e.binding() != null ? e.binding() : e.previous()).name()))
                .containsExactly("ADDED a-one", "ADDED b-two", "CHANGED b-two", "REMOVED b-two");
        Event changed = s.events.get(2);
        Event removed = s.events.get(3);
        assertThat(changed.binding().revision()).isEqualTo(2);
        assertThat(changed.previous().revision()).isEqualTo(1);
        assertThat(removed.binding()).isNull();
        assertThat(removed.previous().revision()).isEqualTo(2);
    }

    @Test
    void aFailedPollKeepsTheState() {
        Binding one = b("1", "one");
        Script s = new Script(polls(List.of(one), new Unavailable("down"), new Unavailable("down"), List.of(one))).run();
        assertThat(s.events.stream().map(Event::kind)).containsExactly(EventKind.ADDED); // no REMOVED, no second ADDED
    }

    @Test
    void credentialsFollowNewAndChangedBindings() {
        Script s = new Script(polls(List.of(b("1", "one")), List.of(b("1", "one", 2))));
        List<Long> reads = new ArrayList<>();
        s.credentials = b -> {
            reads.add(b.revision());
            return cred(s.clock.now, null);
        };
        s.run(Duration.ofSeconds(30), true);
        assertThat(s.events.stream().map(Event::kind)).containsExactly(EventKind.ADDED, EventKind.CREDENTIAL_ROTATED,
                EventKind.CHANGED, EventKind.CREDENTIAL_ROTATED);
        assertThat(reads).containsExactly(1L, 2L);
        assertThat(s.events.get(1).credential()).isNotNull();
        assertThat(s.events.get(1).binding().id()).isEqualTo("1");
    }

    @Test
    void noCredentialsUnlessAsked() {
        Script s = new Script(polls(List.of(b("1", "one")))).run();
        assertThat(s.events.stream().map(Event::kind)).containsExactly(EventKind.ADDED);
    }

    @Test
    void rotationAtTwoThirdsOfALease() {
        Binding one = b("1", "one");
        Script s = new Script(polls(List.of(one), List.of(one), List.of(one)));
        s.credentials = b -> cred(s.clock.now, 90L);
        s.run(Duration.ofSeconds(300), true); // the poll interval is long: only the lease wakes the watch
        assertThat(s.events.stream().map(Event::kind)).startsWith(EventKind.ADDED, EventKind.CREDENTIAL_ROTATED,
                EventKind.CREDENTIAL_ROTATED);
        assertThat(seconds(s.sleeps.get(0))).isEqualTo(60.0); // 2/3 of 90 s
    }

    @Test
    void noCredentialIsNotRetried() {
        int[] calls = {0};
        Script s = new Script(polls(List.of(b("1", "one")), List.of(b("1", "one")), List.of(b("1", "one"))));
        s.credentials = b -> {
            calls[0]++;
            throw new NoCredentialException("svid");
        };
        s.run(Duration.ofSeconds(30), true);
        assertThat(s.events.stream().map(Event::kind)).containsExactly(EventKind.ADDED);
        assertThat(calls[0]).isEqualTo(1);
    }

    @Test
    void aFailedCredentialIsTriedAtTheNextPoll() {
        Deque<Object> results = new ArrayDeque<>(List.of(new StoreError("login: status 503"), cred(Instant.EPOCH, null)));
        Script s = new Script(polls(List.of(b("1", "one")), List.of(b("1", "one"))));
        s.credentials = b -> {
            Object r = results.poll();
            if (r instanceof RuntimeException e) {
                throw e;
            }
            return (Credential) r;
        };
        s.run(Duration.ofSeconds(30), true);
        assertThat(s.events.stream().map(Event::kind)).containsExactly(EventKind.ADDED, EventKind.CREDENTIAL_ROTATED);
        assertThat(String.join("\n", s.log)).contains("credential not read").contains("status 503");
    }

    // JV-12
    @Test
    void pollCadenceHasJitter() {
        Script s = new Script(java.util.Collections.nCopies(6, List.of(b("1", "one")))).run();
        assertThat(s.sleeps).isNotEmpty().allSatisfy(d -> assertThat(seconds(d)).isBetween(30.0, 33.0001));
        assertThat(s.sleeps.stream().distinct().count()).isGreaterThan(1); // not a metronome
    }

    @Test
    void backoffDoublesToFiveMinutes() {
        List<Object> p = new ArrayList<>(java.util.Collections.nCopies(9, new Unavailable("x")));
        p.add(List.of());
        Script s = new Script(p).run();
        assertThat(s.sleeps.subList(0, 9).stream().map(WatchTest::seconds))
                .containsExactly(30.0, 60.0, 120.0, 240.0, 300.0, 300.0, 300.0, 300.0, 300.0);
    }

    @Test
    void retryAfterWinsWhenLonger() {
        Script s = new Script(polls(new Unavailable("busy", Duration.ofSeconds(120), null),
                new Unavailable("busy", Duration.ofSeconds(1), null), List.of())).run();
        assertThat(s.sleeps.subList(0, 2).stream().map(WatchTest::seconds)).containsExactly(120.0, 60.0);
    }

    @Test
    void aSuccessResetsTheBackoff() {
        Script s = new Script(polls(new Unavailable("x"), new Unavailable("x"), List.of(), new Unavailable("x"), List.of())).run();
        assertThat(seconds(s.sleeps.get(0))).isEqualTo(30.0);
        assertThat(seconds(s.sleeps.get(1))).isEqualTo(60.0);
        assertThat(seconds(s.sleeps.get(2))).isBetween(30.0, 33.1);
        assertThat(seconds(s.sleeps.get(3))).isEqualTo(30.0);
    }

    @Test
    void aStoppedWatchPollsNothing() {
        Script s = new Script(polls(List.of(b("1", "one"))));
        s.stop.set(true);
        s.run();
        assertThat(s.events).isEmpty();
        assertThat(s.polled).isZero();
    }

    @Test
    void eventTextHidesThePassword() {
        Script s = new Script(polls(List.of(b("1", "one"))));
        s.credentials = b -> new Credential("u", "hunter2", null);
        s.run(Duration.ofSeconds(30), true);
        assertThat(s.events.toString()).doesNotContain("hunter2");
        assertThat(s.events.get(1).toString()).doesNotContain("hunter2");
    }
}
