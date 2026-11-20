// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.spiffe.bundle.x509bundle.X509Bundle;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * How flows are checked. The defaults: 5 s a try, 2 tries 200 ms apart, 8 checks at a time, the JDK's roots for TLS
 * flows, link-local and cloud metadata ranges denied.
 */
public final class FlowOptions {
    /** Never checked unless the caller replaces the list: link-local addresses and the cloud metadata ranges. */
    public static final List<String> DEFAULT_DENIED = List.of("169.254.0.0/16", "fe80::/10", "fd00:ec2::/32");

    final Duration timeout;
    final int tries;
    final Duration retryDelay;
    final int concurrency;
    final List<X509Certificate> roots;
    final List<Cidr> denied;
    final Handshake handshake;
    final X509Bundle spiffeBundle;
    final String spiffeId;
    final Map<String, String> platforms;
    final System.Logger logger;
    final Function<String, List<InetAddress>> resolver;
    final BooleanSupplier stop;

    private FlowOptions(Builder b) {
        timeout = b.timeout;
        tries = b.tries;
        retryDelay = b.retryDelay;
        concurrency = b.concurrency;
        roots = List.copyOf(b.roots);
        denied = List.copyOf(b.denied);
        handshake = b.handshake;
        spiffeBundle = b.spiffeBundle;
        spiffeId = b.spiffeId;
        platforms = Map.copyOf(b.platforms);
        logger = b.logger;
        resolver = b.resolver;
        stop = b.stop;
    }

    public static Builder builder() {
        return new Builder();
    }

    Builder toBuilder() {
        Builder b = new Builder();
        b.timeout = timeout;
        b.tries = tries;
        b.retryDelay = retryDelay;
        b.concurrency = concurrency;
        b.roots = roots;
        b.denied = denied;
        b.handshake = handshake;
        b.spiffeBundle = spiffeBundle;
        b.spiffeId = spiffeId;
        b.platforms = platforms;
        b.logger = logger;
        b.resolver = resolver;
        b.stop = stop;
        return b;
    }

    public static final class Builder {
        private Duration timeout = Duration.ofSeconds(5);
        private int tries = 2;
        private Duration retryDelay = Duration.ofMillis(200);
        private int concurrency = 8;
        private List<X509Certificate> roots = List.of();
        private List<Cidr> denied = DEFAULT_DENIED.stream().map(Cidr::parse).toList();
        private Handshake handshake;
        private X509Bundle spiffeBundle;
        private String spiffeId;
        private Map<String, String> platforms = Map.of();
        private System.Logger logger;
        private Function<String, List<InetAddress>> resolver = Builder::resolve;
        private BooleanSupplier stop = () -> false;

        private Builder() {}

        private static List<InetAddress> resolve(String host) {
            try {
                return Arrays.asList(InetAddress.getAllByName(host));
            } catch (UnknownHostException e) {
                throw new IllegalStateException("cannot resolve " + host, e);
            }
        }

        /** The time a try may take. */
        public Builder timeout(Duration timeout) {
            if (timeout.isZero() || timeout.isNegative()) {
                throw new IllegalArgumentException("timeout: must be positive");
            }
            this.timeout = timeout;
            return this;
        }

        public Builder tries(int tries) {
            this.tries = Math.max(1, tries);
            return this;
        }

        public Builder retryDelay(Duration retryDelay) {
            this.retryDelay = retryDelay;
            return this;
        }

        public Builder concurrency(int concurrency) {
            this.concurrency = Math.max(1, concurrency);
            return this;
        }

        /** The trust anchors for TLS flows; the default is the JDK's. */
        public Builder roots(Collection<X509Certificate> roots) {
            this.roots = List.copyOf(roots);
            return this;
        }

        /** Replaces the denied networks, given as CIDR blocks; an empty list denies nothing. */
        public Builder deniedNetworks(Collection<String> cidrs) {
            List<Cidr> list = new ArrayList<>();
            for (String c : cidrs) {
                list.add(Cidr.parse(c));
            }
            this.denied = list;
            return this;
        }

        /** Chooses how TLS starts per flow; the default is {@code FlowCheck.defaultChooser}'s, with {@link #platforms}. */
        public Builder handshake(Handshake handshake) {
            this.handshake = handshake;
            return this;
        }

        /** The bundle that "spire" flows are verified against (any ID of its trust domain, or {@link #spiffeId}). */
        public Builder spiffeBundle(X509Bundle bundle) {
            this.spiffeBundle = bundle;
            return this;
        }

        public Builder spiffeId(String spiffeId) {
            this.spiffeId = spiffeId;
            return this;
        }

        /** Binding name to platform type, which the default handshake needs to know PostgreSQL bindings. */
        public Builder platforms(Map<String, String> platforms) {
            this.platforms = Map.copyOf(platforms);
            return this;
        }

        /** Where each result is logged, at DEBUG: the flow and the outcome, nothing else. */
        public Builder logger(System.Logger logger) {
            this.logger = Objects.requireNonNull(logger, "logger");
            return this;
        }

        /** For tests: the name resolver. */
        Builder resolver(Function<String, List<InetAddress>> resolver) {
            this.resolver = resolver;
            return this;
        }

        /** When true, the checks not yet started are skipped. */
        Builder stop(BooleanSupplier stop) {
            this.stop = stop;
            return this;
        }

        public FlowOptions build() {
            return new FlowOptions(this);
        }
    }
}
