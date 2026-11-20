// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.time.Duration;

/**
 * The outcome of one flow and port.
 *
 * @param protocol tcp, tls, postgresql, spire or udp; empty when skipped before a check was chosen
 * @param reason why it is unreachable or skipped; for a UDP pass, what the pass means
 * @param error the check's error when unreachable
 */
public record FlowResult(String binding, String target, String flow, String destination, int port, String protocol,
        FlowStatus status, String reason, Throwable error, Duration latency, int attempts) {}
