// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** The outcome of one flow check. */
public enum FlowStatus {
    REACHABLE,
    UNREACHABLE,
    /** The flow could not be checked, which is not a failure. */
    SKIPPED
}
