// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/** Inclusive; a single port has low == high. */
public record PortRange(int low, int high) {}
