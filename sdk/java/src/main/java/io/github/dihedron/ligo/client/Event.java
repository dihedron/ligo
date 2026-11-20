// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

/**
 * One change seen by a watch.
 *
 * @param binding the binding now; null for {@code REMOVED}
 * @param previous the binding before; set for {@code CHANGED} and {@code REMOVED}
 * @param credential set for {@code CREDENTIAL_ROTATED}; its text hides the password
 */
public record Event(EventKind kind, Binding binding, Binding previous, Credential credential) {}
