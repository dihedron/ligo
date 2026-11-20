// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.List;

/** The network flows a binding needs. */
public record BindingFlows(String binding, String source, String target, List<Flow> flows) {
    public BindingFlows {
        flows = List.copyOf(flows);
    }
}
