// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.AbstractList;
import java.util.List;

/** The results of a call, one per flow and port, in the order of the flows. */
public final class FlowResults extends AbstractList<FlowResult> {
    private final List<FlowResult> results;

    public FlowResults(List<FlowResult> results) {
        this.results = List.copyOf(results);
    }

    @Override
    public FlowResult get(int index) {
        return results.get(index);
    }

    @Override
    public int size() {
        return results.size();
    }

    public FlowResults unreachable() {
        return new FlowResults(results.stream().filter(r -> r.status() == FlowStatus.UNREACHABLE).toList());
    }

    /** No flow is unreachable. Skipped flows do not count. */
    public boolean ok() {
        return unreachable().isEmpty();
    }
}
