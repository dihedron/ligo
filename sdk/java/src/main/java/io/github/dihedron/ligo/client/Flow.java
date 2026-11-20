// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.util.List;

/** One network flow. */
public record Flow(String name, String purpose, String protocol, String destination, List<PortRange> ports,
        boolean tls, String serverName, String description, String declaredBy) {
    public Flow {
        ports = List.copyOf(ports);
    }
}
