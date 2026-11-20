// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** An IP network. An IPv4-mapped IPv6 address is the IPv4 address (the JDK already says so). */
record Cidr(byte[] address, int bits) {
    static Cidr parse(String s) {
        int slash = s.indexOf('/');
        try {
            if (slash <= 0 || !Literal.is(s.substring(0, slash))) {
                throw new IllegalArgumentException("\"" + s + "\" is not a network in CIDR form");
            }
            byte[] a = InetAddress.getByName(s.substring(0, slash)).getAddress();
            int n = Integer.parseInt(s.substring(slash + 1));
            if (n < 0 || n > a.length * 8) {
                throw new IllegalArgumentException("\"" + s + "\" is not a network in CIDR form");
            }
            return new Cidr(a, n);
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("\"" + s + "\" is not a network in CIDR form");
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Cidr c && bits == c.bits && java.util.Arrays.equals(address, c.address);
    }

    @Override
    public int hashCode() {
        return 31 * java.util.Arrays.hashCode(address) + bits;
    }

    @Override
    public String toString() {
        try {
            return InetAddress.getByAddress(address).getHostAddress() + "/" + bits;
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    boolean contains(InetAddress ip) {
        byte[] b = ip.getAddress();
        if (b.length != address.length) {
            return false;
        }
        int whole = bits / 8;
        for (int i = 0; i < whole; i++) {
            if (b[i] != address[i]) {
                return false;
            }
        }
        int rest = bits % 8;
        if (rest == 0) {
            return true;
        }
        int mask = 0xFF << (8 - rest);
        return (b[whole] & mask) == (address[whole] & mask);
    }

    /** What is an IP literal, so that no DNS lookup is ever made for it. */
    static final class Literal {
        private Literal() {}

        static boolean is(String host) {
            String h = host.replaceAll("(?:^\\[|]$)", "");
            return h.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}") || (h.contains(":") && h.matches("[0-9a-fA-F:.]+"));
        }

        static InetAddress of(String host) {
            try {
                return InetAddress.getByName(host.replaceAll("(?:^\\[|]$)", ""));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
