// SPDX-License-Identifier: MIT
// The lab's echo client in Java (lab only, not hardened; .specs/ligo-client-sdk-java.md JV-L1).
//
// The same as test/lab/echo/client: it finds its binding to an echo target, authenticates as the binding says (its
// SVID, or the password OpenBao keeps for it) and prints what the server echoes, on REST or on gRPC.
// Exit codes: 0 echoed, 1 error, 2 no binding, 3 denied.

import io.github.dihedron.ligo.client.Binding;
import io.github.dihedron.ligo.client.Credential;
import io.github.dihedron.ligo.client.Filter;
import io.github.dihedron.ligo.client.LigoClient;
import io.github.dihedron.ligo.client.LigoException;
import io.github.dihedron.ligo.client.NoCredentialException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public final class EchoClient {
    static final int ECHOED = 0, ERROR = 1, NO_BINDING = 2, DENIED = 3;

    private EchoClient() {}

    public static void main(String[] args) {
        System.exit(run(args, System.out));
    }

    static int run(String[] args, PrintStream out) {
        try {
            return runClient(args, out);
        } catch (IllegalArgumentException | IllegalStateException e) { // a bad address, id or CA file
            return fail(out, e.getMessage());
        }
    }

    static int runClient(String[] args, PrintStream out) {
        Map<String, String> a = new java.util.HashMap<>(Map.of("target", "", "message", "hello", "ligo", "ligo1.ligo.lab:8443",
                "ligo-id", "spiffe://prod.lab/ns/sys/sa/ligo", "transport", "rest", "direct", "", "mode", "svid", "user", "",
                "password", "", "server-id", "spiffe://prod.lab/ns/lab/sa/echo-server"));
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--") || !a.containsKey(args[i].substring(2)) || i + 1 >= args.length) {
                return fail(out, "usage: EchoClient [--target T] [--message M] [--ligo H:P] [--ligo-id ID] [--transport rest|grpc] [--direct H:P] [--mode svid|password] [--user U] [--password P] [--server-id ID]");
            }
            a.put(args[i].substring(2), args[++i]);
        }
        if (a.get("message").contains("\n") || a.get("message").contains("\t")) {
            return fail(out, "--message: one line without tabs");
        }
        LigoClient.Transport transport;
        switch (a.get("transport")) {
            case "rest" -> transport = LigoClient.Transport.REST;
            case "grpc" -> transport = LigoClient.Transport.GRPC;
            default -> {
                return fail(out, "--transport: rest or grpc");
            }
        }
        String ca = System.getenv().getOrDefault("ECHO_CA_FILE", "/etc/ligo-lab/ca.crt");
        try (LigoClient client = LigoClient.builder().address(a.get("ligo")).serverId(a.get("ligo-id")).transport(transport)
                .storeRoots(Path.of(ca)).build()) {
            String endpoint = a.get("direct");
            String serverId = a.get("server-id");
            String mode = a.get("mode");
            String user = a.get("user");
            String password = a.get("password");
            if (endpoint.isEmpty()) {
                if (a.get("target").isEmpty()) {
                    return fail(out, "--target or --direct is required");
                }
                List<Binding> bindings;
                try {
                    bindings = client.bindings(Filter.target(a.get("target")));
                } catch (LigoException e) {
                    return fail(out, "ligo's workload API: " + e.getMessage());
                }
                if (bindings.isEmpty()) {
                    out.println("no binding");
                    return NO_BINDING;
                }
                Binding b = bindings.get(0);
                endpoint = b.endpoint();
                serverId = String.valueOf(b.spec().getOrDefault("serverId", ""));
                mode = String.valueOf(b.spec().getOrDefault("mode", ""));
                try {
                    Credential c = client.credential(b);
                    user = c.username();
                    password = c.password();
                } catch (NoCredentialException e) {
                    if (mode.equals("password")) {
                        return fail(out, "the binding's password: no credential");
                    }
                } catch (LigoException e) {
                    return fail(out, "the binding's password: " + e.getMessage());
                }
                out.println("binding " + b.name() + ": " + mode + " mode, " + endpoint);
            }
            String answer;
            try {
                answer = echo(client, endpoint, serverId, mode, user, password, a.get("message"));
            } catch (IOException | RuntimeException e) {
                return fail(out, "the echo server: " + e.getMessage());
            }
            out.println(answer);
            if (answer.equals("denied")) {
                return DENIED;
            }
            if (answer.startsWith(a.get("message") + "\t")) {
                return ECHOED;
            }
            return fail(out, "unexpected answer");
        }
    }

    static String echo(LigoClient client, String endpoint, String serverId, String mode, String user, String password,
            String message) throws IOException {
        if (!mode.equals("svid") && !mode.equals("password")) {
            throw new IllegalArgumentException("mode \"" + mode + "\": svid or password");
        }
        String lines = (mode.equals("password") ? "auth " + user + " " + password + "\n" : "") + message + "\n";
        try (Socket sock = client.connect(endpoint, serverId, Duration.ofSeconds(15))) {
            sock.getOutputStream().write(lines.getBytes(StandardCharsets.UTF_8));
            sock.getOutputStream().flush();
            String answer = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8)).readLine();
            return answer == null ? "" : answer;
        }
    }

    private static int fail(PrintStream out, String message) {
        out.println("error: " + message);
        return ERROR;
    }
}
