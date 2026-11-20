// SPDX-License-Identifier: MIT
// What the Go lab tests ask of the Java SDK (.specs/ligo-client-sdk-java.md JV-L2, JV-L3).
//
// Runs on ligo1 under the workload's user. The Go tests (TestServeClientSDKJava, TestServeClientFlowcheckJava) file
// and approve the bindings, call this helper and judge its JSON lines. The workload's SVID and JWT-SVID were minted by
// lab.sh into LIGO_E2E_DIR, so this client reads them from files instead of the Workload API.
//
//   SdkCheck watch --target T [--transport rest|grpc]   one JSON line per event, until the binding is removed
//   SdkCheck flowcheck --target T                       {"results": [...]} for the flows of T
//   SdkCheck denied                                     a flow to the cloud metadata address: it must be skipped

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dihedron.ligo.client.Binding;
import io.github.dihedron.ligo.client.BindingFlows;
import io.github.dihedron.ligo.client.Credential;
import io.github.dihedron.ligo.client.Event;
import io.github.dihedron.ligo.client.EventKind;
import io.github.dihedron.ligo.client.Filter;
import io.github.dihedron.ligo.client.Flow;
import io.github.dihedron.ligo.client.FlowCheck;
import io.github.dihedron.ligo.client.FlowOptions;
import io.github.dihedron.ligo.client.FlowResult;
import io.github.dihedron.ligo.client.LigoClient;
import io.github.dihedron.ligo.client.LigoException;
import io.github.dihedron.ligo.client.PortRange;
import io.github.dihedron.ligo.client.Watch;
import io.github.dihedron.ligo.client.WatchOptions;
import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.X509Source;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class SdkCheck {
    static final String LIGO_ID = "spiffe://prod.lab/ns/sys/sa/ligo";
    static final ObjectMapper JSON = new ObjectMapper();

    private SdkCheck() {}

    /** The SVID and bundle that lab.sh minted, as java-spiffe's X509Source gives them. */
    static final class FileSource implements X509Source {
        private final X509Svid svid;
        private final X509Bundle bundle;

        FileSource(Path dir) throws Exception {
            svid = X509Svid.load(dir.resolve("workload-svid.pem"), dir.resolve("workload-key.pem"));
            bundle = X509Bundle.load(TrustDomain.parse("prod.lab"), dir.resolve("workload-bundle.pem"));
        }

        @Override
        public X509Svid getX509Svid() {
            return svid;
        }

        @Override
        public X509Bundle getBundleForTrustDomain(TrustDomain trustDomain) throws BundleNotFoundException {
            return bundle.getBundleForTrustDomain(trustDomain);
        }

        @Override
        public void close() {
            // nothing is open
        }
    }

    /** The JWT-SVID that lab.sh minted for the secrets backend, as java-spiffe's JwtSource gives it. */
    static final class FileJwt implements JwtSvidSource {
        private final Path path;

        FileJwt(Path path) {
            this.path = path;
        }

        @Override
        public JwtSvid fetchJwtSvid(String audience, String... extra) throws JwtSvidException {
            try {
                return JwtSvid.parseInsecure(Files.readString(path).strip(), Set.of(audience));
            } catch (IOException e) {
                throw new JwtSvidException("cannot read the JWT-SVID", e);
            }
        }

        @Override
        public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extra) throws JwtSvidException {
            return fetchJwtSvid(audience, extra);
        }

        @Override
        public List<JwtSvid> fetchJwtSvids(String audience, String... extra) throws JwtSvidException {
            return List.of(fetchJwtSvid(audience, extra));
        }

        @Override
        public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extra) throws JwtSvidException {
            return List.of(fetchJwtSvid(audience, extra));
        }
    }

    static String env(String name) {
        String v = System.getenv(name);
        if (v == null || v.isEmpty()) {
            throw new IllegalStateException(name + " is not set");
        }
        return v;
    }

    static LigoClient makeClient(LigoClient.Transport transport) throws Exception {
        Path dir = Path.of(env("LIGO_E2E_DIR"));
        String address = env("LIGO_E2E_WORKLOAD").replaceFirst("^https://", "");
        return LigoClient.builder().address(address).serverId(LIGO_ID).transport(transport).x509Source(new FileSource(dir))
                .jwtSource(new FileJwt(dir.resolve("workload-store-jwt"))).storeRoots(Path.of(env("LIGO_TEST_CA")))
                .pollInterval(Duration.ofSeconds(5)).build();
    }

    static void emit(ObjectNode doc) {
        System.out.println(doc.toString());
        System.out.flush();
    }

    static ObjectNode bindingDoc(Binding b) {
        if (b == null) {
            return null;
        }
        ObjectNode n = JSON.createObjectNode();
        n.put("name", b.name()).put("target", b.target()).put("strategy", b.auth().strategy()).put("endpoint", b.endpoint())
                .put("description", b.description());
        n.set("annotations", JSON.valueToTree(b.annotations()));
        return n;
    }

    static ObjectNode credentialDoc(Credential c) {
        if (c == null) {
            return null;
        }
        ObjectNode n = JSON.createObjectNode();
        n.put("username", c.username()).put("password", c.password()).put("expires",
                c.expires() == null ? 0 : c.expires().toEpochMilli() / 1000.0);
        return n;
    }

    static void watch(LigoClient client, String target) {
        boolean rotated = false;
        try (Watch w = client.watch(target.isEmpty() ? Filter.all() : Filter.target(target), WatchOptions.withCredentials())) {
            for (Event ev : w) {
                ObjectNode n = JSON.createObjectNode();
                n.put("kind", ev.kind().name().toLowerCase(java.util.Locale.ROOT));
                n.set("binding", bindingDoc(ev.binding()));
                n.set("previous", bindingDoc(ev.previous()));
                n.set("credential", credentialDoc(ev.credential()));
                emit(n);
                if (ev.kind() == EventKind.CREDENTIAL_ROTATED && !rotated && ev.binding() != null) {
                    rotated = true;
                    ObjectNode second = JSON.createObjectNode().put("kind", "second_credential");
                    second.set("credential", credentialDoc(client.credential(ev.binding())));
                    emit(second);
                    List<BindingFlows> flows = client.flows(target);
                    emit(JSON.createObjectNode().put("kind", "flows").put("count", flows.size()).put("flows",
                            flows.stream().mapToInt(bf -> bf.flows().size()).sum()));
                }
                if (ev.kind() == EventKind.REMOVED && ev.previous() != null) {
                    client.invalidate(ev.previous());
                    String error = "";
                    try {
                        client.credential(ev.previous());
                    } catch (LigoException e) {
                        error = e.getClass().getSimpleName();
                    }
                    emit(JSON.createObjectNode().put("kind", "refused").put("error", error));
                    emit(JSON.createObjectNode().put("kind", "bindings_after").put("count",
                            client.bindings(target.isEmpty() ? Filter.all() : Filter.target(target)).size()));
                    return;
                }
            }
        }
    }

    static ObjectNode resultDoc(FlowResult r) {
        return JSON.createObjectNode().put("binding", r.binding()).put("target", r.target()).put("flow", r.flow())
                .put("destination", r.destination()).put("port", r.port()).put("protocol", r.protocol())
                .put("status", r.status().name().toLowerCase(java.util.Locale.ROOT)).put("reason", r.reason())
                .put("error", r.error() == null ? "" : r.error().getClass().getSimpleName());
    }

    static void emitResults(List<FlowResult> results) {
        ObjectNode n = JSON.createObjectNode();
        n.putArray("results").addAll(results.stream().map(SdkCheck::resultDoc).toList());
        emit(n);
    }

    static List<X509Certificate> roots() throws Exception {
        try (var in = Files.newInputStream(Path.of(env("LIGO_TEST_CA")))) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in).stream().map(X509Certificate.class::cast)
                    .toList();
        }
    }

    public static void main(String[] args) throws Exception {
        String command = args.length > 0 ? args[0] : "";
        String target = "";
        LigoClient.Transport transport = LigoClient.Transport.REST;
        for (int i = 1; i + 1 < args.length; i += 2) {
            switch (args[i]) {
                case "--target" -> target = args[i + 1];
                case "--transport" -> transport = LigoClient.Transport.valueOf(args[i + 1].toUpperCase(java.util.Locale.ROOT));
                default -> throw new IllegalArgumentException("unknown option " + args[i]);
            }
        }
        switch (command) {
            case "watch" -> {
                try (LigoClient client = makeClient(transport)) {
                    watch(client, target);
                }
            }
            case "flowcheck" -> {
                try (LigoClient client = makeClient(transport)) {
                    emitResults(client.checkFlows(target, FlowOptions.builder().roots(roots()).timeout(Duration.ofSeconds(5))
                            .tries(1).build()));
                }
            }
            case "denied" -> {
                List<BindingFlows> flows = List.of(new BindingFlows("b", "", "t", List.of(new Flow("metadata", "", "TCP",
                        "169.254.169.254", List.of(new PortRange(80, 80)), false, "", "", ""))));
                emitResults(FlowCheck.run(flows, FlowOptions.builder().build()));
            }
            default -> throw new IllegalArgumentException("watch, flowcheck or denied");
        }
        System.exit(0); // the SPIFFE and gRPC threads are daemons, but be sure
    }
}
