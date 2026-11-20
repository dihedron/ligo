// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.protobuf.Any;
import com.google.protobuf.ListValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Timestamp;
import com.google.protobuf.Value;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import ligo.workload.v1alpha1.Workload.BindingFlows;
import ligo.workload.v1alpha1.Workload.GetBindingsRequest;
import ligo.workload.v1alpha1.Workload.GetBindingsResponse;
import ligo.workload.v1alpha1.Workload.GetFlowsRequest;
import ligo.workload.v1alpha1.Workload.GetFlowsResponse;
import ligo.workload.v1alpha1.Workload.NetworkFlow;
import ligo.workload.v1alpha1.Workload.PortRange;
import ligo.workload.v1alpha1.Workload.WorkloadBinding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JV-2 to JV-4 on the gRPC transport (.specs/ligo-client-sdk-java.md §6). */
class GrpcTest {
    Pki pki;
    StaticSource source;
    final List<AutoCloseable> open = new ArrayList<>();

    @BeforeEach
    void setUp() {
        pki = new Pki();
        source = new StaticSource(pki, ClientTest.WORKER_ID);
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    static Value str(String s) {
        return Value.newBuilder().setStringValue(s).build();
    }

    static Value num(double d) {
        return Value.newBuilder().setNumberValue(d).build();
    }

    static WorkloadBinding binding() {
        Struct config = Struct.newBuilder().putFields("address", str("https://vault.lab:8200"))
                .putFields("audience", str("https://vault.lab")).putFields("authMount", str("jwt"))
                .putFields("role", str("binding-0192")).putFields("secretPath", str("kv/data/bindings/0192")).build();
        Struct auth = Struct.newBuilder().putFields("secretStorageStrategy", str("vault-static"))
                .putFields("secretStoreType", str("vault")).putFields("secretStoreInstance", str("vault-prod"))
                .putFields("config", Value.newBuilder().setStructValue(config).build()).build();
        Struct spec = Struct.newBuilder().putFields("endpoint", str("db.lab:5432")).putFields("database", str("ledger"))
                .putFields("port", num(5432)).putFields("tags", Value.newBuilder()
                        .setListValue(ListValue.newBuilder().addValues(str("a")).addValues(num(2.5))).build()).build();
        return WorkloadBinding.newBuilder().setId("0192").setName("workers-ledger").setSource("workers").setTarget("ledger")
                .setAccessLevel("write").setPlatformType("postgres").setPlatform("pg-prod").setRevision(4).setAuth(auth)
                .setSpec(spec).setUpdatedAt(Timestamp.newBuilder().setSeconds(1792134131)) // 2026-10-16T07:02:11Z
                .setDescription("Ledger posting").putAnnotations("change", "CHG0012345").build();
    }

    GrpcTestServer serve(String id, GrpcTestServer.Handler h) {
        GrpcTestServer s = new GrpcTestServer(pki, id, h);
        open.add(s);
        return s;
    }

    GrpcTestServer serve(Function<GetBindingsRequest, GetBindingsResponse> bindings) {
        return serve(ClientTest.LIGO_ID, new GrpcTestServer.Handler() {
            @Override
            public GetBindingsResponse bindings(GetBindingsRequest r) {
                return bindings.apply(r);
            }

            @Override
            public GetFlowsResponse flows(GetFlowsRequest r) {
                throw Status.UNIMPLEMENTED.asRuntimeException();
            }
        });
    }

    LigoClient client(GrpcTestServer s) {
        LigoClient c = LigoClient.builder().address(s.address()).serverId(ClientTest.LIGO_ID).x509Source(source)
                .transport(LigoClient.Transport.GRPC).build();
        open.add(c);
        return c;
    }

    // JV-2
    @Test
    void bindingsDecode() {
        GrpcTestServer s = serve(r -> GetBindingsResponse.newBuilder().setEtag("e1").addItems(binding()).build());
        List<Binding> got = client(s).bindings(new Filter("ledger", "postgres"));
        GetBindingsRequest sent = (GetBindingsRequest) s.requests.get(0);
        assertThat(sent.getTargetFilter()).isEqualTo("ledger");
        assertThat(sent.getPlatformTypeFilter()).isEqualTo("postgres");
        assertThat(s.peers).containsExactly(ClientTest.WORKER_ID);
        assertThat(got).hasSize(1);
        Binding b = got.get(0);
        assertThat(List.of(b.id(), b.name(), b.source(), b.target(), b.accessLevel()))
                .containsExactly("0192", "workers-ledger", "workers", "ledger", "write");
        assertThat(b.revision()).isEqualTo(4);
        assertThat(b.updatedAt()).hasToString("2026-10-16T07:02:11Z");
        assertThat(b.spec()).containsEntry("endpoint", "db.lab:5432").containsEntry("port", 5432)
                .containsEntry("tags", List.of("a", 2.5));
        assertThat(b.description()).isEqualTo("Ledger posting");
        assertThat(b.annotations()).containsEntry("change", "CHG0012345");
        assertThat(b.auth().strategy()).isEqualTo("vault-static");
        assertThat(b.auth().config()).containsEntry("secretPath", "kv/data/bindings/0192").containsEntry("role", "binding-0192");
    }

    @Test
    void anEmptyListIsNotAnError() {
        GrpcTestServer s = serve(r -> GetBindingsResponse.newBuilder().setEtag("e0").build());
        assertThat(client(s).bindings(Filter.all())).isEmpty();
    }

    // JV-3
    @Test
    void theSecondCallSendsTheEtagAndGetsTheRememberedList() {
        GrpcTestServer s = serve(r -> r.getKnownEtag().equals("e1") ? GetBindingsResponse.newBuilder().setNotModified(true)
                .setEtag("e1").build() : GetBindingsResponse.newBuilder().setEtag("e1").addItems(binding()).build());
        LigoClient c = client(s);
        List<Binding> first = c.bindings(Filter.target("ledger"));
        List<Binding> second = c.bindings(Filter.target("ledger"));
        assertThat(second).isEqualTo(first).hasSize(1);
        assertThat(((GetBindingsRequest) s.requests.get(1)).getKnownEtag()).isEqualTo("e1");
        c.bindings(Filter.all()); // another filter has its own ETag
        assertThat(((GetBindingsRequest) s.requests.get(2)).getKnownEtag()).isEmpty();
    }

    @Test
    void flowsDecode() {
        GrpcTestServer s = serve(ClientTest.LIGO_ID, new GrpcTestServer.Handler() {
            @Override
            public GetBindingsResponse bindings(GetBindingsRequest r) {
                throw Status.UNIMPLEMENTED.asRuntimeException();
            }

            @Override
            public GetFlowsResponse flows(GetFlowsRequest r) {
                NetworkFlow f = NetworkFlow.newBuilder().setName("data").setPurpose("DATA").setProtocol("TCP")
                        .setDestination("db.lab").addPorts(PortRange.newBuilder().setLow(5432).setHigh(5432))
                        .addPorts(PortRange.newBuilder().setLow(6000).setHigh(6010)).setTls(true).setServerName("db.lab")
                        .setDeclaredBy("target:ledger").build();
                return GetFlowsResponse.newBuilder().setEtag("f1").addItems(BindingFlows.newBuilder()
                        .setBinding("workers-ledger").setSource("workers").setTarget(r.getTargetFilter()).addFlows(f)).build();
            }
        });
        List<io.github.dihedron.ligo.client.BindingFlows> got = client(s).flows("ledger");
        assertThat(((GetFlowsRequest) s.requests.get(0)).getTargetFilter()).isEqualTo("ledger");
        assertThat(got).hasSize(1);
        assertThat(got.get(0).target()).isEqualTo("ledger");
        Flow f = got.get(0).flows().get(0);
        assertThat(f.destination()).isEqualTo("db.lab");
        assertThat(f.ports()).containsExactly(new io.github.dihedron.ligo.client.PortRange(5432, 5432),
                new io.github.dihedron.ligo.client.PortRange(6000, 6010));
        assertThat(f.tls()).isTrue();
        assertThat(f.declaredBy()).isEqualTo("target:ledger");
    }

    // JV-4
    @Test
    void aServerWithAnotherIdGetsNoRequest() {
        GrpcTestServer s = serve("spiffe://prod.lab/ns/sys/sa/impostor", new GrpcTestServer.Handler() {
            @Override
            public GetBindingsResponse bindings(GetBindingsRequest r) {
                return GetBindingsResponse.getDefaultInstance();
            }

            @Override
            public GetFlowsResponse flows(GetFlowsRequest r) {
                return GetFlowsResponse.getDefaultInstance();
            }
        });
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOf(Unauthorized.class);
        assertThat(s.requests).isEmpty();
    }

    @Test
    void unavailableCarriesTheRetryDelay() {
        com.google.rpc.Status detail = com.google.rpc.Status.newBuilder().setCode(14)
                .addDetails(Any.pack(com.google.rpc.RetryInfo.newBuilder().setRetryDelay(com.google.protobuf.Duration.newBuilder().setSeconds(7)).build())).build();
        GrpcTestServer s = serve(r -> {
            throw io.grpc.protobuf.StatusProto.toStatusRuntimeException(detail);
        });
        assertThatThrownBy(() -> client(s).bindings(Filter.all())).isInstanceOfSatisfying(Unavailable.class,
                e -> assertThat(e.retryAfter()).isEqualTo(Duration.ofSeconds(7)));
    }

    @Test
    void statusesMapToTheSameErrorsAsRest() {
        assertThat(failure(Status.UNAUTHENTICATED)).isInstanceOf(Unauthorized.class);
        assertThat(failure(Status.PERMISSION_DENIED)).isInstanceOf(Unauthorized.class);
        assertThat(failure(Status.RESOURCE_EXHAUSTED)).isInstanceOfSatisfying(Unavailable.class,
                e -> assertThat(e.retryAfter()).isNull());
        assertThat(failure(Status.UNAVAILABLE)).isInstanceOf(Unavailable.class);
        assertThat(failure(Status.INTERNAL)).isNotInstanceOfAny(Unauthorized.class, Unavailable.class)
                .isInstanceOf(LigoException.class);
    }

    Throwable failure(Status status) {
        GrpcTestServer s = serve(r -> {
            throw new StatusRuntimeException(status.withDescription("secret detail s3cr3t"));
        });
        Throwable t = org.assertj.core.api.Assertions.catchThrowable(() -> client(s).bindings(Filter.all()));
        assertThat(t.getMessage()).doesNotContain("s3cr3t");
        return t;
    }

    // the two transports give the same values for the same documents
    @Test
    void restAndGrpcAgree() {
        Pki rest = pki;
        try (TestServer r = new TestServer(rest, ClientTest.LIGO_ID, rest, req -> ClientTest.ok(ClientTest.BINDINGS))) {
            LigoClient c = LigoClient.builder().address(r.address()).serverId(ClientTest.LIGO_ID).x509Source(source).build();
            open.add(c);
            GrpcTestServer s = serve(q -> GetBindingsResponse.newBuilder().setEtag("e").addItems(binding()).build());
            Binding viaRest = c.bindings(Filter.all()).get(0);
            Binding viaGrpc = client(s).bindings(Filter.all()).get(0);
            assertThat(viaGrpc.auth()).isEqualTo(viaRest.auth());
            assertThat(viaGrpc.annotations()).isEqualTo(viaRest.annotations());
            assertThat(viaGrpc.updatedAt()).isEqualTo(viaRest.updatedAt());
            assertThat(viaGrpc.endpoint()).isEqualTo(viaRest.endpoint());
            assertThat(viaGrpc.revision()).isEqualTo(viaRest.revision());
        }
    }
}
