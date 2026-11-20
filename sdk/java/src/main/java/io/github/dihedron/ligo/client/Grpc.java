// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.Struct;
import com.google.protobuf.Timestamp;
import com.google.protobuf.Value;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import io.grpc.protobuf.StatusProto;
import io.spiffe.provider.SpiffeKeyManager;
import io.spiffe.provider.SpiffeTrustManager;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.X509Source;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.X509ExtendedTrustManager;
import ligo.workload.v1alpha1.Workload.BindingFlows;
import ligo.workload.v1alpha1.Workload.GetBindingsRequest;
import ligo.workload.v1alpha1.Workload.GetBindingsResponse;
import ligo.workload.v1alpha1.Workload.GetFlowsRequest;
import ligo.workload.v1alpha1.Workload.GetFlowsResponse;
import ligo.workload.v1alpha1.Workload.NetworkFlow;
import ligo.workload.v1alpha1.Workload.PortRange;
import ligo.workload.v1alpha1.Workload.WorkloadBinding;
import ligo.workload.v1alpha1.WorkloadBindingServiceGrpc;

/**
 * The gRPC transport (.specs/ligo-client-sdk-java.md §3.4): the same SVID and the same server-ID check as REST, the
 * messages turned into the JSON items REST gives, so both transports decode with the same code.
 */
final class Grpc implements Wire {
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private final ManagedChannel channel;
    private final WorkloadBindingServiceGrpc.WorkloadBindingServiceBlockingStub stub;
    private final AtomicReference<CertificateException> refused = new AtomicReference<>(); // why a handshake failed

    Grpc(String host, int port, X509Source source, SpiffeId serverId) {
        try {
            SpiffeTrustManager spiffe = new SpiffeTrustManager(source, () -> Set.of(serverId));
            SslContextBuilder ssl = SslContextBuilder.forClient().keyManager(new SpiffeKeyManager(source))
                    .trustManager(new Recording(spiffe, refused)).protocols(Tls.PROTOCOLS);
            // the JDK engine, not the OpenSSL one: the trust manager is the JDK's, and so is the hostname rule (none)
            channel = NettyChannelBuilder.forAddress(host, port)
                    .sslContext(GrpcSslContexts.configure(ssl, SslProvider.JDK).build())
                    .maxInboundMessageSize(Rest.MAX_BODY).build();
        } catch (SSLException e) {
            throw new LigoException("cannot build the TLS context", e);
        }
        stub = WorkloadBindingServiceGrpc.newBlockingStub(channel);
    }

    @Override
    public Answer get(Kind kind, Map<String, String> query, String etag) {
        String target = query.getOrDefault("target", "");
        var s = stub.withDeadlineAfter(Rest.CALL_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        try {
            if (kind == Kind.BINDINGS) {
                GetBindingsResponse r = s.getBindings(GetBindingsRequest.newBuilder().setTargetFilter(target)
                        .setPlatformTypeFilter(query.getOrDefault("platformType", "")).setKnownEtag(etag).build());
                if (r.getNotModified()) {
                    return new Answer(List.of(), r.getEtag(), true);
                }
                List<JsonNode> items = new ArrayList<>();
                r.getItemsList().forEach(b -> items.add(binding(b)));
                return new Answer(items, r.getEtag(), false);
            }
            GetFlowsResponse r = s.getFlows(GetFlowsRequest.newBuilder().setTargetFilter(target).setKnownEtag(etag).build());
            if (r.getNotModified()) {
                return new Answer(List.of(), r.getEtag(), true);
            }
            List<JsonNode> items = new ArrayList<>();
            r.getItemsList().forEach(f -> items.add(flows(f)));
            return new Answer(items, r.getEtag(), false);
        } catch (StatusRuntimeException e) {
            throw failure(e);
        }
    }

    @Override
    public void close() {
        channel.shutdownNow();
        try {
            channel.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** gRPC statuses mean what the HTTP statuses of REST mean; the details never reach a message. */
    private LigoException failure(StatusRuntimeException e) {
        Status.Code code = e.getStatus().getCode();
        switch (code) {
            case UNAUTHENTICATED, PERMISSION_DENIED:
                return new Unauthorized("ligo refused the workload: " + code);
            case UNAVAILABLE:
                if (refused.get() != null || causedByCertificate(e)) {
                    return new Unauthorized("the server is not the one this client accepts", e);
                }
                return new Unavailable("ligo is unavailable: " + code, retryDelay(e), e);
            case RESOURCE_EXHAUSTED, DEADLINE_EXCEEDED:
                return new Unavailable("ligo is unavailable: " + code, retryDelay(e), e);
            default:
                return new LigoException("unexpected answer: " + code);
        }
    }

    private static boolean causedByCertificate(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateException) {
                return true;
            }
        }
        return false;
    }

    /** The RetryInfo detail, which ligo sends as REST sends Retry-After. */
    private static java.time.Duration retryDelay(StatusRuntimeException e) {
        com.google.rpc.Status status = StatusProto.fromThrowable(e);
        if (status == null) {
            return null;
        }
        for (com.google.protobuf.Any d : status.getDetailsList()) {
            try {
                if (d.is(com.google.rpc.RetryInfo.class)) {
                    com.google.protobuf.Duration delay = d.unpack(com.google.rpc.RetryInfo.class).getRetryDelay();
                    java.time.Duration after = java.time.Duration.ofSeconds(delay.getSeconds(), delay.getNanos());
                    return !after.isZero() && !after.isNegative() && after.compareTo(Rest.MAX_RETRY_AFTER) <= 0 ? after : null;
                }
            } catch (com.google.protobuf.InvalidProtocolBufferException ignored) {
                return null;
            }
        }
        return null;
    }

    // -- messages to the items of the REST documents

    static ObjectNode binding(WorkloadBinding b) {
        ObjectNode n = NODES.objectNode();
        n.put("id", b.getId()).put("name", b.getName()).put("source", b.getSource()).put("target", b.getTarget())
                .put("accessLevel", b.getAccessLevel()).put("platformType", b.getPlatformType())
                .put("platform", b.getPlatform()).put("revision", b.getRevision()).put("description", b.getDescription());
        if (b.hasUpdatedAt()) {
            Timestamp t = b.getUpdatedAt();
            n.put("updatedAt", Instant.ofEpochSecond(t.getSeconds(), t.getNanos()).toString());
        }
        ObjectNode annotations = n.putObject("annotations");
        b.getAnnotationsMap().forEach(annotations::put);
        n.set("auth", struct(b.getAuth()));
        n.set("spec", struct(b.getSpec()));
        return n;
    }

    static ObjectNode flows(BindingFlows f) {
        ObjectNode n = NODES.objectNode();
        n.put("binding", f.getBinding()).put("source", f.getSource()).put("target", f.getTarget());
        ArrayNode list = n.putArray("flows");
        for (NetworkFlow fl : f.getFlowsList()) {
            ObjectNode o = list.addObject();
            o.put("name", fl.getName()).put("purpose", fl.getPurpose()).put("protocol", fl.getProtocol())
                    .put("destination", fl.getDestination()).put("tls", fl.getTls()).put("serverName", fl.getServerName())
                    .put("description", fl.getDescription()).put("declaredBy", fl.getDeclaredBy());
            ArrayNode ports = o.putArray("ports");
            for (PortRange p : fl.getPortsList()) {
                if (p.getLow() == p.getHigh()) {
                    ports.add(p.getLow());
                } else {
                    ports.add(p.getLow() + "-" + p.getHigh());
                }
            }
        }
        return n;
    }

    private static ObjectNode struct(Struct s) {
        ObjectNode n = NODES.objectNode();
        s.getFieldsMap().forEach((k, v) -> n.set(k, value(v)));
        return n;
    }

    private static JsonNode value(Value v) {
        switch (v.getKindCase()) {
            case STRING_VALUE:
                return NODES.textNode(v.getStringValue());
            case BOOL_VALUE:
                return NODES.booleanNode(v.getBoolValue());
            case NUMBER_VALUE:
                double d = v.getNumberValue();
                if (d == Math.rint(d) && Math.abs(d) < 9e15) { // a whole number is written as REST writes it
                    return Math.abs(d) <= Integer.MAX_VALUE ? NODES.numberNode((int) d) : NODES.numberNode((long) d);
                }
                return NODES.numberNode(d);
            case STRUCT_VALUE:
                return struct(v.getStructValue());
            case LIST_VALUE:
                ArrayNode a = NODES.arrayNode();
                v.getListValue().getValuesList().forEach(x -> a.add(value(x)));
                return a;
            default:
                return NODES.nullNode();
        }
    }

    /** Remembers why the server was refused: gRPC reports a failed handshake only as UNAVAILABLE. */
    private static final class Recording extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager delegate;
        private final AtomicReference<CertificateException> refused;

        Recording(X509ExtendedTrustManager delegate, AtomicReference<CertificateException> refused) {
            this.delegate = delegate;
            this.refused = refused;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            try {
                delegate.checkServerTrusted(chain, authType, engine);
                refused.set(null);
            } catch (CertificateException e) {
                refused.set(e);
                throw e;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            try {
                delegate.checkServerTrusted(chain, authType, socket);
                refused.set(null);
            } catch (CertificateException e) {
                refused.set(e);
                throw e;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                delegate.checkServerTrusted(chain, authType);
                refused.set(null);
            } catch (CertificateException e) {
                refused.set(e);
                throw e;
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            delegate.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            delegate.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
