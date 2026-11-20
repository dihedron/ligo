// SPDX-License-Identifier: MIT
package io.github.dihedron.ligo.client;

import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import io.grpc.stub.StreamObserver;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLSession;
import ligo.workload.v1alpha1.Workload.GetBindingsRequest;
import ligo.workload.v1alpha1.Workload.GetBindingsResponse;
import ligo.workload.v1alpha1.Workload.GetFlowsRequest;
import ligo.workload.v1alpha1.Workload.GetFlowsResponse;
import ligo.workload.v1alpha1.WorkloadBindingServiceGrpc;

/** An in-process ligo on gRPC: TLS 1.3, a client certificate required, the peer's SPIFFE ID recorded. */
final class GrpcTestServer implements AutoCloseable {
    interface Handler {
        GetBindingsResponse bindings(GetBindingsRequest r) throws StatusRuntimeException, InterruptedException;

        GetFlowsResponse flows(GetFlowsRequest r) throws StatusRuntimeException, InterruptedException;
    }

    final List<Object> requests = new CopyOnWriteArrayList<>();
    final List<String> peers = new CopyOnWriteArrayList<>();
    private final Server server;

    GrpcTestServer(Pki pki, String serverId, Handler handler) {
        try {
            Pki.Leaf leaf = pki.svid(serverId);
            SslContextBuilder ssl = SslContextBuilder.forServer(leaf.key(), leaf.certificate()).trustManager(pki.ca)
                    .clientAuth(ClientAuth.REQUIRE).protocols("TLSv1.3");
            ServerInterceptor peer = new ServerInterceptor() {
                @Override
                public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers,
                        ServerCallHandler<Q, R> next) {
                    peers.add(spiffeId(call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION)));
                    return next.startCall(call, headers);
                }
            };
            server = NettyServerBuilder.forAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                    .sslContext(GrpcSslContexts.configure(ssl, SslProvider.JDK).build())
                    .addService(ServerInterceptors.intercept(new WorkloadBindingServiceGrpc.WorkloadBindingServiceImplBase() {
                        @Override
                        public void getBindings(GetBindingsRequest r, StreamObserver<GetBindingsResponse> out) {
                            requests.add(r);
                            try {
                                out.onNext(handler.bindings(r));
                                out.onCompleted();
                            } catch (StatusRuntimeException e) {
                                out.onError(e);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                        }

                        @Override
                        public void getFlows(GetFlowsRequest r, StreamObserver<GetFlowsResponse> out) {
                            requests.add(r);
                            try {
                                out.onNext(handler.flows(r));
                                out.onCompleted();
                            } catch (StatusRuntimeException e) {
                                out.onError(e);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                        }
                    }, peer)).build().start();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String address() {
        return "127.0.0.1:" + server.getPort();
    }

    private static String spiffeId(SSLSession session) {
        try {
            X509Certificate leaf = (X509Certificate) session.getPeerCertificates()[0];
            for (List<?> san : leaf.getSubjectAlternativeNames()) {
                if ((Integer) san.get(0) == 6) {
                    return (String) san.get(1);
                }
            }
        } catch (Exception e) {
            // no peer certificate
        }
        return "";
    }

    @Override
    public void close() {
        server.shutdownNow();
    }
}
