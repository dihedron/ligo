# ligo-client (Java)

Java SDK for workloads that use [ligo](https://github.com/dihedron/ligo): it reads the calling
workload's bindings and network flows from ligo's workload API over mTLS, on REST or gRPC, with
the workload's SVID, accepting only ligo's SPIFFE ID; it takes the binding's credential from the
secret store with a JWT-SVID; and it follows rotation and revocation.

Java 17 or later; depends on `java-spiffe`, `grpc-java` and `jackson-databind`. Every network call
has a blocking form and a `CompletableFuture` twin; safe to use from several threads. MIT license.

## Install

The jar, the sources jar, the javadoc jar and the pom are attached to each release of ligo (the
library is not on Maven Central yet). Install the ones of the version that matches your ligo:

```bash
mvn install:install-file -Dfile=ligo-client-X.Y.Z.jar -DpomFile=ligo-client-X.Y.Z.pom
```

```xml
<dependency>
  <groupId>io.github.dihedron.ligo</groupId>
  <artifactId>ligo-client</artifactId>
  <version>X.Y.Z</version>
</dependency>
```

## Use

```java
try (LigoClient client = LigoClient.builder()
        .address("ligo.example.com:8443")
        .serverId("spiffe://example.com/ns/sys/sa/ligo")
        .build()) {
    for (Binding b : client.bindings(Filter.target("orders-db"))) {
        Credential cred = client.credential(b); // its password never shows in toString or logs
    }
    try (Watch watch = client.watch(Filter.target("orders-db"), WatchOptions.withCredentials())) {
        for (Event ev : watch) {
            // ADDED, CHANGED, REMOVED, CREDENTIAL_ROTATED
        }
    }
    FlowResults results = client.checkFlows("orders-db", FlowOptions.builder().build());
    assert results.ok();
}
```

The Developer's Guide has the chapter "The Java SDK": the builder, credentials and JDBC, watch,
async, flow testing, the errors, and what the SDK protects. Design and threat model:
`.specs/ligo-client-sdk-java.md` in the repository.

## Develop

```bash
make java-test java-lint java-build   # from the repository root; java-bench for the JMH benchmark
```

The tests need no ligo: they run an in-memory CA and in-process TLS servers, on REST and on gRPC.
The golden documents in `api/testdata/workload/` are decoded by the Go, Python and Java tests.
The gRPC stubs are generated at build time from `api/proto/workload/v1alpha1/workload.proto`.
