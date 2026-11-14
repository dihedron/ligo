# Testing and packaging

## Testing

A plugin is tested at three levels, and the shipped plugins have all three.

**Unit tests, with no backend.** Test the parsing of the configuration (a table of good and bad configurations, each bad one naming its field), the validation of targets and bindings, the identifier grammars, and the error mapping. Give `ConfigureInstances` a fake Workload API client: `pluginsdk.WorkloadClient` is the small interface a selector needs, and `NewInstanceSVIDSelector` takes it. Call your methods directly; no gRPC is needed.

**Integration tests, with a real backend.** For a database or a directory, run the real thing and test `EnsureTarget` and `CleanupTarget` end to end: that a second call changes nothing, that a foreign object is left alone, that an interrupted run leaves nothing behind. The PostgreSQL plugin does it in one transaction per call, so a crash cannot leave a role without its tag. Tag these tests with a build tag, as `//go:build integration`, so `go test ./...` stays fast.

**A test through the host.** `internal/pluginmgr/testdata/testplugin` is a small plugin that `ligo`'s own tests start as a real process, with the handshake, the checksum and the mutual TLS. Copy it to see how a plugin is run and what the host expects; run your plugin with a test version of `server.yaml` to see how it is configured.

In every test, check three things that are easy to forget:

- no secret reaches a log line or an error: run the test with a `slog` handler that writes to a buffer, and search the buffer for the passwords you generated;
- an error from the backend is not copied into `public_message`;
- `ValidateInstance` connects to nothing: point the instance at an address that refuses connections and expect success.

## Packaging

A plugin is one static binary. Build it with `CGO_ENABLED=0`, and package it as the shipped ones are: `ligo-plugin-NAME`, installed in `plugins.directory` (by default `/usr/lib/ligo/plugins`), owned by root and not writable by others.

The platform team then:

1. declares the type in `server.yaml`, with the binary's name, its SHA-256 and the `instance_bounds` that limit where its instances may connect:

   ```yaml
   platform_providers:
     - type: "echo.v1"
       binary: "ligo-plugin-echo"
       sha256: "<64-hex>"
       instance_bounds:
         allowed_endpoints: ["echo.example.com:7101", "vault.example.com:8200"]
   ```

2. registers the plugin's SVID in SPIRE, selecting it by the binary's SHA-256, so that only that binary can obtain it;
3. creates instances with `ligo apply`, as change requests.

Because the checksum is pinned, a new build of the plugin is a change to `server.yaml` and a restart: that is on purpose.

## A checklist

Before you ship a plugin, check that it:

- reports protocol version 2 and a configuration schema with `additionalProperties: false`;
- keeps the previous set when `ConfigureInstances` fails;
- connects to nothing in `ValidateInstance`, and lists every endpoint, the bootstrap Vault included;
- is idempotent in `Ensure*`, tolerant in `Cleanup*`, and leaves foreign objects alone;
- names objects from `derived_principal_name`, and tags them with the binding's ID where it can;
- checks every request value against an identifier grammar before it goes into a command;
- never returns a password but when it has just made it, and never logs one;
- returns errors with a stable code, a fixed public message and the right `retryable`;
- leaves lease times at 0 when its configuration has none, if it makes dynamic credentials;
- has the three levels of tests above.
