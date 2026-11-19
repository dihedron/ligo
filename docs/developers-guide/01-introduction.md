# Introduction

This guide is for developers. It has three parts.

**Part 1, Developing an application,** is for the developer of a workload that `ligo` gives access to a target: a service that needs a database, a directory or any other system through a binding. It shows how the workload finds its bindings, reads the credentials and follows their rotation, with the Go client SDK, `pkg/client`, or the Python one, `ligo-client`. SDKs for Java and JavaScript/TypeScript will follow; the chapter "Other languages" says what they will cover.

**Part 2, Developing a Ligo Plugin,** is for the developer of a new kind of identity provider, platform provider or secret store, with the plugin SDK, `pkg/pluginsdk`. It assumes Part 1's vocabulary and the Architecture and Design Guide's.

**Part 3, Automating ligo,** is for the developer of a tool that drives `ligo` itself, such as a program that files sources and waits for their approval, with the admin client, `pkg/adminclient`. The `ligo` CLI is built on it, and so are the Terraform and OpenTofu provider and the MCP server of the same project.

The Setup Guide installs `ligo` and the Operator's Guide runs it; this guide does neither. Where it needs a term from them, it says it again in one line.

## Words used here

- A **source** is a workload identity, a **target** is a resource on a **platform**, and a **binding** links one source to one target at one **access level**.
- A **workload** is a running program with a SPIFFE identity, an SVID, that its SPIRE agent issues. It is the source of a binding.
- `ligo` serves the **workload API** on port 8443: over REST and over gRPC, with the same data. A workload calls it with its X.509-SVID.
- A **secret store** keeps the credential of a binding. Today the shipped stores are Vault and OpenBao.

## Versions

The Python SDK, `ligo-client`, is built from the same tag as `ligo` and has its version; its wheel is attached to the release. The Go SDK and the admin client are part of `ligo`'s module, `github.com/dihedron/ligo/pkg/client` and `github.com/dihedron/ligo/pkg/adminclient`, and have its version. Until `ligo` is 1.0.0, their APIs may change between minor versions; the release notes say how.
