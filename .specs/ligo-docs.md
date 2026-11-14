# ligo: release documents

Status: approved 2026-11-05.

## Overview

People who deploy and run `ligo` need documents written for them. This file adds three (a fourth, the Planning for Deployment Guide, is specified in `.specs/ligo-planning-guide.md`), and a short leaflet for newcomers, *Why ligo?*, built as PDFs and published with every release, beside the binaries.

| Document | For | Answers |
| :------- | :------ | :---------------------- |
| **Setup Guide** | Whoever installs `ligo` and its plugins | How do I prepare PostgreSQL, SPIRE and Vault, configure and start `ligo`, and check that it works? |
| **Architecture and Design** | Architects, security reviewers, auditors | How does `ligo` work, why is it built this way, what does it protect against and what does it not? |
| **Operator's Guide** | Whoever runs it day to day, and on call | How do I watch it, what are the routine and incident procedures, what does each error mean? |
| **Planning for Deployment Guide** | Architects planning an installation | Which layout fits my organisation: realms, SPIRE, installations, roles, capacity? Specified in `.specs/ligo-planning-guide.md`. |
| **Developer's Guide** | Developers of workloads and plugins | How do I read my binding and follow its rotation with the Go client SDK? How do I write a plugin? Sources in `docs/developers-guide/`. |
| **Why ligo?** | Newcomers, decision makers, security leads | Why give workloads identities, how do `ligo` and the attestation plugins fit in the SPIFFE and SPIRE ecosystem, and what does it bring to security? |

The documents are self-contained: a reader never needs the specs, which stay the developers' design. Out of scope: an HTML site, translations, documentation of the code.

## Toolchain

The toolchain of `lxd-spiffe`:

- pandoc with LaTeX and the Eisvogel template, from the `pandoc/extra` image pinned by version and digest; Mermaid diagrams (`docs/common/diagrams/*.md`, one `mermaid` block each) rendered by the pinned `mermaid-cli` image; `docs/build.sh` runs both. Output goes to `build/docs/`, because goreleaser cleans `dist/`.
- One directory per document, one file per chapter, in file order, and a `metadata.yaml`; `docs/common/` for the shared defaults, front matter, filters, diagrams and artwork.
- **Filters**: `include.lua` shows a file's content in a code block; `landscape.lua` turns a `::: landscape` div into landscape pages, for a table or a diagram that does not fit in portrait; `breakcode.lua` allows breaks in long inline code.
- **Artwork**: `docs/common/artwork/logo.png`, the symbol only, rendered once from `ligo-symbol.svg` with a transparent background, as LaTeX cannot include the SVG. It is on every title page.

## Build and publication

- `make docs` builds `ligo-setup-guide-<version>.pdf`, `ligo-architecture-and-design-<version>.pdf`, `ligo-operators-guide-<version>.pdf`, `ligo-planning-for-deployment-guide-<version>.pdf`, `ligo-developers-guide-<version>.pdf` and `ligo-why-ligo-<version>.pdf`; `make release` builds them with the release tag first.
- `.github/workflows/docs.yml` builds them on every change to `docs/` or `examples/`, and attaches them to the run.
- goreleaser attaches them to the release (`release.extra_files`) and lists them in the signed checksums file (`checksum.extra_files`). The packages do not install them.

## Completeness

`docs/docs_test.go` fails when something a reader needs is missing:

- every `server.yaml` key, read from the configuration's types, in the Setup Guide's configuration reference;
- every field of each shipped plugin's configuration, in the same reference;
- every problem slug of the admin API, and every error code of the shipped plugins, in the Operator's Guide's error reference;
- every metric, in the Operator's Guide's monitoring chapter;
- a table whose columns all have the same width, as the dashes set the proportions.

## Content

The outlines fix the jurisdiction, not the wording.

- **Setup Guide**: introduction and known limits; prerequisites; getting and verifying a release; PostgreSQL; SPIRE; Vault or OpenBao; configuring and starting `ligo`; each plugin; a first binding; upgrades and removal; configuration reference.
- **Architecture and Design**: context and goals; components and trust boundaries; resources and jurisdictions; the pipeline; consent and the charter; durability and sealing; workload resolution; the threat model; validation; design decisions and alternatives.
- **Operator's Guide**: operating model; monitoring; routine procedures; incident procedures; error reference; troubleshooting.
- **Why ligo?**: a leaflet of 5 to 10 pages, for a reader who knows neither SPIFFE nor `ligo`. The problem with local passwords; the few concepts needed (workload, SPIFFE ID, SVID, trust domain, SPIRE, attestation, federation); step one, giving every machine and workload an identity, with SPIRE's attestors and the companion projects `lxd-spiffe`, `openstack-spiffe` and the planned `esxi-spiffe`; step two, wiring the data centre together across realms with `ligo`; security considerations, including the visibility it gives across clouds and data centres, and the current limits; where to go next. One diagram per step at least. The README carries the same content, shortened.
