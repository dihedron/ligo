# Man pages and shell completions for ligo

- **Version:** 0.1 (2026-11-18), approved by the user in plan mode
- **Backlog:** item 17
- **Branch:** `feature/cli-extras`, from main
- **Reference:** netcheck's `.specs/netcheck-cli-extras.md` (the same design, merged in PR #34)

## 1. Why

`ligo` has 19 top-level commands, most with subcommands, and no man page and no shell completion. An operator who types `ligo cr approve` all day expects both. They ship as part of the packages.

## 2. Decisions (the user, 2026-11-18)

| Question | Decision |
| :-- | :-- |
| Pages | A hand-written `ligo(1)` and one generated `ligo-<command>(1)` for each top-level command (`ligo-source(1)`, `ligo-cr(1)`, ...). |
| Generation | `ligo.1` is written in Markdown (`docs/man/ligo.1.md`) and built with pandoc into the committed `docs/man/ligo.1` (`make man`, `make man-check`). The per-command pages are generated from the live parser by `internal/tools/genman` at release time and are not committed. |
| Completions | `ligo completion <bash|zsh|fish|powershell>`, static scripts built from the whole command tree. |
| Shipping | The deb and rpm packages install the pages and the bash, zsh and fish completions; the archives carry the pages and all four scripts. |

## 3. Design

- `completion` is a command of the tree, with the process commands (`serve`, `migrate`, `version`). It walks the parser recursively: commands, aliases, descriptions, options (short and long), the choices of an option (`--output`: `table json yaml`) and file-valued options. A press of TAB never runs `ligo`, so it never reaches a server or reads a credential.
- `ligo.1` has NAME, SYNOPSIS, DESCRIPTION, GLOBAL OPTIONS, COMMANDS (with a pointer to each `ligo-<command>(1)`), AUTHENTICATION, ENVIRONMENT, FILES, EXIT STATUS, EXAMPLES, SEE ALSO and AUTHOR.
- A generated page has the command's description, then each subcommand with its aliases, description, arguments and options.
- File names: `ligo.1.gz`, `ligo-<command>.1.gz`, `_ligo`, `ligo` (bash), `ligo.fish`; nothing else is written.

## 4. Threat model

| ID | Threat | Mitigation |
| :-- | :-- | :-- |
| T-K1 | TAB runs `ligo`, which would talk to a server with the operator's identity. | The scripts are static and call nothing; a test rejects `eval` and command substitution. |
| T-K2 | A description breaks a script or injects code. | The text comes from the binary's own tags, escaped by one function per shell; a fuzz target. |
| T-K3 | A package overwrites another package's files. | Only the names above. |
| T-K4 | The pages drift from the CLI. | The generated pages are built from the parser; a test compares `ligo.1.md` with it; `make man-check`. |
| T-K5 | Secrets in examples. | Placeholders only; no password on a command line. |

## 5. Tests first

- **CX-1** Every command, subcommand, alias and option of the tree is in each script.
- **CX-2** An unknown shell, or none, is exit 1 with the usage.
- **CX-3** bash loads the script and completes `ligo so` to `source`, `ligo source l` to `list ls`, `ligo --output ` to `table json yaml`; zsh and fish load when installed.
- **CX-4** `ligo.1.md` documents every top-level command and global option; `groff -ww -z` renders `ligo.1` and every generated page with no warning.
- **CX-5** The escaping is fuzzed.
- **CX-6** `genman` writes one page for each top-level command with every subcommand and option, the same bytes on every run.
- **CX-7** On a machine with the `.deb` installed: the files are readable by an ordinary user, `man -w ligo-source` finds its page, bash completes.

## 6. Chunks

| Chunk | Content |
| :-- | :-- |
| 0 | This spec and the backlog row. |
| 1 | CX-1 to CX-3 and CX-5, the `completion` command. |
| 2 | `ligo.1.md`, `make man`, `genman`, CX-4 and CX-6. |
| 3 | goreleaser and nfpm, `make snapshot`. |
| 4 | The Operator's and Setup Guides, the README. |
| 5 | CX-7. |

## 7. Out of scope

Dynamic completion (asking the server for names of sources or bindings); a `man` command; pages for the plugins; sharing the code with netcheck through a module (a later refactor).
