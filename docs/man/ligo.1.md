---
title: LIGO
section: 1
header: User Commands
footer: ligo
date: 2026-11-18
---

# NAME

ligo - the SPIFFE binding lifecycle service: the daemon and its command line

# SYNOPSIS

**ligo** [*GLOBAL OPTIONS*] *COMMAND* [*SUBCOMMAND*] [*OPTIONS*] [*ARGUMENTS*]

**ligo serve** [**-c** *FILE*]

**ligo completion** *SHELL*

**ligo version** [**-v**]

# DESCRIPTION

**ligo** is the control plane that creates, approves, applies and revokes the bindings between workloads and the targets they use, and that rotates the credentials behind them. The same program is the daemon (**ligo serve**) and the administrator's command line: every other command talks to a running **ligo** over its admin API, with the caller's identity, and files, shows, approves or withdraws change requests and the resources they create.

Commands are written as **ligo** *object* *verb*: the *object* is the type of resource (**source**, **target**, **binding**, **cr**, ...) and the *verb* the action (**list**, **show**, **delete**, ...). The verb that displays an object is **show**. The exceptions are the commands that act on a manifest (**apply**, whose kinds come from the file) and the process commands (**serve**, **migrate**, **version**, **completion**).

Each top-level command has its own manual page, **ligo-**\ *command*\ **(1)**, with its subcommands, their arguments and options. **ligo** *command* **\--help** prints the same from the program.

# GLOBAL OPTIONS

**-l**, **\--log-level**=*LEVEL*
:   Set logging verbosity: **debug**, **info** (the default), **warn**, **error** or **off**. Environment: **LIGO_LOG_LEVEL**.

**-o**, **\--output**=*FORMAT*
:   Output format for the commands that show data: **table** (the default), **json** or **yaml**. Environment: **LIGO_OUTPUT**.

**-h**, **\--help**
:   Show the help message.

# COMMANDS

**account**
:   Manage the registry of accounts (tenants).

**apply**
:   Submit create or update change requests from a YAML or JSON manifest.

**audit**
:   Query and verify the cryptographic audit log.

**binding**
:   Bindings: list, show, delete, release, retry, rotate, flows.

**break-glass**
:   Emergency changes in approval-required jurisdictions.

**catalog**
:   Search the catalog of targets and show their flows.

**charter**
:   Show the charter and evaluate a planned change.

**completion**
:   Print the shell completion script: bash, zsh, fish or powershell.

**cr**
:   Manage change requests: list, show, approve, decline, withdraw, ratify, revert, review.

**executors**
:   Show the executors' pending workflows, and recover those of a replica gone for good.

**hold**
:   List and lift the holds left by emergency removals of managed bindings.

**identity-provider**
:   Identity provider instances.

**maintenance**
:   Show, enable or disable cluster-wide maintenance mode.

**migrate**
:   Apply the database migrations as the migrator role, before a rollout.

**platform**
:   Inspect configured platforms and their UI schemas.

**secret-store**
:   Secret store instances.

**serve**
:   Run the control-plane daemon.

**source**
:   Sources: list, show, delete, release, test a regex, deprecate, reactivate.

**target**
:   Targets: list, show, delete, release, deprecate, reactivate, access levels, bulk revocation.

**version**
:   Print the program version information; **-v** prints the build details too.

# AUTHENTICATION

The commands that call the admin API choose how they identify the caller:

**\--spiffe-socket**=*PATH*
:   Authenticate with the X.509-SVID that the SPIRE Workload API socket at *PATH* gives. The server is verified with the socket's bundle against **\--server-id**, or against the CA given by **\--ca-cert**. Environment: **LIGO_SPIFFE_SOCKET**, **LIGO_SERVER_ID**.

**-u**, **\--username**=*NAME*, **\--password-file**=*FILE*
:   Authenticate with LDAP Basic credentials, which works only when the server allows them. Without a password file the password is prompted for, without echo. The password is never taken from a command line option. Environment: **LIGO_USERNAME**, **LIGO_PASSWORD_FILE**.

**-s**, **\--server**=*URL*
:   The admin server's base URL; the default is *https://localhost:9443*. Environment: **LIGO_SERVER_URL**.

**\--ca-cert**=*FILE*
:   The CA bundle that verifies the admin server. Environment: **LIGO_CA_CERT**.

**ligo** never offers a way to skip the verification of the server.

# ENVIRONMENT

**LIGO_LOG_LEVEL**, **LIGO_OUTPUT**
:   The global options above.

**LIGO_SERVER_URL**, **LIGO_CA_CERT**, **LIGO_SERVER_ID**, **LIGO_SPIFFE_SOCKET**, **LIGO_USERNAME**, **LIGO_PASSWORD_FILE**
:   The connection to the admin API, as above.

**LIGO_CONFIG**
:   The path of *server.yaml* for **ligo serve**.

**LIGO_APPROVAL_REF**, **LIGO_AUTOMATION_CONTEXT**
:   The approval reference of a delegated approval, and the optional description of the calling automation, for the commands that write.

**LIGO_DOTENV**
:   A *.env* file that **ligo version -v** loads and lists, with the values of passwords, tokens and secrets masked.

# FILES

*/etc/ligo/server.yaml*
:   The daemon's configuration, read by **ligo serve** (**-c** or **LIGO_CONFIG** names another).

*/usr/lib/ligo/plugins*
:   The directory of the plugins that the daemon launches.

*/usr/share/ligo/examples*
:   An example *server.yaml* and the database roles.

# EXIT STATUS

**0**
:   The command succeeded, or it printed the help.

**1**
:   The command line was invalid, or the command failed; the reason is on the standard error.

# EXAMPLES

List the sources, as JSON:

    ligo --output=json source list

Show a change request and approve it:

    ligo cr show CR-ID
    ligo cr approve CR-ID

Submit the resources of a manifest:

    ligo apply manifest.yaml

Load the completion for bash in the current shell:

    source <(ligo completion bash)

# SEE ALSO

**ligo-source**(1), **ligo-target**(1), **ligo-binding**(1), **ligo-cr**(1), **ligo-serve**(1) and the other **ligo-**\ *command*\ **(1)** pages; the Setup Guide, the Operator's Guide and the Architecture and Design Guide, attached to each release as PDF; *https://github.com/dihedron/ligo*.

# AUTHOR

Andrea Funtò.
