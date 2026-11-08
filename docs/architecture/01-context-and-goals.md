# Context and goals

## The problem

SPIFFE gives a workload an identity. It does not say what that identity may use, who agreed to that, or how the workload gets a credential for a system that knows nothing of SPIFFE.

In practice someone creates a database role by hand, puts its password in a vault, tells the team where it is, and forgets it. Nobody knows later why it exists. It is hard to revoke, and rarely rotated.

Two organisations make it harder. In a multi-tenant cloud, each team is autonomous in its own tenancy, and has no rights in its neighbours'. In a data centre, authority is central. A connection can cross between them, and a rule that lets one owner alone create it allows **target hijacking**, binding a workload of your own to someone else's database, and **credential injection**, binding someone else's workloads to a system you control.

## The solution

`ligo` makes that connection a first-class resource, decided by the people responsible for each end:

- A **source** is a group of workloads, defined by a SPIFFE ID regex in one trust domain.
- A **target** is one resource on a **platform**, with named access levels and the network flows needed to reach it.
- A **binding** says that a source may use a target at one of its access levels.

Every change is a change request that each owner must approve. `ligo` then provisions the binding through plugins, repairs drift, rotates secrets, and tells attested workloads what they may use.

```{=latex}
\begin{center}
```
![The components of ligo.](overview.pdf){width=100%}
```{=latex}
\end{center}
```

## Goals

- **Least privilege by construction.** One principal per binding, only the access level's privileges, within the platform's bounds.
- **Consent from everyone concerned**, enforced in the database, not only in code.
- **Survive crashes.** Provisioning resumes from its last checkpoint, never loses a secret and never leaves one in clear.
- **A failure never takes working access away.** Workloads keep the last good snapshot.
- **Revocation is fast and unilateral.** It takes effect at once in the API, and any one owner can do it.
- **An auditable history**, in a hash chain.

## Non-goals

- `ligo` does not carry traffic or broker credentials: workloads read them from the store, and connect themselves.
- It is not an identity provider for workloads: that is SPIRE.
- It does not manage target schemas, tables or group roles: targets are registered, never created.
- It does not register workloads in SPIRE, and cannot detect one registered under the wrong tenancy.
