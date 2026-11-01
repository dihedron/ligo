# ligo: manual test backlog

Scenarios that need a person at the browser or the terminal. They are collected here and run together in one lab session. Each one names the code it checks, the session's prerequisites, and what to expect. When a scenario has passed, mark it `passed <date>`. When it has failed, mark it `failed <date>` with a note, and the fix gets its own entry.

## Before the session

Everything runs on one lab, from the repository's root, on a build that holds every branch listed below:

1. `feature/echo`, with `feature/ui` merged into it. The echo target needs both.
2. `test/lab/lab.sh reset`, then `deploy`, `serve install`, `echo install`.
3. Break-glass scenarios only (B-*): `serve install` grants `livia` the role `break_glass` and sets a break-glass policy (lab work of phase 9.7, **not done yet**).

Users (passwords in `test/lab/.state/passwords/ldap-<user>`): `carol` operator, `dave` approver, `livia` break-glass, all on `dc/corp-prod/*`. CLI principals: `ligo-ops` (olga, operator) and `ligo-approver` (dora, approver). Web UI: <https://10.252.0.20:9443/ui/login>; use one private window per user so that the sessions stay apart.

## Scenarios

| ID | Scenario | Checks | Status |
|----|----------|--------|--------|
| E-1 | Echo guide, `echo-svid-target`, request through the web UI | feature/echo | open |
| E-2 | Echo guide, `echo-local-target`, request through the CLI | feature/echo | open |
| U-1 | The change request page shows one status, which turns `APPLIED` | 7a71d06 | open |
| U-2 | Catalog "Request access" opens the wizard at step 2, with Next | 7a71d06 | open |
| U-3 | `cr list --awaiting-me` lists PENDING requests only | 7a71d06 | open |
| B-1 | Break-glass CREATE from the web UI, then ratified | d473d23 (9.6b) | open, needs 9.7 lab |
| B-2 | Break-glass CREATE reverted from the dashboard banner | d473d23 (9.6b) | open, needs 9.7 lab |
| B-3 | Break-glass refusals in the form | d473d23 (9.6b) | open, needs 9.7 lab |
| B-4 | Emergency revoke (DELETE), then ratified | d473d23 (9.6b) | open, needs 9.7 lab |
| C-1 | `ligo cr review` on a real terminal | phase 7 (34abf50) | open |

### E-1, E-2: the echo guide

Follow the guide in `.specs/ligo-echo-target.md` (on `feature/echo`): steps 1, 2b, 3 and 4 for `echo-svid-target` (E-1), then steps 1, 2a, 3 and 4 for `echo-local-target` (E-2). In 2b, set the binding name to `echo-bound-svid` at the review. U-1 to U-3 come up along the way:
- **U-1** (step 2b.6): the page shows its status only once, at the top, and that status turns `APPLIED` after dave's approval, without a reload.
- **U-2** (step 2b.4): "Request access" opens at "2. Access level", and the form has a Next button.
- **U-3** (step 2a): `cr list --awaiting-me` lists only `PENDING` requests. Run it again after the approvals: the list is empty.

### B-1: break-glass CREATE, ratified

1. As `livia`, open the **Break glass** menu entry. The entry is not shown to `carol` or `dave`.
2. Fill in a CREATE: binding `echo-bg-svid`, source `echo-bound-src`, target `echo-svid-target`, level `echo`, a justification of at least 20 characters, an incident reference, TTL `1h`, and your password. Submit, and accept the confirmation.
3. Expect a redirect to the binding. Then `test/lab/lab.sh echo client echo-bound echo-svid-target` echoes the message back (exit 0) once the binding is `ACTIVE`.
4. As `dave`, open **Bindings**. The red banner lists `echo-bg-svid` with its time to expiry, and offers Ratify and Revert.
5. Click **Ratify**, enter a comment, and submit. The sides table says "ratified by dave", and the banner entry disappears.

### B-2: break-glass CREATE, reverted

1. As in B-1, with the binding name `echo-bg-revert`.
2. As `dave`, from the banner, click **Revert**, then **Revert now** on the change request page, and confirm.
3. The binding is deleted (or `DELETING`, then gone), and the echo client gets `no binding` (exit 2).

### B-3: refusals in the form

As `livia`, each of these must show an error in the form, and the change must not be applied:
- a wrong password. The audit log then holds a `SESSION_LOGIN_FAILED` entry (`test/lab/lab.sh cli ligo-ops audit …`, or a psql query on `audit_log`);
- a justification shorter than 20 characters;
- a TTL of `1m`;
- a second break-glass change of a binding that already has one open (`409 break-glass-open`).

### B-4: emergency revoke

1. As `livia`, choose **Revoke a binding**, enter `echo-bg-svid` (ratified in B-1) and its current revision, and the emergency fields. Submit.
2. The binding goes away at once, with no approval. There is nothing to revert: the change request page offers dave Ratify but no Revert.

### C-1: `ligo cr review`

1. File two requests, e.g. the source and a binding of the echo guide (2a), as `ligo-ops`.
2. On a real terminal: `test/lab/lab.sh cli ligo-approver cr review`. The queue lists both requests. Read one, approve it, decline the other with a comment, and quit.
3. `cr list` shows the decisions you made.
