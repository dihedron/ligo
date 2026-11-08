# ligo: manual test backlog

Scenarios that need a person at the browser or the terminal. They are collected here and run together in one lab session. Each one names the code it checks, the session's prerequisites, and what to expect. When a scenario has passed, mark it `passed <date>`. When it has failed, mark it `failed <date>` with a note, and the fix gets its own entry.

## Before the session

Everything runs on one lab, from the repository's root, on a build that holds every branch listed below:

1. `feature/echo`, with `feature/ui` merged into it. The echo target needs both.
2. `test/lab/lab.sh reset`, then `deploy`, `serve install`, `echo install`.
3. Break-glass scenarios only (B-*): `serve install` grants `livia` the role `break_glass` on `dc/corp-prod/*` and sets a break-glass policy (default TTL 1h, maximum 4h, at most 3 open changes).

Users (passwords in `test/lab/.state/passwords/ldap-<user>`): `carol` operator, `dave` approver, `livia` break-glass, all on `dc/corp-prod/*`. CLI principals: `ligo-ops` (olga, operator) and `ligo-approver` (dora, approver). Web UI: <https://10.252.0.20:9443/ui/login>, or <https://10.252.0.20:9445/ui/login> with the `lb` scenario (`external_origin`); use one private window per user so that the sessions stay apart.

## Scenarios

| ID | Scenario | Checks | Status |
|----|----------|--------|--------|
| E-1 | Echo guide, `echo-svid-target`, request through the web UI | feature/echo | passed 2026-11-01 (F-1, F-2) |
| E-2 | Echo guide, `echo-local-target`, request through the CLI | feature/echo | passed 2026-11-01 |
| U-1 | The change request page shows one status, which turns `APPLIED` | 7a71d06 | passed 2026-11-01 |
| U-2 | Catalog "Request access" opens the wizard at step 2, with Next | 7a71d06 | passed 2026-11-01 |
| U-3 | `cr list --awaiting-me` lists PENDING requests only | 7a71d06 | passed 2026-11-01 |
| U-4 | Header and sign-in: ligo symbol, user menu | a96b117 | passed 2026-11-01 |
| B-1 | Break-glass CREATE from the web UI, then ratified | d473d23 (9.6b) | passed 2026-11-01 (F-4, F-5, F-6) |
| B-2 | Break-glass CREATE reverted from the dashboard banner | d473d23 (9.6b) | passed 2026-11-01 (F-7, F-8, F-9) |
| B-3 | Break-glass refusals in the form | d473d23 (9.6b) | failed 2026-11-01 (F-10, F-11, F-12); passed 2026-11-01 after the fixes (R-3, R-4) |
| B-4 | Emergency revoke (DELETE), then ratified | d473d23 (9.6b) | passed 2026-11-02 (overdue review raised once, after a power cut) |
| C-1 | `ligo cr review` on a real terminal | phase 7 (34abf50) | passed 2026-11-02 (through `lab.sh cli`) |
| A-1 | The Accounts page in a real browser: register, refusals in the form, retire with its confirmation | b13c234 | open |

## Findings of 2026-11-01 (fixed in 4b7adb2 on feature/ui; F-1 on feature/echo)

| ID | Finding | Fix |
|----|---------|-----|
| F-1 | The guide requests the binding while its source is still pending; the wizard offers approved sources only | Guide: dave approves the source first |
| F-2 | A side a closed `ANY` request left undecided shows `AWAITING` | Shows "not needed" |
| F-4 | A break_glass-only user lands on a viewer error after signing in and after a change | Lands on the form; a confirmation after a change; the error points to Break glass |
| F-5 | Ratify (and approve) decide one side per submit, easy to miss | "All my sides" first when distinct approvers are not required |
| F-6 | The banner lists an inline source's break-glass change, whose buttons lead nowhere | Banner lists open binding changes only |
| F-7 | Banner buttons are red on red | Outlined in white |
| F-8 | A reverted break-glass change still looks just `APPLIED` | `REVERTED` label, by whom, link to the revert |
| F-9 | An inline source retired after a manual revert names `system:break-glass-expiry` | Names whoever reverted the binding |
| F-10 | Form errors show at the top, not on the field | Form re-rendered in place, message on each field |
| F-11 | The pair check ran before the emergency fields | Emergency fields first, all together |
| F-12 | Reverted changes and inline sources counted against `max_open` | Only open changes count, inline sources with their binding |

Also seen on 2026-11-01/02: an unratified break-glass CREATE reverted by the sweeper at expiry, its inline source retired (INV-16, `echo-bg-x`).

## Findings of 2026-11-01/02 (fixed on feature/ui after 4b7adb2)

| ID | Finding | Decision |
|----|---------|----------|
| F-13 | The break-glass form shows every operation's fields; an UPDATE was sent as a CREATE by mistake | Only the chosen operation's fields are shown (CSS `:has()`, no request), and the button names it ("Revoke the binding now") |
| F-14 | The ratify comment looks like it belongs to Revert, which takes none | Revert requires a comment, stored and audited with the revert (`/revert` body `{"comment"}`, 422 without); the sweeper's reverts say "TTL expired" |
| F-15 | A sealed OpenBao makes ligo restart every 5s, each start auditing CONFIG_LOADED (15 in 90s) | SPIRE and the sealer are checked before CONFIG_LOADED (§8.2 step 2); the lab unit backs off from 5s to 5min |
| F-16 | Seen while fixing F-15: at startup, ligo waits without a deadline for an unreachable SPIRE agent socket, neither failing nor serving | `service.startup_timeout` (default 60s, 5s–10m): past it ligo exits, naming SPIRE or the sealer, and systemd restarts it (test: `TestServeStartupTimeout`) |

## Retests (after the fixes)

| ID | Retest | Status |
|----|--------|--------|
| R-1 | F-4: livia lands on Break glass after signing in; after a change, back on the form with a green confirmation | passed 2026-11-01 |
| R-2 | F-5, F-2, F-8, F-7: "All my sides" ratifies both sides at once; banner buttons outlined; a revert shows `REVERTED` | passed 2026-11-01 |
| R-3 | F-10, F-11: a short justification and a TTL of `1m` together: both fields marked, the pair never mentioned; a wrong password marks the password field | passed 2026-11-01 |
| R-4 | F-12, B-3 attempt 4: an emergency UPDATE of `echo-bg-svid` goes through, a second gives `break-glass-open` | passed 2026-11-01 |
| R-5 | F-9: after a manual revert of a binding with an inline source, the source's retirement names the reverter | passed 2026-11-01 |
| R-6 | F-13: switching the operation shows only its fields; the button says "Create/Update/Revoke the binding now" | passed 2026-11-06 |
| R-7 | F-14: Revert sits in its own card and needs a reason; the `REVERTED` line shows it in quotes; `ligo cr revert` needs `-m` | passed 2026-11-06 (the `REVERTED` line is on the `BREAK_GLASS` request, not on its `SYSTEM_REVERT`) |
| R-8 | F-15: with OpenBao sealed, restarting ligo audits no CONFIG_LOADED, and the restarts slow down | passed 2026-11-02 (0 entries in 90s; restarts 5s, 7s, 11s, 18s apart; one entry once unsealed) |

### E-1, E-2: the echo guide

Follow the guide in `.specs/ligo-echo-target.md` (on `feature/echo`): steps 1, 2b, 3 and 4 for `echo-svid-target` (E-1), then steps 1, 2a, 3 and 4 for `echo-local-target` (E-2). In 2b, set the binding name to `echo-bound-svid` at the review. U-1 to U-3 come up along the way:
- **U-1** (step 2b.6): the page shows its status only once, at the top, and that status turns `APPLIED` after dave's approval, without a reload.
- **U-2** (step 2b.4): "Request access" opens at "2. Access level", and the form has a Next button.
- **U-3** (step 2a): `cr list --awaiting-me` lists only `PENDING` requests. Run it again after the approvals: the list is empty.

### U-4: header logo and user menu

1. Every page's header shows the ligo symbol (no wordmark), and so does the sign-in card, left of "Sign in to ligo". The symbol has no background of its own: it blends into the page under **Appearance** light and dark alike.
2. Click the head icon at the top right. The menu shows the username, the full name from LDAP (`cn` in the lab: e.g. "Dave Approver"), the roles with their jurisdictions, **Appearance** and **Sign out**.
3. The menu closes when you click outside it or press Escape. **Sign out** returns you to the login page.
4. Sign in as `livia`: the roles include `break_glass on dc/corp-prod/*`.

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

### A-1: the Accounts page

Prerequisite: `test/lab/lab.sh serve test-accounts`, which leaves `ligo` installed with `governance.accounts`. Afterwards, run `reset` and `serve install` before any other scenario. Users: `kim` is the account administrator, `alan` an approver of `acme`.

1. As `alan`, open **Accounts**: `acme` only, and no register form. Its page shows the counts and no Retire.
2. As `kim`, register `umbrella`. The browser goes to its page.
3. Register `umbrella` again, then `a-b` with the browser's own check bypassed: the reason appears inside the form, and the form stays usable.
4. On `acme`, press Retire and confirm: `account-in-use` appears on the page, and `acme` stays `ACTIVE`.
5. On `umbrella`, press Retire. The dialog says the name can never be registered again. Cancel: nothing changes. Press it again and confirm: the status turns `RETIRED`, and Retire is gone.
6. Turn maintenance on: both buttons are disabled.
