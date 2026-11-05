# ligo acceptance and invariant matrix

This file is the index of §11.2 and of the invariants of §4: where each one is tested, at what level, and what is still missing. Tests live next to the code they test; this matrix replaces the `test/acceptance` directory (§11.1 rule 3, §11.2). Update it in the same commit as a test that changes a row.

**How it was made (chunk 10.5a, 2026-11-04).** Every row was classified from the test's name and doc comment, the scenario's tags in the code, and searches for its specific error codes and audit actions. Test bodies were not read beyond those search hits, so a `Covered` row can still hide a missing clause, and a `Gap` or a missing clause means "not found by these searches". Chunk 10.5b read the bodies of the rows it touched; the rows it did not touch stand as classified.

## Verdicts and levels

- **Covered:** every clause of the row has a test. **Partial:** some clauses do, and the note says which do not. **Gap:** nothing tests it.
- **L**, lab e2e: `ligo serve` on the lab, over its APIs (`lab.sh serve test*`). **P**, lab tests with real services: plugins, Transit, SPIRE or LDAP (tag `lab`). **I**, integration: `ligo`'s services in process, on a real PostgreSQL, usually with fake plugins (tag `integration`); it runs in CI and, on the lab's PostgreSQL over TLS, with `lab.sh test`. **U**, unit: no database, CI only. **B**, browser: headless Chrome on the UI's real headers, without a database.

## Summary

| | Rows | Covered | Partial | Gap | Covered at L or P | Covered only at U or B |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Scenarios (§11.2) | 92 | 92 | 0 | 0 | 19 | 15 |
| Invariants (§4) | 26 | 25 | 1 | 0 | 4 | 4 |

## Lab rules (§11.1)

- **Rule 1, tenancies.** `TestServeTopologies` runs the four topologies of ADR-13 on the lab: cloud to cloud, data centre to data centre, cloud to data centre with an additional party, and data centre to cloud. Another account's source is refused. Limit: the tenancy's workload is minted by `lab.sh`, not registered by a registrar, and it reads its binding from ligo but not its credential from the store, because the store of zone `prod` does not trust `test.lab` tokens.
- **Shipped plugins.** `.specs/ligo-postgres-plugin.md` §9 and `.specs/ligo-vault-plugin.md` §9 list their acceptance rows, and `TestServeDynamicCredentials` runs `vault-dynamic` end to end. `SVID` mode on PostgreSQL is not offered in v0.1.0 (OI-4), and `vault.v1` accepts exact SPIFFE IDs only (OI-1, `TestSourceNotExact`).
- **Rule 3, faults.** `lab.sh serve test-faults` stops the secrets backend under a binding's sealing (AC-09), and PostgreSQL for 10 s under bindings being applied (`TestServeFaultDatabase`): every binding converges, and no replica restarts.

## Scenarios (§11.2)

| ID | Verdict | Level | Tests | Notes |
| :--- | :--- | :--- | :--- | :--- |
| AC-01 | Covered | P | TestLabApply | `internal/workflows`. Self-service scope on the real plugins. |
| AC-02 | Covered | U | TestAC02 |  |
| AC-03 | Covered | U | TestAC03, TestAppendixA5 |  |
| AC-04 | Covered | I | TestAC04AC05 |  |
| AC-05 | Covered | I | TestAC04AC05 |  |
| AC-05a | Covered | I | TestAC05 (bindings), TestApproveFailures |  |
| AC-05b | Covered | I | TestAC05 (bindings) |  |
| AC-05c | Covered | I | TestAC05c |  |
| AC-06 | Covered | I | TestAC06, TestRefresh | Checked on `v_active_bindings`, which the resolver reads, with one workflow; no workload holds a session across r2. |
| AC-07 | Covered | I | TestUpdate, TestBusy |  |
| AC-07a | Covered | I | TestBusy |  |
| AC-08 | Covered | I+P | TestAC08, TestLabTransit | A real SIGKILL of a child process; the Transit path separately on the lab. |
| AC-09 | Covered | L+I | TestServeFaultTransitDown, TestServeFaultTransitBack, TestAC09, TestTransitUnavailable | `lab.sh serve test-faults` stops the real backend, OpenBao and Vault. |
| AC-10 | Covered | L+I | TestServeLDAPStageTwoFails, TestAC10 | The real `openldap.v1` plugin and directory on the lab, fake plugins in TestAC10. |
| AC-11 | Covered | I | TestAC11 |  |
| AC-12 | Covered | L | TestServeE2ERestarted, TestRefresh, TestDelete |  |
| AC-13 | Covered | I | TestOutputRefused |  |
| AC-14 | Covered | L+P | TestServeE2EApply, TestLabTargetPostgres, TestPlatforms |  |
| AC-15 | Covered | P | TestLabPluginRefusals, TestManagerStartRefusals |  |
| AC-16 | Covered | U | TestAuthentication (workloadhttp) |  |
| AC-17 | Covered | I | TestSessionLifetime |  |
| AC-18 | Covered | I | TestAC18 |  |
| AC-19 | Covered | I | TestAC19 | The crash is simulated by a committed row with no workflow. |
| AC-20 | Covered | I+P | TestAC20 (workflows), TestLabTargetPostgres | The plugin and the workflow are tested apart: `derived_principal_name` is unique, so ligo cannot create the collision itself. |
| AC-21 | Covered | I | TestConcurrentDecisions, TestDeclineAndWithdraw |  |
| AC-22 | Covered | I | TestConcurrentDecisions |  |
| AC-23 | Covered | I | TestAC23 | The plugin call is held open and every row is locked `NOWAIT` from it; a mutation holding the request row made the test fail. |
| AC-24 | Covered | I | TestINV14 |  |
| AC-25 | Covered | I+U | TestAC25, TestConfigLoaded, TestLoosening |  |
| AC-26 | Covered | L | TestServeHAMaintenance, TestReconcileLimits |  |
| AC-27 | Covered | I | TestAC27 |  |
| AC-28 | Covered | I | TestAC28 |  |
| AC-29 | Covered | U+I | TestRules, TestINV14 |  |
| AC-30 | Covered | I | TestAC30 |  |
| AC-31 | Covered | L+I | TestServeWebhookFile, TestAC31 |  |
| AC-32 | Covered | I | TestAC32, TestWarnBreakGlass |  |
| AC-33 | Covered | I | TestAC33, TestBreakGlass |  |
| AC-34 | Covered | I+P | TestAC34, TestLabBreakGlass |  |
| AC-35 | Covered | I | TestAC35 |  |
| AC-36 | Covered | I | TestBreakGlassRefusals, TestBreakGlass |  |
| AC-37 | Covered | L | serve test-webhook, TestDelivery | 24h by aging rows with SQL. |
| AC-38 | Covered | I | TestAC32 |  |
| AC-38a | Covered | I | TestAC38a |  |
| AC-38b | Covered | I | TestBreakGlassRefusals |  |
| AC-38c | Covered | I | TestAC38c, TestRatifyWhileDeleting |  |
| AC-39 | Covered | U+I+B | TestThemeBrowser, TestLoadConventional, TestHandler, TestConfigLoaded | The layout, not the login page, is rendered in the browser; both use the same logo template. |
| AC-40 | Covered | U | TestLogoFile |  |
| AC-41 | Covered | U+B | TestThemeBrowser, TestLayout | Persistence: a new navigation and the cookie's one-year `Max-Age`; no real browser restart. |
| AC-42 | Covered | U+B | TestLogoSandboxBrowser, TestHandler | The same SVG without the CSP runs its script, as a control. |
| AC-43 | Covered | U | TestLoadRefuses |  |
| AC-44 | Covered | I | TestAC44 (bindings, governance) |  |
| AC-45 | Covered | U | TestAC45, TestAppendixD2Extraction |  |
| AC-46 | Covered | U | TestValidate (sources) |  |
| AC-47 | Covered | I | TestAC47 |  |
| AC-48 | Covered | I | TestAC48 |  |
| AC-49 | Covered | I | TestAC49, TestINV18 |  |
| AC-50 | Covered | L | TestServeHAConcurrentApproval, TestAC50 |  |
| AC-51 | Covered | I | TestAC51 (bindings, governance) |  |
| AC-52 | Covered | I | TestAC52 (bindings, changerequests) | Restart replaced by a changed policy in process. |
| AC-53 | Covered | I | TestRevoke |  |
| AC-54 | Covered | I+U | TestAC54, TestBuildSides |  |
| AC-55 | Covered | I+U | TestAC55, TestBreakGlassSides, TestRatifiableSides, TestRevertParty |  |
| AC-56 | Covered | U | TestAC56 |  |
| AC-57 | Covered | I | TestScopes, TestINV08 |  |
| AC-58 | Covered | I | TestAC58, TestNamesAndInterconnects, TestDowngrade |  |
| AC-59 | Covered | I | TestAC59 |  |
| AC-60 | Covered | I | TestAC60 |  |
| AC-61 | Covered | I | TestAC61, TestRefresh |  |
| AC-62 | Covered | U | TestWideningWitness, TestAppendixD3 |  |
| AC-63 | Covered | I | TestAC63 |  |
| AC-64 | Covered | U+I | TestAC64, TestAC64Ports, TestFlowColumns |  |
| AC-65 | Covered | I | TestAC65 |  |
| AC-66 | Covered | I+L | TestAC66 (bindings, workflows), TestServeHARetireRace, TestAC65 |  |
| AC-67 | Covered | I | TestStates, TestINV22, TestPrivileges |  |
| AC-68 | Covered | I | TestINV23, binding-exists in bindings tests |  |
| AC-69 | Covered | I | TestDowngrade |  |
| AC-70 | Covered | I+L | TestAC70, TestRevoke, TestAudited, TestServeWebhookFile |  |
| AC-71 | Covered | I+P | TestAC71, TestLabExpiry | Clock control by editing `expires_at`. |
| AC-72 | Covered | I | TestAC72 |  |
| AC-73 | Covered | L | TestServeE2EWorkload, TestGetFlows |  |
| AC-74 | Covered | I | TestInlineSource, TestSweepRequests, TestWizard |  |
| AC-75 | Covered | I | TestAC32 |  |
| AC-76 | Covered | I | TestAC76Backlog, TestAC76, TestDB |  |
| AC-77 | Covered | L | TestServeHARetireRace |  |
| AC-78 | Covered | I+P | TestAC78, TestPlatforms, TestAC05 | Stated with the fake plugin's refusal; the real one's `PRIVILEGE_OUT_OF_BOUNDS` is in `ligo-plugin-postgres`. |
| AC-79 | Covered | I | TestTargetsAPI |  |
| AC-81 | Covered | U | TestAppendixD3, TestAC81BruteForce |  |
| AC-82 | Covered | B | TestAlteredFragmentBrowser, TestBrowser | The altered fragment comes from a test route, not a proxy: the browser cannot tell them apart. |
| AC-83 | Covered | U+B | TestErrorsBrowser, TestAlertAndRedirect |  |
| AC-84 | Covered | I+B | TestPollingBrowser, TestPages | No real 70 s wait: the browser's timeout is read as 90 s, and htmx is shown to enforce that setting with a shorter one. |
| AC-85 | Covered | U+B+tool | TestStorageBrowser, TestInheritedTargetsBrowser, TestVendored, `make htmx-check` | `make htmx-check` downloads the pinned htmx from npm, so it runs on the release path (§11.1 rule 4), not in CI. |
| AC-86 | Covered | I | TestAC86 (bindings, workflows), TestINV08 | The restart is a changed platform in the rules; startup does not read the prefix. |

## Invariants (§4)

| ID | Verdict | Level | Tests | Notes |
| :--- | :--- | :--- | :--- | :--- |
| INV-01 | Covered | U | TestINV01, TestRefresh |  |
| INV-02 | Covered | I | TestINV02, TestApply |  |
| INV-03 | Covered | I+U+L | TestAC08 (canary), TestLogsRedacted, TestServeTraceFile, TestServeWebhookFile, `serve_scan_secrets` | After `lab.sh serve test`, the passwords the e2e read from the store are searched for in a `pg_dump` of `ligo_serve`, DBOS checkpoints included, and in every replica's journal. |
| INV-04 | Covered | I | TestDelete |  |
| INV-05 | Covered | I | TestApply |  |
| INV-06 | Covered | I | TestFenced, TestMarkStep |  |
| INV-07 | Partial | I+P+U | TestTargetLocal, TestForeign, TestCleanup (postgres), TestCleanup (vault), TestLabTargetPostgres, TestLabStoreVault, TestLabIdentityOpenLDAP | Known limit for v0.1.0: each plugin is tested on its own; no conformance suite every plugin must pass. |
| INV-08 | Covered | I | TestINV08 |  |
| INV-09 | Covered | I | TestINV09, TestAC11 |  |
| INV-10 | Covered | P | TestLabPlugin, TestManagerStartRefusals |  |
| INV-11 | Covered | I | TestChain, TestINV11, TestINV11Routes (adminhttp, ui), TestAC09, TestRotate, TestAC18 | Every state-changing route of the API and the UI, read from the routers, must audit under its request ID or be listed with the reason it does not. |
| INV-12 | Covered | U | TestINV12, TestUISchemaRules, TestTemplates | Hostile values in every string of every page and fragment; plugin data never in `hx-*`. |
| INV-13 | Covered | I+U | TestOutputRefused, TestValidate (outputvalidation) |  |
| INV-14 | Covered | I | TestINV14, TestStructure |  |
| INV-15 | Covered | U | TestINV15 |  |
| INV-16 | Covered | P | TestLabBreakGlass, TestRevertFailed |  |
| INV-17 | Covered | U+I | TestINV17, TestAppendixD2Extraction, TestScopes, TestINV08 |  |
| INV-18 | Covered | I | TestINV18, TestAC49 |  |
| INV-19 | Covered | I | TestRecheck, TestAC52 |  |
| INV-20 | Covered | I | TestINV20, TestConsent |  |
| INV-21 | Covered | U+I | TestAppendixD3, TestNarrowingPrivileges, TestAC65 |  |
| INV-22 | Covered | I | TestINV22, TestServeHARetireRace |  |
| INV-23 | Covered | I | TestINV23 |  |
| INV-24 | Covered | U | TestAC64, TestWithin |  |
| INV-25 | Covered | P | TestINV25, TestAC71, TestLabExpiry |  |
| INV-26 | Covered | I | TestAC61, TestNarrowingPropagates |  |
