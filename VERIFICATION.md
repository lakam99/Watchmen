# Watchmen verification — October 28, 2026

The Windows x64 build is `release/0.6.0/Watchmen-win32-x64/Watchmen.exe`. Keep its adjacent runtime files together.

## Version 0.6 validation

- Production React/TypeScript build and versioned self-contained native publish passed. All 47 unit tests pass, including streamed/chunked progress, completion after final response, stdin cancellation acknowledgement, silent-helper handling, job state during a pending mutation, exact IPv4/IPv6 complement boundaries, local exemptions, unknown-location choices and frozen country-only review options.
- Both source and packaged desktop rules workflows pass with the production manager and a simulated Windows transport. Added checks cover Canada/US country-only selection and acknowledgement, task counts, minimizing, navigating to Applications while pending, restoring, cancelling, completing, the active-mode banner and saved country-only state after app restart. Screenshots were inspected. This does not activate real geographic restrictions.
- The packaged real-collector monitor smoke test passes with 280 observed flows, grouping, search, inspector, privacy default, pause/resume, JSON export, minimum width and no renderer exceptions. The smoke harness uses its own Chromium test profile to run alongside the existing elevated app. Package/source and native hashes match; the archive excludes working-directory credentials, profiles and captures.
- The real October 2026 public DB-IP dataset was reused to prepare Canada/US-only policies: 76,573 ranges / 153,146 filters with unknown public destinations blocked and local networks exempt, prepared in about 1.2 seconds. Allowing unknown locations produces 76,574 ranges. This measures preparation, not Windows enforcement time.
- The native builder now uses a 15-second transaction-start wait, skips deletion lookups for newly generated rule IDs, emits progress and heartbeats, checks cancellation between operations, and commits atomically. The JavaScript helper has no five-minute total-operation cutoff; a silent helper is bounded and reported as needing state verification.
- A read-only check could not verify this machine's existing large v0.5 region policies through Windows; saved enabled flags are not treated as proof of enforcement. Existing user rules were preserved. The user-authorized administrator scoped test ran at 21:05 America/Toronto and failed with Windows error 0x80320012 (FWP_E_TIMEOUT while acquiring the filtering transaction lock). Another Watchmen rule change was active during that attempt. A retry queued behind the shared Watchmen mutation mutex, then ran after that mutex was released; it also returned 0x80320012 and exited at 21:20. The shared-mutex retry prevents this test from competing with Watchmen rule changes, but it cannot clear a Windows filtering transaction lock held elsewhere. Neither attempt verifies enforcement, the bulk benchmark or successful test-filter cleanup. Both test launchers exited. The test code accesses only its separate test sublayer and private loopback port; it does not modify production rule records. No global country-only policy was activated and no reboot was performed.

Evidence: `test-results/rules-smoke.json`, `rules-smoke-packaged.json`, `packaged-smoke.json`, `build-manifest-v0.6.0.json`, `background-rule-task.png`, `country-only-active.png`, and `country-only-dataset-smoke.json`, and `policy-scoped-smoke-v0.6.0.json` / `policy-scoped-smoke-v0.6.0.log` (failed serialized retry), with the original attempt retained as `policy-scoped-smoke-v0.6.0-attempt1.json` / `.log`. Earlier v0.5 enforcement evidence below is historical and does not certify this updated binary.

## Version 0.5 validation

- TypeScript/React production build and self-contained .NET collector publish passed. Collector output is versioned under `native/bin/0.5.0`, allowing a running earlier collector to remain untouched.
- 41 unit tests cover the retained monitor, profiles, alerts, AI credentials and packets, plus trusted-flow rule derivation, frozen previews, executable/endpoint scope, administrator gating, concurrent operations, error refresh, country selection and IPv4/IPv6 parsing, country-cache validation, and the exact dated region ranges applied after review.
- The real elevated enforcement suite passed executable blocking and app/remote-IP/TCP-port blocking against controlled probe executables. A fresh helper process observed the persistent rules; unblock restored connectivity. The test removed its own policy records and preserved prior Watchmen rules.
- The same native filter builder passed a scoped loopback test: the selected executable connected over IPv4 and IPv6 while a second executable was blocked. TCP and echoed UDP were verified. Country-style IPv4/IPv6 range filters blocked both executables; removing the ranges restored access. A previously established TCP echo connection stopped delivering after policy commit.
- The scoped tests constrain filters to loopback and one private test port. No system-wide only-app mode or real geographic block was activated during verification. The operating system was not rebooted; reboot persistence uses the documented persistent filter and sublayer flags.
- Country data was downloaded over HTTPS from DB-IP's October 2026 release and parsed locally. Country/continent selection preparation was checked with the Vatican, United States and Europe. Large country/continent enforcement was not activated. The final additional administrator rerun for recovery enumeration and a synthetic bulk-filter benchmark was canceled at Windows elevation; those added paths were compiled/inspected, not runtime verified.
- Desktop workflow tests run the production JavaScript rule manager and IPC contract with a simulated Windows transport. They cover non-admin review without mutation, main-table app block, nested-table endpoint block, independent overlapping rules, direct unblock, only-app acknowledgement/banner/restore, continent and country selection, dated rule evidence, restart persistence, unblock-all UI, minimum width and renderer errors. They do not substitute for the separate real enforcement checks above.
- Recovery launchers are packaged beside the app. Their automatic policy-removal path has not been invoked against this final build; the normal per-rule unblock path was verified by the elevated suite.
- Chromium disk caches are isolated per instance; GPU shader disk caching is disabled. The stable encryption profile remains in place, and a real Windows encryption save/restart/decrypt/removal check passed after this fix. Existing monitor/profile/insight/packet desktop regressions are retained. OpenRouter inference is mocked; no real user API token or paid inference was used. Packet contents are never included in AI requests.

## Local evidence

Evidence lives in ignored `test-results/`:

- `firewall-live-smoke.json` and `firewall-live-smoke.log`: real native enforcement, persistence, scoped IPv4/IPv6 TCP/UDP, existing-connection blocking and cleanup.
- `rules-smoke-packaged.json`: desktop rule workflows with a simulated Windows transport.
- `table-blocking-dark.png`, `only-app-review-dark.png`, `network-rules-dark.png`: desktop screenshots using named synthetic fixtures.
- `region-dataset-smoke.json`: public monthly country-data download/parse check, with counts only.
- `packaged-smoke.json`, `features-smoke-packaged.json`, `profile-smoke-packaged.json`, `inspection-smoke-packaged.json`: retained desktop regression results.
- `collector-smoke.json`: standard Windows collector check. Earlier `elevated-smoke.log` and `packet-live-smoke.json` retain administrator ETW accounting and live packet checks from version 0.4.
- `build-manifest-v0.5.0.json`: final hashes and package exclusion audit.

These are focused checks, not certification of all Windows versions, corporate policies, third-party drivers or long-running workloads. See README for scope, persistence, data provenance and recovery instructions.

