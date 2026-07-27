# Changelog

## 0.1.0-alpha.10 – 2026-07-25

- Keep Notepad and File Explorer GUI windows visible instead of launching them with `windowsHide: true`.
- Preserve the completed assessment output and require an explicit `O` or `F` action before opening report files.
- Use accurate “open request sent” wording because a spawned process does not prove that a GUI window became visible.
- Adds `BOUNDARY_ASSESSMENT_DECLINED` for explicitly declined live-probe prompts and still writes reports for those paths.
- Reports declined sandbox-only live probes with `NOT RUN` runtime, runtime-pair, and execpolicy coverage instead of ambiguous numeric coverage.
- Removes the product-reachable synthetic test mode from the CLI entry point.
- Moves CLI test doubles into injected test fixtures instead of runtime environment switches.
- Preserves already executed guided execpolicy results when later live probes are declined.
- Replaces regex-based selected TOML parsing and dynamic username substitution with bounded parsers and literal case-insensitive replacement.
- Redacts report-scoped local paths and sandbox cleanup messages from share-safe reports.
- Uses neutral redaction placeholders that do not trigger false-positive AppData path checks.

## 0.1.0-alpha.9 – 2026-07-25

### Added

- Adds structured assessment modes and diagnosis recommendations to detailed, support, JSON, and console output.
- Distinguishes intentionally unassessed sandbox boundaries from inconclusive or failed boundary checks.
- Represents skipped execpolicy coverage as `NOT RUN` instead of an ambiguous `0/0`.

### Changed

- Uses asynchronous, error-aware report opening for Notepad and Explorer without claiming success before process start.
- Clarifies `:workspace` permission-profile wording in console and detailed reports.
- Keeps local review inputs and local diff artifacts out of release and source-control inputs.

## 0.1.0-alpha.8 – 2026-07-25

### Added

- Separates the active CLI assessment from the exact bundle used for live probes.
- Adds plain-language interpretation and concrete next steps for split installations.
- Creates share-safe TXT and JSON support reports without usernames, executable paths, project paths, credential paths, or raw configuration contents.
- Adds a menu option for opening the latest share-safe support report.

### Changed

- Labels execpolicy `x/y` as additional user-rule coverage rather than a sandbox boundary score.
- Writes final reports after disposable-run cleanup so cleanup status is consistent across detailed and support reports.

## 0.1.0-alpha.7 – 2026-07-24

### Changed

- Uses the current `codex sandbox` permission-profile interface: `--permission-profile :workspace --cd <workspace>`.
- Tests PowerShell, `cmd.exe`, and Node.js as matched inside/outside runtime pairs.
- Reports a full pass only when every tested runtime can delete inside the workspace and is denied outside it.
- Reports a partial pass when at least one runtime pair proves the boundary but another runtime remains inconclusive.

### Fixed

- Recognizes localized Windows denial text such as `Zugriff auf den Pfad wurde verweigert`.
- Stops treating a global `--sandbox workspace-write` flag as sufficient configuration for the `codex sandbox` developer command.

## 0.1.0-alpha.6 – 2026-07-24

### Fixed

- Fixes the Node.js deletion probe so Windows paths are passed as an argument rather than embedded as invalid JavaScript.
- Requires actual access-denial evidence before a retained outside file can count as `PASS`.
- Treats unrelated command failures as `TEST_ERROR` rather than sandbox protection.
- Adds a normal-user deletion preflight before sandbox probes.
- Requires a successful inside-workspace control before reporting a boundary pass.

## 0.1.0-alpha.5 – Unreleased

### Added

- Detect complete local Codex bundles that are newer than an incomplete active CLI.
- Verify the alternative bundle's own sandbox command before offering it.
- Offer a newer complete bundle only with explicit consent and a precise version-mismatch warning.
- Record active and tested Codex versions separately in reports.
- Label successful or failed version-mismatched probes as alternative-bundle results rather than validation of the active CLI.

### Fixed

- Use the selected bundle's own `--full-auto` capability instead of inheriting that flag from the active CLI.
- Explain when a complete bundle exists but is older or not test-ready.

## 0.1.0-alpha.4

### Added

- Detect the exact `codex.exe` resolved through `PATH` and inspect whether its Windows sandbox helper files are present beside it.
- Search only the known local Codex installation roots for complete alternative bundles.
- Compare bundle versions and offer a same-version complete bundle for disposable live probes when the active CLI bundle is incomplete.
- Require explicit user consent before using an alternative bundle and record the exact executable in TXT and JSON reports.
- Run a harmless sandbox smoke test before any deletion probe.
- Distinguish sandbox command availability, runtime setup, boundary results, and inside-workspace behavior.

### Fixed

- Report workspace deletion as `NOT TESTED` when sandbox setup fails before a probe runs.
- Avoid repeating the same setup failure across all four deletion probes.
- Keep the active Codex installation unchanged: no files are copied and `PATH` is never modified.

## 0.1.0-alpha.3

### Fixed

- Detect the current general `codex sandbox -- <COMMAND>` interface instead of the obsolete `codex sandbox windows` form.
- Distinguish `AVAILABLE`, `AVAILABLE_BUT_SETUP_FAILED`, `UNSUPPORTED`, and `DETECTION_ERROR`.
- Allow live probes only when the detected sandbox state is exactly `AVAILABLE`.
- Use the general sandbox command syntax for every live probe.
- Keep the execpolicy explanation on one line.
- Include the detected sandbox state and diagnostic error in text reports.
- Remove internal review notes from the distributable package.

## 0.1.0-alpha.2

### Fixed

- Treat the documented `{"matchedRules":[]}` execpolicy response as a valid `NO_MATCH` result instead of `UNKNOWN_SCHEMA`.
- Treat a successful sandbox-help exit as availability rather than matching brittle wording in the help text.
- Use `--full-auto` for disposable sandbox probes when the installed CLI advertises that option.
- Distinguish a normal Node.js installation from the bundled Codex runtime and report whether `node` and `npm` are available through `PATH`.

## 0.1.0-alpha.1

### Added

- Single Windows launcher with a guided assessment.
- Safe inventory of selected Codex and Windows settings.
- User-level execpolicy coverage checks for common deletion forms.
- Optional deterministic Windows sandbox probes using only synthetic files.
- Clear distinction between writable-workspace behavior and workspace-boundary enforcement.
- External TXT and JSON reports under `%LOCALAPPDATA%\CodexSafetyCanary`.
- Refusal to run live probes with Administrator privileges.
- Automated tests for parsers, path safety, report semantics, and configuration redaction.
