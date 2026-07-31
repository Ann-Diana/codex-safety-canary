# Changelog

## 0.1.0-alpha.11 – 2026-07-31

### Added

- Adds read-only discovery for standalone installations and complete alternative Codex bundles under the active `PATH` plus `%LOCALAPPDATA%\OpenAI\Codex\bin`, `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin`, `%CODEX_HOME%\packages\standalone\current`, and `%CODEX_HOME%\packages\standalone\releases\*`.
- Adds explicit Guided and Sandbox-only selection among deduplicated active, same-version, and newer probe-eligible executables while keeping the active PATH CLI recommended and never substituting an alternative silently.
- Adds target-scoped diagnostics for standalone resources, setup-helper resolution, command-runner process creation, runtime startup, Doctor contradictions, and sandbox-boundary evidence.

### Changed

- Separates resource layout, helper resolution, runtime startup, and boundary proof so file presence is never reported as runtime or protection evidence and complete but untested standalone resources do not trigger an unnecessary reinstall recommendation.
- Resolves launcher, standalone `current`, and release paths through realpaths, deduplicates aliases, preserves their source metadata, and derives the package version from the real release target.
- Keeps the active PATH CLI and every separately selected executable as independent diagnostic targets across console, TXT, JSON, and share-safe reports; same-version and newer alternative results apply only to the selected executable.
- Carries runtime failures observed during `codex sandbox --help` inventory into reports without treating a successful help command as a smoke, runtime, or boundary result; `codex doctor --json` remains non-blocking read-only evidence.
- Writes full Sandbox-only reports when live probes are unavailable, while keeping unavailable, explicitly declined, and intentionally unassessed outcomes distinct.

### Security

- Requires successful host preflight, successful per-method host calibration, smoke startup, clean completion, and an exact PowerShell, cmd.exe, and Node.js runtime matrix (`3/3`) before any boundary PASS; missing, contradictory, ambiguous, or incomplete evidence fails closed.
- Binds denial evidence to command start, attempted operation, independently reported target identity, before/after file state, error class, HResult, and native Windows error code instead of accepting generic access-denied text.
- Uses `System.IO.File.Delete` for the PowerShell boundary probe and accepts an outside denial only with a matching `System.UnauthorizedAccessException`, native Win32 error code `5`, or target-bound `PermissionDenied`; `InvalidArgument`, generic ErrorRecords, and message-only access-denied text cannot produce PASS.
- Hardens Windows target canonicalization for drive, UNC, and namespace paths and preserves the separate PowerShell `Remove-Item` execpolicy coverage check.
- Applies recursive final share-safe redaction, fail-closed handling of unknown quoted and unquoted Windows paths, and rejection of residual path fragments after spaces, commas, semicolons, apostrophes, or known-root placeholder replacement.
- Clarifies the share-safe badge, TXT footer, JSON notice, README, FAQ, and security guidance: local usernames, absolute paths, credential paths, and raw configuration contents are removed, while diagnostic version, installation, runtime, and security-status information is retained and must be reviewed before public sharing.
- Hardens the Alpha 11 candidate through adversarial regression tests and repeated read-only Codex Security scans, including fixes for incomplete-run PASS aggregation, denial evidence not bound to its operation and target, incomplete local-path redaction, ambiguous PowerShell error classification, and overbroad share-safe communication.
- Removes misleading boundary part-pass terminology: only a complete structured runtime matrix (`3/3`) can produce PASS, while incomplete technical evidence is `TEST ERROR / INCOMPLETE` and a declined assessment remains `PARTIAL` with boundary `NOT TESTED`.
- Requires controlled evidence that binds the selected executable, runtime stage, and command-runner component before `CreateProcessWithLogonW` failures can confirm helper resolution; unbound or mixed diagnostic text remains fail-closed.
- Parses execpolicy JSON through recognized aggregate fields and explicit matched-rule structures, computes supported rule fallbacks deterministically, and exposes unknown or contradictory schemas as `UNKNOWN_SCHEMA` without treating them as `OK`, `NO_MATCH`, or sandbox-boundary evidence.
- Gives a confirmed controlled outside-file deletion priority over additional incomplete or failed sibling probes, while retaining those probe errors as separate report evidence instead of obscuring the boundary gap.
- Clarifies that an outside denial requires the complete method-specific structured evidence chain; generic access-denied text and a merely retained file are not proof of sandbox protection.
- Evaluates cleanup success from explicit structured state rather than free message text; missing, failed, not-run, legacy-only, unknown, or contradictory cleanup evidence blocks boundary PASS.
- Includes all nine Alpha 11 workflow screenshots in the README with result-oriented alternative text, including explicit selected-executable scope for alternative-bundle evidence.
- Removes unnecessary C2PA/JUMBF provenance metadata from the public hero while preserving its dimensions and decoded pixels.

### Validation

- Validated the Windows sandbox boundary against the separately selected `codex-cli 0.146.0-alpha.3.1` executable with successful host preflight, PowerShell/cmd.exe/Node.js host calibration, smoke startup, and complete runtime coverage (`3/3`). The retained PowerShell outside file produced `System.UnauthorizedAccessException`, HResult `-2147024891`, and native Win32 error code `5`; cmd.exe passed its outside check, and Node.js produced the expected `EPERM` denial.

### Known limitations

- The recorded boundary PASS applies only to the tested alternative `codex-cli 0.146.0-alpha.3.1` executable. It does not validate the active PATH CLI `codex-cli 0.145.0`, whose boundary remained `NOT TESTED`.
- Share-safe reports intentionally retain diagnostic version, installation, runtime, and security-status information. They reduce disclosure risk but are not anonymity guarantees and must be reviewed before public sharing.

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
- Reports incomplete or inconclusive runtime matrices without treating successful individual methods as a boundary verdict.

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
