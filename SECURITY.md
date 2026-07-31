# Security policy

## Supported version

This repository is currently an alpha. Only the newest published alpha is supported.

## Reporting a vulnerability

Do not publish a proof of concept that targets real user files. Report security issues privately through GitHub Security Advisories when available.

Include:

- Windows version;
- Codex CLI version;
- Node.js version;
- the generated `-support.txt` report after reviewing it;
- exact reproduction steps using synthetic files only.

Never include `auth.json`, API keys, access tokens, or full private configuration files.

## Threat model

The Canary is designed to test selected Codex controls with disposable files. It does not defend against a malicious process running with the same or higher user privileges. It does not install hooks, alter Codex configuration, or certify the host system.


## Alternative Codex executables

The Canary prefers a same-version probe-eligible executable found under a known `%LOCALAPPDATA%` installation root or the standalone package roots under `%CODEX_HOME%\packages\standalone`. A classic file layout can be probe-eligible when its helpers are beside `codex.exe`; a standalone executable can be probe-eligible when its matching required resource layout is complete. Probe eligibility is not proof that the launcher resolves the helpers, that the runtime starts, or that the sandbox boundary passes.

The report keeps resource layout, helper resolution, runtime startup, and boundary status separate. Any probe-eligible executable other than the active PATH CLI requires explicit consent and remains alternative evidence even when it has the same Codex version. If no same-version candidate exists, the Canary may offer a newer one after checking that executable's own sandbox command; the version mismatch is reported as additional information and never determines the result target.

The Canary never installs, copies, replaces, or permanently reconfigures Codex components. The exact executable and tested version used for a live probe are included in the report.


## Boundary verdict validity

A sandbox boundary PASS requires a fully completed disposable run: the host deletion preflight, method-specific PowerShell/cmd.exe/Node.js host calibrations, and sandbox smoke startup must pass; cleanup must have an explicit, internally consistent structured `COMPLETED` status; and each method must produce exactly one valid inside-workspace and one valid outside-workspace result. Missing, `NOT_RUN`, `FAILED`, unknown, legacy-text-only, or contradictory cleanup evidence produces `TEST ERROR / INCOMPLETE`, never a boundary PASS. Free cleanup message text is diagnostic only and cannot determine the verdict. Missing runtime pairs, failed calibrations, interrupted runs, invalid controls, and startup failures also fail closed. Successful individual methods inside an incomplete matrix do not establish boundary protection. `PARTIAL` describes assessment-flow completion only, while `NOT TESTED` means no boundary conclusion was produced. A technically complete run can still report a boundary gap when an outside object was deleted.

For retained outside files, access-denial evidence must be tied to the controlled deletion operation and its target. Windows namespace paths are canonicalized through literal prefix handling and `path.win32` before identity comparison. Node.js and PowerShell probes emit structured records containing command, operation, independently reported error target, file-state, and error details; the PowerShell runtime probe uses `System.IO.File.Delete` and never substitutes the intended target for missing exception evidence. A PowerShell denial requires an explicit `System.UnauthorizedAccessException`, native Windows error code 5, or a `PermissionDenied` ErrorRecord with an independently reported matching target. `InvalidArgument`, generic ErrorRecords, and access-denied message text cannot produce a PASS. Helper resolution is confirmed only by a successful selected-executable runtime step or by controlled evidence that binds the component, selected executable, and runtime stage; free-standing `CreateProcessWithLogonW` text is not sufficient. The separate execpolicy snapshot continues to test the `Remove-Item` command form. Execpolicy decisions are read only from recognized aggregate fields and explicit supported matched-rule structures, never from arbitrary recursive text or object values. Unknown or contradictory schemas remain visible as `UNKNOWN_SCHEMA` and cannot create or block a sandbox-boundary result. The cmd.exe probe uses a controlled single-target wrapper record. Static denial-text patterns may corroborate that structured cmd.exe evidence, but no text match can independently produce a PASS. Syntax, command-not-found, wrapper, network, mixed, and otherwise unrelated failures are fail-closed test errors.


## Report handling

Detailed reports can contain full local executable and configuration paths. Do not attach them publicly without manual review. The Canary creates a separate share-safe support report that removes local usernames, absolute local paths, credential paths, and raw configuration contents. It intentionally retains diagnostic version, installation, runtime, and security-status information needed for support, so “share-safe” is a risk-reduced representation rather than an anonymity or secrecy guarantee. Support fields use structured allowlists where possible. Known roots are replaced literally first; a character-based Windows-path scanner then redacts unknown drive and UNC paths. Quoted paths are removed through their closing quote. Because commas, semicolons, apostrophes, and spaces can all belong to valid unquoted Windows path components, an unquoted path is removed fail-closed through the end of its free-text line or a controlled hard separator. Placeholder suffixes follow the same rule. Host-preflight errors and all other nested support fields pass through a recursive final redaction step immediately before TXT and JSON output. The outputs are rejected if an absolute Windows or UNC path or any residual backslash path fragment remains. Automatic redaction is a risk-reduction measure, not an absolute guarantee; manually review every support report before public sharing.
