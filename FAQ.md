# FAQ

## Does the Canary delete real files?

No. Live probes affect only files created under `%LOCALAPPDATA%\CodexSafetyCanary\runs`. The tool never asks for a project path.

## Does it use Codex tokens or call a model?

No. The Canary uses local CLI diagnostics such as `codex execpolicy check` and direct sandbox commands.

## Why does the inside-workspace test delete its file?

Because the built-in `:workspace` permission profile is intended to allow changes inside the selected workspace. The important boundary test is whether the same runtime is denied outside that workspace.

## Does a restrictive execpolicy rule prevent every deletion?

No. Execpolicy rules control commands that request to run outside the sandbox. They are not a backup and do not make a writable workspace read-only.

## Why are live tests blocked when the launcher is elevated?

Administrator execution could change the behavior being measured and encourages an unsafe operating habit. The result should reflect a normal user session.

## What should I do if Windows blocks the downloaded ZIP?

Right-click the downloaded ZIP, open **Properties**, select **Unblock** / **Zulassen** if shown, apply the change, and extract the ZIP again.

## Where are reports stored?

Under `%LOCALAPPDATA%\CodexSafetyCanary\reports`.

## Does the tool read auth.json?

No. It reports only whether the file exists. Authentication data is never opened or copied.

## Does the Canary run codex doctor?

No. The Canary skips `codex doctor` in Configuration-only, Execpolicy-only, Guided, and Sandbox-only. There is no Doctor consent question or executable Doctor path. Reports use `NOT_RUN` when the CLI is available and `UNAVAILABLE` when it is not. A skipped Doctor is not an error, warning, or protection result, and the Canary makes no Doctor-derived claim about authentication, runtime, Git, terminal, app or session inventory, network access, or updates.

## Are project-local rules tested?

No. The disposable workspace is intentionally not a trusted real project. The Canary tests user-level `.rules` files under `%CODEX_HOME%\rules` and labels that scope explicitly.

## Why does an execpolicy probe show `NO_MATCH`?

Codex CLI can return `{"matchedRules":[]}` when no loaded rule matches the tested command. This is not a parser failure. It means the user-level rule files did not provide restrictive coverage for that exact command shape. Sandbox enforcement remains a separate layer.

## Why does the Canary mention a Codex desktop runtime?

The Canary itself runs on Node.js. The Windows launcher normally uses Node.js from `PATH`. If that is unavailable, it can use a compatible `node.exe` from a recognized Codex desktop runtime cache when such a cache is present and executable.

This fallback belongs to the Codex desktop runtime environment; it does not mean that the native Codex CLI generally requires or bundles Node.js. It also does not imply that `npm` or a system-wide Node.js installation is available.

## Why does the Canary say that the active CLI bundle is incomplete?

The Canary distinguishes two layouts. In a classic layout, the required Windows sandbox helper and command-runner executables sit beside `codex.exe`. In a standalone layout, matching helpers live under the package's `codex-resources` directory instead. A complete standalone resource layout is not reported as an incomplete bundle merely because runtime resolution has not yet been tested; resource presence, helper resolution, runtime startup, and boundary proof remain separate states.

## What happens when another probe-eligible executable is found?

An alternative executable discovered by Guided or Sandbox-only must be explicitly selected and bound to one exact filesystem object before the Canary may run its `--version` command. The active PATH CLI remains the recommended default. Alternative executables are first discovered and deduplicated only through filesystem evidence. Before selection, a path- or package-derived version is labeled as metadata, while the executable version and sandbox status remain unconfirmed. Configuration-only and Execpolicy-only never show a selection and never start an alternative executable. The selected alternative's version output must be parseable and must agree with package metadata when such metadata exists; otherwise diagnostics stop before the Canary runs `sandbox --help` on it. A separate confirmation is still required before the Canary may run a startup smoke command that neither deletes files nor calls a model, or any deletion probe, through the selected alternative.

Any result from an executable other than the active PATH CLI applies only to that alternative executable, even when both executables report the same Codex version. It does **not** prove that the incomplete active CLI found through `PATH` is protected. A newer alternative additionally carries a version-mismatch warning. The Canary never copies files, alters `PATH`, or modifies Codex.

## Why is there a smoke test before the deletion probes?

A sandbox command can exist while its helper is missing or unresolvable. The smoke test first starts the selected Codex executable with a startup smoke command that neither deletes files nor calls a model; the command invokes `cmd.exe /c echo`. If setup fails, no deletion commands are attempted and the report records a setup error.

## Does the Canary search all of my disk for Codex executables?

No. It checks the active `PATH` command plus the known roots `%LOCALAPPDATA%\OpenAI\Codex\bin`, `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin`, `%CODEX_HOME%\packages\standalone\current`, and `%CODEX_HOME%\packages\standalone\releases\*`.


## Why is a newer probe-eligible executable offered instead of silently used?

A split installation can leave an incomplete active CLI beside a newer probe-eligible executable installed by the Codex app. Silently substituting versions would make the report misleading. The Canary therefore performs only filesystem inventory first. Guided or Sandbox-only asks for an exact executable selection before starting that alternative for version and sandbox-syntax diagnostics, then labels every later result as alternative-bundle evidence.


## Why does the Canary need an inside-workspace deletion probe?

It is the positive control for `workspace-write`. If the sandbox blocks all writes everywhere, outside files will remain but the boundary has not actually been distinguished. The Canary therefore reports `PASS` only when the inside deletion succeeds and the outside deletions are specifically denied.

## Can a command failure count as sandbox protection?

Not by itself. An outside `PASS` requires a controlled deletion command that started and actually attempted the operation, successful host calibration for the same method, a pre-existing expected outside file that remained afterward, unambiguous matching target identity, and supported structured denial evidence. Generic or unrelated access-denied text, a merely retained file, syntax or argument errors, wrapper or network failures, missing commands, timeouts, and other ambiguous evidence are `TEST_ERROR`, not sandbox protection. A successful individual method also does not replace the complete structured PowerShell, cmd.exe, and Node.js matrix (`3/3`) required for a boundary `PASS`.


## Why are PowerShell, cmd.exe, and Node.js each tested twice?

A retained outside file is meaningful only if the same runtime can delete its matching inside-workspace control file. Pairing the probes prevents a broken or over-restrictive runtime from being mistaken for successful boundary protection.


## What does `Execpolicy: NOT RUN` mean?

`Execpolicy: NOT RUN` means that no Execpolicy decisions were checked in that run. Execpolicy is additional user-rule coverage outside the boundary result. This state does not change the Windows sandbox result and is not a boundary score.

## Why can an execpolicy rule match without proving the executable path?

`codex execpolicy check` classifies the command tokens supplied to the checker; it does not execute them. An absolute-path rule can therefore fail to match a bare command name, while a bare-name rule can match without proving which executable a later shell invocation resolves. The Canary reports rule-path binding, observed host resolution, and execution binding separately. Host lookup is diagnostic only, and execution binding remains `NOT_PROVEN` unless controlled execution evidence exists. None of these execpolicy states is a sandbox-boundary result.

## Why does the repository include upstream regression fixtures?

Relevant Codex CLI failures are preserved as versioned, synthetic, offline fixtures so their evidence boundaries remain testable after the live environment changes. A fixture may contain a synthetic historical Doctor state solely to prove that such evidence cannot replace runtime or boundary proof; the current Canary does not execute Doctor. Resource presence remains separate from runtime and boundary proof, and policy matching remains separate from execution-path binding. A fixture is a regression contract, not evidence that the current local CLI still has the upstream defect.

## Why are the active CLI and tested bundle reported separately?

A split installation can leave the `codex.exe` resolved through `PATH` incomplete while another complete local bundle exists. A successful test of the alternative bundle applies only to that exact executable and version. The active CLI remains `NOT TESTED` until its own bundle is complete and tested.

## What should I do when the active CLI bundle is incomplete?

First check which layout the report identified. For an incomplete classic layout or a partial or missing standalone resource layout, update or reinstall Codex through the official distribution channel, then rerun the Canary from a new non-administrator PowerShell session. If the standalone resource layout is complete but helper resolution and runtime startup are `NOT_TESTED`, run the controlled preflight or optional live probes instead; resource presence alone is not runtime proof, but it is not a reason to reinstall. For an actual helper or runtime failure, follow the specific diagnostic. Never copy helper executables between versions manually.

## Which report should I attach to a public support issue?

Use the automatically generated `-support.txt` report. It removes local usernames, absolute local paths, credential paths, and raw configuration contents while retaining diagnostic version, installation, runtime, and security-status information needed for support. “Share-safe” means risk-reduced, not anonymous or secret. Review it before posting because no automatic redaction can guarantee that every future diagnostic string is non-sensitive. The detailed report is intended for local diagnosis. Never attach `latest.json`: it is only a local management pointer and contains absolute paths to all four report artifacts.
