# FAQ

## Does the Canary delete real files?

No. Live probes affect only files created under `%LOCALAPPDATA%\CodexSafetyCanary\runs`. The tool never asks for a project path.

## Does it use Codex tokens or call a model?

No. The alpha uses local CLI diagnostics: `codex execpolicy check` and `codex sandbox -- <COMMAND>`.

## Why does the inside-workspace test delete its file?

Because the built-in `:workspace` permission profile is intended to allow changes inside the selected workspace. The important boundary test is whether the same runtime is denied outside that workspace.

## Does a restrictive execpolicy rule prevent every deletion?

No. Execpolicy rules control commands that request to run outside the sandbox. They are not a backup and do not make a writable workspace read-only.

## Why are live tests blocked when the launcher is elevated?

Administrator execution could change the behavior being measured and encourages an unsafe operating habit. The result should reflect a normal user session.

## Where are reports stored?

Under `%LOCALAPPDATA%\CodexSafetyCanary\reports`.

## Does the tool read auth.json?

No. It reports only whether the file exists. Authentication data is never opened or copied.

## Are project-local rules tested?

Not in the alpha. The disposable workspace is intentionally not a trusted real project. Version 0.1 tests user-level `.rules` files under `%CODEX_HOME%\rules` and labels that scope explicitly.

## Why does an execpolicy probe show `NO_MATCH`?

The current Codex CLI legitimately returns `{"matchedRules":[]}` when no loaded rule matches the tested command. This is not a parser failure. It means the user-level rule files did not provide restrictive coverage for that exact command shape. Sandbox enforcement remains a separate layer.

## Why does the Canary mention a bundled Node runtime?

The Windows launcher can use the Node executable bundled inside Codex when `node` is not installed in `PATH`. That is sufficient to run the Canary, but it does not imply that `npm` or a normal system-wide Node.js installation is available.


## Why does the Canary say that the active CLI bundle is incomplete?

The Canary distinguishes two layouts. In a classic layout, the required Windows sandbox helper and command-runner executables sit beside `codex.exe`. In a standalone layout, matching helpers live under the package's `codex-resources` directory instead. A complete standalone resource layout is not reported as an incomplete bundle merely because runtime resolution has not yet been tested; resource presence, helper resolution, runtime startup, and boundary proof remain separate states.

## What happens when another probe-eligible executable is found?

The active PATH CLI remains the recommended default. If multiple probe-eligible local executables exist, the Canary shows a numbered choice with each source, version, exact path, resource layout, and sandbox status. A same-version or newer alternative must be selected explicitly, and the selected executable runs a harmless sandbox smoke test before any deletion probe.

Any result from an executable other than the active PATH CLI applies only to that alternative executable, even when both executables report the same Codex version. It does **not** prove that the incomplete active CLI found through `PATH` is protected. A newer alternative additionally carries a version-mismatch warning. The Canary never copies files, alters `PATH`, or modifies Codex.

## Why is there a smoke test before the deletion probes?

A sandbox command can exist while its helper is missing or unresolvable. The smoke test runs a harmless `echo` command first. If setup fails, no deletion commands are attempted and the report records a setup error.

## Does the Canary search all of my disk for Codex executables?

No. It checks the active `PATH` command plus the known roots `%LOCALAPPDATA%\OpenAI\Codex\bin`, `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin`, `%CODEX_HOME%\packages\standalone\current`, and `%CODEX_HOME%\packages\standalone\releases\*`.


## Why is a newer probe-eligible executable offered instead of silently used?

A split installation can leave an incomplete active CLI beside a newer probe-eligible executable installed by the Codex app. Silently substituting versions would make the report misleading. The Canary therefore asks first and labels the result as an alternative-bundle test.


## Why does the Canary need an inside-workspace deletion probe?

It is the positive control for `workspace-write`. If the sandbox blocks all writes everywhere, outside files will remain but the boundary has not actually been distinguished. The Canary therefore reports `PASS` only when the inside deletion succeeds and the outside deletions are specifically denied.

## Can a command failure count as sandbox protection?

Not by itself. An outside `PASS` requires a controlled deletion command that started and actually attempted the operation, successful host calibration for the same method, a pre-existing expected outside file that remained afterward, unambiguous matching target identity, and supported structured denial evidence. Generic or unrelated access-denied text, a merely retained file, syntax or argument errors, wrapper or network failures, missing commands, timeouts, and other ambiguous evidence are `TEST_ERROR`, not sandbox protection. A successful individual method also does not replace the complete structured PowerShell, cmd.exe, and Node.js matrix (`3/3`) required for a boundary `PASS`.


## Why are PowerShell, cmd.exe, and Node.js each tested twice?

A retained outside file is meaningful only if the same runtime can delete its matching inside-workspace control file. Pairing the probes prevents a broken or over-restrictive runtime from being mistaken for successful boundary protection.


## What does `Execpolicy coverage: 0/6` mean?

None of the six tested command forms matched a restrictive user-level execpolicy rule. This is additional rule coverage only. It does not mean that the Windows sandbox failed, and it is not the sandbox boundary score.

## Why are the active CLI and tested bundle reported separately?

A split installation can leave the `codex.exe` resolved through `PATH` incomplete while another complete local bundle exists. A successful test of the alternative bundle applies only to that exact executable and version. The active CLI remains `NOT TESTED` until its own bundle is complete and tested.

## What should I do when the active CLI bundle is incomplete?

First check which layout the report identified. For an incomplete classic layout or a partial or missing standalone resource layout, update or reinstall Codex through the official distribution channel, then rerun the Canary from a new non-administrator PowerShell session. If the standalone resource layout is complete but helper resolution and runtime startup are `NOT_TESTED`, run the controlled preflight or optional live probes instead; resource presence alone is not runtime proof, but it is not a reason to reinstall. For an actual helper or runtime failure, follow the specific diagnostic. Never copy helper executables between versions manually.

## Which report should I attach to a public support issue?

Use the automatically generated `-support.txt` report. It removes local usernames, absolute local paths, credential paths, and raw configuration contents while retaining diagnostic version, installation, runtime, and security-status information needed for support. “Share-safe” means risk-reduced, not anonymous or secret. Review it before posting because no automatic redaction can guarantee that every future diagnostic string is non-sensitive. The detailed report is intended for local diagnosis.
