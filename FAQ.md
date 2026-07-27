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

The `codex.exe` found through `PATH` does not have the required Windows sandbox helper and command-runner executables beside it. The sandbox subcommand may still appear in help output even though its runtime setup cannot start.

## Is it safe to use a complete bundle found elsewhere?

The Canary prefers a complete bundle with the same Codex version. If none exists, it may offer a newer complete bundle only when that bundle's own `codex sandbox --help` check succeeds. It displays both versions and the exact executable path, requires consent, and runs a harmless sandbox smoke test before any deletion probe.

A newer-bundle result applies only to that alternative executable. It does **not** prove that the incomplete active CLI found through `PATH` is protected. The Canary never copies files, alters `PATH`, or modifies Codex.

## Why is there a smoke test before the deletion probes?

A sandbox command can exist while its helper is missing or unresolvable. The smoke test runs a harmless `echo` command first. If setup fails, no deletion commands are attempted and the report records a setup error.

## Does the Canary search all of my disk for Codex executables?

No. It searches only the active `PATH` command and the known local Codex installation roots under `%LOCALAPPDATA%\OpenAI\Codex\bin` and `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin`.


## Why is a newer complete bundle offered instead of silently used?

A split installation can leave an incomplete active CLI beside a newer complete bundle installed by the Codex app. Silently substituting versions would make the report misleading. The Canary therefore asks first and labels the result as an alternative-bundle test.


## Why does the Canary need an inside-workspace deletion probe?

It is the positive control for `workspace-write`. If the sandbox blocks all writes everywhere, outside files will remain but the boundary has not actually been distinguished. The Canary therefore reports `PASS` only when the inside deletion succeeds and the outside deletions are specifically denied.

## Can a command failure count as sandbox protection?

Only when the file remains and the result contains recognizable access-denial evidence. Syntax errors, missing programs, malformed commands, timeouts, and unrelated failures are reported as `TEST_ERROR`.


## Why are PowerShell, cmd.exe, and Node.js each tested twice?

A retained outside file is meaningful only if the same runtime can delete its matching inside-workspace control file. Pairing the probes prevents a broken or over-restrictive runtime from being mistaken for successful boundary protection.


## What does `Execpolicy coverage: 0/6` mean?

None of the six tested command forms matched a restrictive user-level execpolicy rule. This is additional rule coverage only. It does not mean that the Windows sandbox failed, and it is not the sandbox boundary score.

## Why are the active CLI and tested bundle reported separately?

A split installation can leave the `codex.exe` resolved through `PATH` incomplete while another complete local bundle exists. A successful test of the alternative bundle applies only to that exact executable and version. The active CLI remains `NOT TESTED` until its own bundle is complete and tested.

## What should I do when the active CLI bundle is incomplete?

Update or reinstall Codex using the official installer so `codex.exe`, `codex-windows-sandbox-setup.exe`, and `codex-command-runner.exe` are installed together. Then open a new non-administrator PowerShell session and rerun the Canary. Do not manually copy helper executables between different versions.

## Which report should I attach to a public support issue?

Use the automatically generated `-support.txt` report. It omits usernames, executable paths, project paths, credential paths, and raw configuration contents. Review it before posting because no automatic redaction can guarantee that every future diagnostic string is non-sensitive. The detailed report is intended for local diagnosis.
