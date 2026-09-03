# Codex Safety Canary

<p align="center">
  <img src="docs/assets/codex-safety-canary-hero.png" alt="Yellow canary beside a wooden sandbox frame" width="760">
</p>

Codex Safety Canary is a Windows-first local diagnostic for one specific Codex CLI installation. It keeps configuration, execpolicy, runtime, and filesystem-boundary evidence separate and can, with explicit consent, run a disposable sandbox assessment.

This is alpha software. Its results apply only to the tested setup and do not certify that a computer is secure. The Canary is not a command blocker, repair mechanism, backup system, or malware scanner.

Unofficial project. Not affiliated with, endorsed by, or supported by OpenAI.

## What does it check?

The non-live inventory identifies the active CLI, its installation and resource layout, the supported sandbox command shape, selected safety-relevant Codex settings, and user-level rule files. It checks only whether `auth.json` exists; it never reads or prints credential contents. The Canary does not start `codex doctor`.

Execpolicy checks classify common command forms against detected user-level rules. A rule match, path binding, and later execution binding are reported as separate facts. Execpolicy coverage is additional rule evidence and is not a sandbox-boundary result.

With explicit consent, the Windows sandbox assessment uses only synthetic disposable files. It verifies host-side controls, starts the selected CLI with a non-deleting, non-model smoke command, and then compares matched inside- and outside-workspace deletion probes through PowerShell, `cmd.exe`, and Node.js. Cleanup is part of the recorded result.

## What does it explicitly not check?

The Canary never opens, scans, modifies, or deletes real project files. It does not call a model, consume model tokens, alter `PATH`, copy helper executables, change Codex configuration or rules, repair an installation, or silently substitute another executable.

A sandbox result does not establish the behavior of commands approved through `require_escalated`, nor does it prove which host or credential context such an execution would receive. It also does not validate every command form, the desktop app, an IDE extension, or the general security of the computer.

## Requirements and quick start

Use a normal, non-administrator Windows session. The launcher needs Node.js 18 or newer through `PATH` or a compatible Node.js runtime from a recognized Codex desktop runtime cache. Node.js 22 or 24 is recommended. A full assessment also needs an active Codex CLI callable as `codex`.

1. Download the release ZIP from the [GitHub Releases page](https://github.com/Ann-Diana/codex-safety-canary/releases).
2. Extract the ZIP. If Windows blocks the downloaded file, follow the [ZIP help in the FAQ](FAQ.md#what-should-i-do-if-windows-blocks-the-downloaded-zip).
3. Double-click `codex-safety-canary.cmd`.

For a first review, choose the safe guided assessment. Read every displayed path and diagnostic target before consenting to optional live probes. Live probes proceed only when the detected sandbox command and syntax contract are explicitly supported.

## Assessment modes

- **Guided assessment** combines inventory and user-rule checks, then offers the optional disposable sandbox assessment.
- **Configuration-only** records installation, resource, sandbox-command, and selected configuration facts without sandbox live probes.
- **Execpolicy-only** checks user-level command classifications without running the submitted commands or sandbox live probes.
- **Sandbox-only** performs the disposable Windows boundary workflow after the required gates and explicit consent.

The active PATH CLI is the default. Alternative executables remain filesystem inventory until Guided or Sandbox-only presents one for explicit selection and binds that choice to its exact filesystem identity. An alternative starts only after that explicit selection, and its evidence validates only that executable, never the active PATH CLI.

## Understanding results

An overall boundary `PASS` requires a complete and internally consistent disposable run. Each supported runtime must delete its inside-workspace control and produce target-bound denial evidence for its outside-workspace control. Required startup, identity, calibration, process-start, and cleanup evidence must also be complete.

`CRITICAL_GAP` means a controlled synthetic file outside the disposable workspace was deleted. `TEST ERROR / INCOMPLETE` means the evidence cannot support a boundary conclusion. `NOT TESTED` means no boundary verdict was produced. `PARTIAL` describes assessment-flow completion, such as a deliberate decline, and never establishes boundary protection.

Every result is limited to the Codex version, executable and installation, configuration, permission profile, and environment actually tested. Re-run the Canary after any relevant change.

## Security, privacy, and further documentation

Reports are written outside projects under `%LOCALAPPDATA%\CodexSafetyCanary`. Detailed reports can contain local paths and are intended for local diagnosis. Separate share-safe reports are designed to remove defined path and configuration categories while retaining useful diagnostic version, installation, runtime, and security-status information. Reports open only when selected from the report dialog or menu.

Share-safe output reduces disclosure risk but guarantees neither anonymity nor secrecy. Review it manually before public sharing. Never publish `latest.json`, credential files, tokens, or unreviewed detailed reports.

Further documentation:

- [Frequently asked questions](FAQ.md)
- [Security policy and evidence boundaries](SECURITY.md)
- [Changelog and release links](CHANGELOG.md)
- [Repeatable Windows test plan](docs/TEST_PLAN.md)

MIT License. See [LICENSE](LICENSE).
