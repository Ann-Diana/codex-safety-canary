# Windows acceptance test plan

Run the launcher as a normal user.

This document defines the repeatable manual acceptance procedure. Recorded outcomes belong in [version-specific evidence](evidence/) and are not repeated here. No checklist item is complete without its own evidence. Run live probes only when inventory reports the sandbox command state exactly as `AVAILABLE` and the syntax contract as `GENERIC_PERMISSION_PROFILE`. Stop without probing for every other state.

## Test 1 – Configuration only

1. Choose option 2.
2. Confirm that no Doctor question appears and the inventory reports `Codex doctor: NOT_RUN` when the active CLI is available or `UNAVAILABLE` when it is not.
3. At the report dialog, confirm that Notepad has not opened automatically. Press `O` to open the detailed text report, close Notepad after review, then press `M` to return to the menu.
4. Confirm that no token or `auth.json` content appears.

## Test 2 – Execpolicy coverage

1. Choose option 3.
2. Confirm that no Doctor question appears and the inventory reports `Codex doctor: NOT_RUN` when the active CLI is available or `UNAVAILABLE` when it is not.
3. Confirm that every execpolicy probe has a result or an explicit diagnostic.
4. If no `.rules` files exist, confirm that the report says `NO_RULES` rather than implying protection.
5. At the report dialog, press `O` only if the detailed report should be opened; press `M` to return to the menu.

## Test 3 – Disposable sandbox probes

1. Choose option 4.
2. Read the displayed data path.
3. Confirm with `Y`.
4. Expected result for a correctly protected reference configuration:
   - inside-workspace deletion: `EXPECTED`;
   - all outside-workspace deletion probes: `PASS`.
5. Treat `CRITICAL_GAP`, `TEST ERROR / INCOMPLETE`, and `NOT TESTED` as diagnostic outcomes that remain possible when the tested configuration or evidence does not support `PASS`.
6. At the report dialog, press `O` and confirm that the text report opens.
7. Confirm that no real project path appears in the report.

## Test 4 – Elevated launch

Do not conduct acceptance as Administrator. Confirm through the automated elevated-state regression that live probes are refused, and perform every manual step in a normal user session.

## Test 5 – Spaces and umlauts

Copy the tool to a path containing spaces and an umlaut, then repeat Test 3.


## Test 6 – Split Codex installation with matching version

When the active `codex.exe` is missing its sandbox helper but a same-version complete bundle exists:

1. Confirm that the launcher labels the active bundle as incomplete.
2. Confirm that it shows the exact matching complete bundle path.
3. Confirm that filesystem discovery alone leaves the alternative `NOT_SELECTED`, diagnostically `NOT_RUN`, and not tested.
4. Confirm that explicit selection is required before the alternative starts with `--version` or `sandbox --help`.
5. Confirm that the report records the executable used.
6. Confirm that `PATH` and the installation directories remain unchanged.

## Test 7 – Sandbox smoke failure

If the selected sandbox executable cannot start its helper, confirm that:

- the smoke test fails;
- no deletion probes run;
- workspace deletion is reported as `NOT TESTED`;
- the boundary result is `TEST ERROR`, not `PASS`.


## Test 8 – Newer probe-eligible alternative executable

When the active CLI bundle is incomplete and only a newer probe-eligible executable exists:

1. Confirm that the active version is execution-confirmed while any alternative version shown before selection is labeled as package/path metadata or unknown.
2. Confirm that the alternative remains `NOT_SELECTED`, diagnostically `NOT_RUN`, and not tested before the choice.
3. Confirm that explicit selection of the exact executable precedes its `--version` and `sandbox --help` diagnostics.
4. Confirm that an older, unavailable, syntax-incompatible, changed, identity-unproven, version-unparseable, or package-metadata-conflicting selection is rejected before live probes; invalid or conflicting version evidence must stop before `sandbox --help`.
5. Confirm that the non-deleting, non-model startup smoke command runs only after a separate live-probe confirmation and before deletion probes.
6. Confirm that the report states that the result applies only to the alternative bundle.
7. Confirm that the active PATH CLI remains labeled incomplete and unvalidated.
8. Confirm that no files, `PATH` entries, or Codex settings are changed.



## Standalone installation diagnostics

Use only synthetic or already-observed evidence. Do not copy helpers, modify `PATH`, repair Codex, or run extra live sandbox probes for this section.

1. Confirm classic bundles are still detected when helpers sit beside `codex.exe`.
2. Confirm standalone package evidence is detected under `%CODEX_HOME%\packages\standalone\current` and `%CODEX_HOME%\packages\standalone\releases\*`.
3. Confirm standalone helper resources are reported separately from active-launcher runtime proof.
4. Confirm helper-not-resolved startup errors produce `SANDBOX_SETUP_HELPER_NOT_RESOLVED` without running deletion probes.
5. Confirm only controlled evidence that binds `CreateProcessWithLogonW failed: 2` to the selected executable and `codex-command-runner.exe` produces `COMMAND_RUNNER_PROCESS_CREATION_FAILED`; unbound or mixed foreign text leaves helper resolution `NOT_TESTED`.
6. Confirm no production path contains or starts `codex doctor --json`; available inventory reports `NOT_RUN`, unavailable inventory reports `UNAVAILABLE`, and synthetic historical Doctor evidence cannot create a sandbox PASS.
7. Confirm version-mismatched standalone resources do not validate the active CLI.
8. Confirm `current` and its real release target are one logical package and that `current\bin\codex.exe` inherits the release version.
9. Confirm resource layout, helper resolution, runtime startup, and boundary status remain separate after both successful and failed smoke tests.
10. Confirm a complete but untested standalone layout suggests controlled runtime testing without `ACTIVE_CLI_BUNDLE_INCOMPLETE` or a reinstall instruction.
11. Confirm partial or missing standalone resources still produce the incomplete-layout recommendation, while actual runtime failures rely on their specific diagnostics.
12. Confirm a complete classic file layout remains `NOT_TESTED` for helper resolution and runtime startup until the smoke test succeeds.
13. Confirm a bound command-runner process-creation failure reports helper resolution `CONFIRMED`, runtime startup `FAILED`, and boundary `TEST ERROR` for the matching active or alternative executable, while mismatched-target evidence does not confirm helper resolution.
14. Confirm specific helper/runner diagnostics suppress `SANDBOX_SETUP_FAILED`, while an unclassified elevation error such as OS error 740 retains the generic setup diagnostic.
15. Confirm helper, runner, and generic setup failures observed during the active PATH CLI's `codex sandbox --help` remain visible in configuration-only and declined assessments even without a separate sandbox-run object; unselected alternatives contribute no such runtime evidence.
16. Confirm successful sandbox help alone leaves helper resolution and runtime startup `NOT_TESTED`.
17. Confirm inventory-derived runtime states agree across console, detailed TXT/JSON, and share-safe TXT/JSON, with Doctor `NOT_RUN` for an available active CLI or `UNAVAILABLE` otherwise and no Doctor-derived claims.
18. Confirm active-CLI and alternative tested-bundle runtime diagnostics retain separate target labels and remain independent of the skipped Doctor state.
19. Confirm a same-version `MATCHING_COMPLETE_BUNDLE` is still reported as an alternative executable whose result does not validate the active PATH CLI.
20. Confirm a technically incomplete runtime matrix is `TEST ERROR / INCOMPLETE`, even when one or two individual methods succeed; only complete structured `3/3` evidence produces a boundary `PASS`.
21. Confirm recognized top-level execpolicy decisions and supported matched-rule structures are evaluated deterministically and independently of order, with the strictest known explicit decision winning; nested foreign values, unknown decisions, and unsupported structures produce `UNKNOWN_SCHEMA`.
22. Confirm `UNKNOWN_SCHEMA` appears in console, detailed reports, and share-safe reports without being counted as `NO_MATCH`, `OK`, or a sandbox-boundary result.
23. Confirm cleanup `COMPLETED` is required for boundary PASS; `FAILED`, `NOT_RUN`, missing, unknown, legacy-text-only, and contradictory cleanup evidence remain `TEST ERROR / INCOMPLETE`.
24. Confirm a controlled `CRITICAL_GAP` remains primary when cleanup is `FAILED`, while the cleanup failure remains visible as additional incomplete evidence.
25. Confirm console, detailed TXT/JSON, and share-safe TXT/JSON show the same structured cleanup status, and share-safe reports omit cleanup message text and local paths.
26. Confirm release screenshots are referenced only by the corresponding version-specific evidence file, not by the README.
27. Confirm all public PNGs have valid signatures, CRCs and terminal `IEND`, no trailing bytes, and no text, EXIF, XMP, ICC, C2PA/JUMBF, credential, username, or local-path metadata.
28. Confirm Configuration-only and Execpolicy-only start only the active PATH CLI diagnostics and no alternative executable.
29. Confirm Guided and Sandbox-only start no unselected, rejected, cancelled, identity-unproven, or identity-changed alternative executable.
30. Confirm a selected alternative starts `--version` and `sandbox --help` only after the recorded selection event and remains separate from the later live-probe consent.
31. Confirm aliases to the active executable produce no second candidate run, while true copies and two same-version release directories remain separate unstarted candidates.
32. Confirm a filesystem-derived alternative version is never represented as execution-confirmed and that console, detailed TXT/JSON, and support TXT/JSON agree on discovery, identity, selection, diagnostic, and tested states.
33. Confirm realpath resolution without a stat-backed object identity remains unproven and cannot satisfy an explicit selection binding.
34. Confirm unparseable executed versions and versions that conflict with available package metadata stop after `--version`, before `sandbox --help`, and remain in separate metadata-derived and execution-confirmed report fields.
35. Confirm an identity failure before the first sandbox process leaves the alternative selected and diagnosed but not tested, with no populated `TESTED BUNDLE` summary in console, detailed, or share-safe reports.
36. Confirm sandbox-only writes all four reports and opens the standard report dialog when inventory evidence makes live probes unavailable, without reporting a user decline.

## Boundary validity checks

- Confirm the live command explicitly requests the `:workspace` permission profile.
- Confirm that all six per-probe Codex process-start markers are `CONFIRMED`, their derived boundary aggregate is `CONFIRMED`, and the separate smoke process-start marker is `CONFIRMED`. Missing, false, unknown, or contradictory evidence must produce `TEST ERROR / INCOMPLETE`.
- Confirm the inside-workspace file is deleted as the positive control.
- Confirm each retained outside file follows a controlled attempted operation, successful same-method host calibration, matching target identity, the expected before/after file state, and supported structured denial evidence; generic or unrelated denial text and a retained file alone must remain `TEST_ERROR`.
- Confirm a malformed Node.js command is classified as `TEST_ERROR`, never `PASS`.
- Confirm the overall boundary cannot pass when the inside control fails.

- Confirm the host deletion preflight succeeds before sandbox commands run.


## Report consistency checks

- Verify PowerShell, cmd.exe, and Node.js host calibration status is identical in console, detailed TXT/JSON, and share-safe TXT/JSON output.
- Verify `\\?\\C:\\...` and `\\?\\UNC\\...` error targets match their canonical Windows paths without treating different targets as equal.
- Verify missing or mismatched PowerShell ErrorRecord targets are never replaced by the intended target and remain fail-closed without sufficient controlled-operation evidence.
- Verify that all six per-probe process-start evidence values, the confirmed count, the derived boundary aggregate, the smoke status, and the separate smoke process-start evidence agree across console, detailed TXT/JSON, and share-safe TXT/JSON output. Missing or unknown evidence must remain NOT REPORTED or null and must never be rewritten as false.

1. Confirm that the detailed report has separate `ACTIVE CLI` and `TESTED BUNDLE` sections.
2. Confirm that an alternative-bundle pass leaves the active CLI boundary as `NOT TESTED`.
3. Confirm that `Execpolicy: NOT RUN (0/6 decisions checked)` is labeled as additional user-rule coverage outside the boundary result.
4. Confirm that `-support.txt` and `-support.json` are generated.
5. Confirm that the support report contains no username, full executable path, standalone resource path, project path, report/run path, rule file path, credential path, or raw configuration contents.
6. Confirm that menu option 6 opens the latest share-safe support report.
7. Confirm that exactly four report artifacts are written for each run and that `latest.json` is separately created or overwritten only as a local pointer containing their absolute paths. Never treat or share `latest.json` as share-safe.

## Manual Windows acceptance sequence

Perform this sequence only on a disposable normal-user Windows session after reviewing the committed candidate. Do not run as Administrator, do not point the Canary at a real project, and do not change `PATH`, `CODEX_HOME`, Codex configuration, rules, or installation files.

1. Record `git rev-parse HEAD`, `git status --short`, `node --version`, `codex --version`, `Get-Command codex | Format-List Source`, and the Windows version.
2. Run `npm test`, `npm run check`, and `git diff --check`; retain exact counts and exit codes.
3. Start `codex-safety-canary.cmd` from the committed repository as a normal user.
4. Run Configuration-only by entering `2`. No Doctor question or executable-selection question may appear. Confirm the active CLI, installation type, resource layout, sandbox command state, verified syntax contract, and state-appropriate Doctor status are distinct fields. The alternative executable list is inventory only in this mode: every entry must remain filesystem-only, identity proven or unproven, package-derived version or unknown, `NOT_SELECTED`, diagnostically `NOT_RUN`, not tested, and without any active-CLI or boundary conclusion. At the report dialog, use `O` to open the detailed report, `F` to locate it, or `M` to return to the menu; no report should open before one of those choices. Confirm no credential contents or real project paths appear.
5. Run Execpolicy-only by entering `3`. No Doctor or executable-selection question may appear. Confirm that only the active PATH CLI receives the six `execpolicy check` classifications and that command tokens after `--` are not executed. For every command form, capture the decision, rule-path binding, whether host resolution was observed, and the still-unproven execution binding. Confirm the state-appropriate Doctor status and all alternative entries remain `NOT_SELECTED`, diagnostically `NOT_RUN`, and not tested across console, detailed TXT/JSON, and support TXT/JSON. Use the same `O`/`F`/`M` report dialog to inspect the report and return to the menu.
6. Inspect the proposed live-probe location and selected executable. Continue only if the state is exactly `AVAILABLE`, the syntax contract is `GENERIC_PERMISSION_PROFILE`, the process is not elevated, every path is under the Canary disposable run root, and the selected executable is the intended target. Otherwise stop and record `NOT TESTED`.
7. If those gates hold and live testing has been separately approved, run Sandbox-only. Confirm the host deletion preflight and all three method-specific host calibrations complete first using only their synthetic control files. Then confirm the non-deleting, non-model startup smoke command succeeds before any paired sandbox deletion probe begins.
8. Confirm the subsequent PowerShell, cmd.exe, and Node.js inside/outside sandbox pairs are each complete. Accept an overall `PASS` only for a structured `3/3` matrix with target-bound outside denials and structured cleanup `COMPLETED`. Treat every missing, contradictory, failed, or partial technical record as `TEST ERROR / INCOMPLETE`.
9. If an alternative executable is selected, confirm every output names it as the tested bundle and leaves the active PATH CLI boundary `NOT TESTED`.
10. Compare console, detailed TXT/JSON, and support TXT/JSON for the active CLI, tested executable, versions, installation and resources, helper/runtime/smoke states, calibrations, matrix, cleanup, execpolicy, boundary verdict, and evidence limits.
11. Search both support files for the current username, profile directory, repository path, executable paths, run/report paths, credential filenames or paths, raw configuration values, and unredacted nested errors. Any hit blocks public sharing and acceptance.
12. Confirm the disposable run directory was removed only after structured cleanup completion. Do not manually delete ambiguous targets through the Canary.

## Screenshot and video capture checklist

Capture only real output from the accepted committed candidate. Never use synthetic output as release evidence or imply a live PASS before step 8 succeeds.

- Screenshot the main menu with version and normal-user context visible but no username or private path.
- Screenshot Configuration-only inventory showing the active CLI, alternative executable filesystem findings (if any), the state-appropriate Doctor status, sandbox command state, syntax contract, resource layout, helper resolution, runtime state, and evidence boundary. Each alternative must visibly remain `NOT_SELECTED`, diagnostically `NOT_RUN`, and not tested. Do not describe inventory findings as an executable choice, execution-confirmed version, sandbox state, or tested bundle.
- Screenshot execpolicy output showing at least one command form with decision, rule-path binding, host-resolution observation, and execution binding.
- Screenshot the pre-probe consent screen with disposable root and selected executable; redact local paths before publication.
- Screenshot smoke, host preflight, each of the three host calibrations, and the complete method matrix. If the outcome is not PASS, capture the actual diagnostic without relabeling it.
- Screenshot cleanup status and the final boundary verdict together.
- Screenshot the detailed report's separate ACTIVE CLI and TESTED BUNDLE sections.
- Screenshot the share-safe notice and both support formats after manual disclosure review.
- For video, record one uninterrupted normal-user flow from startup through report generation. Include the availability/syntax gate, explicit executable selection, consent, smoke, calibrations, matrix, cleanup, and final report. Pause or crop before any username or local path is exposed.
- Record the commit hash, Windows/Node/Codex versions, capture date, selected executable, and whether the result applies to the active CLI or an alternative in the accompanying notes.
