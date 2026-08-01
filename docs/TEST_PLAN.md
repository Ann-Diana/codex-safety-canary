# Windows alpha test plan

Current candidate: `0.1.0-alpha.11`.

Run the launcher as a normal user.

## Test 1 – Configuration only

1. Choose option 2.
2. Confirm that the report opens in Notepad.
3. Confirm that no token or `auth.json` content appears.

## Test 2 – Execpolicy coverage

1. Choose option 3.
2. Confirm that every probe has a result or an explicit diagnostic.
3. If no `.rules` files exist, confirm that the report says `NO_RULES` rather than implying protection.

## Test 3 – Disposable sandbox probes

1. Choose option 4.
2. Read the displayed data path.
3. Confirm with `Y`.
4. Expected result:
   - inside-workspace deletion: `EXPECTED`;
   - all outside-workspace deletion probes: `PASS`.
5. Confirm that the text report opens.
6. Confirm that no real project path appears in the report.

## Test 4 – Elevated launch

1. Deliberately start the launcher once as Administrator.
2. Choose option 4.
3. Confirm that live probes are refused.
4. Close the elevated window and return to normal execution.

## Test 5 – Spaces and umlauts

Copy the tool to a path containing spaces and an umlaut, then repeat Test 3.


## Test 6 – Split Codex installation with matching version

When the active `codex.exe` is missing its sandbox helper but a same-version complete bundle exists:

1. Confirm that the launcher labels the active bundle as incomplete.
2. Confirm that it shows the exact matching complete bundle path.
3. Confirm that using the alternative bundle requires explicit approval.
4. Confirm that the report records the executable used.
5. Confirm that `PATH` and the installation directories remain unchanged.

## Test 7 – Sandbox smoke failure

If the selected sandbox executable cannot start its helper, confirm that:

- the smoke test fails;
- no deletion probes run;
- workspace deletion is reported as `NOT TESTED`;
- the boundary result is `TEST ERROR`, not `PASS`.


## Test 8 – Newer probe-eligible alternative executable

When the active CLI bundle is incomplete and only a newer probe-eligible executable exists:

1. Confirm that both active and alternative versions are shown.
2. Confirm that the alternative is offered only if its own sandbox command is `AVAILABLE`.
3. Confirm that explicit approval is required before using it.
4. Confirm that the harmless smoke test runs before deletion probes.
5. Confirm that the report states that the result applies only to the alternative bundle.
6. Confirm that the active PATH CLI remains labeled incomplete and unvalidated.
7. Confirm that no files, `PATH` entries, or Codex settings are changed.



## Standalone installation diagnostics

Use only synthetic or already-observed evidence. Do not copy helpers, modify `PATH`, repair Codex, or run extra live sandbox probes for this section.

1. Confirm classic bundles are still detected when helpers sit beside `codex.exe`.
2. Confirm standalone package evidence is detected under `%CODEX_HOME%\packages\standalone\current` and `%CODEX_HOME%\packages\standalone\releases\*`.
3. Confirm standalone helper resources are reported separately from active-launcher runtime proof.
4. Confirm helper-not-resolved startup errors produce `SANDBOX_SETUP_HELPER_NOT_RESOLVED` without running deletion probes.
5. Confirm only controlled evidence that binds `CreateProcessWithLogonW failed: 2` to the selected executable and `codex-command-runner.exe` produces `COMMAND_RUNNER_PROCESS_CREATION_FAILED`; unbound or mixed foreign text leaves helper resolution `NOT_TESTED`.
6. Confirm `codex doctor --json` output is treated as inventory only and cannot create a sandbox PASS.
7. Confirm version-mismatched standalone resources do not validate the active CLI.
8. Confirm `current` and its real release target are one logical package and that `current\bin\codex.exe` inherits the release version.
9. Confirm resource layout, helper resolution, runtime startup, and boundary status remain separate after both successful and failed smoke tests.
10. Confirm a complete but untested standalone layout suggests controlled runtime testing without `ACTIVE_CLI_BUNDLE_INCOMPLETE` or a reinstall instruction.
11. Confirm partial or missing standalone resources still produce the incomplete-layout recommendation, while actual runtime failures rely on their specific diagnostics.
12. Confirm a complete classic file layout remains `NOT_TESTED` for helper resolution and runtime startup until the smoke test succeeds.
13. Confirm a bound command-runner process-creation failure reports helper resolution `CONFIRMED`, runtime startup `FAILED`, and boundary `TEST ERROR` for the matching active or alternative executable, while mismatched-target evidence does not confirm helper resolution.
14. Confirm specific helper/runner diagnostics suppress `SANDBOX_SETUP_FAILED`, while an unclassified elevation error such as OS error 740 retains the generic setup diagnostic.
15. Confirm helper, runner, and generic setup failures observed during `codex sandbox --help` remain visible in configuration-only and declined assessments even without a separate sandbox-run object.
16. Confirm successful sandbox help alone leaves helper resolution and runtime startup `NOT_TESTED`.
17. Confirm inventory-derived runtime states agree across console, detailed TXT/JSON, and share-safe TXT/JSON, including doctor-OK/runtime-failed contradictions.
18. Confirm active-CLI and alternative tested-bundle runtime diagnostics retain separate target labels, and that Doctor evidence is compared only with the active CLI it assessed.
19. Confirm a same-version `MATCHING_COMPLETE_BUNDLE` is still reported as an alternative executable whose result does not validate the active PATH CLI.
20. Confirm a technically incomplete runtime matrix is `TEST ERROR / INCOMPLETE`, even when one or two individual methods succeed; only complete structured `3/3` evidence produces a boundary `PASS`.
21. Confirm recognized top-level execpolicy decisions and supported matched-rule structures are evaluated deterministically, while nested foreign values, contradictory fields, and unknown decisions produce `UNKNOWN_SCHEMA`.
22. Confirm `UNKNOWN_SCHEMA` appears in console, detailed reports, and share-safe reports without being counted as `NO_MATCH`, `OK`, or a sandbox-boundary result.
23. Confirm cleanup `COMPLETED` is required for boundary PASS; `FAILED`, `NOT_RUN`, missing, unknown, legacy-text-only, and contradictory cleanup evidence remain `TEST ERROR / INCOMPLETE`.
24. Confirm a controlled `CRITICAL_GAP` remains primary when cleanup is `FAILED`, while the cleanup failure remains visible as additional incomplete evidence.
25. Confirm console, detailed TXT/JSON, and share-safe TXT/JSON show the same structured cleanup status, and share-safe reports omit cleanup message text and local paths.
26. Confirm the explicit README screenshot/alt-text matrix contains all nine authoritative images exactly once, excludes the collage, and preserves the documented result semantics.
27. Confirm all 15 public PNGs have valid signatures, CRCs and terminal `IEND`, no trailing bytes, and no text, EXIF, XMP, ICC, C2PA/JUMBF, credential, username, or local-path metadata.
28. Confirm sandbox-only writes all four reports and opens the standard report dialog when inventory evidence makes live probes unavailable, without reporting a user decline.
## Boundary validity checks

- Confirm the live command explicitly requests the `:workspace` permission profile.
- Confirm the inside-workspace file is deleted as the positive control.
- Confirm each retained outside file follows a controlled attempted operation, successful same-method host calibration, matching target identity, the expected before/after file state, and supported structured denial evidence; generic or unrelated denial text and a retained file alone must remain `TEST_ERROR`.
- Confirm a malformed Node.js command is classified as `TEST_ERROR`, never `PASS`.
- Confirm the overall boundary cannot pass when the inside control fails.

- Confirm the host deletion preflight succeeds before sandbox commands run.


## Report consistency checks

- Verify PowerShell, cmd.exe, and Node.js host calibration status is identical in console, detailed TXT/JSON, and share-safe TXT/JSON output.
- Verify `\\?\\C:\\...` and `\\?\\UNC\\...` error targets match their canonical Windows paths without treating different targets as equal.
- Verify missing or mismatched PowerShell ErrorRecord targets are never replaced by the intended target and remain fail-closed without sufficient controlled-operation evidence.

1. Confirm that the detailed report has separate `ACTIVE CLI` and `TESTED BUNDLE` sections.
2. Confirm that an alternative-bundle pass leaves the active CLI boundary as `NOT TESTED`.
3. Confirm that `Execpolicy coverage: 0/6` is labeled as additional user-rule coverage only.
4. Confirm that `-support.txt` and `-support.json` are generated.
5. Confirm that the support report contains no username, full executable path, standalone resource path, project path, report/run path, rule file path, credential path, or raw configuration contents.
6. Confirm that menu option 6 opens the latest share-safe support report.
