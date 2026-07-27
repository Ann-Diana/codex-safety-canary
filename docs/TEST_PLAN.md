# Windows alpha test plan

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


## Test 8 – Newer complete alternative bundle

When the active CLI bundle is incomplete and only a newer complete bundle exists:

1. Confirm that both active and alternative versions are shown.
2. Confirm that the alternative is offered only if its own sandbox command is `AVAILABLE`.
3. Confirm that explicit approval is required before using it.
4. Confirm that the harmless smoke test runs before deletion probes.
5. Confirm that the report states that the result applies only to the alternative bundle.
6. Confirm that the active PATH CLI remains labeled incomplete and unvalidated.
7. Confirm that no files, `PATH` entries, or Codex settings are changed.


## Boundary validity checks

- Confirm the live command explicitly requests the `:workspace` permission profile.
- Confirm the inside-workspace file is deleted as the positive control.
- Confirm retained outside files include access-denial evidence.
- Confirm a malformed Node.js command is classified as `TEST_ERROR`, never `PASS`.
- Confirm the overall boundary cannot pass when the inside control fails.

- Confirm the host deletion preflight succeeds before sandbox commands run.


## Report consistency checks

1. Confirm that the detailed report has separate `ACTIVE CLI` and `TESTED BUNDLE` sections.
2. Confirm that an alternative-bundle pass leaves the active CLI boundary as `NOT TESTED`.
3. Confirm that `Execpolicy coverage: 0/6` is labeled as additional user-rule coverage only.
4. Confirm that `-support.txt` and `-support.json` are generated.
5. Confirm that the support report contains no username, full executable path, project path, credential path, or raw configuration contents.
6. Confirm that menu option 6 opens the latest share-safe support report.
