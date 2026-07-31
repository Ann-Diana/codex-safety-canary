import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { stdin as defaultInput, stdout as defaultOutput } from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  APP_NAME,
  APP_VERSION,
  ASSESSMENT_MODES,
  CLEANUP_STATES,
  createCleanupResult,
  describeAlternativeExecutableScope,
  deriveSandboxRuntimeObservation,
  formatDiagnosticRecommendationLines,
  formatExecpolicyCoverage,
  summarizeExecutableBundles,
} from './core.mjs';

const YES_ANSWERS = new Set(['y', 'yes', 'j', 'ja']);

function normalizeExistingFile(file) {
  if (!file) return { file: null, error: 'No file path was provided.' };
  const normalized = path.resolve(file);
  if (!fs.existsSync(normalized)) return { file: normalized, error: `File does not exist: ${normalized}` };
  return { file: normalized, error: null };
}

export function createCanaryCli(dependencies) {
  const {
    appRoot,
    platform = process.platform,
    input = defaultInput,
    output = defaultOutput,
    getInventory,
    runExecpolicyCoverage,
    runSandboxProbes,
    writeReport,
    getLatestReport,
    safeRemoveRun,
    launchDetachedProcess,
    clearEnabled = true,
  } = dependencies;
  const rl = readline.createInterface({ input, output });
  const writeLine = (value = '') => output.write(`${value}\n`);

  function clear() {
    if (clearEnabled && output.isTTY) output.write('\x1Bc');
  }

  function header(title = `${APP_NAME} for Windows`) {
    writeLine('='.repeat(64));
    writeLine(title);
    writeLine('='.repeat(64));
    writeLine();
  }

  async function pause(message = 'Press Enter to return to the menu...') {
    await rl.question(`\n${message}`);
  }

  async function openInNotepad(file) {
    const check = normalizeExistingFile(file);
    if (check.error) return { ok: false, file: check.file, error: check.error };
    return launchDetachedProcess('notepad.exe', [check.file], { windowsHide: false });
  }

  async function showFileInExplorer(file) {
    const check = normalizeExistingFile(file);
    if (check.error) return { ok: false, file: check.file, error: check.error };
    return launchDetachedProcess('explorer.exe', [`/select,${check.file}`], { windowsHide: false });
  }

  function printLaunchStatus(label, result) {
    if (result?.ok) writeLine(`${label} open request sent.`);
    else writeLine(`${label} could not be started: ${result?.error || 'unknown error'}`);
  }

  async function openFileDialog(title, file, options = {}) {
    const clearScreen = options.clearScreen !== false;
    const autoOpen = options.autoOpen === true;
    if (clearScreen) clear();
    header(title);
    const normalized = file ? path.resolve(file) : null;
    writeLine(`File:\n  ${normalized || '(none)'}`);
    let lastResult = null;
    if (autoOpen) {
      lastResult = await openInNotepad(normalized);
      printLaunchStatus('Notepad', lastResult);
    } else {
      writeLine('Choose O to open the file or F to show it in File Explorer.');
    }
    while (true) {
      writeLine('\n[O] Open or reopen in Notepad');
      writeLine('[F] Show the file in File Explorer');
      writeLine('[M] Return to menu');
      const answer = (await rl.question('Choose an option: ')).trim().toLowerCase();
      if (answer === 'm') return;
      if (answer === 'o') {
        lastResult = await openInNotepad(normalized);
        printLaunchStatus('Notepad', lastResult);
      } else if (answer === 'f') {
        lastResult = await showFileInExplorer(normalized);
        printLaunchStatus('File Explorer', lastResult);
      } else {
        writeLine('Unknown option.');
      }
    }
  }

  function printInventory(inventory, assessmentMode = ASSESSMENT_MODES.GUIDED) {
    const runtimeObservation = inventory.runtimeObservation || deriveSandboxRuntimeObservation(inventory, null);
    writeLine(`Windows:       ${inventory.release}`);
    writeLine(`Node.js:       ${inventory.nodeVersion} (${inventory.nodeRuntimeSource})`);
    writeLine(`node in PATH:  ${inventory.nodeInPath ? 'yes' : 'no'}`);
    writeLine(`npm in PATH:   ${inventory.npmInPath ? 'yes' : 'no'}`);
    writeLine(`Administrator: ${inventory.elevated ? 'yes – live tests will be blocked' : 'no'}`);
    writeLine(`Codex:         ${inventory.codexInstalled ? inventory.codexVersion : 'not found'}`);
    writeLine(`Active CLI:    ${inventory.activeCodexPath || 'not resolved'}`);
    writeLine(`Classic file layout: ${inventory.activeBundle?.complete ? 'complete' : 'incomplete'}`);
    writeLine(`Probe eligible: ${inventory.activeBundle?.probeEligible || inventory.sandboxHelperInPath ? 'yes' : 'no'}`);
    writeLine(`Resource layout: ${inventory.activeBundle?.resourceLayout || 'MISSING'}`);
    writeLine(`Helper resolution: ${inventory.activeBundle?.helperResolution || 'NOT_TESTED'}`);
    writeLine(`Runtime startup: ${inventory.activeBundle?.runtimeStartup || 'NOT_TESTED'}`);
    if (inventory.activeBundle?.missing?.length) writeLine(`Missing files: ${inventory.activeBundle.missing.join(', ')}`);
    const matchingBundleStatistics = summarizeExecutableBundles(inventory.matchingCompleteBundles || []);
    const newerBundleStatistics = summarizeExecutableBundles(inventory.newerCompleteBundles || []);
    writeLine(`Matching logical executables: ${matchingBundleStatistics.logicalExecutableCount}`);
    writeLine(`Matching discovered paths: ${matchingBundleStatistics.discoveredPathCount}`);
    writeLine(`Matching alias paths: ${matchingBundleStatistics.aliasPathCount}`);
    for (const executablePath of matchingBundleStatistics.discoveredPaths) writeLine(`  Matching path: ${executablePath}`);
    writeLine(`Newer logical executables: ${newerBundleStatistics.logicalExecutableCount}`);
    writeLine(`Newer discovered paths: ${newerBundleStatistics.discoveredPathCount}`);
    writeLine(`Newer alias paths: ${newerBundleStatistics.aliasPathCount}`);
    for (const executablePath of newerBundleStatistics.discoveredPaths) writeLine(`  Newer path: ${executablePath}`);
    if (inventory.newerCompleteBundles?.length) {
      writeLine(`Newer bundle version:     ${inventory.newerCompleteBundles[0].version}`);
    }
    writeLine(`CODEX_HOME:    ${inventory.codexHome}`);
    writeLine(`config.toml:   ${inventory.config.exists ? 'found' : 'not found'}`);
    writeLine(`User rules:    ${inventory.ruleFiles.length}`);
    const sandboxState = inventory.sandboxWindowsState || (inventory.sandboxWindowsAvailable ? 'AVAILABLE' : 'UNSUPPORTED');
    const sandboxSuffix = sandboxState === 'AVAILABLE' && inventory.sandboxFullAutoAvailable ? ' (--full-auto supported)' : '';
    writeLine(`Sandbox command syntax: ${sandboxState}${sandboxSuffix}`);
    writeLine(`Sandbox runtime:        ${runtimeObservation.sandboxRuntime}`);
    writeLine(`Assessment mode:        ${assessmentMode}`);
    if (sandboxState === 'AVAILABLE_BUT_SETUP_FAILED') {
      writeLine('Windows sandbox setup: command exists, but setup is currently not test-ready.');
    }
    if (inventory.config.warnings.length) {
      writeLine('\nConfiguration warnings');
      for (const warning of inventory.config.warnings) writeLine(`- ${warning}`);
    }
  }

  function printRuleResults(results) {
    writeLine('\nExecpolicy coverage');
    writeLine('-'.repeat(64));
    for (const item of results) {
      const status = item.decision ? item.decision.toUpperCase() : item.status;
      writeLine(`${status.padEnd(14)} ${item.label}`);
    }
    writeLine('\nNote: execpolicy rules govern commands that request execution outside the sandbox. They do not prevent deletion inside a writable workspace.');
    writeLine('The x/y count describes additional user-rule coverage only; it is not the sandbox boundary result.');
  }

  function printSandboxResults(result) {
    writeLine('\nWindows sandbox probes');
    writeLine('-'.repeat(64));
    if (result.error) writeLine(`Error: ${result.error}`);
    if (result.hostPreflight) writeLine(`Host deletion preflight: ${result.hostPreflight.passed ? 'PASS' : 'FAIL'}`);
    for (const calibration of result.hostCalibrations || []) {
      writeLine(`Host calibration ${calibration.label}: ${calibration.status}`);
      writeLine(`  operation ${calibration.operation || '(not recorded)'}, target identity ${calibration.targetIdentityStatus || 'NOT MATCHED'}`);
      writeLine(`  exception ${calibration.exceptionType || calibration.errorClass || '(none)'}, HResult/native ${calibration.errorHResult ?? '(none)'}/${calibration.nativeWin32ErrorCode ?? '(none)'}`);
    }
    if (result.permissionProfile) writeLine(`Permission profile: ${result.permissionProfile}`);
    for (const item of result.probes || []) {
      writeLine(`${item.assessment.padEnd(14)} ${item.label}`);
      writeLine(`               expected ${item.expected}, observed ${item.observed}`);
      writeLine(`               host calibration ${item.hostCalibrationStatus || 'FAIL'}, target identity ${item.targetIdentityStatus || 'NOT REPORTED'}`);
      writeLine(`               operation ${item.operation || '(not recorded)'}`);
      writeLine(`               exception ${item.exceptionType || item.errorClass || '(none)'}, HResult/native ${item.errorHResult ?? '(none)'}/${item.nativeWin32ErrorCode ?? '(none)'}`);
      writeLine(`               error ${item.errorCategory || '(none)'} / ${item.errorCode || '(none)'}`);
      writeLine(`               started ${item.commandStarted ? 'yes' : 'no'}, attempted ${item.operationAttempted ? 'yes' : 'no'}, unrelated failure ${item.unrelatedFailureDetected ? 'yes' : 'no'}`);
    }
    writeLine('\nInside-workspace deletion is expected under the :workspace permission profile.');
    writeLine('The critical check is whether synthetic files outside the workspace remain.');
  }

  function printConsolidatedResult(summary) {
    writeLine('\nResult by installation');
    writeLine('-'.repeat(64));
    writeLine(`Overall:            ${summary.overall}`);
    writeLine(`Sandbox runtime:    ${summary.sandboxRuntime}`);
    writeLine(`Sandbox boundary:   ${summary.boundary}`);
    writeLine(`Workspace deletion: ${summary.workspaceDeletion}`);
    writeLine(`Cleanup status:      ${summary.cleanup?.status || CLEANUP_STATES.NOT_RUN}`);
    writeLine(`Runtime pairs:      ${summary.methodCoverage}`);
    writeLine(`Execpolicy coverage: ${formatExecpolicyCoverage(summary.execpolicyCoverage)}`);
    writeLine('\nACTIVE CLI');
    writeLine(`  Version:           ${summary.activeCli?.version || '(unavailable)'}`);
    writeLine(`  File status:       ${summary.activeCli?.bundleStatus || 'UNKNOWN'}`);
    writeLine(`  Resource layout:   ${summary.activeCli?.resourceLayout || 'MISSING'}`);
    writeLine(`  Helper resolution: ${summary.activeCli?.helperResolution || 'NOT_TESTED'}`);
    writeLine(`  Runtime startup:   ${summary.activeCli?.runtimeStartup || 'NOT_TESTED'}`);
    writeLine(`  Boundary:          ${summary.activeCli?.boundaryStatus || 'NOT TESTED'}`);
    writeLine('TESTED BUNDLE');
    if (!summary.testedBundle) writeLine('  (not tested)');
    else {
      writeLine(`  Source:            ${summary.testedBundle.source}`);
      writeLine(`  Version:           ${summary.testedBundle.version || '(unavailable)'}`);
      writeLine(`  File status:       ${summary.testedBundle.bundleStatus || 'UNKNOWN'}`);
      writeLine(`  Resource layout:   ${summary.testedBundle.resourceLayout || 'MISSING'}`);
      writeLine(`  Helper resolution: ${summary.testedBundle.helperResolution || 'NOT_TESTED'}`);
      writeLine(`  Runtime startup:   ${summary.testedBundle.runtimeStartup || 'NOT_TESTED'}`);
      writeLine(`  Boundary:          ${summary.testedBundle.boundaryStatus}`);
      writeLine(`  Methods:           ${summary.testedBundle.methodCoverage}`);
      if (summary.testedBundle.scopeNote) writeLine(`  Scope:             ${summary.testedBundle.scopeNote}`);
    }
    if (summary.interpretation?.length) {
      writeLine('\nPlain-language interpretation');
      for (const line of summary.interpretation) writeLine(`- ${line}`);
    }
    if (summary.recommendations?.length) {
      writeLine('\nDiagnostic recommendations');
      for (const line of formatDiagnosticRecommendationLines(summary.recommendations)) writeLine(line);
    }
    if (summary.nextSteps?.length) {
      writeLine('\nRecommended next steps');
      for (const line of summary.nextSteps) writeLine(`- ${line}`);
    }
  }

  async function showReportAndOpenDialog(report) {
    writeLine(`\nDetailed text report: ${report.txtPath}`);
    writeLine(`Detailed JSON report: ${report.jsonPath}`);
    writeLine(`Share-safe support report: ${report.supportTxtPath}`);
    printConsolidatedResult(report.payload.summary);
    await openFileDialog('DETAILED REPORT', report.txtPath, { clearScreen: false, autoOpen: false });
  }

  async function chooseSandboxProbePlan(inventory) {
    const plan = inventory.sandboxProbePlan;
    if (!plan?.ready) {
      writeLine(`\nLive probes are unavailable: ${plan?.reason || 'no usable Codex sandbox executable was found.'}`);
      return null;
    }
    if (plan.requiresSelection && plan.candidates?.length > 1) {
      writeLine('\nMultiple probe-eligible Codex executables were found.');
      writeLine('The active PATH CLI is the recommended default. Choose the exact executable to test:');
      plan.candidates.forEach((candidate, index) => {
        const label = candidate.source === 'ACTIVE_CLI'
          ? 'Active PATH CLI (recommended)'
          : candidate.source === 'MATCHING_COMPLETE_BUNDLE'
            ? 'Separate same-version standalone executable'
            : 'Separate newer executable';
        writeLine(`\n[${index + 1}] ${label}: ${candidate.testedVersion || '(unknown version)'}`);
        writeLine(`    Source:          ${candidate.source}`);
        writeLine(`    Executable:      ${candidate.codexExe}`);
        writeLine(`    Resource layout: ${candidate.testedBundleMetadata?.resourceLayout || 'MISSING'}`);
        writeLine(`    Sandbox status:  ${candidate.sandboxState || 'UNKNOWN'}`);
        if (candidate.isAlternativeExecutable) {
          writeLine(`    Scope: ${candidate.scopeNote || describeAlternativeExecutableScope(candidate)}`);
          writeLine('    This result applies only to the selected executable and does not validate the active PATH CLI.');
        }
        if (candidate.versionMismatch) {
          writeLine(`    Version warning: active ${candidate.activeVersion || '(unknown)'}; selected ${candidate.testedVersion || '(unknown)'}.`);
        }
      });
      writeLine('\n[N] Skip live probes');
      while (true) {
        const answer = (await rl.question(`Choose a test executable [1-${plan.candidates.length}/N]: `)).trim().toLowerCase();
        if (answer === 'n') return { declined: true, source: null };
        const selectedIndex = Number(answer) - 1;
        if (Number.isInteger(selectedIndex) && selectedIndex >= 0 && selectedIndex < plan.candidates.length) {
          return plan.candidates[selectedIndex];
        }
        writeLine('Unknown option.');
      }
    }
    if (!plan.requiresConfirmation) return plan;

    writeLine('\nThe active Codex CLI bundle is incomplete.');
    if (plan.source === 'NEWER_COMPLETE_BUNDLE') {
      writeLine('A newer probe-eligible local Codex bundle was found:');
      writeLine(`  ${plan.codexExe}`);
      writeLine(`Active CLI version: ${plan.activeVersion || '(unknown)'}`);
      writeLine(`Test bundle version: ${plan.testedVersion || '(unknown)'}`);
      writeLine('IMPORTANT: This test will evaluate only the newer alternative bundle.');
      writeLine('It will not prove that the active CLI resolved through PATH is protected.');
    } else {
      writeLine('A probe-eligible local bundle with the same Codex version was found:');
      writeLine(`  ${plan.codexExe}`);
    }
    writeLine(describeAlternativeExecutableScope({
      versionMismatch: plan.versionMismatch === true,
      testedVersion: plan.testedVersion,
      activeVersion: plan.activeVersion,
    }));
    writeLine('The Canary can use this executable for this disposable test only.');
    writeLine('It will not change PATH, copy files, or modify the Codex installation.');
    const prompt = plan.source === 'NEWER_COMPLETE_BUNDLE'
      ? 'Test the newer probe-eligible bundle separately? [Y/N]: '
      : 'Use the matching probe-eligible bundle for live probes? [Y/N]: ';
    const answer = (await rl.question(prompt)).trim().toLowerCase();
    return YES_ANSWERS.has(answer) ? plan : { declined: true, source: plan.source };
  }

  async function runGuided() {
    clear();
    header('SAFE GUIDED ASSESSMENT');
    writeLine('This assessment never opens or modifies a real project.');
    writeLine('It reads only selected Codex settings and user-level rule files.');
    writeLine('Optional live probes use disposable synthetic files under:');
    writeLine(`  ${path.join(appRoot, 'runs')}`);
    writeLine('It does not call a model, consume Codex tokens, or require Git.');
    writeLine();

    const inventory = getInventory();
    printInventory(inventory, ASSESSMENT_MODES.GUIDED);
    if (!inventory.codexInstalled) {
      const report = writeReport({ inventory, rules: [], sandbox: null, assessmentMode: ASSESSMENT_MODES.GUIDED });
      writeLine(`\nCodex was not found. Configuration report saved to:\n  ${report.txtPath}`);
      await openFileDialog('DETAILED REPORT', report.txtPath, { clearScreen: false, autoOpen: false });
      return;
    }

    writeLine('\nStep 1 of 2 – test user-level execpolicy coverage');
    const rules = runExecpolicyCoverage(inventory.ruleFiles, { codexExe: inventory.activeCodexPath });
    printRuleResults(rules);

    let sandbox = null;
    let boundaryAssessmentDeclined = false;
    if (inventory.elevated) {
      writeLine('\nLive probes were skipped because this launcher is running as Administrator.');
      writeLine('Rerun it normally so the result reflects a normal user session.');
    } else {
      const probePlan = await chooseSandboxProbePlan(inventory);
      if (probePlan?.declined) {
        boundaryAssessmentDeclined = true;
        writeLine('Live probes skipped.');
      } else if (probePlan) {
        writeLine('\nStep 2 of 2 – optional live Windows sandbox probes');
        writeLine('A few tiny synthetic files will be created. No real project is used.');
        writeLine(`Sandbox executable for this test:\n  ${probePlan.codexExe || inventory.activeCodexPath}`);
        const answer = (await rl.question('Run the disposable live probes now? [Y/N]: ')).trim().toLowerCase();
        if (YES_ANSWERS.has(answer)) {
          sandbox = runSandboxProbes({
            appRoot,
            fullAuto: probePlan.fullAutoAvailable === true,
            codexExe: probePlan.codexExe,
            codexSource: probePlan.source,
            testedCodexVersion: probePlan.testedVersion,
            activeCodexVersion: probePlan.activeVersion,
            isAlternativeExecutable: probePlan.isAlternativeExecutable,
            versionMismatch: probePlan.versionMismatch,
            testedBundleMetadata: probePlan.testedBundleMetadata,
            scopeNote: probePlan.scopeNote,
            sandboxWindowsState: probePlan.sandboxState,
          });
          printSandboxResults(sandbox);
        } else {
          boundaryAssessmentDeclined = true;
          writeLine('Live probes skipped.');
        }
      }
    }

    if (sandbox?.layout?.runDir) {
      try {
        safeRemoveRun(sandbox.layout.runDir, appRoot);
        sandbox.cleanup = createCleanupResult(CLEANUP_STATES.COMPLETED, 'Disposable run folder removed before final reports were written.');
      } catch (error) {
        sandbox.cleanup = createCleanupResult(CLEANUP_STATES.FAILED, error.message);
        writeLine(`\nCleanup warning: ${error.message}`);
      }
    }
    const report = writeReport({ inventory, rules, sandbox, assessmentMode: sandbox ? ASSESSMENT_MODES.GUIDED : ASSESSMENT_MODES.GUIDED_LIVE_PROBES_SKIPPED, boundaryAssessmentDeclined });
    writeLine('\nAssessment complete.');
    writeLine(`Overall: ${report.payload.summary.overall}`);
    await showReportAndOpenDialog(report);
  }

  async function scanOnly() {
    clear();
    header('CONFIGURATION SCAN');
    const inventory = getInventory();
    printInventory(inventory, ASSESSMENT_MODES.CONFIGURATION_ONLY);
    const report = writeReport({ inventory, rules: [], sandbox: null, assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY });
    await showReportAndOpenDialog(report);
  }

  async function rulesOnly() {
    clear();
    header('EXECPOLICY COVERAGE TEST');
    const inventory = getInventory();
    printInventory(inventory, ASSESSMENT_MODES.EXECPOLICY_ONLY);
    const rules = inventory.codexInstalled ? runExecpolicyCoverage(inventory.ruleFiles, { codexExe: inventory.activeCodexPath }) : [];
    printRuleResults(rules);
    const report = writeReport({ inventory, rules, sandbox: null, assessmentMode: ASSESSMENT_MODES.EXECPOLICY_ONLY });
    await showReportAndOpenDialog(report);
  }

  async function sandboxOnly() {
    clear();
    header('DISPOSABLE WINDOWS SANDBOX TEST');
    const inventory = getInventory();
    printInventory(inventory, ASSESSMENT_MODES.SANDBOX_ONLY);
    if (!inventory.codexInstalled) {
      writeLine('\nCodex was not found.');
      await pause();
      return;
    }
    if (inventory.elevated) {
      writeLine('\nLive probes are blocked while running as Administrator.');
      writeLine('Close this window and start the launcher normally.');
      await pause();
      return;
    }
    const probePlan = await chooseSandboxProbePlan(inventory);
    if (probePlan?.declined) {
      const report = writeReport({ inventory, rules: [], sandbox: null, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY_LIVE_PROBES_SKIPPED, boundaryAssessmentDeclined: true });
      await showReportAndOpenDialog(report);
      return;
    }
    if (!probePlan) {
      const report = writeReport({
        inventory,
        rules: [],
        sandbox: null,
        assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY,
        boundaryAssessmentDeclined: false,
      });
      await showReportAndOpenDialog(report);
      return;
    }
    writeLine('\nThe test affects only synthetic files inside the Canary data directory.');
    writeLine(`Sandbox executable for this test:\n  ${probePlan.codexExe || inventory.activeCodexPath}`);
    const answer = (await rl.question('Continue? [Y/N]: ')).trim().toLowerCase();
    if (!YES_ANSWERS.has(answer)) {
      const report = writeReport({ inventory, rules: [], sandbox: null, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY_LIVE_PROBES_SKIPPED, boundaryAssessmentDeclined: true });
      await showReportAndOpenDialog(report);
      return;
    }
    const sandbox = runSandboxProbes({
      appRoot,
      fullAuto: probePlan.fullAutoAvailable === true,
      sandboxWindowsState: probePlan.sandboxState,
      codexExe: probePlan.codexExe,
      codexSource: probePlan.source,
      testedCodexVersion: probePlan.testedVersion,
      activeCodexVersion: probePlan.activeVersion,
      isAlternativeExecutable: probePlan.isAlternativeExecutable,
      versionMismatch: probePlan.versionMismatch,
      testedBundleMetadata: probePlan.testedBundleMetadata,
      scopeNote: probePlan.scopeNote,
    });
    printSandboxResults(sandbox);
    if (sandbox?.layout?.runDir) {
      try {
        safeRemoveRun(sandbox.layout.runDir, appRoot);
        sandbox.cleanup = createCleanupResult(CLEANUP_STATES.COMPLETED, 'Disposable run folder removed before final reports were written.');
      } catch (error) {
        sandbox.cleanup = createCleanupResult(CLEANUP_STATES.FAILED, error.message);
      }
    }
    const report = writeReport({ inventory, rules: [], sandbox, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
    await showReportAndOpenDialog(report);
  }

  async function openLatest() {
    const latest = getLatestReport(appRoot);
    if (!latest) {
      clear();
      header('LATEST REPORT');
      writeLine('No report has been created yet.');
      await pause();
    } else {
      await openFileDialog('LATEST REPORT', latest.txtPath, { autoOpen: true });
    }
  }

  async function openLatestSupport() {
    const latest = getLatestReport(appRoot);
    if (!latest?.supportTxtPath) {
      clear();
      header('LATEST SHARE-SAFE SUPPORT REPORT');
      writeLine('No share-safe support report has been created yet.');
      await pause();
    } else {
      await openFileDialog('LATEST SHARE-SAFE SUPPORT REPORT', latest.supportTxtPath, { autoOpen: true });
    }
  }

  async function openDocs() {
    const readme = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'README.md');
    await openFileDialog('README', readme, { autoOpen: true });
  }

  async function menu() {
    while (true) {
      clear();
      header(`${APP_NAME} for Windows – ${APP_VERSION}`);
      writeLine('[1] Run the safe guided assessment');
      writeLine('[2] Scan Codex configuration only');
      writeLine('[3] Test execpolicy rule coverage');
      writeLine('[4] Test Windows sandbox with disposable files');
      writeLine('[5] Open the latest report');
      writeLine('[6] Open the latest share-safe support report');
      writeLine('[7] Open README');
      writeLine('[0] Exit');
      writeLine();
      const choice = (await rl.question('Choose an option: ')).trim();
      if (choice === '1') await runGuided();
      else if (choice === '2') await scanOnly();
      else if (choice === '3') await rulesOnly();
      else if (choice === '4') await sandboxOnly();
      else if (choice === '5') await openLatest();
      else if (choice === '6') await openLatestSupport();
      else if (choice === '7') await openDocs();
      else if (choice === '0') break;
      else await pause('Unknown option. Press Enter...');
    }
  }

  async function run() {
    try {
      if (platform !== 'win32') {
        writeLine('Codex Safety Canary v0.1 is designed for native Windows.');
        return 2;
      }
      await menu();
      return 0;
    } finally {
      rl.close();
    }
  }

  return { run, menu, runGuided, sandboxOnly, scanOnly, rulesOnly };
}
