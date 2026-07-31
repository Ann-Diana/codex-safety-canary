import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { createCanaryCli } from '../lib/cli-flow.mjs';
import { buildSandboxRuntimeEvidence, deriveSandboxRuntimeObservation, getLatestReport, selectCodexProbePlan, writeReport } from '../lib/core.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function latestDetailJson(localAppData) {
  const reportsDir = path.join(localAppData, 'CodexSafetyCanary', 'reports');
  const files = fs.readdirSync(reportsDir)
    .filter((name) => name.endsWith('.json') && name !== 'latest.json' && !name.endsWith('-support.json'))
    .map((name) => path.join(reportsDir, name))
    .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
  assert.ok(files.length > 0, 'expected a detailed JSON report');
  return JSON.parse(fs.readFileSync(files[0], 'utf8'));
}

function latestReportFile(localAppData, predicate) {
  const reportsDir = path.join(localAppData, 'CodexSafetyCanary', 'reports');
  const files = fs.readdirSync(reportsDir)
    .filter(predicate)
    .map((name) => path.join(reportsDir, name))
    .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
  assert.ok(files.length > 0, 'expected matching report file');
  return files[0];
}

function makeInventory(scenario, appRoot) {
  const unavailableRuntimeScenarios = new Set([
    'sandbox-unavailable-helper',
    'sandbox-unavailable-runner',
    'sandbox-unavailable-elevation',
  ]);
  const multipleCandidateScenario = scenario.startsWith('multi-');
  const matchingCandidateScenarios = new Set([
    'matching-alt-pass',
    'multi-guided-matching-select',
    'multi-sandbox-active-select',
    'multi-sandbox-matching-select',
    'multi-sandbox-all-newer-select',
    'multi-sandbox-all-skip',
  ]);
  const newerCandidateScenarios = new Set([
    'multi-sandbox-newer-select',
    'multi-sandbox-all-newer-select',
    'multi-sandbox-all-skip',
  ]);
  const activeComplete = multipleCandidateScenario || ['guided-live-run', 'sandbox-continue-decline', 'sandbox-live-run', 'sandbox-incomplete-error', 'sandbox-gap-with-errors', 'sandbox-cleanup-failure'].includes(scenario);
  const activeStandalone = [
    'runner-process-failure',
    'inventory-runner-help-failure',
    'targeted-dual-failure',
    'alternative-pass-active-helper-failure',
    ...unavailableRuntimeScenarios,
  ].includes(scenario);
  const activeProbeReady = activeComplete || ['runner-process-failure', 'inventory-runner-help-failure'].includes(scenario);
  const inventoryRuntimeFailure = ['inventory-runner-help-failure', 'targeted-dual-failure', 'alternative-pass-active-helper-failure'].includes(scenario) || unavailableRuntimeScenarios.has(scenario);
  const doctorOk = ['inventory-runner-help-failure', 'targeted-dual-failure'].includes(scenario);
  const matchingAlternative = scenario === 'matching-alt-pass';
  const activeCodexPath = path.join(appRoot, 'mock-active-codex.exe');
  const matchingCodexPath = path.join(appRoot, 'mock-matching-codex.exe');
  const newerCodexPath = path.join(appRoot, 'mock-newer-codex.exe');
  const matchingBundle = {
    complete: true,
    probeEligible: true,
    installType: 'classic',
    resourceLayout: 'COMPLETE',
    helperResolution: 'NOT_TESTED',
    runtimeStartup: 'NOT_TESTED',
    missing: [],
    executablePath: matchingCodexPath,
    version: 'codex-cli 0.1.0-alpha.8',
    sandboxState: 'AVAILABLE',
    sandboxFullAutoAvailable: true,
  };
  const newerBundle = {
    ...matchingBundle,
    executablePath: newerCodexPath,
    version: 'codex-cli 0.1.0-alpha.11',
    sandboxState: 'AVAILABLE',
    sandboxFullAutoAvailable: true,
  };
  const includeMatchingCandidate = matchingCandidateScenarios.has(scenario);
  const includeNewerCandidate = newerCandidateScenarios.has(scenario) || (!activeProbeReady && !matchingAlternative);
  let matchingCompleteBundles = includeMatchingCandidate ? [matchingBundle] : [];
  let newerCompleteBundles = includeNewerCandidate ? [newerBundle] : [];
  if (scenario === 'report-bundle-alias-count') {
    const releaseDir = path.join(appRoot, 'standalone', 'releases', '0.1.0-alpha.8-x86_64-pc-windows-msvc');
    const releaseBin = path.join(releaseDir, 'bin');
    const currentDir = path.join(appRoot, 'standalone', 'current');
    fs.mkdirSync(releaseBin, { recursive: true });
    fs.writeFileSync(path.join(releaseBin, 'codex.exe'), 'synthetic');
    if (!fs.existsSync(currentDir)) fs.symlinkSync(releaseDir, currentDir, process.platform === 'win32' ? 'junction' : 'dir');
    matchingCompleteBundles = [
      { ...matchingBundle, executablePath: path.join(currentDir, 'bin', 'codex.exe') },
      { ...matchingBundle, executablePath: path.join(releaseBin, 'codex.exe') },
    ];
    newerCompleteBundles = [];
  }
  const inventory = {
    platform: 'win32',
    release: 'test-release',
    nodeVersion: process.version,
    nodeRuntimeSource: 'TEST',
    nodeInPath: true,
    npmInPath: false,
    elevated: false,
    codexInstalled: true,
    codexVersion: 'codex-cli 0.1.0-alpha.8',
    activeCodexPath,
    activeBundle: activeStandalone
      ? { complete: false, probeEligible: true, installType: 'standalone', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', standaloneResourcesFound: true, standaloneRequiredResourcesPresent: true, resourceVersionMatchesActive: true, standalonePackage: { releaseVersion: '0.1.0-alpha.8' }, missing: ['codex-windows-sandbox-setup.exe', 'codex-command-runner.exe'] }
      : activeComplete
      ? { complete: true, probeEligible: true, installType: 'classic', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', missing: [] }
      : { complete: false, probeEligible: false, installType: 'classic', resourceLayout: 'MISSING', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', missing: ['codex-windows-sandbox-setup.exe'] },
    sandboxHelperInPath: false,
    completeBundles: [...matchingCompleteBundles, ...newerCompleteBundles],
    matchingCompleteBundles,
    newerCompleteBundles,
    codexHome: path.join(appRoot, 'mock-codex-home'),
    authFilePresent: false,
    doctor: doctorOk
      ? { status: 'COMPLETED', ok: true, overallStatus: 'ok', error: null }
      : { status: 'NOT_RUN', ok: false, overallStatus: null, error: null },
    config: { exists: false, path: path.join(appRoot, 'mock-codex-home', 'config.toml'), sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
    ruleFiles: [],
    sandboxWindowsState: inventoryRuntimeFailure ? 'AVAILABLE_BUT_SETUP_FAILED' : 'AVAILABLE',
    sandboxWindowsAvailable: !inventoryRuntimeFailure,
    sandboxFullAutoAvailable: true,
    sandboxSetupFailed: inventoryRuntimeFailure,
    sandboxHelpStatus: inventoryRuntimeFailure ? 1 : 0,
    sandboxHelpError: scenario === 'inventory-runner-help-failure'
      ? 'codex-command-runner.exe CreateProcessWithLogonW failed: 2'
      : ['targeted-dual-failure', 'sandbox-unavailable-helper', 'alternative-pass-active-helper-failure'].includes(scenario)
        ? 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT'
        : scenario === 'sandbox-unavailable-runner'
          ? 'codex-command-runner.exe CreateProcessWithLogonW failed: 2'
          : scenario === 'sandbox-unavailable-elevation'
            ? 'requested operation requires elevation (os error 740)'
        : null,
  };
  inventory.sandboxHelpRuntimeEvidence = inventory.sandboxHelpError
    ? buildSandboxRuntimeEvidence(inventory.sandboxHelpError, { step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI' })
    : null;
  const inventoryRuntimeObservation = deriveSandboxRuntimeObservation(inventory, null);
  inventory.activeBundle = {
    ...inventory.activeBundle,
    helperResolution: inventoryRuntimeObservation.helperResolution,
    runtimeStartup: inventoryRuntimeObservation.runtimeStartup,
  };
  inventory.runtimeObservation = inventoryRuntimeObservation;
  inventory.sandboxProbePlan = unavailableRuntimeScenarios.has(scenario)
    ? { ready: false, requiresConfirmation: false, requiresSelection: false, candidates: [], source: null, codexExe: null, reason: 'Synthetic inventory runtime failure blocks live probes.' }
    : selectCodexProbePlan(inventory);
  return inventory;
}

function syntheticExecpolicyCoverage() {
  return Array.from({ length: 6 }, (_, index) => ({
    label: `synthetic execpolicy ${index + 1}`,
    command: ['synthetic', String(index + 1)],
    decision: null,
    status: 'NO MATCH',
    ok: true,
  }));
}

function syntheticBoundaryProbe({ method, location, label, command, expected, observed, assessment }) {
  const retained = observed === 'RETAINED';
  return {
    method, location, label, command, expected, observed, assessment,
    targetId: `${location}-workspace-${method === 'cmd.exe' ? 'cmd' : method === 'node.js' ? 'node' : method}`,
    commandStarted: true,
    operationAttempted: true,
    hostCalibrationStatus: 'PASS',
    targetIdentityStatus: 'MATCHED',
    errorTargetMatched: location === 'outside' && assessment === 'PASS',
    fileExistedBefore: true,
    fileExistsAfter: retained,
    unrelatedFailureDetected: false,
  };
}

function syntheticHostCalibrations() {
  return ['powershell', 'cmd', 'node'].map((method) => ({
    method, label: method, status: 'PASS', passed: true,
    commandStarted: true, operationAttempted: true, targetIdentityStatus: 'MATCHED',
    commandExitCode: 0, errorClass: null, errorCategory: null, errorCode: null,
  }));
}

function syntheticSandboxResult(options, appRoot, scenario) {
  const targetMetadata = {
    codexSource: options.codexSource,
    testedCodexVersion: options.testedCodexVersion,
    activeCodexVersion: options.activeCodexVersion,
    isAlternativeExecutable: options.isAlternativeExecutable === true,
    versionMismatch: options.versionMismatch === true,
    testedBundleMetadata: options.testedBundleMetadata,
    scopeNote: options.scopeNote || null,
  };
  if (['runner-process-failure', 'targeted-dual-failure'].includes(scenario)) {
    return {
      status: 'SETUP_FAILED',
      ...targetMetadata,
      permissionProfile: ':workspace',
      hostCalibrations: syntheticHostCalibrations(),
      layout: { runDir: path.join(appRoot, 'runs', `synthetic-${Date.now()}`) },
      smoke: { passed: false, commandExitCode: 1, setupFailure: true, stderr: 'codex-command-runner.exe CreateProcessWithLogonW failed: 2' },
      probes: [],
      runtimeEvidence: buildSandboxRuntimeEvidence('codex-command-runner.exe CreateProcessWithLogonW failed: 2', {
        step: 'SANDBOX_SMOKE', codexSource: targetMetadata.codexSource,
      }),
      error: 'codex-command-runner.exe CreateProcessWithLogonW failed: 2',
    };
  }
  if (scenario === 'sandbox-incomplete-error') {
    return {
      status: 'ERROR',
      ...targetMetadata,
      permissionProfile: ':workspace',
      layout: { runDir: path.join(appRoot, 'runs', `synthetic-${Date.now()}`) },
      hostPreflight: { passed: true, filesChecked: 2 },
      hostCalibrations: syntheticHostCalibrations(),
      smoke: { passed: true, commandExitCode: 0, setupFailure: false, stderr: '' },
      probes: [
        syntheticBoundaryProbe({ method: 'powershell', location: 'inside', label: 'PowerShell synthetic inside workspace', command: ['powershell', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
        syntheticBoundaryProbe({ method: 'powershell', location: 'outside', label: 'PowerShell synthetic outside workspace', command: ['powershell', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' }),
      ],
      error: 'Synthetic interruption after the PowerShell runtime pair.',
    };
  }
  if (scenario === 'sandbox-gap-with-errors') {
    return {
      status: 'ERROR',
      ...targetMetadata,
      permissionProfile: ':workspace',
      layout: { runDir: path.join(appRoot, 'runs', `synthetic-${Date.now()}`) },
      hostPreflight: { passed: true, filesChecked: 2 },
      hostCalibrations: syntheticHostCalibrations(),
      smoke: { passed: true, commandExitCode: 0, setupFailure: false, stderr: '' },
      probes: [
        syntheticBoundaryProbe({ method: 'powershell', location: 'inside', label: 'PowerShell synthetic inside workspace', command: ['powershell', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
        syntheticBoundaryProbe({ method: 'powershell', location: 'outside', label: 'PowerShell synthetic outside workspace', command: ['powershell', 'outside'], expected: 'RETAINED', observed: 'DELETED', assessment: 'CRITICAL_GAP' }),
        syntheticBoundaryProbe({ method: 'cmd.exe', location: 'inside', label: 'cmd.exe synthetic inside workspace', command: ['cmd.exe', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
        syntheticBoundaryProbe({ method: 'cmd.exe', location: 'outside', label: 'cmd.exe synthetic outside workspace', command: ['cmd.exe', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'TEST_ERROR' }),
        syntheticBoundaryProbe({ method: 'node.js', location: 'inside', label: 'Node.js synthetic inside workspace', command: ['node', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
        syntheticBoundaryProbe({ method: 'node.js', location: 'outside', label: 'Node.js synthetic outside workspace', command: ['node', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' }),
      ],
      error: 'Synthetic sibling probe failure after a confirmed outside deletion.',
    };
  }
  return {
    status: 'COMPLETED',
    ...targetMetadata,
    permissionProfile: ':workspace',
    layout: { runDir: path.join(appRoot, 'runs', `synthetic-${Date.now()}`) },
    hostPreflight: { passed: true, filesChecked: 2 },
    hostCalibrations: syntheticHostCalibrations(),
    smoke: { passed: true, commandExitCode: 0, setupFailure: false, stderr: '' },
    probes: [
      syntheticBoundaryProbe({ method: 'powershell', location: 'inside', label: 'PowerShell synthetic inside workspace', command: ['powershell', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
      syntheticBoundaryProbe({ method: 'powershell', location: 'outside', label: 'PowerShell synthetic outside workspace', command: ['powershell', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' }),
      syntheticBoundaryProbe({ method: 'cmd.exe', location: 'inside', label: 'cmd.exe synthetic inside workspace', command: ['cmd.exe', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
      syntheticBoundaryProbe({ method: 'cmd.exe', location: 'outside', label: 'cmd.exe synthetic outside workspace', command: ['cmd.exe', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' }),
      syntheticBoundaryProbe({ method: 'node.js', location: 'inside', label: 'Node.js synthetic inside workspace', command: ['node', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' }),
      syntheticBoundaryProbe({ method: 'node.js', location: 'outside', label: 'Node.js synthetic outside workspace', command: ['node', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' }),
    ],
  };
}

async function runCliScenario(t, scenario, inputText) {
  const localAppData = fs.mkdtempSync(path.join(os.tmpdir(), `canary-cli-${scenario}-`));
  const appRoot = path.join(localAppData, 'CodexSafetyCanary');
  t.after(() => fs.rmSync(localAppData, { recursive: true, force: true }));
  const input = new PassThrough();
  const output = new PassThrough();
  let stdout = '';
  let sandboxRunCount = 0;
  let sandboxOptions = null;
  output.setEncoding('utf8');
  output.on('data', (chunk) => { stdout += chunk; });
  const cli = createCanaryCli({
    appRoot,
    platform: 'win32',
    input,
    output,
    clearEnabled: false,
    getInventory: () => makeInventory(scenario, appRoot),
    runExecpolicyCoverage: () => syntheticExecpolicyCoverage(),
    runSandboxProbes: (options) => {
      sandboxRunCount += 1;
      sandboxOptions = options;
      return syntheticSandboxResult(options, appRoot, scenario);
    },
    writeReport: (args) => writeReport({ ...args, appRoot }),
    getLatestReport,
    safeRemoveRun: () => {
      if (scenario === 'sandbox-cleanup-failure') throw new Error('Could not remove disposable run folder.');
    },
    launchDetachedProcess: async () => ({ ok: true, error: null }),
  });
  const runPromise = cli.run();
  const answers = inputText.trimEnd().split('\n');
  for (const answer of answers) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    input.write(`${answer}\n`);
  }
  input.end();
  const exitCode = await runPromise;
  assert.equal(exitCode, 0);
  return { stdout, report: latestDetailJson(localAppData), localAppData, sandboxRunCount, sandboxOptions };
}

function assertAllFourReportsExist(localAppData) {
  const reportsDir = path.join(localAppData, 'CodexSafetyCanary', 'reports');
  const files = fs.readdirSync(reportsDir);
  assert.equal(files.some((name) => name.endsWith('.json') && name !== 'latest.json' && !name.endsWith('-support.json')), true);
  assert.equal(files.some((name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), true);
  assert.equal(files.some((name) => name.endsWith('-support.json')), true);
  assert.equal(files.some((name) => name.endsWith('-support.txt')), true);
}

function assertReturnedToMenuAfterReport(stdout) {
  const reportIndex = stdout.indexOf('Detailed JSON report:');
  const fileDialogIndex = stdout.indexOf('File:', reportIndex);
  const finalMenuIndex = stdout.lastIndexOf('[0] Exit');
  assert.ok(reportIndex >= 0, 'expected report paths before returning');
  assert.ok(fileDialogIndex > reportIndex, 'expected open-dialog prompt after report paths');
  assert.match(stdout.slice(reportIndex, finalMenuIndex), /\[O\] Open or reopen in Notepad/);
  assert.match(stdout.slice(reportIndex, finalMenuIndex), /\[F\] Show the file in File Explorer/);
  assert.match(stdout.slice(reportIndex, finalMenuIndex), /\[M\] Return to menu/);
  assert.ok(finalMenuIndex > fileDialogIndex, 'expected main menu only after the open-dialog return choice');
}

function assertConsoleRuntimeMatchesReport(stdout, expectedRuntime) {
  const runtimeLines = stdout.split(/\r?\n/)
    .filter((line) => line.startsWith('Sandbox runtime:'))
    .map((line) => line.replace(/^Sandbox runtime:\s*/, ''));
  assert.ok(runtimeLines.length >= 2, 'expected sandbox runtime in inventory and consolidated result');
  assert.deepEqual([...new Set(runtimeLines)], [expectedRuntime]);
}

test('CLI guided assessment reports declined boundary when alternative bundle is rejected', async (t) => {
  const { stdout, report } = await runCliScenario(t, 'guided-alt-decline', '1\nn\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assert.equal(report.assessmentMode, 'GUIDED – LIVE PROBES SKIPPED');
  assert.equal(report.summary.overall, 'PARTIAL / LIVE PROBES DECLINED');
  assert.equal(report.summary.sandboxRuntime, 'NOT RUN');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.methodCoverage, 'NOT RUN');
  assert.deepEqual(report.summary.execpolicyCoverage, { status: 'COMPLETED', matched: 0, total: 6 });
  assert.equal(report.summary.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE'), false);
});

test('alternative PASS recommends only repair and separate testing of the active PATH CLI across report channels', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'alternative-pass-active-helper-failure', '4\ny\ny\nm\n0\n');
  const expected = 'The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, correct its helper-resolution problem and test that executable separately.';
  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const output of [stdout, detailText, supportText, JSON.stringify(report), JSON.stringify(supportJson)]) {
    assert.match(output, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.doesNotMatch(output, /When the Windows sandbox state is AVAILABLE/);
  }
  assert.equal(report.summary.activeCli.helperResolution, 'FAILED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle.boundaryStatus, 'PASS');
});

test('logical bundle counts and alias path counts stay consistent across console and all reports', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'report-bundle-alias-count', '2\nm\n0\n');
  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  assert.deepEqual(report.summary.bundleStatistics.matching, {
    logicalExecutableCount: 1,
    discoveredPathCount: 2,
    aliasPathCount: 1,
  });
  assert.equal(report.inventory.matchingCompleteBundles.length, 2);
  assert.equal(supportJson.environment.matchingCompleteBundleCount, 1);
  assert.equal(supportJson.environment.matchingCompleteBundlePathCount, 2);
  assert.equal(supportJson.environment.matchingCompleteBundleAliasCount, 1);
  for (const output of [stdout, detailText, supportText]) {
    assert.match(output, /Matching logical executables:\s+1/);
    assert.match(output, /Matching discovered paths:\s+2/);
    assert.match(output, /Matching alias paths:\s+1/);
  }
});

test('CLI guided assessment reports declined boundary after alternative bundle is accepted and live probes are rejected', async (t) => {
  const { stdout, report } = await runCliScenario(t, 'guided-alt-live-decline', '1\ny\nn\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assert.equal(report.assessmentMode, 'GUIDED – LIVE PROBES SKIPPED');
  assert.equal(report.summary.overall, 'PARTIAL / LIVE PROBES DECLINED');
  assert.equal(report.summary.sandboxRuntime, 'NOT RUN');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.methodCoverage, 'NOT RUN');
  assert.deepEqual(report.summary.execpolicyCoverage, { status: 'COMPLETED', matched: 0, total: 6 });
  assert.equal(report.summary.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE'), false);
});

test('CLI sandbox-only writes reports when Continue is rejected', async (t) => {
  const { stdout, report } = await runCliScenario(t, 'sandbox-continue-decline', '4\nn\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assert.equal(report.assessmentMode, 'SANDBOX ONLY – LIVE PROBES SKIPPED');
  assert.equal(report.summary.overall, 'BOUNDARY ASSESSMENT DECLINED');
  assert.equal(report.summary.sandboxRuntime, 'NOT RUN');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.methodCoverage, 'NOT RUN');
  assert.deepEqual(report.summary.execpolicyCoverage, { status: 'NOT_RUN', matched: null, total: null });
  assert.equal(report.summary.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
});

test('CLI guided live-probe success path still reports all three runtime pairs', async (t) => {
  const { report } = await runCliScenario(t, 'guided-live-run', '1\ny\nm\n0\n');
  assert.equal(report.assessmentMode, 'GUIDED');
  assert.equal(report.summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(report.summary.sandboxRuntime, 'READY');
  assert.equal(report.summary.boundary, 'PASS');
  assert.equal(report.summary.methodCoverage, '3/3');
  assert.equal(report.summary.testedBundle.resourceLayout, 'COMPLETE');
  assert.equal(report.summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.testedBundle.runtimeStartup, 'READY');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI sandbox-only live-probe success path still reports all three runtime pairs', async (t) => {
  const { stdout, report, sandboxOptions } = await runCliScenario(t, 'sandbox-live-run', '4\ny\nm\n0\n');
  assert.doesNotMatch(stdout, /Multiple probe-eligible Codex executables/);
  assert.equal(sandboxOptions.codexSource, 'ACTIVE_CLI');
  assert.equal(report.assessmentMode, 'SANDBOX ONLY');
  assert.equal(report.summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(report.summary.sandboxRuntime, 'READY');
  assert.equal(report.summary.boundary, 'PASS');
  assert.equal(report.summary.methodCoverage, '3/3');
  assert.equal(report.summary.testedBundle.resourceLayout, 'COMPLETE');
  assert.equal(report.summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.testedBundle.runtimeStartup, 'READY');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI Guided Assessment lets the user select a same-version alternative explicitly', async (t) => {
  const { stdout, report, sandboxOptions } = await runCliScenario(t, 'multi-guided-matching-select', '1\n2\ny\nm\n0\n');
  assert.match(stdout, /Multiple probe-eligible Codex executables/);
  assert.match(stdout, /\[1\] Active PATH CLI \(recommended\)/);
  assert.match(stdout, /\[2\] Separate same-version standalone executable/);
  assert.match(stdout, /This result applies only to the selected executable and does not validate the active PATH CLI/);
  assert.equal(sandboxOptions.codexSource, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(sandboxOptions.isAlternativeExecutable, true);
  assert.equal(sandboxOptions.versionMismatch, false);
  assert.match(sandboxOptions.scopeNote, /same Codex version/);
  assert.equal(report.summary.overall, 'ALTERNATIVE BUNDLE BOUNDARY PASSED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle.source, 'MATCHING_COMPLETE_BUNDLE');
});

test('CLI Sandbox-only lets the user keep the recommended active CLI when alternatives exist', async (t) => {
  const { stdout, report, sandboxOptions } = await runCliScenario(t, 'multi-sandbox-active-select', '4\n1\ny\nm\n0\n');
  assert.match(stdout, /Choose a test executable \[1-2\/N\]/);
  assert.equal(sandboxOptions.codexSource, 'ACTIVE_CLI');
  assert.equal(sandboxOptions.isAlternativeExecutable, false);
  assert.equal(sandboxOptions.scopeNote, null);
  assert.equal(report.summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'PASS');
  assert.equal(report.summary.testedBundle.source, 'ACTIVE_CLI');
});

test('CLI Sandbox-only marks a selected same-version executable as TESTED_BUNDLE', async (t) => {
  const { report, localAppData, sandboxOptions } = await runCliScenario(t, 'multi-sandbox-matching-select', '4\n2\ny\nm\n0\n');
  assert.equal(sandboxOptions.codexSource, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(sandboxOptions.testedCodexVersion, sandboxOptions.activeCodexVersion);
  assert.equal(report.sandbox.codexSource, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(report.sandbox.isAlternativeExecutable, true);
  assert.equal(report.sandbox.versionMismatch, false);
  assert.equal(report.sandbox.testedBundleMetadata.resourceLayout, 'COMPLETE');
  assert.match(report.sandbox.scopeNote, /does not validate the active PATH CLI/);
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle.isAlternativeExecutable, true);
  assert.equal(report.summary.testedBundle.versionMismatch, false);
  assert.match(report.summary.testedBundle.scopeNote, /does not validate the active PATH CLI/);
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  assert.equal(supportJson.sandbox.source, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(supportJson.sandbox.isAlternativeExecutable, true);
  assert.equal(supportJson.sandbox.versionMismatch, false);
  assert.match(supportJson.sandbox.scopeNote, /does not validate the active PATH CLI/);
});

test('CLI Sandbox-only shows and preserves the newer-executable version warning', async (t) => {
  const { stdout, report, sandboxOptions } = await runCliScenario(t, 'multi-sandbox-newer-select', '4\n2\ny\nm\n0\n');
  assert.match(stdout, /\[2\] Separate newer executable/);
  assert.match(stdout, /Version warning: active codex-cli 0\.1\.0-alpha\.8; selected codex-cli 0\.1\.0-alpha\.11/);
  assert.equal(sandboxOptions.codexSource, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(sandboxOptions.versionMismatch, true);
  assert.equal(report.summary.testedBundle.source, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(report.summary.testedBundle.versionMismatch, true);
});

test('CLI lists all three deduplicated candidate classes and can select the third', async (t) => {
  const { stdout, report, sandboxOptions } = await runCliScenario(t, 'multi-sandbox-all-newer-select', '4\n3\ny\nm\n0\n');
  assert.match(stdout, /\[1\] Active PATH CLI \(recommended\)/);
  assert.match(stdout, /\[2\] Separate same-version standalone executable/);
  assert.match(stdout, /\[3\] Separate newer executable/);
  assert.match(stdout, /Choose a test executable \[1-3\/N\]/);
  assert.equal(sandboxOptions.codexSource, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(report.summary.testedBundle.source, 'NEWER_COMPLETE_BUNDLE');
});

test('CLI candidate selection N creates a decline report without running probes', async (t) => {
  const { stdout, report, sandboxRunCount, sandboxOptions } = await runCliScenario(t, 'multi-sandbox-all-skip', '4\nn\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assert.match(stdout, /\[N\] Skip live probes/);
  assert.equal(sandboxRunCount, 0);
  assert.equal(sandboxOptions, null);
  assert.equal(report.assessmentMode, 'SANDBOX ONLY – LIVE PROBES SKIPPED');
  assert.equal(report.summary.overall, 'BOUNDARY ASSESSMENT DECLINED');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), true);
});

test('CLI command-runner failure reports confirmed helper resolution consistently across every report channel', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'runner-process-failure', '4\ny\nm\n0\n');
  const resultSection = stdout.slice(stdout.lastIndexOf('Result by installation'));
  assert.match(resultSection, /ACTIVE CLI[\s\S]*Helper resolution:\s+CONFIRMED[\s\S]*Runtime startup:\s+FAILED[\s\S]*Boundary:\s+TEST ERROR/);
  assert.match(resultSection, /TESTED BUNDLE[\s\S]*Helper resolution:\s+CONFIRMED[\s\S]*Runtime startup:\s+FAILED[\s\S]*Boundary:\s+TEST ERROR/);
  assert.doesNotMatch(resultSection, /Helper resolution:\s+NOT_TESTED/);
  assert.match(resultSection, /COMMAND_RUNNER_PROCESS_CREATION_FAILED/);
  assert.doesNotMatch(resultSection, /SANDBOX_SETUP_FAILED/);

  assert.equal(report.summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'TEST ERROR');
  assert.equal(report.summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(report.summary.testedBundle.boundaryStatus, 'TEST ERROR');

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const text of [detailText, supportText]) {
    assert.match(text, /helper resolution:\s+CONFIRMED/i);
    assert.match(text, /runtime startup:\s+FAILED/i);
    assert.match(text, /Boundary status:\s+TEST ERROR|bundle boundary:\s+TEST ERROR/i);
    assert.match(text, /COMMAND_RUNNER_PROCESS_CREATION_FAILED/);
    assert.doesNotMatch(text, /ACTION_RECOMMENDED SANDBOX_SETUP_FAILED/);
    assert.doesNotMatch(text, /helper resolution:\s+NOT_TESTED/i);
    assert.doesNotMatch(text, /runtime startup:\s+NOT_TESTED/i);
  }
  assert.equal(supportJson.summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(supportJson.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(supportJson.summary.activeCli.boundaryStatus, 'TEST ERROR');
  assert.equal(supportJson.summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(supportJson.summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(supportJson.summary.testedBundle.boundaryStatus, 'TEST ERROR');
  assert.equal(supportJson.environment.activeHelperResolution, 'CONFIRMED');
  assert.equal(supportJson.environment.activeRuntimeStartup, 'FAILED');
  assert.equal(supportJson.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
});

test('CLI inventory-only command-runner failure stays consistent across console and report formats', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'inventory-runner-help-failure', '2\nm\n0\n');
  const resultSection = stdout.slice(stdout.lastIndexOf('Result by installation'));
  assert.match(resultSection, /ACTIVE CLI[\s\S]*Helper resolution:\s+CONFIRMED[\s\S]*Runtime startup:\s+FAILED[\s\S]*Boundary:\s+NOT TESTED/);
  assert.match(resultSection, /TESTED BUNDLE\s+\(not tested\)/);
  assert.doesNotMatch(resultSection, /Helper resolution:\s+NOT_TESTED/);
  assert.match(resultSection, /COMMAND_RUNNER_PROCESS_CREATION_FAILED/);
  assert.match(resultSection, /DOCTOR_OK_BUT_RUNTIME_FAILED/);
  assert.doesNotMatch(resultSection, /SANDBOX_SETUP_FAILED/);

  assert.equal(report.summary.sandboxRuntime, 'FAILED – PROCESS CREATION FAILED');
  assert.equal(report.summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle, null);

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const text of [detailText, supportText]) {
    assert.match(text, /helper resolution:\s+CONFIRMED/i);
    assert.match(text, /runtime startup:\s+FAILED/i);
    assert.match(text, /COMMAND_RUNNER_PROCESS_CREATION_FAILED/);
    assert.match(text, /DOCTOR_OK_BUT_RUNTIME_FAILED/);
    assert.doesNotMatch(text, /helper resolution:\s+NOT_TESTED/i);
    assert.doesNotMatch(text, /ACTION_RECOMMENDED SANDBOX_SETUP_FAILED/);
  }
  assert.equal(supportJson.summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(supportJson.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(supportJson.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(supportJson.summary.testedBundle, null);
  assert.equal(supportJson.environment.activeHelperResolution, 'CONFIRMED');
  assert.equal(supportJson.environment.activeRuntimeStartup, 'FAILED');
});

test('CLI keeps active and tested-bundle runtime failures targeted across every report channel', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'targeted-dual-failure', '4\ny\ny\nm\n0\n');
  const resultSection = stdout.slice(stdout.lastIndexOf('Result by installation'));
  assert.match(resultSection, /SANDBOX_SETUP_HELPER_NOT_RESOLVED \[ACTIVE_CLI\]/);
  assert.match(resultSection, /COMMAND_RUNNER_PROCESS_CREATION_FAILED \[TESTED_BUNDLE\]/);
  assert.match(resultSection, /DOCTOR_OK_BUT_RUNTIME_FAILED \[ACTIVE_CLI\]/);
  assert.doesNotMatch(resultSection, /DOCTOR_OK_BUT_RUNTIME_FAILED \[TESTED_BUNDLE\]/);
  assert.doesNotMatch(resultSection, /SANDBOX_SETUP_FAILED \[ACTIVE_CLI\]|SANDBOX_SETUP_FAILED \[TESTED_BUNDLE\]/);

  assert.equal(report.summary.activeCli.helperResolution, 'FAILED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(report.summary.testedBundle.boundaryStatus, 'TEST ERROR');
  assert.equal(report.summary.activeRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED' && item.target === 'ACTIVE_CLI'), true);
  assert.equal(report.summary.testedRuntimeDiagnostics.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED' && item.target === 'TESTED_BUNDLE'), true);

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const text of [detailText, supportText]) {
    assert.match(text, /SANDBOX_SETUP_HELPER_NOT_RESOLVED \[ACTIVE_CLI\]/);
    assert.match(text, /COMMAND_RUNNER_PROCESS_CREATION_FAILED \[TESTED_BUNDLE\]/);
    assert.doesNotMatch(text, /DOCTOR_OK_BUT_RUNTIME_FAILED \[TESTED_BUNDLE\]/);
  }
  assert.equal(supportJson.summary.activeRuntimeDiagnostics.some((item) => item.target === 'ACTIVE_CLI'), true);
  assert.equal(supportJson.summary.testedRuntimeDiagnostics.some((item) => item.target === 'TESTED_BUNDLE'), true);
  assert.equal(supportJson.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED' && item.target === 'TESTED_BUNDLE'), false);
});

test('CLI reports same-version matching bundle scope before confirmation and across reports', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'matching-alt-pass', '4\ny\ny\nm\n0\n');
  const scopePattern = /A separate executable with the same Codex version was tested\. Its result applies only to that executable and does not validate the active PATH CLI\./;
  assert.match(stdout, scopePattern);
  const confirmationScopeIndex = stdout.indexOf('A separate executable with the same Codex version was tested.');
  const confirmationPromptIndex = stdout.indexOf('Use the matching probe-eligible bundle for live probes?');
  assert.ok(confirmationScopeIndex >= 0 && confirmationScopeIndex < confirmationPromptIndex, 'expected the scope warning before alternative-executable confirmation');
  assert.match(stdout, /Scope:\s+A separate executable with the same Codex version/);
  assert.equal(report.summary.overall, 'ALTERNATIVE BUNDLE BOUNDARY PASSED');
  assert.equal(report.summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(report.summary.testedBundle.source, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(report.summary.testedBundle.versionMismatch, false);
  assert.match(report.summary.testedBundle.scopeNote, scopePattern);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'ALTERNATIVE_BUNDLE_BOUNDARY_PASS' && item.target === 'TESTED_BUNDLE'), true);

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  assert.match(detailText, scopePattern);
  assert.match(supportText, scopePattern);
  assert.match(supportJson.summary.testedBundle.scopeNote, scopePattern);
  assert.equal(supportJson.summary.testedBundle.isAlternativeExecutable, true);
});

test('CLI sandbox-only reports inventory helper resolution failure when probes are unavailable', async (t) => {
  const { stdout, report, localAppData, sandboxRunCount } = await runCliScenario(t, 'sandbox-unavailable-helper', '4\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assertAllFourReportsExist(localAppData);
  assert.equal(sandboxRunCount, 0);
  assertConsoleRuntimeMatchesReport(stdout, 'FAILED – HELPER NOT RESOLVABLE');
  assert.equal(report.assessmentMode, 'SANDBOX ONLY');
  assert.equal(report.summary.sandboxRuntime, 'FAILED – HELPER NOT RESOLVABLE');
  assert.equal(report.summary.activeCli.helperResolution, 'FAILED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.methodCoverage, 'NOT RUN');
  assert.deepEqual(report.summary.execpolicyCoverage, { status: 'NOT_RUN', matched: null, total: null });
  assert.equal(report.summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), true);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), true);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI sandbox-only reports inventory command-runner failure and opens the report dialog', async (t) => {
  const { stdout, report, localAppData, sandboxRunCount } = await runCliScenario(t, 'sandbox-unavailable-runner', '4\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assertAllFourReportsExist(localAppData);
  assert.equal(sandboxRunCount, 0);
  assertConsoleRuntimeMatchesReport(stdout, 'FAILED – PROCESS CREATION FAILED');
  assert.equal(report.summary.sandboxRuntime, 'FAILED – PROCESS CREATION FAILED');
  assert.equal(report.summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED'), true);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI sandbox-only reports generic inventory setup failure without treating it as a decline', async (t) => {
  const { stdout, report, localAppData, sandboxRunCount } = await runCliScenario(t, 'sandbox-unavailable-elevation', '4\nm\n0\n');
  assertReturnedToMenuAfterReport(stdout);
  assertAllFourReportsExist(localAppData);
  assert.equal(sandboxRunCount, 0);
  assertConsoleRuntimeMatchesReport(stdout, 'FAILED');
  assert.equal(report.summary.sandboxRuntime, 'FAILED');
  assert.equal(report.summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(report.summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(report.summary.boundary, 'NOT TESTED');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), true);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), true);
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI incomplete sandbox execution is a test error across console and every report channel', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'sandbox-incomplete-error', '4\ny\nm\n0\n');
  assert.match(stdout, /Sandbox boundary:\s+TEST ERROR/);
  assert.match(stdout, /Runtime pairs:\s+1\/3/);
  assert.equal(report.summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(report.summary.boundary, 'TEST ERROR');
  assert.equal(report.summary.methodCoverage, '1/3');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS'), false);

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const text of [detailText, supportText]) {
    assert.match(text, /Overall:\s+TEST ERROR \/ INCOMPLETE/);
    assert.match(text, /Sandbox boundary:\s+TEST ERROR|Tested bundle boundary:\s+TEST ERROR/);
    assert.match(text, /Runtime pair coverage:\s+1\/3/);
    assert.doesNotMatch(text, /ACTIVE_BUNDLE_BOUNDARY_PASS/);
  }
  assert.equal(supportJson.summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(supportJson.summary.boundary, 'TEST ERROR');
  assert.equal(supportJson.summary.methodCoverage, '1/3');
  assert.equal(supportJson.recommendations.some((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS'), false);
});

test('CLI keeps a confirmed gap primary across console and every report channel when sibling probes fail', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'sandbox-gap-with-errors', '4\ny\nm\n0\n');
  assert.match(stdout, /Overall:\s+CRITICAL GAP DETECTED – ADDITIONAL PROBE ERRORS/);
  assert.match(stdout, /Sandbox boundary:\s+GAP/);
  assert.match(stdout, /POTENTIAL_SECURITY_GAP BOUNDARY_GAP \[ACTIVE_CLI\]/);
  assert.match(stdout, /Additional probe errors.*do not weaken that result/i);
  assert.equal(report.summary.overall, 'CRITICAL GAP DETECTED – ADDITIONAL PROBE ERRORS');
  assert.equal(report.summary.boundary, 'GAP');
  assert.equal(report.summary.additionalProbeErrors, true);
  assert.equal(report.summary.recommendations[0].code, 'BOUNDARY_GAP');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  for (const text of [detailText, supportText]) {
    assert.match(text, /Overall:\s+CRITICAL GAP DETECTED – ADDITIONAL PROBE ERRORS/);
    assert.match(text, /Sandbox boundary:\s+GAP|Active CLI boundary:\s+GAP/);
    assert.match(text, /BOUNDARY_GAP \[ACTIVE_CLI\]/);
    assert.match(text, /Additional probe errors.*do not weaken that result/i);
  }
  assert.equal(supportJson.summary.overall, 'CRITICAL GAP DETECTED – ADDITIONAL PROBE ERRORS');
  assert.equal(supportJson.summary.boundary, 'GAP');
  assert.equal(supportJson.summary.additionalProbeErrors, true);
  assert.equal(supportJson.recommendations[0].code, 'BOUNDARY_GAP');
});

test('CLI reports structured cleanup failure consistently without exposing its message in share-safe output', async (t) => {
  const { stdout, report, localAppData } = await runCliScenario(t, 'sandbox-cleanup-failure', '4\ny\nm\n0\n');
  assert.match(stdout, /Overall:\s+TEST ERROR \/ INCOMPLETE/);
  assert.match(stdout, /Sandbox boundary:\s+TEST ERROR/);
  assert.match(stdout, /Cleanup status:\s+FAILED/);
  assert.equal(report.summary.cleanup.status, 'FAILED');
  assert.equal(report.summary.boundary, 'TEST ERROR');

  const detailText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('.txt') && !name.endsWith('-support.txt')), 'utf8');
  const supportText = fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.txt')), 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(latestReportFile(localAppData, (name) => name.endsWith('-support.json')), 'utf8'));
  assert.match(detailText, /Cleanup status:\s+FAILED/);
  assert.match(supportText, /Cleanup status:\s+FAILED/);
  assert.doesNotMatch(supportText, /Could not remove disposable run folder/);
  assert.deepEqual(supportJson.sandbox.cleanup, { status: 'FAILED', attempted: true, completed: false, errorPresent: true, valid: true });
  assert.equal(JSON.stringify(supportJson).includes('Could not remove disposable run folder'), false);
});

test('production entry has no runtime synthetic test-mode switch', () => {
  const entry = fs.readFileSync(path.join(repoRoot, 'bin', 'codex-safety-canary.mjs'), 'utf8');
  assert.doesNotMatch(entry, /CODEX_CANARY_TEST_SCENARIO/);
  assert.doesNotMatch(entry, /testScenario/);
  assert.doesNotMatch(entry, /makeTestInventory/);
  assert.doesNotMatch(entry, /runtimeSandboxProbes|runtimeExecpolicyCoverage|runtimeInventory/);
});
