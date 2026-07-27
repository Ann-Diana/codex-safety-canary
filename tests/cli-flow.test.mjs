import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { createCanaryCli } from '../lib/cli-flow.mjs';
import { getLatestReport, writeReport } from '../lib/core.mjs';

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

function makeInventory(scenario, appRoot) {
  const activeComplete = ['guided-live-run', 'sandbox-continue-decline', 'sandbox-live-run'].includes(scenario);
  const activeCodexPath = path.join(appRoot, 'mock-active-codex.exe');
  const alternativeCodexPath = path.join(appRoot, 'mock-newer-codex.exe');
  const alternativeBundle = {
    complete: true,
    missing: [],
    executablePath: alternativeCodexPath,
    version: 'codex-cli 0.1.0-alpha.10',
    sandboxState: 'AVAILABLE',
    sandboxFullAutoAvailable: true,
  };
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
    activeBundle: activeComplete ? { complete: true, missing: [] } : { complete: false, missing: ['codex-windows-sandbox-setup.exe'] },
    sandboxHelperInPath: false,
    completeBundles: activeComplete ? [] : [alternativeBundle],
    matchingCompleteBundles: [],
    newerCompleteBundles: activeComplete ? [] : [alternativeBundle],
    codexHome: path.join(appRoot, 'mock-codex-home'),
    authFilePresent: false,
    config: { exists: false, path: path.join(appRoot, 'mock-codex-home', 'config.toml'), sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
    ruleFiles: [],
    sandboxWindowsState: 'AVAILABLE',
    sandboxWindowsAvailable: true,
    sandboxFullAutoAvailable: true,
    sandboxSetupFailed: false,
    sandboxHelpStatus: 0,
    sandboxHelpError: null,
  };
  inventory.sandboxProbePlan = activeComplete
    ? { ready: true, requiresConfirmation: false, source: 'ACTIVE_CLI', codexExe: activeCodexPath, testedVersion: inventory.codexVersion, activeVersion: inventory.codexVersion, versionMismatch: false, fullAutoAvailable: true, reason: null }
    : { ready: true, requiresConfirmation: true, source: 'NEWER_COMPLETE_BUNDLE', codexExe: alternativeCodexPath, testedVersion: alternativeBundle.version, activeVersion: inventory.codexVersion, versionMismatch: true, fullAutoAvailable: true, reason: 'Synthetic alternative bundle for CLI integration tests.' };
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

function syntheticSandboxResult(options, appRoot) {
  return {
    status: 'COMPLETED',
    codexSource: options.codexSource,
    testedCodexVersion: options.testedCodexVersion,
    activeCodexVersion: options.activeCodexVersion,
    versionMismatch: options.versionMismatch === true,
    permissionProfile: ':workspace',
    layout: { runDir: path.join(appRoot, 'runs', `synthetic-${Date.now()}`) },
    probes: [
      { method: 'powershell', location: 'inside', label: 'PowerShell synthetic inside workspace', command: ['powershell', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' },
      { method: 'powershell', location: 'outside', label: 'PowerShell synthetic outside workspace', command: ['powershell', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' },
      { method: 'cmd.exe', location: 'inside', label: 'cmd.exe synthetic inside workspace', command: ['cmd.exe', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' },
      { method: 'cmd.exe', location: 'outside', label: 'cmd.exe synthetic outside workspace', command: ['cmd.exe', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' },
      { method: 'node.js', location: 'inside', label: 'Node.js synthetic inside workspace', command: ['node', 'inside'], expected: 'DELETED', observed: 'DELETED', assessment: 'EXPECTED' },
      { method: 'node.js', location: 'outside', label: 'Node.js synthetic outside workspace', command: ['node', 'outside'], expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS' },
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
    runSandboxProbes: (options) => syntheticSandboxResult(options, appRoot),
    writeReport: (args) => writeReport({ ...args, appRoot }),
    getLatestReport,
    safeRemoveRun: () => {},
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
  return { stdout, report: latestDetailJson(localAppData), localAppData };
}

function assertReturnedToMenuAfterReport(stdout) {
  const reportIndex = stdout.indexOf('Detailed JSON report:');
  const fileDialogIndex = stdout.indexOf('File:', reportIndex);
  const finalMenuIndex = stdout.lastIndexOf('[0] Exit');
  assert.ok(reportIndex >= 0, 'expected report paths before returning');
  assert.ok(fileDialogIndex > reportIndex, 'expected open-dialog prompt after report paths');
  assert.ok(finalMenuIndex > fileDialogIndex, 'expected main menu only after the open-dialog return choice');
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
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('CLI sandbox-only live-probe success path still reports all three runtime pairs', async (t) => {
  const { report } = await runCliScenario(t, 'sandbox-live-run', '4\ny\nm\n0\n');
  assert.equal(report.assessmentMode, 'SANDBOX ONLY');
  assert.equal(report.summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(report.summary.sandboxRuntime, 'READY');
  assert.equal(report.summary.boundary, 'PASS');
  assert.equal(report.summary.methodCoverage, '3/3');
  assert.equal(report.summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), false);
});

test('production entry has no runtime synthetic test-mode switch', () => {
  const entry = fs.readFileSync(path.join(repoRoot, 'bin', 'codex-safety-canary.mjs'), 'utf8');
  assert.doesNotMatch(entry, /CODEX_CANARY_TEST_SCENARIO/);
  assert.doesNotMatch(entry, /testScenario/);
  assert.doesNotMatch(entry, /makeTestInventory/);
  assert.doesNotMatch(entry, /runtimeSandboxProbes|runtimeExecpolicyCoverage|runtimeInventory/);
});
