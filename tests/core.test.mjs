import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import {
  ASSESSMENT_MODES,
  buildSandboxCommandArgs,
  canRunLiveSandboxProbes,
  formatDiagnosticRecommendationLines,
  formatExecpolicyCoverage,
  launchDetachedProcess,
  detectWindowsSandboxFeature,
  inspectCodexBundle,
  normalizeCodexVersion,
  compareCodexVersions,
  selectCodexProbePlan,
  findDecision,
  parseExecpolicyOutput,
  isPathInside,
  listRuleFiles,
  readSafeConfigSummary,
  renderTextReport,
  safeRemoveRun,
  detectSandboxSetupFailure,
  summarizeAssessment,
  detectAccessDenied,
  classifySandboxProbe,
  buildNodeDeleteCommand,
  runHostDeletionPreflight,
  buildSupportPayload,
  renderSupportReport,
  writeReport,
} from '../lib/core.mjs';

test('findDecision handles common execpolicy shapes', () => {
  assert.equal(findDecision({ decision: 'prompt' }), 'prompt');
  assert.equal(findDecision({ result: { strictest_decision: 'forbidden' } }), 'forbidden');
  assert.equal(findDecision({ nested: [{ decision: 'allowed' }] }), 'allow');
  assert.equal(findDecision({ message: 'nothing useful' }), null);
});


test('execpolicy parser treats an empty matchedRules array as a valid no-match result', () => {
  const result = parseExecpolicyOutput({ matchedRules: [] });
  assert.equal(result.status, 'NO_MATCH');
  assert.equal(result.decision, null);
  assert.equal(result.error, null);
});

test('execpolicy parser accepts the current matchedRules plus decision schema', () => {
  const result = parseExecpolicyOutput({
    matchedRules: [{ prefixRuleMatch: { matchedPrefix: ['git', 'clean'], decision: 'prompt' } }],
    decision: 'prompt',
  });
  assert.equal(result.status, 'OK');
  assert.equal(result.decision, 'prompt');
});

test('path containment rejects siblings', () => {
  const root = path.resolve('/tmp/root');
  assert.equal(isPathInside(path.join(root, 'a'), root), true);
  assert.equal(isPathInside(path.resolve('/tmp/root-other'), root), false);
});

test('safeRemoveRun only removes a child of runs', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-test-'));
  const run = path.join(temp, 'runs', 'run-1');
  fs.mkdirSync(run, { recursive: true });
  fs.writeFileSync(path.join(run, 'x.txt'), 'x');
  safeRemoveRun(run, temp);
  assert.equal(fs.existsSync(run), false);
  assert.throws(() => safeRemoveRun(temp, temp));
  fs.rmSync(temp, { recursive: true, force: true });
});

test('rule discovery is user-level and deterministic', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-rules-'));
  fs.mkdirSync(path.join(temp, 'rules'));
  fs.writeFileSync(path.join(temp, 'rules', 'b.rules'), '');
  fs.writeFileSync(path.join(temp, 'rules', 'a.rules'), '');
  fs.writeFileSync(path.join(temp, 'rules', 'ignore.txt'), '');
  assert.deepEqual(listRuleFiles(temp).map((p) => path.basename(p)), ['a.rules', 'b.rules']);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('safe config parser exposes selected settings only', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-config-'));
  const config = path.join(temp, 'config.toml');
  fs.writeFileSync(config, `
sandbox_mode = "danger-full-access"
approval_policy = "never"
default_permissions = ":danger-full-access"
secret_token = "must-not-appear"

[windows]
sandbox = "unelevated"

[sandbox_workspace_write]
network_access = true
`);
  const result = readSafeConfigSummary(config);
  assert.equal(result.sandboxMode, 'danger-full-access');
  assert.equal(result.approvalPolicy, 'never');
  assert.equal(result.windowsSandbox, 'unelevated');
  assert.equal(result.networkAccess, true);
  assert.ok(result.warnings.length >= 2);
  assert.equal('secret_token' in result, false);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('safe config parser respects TOML sections, quotes, and inline comments', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-config-'));
  const config = path.join(temp, 'config.toml');
  fs.writeFileSync(config, `
sandbox_mode = "workspace-write" # root setting
default_permissions = ':workspace' # literal string

[unrelated]
approval_policy = "never"
sandbox = "must-not-leak"

[windows] # selected table
sandbox = "unelevated#literal"

[sandbox_workspace_write]
network_access = false # selected boolean
`);
  const result = readSafeConfigSummary(config);
  assert.equal(result.sandboxMode, 'workspace-write');
  assert.equal(result.approvalPolicy, null);
  assert.equal(result.defaultPermissions, ':workspace');
  assert.equal(result.windowsSandbox, 'unelevated#literal');
  assert.equal(result.networkAccess, false);
  assert.deepEqual(result.warnings, []);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('text report distinguishes workspace deletion from boundary failure', () => {
  const text = renderTextReport({
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'x', version: '1' },
    summary: {
      overall: 'BOUNDARY TEST PASSED',
      boundary: 'PASS',
      workspaceDeletion: 'ALLOWED INSIDE :WORKSPACE PERMISSION PROFILE',
      execpolicyCoverage: { status: 'COMPLETED', matched: 0, total: 0 },
      riskWarnings: [],
    },
    inventory: {
      release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true, elevated: false, codexInstalled: true,
      codexVersion: 'x', codexHome: 'x', authFilePresent: true, ruleFiles: [],
      config: { exists: false, path: 'x', sandboxMode: null, approvalPolicy: null,
        defaultPermissions: null, windowsSandbox: null, networkAccess: null },
    },
    execpolicy: [],
    sandbox: null,
  });
  assert.match(text, /Workspace deletion:\s+ALLOWED INSIDE :WORKSPACE PERMISSION PROFILE/);
  assert.match(text, /:workspace permission profile/i);
});


test('sandbox setup failures are not mistaken for boundary passes', () => {
  assert.equal(detectSandboxSetupFailure({ stderr: 'windows sandbox failed: spawn setup refresh, os error 740' }), true);
  const inventory = { config: { warnings: [] } };
  const summary = summarizeAssessment(inventory, [], {
    status: 'SETUP_FAILED',
    probes: [{ method: 'powershell', location: 'outside', assessment: 'TEST_ERROR' }],
  });
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.notEqual(summary.overall, 'BOUNDARY TEST PASSED');
});

test('empty sandbox result is not a pass', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], { probes: [] });
  assert.equal(summary.boundary, 'NOT TESTED');
});
test('windows sandbox detection reports AVAILABLE from general sandbox help', () => {
  const result = detectWindowsSandboxFeature({
    status: 0,
    stdout: 'Usage: codex sandbox [OPTIONS] -- <COMMAND>\nOptions:\n  --full-auto',
    stderr: '',
  });
  assert.equal(result.state, 'AVAILABLE');
  assert.equal(result.available, true);
  assert.equal(result.fullAutoAvailable, true);
});

test('windows sandbox detection reports AVAILABLE_BUT_SETUP_FAILED', () => {
  const result = detectWindowsSandboxFeature({
    status: 1,
    stdout: '',
    stderr: 'windows sandbox failed: spawn setup refresh, os error 740',
  });
  assert.equal(result.state, 'AVAILABLE_BUT_SETUP_FAILED');
  assert.equal(result.available, false);
  assert.equal(result.setupFailed, true);
});

test('windows sandbox detection reports UNSUPPORTED for unknown sandbox command', () => {
  const result = detectWindowsSandboxFeature({
    status: 2,
    stdout: '',
    stderr: 'error: unrecognized subcommand sandbox',
  });
  assert.equal(result.state, 'UNSUPPORTED');
  assert.equal(result.available, false);
});

test('windows sandbox detection reports DETECTION_ERROR for start failure', () => {
  const result = detectWindowsSandboxFeature({
    status: null,
    stdout: '',
    stderr: '',
    error: new Error('Zugriff verweigert'),
  });
  assert.equal(result.state, 'DETECTION_ERROR');
  assert.equal(result.available, false);
});

test('only AVAILABLE windows sandbox state allows live probes', () => {
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'AVAILABLE' }), true);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED' }), false);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'UNSUPPORTED' }), false);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'DETECTION_ERROR' }), false);
});

test('sandbox command builder uses the explicit workspace permission profile and directory', () => {
  const workspace = path.resolve('C:/Synthetic Workspace');
  assert.deepEqual(buildSandboxCommandArgs(['node', '--version'], { workspaceDir: workspace }), ['sandbox', '--permission-profile', ':workspace', '--cd', workspace, '--', 'node', '--version']);
  assert.deepEqual(buildSandboxCommandArgs(['node', '--version'], { permissionProfile: ':read-only', workspaceDir: workspace }), ['sandbox', '--permission-profile', ':read-only', '--cd', workspace, '--', 'node', '--version']);
});


test('text report includes sandbox feature state and diagnostic', () => {
  const text = renderTextReport({
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'x', version: '1' },
    summary: {
      overall: 'PARTIAL / NOT FULLY TESTED',
      boundary: 'NOT TESTED',
      workspaceDeletion: 'ALLOWED INSIDE :WORKSPACE PERMISSION PROFILE',
      execpolicyCoverage: { status: 'COMPLETED', matched: 0, total: 0 },
      riskWarnings: [],
    },
    inventory: {
      release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true, elevated: false, codexInstalled: true,
      codexVersion: 'x', codexHome: 'x', authFilePresent: true, ruleFiles: [],
      sandboxWindowsState: 'DETECTION_ERROR', sandboxHelpError: 'access denied',
      config: { exists: false, path: 'x', sandboxMode: null, approvalPolicy: null,
        defaultPermissions: null, windowsSandbox: null, networkAccess: null },
    },
    execpolicy: [],
    sandbox: null,
  });
  assert.match(text, /Sandbox command syntax:\s+DETECTION_ERROR/);
  assert.match(text, /Sandbox diagnostic:\s+access denied/);
});


test('codex bundle inspection requires the sandbox helper and command runner', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-bundle-'));
  const codex = path.join(temp, 'codex.exe');
  fs.writeFileSync(codex, 'synthetic');
  let result = inspectCodexBundle(codex);
  assert.equal(result.complete, false);
  assert.deepEqual(result.missing.sort(), ['codex-command-runner.exe', 'codex-windows-sandbox-setup.exe']);
  fs.writeFileSync(path.join(temp, 'codex-command-runner.exe'), 'synthetic');
  fs.writeFileSync(path.join(temp, 'codex-windows-sandbox-setup.exe'), 'synthetic');
  result = inspectCodexBundle(codex);
  assert.equal(result.complete, true);
  assert.deepEqual(result.missing, []);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('version normalization compares codex-cli versions without surrounding text', () => {
  assert.equal(normalizeCodexVersion('codex-cli 0.145.0'), '0.145.0');
  assert.equal(normalizeCodexVersion('Codex 1.2.3-beta'), '1.2.3-beta');
});

test('probe plan prefers the active complete CLI bundle', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: true },
    sandboxFullAutoAvailable: true,
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, false);
  assert.equal(plan.source, 'ACTIVE_CLI');
  assert.equal(plan.fullAutoAvailable, true);
});

test('probe plan offers a same-version complete bundle when the active bundle is incomplete', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [{ executablePath: 'C:\\bundle\\codex.exe', version: 'codex-cli 0.145.0', sandboxState: 'AVAILABLE', sandboxFullAutoAvailable: true }],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, true);
  assert.equal(plan.source, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(plan.codexExe, 'C:\\bundle\\codex.exe');
  assert.equal(plan.fullAutoAvailable, true);
});

test('probe plan fails closed when no complete matching bundle exists', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
  });
  assert.equal(plan.ready, false);
  assert.match(plan.reason, /incomplete/i);
});

test('setup failure summary keeps workspace deletion and boundary as untested', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], {
    status: 'SETUP_FAILED',
    error: 'codex-windows-sandbox-setup.exe program not found',
    probes: [],
  });
  assert.equal(summary.sandboxRuntime, 'FAILED – HELPER NOT RESOLVABLE');
  assert.equal(summary.workspaceDeletion, 'NOT TESTED');
  assert.equal(summary.boundary, 'TEST ERROR');
});


test('Codex version comparison recognizes a newer prerelease bundle', () => {
  assert.equal(compareCodexVersions('codex-cli 0.146.0-alpha.3', 'codex-cli 0.145.0'), 1);
  assert.equal(compareCodexVersions('codex-cli 0.145.0', 'codex-cli 0.146.0-alpha.3'), -1);
  assert.equal(compareCodexVersions('codex-cli 0.145.0', 'codex-cli 0.145.0'), 0);
});

test('probe plan offers a newer complete test-ready bundle with an explicit version warning', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    codexVersion: 'codex-cli 0.145.0',
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
    newerCompleteBundles: [{
      executablePath: 'C:\\bundle\\codex.exe',
      version: 'codex-cli 0.146.0-alpha.3',
      sandboxState: 'AVAILABLE',
      sandboxFullAutoAvailable: false,
    }],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, true);
  assert.equal(plan.source, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(plan.versionMismatch, true);
  assert.equal(plan.activeVersion, 'codex-cli 0.145.0');
  assert.equal(plan.testedVersion, 'codex-cli 0.146.0-alpha.3');
  assert.equal(plan.fullAutoAvailable, false);
});

test('probe plan rejects a newer complete bundle whose sandbox command is not test-ready', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
    newerCompleteBundles: [{
      executablePath: 'C:\\bundle\\codex.exe',
      version: 'codex-cli 0.146.0-alpha.3',
      sandboxState: 'DETECTION_ERROR',
    }],
    completeBundles: [{ version: 'codex-cli 0.146.0-alpha.3', sandboxState: 'DETECTION_ERROR' }],
  });
  assert.equal(plan.ready, false);
  assert.match(plan.reason, /none provide/i);
});

test('alternative bundle pass is not reported as validation of the active CLI', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], {
    status: 'COMPLETED',
    versionMismatch: true,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE BOUNDARY PASSED');
  assert.equal(summary.boundary, 'PASS');
});


test('a test-ready newer bundle can be offered even when the incomplete active CLI sandbox command is unavailable', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'UNSUPPORTED',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
    newerCompleteBundles: [{
      executablePath: 'C:\\bundle\\codex.exe',
      version: 'codex-cli 0.146.0-alpha.3',
      sandboxState: 'AVAILABLE',
      sandboxFullAutoAvailable: false,
    }],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.source, 'NEWER_COMPLETE_BUNDLE');
});


test('access-denial detection recognizes Windows denial messages', () => {
  assert.equal(detectAccessDenied({ stderr: 'Zugriff verweigert' }), true);
  assert.equal(detectAccessDenied({ stderr: 'Zugriff auf den Pfad wurde verweigert.' }), true);
  assert.equal(detectAccessDenied({ stderr: 'Access is denied.' }), true);
  assert.equal(detectAccessDenied({ stderr: 'SyntaxError: missing ) after argument list' }), false);
});

test('retained outside file is PASS only with denial evidence', () => {
  const definition = { expected: 'RETAINED', location: 'outside' };
  assert.deepEqual(
    classifySandboxProbe({ before: true, after: true, result: { status: 1, stderr: 'Zugriff verweigert' }, definition }),
    { assessment: 'PASS', denialEvidence: true },
  );
  assert.deepEqual(
    classifySandboxProbe({ before: true, after: true, result: { status: 1, stderr: 'SyntaxError' }, definition }),
    { assessment: 'TEST_ERROR', denialEvidence: false },
  );
});

test('inside workspace denial fails the workspace-write control', () => {
  const definition = { expected: 'DELETED', location: 'inside' };
  assert.deepEqual(
    classifySandboxProbe({ before: true, after: true, result: { status: 1, stderr: 'Access is denied.' }, definition }),
    { assessment: 'UNEXPECTED', denialEvidence: true },
  );
});

test('boundary cannot pass when every runtime control fails', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], {
    status: 'COMPLETED',
    versionMismatch: true,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.workspaceDeletion, 'CONTROL FAILED');
});

test('boundary passes only when every tested runtime pair passes', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], {
    status: 'COMPLETED',
    versionMismatch: false,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
      { method: 'cmd', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'cmd', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(summary.boundary, 'PASS');
  assert.equal(summary.methodCoverage, '2/2');
});

test('one valid runtime pair produces only a partial pass when another runtime control fails', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], {
    status: 'COMPLETED',
    versionMismatch: true,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
      { method: 'cmd', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'cmd', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE PARTIAL PASS');
  assert.equal(summary.boundary, 'PARTIAL PASS');
  assert.equal(summary.methodCoverage, '1/2');
});


test('Node deletion probe passes the Windows path as an argument', () => {
  const command = buildNodeDeleteCommand('C:\Temp\Canary Test\outside-node.txt');
  assert.equal(command[1], '-e');
  assert.match(command[2], /process\.argv\[1\]/);
  assert.equal(command[3], 'C:\Temp\Canary Test\outside-node.txt');
  assert.doesNotMatch(command[2], /C:\\Temp/);
});

test('host deletion preflight proves normal user deletion works in both synthetic folders', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-host-preflight-'));
  const layout = {
    workspace: fs.mkdirSync(path.join(temp, 'workspace'), { recursive: true }),
    control: fs.mkdirSync(path.join(temp, 'control'), { recursive: true }),
  };
  const result = runHostDeletionPreflight(layout, 'marker');
  assert.equal(result.passed, true);
  assert.equal(result.filesChecked, 2);
  fs.rmSync(temp, { recursive: true, force: true });
});


test('summary separates the incomplete active CLI from a passing alternative bundle', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    config: { warnings: [] },
  }, [], {
    status: 'COMPLETED',
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    testedCodexVersion: 'codex-cli 0.146.0-alpha.3',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(summary.activeCli.bundleStatus, 'INCOMPLETE');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.testedBundle.boundaryStatus, 'PASS');
  assert.match(summary.interpretation.join(' '), /does not validate the active PATH CLI/i);
  assert.match(summary.nextSteps.join(' '), /official installer/i);
});

test('share-safe support payload omits executable and credential paths', () => {
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    summary: {
      overall: 'PASS',
      activeCli: { bundleStatus: 'INCOMPLETE', boundaryStatus: 'NOT TESTED' },
      testedBundle: { source: 'NEWER_COMPLETE_BUNDLE', version: 'x', boundaryStatus: 'PASS', methodCoverage: '3/3' },
      execpolicyCoverage: { status: 'COMPLETED', matched: 0, total: 6 }, interpretation: [], nextSteps: [], recommendations: [], riskWarnings: [],
    },
    inventory: {
      platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true,
      elevated: false, codexInstalled: true, codexVersion: 'x', activeCodexPath: 'C:\\Users\\Alice\\codex.exe',
      activeBundle: { complete: false, missing: ['helper.exe'] }, matchingCompleteBundles: [], newerCompleteBundles: [],
      ruleFiles: ['C:\\Users\\Alice\\.codex\\rules\\default.rules'], sandboxWindowsState: 'AVAILABLE',
      config: { sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: 'elevated', networkAccess: null, warnings: [] },
    },
    execpolicy: [],
    sandbox: {
      status: 'COMPLETED', codexSource: 'NEWER_COMPLETE_BUNDLE', testedCodexVersion: 'x', activeCodexVersion: 'y',
      versionMismatch: true, permissionProfile: ':workspace', hostPreflight: { passed: true }, smoke: { passed: true, commandExitCode: 0, setupFailure: false, stderr: '' },
      probes: [{ id: 'p', label: 'p', method: 'node', location: 'outside', expected: 'RETAINED', observed: 'RETAINED', assessment: 'PASS', commandExitCode: 1, denialEvidence: true, stderr: 'C:\\Users\\Alice\\secret.txt access denied' }],
      error: null,
    },
  };
  const payload = buildSupportPayload(report, { LOCALAPPDATA: 'C:\\Users\\Alice\\AppData\\Local', APPDATA: 'C:\\Users\\Alice\\AppData\\Roaming', CODEX_HOME: 'C:\\Users\\Alice\\.codex' });
  const serialized = JSON.stringify(payload);
  assert.doesNotMatch(serialized, /Alice/);
  assert.doesNotMatch(serialized, /activeCodexPath|ruleFiles/);
  assert.match(renderSupportReport(payload), /additional rule coverage only/i);
});

test('share-safe sanitization replaces known paths and usernames case-insensitively', () => {
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    summary: { recommendations: [], execpolicyCoverage: { status: 'NOT_RUN', matched: null, total: null } },
    inventory: {
      platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true,
      elevated: false, codexInstalled: true, codexVersion: 'x', activeBundle: { complete: true, missing: [] },
      matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [], sandboxWindowsState: 'AVAILABLE',
      config: { sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
    },
    execpolicy: [{
      id: 'x', label: 'x', status: 'ERROR', decision: null,
      error: 'c:\\users\\alice\\.CODEX\\rules\\default.rules belongs to ALICE',
    }],
    sandbox: null,
  };
  const payload = buildSupportPayload(report, {
    CODEX_HOME: 'C:\\Users\\Alice\\.codex',
    LOCALAPPDATA: 'C:\\Users\\Alice\\AppData\\Local',
    APPDATA: 'C:\\Users\\Alice\\AppData\\Roaming',
  });
  const serialized = JSON.stringify(payload);
  assert.doesNotMatch(serialized, /Alice/i);
  assert.match(serialized, /%CODEX_HOME%|\[USER\]/);
});

test('share-safe sanitization redacts report-scoped project paths and cleanup text', () => {
  const projectRoot = 'C:\\Users\\Alice\\Documents\\Codex-Lokal\\Projekte\\codex-safety-canary-v0.1.0-alpha.10';
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    summary: { recommendations: [], execpolicyCoverage: { status: 'COMPLETED', matched: 0, total: 1 } },
    inventory: {
      platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true,
      elevated: false, codexInstalled: true, codexVersion: 'x', activeBundle: { complete: true, missing: [] },
      matchingCompleteBundles: [], newerCompleteBundles: [], codexHome: 'C:\\Users\\Alice\\.codex',
      ruleFiles: [path.join(projectRoot, 'README.md')], sandboxWindowsState: 'AVAILABLE',
      config: { path: 'C:\\Users\\Alice\\.codex\\config.toml', sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
    },
    execpolicy: [{
      id: 'x', label: 'x', status: 'ERROR', decision: null,
      error: `Project path ${path.join(projectRoot, 'README.md')} belongs to Alice`,
    }],
    sandbox: { cleanup: `Cleaned ${projectRoot}`, probes: [], status: 'COMPLETED' },
  };
  const payload = buildSupportPayload(report, {
    CODEX_HOME: 'C:\\Users\\Alice\\.codex',
    LOCALAPPDATA: 'C:\\Users\\Alice\\AppData\\Local',
    APPDATA: 'C:\\Users\\Alice\\AppData\\Roaming',
  });
  const serialized = JSON.stringify(payload);
  assert.doesNotMatch(serialized, /Alice/i);
  assert.doesNotMatch(serialized, /Codex-Lokal/i);
  assert.doesNotMatch(serialized, /codex-safety-canary-v0\.1\.0-alpha\.10/i);
  assert.match(serialized, /%LOCAL_PATH%/);
});

test('writeReport creates detailed and share-safe report files', () => {
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-report-'));
  const inventory = {
    platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true,
    elevated: false, codexInstalled: true, codexVersion: 'x', activeCodexPath: null,
    activeBundle: { complete: true, missing: [] }, matchingCompleteBundles: [], newerCompleteBundles: [],
    codexHome: 'x', authFilePresent: false, ruleFiles: [], sandboxWindowsState: 'AVAILABLE', sandboxHelpError: null,
    config: { exists: false, path: 'x', sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
  };
  const result = writeReport({ inventory, appRoot });
  assert.equal(fs.existsSync(result.txtPath), true);
  assert.equal(fs.existsSync(result.jsonPath), true);
  assert.equal(fs.existsSync(result.supportTxtPath), true);
  assert.equal(fs.existsSync(result.supportJsonPath), true);
  const latest = JSON.parse(fs.readFileSync(path.join(appRoot, 'reports', 'latest.json'), 'utf8'));
  assert.equal(latest.supportTxtPath, result.supportTxtPath);
  fs.rmSync(appRoot, { recursive: true, force: true });
});
test('detached process launcher waits for spawn before unref', async () => {
  const events = [];
  const resultPromise = launchDetachedProcess('notepad.exe', ['C:/tmp/report.txt'], {
    spawnImpl(command, args, options) {
      events.push({ command, args, options });
      const child = new EventEmitter();
      child.unref = () => events.push('unref');
      queueMicrotask(() => child.emit('spawn'));
      return child;
    },
  });
  assert.deepEqual(events.map((item) => typeof item === 'string' ? item : item.command), ['notepad.exe']);
  const result = await resultPromise;
  assert.equal(result.ok, true);
  assert.equal(events.includes('unref'), true);
  assert.deepEqual(result.options, { detached: true, stdio: 'ignore', shell: false, windowsHide: false });
});

test('detached process launcher permits explicit GUI visibility options', async () => {
  const resultPromise = launchDetachedProcess('notepad.exe', ['C:/tmp/report.txt'], {
    windowsHide: false,
    spawnImpl(command, args, options) {
      const child = new EventEmitter();
      child.unref = () => {};
      queueMicrotask(() => child.emit('spawn'));
      return child;
    },
  });
  const result = await resultPromise;
  assert.equal(result.ok, true);
  assert.equal(result.options.windowsHide, false);
});

test('detached process launcher reports async start errors visibly', async () => {
  const resultPromise = launchDetachedProcess('notepad.exe', ['C:/tmp/report.txt'], {
    spawnImpl() {
      const child = new EventEmitter();
      child.unref = () => assert.fail('unref must not be called on failed start');
      queueMicrotask(() => child.emit('error', new Error('blocked')));
      return child;
    },
  });
  const result = await resultPromise;
  assert.equal(result.ok, false);
  assert.match(result.error, /blocked/);
});

test('execpolicy coverage is structured and formats NOT RUN or x/y', () => {
  const notRun = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true } }, [], null, { execpolicyRun: false });
  assert.deepEqual(notRun.execpolicyCoverage, { status: 'NOT_RUN', matched: null, total: null });
  assert.equal(formatExecpolicyCoverage(notRun.execpolicyCoverage), 'NOT RUN');
  const completed = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true } }, [{ decision: null }, { decision: 'prompt' }], null, { execpolicyRun: true });
  assert.deepEqual(completed.execpolicyCoverage, { status: 'COMPLETED', matched: 1, total: 2 });
  assert.equal(formatExecpolicyCoverage(completed.execpolicyCoverage), '1/2');
});

test('declined live probes use a dedicated diagnostic and mode-specific coverage', () => {
  const guidedDeclined = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [{ decision: null }], null, { assessmentMode: ASSESSMENT_MODES.GUIDED_LIVE_PROBES_SKIPPED, execpolicyRun: true, boundaryAssessmentDeclined: true });
  assert.equal(guidedDeclined.overall, 'PARTIAL / LIVE PROBES DECLINED');
  assert.equal(guidedDeclined.sandboxRuntime, 'NOT RUN');
  assert.equal(guidedDeclined.boundary, 'NOT TESTED');
  assert.equal(guidedDeclined.methodCoverage, 'NOT RUN');
  assert.equal(formatExecpolicyCoverage(guidedDeclined.execpolicyCoverage), '0/1');
  assert.equal(guidedDeclined.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
  assert.equal(guidedDeclined.recommendations.some((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE'), false);
  assert.equal(guidedDeclined.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);

  const sandboxDeclined = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], null, { assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY_LIVE_PROBES_SKIPPED, boundaryAssessmentDeclined: true });
  assert.equal(sandboxDeclined.overall, 'BOUNDARY ASSESSMENT DECLINED');
  assert.equal(sandboxDeclined.sandboxRuntime, 'NOT RUN');
  assert.equal(sandboxDeclined.boundary, 'NOT TESTED');
  assert.equal(sandboxDeclined.methodCoverage, 'NOT RUN');
  assert.equal(formatExecpolicyCoverage(sandboxDeclined.execpolicyCoverage), 'NOT RUN');
  assert.equal(sandboxDeclined.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
  assert.equal(sandboxDeclined.recommendations.some((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE'), false);
});

test('configuration and execpolicy-only modes report boundary as intentionally not assessed', () => {
  const configurationOnly = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false });
  assert.equal(configurationOnly.recommendations.find((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE')?.severity, 'INFO');
  assert.equal(configurationOnly.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);

  const execpolicyOnly = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [{ decision: null }], null, { assessmentMode: ASSESSMENT_MODES.EXECPOLICY_ONLY, execpolicyRun: true });
  assert.equal(execpolicyOnly.recommendations.find((item) => item.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE')?.severity, 'INFO');
  assert.equal(execpolicyOnly.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);
});

test('recommendation severities follow the alpha-10 diagnostic matrix', () => {
  const activePass = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], {
    status: 'COMPLETED', codexSource: 'ACTIVE_CLI', probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(activePass.recommendations.find((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS')?.severity, 'INFO');

  const alternativePass = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: false }, codexVersion: 'x' }, [], {
    status: 'COMPLETED', codexSource: 'NEWER_COMPLETE_BUNDLE', versionMismatch: true, testedCodexVersion: 'y', activeCodexVersion: 'x', probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(alternativePass.recommendations.find((item) => item.code === 'ALTERNATIVE_BUNDLE_BOUNDARY_PASS')?.severity, 'INFO');
  assert.equal(alternativePass.recommendations.find((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE')?.severity, 'ACTION_RECOMMENDED');

  const setupFailed = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED' }, [], { status: 'SETUP_FAILED', probes: [] });
  assert.equal(setupFailed.recommendations.find((item) => item.code === 'SANDBOX_SETUP_FAILED')?.severity, 'ACTION_RECOMMENDED');
  assert.equal(setupFailed.recommendations.find((item) => item.code === 'BOUNDARY_NOT_CONFIRMED')?.severity, 'PROTECTION_NOT_CONFIRMED');
  const invalidControl = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], {
    status: 'COMPLETED', codexSource: 'ACTIVE_CLI', probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  });
  assert.equal(invalidControl.recommendations.find((item) => item.code === 'BOUNDARY_NOT_CONFIRMED')?.severity, 'PROTECTION_NOT_CONFIRMED');

  const gap = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], {
    status: 'COMPLETED', codexSource: 'ACTIVE_CLI', probes: [
      { method: 'powershell', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'powershell', location: 'outside', assessment: 'CRITICAL_GAP', observed: 'DELETED' },
    ],
  });
  assert.equal(gap.recommendations.find((item) => item.code === 'BOUNDARY_GAP')?.severity, 'POTENTIAL_SECURITY_GAP');

  const noRules = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [{ decision: null }], null, { execpolicyRun: true });
  assert.equal(noRules.recommendations.find((item) => item.code === 'EXECPOLICY_NO_RESTRICTIVE_MATCHES')?.severity, 'OPTIONAL_HARDENING');
});

test('diagnostic recommendation formatter includes every shared field', () => {
  const summary = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false });
  const text = formatDiagnosticRecommendationLines(summary.recommendations).join('\n');
  const item = summary.recommendations.find((recommendation) => recommendation.code === 'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE');
  assert.match(text, new RegExp(`${item.severity} ${item.code}`));
  assert.match(text, new RegExp(item.title));
  assert.match(text, new RegExp(item.message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(text, new RegExp(item.recommendation.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('release inputs and local diff artifacts are ignored', () => {
  const ignore = fs.readFileSync(new URL('../.gitignore', import.meta.url), 'utf8');
  assert.match(ignore, /^_local-review-input\/$/m);
  assert.match(ignore, /^codex-safety-canary-alpha\*\.diff$/m);
});
test('detail and support reports share diagnostic recommendations', () => {
  const inventory = {
    release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true, elevated: false,
    codexInstalled: true, codexVersion: 'x', activeCodexPath: 'C:/Users/Alice/codex.exe', codexHome: 'C:/Users/Alice/.codex', authFilePresent: false,
    activeBundle: { complete: false, missing: ['codex-windows-sandbox-setup.exe'] }, matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [],
    sandboxWindowsState: 'AVAILABLE', config: { exists: false, path: 'x', sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
  };
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
    summary: summarizeAssessment(inventory, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false }),
    inventory,
    execpolicy: [],
    sandbox: null,
  };
  const support = buildSupportPayload(report, { CODEX_HOME: 'C:/Users/Alice/.codex' });
  const detailText = renderTextReport(report);
  const supportText = renderSupportReport(support);
  const diagnosticLabels = report.summary.recommendations.map((item) => `${item.severity} ${item.code}`);
  for (const label of diagnosticLabels) {
    assert.match(detailText, new RegExp(label));
    assert.match(supportText, new RegExp(label));
    assert.deepEqual(support.recommendations.find((item) => `${item.severity} ${item.code}` === label), report.summary.recommendations.find((item) => `${item.severity} ${item.code}` === label));
  }
});
