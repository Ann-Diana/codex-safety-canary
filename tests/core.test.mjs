import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import {
  ASSESSMENT_MODES,
  buildSandboxCommandArgs,
  canRunLiveSandboxProbes,
  formatDiagnosticRecommendationLines,
  formatExecpolicyCoverage,
  launchDetachedProcess,
  detectWindowsSandboxFeature,
  deduplicateStandalonePackageCandidates,
  discoverCodexBundlePaths,
  inventoryAlternativeCodexExecutables,
  diagnoseExplicitlySelectedCodexExecutable,
  getCodexInventory,
  discoverStandalonePackages,
  inspectCodexBundle,
  invokeCodex,
  normalizeCodexVersion,
  compareCodexVersions,
  selectCodexProbePlan,
  findCommandPath,
  findDecision,
  parseExecpolicyOutput,
  isPathInside,
  listRuleFiles,
  readSafeConfigSummary,
  renderTextReport,
  safeRemoveRun,
  detectSandboxSetupFailure,
  detectSandboxHelperResolutionFailure,
  detectCommandRunnerProcessCreationFailure,
  buildSandboxRuntimeEvidence,
  deriveSandboxRuntimeObservation,
  buildRuntimeDiagnostics,
  createCodexDoctorInventoryStatus,
  authFileExists,
  parseCodexDoctorOutput,
  parseStandaloneReleaseVersion,
  summarizeAssessment,
  summarizeExecutableBundles,
  canonicalExistingPathKey,
  normalizeDiscoveryPathForComparison,
  resolveFilesystemIdentity,
  detectAccessDenied,
  canonicalizeWindowsPath,
  sameWindowsPath,
  classifySandboxProbe,
  buildNodeDeleteCommand,
  buildPowerShellDeleteCommand,
  runHostDeletionPreflight,
  runMethodHostCalibrations,
  runSandboxCommand,
  runSandboxProbes,
  boundaryProbeProcessMarkersAreComplete,
  boundaryProbeProcessStartEvidence,
  formatBoundaryProbeProcessStartEvidence,
  formatSmokeProcessStartEvidence,
  processStartEvidenceStatus,
  createBoundaryProbeRecord,
  finalizeSandboxProbeRun,
  validateStandaloneResourceBinding,
  validateSelectedExecutableBinding,
  buildSupportPayload,
  SHARE_SAFE_SHARING_NOTICE,
  formatShareSafeSharingNotice,
  renderSupportReport,
  writeReport,
} from '../lib/core.mjs';

const TEST_SANDBOX_COMMAND_CONTRACT = Object.freeze({
  syntax: 'GENERIC_PERMISSION_PROFILE',
  supported: true,
  usageLine: 'Usage: codex sandbox [OPTIONS] [COMMAND]...',
  commandArgumentsSupported: true,
  permissionProfileSupported: true,
  workingDirectorySupported: true,
  fullAutoAvailable: true,
  reason: null,
});
const ACTIVE_EXECUTABLE_IDENTITY = 'synthetic-active-cli-identity';
const TESTED_EXECUTABLE_IDENTITY = 'synthetic-tested-bundle-identity';
const TEST_RUN_MARKER = 'synthetic-boundary-run-marker';

function filesystemAlternative(executablePath, derivedVersion = null, extra = {}) {
  return {
    executablePath,
    probeEligible: true,
    resourceLayout: 'COMPLETE',
    derivedVersion,
    versionEvidenceSource: derivedVersion ? 'PACKAGE_METADATA' : 'UNKNOWN',
    filesystemIdentity: { status: 'PROVEN', key: `synthetic:${executablePath}`, canonicalPath: executablePath },
    filesystemDiscovery: 'DISCOVERED',
    selectionStatus: 'NOT_SELECTED',
    diagnosticStatus: 'NOT_RUN',
    versionConfirmedByExecution: false,
    tested: false,
    ...extra,
  };
}

function completeBoundaryProbes({ gapMethod = null } = {}) {
  return ['powershell', 'cmd', 'node'].flatMap((method) => {
    const insideId = `inside-workspace-${method}`;
    const outsideId = `outside-workspace-${method}`;
    const gap = method === gapMethod;
    return [
    {
      id: insideId, method, reportedRuntime: method, location: 'inside', assessment: 'EXPECTED', observed: 'DELETED', targetId: insideId,
      codexProcessStarted: true, runMarker: TEST_RUN_MARKER, codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
      commandStarted: true, operationAttempted: true, hostCalibrationStatus: 'PASS', targetIdentityStatus: 'MATCHED', errorTargetMatched: false,
      targetIdentityMatched: true,
      fileExistedBefore: true, fileExistsAfter: false, unrelatedFailureDetected: false,
    },
    {
      id: outsideId,
      method,
      reportedRuntime: method,
      location: 'outside',
      assessment: gap ? 'CRITICAL_GAP' : 'PASS',
      observed: gap ? 'DELETED' : 'RETAINED',
      targetId: outsideId,
      codexProcessStarted: true,
      runMarker: TEST_RUN_MARKER,
      codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
      commandStarted: true,
      operationAttempted: true,
      hostCalibrationStatus: 'PASS',
      targetIdentityStatus: 'MATCHED',
      targetIdentityMatched: true,
      errorTargetMatched: !gap,
      fileExistedBefore: true,
      fileExistsAfter: !gap,
      unrelatedFailureDetected: false,
    },
  ];
  });
}

function completedBoundarySandbox(overrides = {}) {
  const {
    marker = TEST_RUN_MARKER,
    codexExecutableIdentity = ACTIVE_EXECUTABLE_IDENTITY,
    probes: suppliedProbes = completeBoundaryProbes(),
    ...remainingOverrides
  } = overrides;
  const probes = suppliedProbes.map((probe) => {
    const method = probe.method === 'cmd.exe' ? 'cmd' : probe.method === 'node.js' ? 'node' : probe.method;
    const id = `${probe.location}-workspace-${method}`;
    return {
      id,
      targetId: id,
      reportedRuntime: method,
      codexProcessStarted: true,
      runMarker: marker,
      codexExecutableIdentity,
      ...probe,
    };
  });
  return {
    status: 'COMPLETED',
    codexSource: 'ACTIVE_CLI',
    codexProcessStarted: true,
    marker,
    codexExecutableIdentity,
    hostPreflight: { passed: true, filesChecked: 2 },
    hostCalibrations: ['powershell', 'cmd', 'node'].map((method) => ({ method, status: 'PASS', passed: true })),
    smoke: { passed: true, commandExitCode: 0, setupFailure: false, codexProcessStarted: true, stderr: '' },
    probes,
    cleanup: {
      status: 'COMPLETED', attempted: true, completed: true, errorPresent: false,
      message: 'Disposable run folder removed before final reports were written.',
    },
    ...remainingOverrides,
  };
}

function producerBoundarySandbox(overrides = {}) {
  const marker = overrides.marker || TEST_RUN_MARKER;
  const codexExecutableIdentity = overrides.codexExecutableIdentity || ACTIVE_EXECUTABLE_IDENTITY;
  const probes = ['powershell', 'cmd', 'node'].flatMap((method) => ['inside', 'outside'].map((location) => {
    const id = `${location}-workspace-${method}`;
    const classification = classifyStructuredProbe(method, location);
    return createBoundaryProbeRecord({
      definition: {
        id,
        label: `${method} synthetic ${location}`,
        method,
        location,
        file: `C:\\Canary\\${method}-${location}.txt`,
        meaning: 'Synthetic producer-to-consumer process evidence.',
      },
      method,
      expected: location === 'inside' ? 'DELETED' : 'RETAINED',
      after: location === 'outside',
      result: { status: classification.exitCode, stdout: '', stderr: '', codexProcessStarted: true },
      classification,
      runMarker: marker,
      codexExecutableIdentity,
    });
  }));
  return finalizeSandboxProbeRun({
    status: 'COMPLETED',
    codexSource: 'ACTIVE_CLI',
    marker,
    codexExecutableIdentity,
    hostPreflight: { passed: true, filesChecked: 2 },
    hostCalibrations: ['powershell', 'cmd', 'node'].map((method) => ({ method, status: 'PASS', passed: true })),
    smoke: { passed: true, commandExitCode: 0, setupFailure: false, codexProcessStarted: true, stderr: '' },
    probes,
    cleanup: { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false },
    ...overrides,
  });
}

function syntheticReportInventory() {
  return {
    platform: 'win32', release: 'synthetic', nodeVersion: process.version, nodeRuntimeSource: 'TEST',
    nodeInPath: true, npmInPath: true, elevated: false, codexInstalled: true,
    codexVersion: 'codex-cli synthetic', activeCodexPath: null,
    activeBundle: { complete: true, installType: 'classic', resourceLayout: 'COMPLETE', missing: [] },
    matchingCompleteBundles: [], newerCompleteBundles: [], standalonePackages: [],
    codexHome: 'synthetic', authFilePresent: false, ruleFiles: [], sandboxWindowsState: 'AVAILABLE', sandboxHelpError: null,
    config: { exists: false, path: 'synthetic', sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
  };
}

function failedCleanup(message = 'Could not remove disposable run folder.') {
  return { status: 'FAILED', attempted: true, completed: false, errorPresent: true, message };
}

function pngCrc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function readPngChunks(file) {
  const data = fs.readFileSync(file);
  assert.deepEqual(data.subarray(0, 8), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const chunks = [];
  let offset = 8;
  while (offset < data.length) {
    assert.ok(offset + 12 <= data.length, `truncated PNG chunk in ${file}`);
    const length = data.readUInt32BE(offset);
    const typeBytes = data.subarray(offset + 4, offset + 8);
    const payload = data.subarray(offset + 8, offset + 8 + length);
    const expectedCrc = data.readUInt32BE(offset + 8 + length);
    assert.equal(pngCrc32(Buffer.concat([typeBytes, payload])), expectedCrc, `invalid PNG CRC in ${file}`);
    const type = typeBytes.toString('ascii');
    chunks.push({ type, payload });
    offset += 12 + length;
    if (type === 'IEND') break;
  }
  assert.equal(chunks.at(-1)?.type, 'IEND', `missing PNG IEND in ${file}`);
  assert.equal(offset, data.length, `trailing PNG data in ${file}`);
  return chunks;
}

function structuredProbeResult({
  runtime,
  targetId,
  targetPath,
  status,
  succeeded,
  errorClass = null,
  errorCode = null,
  errorCategory = null,
  errorTarget = null,
  errorReason = null,
  errorHResult = null,
  nativeWin32ErrorCode = null,
  exceptionType = null,
  errorMessage = null,
  errorSyscall = runtime === 'node' ? 'rm' : null,
  errorCommand = null,
  errorActivity = null,
  operation = runtime === 'node' ? 'fs.rmSync' : runtime === 'powershell' ? 'System.IO.File.Delete' : null,
  operationTarget = targetPath,
  targetState = null,
  stderr = '',
  operationOutput = null,
}) {
  const record = JSON.stringify({
    codexSafetyCanaryProbe: 1,
    runtime,
    targetId,
    targetPath,
    commandStarted: true,
    operationAttempted: true,
    succeeded,
    errorClass,
    errorCode,
    errorCategory,
    errorTarget,
    errorReason,
    errorHResult,
    nativeWin32ErrorCode,
    exceptionType,
    errorMessage,
    errorSyscall,
    errorCommand,
    errorActivity,
    operation,
    operationTarget,
    targetState,
    exitCode: status,
  });
  const stdout = operationOutput == null
    ? `${record}\n`
    : `CODEX_CANARY_CMD_OUTPUT_BEGIN:${targetId}\n${operationOutput}\nCODEX_CANARY_CMD_OUTPUT_END:${targetId}\n${record}\n`;
  return {
    status,
    stdout,
    stderr,
  };
}

function classifyStructuredProbe(method, location, options = {}) {
  const targetPath = `C:\\Canary\\${method}-${location}.txt`;
  const targetId = `${location}-workspace-${method}`;
  const expected = location === 'inside' ? 'DELETED' : 'RETAINED';
  const definition = { id: targetId, file: targetPath, expected, location, method };
  if (location === 'inside' || options.gap === true) {
    return {
      method,
      location,
      observed: 'DELETED',
      ...classifySandboxProbe({
        before: true,
        after: false,
        definition,
        result: structuredProbeResult({ runtime: method, targetId, targetPath, status: 0, succeeded: true, targetState: 'DELETED' }),
        hostCalibration: { method, status: 'PASS', passed: true },
      }),
    };
  }
  const access = method === 'node'
    ? { errorClass: 'Error', errorCode: 'EACCES', errorTarget: targetPath }
    : method === 'powershell'
      ? { exceptionType: 'System.UnauthorizedAccessException', errorClass: 'System.UnauthorizedAccessException', errorCategory: 'PermissionDenied', errorTarget: targetPath }
      : { targetState: 'RETAINED', operationOutput: 'Access is denied.' };
  return {
    method,
    location,
    observed: 'RETAINED',
    ...classifySandboxProbe({
      before: true,
      after: true,
      definition,
      result: structuredProbeResult({ runtime: method, targetId, targetPath: method === 'cmd' ? null : targetPath, status: 1, succeeded: false, ...access }),
      hostCalibration: { method, status: 'PASS', passed: true },
    }),
  };
}

test('findDecision handles common execpolicy shapes', () => {
  assert.equal(findDecision({ decision: 'prompt' }), 'prompt');
  assert.equal(findDecision({ result: { strictest_decision: 'forbidden' } }), 'forbidden');
  assert.equal(findDecision({ nested: [{ decision: 'allowed' }] }), null);
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

test('execpolicy parser accepts only recognized aggregate decisions', () => {
  for (const decision of ['allow', 'prompt', 'forbidden']) {
    const result = parseExecpolicyOutput({ decision });
    assert.equal(result.status, 'OK');
    assert.equal(result.decision, decision);
  }
  assert.equal(parseExecpolicyOutput({ decision: 'unexpected' }).status, 'UNKNOWN_SCHEMA');
  const strictest = parseExecpolicyOutput({ decision: 'allow', strictestDecision: 'forbidden' });
  assert.equal(strictest.status, 'OK');
  assert.equal(strictest.decision, 'forbidden');
  assert.equal(parseExecpolicyOutput({ decision: 'allow', strictestDecision: 'future-decision' }).status, 'UNKNOWN_SCHEMA');
});

test('execpolicy parser ignores arbitrary nested decisions and is order independent', () => {
  const allowFirst = parseExecpolicyOutput({ metadata: { first: 'allow', later: 'forbidden' } });
  const forbiddenFirst = parseExecpolicyOutput({ metadata: { first: 'forbidden', later: 'allow' } });
  assert.equal(allowFirst.status, 'UNKNOWN_SCHEMA');
  assert.equal(allowFirst.decision, null);
  assert.equal(forbiddenFirst.status, 'UNKNOWN_SCHEMA');
  assert.equal(forbiddenFirst.decision, null);
});

test('execpolicy matched-rule fallback computes the strictest known decision', () => {
  const first = parseExecpolicyOutput({
    matchedRules: [
      { prefixRuleMatch: { decision: 'allow' } },
      { prefixRuleMatch: { decision: 'forbidden' } },
      { prefixRuleMatch: { decision: 'prompt' } },
    ],
  });
  const reversed = parseExecpolicyOutput({ matchedRules: [...first.parsed.matchedRules].reverse() });
  assert.equal(first.status, 'OK');
  assert.equal(first.decision, 'forbidden');
  assert.equal(reversed.status, 'OK');
  assert.equal(reversed.decision, 'forbidden');
  const aggregateConflict = parseExecpolicyOutput({ decision: 'allow', matchedRules: [{ prefixRuleMatch: { decision: 'forbidden' } }] });
  assert.equal(aggregateConflict.status, 'OK');
  assert.equal(aggregateConflict.decision, 'forbidden');
  const withinRule = parseExecpolicyOutput({ matchedRules: [{ decision: 'allow', strictestDecision: 'prompt' }] });
  assert.equal(withinRule.status, 'OK');
  assert.equal(withinRule.decision, 'prompt');
  assert.equal(parseExecpolicyOutput({ matchedRules: [{ prefixRuleMatch: { decision: 'unknown' } }] }).status, 'UNKNOWN_SCHEMA');
});

test('path containment rejects siblings', () => {
  const root = path.resolve('/tmp/root');
  assert.equal(isPathInside(path.join(root, 'a'), root), true);
  assert.equal(isPathInside(path.resolve('/tmp/root-other'), root), false);
});

test('Windows command lookup falls back through a process-local PowerShell lookup value', () => {
  const calls = [];
  const resolved = findCommandPath('synthetic-tool.exe', {
    platform: 'win32',
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      if (command === 'where.exe') return { status: 1, stdout: '', stderr: 'not found' };
      return { status: 0, stdout: 'C:\\Synthetic Tools\\synthetic-tool.exe', stderr: '' };
    },
  });
  assert.equal(resolved, 'C:\\Synthetic Tools\\synthetic-tool.exe');
  assert.equal(calls[1].command, 'powershell.exe');
  assert.equal(calls[1].args.at(-1).includes('Get-Command -Name $name'), true);
  assert.equal(calls[1].options.env.CANARY_COMMAND_LOOKUP, 'synthetic-tool.exe');
  assert.equal(calls[1].args.includes('synthetic-tool.exe'), false);
});

test('Windows Codex wrapper proves the executable start separately from the wrapper process', () => {
  const wrapperOnly = invokeCodex(['sandbox', '--help'], {
    platform: 'win32',
    codexExe: 'C:\\Synthetic\\codex.exe',
    spawnSync: () => ({ status: 127, stdout: '', stderr: 'could not start executable\r\n', error: null }),
  });
  assert.equal(wrapperOnly.codexProcessStarted, false);
  assert.equal(wrapperOnly.stderr, 'could not start executable\r\n');

  const spoofedByErrorPath = invokeCodex(['sandbox', '--help'], {
    platform: 'win32',
    codexExe: 'C:\\Synthetic\\codex.exe',
    spawnSync: () => ({
      status: 127,
      stdout: '',
      stderr: 'Could not start C:\\__CODEX_SAFETY_CANARY_EXECUTABLE_STARTED__\\codex.exe\r\n',
      error: null,
    }),
  });
  assert.equal(spoofedByErrorPath.codexProcessStarted, false);
  assert.match(spoofedByErrorPath.stderr, /__CODEX_SAFETY_CANARY_EXECUTABLE_STARTED__/);

  const childStarted = invokeCodex(['sandbox', '--help'], {
    platform: 'win32',
    codexExe: 'C:\\Synthetic\\codex.exe',
    spawnSync: () => ({
      status: 127,
      stdout: '',
      stderr: 'native diagnostic\r\n__CODEX_SAFETY_CANARY_EXECUTABLE_STARTED__\r\n',
      error: null,
    }),
  });
  assert.equal(childStarted.codexProcessStarted, true);
  assert.equal(childStarted.stderr, 'native diagnostic\r\n');
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

test('empty sandbox result without a Codex process remains not tested', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], { codexSource: 'ACTIVE_CLI', probes: [] });
  assert.equal(summary.overall, 'PARTIAL / NOT FULLY TESTED');
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.methodCoverage, 'NOT RUN');
  assert.equal(summary.testedBundle, null);
});
test('windows sandbox detection reports AVAILABLE from general sandbox help', () => {
  const result = detectWindowsSandboxFeature({
    status: 0,
    stdout: 'Usage: codex sandbox [OPTIONS] [COMMAND]...\nOptions:\n  -P, --permission-profile <NAME>\n  -C, --cd <DIR>\n  --full-auto',
    stderr: '',
  });
  assert.equal(result.state, 'AVAILABLE');
  assert.equal(result.available, true);
  assert.equal(result.fullAutoAvailable, true);
  assert.equal(result.commandContract.syntax, 'GENERIC_PERMISSION_PROFILE');
});

test('windows sandbox detection rejects help that does not prove the runtime syntax contract', () => {
  const result = detectWindowsSandboxFeature({
    status: 0,
    stdout: 'Usage: codex sandbox windows -- <COMMAND>',
    stderr: '',
  });
  assert.equal(result.state, 'UNSUPPORTED');
  assert.equal(result.available, false);
  assert.equal(result.commandContract.syntax, 'UNKNOWN');
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
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'AVAILABLE', sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT }), true);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'AVAILABLE' }), false);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED' }), false);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'UNSUPPORTED' }), false);
  assert.equal(canRunLiveSandboxProbes({ sandboxWindowsState: 'DETECTION_ERROR' }), false);
});

test('sandbox command builder uses the explicit workspace permission profile and directory', () => {
  const workspace = path.resolve('C:/Synthetic Workspace');
  assert.deepEqual(buildSandboxCommandArgs(['node', '--version'], { workspaceDir: workspace, commandContract: TEST_SANDBOX_COMMAND_CONTRACT }), ['sandbox', '--permission-profile', ':workspace', '--cd', workspace, '--', 'node', '--version']);
  assert.deepEqual(buildSandboxCommandArgs(['node', '--version'], { permissionProfile: ':read-only', workspaceDir: workspace, commandContract: TEST_SANDBOX_COMMAND_CONTRACT }), ['sandbox', '--permission-profile', ':read-only', '--cd', workspace, '--', 'node', '--version']);
  assert.deepEqual(buildSandboxCommandArgs(['node', '--version'], { workspaceDir: workspace, commandContract: TEST_SANDBOX_COMMAND_CONTRACT, fullAuto: true }), ['sandbox', '--full-auto', '--permission-profile', ':workspace', '--cd', workspace, '--', 'node', '--version']);
  assert.throws(() => buildSandboxCommandArgs(['node'], { workspaceDir: workspace }), /verified generic sandbox command contract/);
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
  assert.match(text, /Sandbox command state:\s+DETECTION_ERROR/);
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
  assert.equal(result.resourceLayout, 'COMPLETE');
  assert.equal(result.probeEligible, true);
  assert.equal(result.helperResolution, 'NOT_TESTED');
  assert.equal(result.runtimeStartup, 'NOT_TESTED');
  assert.equal(result.helperResolutionProven, false);
  assert.deepEqual(result.missing, []);
  const summary = summarizeAssessment({ codexVersion: 'codex-cli 0.146.0', activeBundle: result, config: { warnings: [] } }, [], null, {
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
    execpolicyRun: false,
  });
  assert.equal(summary.activeCli.resourceLayout, 'COMPLETE');
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'NOT_TESTED');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  fs.rmSync(temp, { recursive: true, force: true });
});

test('version normalization compares codex-cli versions without surrounding text', () => {
  assert.equal(normalizeCodexVersion('codex-cli 0.145.0'), '0.145.0');
  assert.equal(normalizeCodexVersion('Codex 1.2.3-beta'), '1.2.3-beta');
});

test('probe plan prefers the active complete CLI bundle', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: true, probeEligible: true, installType: 'classic', resourceLayout: 'COMPLETE', helperResolution: 'CONFIRMED', runtimeStartup: 'NOT_TESTED' },
    sandboxFullAutoAvailable: true,
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, false);
  assert.equal(plan.requiresSelection, false);
  assert.deepEqual(plan.candidates.map((candidate) => candidate.source), ['ACTIVE_CLI']);
  assert.equal(plan.source, 'ACTIVE_CLI');
  assert.equal(plan.fullAutoAvailable, true);
});

test('probe plan exposes active and same-version alternative executables for explicit selection', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: true, probeEligible: true, resourceLayout: 'COMPLETE' },
    sandboxFullAutoAvailable: true,
    alternativeExecutables: [filesystemAlternative('C:\\matching\\codex.exe', 'codex-cli 0.145.0')],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresSelection, true);
  assert.deepEqual(plan.candidates.map((candidate) => candidate.source), ['ACTIVE_CLI', 'ALTERNATIVE_EXECUTABLE']);
  assert.equal(plan.candidates[1].derivedVersionRelation, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(plan.candidates[1].isAlternativeExecutable, true);
  assert.match(plan.candidates[1].scopeNote, /not been selected, started, tested.*validate the active PATH CLI/i);
  assert.equal(plan.candidates[1].testedVersion, null);
  assert.equal(plan.candidates[1].sandboxState, 'NOT_RUN');
});

test('probe plan exposes active and newer alternative executables with a version warning state', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: true, probeEligible: true, resourceLayout: 'COMPLETE' },
    alternativeExecutables: [filesystemAlternative('C:\\newer\\codex.exe', 'codex-cli 0.146.0-alpha.3.1')],
  });
  assert.equal(plan.requiresSelection, true);
  assert.deepEqual(plan.candidates.map((candidate) => candidate.source), ['ACTIVE_CLI', 'ALTERNATIVE_EXECUTABLE']);
  assert.equal(plan.candidates[1].derivedVersionRelation, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(plan.candidates[1].derivedVersionMismatch, true);
  assert.equal(plan.candidates[1].versionMismatch, false);
  assert.equal(plan.candidates[1].displayedVersion, 'codex-cli 0.146.0-alpha.3.1');
  assert.match(plan.candidates[1].scopeNote, /not been selected, started, tested/i);
});

test('probe plan exposes all three candidate classes in recommended order', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: true, probeEligible: true, resourceLayout: 'COMPLETE' },
    alternativeExecutables: [
      filesystemAlternative('C:\\matching\\codex.exe', 'codex-cli 0.145.0'),
      filesystemAlternative('C:\\newer\\codex.exe', 'codex-cli 0.146.0'),
    ],
  });
  assert.deepEqual(plan.candidates.map((candidate) => candidate.source), [
    'ACTIVE_CLI', 'ALTERNATIVE_EXECUTABLE', 'ALTERNATIVE_EXECUTABLE',
  ]);
  assert.deepEqual(plan.candidates.slice(1).map((candidate) => candidate.derivedVersionRelation), [
    'MATCHING_COMPLETE_BUNDLE', 'NEWER_COMPLETE_BUNDLE',
  ]);
});

test('probe plan deduplicates an executable reached through a junction alias and its real path', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-probe-plan-alias-'));
  const releaseDir = path.join(temp, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const releaseBin = path.join(releaseDir, 'bin');
  const currentDir = path.join(temp, 'current');
  fs.mkdirSync(releaseBin, { recursive: true });
  fs.writeFileSync(path.join(releaseBin, 'codex.exe'), 'synthetic');
  fs.symlinkSync(releaseDir, currentDir, process.platform === 'win32' ? 'junction' : 'dir');
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: path.join(currentDir, 'bin', 'codex.exe'),
    codexVersion: 'codex-cli 0.146.0',
    activeBundle: { complete: false, probeEligible: true, resourceLayout: 'COMPLETE' },
    alternativeExecutables: [filesystemAlternative(path.join(releaseBin, 'codex.exe'), 'codex-cli 0.146.0')],
  });
  assert.equal(plan.candidates.length, 1);
  assert.equal(plan.candidates[0].source, 'ACTIVE_CLI');
  fs.rmSync(temp, { recursive: true, force: true });
});

test('probe plan offers an active probe-eligible standalone executable when sandbox state is AVAILABLE', () => {
  const activeBundle = {
    complete: false,
    probeEligible: true,
    installType: 'standalone',
    resourceLayout: 'COMPLETE',
    helperResolution: 'NOT_TESTED',
    runtimeStartup: 'NOT_TESTED',
    standaloneResourcesFound: true,
    standaloneRequiredResourcesPresent: true,
    standalonePackage: { releaseVersion: '0.146.0' },
  };
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\standalone\\current\\bin\\codex.exe',
    codexVersion: 'codex-cli 0.146.0',
    activeBundle,
    sandboxFullAutoAvailable: false,
    sandboxHelperInPath: false,
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.source, 'ACTIVE_CLI');
  assert.equal(plan.requiresConfirmation, false);
  assert.equal(plan.testedBundleMetadata.resourceLayout, 'COMPLETE');
  assert.equal(plan.testedBundleMetadata.helperResolution, 'NOT_TESTED');
  assert.equal(plan.testedBundleMetadata.runtimeStartup, 'NOT_TESTED');
});

test('probe plan offers a filesystem-discovered same-version candidate for explicit diagnostics when the active bundle is incomplete', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    codexVersion: 'codex-cli 0.145.0',
    alternativeExecutables: [filesystemAlternative('C:\\bundle\\codex.exe', 'codex-cli 0.145.0')],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, true);
  assert.equal(plan.source, 'ALTERNATIVE_EXECUTABLE');
  assert.equal(plan.derivedVersionRelation, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(plan.codexExe, 'C:\\bundle\\codex.exe');
  assert.equal(plan.fullAutoAvailable, false);
  assert.equal(plan.testedVersion, null);
  assert.equal(plan.sandboxState, 'NOT_RUN');
});

test('probe plan fails closed when no complete matching bundle exists', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    matchingCompleteBundles: [],
  });
  assert.equal(plan.ready, false);
  assert.match(plan.reason, /incomplete/i);
});

test('setup failure summary keeps workspace deletion and boundary as untested', () => {
  const error = 'codex-windows-sandbox-setup.exe program not found';
  const summary = summarizeAssessment({ config: { warnings: [] }, activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY }, [], {
    status: 'SETUP_FAILED',
    codexSource: 'ACTIVE_CLI',
    codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    runtimeEvidence: buildSandboxRuntimeEvidence(error, {
      step: 'SANDBOX_SMOKE', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    }),
    error,
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

test('probe plan offers a filesystem-derived newer candidate but does not call it test-ready before selection', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    codexVersion: 'codex-cli 0.145.0',
    activeCodexPath: 'C:\\active\\codex.exe',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    alternativeExecutables: [filesystemAlternative('C:\\bundle\\codex.exe', 'codex-cli 0.146.0-alpha.3')],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.requiresConfirmation, true);
  assert.equal(plan.source, 'ALTERNATIVE_EXECUTABLE');
  assert.equal(plan.derivedVersionRelation, 'NEWER_COMPLETE_BUNDLE');
  assert.equal(plan.versionMismatch, false);
  assert.equal(plan.activeVersion, 'codex-cli 0.145.0');
  assert.equal(plan.testedVersion, null);
  assert.equal(plan.displayedVersion, 'codex-cli 0.146.0-alpha.3');
  assert.equal(plan.fullAutoAvailable, false);
  assert.equal(plan.sandboxState, 'NOT_RUN');
});

test('probe plan rejects an unproven filesystem candidate before any diagnostic process', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'AVAILABLE',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    alternativeExecutables: [filesystemAlternative('C:\\bundle\\codex.exe', 'codex-cli 0.146.0-alpha.3', {
      filesystemIdentity: { status: 'UNPROVEN', key: 'unproven', canonicalPath: null },
    })],
    completeBundles: [{ derivedVersion: '0.146.0-alpha.3' }],
  });
  assert.equal(plan.ready, false);
  assert.match(plan.reason, /provable identity/i);
});

test('alternative bundle pass is not reported as validation of the active CLI', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    versionMismatch: true,
  }));
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE BOUNDARY PASSED');
  assert.equal(summary.boundary, 'PASS');
});


test('a filesystem candidate can be selected for bound diagnostics when the incomplete active CLI sandbox command is unavailable', () => {
  const plan = selectCodexProbePlan({
    sandboxWindowsState: 'UNSUPPORTED',
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    sandboxHelperInPath: false,
    alternativeExecutables: [filesystemAlternative('C:\\bundle\\codex.exe', 'codex-cli 0.146.0-alpha.3')],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.source, 'ALTERNATIVE_EXECUTABLE');
  assert.equal(plan.derivedVersionRelation, 'NEWER_COMPLETE_BUNDLE');
});


test('access-denial detection recognizes Windows denial messages', () => {
  assert.equal(detectAccessDenied({ stderr: 'Zugriff verweigert' }), true);
  assert.equal(detectAccessDenied({ stderr: 'Zugriff auf den Pfad wurde verweigert.' }), true);
  assert.equal(detectAccessDenied({ stderr: 'Access is denied.' }), true);
  assert.equal(detectAccessDenied({ stderr: 'SyntaxError: missing ) after argument list' }), false);
});

test('Windows path canonicalization matches namespace, UNC, slash, and case variants', () => {
  assert.equal(canonicalizeWindowsPath('\\\\?\\C:\\Canary\\Outside.txt'), 'c:\\canary\\outside.txt');
  assert.equal(sameWindowsPath('C:\\Canary\\Outside.txt', '\\\\?\\c:\\canary\\outside.txt'), true);
  assert.equal(sameWindowsPath('\\\\server\\share\\Folder\\File.txt', '\\\\?\\UNC\\SERVER\\SHARE\\folder\\file.txt'), true);
  assert.equal(sameWindowsPath('C:/Canary/Outside.txt', 'c:\\canary\\outside.txt'), true);
  assert.equal(sameWindowsPath('C:\\Canary\\Outside.txt', 'C:\\Canary\\Other.txt'), false);
});

test('Node EPERM with a namespace error target matches the controlled outside file', () => {
  const targetPath = 'C:\\Canary\\outside-node.txt';
  const definition = { id: 'outside-workspace-node', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'node', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'node', targetId: definition.id, targetPath, status: 1, succeeded: false,
      errorClass: 'Error', errorCode: 'EPERM', errorTarget: '\\\\?\\C:\\Canary\\outside-node.txt', errorSyscall: 'rm',
    }),
  });
  assert.equal(result.targetIdentityStatus, 'MATCHED');
  assert.equal(result.errorTargetMatched, true);
  assert.equal(result.assessment, 'PASS');
});

test('structured probe runtime must match the declared boundary method', () => {
  const targetPath = 'C:\\Canary\\powershell-outside.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside', method: 'powershell' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'cmd', targetId: definition.id, targetPath: null, status: 1, succeeded: false,
      targetState: 'RETAINED', operationOutput: 'Access is denied.',
    }),
  });
  assert.equal(result.runtimeIdentityMatched, false);
  assert.equal(result.targetIdentityMatched, false);
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('producer preserves a mismatched child target identity and fails the process-marker aggregate closed', (t) => {
  const targetPath = 'C:\\Canary\\powershell-inside.txt';
  const definition = {
    id: 'inside-workspace-powershell', file: targetPath, expected: 'DELETED', location: 'inside', method: 'powershell',
    label: 'PowerShell synthetic inside workspace', meaning: 'Synthetic target identity mismatch.',
  };
  const result = {
    ...structuredProbeResult({
      runtime: 'powershell', targetId: 'inside-workspace-cmd', targetPath,
      status: 0, succeeded: true, targetState: 'DELETED',
    }),
    codexProcessStarted: true,
  };
  const classification = classifySandboxProbe({
    before: true, after: false, definition, result,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
  });
  const sandbox = producerBoundarySandbox();
  sandbox.probes[0] = createBoundaryProbeRecord({
    definition, method: 'powershell', expected: 'DELETED', after: false, result, classification,
    runMarker: sandbox.marker, codexExecutableIdentity: sandbox.codexExecutableIdentity,
  });
  const finalized = finalizeSandboxProbeRun(sandbox);

  assert.equal(classification.targetIdentityMatched, false);
  assert.equal(finalized.probes[0].targetId, 'inside-workspace-cmd');
  assert.equal(finalized.probes[0].reportedTargetPath, targetPath);
  assert.equal(finalized.codexProcessStarted, false);
  assert.equal(boundaryProbeProcessMarkersAreComplete(finalized), false);
  assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], finalized).boundary, 'TEST ERROR');

  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-target-id-report-'));
  t.after(() => fs.rmSync(appRoot, { recursive: true, force: true }));
  const written = writeReport({ inventory: syntheticReportInventory(), sandbox: finalized, appRoot, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  const detailJson = JSON.parse(fs.readFileSync(written.jsonPath, 'utf8'));
  const detailText = fs.readFileSync(written.txtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(written.supportJsonPath, 'utf8'));
  const supportText = fs.readFileSync(written.supportTxtPath, 'utf8');
  assert.equal(detailJson.sandbox.probes[0].targetId, 'inside-workspace-cmd');
  assert.equal(detailJson.sandbox.probes[0].reportedTargetPath, targetPath);
  assert.equal(supportJson.sandbox.probes[0].targetId, 'inside-workspace-cmd');
  assert.equal(supportJson.sandbox.probes[0].targetIdentityMatched, false);
  assert.equal(supportJson.sandbox.codexProcessStarted, false);
  assert.match(detailText, /Target ID:\s+inside-workspace-cmd/);
  assert.match(detailText, /Child-reported target path:\s+C:\\Canary\\powershell-inside\.txt/);
  assert.match(supportText, /Target ID:\s+inside-workspace-cmd; target identity matched:\s+no/);
  assert.match(supportText, /Boundary probe process-start evidence:\s+6\/6 CONFIRMED; aggregate:\s+NOT CONFIRMED/);

  for (const reportedTargetId of ['', null]) {
    const missingIdResult = {
      ...structuredProbeResult({
        runtime: 'powershell', targetId: reportedTargetId, targetPath,
        status: 0, succeeded: true, targetState: 'DELETED',
      }),
      codexProcessStarted: true,
    };
    const missingIdClassification = classifySandboxProbe({
      before: true, after: false, definition, result: missingIdResult,
      hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    });
    const missingIdSandbox = producerBoundarySandbox();
    missingIdSandbox.probes[0] = createBoundaryProbeRecord({
      definition, method: 'powershell', expected: 'DELETED', after: false,
      result: missingIdResult, classification: missingIdClassification,
      runMarker: missingIdSandbox.marker, codexExecutableIdentity: missingIdSandbox.codexExecutableIdentity,
    });
    const missingIdFinalized = finalizeSandboxProbeRun(missingIdSandbox);
    assert.equal(missingIdFinalized.probes[0].targetId, reportedTargetId);
    assert.equal(missingIdFinalized.codexProcessStarted, false);
  }

  const wrongPath = 'C:\\Canary\\different-target.txt';
  const wrongPathResult = {
    ...structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath: wrongPath,
      status: 0, succeeded: true, targetState: 'DELETED',
    }),
    codexProcessStarted: true,
  };
  const wrongPathClassification = classifySandboxProbe({
    before: true, after: false, definition, result: wrongPathResult,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
  });
  const wrongPathSandbox = producerBoundarySandbox();
  wrongPathSandbox.probes[0] = createBoundaryProbeRecord({
    definition, method: 'powershell', expected: 'DELETED', after: false,
    result: wrongPathResult, classification: wrongPathClassification,
    runMarker: wrongPathSandbox.marker, codexExecutableIdentity: wrongPathSandbox.codexExecutableIdentity,
  });
  const wrongPathFinalized = finalizeSandboxProbeRun(wrongPathSandbox);
  assert.equal(wrongPathFinalized.probes[0].reportedTargetPath, wrongPath);
  assert.equal(wrongPathFinalized.probes[0].targetIdentityMatched, false);
  assert.equal(wrongPathFinalized.codexProcessStarted, false);
});

test('cmd target-path evidence accepts only nullish absence or a matching nonempty string', () => {
  const targetPath = 'C:\\Canary\\cmd-inside.txt';
  const definition = { id: 'inside-workspace-cmd', file: targetPath, expected: 'DELETED', location: 'inside', method: 'cmd' };
  for (const reportedTargetPath of [false, 0, '', { path: targetPath }]) {
    const result = classifySandboxProbe({
      before: true,
      after: false,
      definition,
      result: structuredProbeResult({
        runtime: 'cmd', targetId: definition.id, targetPath: reportedTargetPath,
        status: 0, succeeded: true, targetState: 'DELETED', operationOutput: 'synthetic',
      }),
      hostCalibration: { method: 'cmd', status: 'PASS', passed: true },
    });
    assert.equal(result.targetIdentityMatched, false, JSON.stringify(reportedTargetPath));
    assert.equal(result.assessment, 'TEST_ERROR', JSON.stringify(reportedTargetPath));
  }
});

test('retained outside file passes only with structured target-related access evidence', () => {
  const targetPath = 'C:\\Canary\\outside-node.txt';
  const definition = { id: 'outside-workspace-node', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const targeted = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'node', status: 'PASS', passed: true },
    result: structuredProbeResult({ runtime: 'node', targetId: definition.id, targetPath, status: 1, succeeded: false, errorClass: 'Error', errorCode: 'EACCES', errorTarget: targetPath }),
  });
  assert.equal(targeted.assessment, 'PASS');
  assert.equal(targeted.errorTargetMatched, true);
  assert.equal(targeted.operationAttempted, true);

  const unrelated = classifySandboxProbe({ before: true, after: true, result: { status: 1, stderr: 'SyntaxError: invalid command\nAccess to network is denied' }, definition, hostCalibration: { method: 'node', status: 'PASS', passed: true } });
  assert.equal(unrelated.assessment, 'TEST_ERROR');
  assert.equal(unrelated.denialEvidence, false);
});

test('inside workspace denial fails the workspace-write control', () => {
  const targetPath = 'C:\\Canary\\inside-powershell.txt';
  const definition = { id: 'inside-workspace-powershell', file: targetPath, expected: 'DELETED', location: 'inside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({ runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false, errorClass: 'System.UnauthorizedAccessException', errorCategory: 'PermissionDenied', errorTarget: targetPath }),
  });
  assert.equal(result.assessment, 'UNEXPECTED');
  assert.equal(result.errorTargetMatched, true);
});

test('command-not-found plus generic access denied is inconclusive', () => {
  const definition = { id: 'outside-workspace-cmd', file: 'C:\\Canary\\outside-cmd.txt', expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({ before: true, after: true, definition, result: { status: 1, stderr: 'command not found\nAccess is denied.' }, hostCalibration: { method: 'cmd', status: 'PASS', passed: true } });
  assert.equal(result.assessment, 'TEST_ERROR');
  assert.equal(result.errorTargetMatched, false);
  assert.equal(result.unrelatedFailureDetected, true);
});

test('PowerShell access failure requires structured operation and target evidence', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const targeted = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({ runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false, errorClass: 'System.UnauthorizedAccessException', errorCategory: 'PermissionDenied', errorTarget: targetPath }),
  });
  const wrongTarget = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({ runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false, errorClass: 'System.UnauthorizedAccessException', errorCategory: 'PermissionDenied', errorTarget: 'C:\\Canary\\other.txt' }),
  });
  assert.equal(targeted.assessment, 'PASS');
  assert.equal(wrongTarget.assessment, 'TEST_ERROR');
});

test('PowerShell cannot use the intended target as artificial ErrorRecord target evidence', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      errorClass: 'System.ArgumentException', errorCode: 'RemoveFileSystemItemArgumentError', errorCategory: 'InvalidArgument',
      errorTarget: null, operation: null, operationTarget: null, errorCommand: null,
    }),
  });
  assert.equal(result.targetIdentityStatus, 'NOT MATCHED');
  assert.equal(result.errorTargetMatched, false);
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('PowerShell ArgumentException with InvalidArgument and a matching target fails closed', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.ArgumentException',
      errorClass: 'System.ArgumentException',
      errorCode: 'RemoveFileSystemItemArgumentError,Microsoft.PowerShell.Commands.RemoveItemCommand',
      errorCategory: 'InvalidArgument', errorReason: 'ArgumentException', errorTarget: targetPath,
      operation: 'System.IO.File.Delete', operationTarget: targetPath,
    }),
  });
  assert.equal(result.targetIdentityStatus, 'MATCHED');
  assert.equal(result.controlledOperationMatched, true);
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('PowerShell RemoveFileSystemItemArgumentError with access-denied text fails closed', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.ArgumentException', errorClass: 'System.ArgumentException',
      errorCode: 'RemoveFileSystemItemArgumentError', errorCategory: 'InvalidArgument',
      errorTarget: targetPath, errorMessage: 'Access is denied.', stderr: 'Zugriff verweigert',
    }),
  });
  assert.equal(result.assessment, 'TEST_ERROR');
  assert.equal(result.denialEvidence, false);
});

test('PowerShell ArgumentException without an actual error target fails closed', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.ArgumentException', errorClass: 'System.ArgumentException',
      errorCategory: 'InvalidArgument', errorTarget: null,
    }),
  });
  assert.equal(result.targetIdentityStatus, 'MATCHED');
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('PowerShell UnauthorizedAccessException with a matching controlled target passes', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.UnauthorizedAccessException', errorClass: 'System.UnauthorizedAccessException', errorTarget: targetPath,
    }),
  });
  assert.equal(result.nativeWin32ErrorCode, null);
  assert.equal(result.assessment, 'PASS');
});

test('PowerShell HResult with native access-denied code 5 and a matching target passes', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.IO.IOException', errorClass: 'System.IO.IOException',
      errorHResult: -2147024891, errorTarget: targetPath,
    }),
  });
  assert.equal(result.nativeWin32ErrorCode, 5);
  assert.equal(result.assessment, 'PASS');
});

test('PowerShell PermissionDenied with a wrong target fails closed', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.Management.Automation.RuntimeException', errorCategory: 'PermissionDenied',
      errorTarget: 'C:\\Canary\\other.txt',
    }),
  });
  assert.equal(result.targetIdentityStatus, 'NOT MATCHED');
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('PowerShell PermissionDenied with an independently matching target passes', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.Management.Automation.RuntimeException', errorCategory: 'PermissionDenied', errorTarget: targetPath,
    }),
  });
  assert.equal(result.errorTargetMatched, true);
  assert.equal(result.assessment, 'PASS');
});

test('PowerShell PermissionDenied cannot pass after a failed method calibration', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'FAIL', passed: false },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      exceptionType: 'System.Management.Automation.RuntimeException', errorCategory: 'PermissionDenied', errorTarget: targetPath,
    }),
  });
  assert.equal(result.denialEvidenceMatched, true);
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('PowerShell message-only access denial fails closed', () => {
  const targetPath = 'C:\\Canary\\outside-powershell.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
    result: structuredProbeResult({
      runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
      errorMessage: 'Zugriff verweigert', stderr: 'Zugriff verweigert',
    }),
  });
  assert.equal(result.assessment, 'TEST_ERROR');
  assert.equal(result.denialEvidence, false);
});

test('cmd generic denial without the controlled operation record fails closed', () => {
  const definition = { id: 'outside-workspace-cmd', file: 'C:\\Canary\\outside-cmd.txt', expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({ before: true, after: true, definition, result: { status: 1, stderr: 'Access is denied.' }, hostCalibration: { method: 'cmd', status: 'PASS', passed: true } });
  assert.equal(result.assessment, 'TEST_ERROR');
  assert.equal(result.commandStarted, false);
  assert.equal(result.errorTargetMatched, false);
});

test('cmd structured record cannot borrow denial text from outside its operation-output markers', () => {
  const targetPath = 'C:\\Canary\\outside-cmd.txt';
  const definition = { id: 'outside-workspace-cmd', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'cmd', status: 'PASS', passed: true },
    result: structuredProbeResult({ runtime: 'cmd', targetId: definition.id, targetPath: null, status: 1, succeeded: false, targetState: 'RETAINED', stderr: 'Access is denied.' }),
  });
  assert.equal(result.assessment, 'TEST_ERROR');
  assert.equal(result.commandStarted, true);
  assert.equal(result.errorTargetMatched, false);
});

test('failed method calibration prevents an otherwise valid outside PASS', () => {
  const targetPath = 'C:\\Canary\\outside-node.txt';
  const definition = { id: 'outside-workspace-node', file: targetPath, expected: 'RETAINED', location: 'outside' };
  const result = classifySandboxProbe({
    before: true,
    after: true,
    definition,
    hostCalibration: { method: 'node', status: 'FAIL', passed: false },
    result: structuredProbeResult({
      runtime: 'node', targetId: definition.id, targetPath, status: 1, succeeded: false,
      errorClass: 'Error', errorCode: 'EPERM', errorTarget: targetPath, errorSyscall: 'rm',
    }),
  });
  assert.equal(result.denialEvidenceMatched, true);
  assert.equal(result.hostCalibrationPassed, false);
  assert.equal(result.assessment, 'TEST_ERROR');
});

test('full structured three-runtime matrix still produces a boundary pass', () => {
  const probes = ['powershell', 'cmd', 'node'].flatMap((method) => [
    classifyStructuredProbe(method, 'inside'),
    classifyStructuredProbe(method, 'outside'),
  ]);
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({ probes }));
  assert.equal(summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(summary.boundary, 'PASS');
  assert.equal(summary.methodCoverage, '3/3');
  assert.deepEqual(summary.nextSteps, []);
});

test('boundary pass requires explicit Codex process-start evidence', () => {
  const sandbox = completedBoundarySandbox({
    codexProcessStarted: false,
    smoke: { passed: true, commandExitCode: 0, setupFailure: false, codexProcessStarted: false, stderr: '' },
  });
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.notEqual(summary.overall, 'BOUNDARY TEST PASSED');
});

test('producer preserves six identity-bound process markers and the consumer accepts the complete set', () => {
  const sandbox = producerBoundarySandbox();
  assert.equal(sandbox.probes.length, 6);
  assert.equal(boundaryProbeProcessMarkersAreComplete(sandbox), true);
  assert.equal(sandbox.codexProcessStarted, true);
  for (const probe of sandbox.probes) {
    assert.equal(probe.codexProcessStarted, true);
    assert.equal(probe.runMarker, sandbox.marker);
    assert.equal(probe.codexExecutableIdentity, sandbox.codexExecutableIdentity);
    assert.equal(probe.id, probe.targetId);
    assert.equal(probe.reportedRuntime, probe.method);
  }
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
  assert.equal(summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(summary.boundary, 'PASS');
  assert.equal(summary.methodCoverage, '3/3');
});

test('each individually missing boundary process marker fails closed', () => {
  for (let index = 0; index < 6; index += 1) {
    const sandbox = producerBoundarySandbox();
    delete sandbox.probes[index].codexProcessStarted;
    sandbox.codexProcessStarted = true;
    const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
    assert.equal(boundaryProbeProcessMarkersAreComplete(sandbox), false, `probe ${index}`);
    assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE', `probe ${index}`);
    assert.equal(summary.boundary, 'TEST ERROR', `probe ${index}`);
  }
});

test('false null string and unknown boundary marker values fail closed', () => {
  for (const value of [false, null, 'true', 'UNKNOWN', { value: true }]) {
    const sandbox = producerBoundarySandbox();
    sandbox.probes[0].codexProcessStarted = value;
    sandbox.codexProcessStarted = true;
    const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
    assert.equal(boundaryProbeProcessMarkersAreComplete(sandbox), false, String(value));
    assert.equal(summary.boundary, 'TEST ERROR', String(value));
  }
});

test('duplicate missing and wrongly assigned matrix identities fail closed', () => {
  const cases = [];
  const duplicate = producerBoundarySandbox();
  duplicate.probes[5] = { ...duplicate.probes[4] };
  duplicate.codexProcessStarted = true;
  cases.push(['duplicate', duplicate]);

  const missing = producerBoundarySandbox();
  missing.probes.pop();
  missing.codexProcessStarted = true;
  cases.push(['missing', missing]);

  const wrongMethod = producerBoundarySandbox();
  wrongMethod.probes[0].method = 'ruby';
  wrongMethod.codexProcessStarted = true;
  cases.push(['wrong method', wrongMethod]);

  const wrongLocation = producerBoundarySandbox();
  wrongLocation.probes[0].location = 'control';
  wrongLocation.codexProcessStarted = true;
  cases.push(['wrong location', wrongLocation]);

  const wrongRuntime = producerBoundarySandbox();
  wrongRuntime.probes[0].reportedRuntime = 'cmd';
  wrongRuntime.codexProcessStarted = true;
  cases.push(['wrong child runtime', wrongRuntime]);

  const wrongRun = producerBoundarySandbox();
  wrongRun.probes[0].runMarker = 'different-run';
  wrongRun.codexProcessStarted = true;
  cases.push(['wrong run', wrongRun]);

  const wrongExecutable = producerBoundarySandbox();
  wrongExecutable.probes[0].codexExecutableIdentity = 'different-executable';
  wrongExecutable.codexProcessStarted = true;
  cases.push(['wrong executable', wrongExecutable]);

  for (const [label, sandbox] of cases) {
    const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
    assert.equal(boundaryProbeProcessMarkersAreComplete(sandbox), false, label);
    assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE', label);
    assert.equal(summary.boundary, 'TEST ERROR', label);
  }
});

test('aggregate and smoke contradictions remain fail closed', () => {
  const aggregateFalse = producerBoundarySandbox();
  aggregateFalse.codexProcessStarted = false;
  assert.equal(boundaryProbeProcessMarkersAreComplete(aggregateFalse), true);
  assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], aggregateFalse).boundary, 'TEST ERROR');

  for (const smokeMarker of [undefined, false, null, 'true']) {
    const sandbox = producerBoundarySandbox();
    if (smokeMarker === undefined) delete sandbox.smoke.codexProcessStarted;
    else sandbox.smoke.codexProcessStarted = smokeMarker;
    assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], sandbox).boundary, 'TEST ERROR', String(smokeMarker));
  }
});

test('spawn failure and catch finalization never assert aggregate process start', () => {
  const spawnFailure = producerBoundarySandbox();
  spawnFailure.probes[2].codexProcessStarted = false;
  const failedRun = finalizeSandboxProbeRun({ ...spawnFailure, codexProcessStarted: true });
  assert.equal(failedRun.codexProcessStarted, false);
  assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], failedRun).boundary, 'TEST ERROR');

  const partialRun = producerBoundarySandbox();
  const caught = finalizeSandboxProbeRun({ ...partialRun, status: 'ERROR', probes: partialRun.probes.slice(0, 5), error: 'synthetic catch' });
  assert.equal(caught.codexProcessStarted, false);
  assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], caught).boundary, 'TEST ERROR');

  const caughtAfterSix = finalizeSandboxProbeRun({ ...producerBoundarySandbox(), status: 'ERROR', error: 'synthetic catch after matrix' });
  assert.equal(caughtAfterSix.codexProcessStarted, false);
  assert.equal(summarizeAssessment({ config: { warnings: [] } }, [], caughtAfterSix).boundary, 'TEST ERROR');
});

test('active CLI run binding is revalidated before every sandbox command', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-active-run-binding-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = path.join(root, 'codex.exe');
  fs.writeFileSync(executable, 'synthetic active executable');
  const plan = selectCodexProbePlan({
    activeCodexPath: executable,
    codexVersion: 'codex-cli synthetic',
    activeBundle: { probeEligible: true, installType: 'classic', resourceLayout: 'COMPLETE' },
    sandboxHelperInPath: false,
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    alternativeExecutables: [],
  });
  assert.equal(validateSelectedExecutableBinding(plan.executableRunBinding, executable).valid, true);

  let invocations = 0;
  const first = runSandboxCommand(['cmd.exe', '/d', '/c', 'echo', 'synthetic'], root, {
    codexExe: executable,
    executableRunBinding: plan.executableRunBinding,
    commandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    invokeCodex() {
      invocations += 1;
      fs.renameSync(executable, `${executable}.old`);
      fs.writeFileSync(executable, 'replacement active executable');
      return { status: 0, stdout: 'synthetic', stderr: '', codexProcessStarted: true };
    },
  });
  const second = runSandboxCommand(['cmd.exe', '/d', '/c', 'echo', 'synthetic'], root, {
    codexExe: executable,
    executableRunBinding: plan.executableRunBinding,
    commandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    invokeCodex() {
      invocations += 1;
      return { status: 0, stdout: 'unexpected', stderr: '', codexProcessStarted: true };
    },
  });

  assert.equal(first.codexProcessStarted, true);
  assert.equal(second.codexProcessStarted, false);
  assert.equal(second.status, null);
  assert.match(second.error.message, /identity changed/i);
  assert.equal(invocations, 1);
});

test('detail replay and all report channels retain consistent process-start evidence', (t) => {
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-process-marker-report-'));
  t.after(() => fs.rmSync(appRoot, { recursive: true, force: true }));
  const sandbox = producerBoundarySandbox();
  const written = writeReport({ inventory: syntheticReportInventory(), sandbox, appRoot, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  const detailJson = JSON.parse(fs.readFileSync(written.jsonPath, 'utf8'));
  const detailText = fs.readFileSync(written.txtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(written.supportJsonPath, 'utf8'));
  const supportText = fs.readFileSync(written.supportTxtPath, 'utf8');

  assert.equal(detailJson.sandbox.probes.length, 6);
  assert.equal(detailJson.sandbox.probes.every((probe) => probe.codexProcessStarted === true), true);
  assert.equal(detailJson.sandbox.probes.every((probe) => probe.runMarker === detailJson.sandbox.marker), true);
  assert.equal(detailJson.sandbox.probes.every((probe) => probe.codexExecutableIdentity === detailJson.sandbox.codexExecutableIdentity), true);
  const replay = summarizeAssessment(detailJson.inventory, detailJson.execpolicy, detailJson.sandbox, { assessmentMode: detailJson.assessmentMode });
  assert.equal(replay.boundary, 'PASS');

  assert.equal(supportJson.sandbox.codexProcessStarted, true);
  assert.equal(supportJson.sandbox.processStartEvidence, 'CONFIRMED');
  assert.deepEqual(supportJson.sandbox.boundaryProbeProcessStartEvidence, {
    expectedCount: 6, confirmedCount: 6, aggregate: 'CONFIRMED',
  });
  assert.equal(supportJson.sandbox.smoke.codexProcessStarted, true);
  assert.equal(supportJson.sandbox.smoke.processStartEvidence, 'CONFIRMED');
  assert.equal(supportJson.sandbox.probes.length, 6);
  assert.equal(supportJson.sandbox.probes.every((probe) => probe.codexProcessStarted === true), true);
  assert.equal(JSON.stringify(supportJson).includes(TEST_RUN_MARKER), false);
  assert.equal(JSON.stringify(supportJson).includes(ACTIVE_EXECUTABLE_IDENTITY), false);
  for (const text of [detailText, supportText]) {
    assert.match(text, /Boundary probe process-start evidence:\s+6\/6 CONFIRMED; aggregate:\s+CONFIRMED/);
    assert.equal((text.match(/Process-start evidence:\s+CONFIRMED/g) || []).length, 6);
    assert.match(text, /Runtime smoke test:\s+PASS; process-start evidence:\s+CONFIRMED/);
    assert.match(text, /Sandbox boundary:\s+PASS|Active CLI boundary:\s+PASS/);
  }
});

test('process-start evidence uses the same three states in detail and share-safe reports', (t) => {
  const cases = [
    ['true', true, 'CONFIRMED', true, 6],
    ['false', false, 'NOT CONFIRMED', false, 5],
    ['missing', undefined, 'NOT REPORTED', null, 5],
    ['null', null, 'NOT REPORTED', null, 5],
    ['string', 'false', 'NOT REPORTED', null, 5],
    ['number', 1, 'NOT REPORTED', null, 5],
    ['object', { started: true }, 'NOT REPORTED', null, 5],
  ];

  for (const [label, value, expectedStatus, expectedProjectedMarker, expectedConfirmedCount] of cases) {
    const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), `canary-process-evidence-${label}-`));
    t.after(() => fs.rmSync(appRoot, { recursive: true, force: true }));
    const sandbox = producerBoundarySandbox();
    if (value === undefined) {
      delete sandbox.codexProcessStarted;
      delete sandbox.smoke.codexProcessStarted;
      delete sandbox.probes[0].codexProcessStarted;
    } else {
      sandbox.codexProcessStarted = value;
      sandbox.smoke.codexProcessStarted = value;
      sandbox.probes[0].codexProcessStarted = value;
    }

    assert.equal(processStartEvidenceStatus(value), expectedStatus, label);
    assert.equal(boundaryProbeProcessStartEvidence(sandbox).confirmedCount, expectedConfirmedCount, label);
    assert.match(formatBoundaryProbeProcessStartEvidence(sandbox), new RegExp(`${expectedConfirmedCount}/6 CONFIRMED; aggregate: ${expectedStatus}`), label);
    assert.match(formatSmokeProcessStartEvidence(sandbox.smoke), new RegExp(`process-start evidence: ${expectedStatus}`), label);

    const written = writeReport({
      inventory: syntheticReportInventory(), sandbox, appRoot, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY,
    });
    const detailJson = JSON.parse(fs.readFileSync(written.jsonPath, 'utf8'));
    const detailText = fs.readFileSync(written.txtPath, 'utf8');
    const supportJson = JSON.parse(fs.readFileSync(written.supportJsonPath, 'utf8'));
    const supportText = fs.readFileSync(written.supportTxtPath, 'utf8');

    for (const report of [detailJson, supportJson]) {
      assert.equal(report.sandbox.processStartEvidence, expectedStatus, `${label} aggregate status`);
      assert.equal(report.sandbox.smokeProcessStartEvidence, expectedStatus, `${label} smoke status`);
      assert.equal(report.sandbox.smoke.processStartEvidence, expectedStatus, `${label} smoke object`);
      assert.equal(report.sandbox.probes[0].processStartEvidence, expectedStatus, `${label} probe status`);
    }
    assert.equal(supportJson.sandbox.codexProcessStarted, expectedProjectedMarker, label);
    assert.equal(supportJson.sandbox.smoke.codexProcessStarted, expectedProjectedMarker, label);
    assert.equal(supportJson.sandbox.probes[0].codexProcessStarted, expectedProjectedMarker, label);
    for (const text of [detailText, supportText]) {
      assert.match(text, new RegExp(`aggregate: ${expectedStatus}`), label);
      assert.match(text, new RegExp(`Runtime smoke test: PASS; process-start evidence: ${expectedStatus}`), label);
      assert.match(text, new RegExp(`Process-start evidence: ${expectedStatus}`), label);
    }

    const summary = summarizeAssessment(detailJson.inventory, detailJson.execpolicy, detailJson.sandbox, {
      assessmentMode: detailJson.assessmentMode,
    });
    assert.equal(summary.boundary, value === true ? 'PASS' : 'TEST ERROR', label);
  }
});

test('missing smoke is always reported as not run with process-start evidence not reported', (t) => {
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-missing-smoke-evidence-'));
  t.after(() => fs.rmSync(appRoot, { recursive: true, force: true }));
  const sandbox = producerBoundarySandbox();
  delete sandbox.smoke;
  const written = writeReport({
    inventory: syntheticReportInventory(), sandbox, appRoot, assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY,
  });
  const detailJson = JSON.parse(fs.readFileSync(written.jsonPath, 'utf8'));
  const detailText = fs.readFileSync(written.txtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(written.supportJsonPath, 'utf8'));
  const supportText = fs.readFileSync(written.supportTxtPath, 'utf8');

  for (const report of [detailJson, supportJson]) {
    assert.equal(report.sandbox.smokeStatus, 'NOT RUN');
    assert.equal(report.sandbox.smokeProcessStartEvidence, 'NOT REPORTED');
  }
  for (const text of [detailText, supportText]) {
    assert.match(text, /Runtime smoke test:\s+NOT RUN; process-start evidence:\s+NOT REPORTED/);
    assert.doesNotMatch(text, /Runtime smoke test:\s+NOT RUN; Codex process started:\s+no/i);
  }
  assert.equal(summarizeAssessment(detailJson.inventory, detailJson.execpolicy, detailJson.sandbox, {
    assessmentMode: detailJson.assessmentMode,
  }).boundary, 'TEST ERROR');
});

test('boundary cannot pass when every runtime control fails', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    codexSource: 'MATCHING_COMPLETE_BUNDLE',
    versionMismatch: false,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  }));
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.workspaceDeletion, 'CONTROL FAILED');
});

test('boundary passes only when every tested runtime pair passes', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox());
  assert.equal(summary.overall, 'BOUNDARY TEST PASSED');
  assert.equal(summary.boundary, 'PASS');
  assert.equal(summary.methodCoverage, '3/3');
});

test('one valid runtime pair cannot produce a pass when another runtime control fails', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    codexSource: 'MATCHING_COMPLETE_BUNDLE',
    versionMismatch: false,
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
      { method: 'cmd', location: 'inside', assessment: 'EXPECTED', observed: 'DELETED' },
      { method: 'cmd', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  }));
  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '1/3');
});

test('incomplete sandbox execution cannot produce a boundary pass', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    status: 'ERROR',
    probes: completeBoundaryProbes().slice(0, 2),
  }));
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '1/3');
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS'), false);
});

test('sandbox error evidence has priority over complete probe results', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    error: 'Synthetic runtime failure after probe collection.',
  }));
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '3/3');
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS'), false);
});

test('missing Node runtime pair is a test error with fixed three-pair coverage', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    probes: completeBoundaryProbes().filter((probe) => probe.method !== 'node'),
  }));
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '2/3');
});

test('failed host preflight or smoke prevents a boundary pass', () => {
  const failedPreflight = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    hostPreflight: { passed: false, filesChecked: 1, error: 'preflight failed' },
  }));
  const failedSmoke = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    smoke: { passed: false, commandExitCode: 1, setupFailure: true, stderr: 'smoke failed' },
  }));
  for (const summary of [failedPreflight, failedSmoke]) {
    assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
    assert.equal(summary.boundary, 'TEST ERROR');
    assert.equal(summary.methodCoverage, '3/3');
  }
});

test('cleanup status is required and fail-closed for every non-completed state', () => {
  const completed = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox());
  assert.equal(completed.overall, 'BOUNDARY TEST PASSED');
  assert.equal(completed.boundary, 'PASS');
  assert.equal(completed.cleanup.status, 'COMPLETED');

  const cases = [
    ['FAILED', failedCleanup()],
    ['localized FAILED', failedCleanup('Der temporäre Laufordner konnte nicht entfernt werden.')],
    ['NOT_RUN', { status: 'NOT_RUN', attempted: false, completed: false, errorPresent: false, message: null }],
    ['unknown status', { status: 'REMOVED', attempted: true, completed: true, errorPresent: false, message: null }],
    ['contradictory COMPLETED', { status: 'COMPLETED', attempted: true, completed: false, errorPresent: false, message: null }],
  ];
  for (const [label, cleanup] of cases) {
    const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({ cleanup }));
    assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE', label);
    assert.equal(summary.boundary, 'TEST ERROR', label);
    assert.notEqual(summary.cleanup.status, 'COMPLETED', label);
  }

  const missingCleanup = completedBoundarySandbox();
  delete missingCleanup.cleanup;
  const missing = summarizeAssessment({ config: { warnings: [] } }, [], missingCleanup);
  assert.equal(missing.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(missing.boundary, 'TEST ERROR');
  assert.equal(missing.cleanup.status, 'NOT_RUN');
  assert.equal(missing.cleanup.valid, false);

  const legacyText = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    cleanup: 'Disposable run folder removed before final reports were written.',
  }));
  assert.equal(legacyText.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(legacyText.boundary, 'TEST ERROR');

  const inconsistentSmokeStatus = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({ status: 'SMOKE_COMPLETED' }));
  assert.equal(inconsistentSmokeStatus.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(inconsistentSmokeStatus.boundary, 'TEST ERROR');
});

test('cleanup failure prevents a boundary pass independently of message wording', () => {
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({
    cleanup: failedCleanup('Could not remove disposable run folder.'),
  }));
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '3/3');
  assert.equal(summary.cleanup.status, 'FAILED');
});

test('confirmed boundary gap remains primary when a sibling probe is a test error', () => {
  const probes = completeBoundaryProbes({ gapMethod: 'powershell' }).map((probe) => (
    probe.method === 'cmd' && probe.location === 'outside'
      ? { ...probe, assessment: 'TEST_ERROR', observed: 'RETAINED', fileExistsAfter: true, errorTargetMatched: false }
      : probe
  ));
  const summary = summarizeAssessment(
    { config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' },
    [],
    completedBoundarySandbox({ probes })
  );

  assert.equal(summary.boundary, 'GAP');
  assert.match(summary.overall, /GAP.*ADDITIONAL PROBE ERRORS/);
  assert.equal(summary.additionalProbeErrors, true);
  assert.deepEqual(summary.boundaryGapMethods, ['powershell']);
  assert.equal(summary.recommendations[0].code, 'BOUNDARY_GAP');
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);
  assert.match(summary.interpretation.join('\n'), /confirmed sandbox boundary gap/i);
  assert.match(summary.interpretation.join('\n'), /additional probe errors.*do not weaken/i);
});

test('a boundary gap is confirmed only when the affected outside probe has bound process-start evidence', () => {
  for (const value of [undefined, false, null, 'true', { started: true }]) {
    const sandbox = completedBoundarySandbox({ probes: completeBoundaryProbes({ gapMethod: 'powershell' }) });
    const gapProbe = sandbox.probes.find((probe) => probe.method === 'powershell' && probe.location === 'outside');
    if (value === undefined) delete gapProbe.codexProcessStarted;
    else gapProbe.codexProcessStarted = value;
    sandbox.codexProcessStarted = true;

    const summary = summarizeAssessment({ config: { warnings: [] } }, [], sandbox);
    assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE', String(value));
    assert.equal(summary.boundary, 'TEST ERROR', String(value));
    assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_GAP'), false, String(value));
  }

  const siblingMissing = completedBoundarySandbox({ probes: completeBoundaryProbes({ gapMethod: 'powershell' }) });
  delete siblingMissing.probes.find((probe) => probe.method === 'node' && probe.location === 'inside').codexProcessStarted;
  siblingMissing.codexProcessStarted = false;
  const siblingSummary = summarizeAssessment({ config: { warnings: [] } }, [], siblingMissing);
  assert.equal(siblingSummary.boundary, 'GAP');
  assert.equal(siblingSummary.recommendations.some((item) => item.code === 'BOUNDARY_GAP'), true);
});

test('confirmed boundary gap remains primary with missing method coverage', () => {
  const probes = completeBoundaryProbes({ gapMethod: 'powershell' })
    .filter((probe) => probe.method !== 'node');
  const summary = summarizeAssessment(
    { config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' },
    [],
    completedBoundarySandbox({ probes })
  );

  assert.equal(summary.boundary, 'GAP');
  assert.match(summary.overall, /GAP.*ADDITIONAL PROBE ERRORS/);
  assert.equal(summary.additionalProbeErrors, true);
  assert.equal(summary.methodCoverage, '1/3');
});

test('confirmed boundary gap remains primary with cleanup failure', () => {
  const summary = summarizeAssessment(
    { config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' },
    [],
    completedBoundarySandbox({
      probes: completeBoundaryProbes({ gapMethod: 'powershell' }),
      cleanup: failedCleanup('Der temporäre Laufordner konnte nicht entfernt werden.'),
    })
  );

  assert.equal(summary.boundary, 'GAP');
  assert.match(summary.overall, /GAP.*ADDITIONAL PROBE ERRORS/);
  assert.equal(summary.additionalProbeErrors, true);
  assert.equal(summary.cleanup.status, 'FAILED');
  assert.equal(summary.recommendations[0].code, 'BOUNDARY_GAP');
});

test('multiple confirmed gaps and sibling errors retain one primary gap recommendation', () => {
  const probes = completeBoundaryProbes({ gapMethod: 'powershell' }).map((probe) => {
    if (probe.method === 'cmd' && probe.location === 'outside') {
      return { ...probe, assessment: 'CRITICAL_GAP', observed: 'DELETED', fileExistsAfter: false, errorTargetMatched: false };
    }
    if (probe.method === 'node' && probe.location === 'outside') {
      return { ...probe, assessment: 'TEST_ERROR', observed: 'RETAINED', fileExistsAfter: true, errorTargetMatched: false };
    }
    return probe;
  });
  const summary = summarizeAssessment(
    { config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' },
    [],
    completedBoundarySandbox({ probes, error: 'Synthetic additional probe errors.' })
  );

  assert.equal(summary.boundary, 'GAP');
  assert.deepEqual(summary.boundaryGapMethods, ['powershell', 'cmd']);
  assert.equal(summary.recommendations.filter((item) => item.code === 'BOUNDARY_GAP').length, 1);
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);
});

test('execpolicy unknown schema remains separate from a confirmed boundary gap', () => {
  const summary = summarizeAssessment(
    { config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' },
    [{ label: 'synthetic unknown schema', command: ['synthetic'], status: 'UNKNOWN_SCHEMA', decision: null }],
    completedBoundarySandbox({ probes: completeBoundaryProbes({ gapMethod: 'powershell' }) }),
    { execpolicyRun: true }
  );

  assert.equal(summary.boundary, 'GAP');
  assert.equal(summary.additionalProbeErrors, false);
  assert.deepEqual(summary.execpolicyCoverage, { status: 'UNKNOWN_SCHEMA', matched: null, total: 1 });
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_GAP'), true);
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

test('method host calibration proves PowerShell, cmd.exe, and Node.js runners independently', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-method-calibration-'));
  const layout = {
    workspace: fs.mkdirSync(path.join(temp, 'workspace'), { recursive: true }),
    control: fs.mkdirSync(path.join(temp, 'control'), { recursive: true }),
  };
  const methods = ['powershell', 'cmd', 'node'].map((method) => ({
    method,
    label: method,
    command: (file, targetId) => [method, file, targetId],
  }));
  const calibrations = runMethodHostCalibrations(layout, 'marker', methods, {
    runCommand: (command, cwd, context) => {
      assert.equal(cwd, layout.workspace);
      fs.rmSync(context.file);
      return structuredProbeResult({
        runtime: context.method.method,
        targetId: context.definition.id,
        targetPath: context.file,
        status: 0,
        succeeded: true,
        targetState: 'DELETED',
      });
    },
  });
  assert.deepEqual(calibrations.map((item) => [item.method, item.status]), [
    ['powershell', 'PASS'], ['cmd', 'PASS'], ['node', 'PASS'],
  ]);
  assert.equal(calibrations.every((item) => item.commandStarted && item.operationAttempted && !item.fileExistsAfter), true);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('PowerShell .NET host calibration deletes its synthetic file outside the sandbox', (t) => {
  if (process.platform !== 'win32') {
    t.skip('PowerShell host calibration is Windows-specific.');
    return;
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-powershell-dotnet-calibration-'));
  const layout = {
    workspace: fs.mkdirSync(path.join(temp, 'workspace'), { recursive: true }),
    control: fs.mkdirSync(path.join(temp, 'control'), { recursive: true }),
  };
  const calibrations = runMethodHostCalibrations(layout, 'marker', [{
    method: 'powershell',
    label: 'PowerShell .NET',
    command: (file, targetId) => buildPowerShellDeleteCommand(file, targetId),
  }]);
  assert.equal(calibrations[0].status, 'PASS');
  assert.equal(calibrations[0].operation, 'System.IO.File.Delete');
  assert.equal(calibrations[0].targetIdentityStatus, 'MATCHED');
  assert.equal(calibrations[0].fileExistsAfter, false);
  fs.rmSync(temp, { recursive: true, force: true });
});

test('ambiguous PowerShell error keeps a complete cmd.exe and Node.js run at TEST ERROR', () => {
  const targetPath = 'C:\\Canary\\powershell-outside.txt';
  const definition = { id: 'outside-workspace-powershell', file: targetPath, expected: 'RETAINED', location: 'outside', method: 'powershell' };
  const ambiguousPowerShell = {
    method: 'powershell',
    location: 'outside',
    observed: 'RETAINED',
    ...classifySandboxProbe({
      before: true,
      after: true,
      definition,
      hostCalibration: { method: 'powershell', status: 'PASS', passed: true },
      result: structuredProbeResult({
        runtime: 'powershell', targetId: definition.id, targetPath, status: 1, succeeded: false,
        exceptionType: 'System.ArgumentException', errorClass: 'System.ArgumentException',
        errorCategory: 'InvalidArgument', errorTarget: targetPath,
      }),
    }),
  };
  const probes = [
    classifyStructuredProbe('powershell', 'inside'),
    ambiguousPowerShell,
    classifyStructuredProbe('cmd', 'inside'),
    classifyStructuredProbe('cmd', 'outside'),
    classifyStructuredProbe('node', 'inside'),
    classifyStructuredProbe('node', 'outside'),
  ];
  const summary = summarizeAssessment({ config: { warnings: [] } }, [], completedBoundarySandbox({ probes }));
  assert.equal(ambiguousPowerShell.assessment, 'TEST_ERROR');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.overall, 'TEST ERROR / INCOMPLETE');
  assert.equal(summary.methodCoverage, '2/3');
});


test('summary separates the incomplete active CLI from a passing alternative bundle', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: { complete: false },
    config: { warnings: [] },
  }, [], completedBoundarySandbox({
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    testedCodexVersion: 'codex-cli 0.146.0-alpha.3',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
  }));
  assert.equal(summary.activeCli.bundleStatus, 'INCOMPLETE');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.testedBundle.boundaryStatus, 'PASS');
  assert.match(summary.interpretation.join(' '), /does not validate the active PATH CLI/i);
  assert.match(summary.nextSteps.join(' '), /selected alternative executable passed.*active PATH CLI.*separately/i);
  assert.doesNotMatch(summary.nextSteps.join(' '), /test the selected alternative|Windows sandbox state is AVAILABLE/i);
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

test('share-safe reports disclose removed and retained categories plus manual review', () => {
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: '0.1.0-alpha.11' },
    summary: {
      overall: 'NOT TESTED',
      activeCli: {
        bundleStatus: 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION NOT TESTED',
        resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', boundaryStatus: 'NOT TESTED',
      },
      testedBundle: null,
      sandboxRuntime: 'NOT TESTED',
      execpolicyCoverage: { status: 'NOT_RUN', matched: null, total: null },
      interpretation: [], nextSteps: [], recommendations: [], riskWarnings: [],
    },
    inventory: {
      platform: 'win32', release: '10.0.synthetic', nodeVersion: 'v22.synthetic', nodeRuntimeSource: 'bundled', nodeInPath: false, npmInPath: false,
      elevated: false, codexInstalled: true, codexVersion: 'codex-cli 0.146.0',
      activeBundle: {
        complete: false, installType: 'standalone', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED',
        standaloneResourcesFound: true, standaloneRequiredResourcesPresent: true, missing: [],
      },
      standalonePackages: [], matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [], sandboxWindowsState: 'AVAILABLE',
      doctor: { status: 'COMPLETED', ok: true, overallStatus: 'OK', installationStatus: 'READY', runtimeStatus: 'NOT_TESTED', warningCount: 0 },
      config: { sandboxMode: 'workspace-write', approvalPolicy: 'on-request', defaultPermissions: null, windowsSandbox: true, networkAccess: false, warnings: [] },
    },
    execpolicy: [],
    sandbox: null,
  };
  const payload = buildSupportPayload(report, {
    USERNAME: 'Alice',
    USERPROFILE: 'C:\\Users\\Alice',
    CODEX_HOME: 'C:\\Users\\Alice\\.codex',
  });
  const supportText = renderSupportReport(payload);
  assert.deepEqual(payload.sharingNotice, SHARE_SAFE_SHARING_NOTICE);
  assert.equal(payload.sharingNotice.riskNotice, 'Share-safe output reduces disclosure risk but guarantees neither anonymity nor secrecy.');
  assert.equal(payload.sharingNotice.reviewNotice, 'Review it before public sharing.');
  assert.equal(formatShareSafeSharingNotice(payload.sharingNotice), 'Share-safe output reduces disclosure risk but guarantees neither anonymity nor secrecy. Review it before public sharing. It is designed to remove local usernames, absolute local paths, credential paths, and raw configuration contents. It retains diagnostic version information, installation information, runtime information, and security-status information.');
  assert.match(supportText, /guarantees neither anonymity nor secrecy/i);
  assert.match(supportText, /designed to remove local usernames, absolute local paths, credential paths, and raw configuration contents/i);
  assert.match(supportText, /retains diagnostic version information, installation information, runtime information, and security-status information/i);
  assert.match(supportText, /Review it before public sharing/i);
  assert.equal(payload.environment.windowsRelease, '10.0.synthetic');
  assert.equal(payload.environment.nodeVersion, 'v22.synthetic');
  assert.equal(payload.environment.activeCodexVersion, 'codex-cli 0.146.0');
  assert.equal(payload.environment.activeInstallType, 'standalone');
  assert.equal(payload.environment.activeRuntimeStartup, 'NOT_TESTED');
  assert.equal(payload.environment.doctor.overallStatus, 'OK');
  assert.equal(payload.environment.selectedConfig.sandboxMode, 'workspace-write');
  const serializedNotice = JSON.stringify(payload.sharingNotice);
  assert.doesNotMatch(serializedNotice, /Alice|config\.toml|[A-Za-z]:|\\\\/i);
  assert.equal(serializedNotice.includes('\\'), false);
});

test('public documentation avoids absolute share-safe guarantees', () => {
  const documents = ['../README.md', '../SECURITY.md', '../FAQ.md'].map((file) => fs.readFileSync(new URL(file, import.meta.url), 'utf8'));
  for (const document of documents) {
    assert.doesNotMatch(document, /no environment-specific information|contains no environment information|environment-free report/i);
    assert.match(document, /diagnostic version.*installation.*runtime.*security-status/is);
    assert.match(document, /review.*public|public.*review/is);
  }
});

test('security documentation bounds approval and require_escalated evidence', () => {
  const security = fs.readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
  assert.match(security, /boundary PASS applies only to the sandbox permission profile actually tested/i);
  assert.match(security, /does not establish whether an approved `require_escalated` command leaves that sandbox context/i);
  assert.match(security, /which host or credential context such an execution receives/i);
  assert.match(security, /does not exercise this approval or escalation path/i);
  assert.match(security, /\[openai\/codex#41161\]\(https:\/\/github\.com\/openai\/codex\/issues\/41161\)/);
  assert.match(security, /retained only as evidence-boundary context/i);
  assert.match(security, /does not reproduce or validate that scenario[^.]*not a fix or release-specific claim/i);
  assert.doesNotMatch(security, /codex-cli\s+\d/i);
});

test('Alpha 12 run records exist only in changelog and version-specific evidence', () => {
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const faq = fs.readFileSync(new URL('../FAQ.md', import.meta.url), 'utf8');
  const security = fs.readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
  const changelog = fs.readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
  const testPlan = fs.readFileSync(new URL('../docs/TEST_PLAN.md', import.meta.url), 'utf8');
  const evidence = fs.readFileSync(new URL('../docs/evidence/0.1.0-alpha.12.md', import.meta.url), 'utf8');

  for (const document of [readme, faq, security, testPlan]) {
    assert.doesNotMatch(document, /recorded pre-fix normal-user Windows live run|210\/210|229\/229|33378433400|33913510379|abc18a9241fa86e4852477ff1e291bb9aa3e5df9bdb779c8d3ef4c72e6fd07dd/i);
  }
  assert.match(changelog, /\[Alpha 12 evidence file\]\(docs\/evidence\/0\.1\.0-alpha\.12\.md\)/);
  assert.match(testPlan, /\[version-specific evidence\]\(evidence\/\)/);
  assert.match(evidence, /Recorded pre-fix candidate/i);
  assert.match(evidence, /78dbabbb0747285a708d540e0044ba9deb87a5f7/);
  assert.match(evidence, /33378433400/);
  assert.match(evidence, /abc18a9241fa86e4852477ff1e291bb9aa3e5df9bdb779c8d3ef4c72e6fd07dd/);
  assert.match(evidence, /pre-fix hosted or live evidence does not validate this corrected producer chain/i);
  assert.match(evidence, /Repeat Windows acceptance: completed for this commit and tree/i);
  assert.match(evidence, /The repeat normal-user Windows acceptance tested exactly product commit `1d71e8687c40a7e62a468df6bb93995f992f80d2` and tree `f43769c99813d9828d1f7fa721b07aa2923c819c`/i);
  assert.match(evidence, /Hosted CI: completed for PR head `a973f31af2c8d6d2891106f52afd9dd70dbd3941` in \[Test run `33913510379`\]/i);
  assert.match(evidence, /Ubuntu with Node\.js 18, 20, 22, and 24: 229 tests, 228 passed, 1 intentional Windows-specific skip, and 0 failed in each job/i);
  assert.match(evidence, /Windows with Node\.js 18, 20, 22, and 24: 229 tests, 229 passed, 0 skipped, and 0 failed in each job/i);
  assert.match(evidence, /\[CodeQL run `33913508605`\]\(https:\/\/github\.com\/Ann-Diana\/codex-safety-canary\/actions\/runs\/33913508605\) targeted the same PR head/i);
  assert.match(evidence, /The later documentation commit that records this evidence was not itself live-tested/i);
  assert.match(evidence, /screenshots depict the recorded pre-fix live run/i);
  assert.match(security, /A sandbox boundary PASS requires a fully completed disposable run\./);
  assert.match(security, /All six per-probe Codex process-start markers[^.]*derived boundary aggregate[^.]*separate smoke process-start marker[^.]*`CONFIRMED`/i);
  assert.match(security, /missing evidence is never rewritten as proof that no process started/i);
  assert.match(faq, /An alternative executable discovered by Guided or Sandbox-only must be explicitly selected and bound to one exact filesystem object before the Canary may run its `--version` command/i);
  assert.match(faq, /startup smoke command that neither deletes files nor calls a model/i);
  assert.match(testPlan, /all six per-probe Codex process-start markers are `CONFIRMED`[^.]*derived boundary aggregate is `CONFIRMED`[^.]*separate smoke process-start marker is `CONFIRMED`/i);
  assert.match(testPlan, /Missing, false, unknown, or contradictory evidence must produce `TEST ERROR \/ INCOMPLETE`/i);
  assert.match(evidence, /NOT RUN \(0\/6 decisions checked\)/);
});


test('identity failure messages are scoped to the affected sandbox invocation', () => {
  const source = fs.readFileSync(new URL('../lib/core.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /No sandbox process was started\./);
  assert.match(source, /affected sandbox invocation was not started because the executable no longer matched the identity bound for that invocation/i);
  assert.match(source, /affected sandbox invocation was not started because the selected alternative executable no longer matched its explicit selection binding/i);
});

test('durable public documentation keeps release evidence in the version-specific record', () => {
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const faq = fs.readFileSync(new URL('../FAQ.md', import.meta.url), 'utf8');
  const security = fs.readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
  const changelog = fs.readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
  const testPlan = fs.readFileSync(new URL('../docs/TEST_PLAN.md', import.meta.url), 'utf8');
  const evidence = fs.readFileSync(new URL('../docs/evidence/0.1.0-alpha.12.md', import.meta.url), 'utf8');
  const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const workflow = fs.readFileSync(new URL('../.github/workflows/test.yml', import.meta.url), 'utf8');

  const words = readme.replace(/<[^>]+>/g, ' ').match(/[\p{L}\p{N}][\p{L}\p{N}’'._/-]*/gu) ?? [];
  const topLevelHeadings = readme.match(/^## .+$/gm) ?? [];
  assert.ok(words.length <= 1000, `README word count: ${words.length}`);
  assert.equal(topLevelHeadings.length, 6, `README main headings: ${topLevelHeadings.length}`);
  for (const required of [
    /Windows-first local diagnostic[^.]*Codex CLI/i,
    /This is alpha software\. Its results apply only to the tested setup and do not certify that a computer is secure\./,
    /synthetic disposable files/i,
    /never opens, scans, modifies, or deletes real project files/i,
    /never reads or prints credential contents/i,
    /does not call a model/i,
    /not a command blocker, repair mechanism, backup system, or malware scanner/i,
    /Node\.js 18 or newer through `PATH` or a compatible Node\.js runtime from a recognized Codex desktop runtime cache/i,
    /Node\.js 22 or 24 is recommended/i,
    /\[GitHub Releases page\]\(https:\/\/github\.com\/Ann-Diana\/codex-safety-canary\/releases\)/,
    /\[ZIP help in the FAQ\]\(FAQ\.md#what-should-i-do-if-windows-blocks-the-downloaded-zip\)/,
    /permission profile/i,
    /does not validate[^.]*general security of the computer/i,
    /guarantees neither anonymity nor secrecy/i,
    /review it manually before public sharing/i,
    /\[Frequently asked questions\]\(FAQ\.md\)/,
    /\[Security policy and evidence boundaries\]\(SECURITY\.md\)/,
    /\[Changelog and release links\]\(CHANGELOG\.md\)/,
    /\[Repeatable Windows test plan\]\(docs\/TEST_PLAN\.md\)/,
  ]) assert.match(readme, required);
  const assessmentModes = readme.slice(
    readme.indexOf('## Assessment modes'),
    readme.indexOf('## Understanding results'),
  );
  assert.equal((assessmentModes.match(/^- \*\*/gm) ?? []).length, 4);
  assert.doesNotMatch(assessmentModes, /Report options/i);
  assert.match(assessmentModes, /active PATH CLI is the default/i);
  assert.match(assessmentModes, /alternative starts only after that explicit selection/i);
  assert.match(assessmentModes, /validates only that executable, never the active PATH CLI/i);
  assert.match(readme, /share-safe reports are designed to remove defined path and configuration categories/i);
  assert.doesNotMatch(readme, /^##\s+-|^<{7}|^={7}|^>{7}/m);
  const fenceLines = readme.match(/^```.*$/gm) ?? [];
  assert.equal(fenceLines.length % 2, 0, 'README code fences must be paired');
  for (const line of readme.split(/\r?\n/).filter((value) => !value.startsWith('```'))) {
    assert.equal((line.match(/`/g) ?? []).length % 2, 0, `unpaired inline backtick: ${line}`);
  }
  assert.doesNotMatch(readme, /0\.1\.0-alpha\.12|pre-fix|33378433400|abc18a9241fa86e4852477ff1e291bb9aa3e5df9bdb779c8d3ef4c72e6fd07dd|codex-cli\s+0\.|docs\/screenshots\//i);

  assert.doesNotMatch(faq, /recorded pre-fix|0\.1\.0-alpha\.12|33378433400|codex-cli\s+0\.|229\/229|210\/210/i);
  assert.match(faq, /## What should I do if Windows blocks the downloaded ZIP\?/);
  assert.match(faq, /Properties[^.]*Unblock[^.]*Zulassen[^.]*extract the ZIP again/i);
  assert.match(faq, /alternative executable discovered by Guided or Sandbox-only must be explicitly selected/i);
  assert.match(faq, /startup smoke command that neither deletes files nor calls a model/i);
  assert.match(faq, /Execpolicy is additional user-rule coverage outside the boundary result/i);
  assert.match(faq, /Share-safe.*risk-reduced[^.]*not anonymous or secret/is);

  assert.match(security, /missing, false, unknown, or contradictory process-start marker[^.]*fails closed/i);
  assert.match(security, /require_escalated[^.]*host or credential context/is);
  assert.match(security, /does not exercise this approval or escalation path/i);
  assert.doesNotMatch(security, /codex-cli\s+\d/i);

  for (const procedure of [
    /normal user/i,
    /sandbox command state exactly as `AVAILABLE`/i,
    /Configuration only/i,
    /Execpolicy coverage/i,
    /host deletion preflight/i,
    /startup smoke/i,
    /all six per-probe Codex process-start markers/i,
    /Cleanup/i,
    /Report consistency checks/i,
    /Screenshot and video capture checklist/i,
  ]) assert.match(testPlan, procedure);
  assert.doesNotMatch(testPlan, /Recorded pre-fix|78dbabbb0747285a708d540e0044ba9deb87a5f7|33378433400|33913510379|abc18a9241fa86e4852477ff1e291bb9aa3e5df9bdb779c8d3ef4c72e6fd07dd|codex-cli\s+0\.|Node\.js\s+`?v\d|Windows\s+`?10\.0/i);

  for (const requiredEvidence of [
    /78dbabbb0747285a708d540e0044ba9deb87a5f7/,
    /70348ee7fda0ff578685da385e2f3e36afee5138/,
    /210\/210/,
    /229\/229/,
    /33378433400/,
    /33913510379/,
    /Windows `10\.0\.26200`/,
    /Node\.js `v24\.19\.0`/,
    /codex-cli 0\.151\.0/,
    /codex-cli 0\.145\.0/,
    /abc18a9241fa86e4852477ff1e291bb9aa3e5df9bdb779c8d3ef4c72e6fd07dd/,
    /permission profile `:workspace`/,
    /NOT RUN \(0\/6 decisions checked\)/,
    /Two alternative executables were discovered but never selected or executed/i,
    /Hosted CI: completed for PR head `a973f31af2c8d6d2891106f52afd9dd70dbd3941`/i,
    /Ubuntu with Node\.js 18, 20, 22, and 24: 229 tests, 228 passed, 1 intentional Windows-specific skip, and 0 failed in each job/i,
    /Windows with Node\.js 18, 20, 22, and 24: 229 tests, 229 passed, 0 skipped, and 0 failed in each job/i,
    /Repeat Windows acceptance: completed for this commit and tree/i,
    /The repeat normal-user Windows acceptance tested exactly product commit `1d71e8687c40a7e62a468df6bb93995f992f80d2` and tree `f43769c99813d9828d1f7fa721b07aa2923c819c`/i,
    /The later documentation commit that records this evidence was not itself live-tested/i,
    /does not validate this corrected producer chain/i,
  ]) assert.match(evidence, requiredEvidence);
  assert.match(changelog, /Alpha 12 evidence file/i);

  assert.equal(packageJson.engines.node, '>=18');
  assert.match(workflow, /node-version:\s*\[18, 20, 22, 24\]/);
});

test('release screenshots live in evidence and relative documentation links resolve', () => {
  const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
  const documentPaths = [
    'README.md',
    'FAQ.md',
    'SECURITY.md',
    'CHANGELOG.md',
    'docs/TEST_PLAN.md',
    'docs/evidence/0.1.0-alpha.12.md',
  ];
  const documents = Object.fromEntries(documentPaths.map((relativePath) => [
    relativePath,
    fs.readFileSync(path.join(repositoryRoot, relativePath), 'utf8'),
  ]));
  const readme = documents['README.md'];
  const evidence = documents['docs/evidence/0.1.0-alpha.12.md'];
  const releaseScreenshots = [
    '10-alpha12-menu.png',
    '11-alpha12-boundary-pass.png',
    '12-alpha12-share-safe-report.png',
  ];

  assert.equal(readme.split(/docs\/screenshots\//i).length - 1, 0);
  assert.match(evidence, /screenshots depict the recorded pre-fix live run/i);
  assert.match(evidence, /not final release evidence for the process-evidence-corrected candidate/i);
  for (const name of releaseScreenshots) {
    const relativePath = `../screenshots/${name}`;
    assert.equal(evidence.split(relativePath).length - 1, 1, name);
    assert.equal(fs.existsSync(path.resolve(repositoryRoot, 'docs', 'evidence', relativePath)), true, name);
  }

  for (const [relativeDocumentPath, document] of Object.entries(documents)) {
    const targets = [
      ...[...document.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)].map((match) => match[1]),
      ...[...document.matchAll(/\b(?:src|href)="([^"]+)"/g)].map((match) => match[1]),
    ];
    for (const target of targets) {
      if (/^(?:[a-z][a-z0-9+.-]*:|#)/i.test(target)) continue;
      const localTarget = decodeURIComponent(target.split('#', 1)[0]);
      assert.equal(
        fs.existsSync(path.resolve(repositoryRoot, path.dirname(relativeDocumentPath), localTarget)),
        true,
        `${relativeDocumentPath}: ${target}`,
      );
    }
  }
});


test('all eighteen public PNGs are structurally valid and free of metadata-bearing chunks', () => {
  const docsRoot = fileURLToPath(new URL('../docs/', import.meta.url));
  const pngFiles = fs.readdirSync(path.join(docsRoot, 'assets')).filter((name) => name.endsWith('.png')).map((name) => path.join(docsRoot, 'assets', name))
    .concat(fs.readdirSync(path.join(docsRoot, 'screenshots')).filter((name) => name.endsWith('.png')).map((name) => path.join(docsRoot, 'screenshots', name)));
  assert.equal(pngFiles.length, 18);
  const allowedChunks = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'sRGB', 'gAMA', 'pHYs']);
  const forbiddenChunks = new Set(['caBX', 'eXIf', 'iCCP', 'iTXt', 'tEXt', 'zTXt']);
  const forbiddenMetadataText = ['synthetic-local-user', 'private-test-user', 'c:\\users', 'appdata', 'c2pa', 'jumbf', 'openai-media-service', 'urn:uuid', '-----begin'];
  for (const file of pngFiles) {
    const chunks = readPngChunks(file);
    for (const chunk of chunks) {
      assert.equal(allowedChunks.has(chunk.type), true, `${path.basename(file)}: unexpected ${chunk.type}`);
      assert.equal(forbiddenChunks.has(chunk.type), false, `${path.basename(file)}: ${chunk.type}`);
      if (!['IDAT', 'PLTE'].includes(chunk.type)) {
        const metadataText = chunk.payload.toString('latin1').toLowerCase();
        for (const marker of forbiddenMetadataText) assert.equal(metadataText.includes(marker), false, `${path.basename(file)}: ${marker}`);
      }
    }
  }
  const heroChunks = readPngChunks(path.join(docsRoot, 'assets', 'codex-safety-canary-hero.png')).map((chunk) => chunk.type);
  assert.deepEqual([...new Set(heroChunks)], ['IHDR', 'IDAT', 'IEND']);
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
  assert.equal(payload.execpolicy[0].errorPresent, true);
});

test('share-safe sanitization redacts report-scoped project paths and cleanup text', () => {
  const projectRoot = 'C:\\Users\\Alice\\Documents\\Codex-Lokal\\Projekte\\codex-safety-canary-v0.1.0-alpha.11';
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
    sandbox: { cleanup: { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false, message: `Cleaned ${projectRoot}` }, probes: [], status: 'COMPLETED' },
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
  assert.equal(payload.execpolicy[0].errorPresent, true);
  assert.deepEqual(payload.sandbox.cleanup, { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false, valid: true });
});

test('share-safe path scanner fully redacts quoted, unquoted, UNC, and multiple Windows paths with spaces', () => {
  const normalText = "Normal text, Inc.; O'Brien said Archive remains unchanged.";
  const secretLines = [
    'D:\\Client, Inc\\reports\\private.log',
    'D:\\Research; Archive\\secret.txt',
    "D:\\O'Brien\\Client Alpha\\private.log",
    '"D:\\Client, Inc\\reports\\private.log"',
    '"D:\\Research; Archive\\secret.txt"',
    '"D:\\O\'Brien\\Client Alpha\\private.log"',
    "'D:\\Client, Inc\\reports\\private.log'",
    "'D:\\Research; Archive\\secret.txt'",
    "'D:\\O'Brien\\Client Alpha\\private.log'",
    "\\\\fileserver\\Client, Inc; O'Brien\\Client Alpha\\private.log",
    "multiple D:\\Client, Inc\\reports\\private.log and E:/Research; Archive/O'Brien/secret.txt",
    'D:\\KnownRoot, Inc\\reports\\private.log',
    'D:\\KnownRoot; Archive\\secret.txt',
    "D:\\KnownRoot'Brien\\Client Alpha\\private.log",
  ];
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    summary: {
      overall: 'TEST ERROR / INCOMPLETE', boundary: 'TEST ERROR', sandboxRuntime: 'FAILED', workspaceDeletion: 'NOT TESTED', methodCoverage: 'NOT RUN',
      execpolicyCoverage: { status: 'NOT_RUN', matched: null, total: null }, recommendations: [], interpretation: [...secretLines], nextSteps: [], riskWarnings: [...secretLines],
      activeCli: { bundleStatus: 'INCOMPLETE', boundaryStatus: 'NOT TESTED' }, testedBundle: null,
    },
    inventory: {
      platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: false,
      elevated: false, codexInstalled: true, codexVersion: 'x', activeBundle: { complete: false, missing: [] }, standalonePackages: [],
      matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [], sandboxWindowsState: 'AVAILABLE',
      config: { warnings: [...secretLines] },
    },
    execpolicy: [], sandbox: null,
  };
  const payload = buildSupportPayload(report, { CODEX_HOME: 'D:\\KnownRoot' });
  const serialized = `${JSON.stringify(payload)}\n${renderSupportReport(payload)}`;
  for (const marker of ['Inc', 'Archive', "O'Brien", 'Client Alpha', 'private.log', 'secret.txt', 'fileserver']) {
    assert.equal(serialized.includes(marker), false, `unexpected share-safe marker: ${marker}`);
  }
  const supportStrings = [];
  const collectStrings = (value) => {
    if (typeof value === 'string') supportStrings.push(value);
    else if (Array.isArray(value)) value.forEach(collectStrings);
    else if (value && typeof value === 'object') Object.values(value).forEach(collectStrings);
  };
  collectStrings(payload);
  assert.equal(supportStrings.some((value) => value.includes('\\')), false);
  assert.match(serialized, /%LOCAL_PATH%/);

  const normalReport = {
    ...report,
    summary: { ...report.summary, interpretation: [normalText], riskWarnings: [] },
    inventory: { ...report.inventory, config: { warnings: [] } },
  };
  const normalPayload = buildSupportPayload(normalReport, { CODEX_HOME: 'D:\\KnownRoot' });
  assert.equal(normalPayload.summary.interpretation[0], normalText);
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

test('writeReport recursively redacts host-preflight and nested local paths from share-safe files', () => {
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-support-redaction-'));
  const userRoot = 'C:\\Users\\Alice';
  const projectRoot = `${userRoot}\\Documents\\Codex-Lokal\\Projekte\\codex-safety-canary-v0.1.0-alpha.11`;
  const inventory = {
    platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true,
    elevated: false, codexInstalled: true, codexVersion: 'x', activeCodexPath: `${userRoot}\\AppData\\Local\\OpenAI\\Codex\\bin\\codex.exe`,
    activeBundle: { complete: true, installType: 'classic', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', missing: [] },
    matchingCompleteBundles: [], newerCompleteBundles: [], standalonePackages: [],
    codexHome: `${userRoot}\\.codex`, authFilePresent: false,
    doctor: { status: 'ERROR', ok: false, error: `${userRoot}\\.codex\\doctor.log` },
    ruleFiles: [`${userRoot}\\.codex\\rules\\default.rules`], sandboxWindowsState: 'AVAILABLE', sandboxHelpError: null,
    config: {
      exists: true, path: `${userRoot}\\.codex\\config.toml`, sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null,
      warnings: [
        'D:\\Client, Inc\\reports\\private.log',
        'D:\\Research; Archive\\secret.txt',
        "D:\\O'Brien\\Client Alpha\\private.log",
        "\\\\fileserver\\Client, Inc; O'Brien\\Client Alpha\\private.log",
      ],
    },
  };
  const rules = [{ label: 'synthetic', command: ['test'], status: 'ERROR', decision: null, error: `${projectRoot}\\reports\\execpolicy.log` }];
  const sandbox = {
    status: 'HOST_PREFLIGHT_FAILED', codexSource: 'ACTIVE_CLI', probes: [],
    hostPreflight: { passed: false, filesChecked: 1, error: `${userRoot}\\AppData\\Local\\CodexSafetyCanary\\runs\\run-1\\preflight.log failed` },
    smoke: { passed: false, commandExitCode: 1, setupFailure: false, stderr: `${projectRoot}\\runs\\smoke.log` },
    error: `${projectRoot}\\runs\\sandbox-error.log`,
    cleanup: `Cleanup failed for ${projectRoot}\\runs\\run-1`,
  };

  const result = writeReport({ inventory, rules, sandbox, appRoot });
  const supportJson = JSON.parse(fs.readFileSync(result.supportJsonPath, 'utf8'));
  const supportText = fs.readFileSync(result.supportTxtPath, 'utf8');
  const serialized = `${JSON.stringify(supportJson)}\n${supportText}`;
  const forbidden = /Alice|C:\\Users|AppData|\.codex|Codex-Lokal|codex-safety-canary-v0\.1\.0-alpha\.11|\bInc\b|Archive|O'Brien|Client Alpha|private\.log|secret\.txt|fileserver|reports\\|runs\\|\.log\b/i;

  assert.doesNotMatch(serialized, forbidden);
  assert.deepEqual(supportJson.sandbox.hostPreflight, {
    status: 'FAILED',
    passed: false,
    filesChecked: 1,
    errorPresent: true,
  });
  assert.equal(supportJson.summary.boundary, 'TEST ERROR');
  assert.equal(supportJson.summary.sandboxRuntime, 'HOST PREFLIGHT FAILED');
  fs.rmSync(appRoot, { recursive: true, force: true });
});

test('share-safe reports include calibration and evidence status without paths or raw errors', () => {
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-calibration-report-'));
  const secretPath = 'C:\\Users\\Alice\\AppData\\Local\\CodexSafetyCanary\\runs\\run-1\\control\\powershell-outside.txt';
  const probes = completeBoundaryProbes();
  const powershellOutside = probes.find((probe) => probe.method === 'powershell' && probe.location === 'outside');
  Object.assign(powershellOutside, {
    hostCalibrationStatus: 'PASS', targetIdentityStatus: 'MATCHED',
    operation: 'System.IO.File.Delete', exceptionType: 'System.UnauthorizedAccessException',
    errorClass: 'System.UnauthorizedAccessException', errorCategory: 'PermissionDenied',
    errorHResult: -2147024891, nativeWin32ErrorCode: 5,
    errorTarget: secretPath, targetPath: secretPath, errorMessage: `Access denied ${secretPath}`,
  });
  const inventory = {
    platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: false,
    elevated: false, codexInstalled: true, codexVersion: 'x', activeCodexPath: 'C:\\Users\\Alice\\codex.exe',
    activeBundle: { complete: true, resourceLayout: 'COMPLETE' }, standalonePackages: [], matchingCompleteBundles: [], newerCompleteBundles: [],
    codexHome: 'C:\\Users\\Alice\\.codex', authFilePresent: false, doctor: null, ruleFiles: [], sandboxWindowsState: 'AVAILABLE',
    config: { exists: false, path: 'C:\\Users\\Alice\\.codex\\config.toml', warnings: [] },
  };
  const result = writeReport({ inventory, sandbox: completedBoundarySandbox({ probes }), appRoot });
  const supportText = fs.readFileSync(result.supportTxtPath, 'utf8');
  const supportJsonText = fs.readFileSync(result.supportJsonPath, 'utf8');
  const combined = `${supportText}\n${supportJsonText}`;
  assert.match(combined, /Host calibration powershell: PASS/i);
  assert.match(combined, /System\.IO\.File\.Delete/i);
  assert.match(combined, /System\.UnauthorizedAccessException/i);
  assert.match(combined, /native Win32[^\n]*5/i);
  assert.match(combined, /target identity[=:]MATCHED/i);
  assert.doesNotMatch(combined, /Alice|AppData|Invalid path|powershell-outside\.txt|C:\\/i);
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

test('unknown execpolicy schema stays visible without affecting a valid boundary result', () => {
  const inventory = {
    platform: 'win32', release: 'synthetic', nodeVersion: 'synthetic', nodeRuntimeSource: 'TEST', nodeInPath: true, npmInPath: false,
    elevated: false, codexInstalled: true, codexVersion: 'codex-cli synthetic', activeCodexPath: null,
    activeBundle: { complete: true, probeEligible: true, resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', missing: [] },
    standalonePackages: [], matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [], sandboxWindowsState: 'AVAILABLE',
    config: { exists: false, sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] },
  };
  const rules = [{
    id: 'schema-check', label: 'Synthetic schema check', command: ['synthetic'], status: 'UNKNOWN_SCHEMA', decision: null,
    raw: { metadata: { first: 'allow', later: 'forbidden' } }, error: 'No recognized top-level execpolicy decision field was present.',
  }];
  const sandbox = completedBoundarySandbox();
  const summary = summarizeAssessment(inventory, rules, sandbox, { execpolicyRun: true });
  assert.equal(summary.boundary, 'PASS');
  assert.deepEqual(summary.execpolicyCoverage, { status: 'UNKNOWN_SCHEMA', matched: null, total: 1 });
  assert.equal(summary.recommendations.some((item) => item.code === 'EXECPOLICY_NO_RESTRICTIVE_MATCHES'), false);
  const report = {
    generatedAt: '2026-07-31T00:00:00Z', tool: { name: 'Canary', version: '0.1.0-alpha.11' }, assessmentMode: ASSESSMENT_MODES.GUIDED,
    inventory, summary, execpolicy: rules, sandbox,
  };
  const detailText = renderTextReport(report);
  const supportPayload = buildSupportPayload(report, {});
  const supportText = renderSupportReport(supportPayload);
  assert.match(detailText, /Execpolicy coverage:\s+UNKNOWN_SCHEMA/i);
  assert.match(detailText, /Synthetic schema check: UNKNOWN_SCHEMA/i);
  assert.match(supportText, /Execpolicy rule coverage:\s+UNKNOWN_SCHEMA/i);
  assert.equal(supportPayload.execpolicy[0].status, 'UNKNOWN_SCHEMA');
  assert.equal(supportPayload.summary.boundary, 'PASS');
  assert.doesNotMatch(`${detailText}\n${supportText}`, /NO_MATCH|NO MATCH/);
});

test('invalid execpolicy JSON remains a parsing error', () => {
  assert.throws(() => parseExecpolicyOutput('{not-json'), SyntaxError);
});

test('boundary documentation never describes incomplete evidence as a partial pass', () => {
  const files = ['../README.md', '../docs/TEST_PLAN.md', '../FAQ.md', '../SECURITY.md'];
  for (const file of files) {
    const document = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.doesNotMatch(document, /partial[^.\n]{0,50}\bpass\b/i);
  }
});

test('manual acceptance documentation matches skipped Doctor and the actual report dialog', () => {
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const faq = fs.readFileSync(new URL('../FAQ.md', import.meta.url), 'utf8');
  const security = fs.readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
  const testPlan = fs.readFileSync(new URL('../docs/TEST_PLAN.md', import.meta.url), 'utf8');

  for (const document of [faq, security, testPlan]) {
    assert.match(document, /Doctor[^\n]*NOT_RUN|NOT_RUN[^\n]*Doctor/i);
    assert.doesNotMatch(document, /codex doctor[^.\n]*(?:remains|is|as) (?:non-blocking )?read-only evidence/i);
  }
  assert.match(readme, /does not start `codex doctor`/i);
  assert.match(readme, /Reports open only when selected from the report dialog or menu/i);

  const configurationSection = testPlan.slice(
    testPlan.indexOf('## Test 1 – Configuration only'),
    testPlan.indexOf('## Test 2 – Execpolicy coverage')
  );
  assert.match(configurationSection, /no Doctor question[^.]*NOT_RUN/is);
  assert.match(configurationSection, /Notepad has not opened automatically\. Press `O`/i);
  assert.doesNotMatch(configurationSection, /report opens in Notepad/i);
  assert.equal(testPlan.includes('tested executable choice'), false);
  assert.match(testPlan, /alternative executable list is inventory only/i);
  assert.match(testPlan, /No Doctor question or executable-selection question may appear/i);
  assert.match(testPlan, /same `O`\/`F`\/`M` report dialog/i);
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

test('recommendation severities follow the alpha-11 diagnostic matrix', () => {
  const activePass = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], completedBoundarySandbox());
  assert.equal(activePass.recommendations.find((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS')?.severity, 'INFO');

  const alternativePass = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: false }, codexVersion: 'x' }, [], completedBoundarySandbox({
    codexSource: 'NEWER_COMPLETE_BUNDLE', versionMismatch: true, testedCodexVersion: 'y', activeCodexVersion: 'x',
  }));
  assert.equal(alternativePass.recommendations.find((item) => item.code === 'ALTERNATIVE_BUNDLE_BOUNDARY_PASS')?.severity, 'INFO');
  assert.equal(alternativePass.recommendations.find((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE')?.severity, 'ACTION_RECOMMENDED');

  const setupFailed = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED' }, [], { status: 'SETUP_FAILED', probes: [] });
  assert.equal(setupFailed.recommendations.find((item) => item.code === 'SANDBOX_SETUP_FAILED')?.severity, 'ACTION_RECOMMENDED');
  assert.equal(setupFailed.recommendations.find((item) => item.code === 'BOUNDARY_NOT_CONFIRMED')?.severity, 'PROTECTION_NOT_CONFIRMED');
  const invalidControl = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], completedBoundarySandbox({
    probes: [
      { method: 'powershell', location: 'inside', assessment: 'UNEXPECTED', observed: 'RETAINED' },
      { method: 'powershell', location: 'outside', assessment: 'PASS', observed: 'RETAINED' },
    ],
  }));
  assert.equal(invalidControl.recommendations.find((item) => item.code === 'BOUNDARY_NOT_CONFIRMED')?.severity, 'PROTECTION_NOT_CONFIRMED');

  const gap = summarizeAssessment({ config: { warnings: [] }, activeBundle: { complete: true }, codexVersion: 'x' }, [], completedBoundarySandbox({
    probes: completeBoundaryProbes({ gapMethod: 'powershell' }),
  }));
  assert.equal(gap.recommendations.find((item) => item.code === 'BOUNDARY_GAP')?.severity, 'POTENTIAL_SECURITY_GAP');
  assert.equal(gap.boundary, 'GAP');
  assert.equal(gap.methodCoverage, '2/3');
  assert.equal(gap.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED'), false);

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

test('standalone release versions are parsed from Windows release directory names', () => {
  assert.equal(parseStandaloneReleaseVersion('0.146.0-x86_64-pc-windows-msvc'), '0.146.0');
  assert.equal(parseStandaloneReleaseVersion('0.146.0-alpha.3-x86_64-pc-windows-msvc'), '0.146.0-alpha.3');
  assert.equal(parseStandaloneReleaseVersion('not-a-version'), null);
});

test('standalone package discovery records resources separately from classic bundle layout', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-'));
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  fs.mkdirSync(path.join(release, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(release, 'codex-resources'), { recursive: true });
  fs.mkdirSync(path.join(release, 'codex-path'), { recursive: true });
  const executable = path.join(release, 'bin', 'codex.exe');
  fs.writeFileSync(executable, 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-path', 'rg.exe'), 'synthetic');

  const packages = discoverStandalonePackages(codexHome);
  assert.equal(packages.length, 1);
  assert.equal(packages[0].releaseVersion, '0.146.0');
  assert.equal(packages[0].resourcesFound, true);
  assert.equal(packages[0].requiredResourcesPresent, true);

  const bundle = inspectCodexBundle(executable, { codexHome, standalonePackages: packages });
  assert.equal(bundle.installType, 'standalone');
  assert.equal(bundle.helperLayout, 'STANDALONE_RESOURCES');
  assert.equal(bundle.complete, false);
  assert.equal(bundle.probeEligible, true);
  assert.equal(bundle.resourceLayout, 'COMPLETE');
  assert.equal(bundle.helperResolution, 'NOT_TESTED');
  assert.equal(bundle.runtimeStartup, 'NOT_TESTED');
  assert.equal(bundle.helperResolutionProven, false);
  assert.equal(bundle.standaloneRequiredResourcesPresent, true);

  const env = { CODEX_HOME: codexHome, LOCALAPPDATA: path.join(codexHome, 'LocalAppData') };
  assert.deepEqual(discoverCodexBundlePaths(env, { platform: 'win32' }).map((item) => path.basename(item)), ['codex.exe']);
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('same-version standalone resources remain neutral inventory for a distinct active launcher', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-launcher-'));
  const codexHome = path.join(root, '.codex');
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const launcherDir = path.join(root, 'LocalAppData', 'Programs', 'OpenAI', 'Codex', 'bin');
  fs.mkdirSync(path.join(release, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(release, 'codex-resources'), { recursive: true });
  fs.mkdirSync(path.join(release, 'codex-path'), { recursive: true });
  fs.mkdirSync(launcherDir, { recursive: true });
  fs.writeFileSync(path.join(release, 'bin', 'codex.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-path', 'rg.exe'), 'synthetic');
  const activeLauncher = path.join(launcherDir, 'codex.exe');
  fs.writeFileSync(activeLauncher, 'synthetic launcher');

  const packages = discoverStandalonePackages(codexHome);
  const bundle = inspectCodexBundle(activeLauncher, { codexHome, activeVersion: 'codex-cli 0.146.0', standalonePackages: packages });
  assert.equal(bundle.complete, false);
  assert.equal(bundle.installType, 'classic');
  assert.equal(bundle.standaloneResourcesFound, false);
  assert.equal(bundle.resourceLayout, 'MISSING');
  assert.equal(bundle.helperResolution, 'NOT_TESTED');
  assert.equal(bundle.runtimeStartup, 'NOT_TESTED');
  assert.equal(bundle.helperResolutionProven, false);
  assert.equal(bundle.resourceVersionMatchesActive, null);
  assert.equal(bundle.standaloneResourceBinding, null);

  const diagnostics = buildRuntimeDiagnostics({
    activeBundle: bundle,
    standalonePackages: packages,
    sandboxHelpError: 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe program not found',
    sandboxHelpRuntimeEvidence: buildSandboxRuntimeEvidence(
      'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe program not found',
      { step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI' }
    ),
  }, null);
  assert.equal(diagnostics.some((item) => item.code === 'STANDALONE_RESOURCES_FOUND'), false);
  assert.equal(diagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('foreign standalone resources do not create an active-CLI runtime diagnostic', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-mismatch-'));
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const active = path.join(codexHome, 'active', 'codex.exe');
  fs.mkdirSync(path.join(release, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(release, 'codex-resources'), { recursive: true });
  fs.mkdirSync(path.dirname(active), { recursive: true });
  fs.writeFileSync(path.join(release, 'bin', 'codex.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
  fs.writeFileSync(path.join(release, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
  fs.writeFileSync(active, 'synthetic');
  const packages = discoverStandalonePackages(codexHome);
  const bundle = inspectCodexBundle(active, { codexHome, activeVersion: 'codex-cli 0.145.0', standalonePackages: packages });
  assert.equal(bundle.complete, false);
  assert.equal(bundle.standaloneResourcesFound, false);
  assert.equal(bundle.resourceVersionMatchesActive, null);
  const diagnostics = buildRuntimeDiagnostics({
    codexVersion: 'codex-cli 0.145.0',
    activeBundle: bundle,
    standalonePackages: packages,
    sandboxHelpError: 'orchestrator_helper_launch_failed: program not found',
  }, null);
  assert.equal(packages.length, 1);
  assert.equal(diagnostics.some((item) => item.code === 'STANDALONE_RESOURCES_FOUND' && item.target === 'ACTIVE_CLI'), false);
  assert.equal(diagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), false);
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('command runner process creation failures are distinct from helper resolution failures', () => {
  const error = 'codex-command-runner.exe CreateProcessWithLogonW failed: 2';
  const runtimeEvidence = buildSandboxRuntimeEvidence(error, {
    step: 'SANDBOX_SMOKE', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
  });
  assert.equal(detectCommandRunnerProcessCreationFailure(error), false);
  assert.equal(detectCommandRunnerProcessCreationFailure(error, runtimeEvidence), true);
  assert.equal(detectSandboxHelperResolutionFailure(error), false);
  const inventory = {
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: { complete: true, probeEligible: true, installType: 'classic', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    doctor: { ok: true },
    sandboxWindowsState: 'AVAILABLE',
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
  };
  const summary = summarizeAssessment(inventory, [], {
    status: 'SETUP_FAILED', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    testedCodexVersion: 'codex-cli 0.146.0', probes: [], runtimeEvidence, error,
  });
  assert.equal(summary.sandboxRuntime, 'FAILED – PROCESS CREATION FAILED');
  assert.equal(summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.activeCli.boundaryStatus, 'TEST ERROR');
  assert.equal(summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(summary.testedBundle.boundaryStatus, 'TEST ERROR');
  assert.equal(summary.recommendations.find((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED')?.severity, 'PROTECTION_NOT_CONFIRMED');
  assert.equal(summary.recommendations.find((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED')?.severity, 'PROTECTION_NOT_CONFIRMED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
});

test('unbound process-creation text never confirms helper resolution', () => {
  const messages = [
    'unrelated diagnostic subsystem: CreateProcessWithLogonW failed: 2',
    'foreign diagnostics begin; codex-command-runner.exe CreateProcessWithLogonW failed: 2; foreign diagnostics end',
    'codex-command-runner.exe CreateProcessWithLogonW failed: 2',
  ];
  for (const sandboxHelpError of messages) {
    const observation = deriveSandboxRuntimeObservation({
      sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED',
      sandboxSetupFailed: true,
      sandboxHelpError,
      activeBundle: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    }, null);
    assert.equal(observation.helperResolution, 'NOT_TESTED');
    assert.equal(observation.runtimeStartup, 'FAILED');
    assert.equal(observation.commandRunnerProcessCreationFailed, false);
  }
});

test('bound runtime evidence stays scoped to the selected executable', () => {
  const error = 'codex-command-runner.exe CreateProcessWithLogonW failed: 2';
  const activeEvidence = buildSandboxRuntimeEvidence(error, {
    step: 'SANDBOX_SMOKE', codexSource: 'NEWER_COMPLETE_BUNDLE', codexExecutableIdentity: 'synthetic-other-bundle-identity',
  });
  const mismatched = deriveSandboxRuntimeObservation({
    activeBundle: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
  }, {
    status: 'SETUP_FAILED', codexSource: 'NEWER_COMPLETE_BUNDLE', codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    runtimeEvidence: activeEvidence,
    testedBundleMetadata: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' }, error,
  });
  assert.equal(mismatched.helperResolution, 'NOT_TESTED');
  assert.equal(mismatched.runtimeStartup, 'FAILED');

  const testedEvidence = buildSandboxRuntimeEvidence(error, {
    step: 'SANDBOX_SMOKE', codexSource: 'NEWER_COMPLETE_BUNDLE', codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
  });
  const matched = deriveSandboxRuntimeObservation({}, {
    status: 'SETUP_FAILED', codexSource: 'NEWER_COMPLETE_BUNDLE', codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    runtimeEvidence: testedEvidence,
    testedBundleMetadata: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' }, error,
  });
  assert.equal(matched.helperResolution, 'CONFIRMED');
  assert.equal(matched.runtimeStartup, 'FAILED');
});

test('bound runtime evidence stays scoped to help versus smoke invocation stages', () => {
  const error = 'codex-command-runner.exe CreateProcessWithLogonW failed: 2';
  const helpEvidence = buildSandboxRuntimeEvidence(error, {
    step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
  });
  const smokeEvidence = buildSandboxRuntimeEvidence(error, {
    step: 'SANDBOX_SMOKE', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
  });

  const helpAttachedToSmoke = deriveSandboxRuntimeObservation({
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    activeBundle: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
  }, {
    status: 'SETUP_FAILED', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    runtimeEvidence: helpEvidence, error,
  });
  assert.equal(helpAttachedToSmoke.helperResolution, 'NOT_TESTED');
  assert.equal(helpAttachedToSmoke.runtimeStartup, 'FAILED');
  assert.equal(helpAttachedToSmoke.commandRunnerProcessCreationFailed, false);

  const smokeAttachedToHelp = deriveSandboxRuntimeObservation({
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    activeBundle: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED', sandboxHelpRuntimeEvidence: smokeEvidence,
    sandboxHelpError: error,
  }, null);
  assert.equal(smokeAttachedToHelp.helperResolution, 'NOT_TESTED');
  assert.equal(smokeAttachedToHelp.commandRunnerProcessCreationFailed, false);
});

test('explicit bound setup-helper evidence fails helper resolution without a boundary pass', () => {
  const error = 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT';
  const summary = summarizeAssessment({
    config: { warnings: [] }, sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED', sandboxSetupFailed: true,
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    sandboxHelpError: error,
    sandboxHelpRuntimeEvidence: buildSandboxRuntimeEvidence(error, {
      step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    }),
    activeBundle: { helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', resourceLayout: 'COMPLETE' },
  }, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false });
  assert.equal(summary.activeCli.helperResolution, 'FAILED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.boundary, 'NOT TESTED');
});

test('alternative standalone command-runner failure confirms helper resolution but not runtime or boundary', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.145.0',
    config: { warnings: [] },
    activeBundle: { complete: false, probeEligible: false, installType: 'classic', resourceLayout: 'MISSING', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    sandboxWindowsState: 'AVAILABLE',
  }, [], {
    status: 'SETUP_FAILED',
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    testedCodexVersion: 'codex-cli 0.146.0',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
    testedBundleMetadata: {
      installType: 'standalone', complete: false, probeEligible: true,
      resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true, standaloneRequiredResourcesPresent: true, releaseVersion: '0.146.0',
    },
    smoke: { passed: false, stderr: 'CreateProcessWithLogonW failed: 2' },
    probes: [],
    runtimeEvidence: buildSandboxRuntimeEvidence('codex-command-runner.exe CreateProcessWithLogonW failed: 2', {
      step: 'SANDBOX_SMOKE', codexSource: 'NEWER_COMPLETE_BUNDLE',
      codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    }),
    error: 'codex-command-runner.exe CreateProcessWithLogonW failed: 2',
  }, { execpolicyRun: false });
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.testedBundle.resourceLayout, 'COMPLETE');
  assert.equal(summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(summary.testedBundle.boundaryStatus, 'TEST ERROR');
  assert.equal(summary.recommendations.find((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED')?.severity, 'PROTECTION_NOT_CONFIRMED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
});

test('Doctor states keep skipped, unavailable, error, and completed evidence distinct', () => {
  const skipped = createCodexDoctorInventoryStatus(true);
  assert.equal(skipped.status, 'NOT_RUN');
  assert.equal(skipped.ok, false);
  assert.equal(skipped.error, null);
  assert.match(skipped.reason, /no Doctor process was started/i);

  const unavailable = createCodexDoctorInventoryStatus(false);
  assert.equal(unavailable.status, 'UNAVAILABLE');
  assert.equal(unavailable.ok, false);
  assert.equal(unavailable.error, null);

  const ok = parseCodexDoctorOutput({ status: 0, stdout: JSON.stringify({ overallStatus: 'ok', checks: { installation: { status: 'ok' }, runtime: { status: 'ok' } } }), stderr: '' });
  assert.equal(ok.status, 'COMPLETED');
  assert.equal(ok.ok, true);
  assert.equal(ok.installationStatus, 'ok');
  const invalid = parseCodexDoctorOutput({ status: 0, stdout: 'not-json', stderr: '' });
  assert.equal(invalid.status, 'ERROR');
  assert.equal(invalid.ok, false);
  const failed = parseCodexDoctorOutput({ status: 1, stdout: '', stderr: 'doctor failed' });
  assert.equal(failed.status, 'ERROR');
});

test('production inventory contains no Doctor subprocess invocation', () => {
  const source = fs.readFileSync(new URL('../lib/core.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\[\s*['"]doctor['"]\s*,\s*['"]--json['"]\s*\]/);
  assert.doesNotMatch(source, /function\s+runCodexDoctor\b|runCodexDoctor\s*\(/);
  const inventoryStart = source.indexOf('export function getCodexInventory');
  const inventoryEnd = source.indexOf('export function isElevatedWindows', inventoryStart);
  assert.ok(inventoryStart >= 0 && inventoryEnd > inventoryStart);
  const inventorySource = source.slice(inventoryStart, inventoryEnd);
  assert.match(inventorySource, /createCodexDoctorInventoryStatus\(installed\)/);
  assert.doesNotMatch(inventorySource, /doctor[^\n]*(?:invoke|spawn|exec)/i);
});

test('auth.json inventory uses an existence check only', () => {
  const calls = [];
  const fileSystem = {
    existsSync(candidate) {
      calls.push(candidate);
      return true;
    },
  };
  assert.equal(authFileExists('C:\\Synthetic\\CodexHome', fileSystem), true);
  assert.deepEqual(calls, [path.join('C:\\Synthetic\\CodexHome', 'auth.json')]);
});

test('share-safe payload redacts standalone paths and nested sandbox diagnostics', () => {
  const userRoot = 'C:\\Users\\Alice';
  const codexHome = `${userRoot}\\.codex`;
  const releaseDir = `${codexHome}\\packages\\standalone\\releases\\0.146.0-x86_64-pc-windows-msvc`;
  const report = {
    generatedAt: '2026-01-01T00:00:00Z',
    tool: { name: 'Canary', version: 'x' },
    assessmentMode: ASSESSMENT_MODES.GUIDED,
    summary: {
      overall: 'TEST ERROR / INCOMPLETE',
      boundary: 'TEST ERROR',
      sandboxRuntime: 'FAILED – HELPER NOT RESOLVABLE',
      workspaceDeletion: 'NOT TESTED',
      methodCoverage: 'NOT RUN',
      execpolicyCoverage: { status: 'NOT_RUN', matched: null, total: null },
      riskWarnings: [],
      activeCli: { bundleStatus: 'STANDALONE RESOURCES PRESENT – LAUNCHER RESOLUTION NOT CONFIRMED', boundaryStatus: 'NOT TESTED' },
      testedBundle: null,
      runtimeDiagnostics: [],
      recommendations: [],
      interpretation: [],
      nextSteps: [],
    },
    inventory: {
      platform: 'win32', release: 'x', nodeVersion: 'x', nodeRuntimeSource: 'PATH', nodeInPath: true, npmInPath: true, elevated: false,
      codexInstalled: true, codexVersion: 'codex-cli 0.146.0', activeCodexPath: `${userRoot}\\AppData\\Local\\Programs\\OpenAI\\Codex\\bin\\codex.exe`, codexHome, authFilePresent: false,
      activeBundle: {
        complete: false,
        missing: ['codex-windows-sandbox-setup.exe'],
        installType: 'standalone',
        helperLayout: 'STANDALONE_RESOURCES',
        standaloneResourcesFound: true,
        standaloneRequiredResourcesPresent: true,
        standalonePackage: {
          releaseDir,
          binDir: `${releaseDir}\\bin`,
          codexResourcesDir: `${releaseDir}\\codex-resources`,
          codexPathDir: `${releaseDir}\\codex-path`,
          executablePath: `${releaseDir}\\bin\\codex.exe`,
          files: { setupHelper: `${releaseDir}\\codex-resources\\codex-windows-sandbox-setup.exe` },
        },
      },
      standalonePackages: [{ source: 'release', releaseVersion: '0.146.0', resourcesFound: true, codexPathFound: true, aliases: [`${codexHome}\\packages\\standalone\\current`], requiredResourcesPresent: true, requiredResourcesMissing: [], optionalResourcesMissing: [] }],
      doctor: { status: 'COMPLETED', ok: true, overallStatus: 'ok', error: `${releaseDir}\\codex-resources\\codex-windows-sandbox-setup.exe` },
      matchingCompleteBundles: [], newerCompleteBundles: [], ruleFiles: [`${codexHome}\\rules\\danger.rules`],
      config: { exists: true, path: `${codexHome}\\config.toml`, warnings: [] },
      sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED', sandboxHelpError: `${releaseDir}\\codex-resources\\codex-windows-sandbox-setup.exe program not found`,
    },
    execpolicy: [],
    sandbox: { status: 'SETUP_FAILED', probes: [], error: `${releaseDir}\\codex-command-runner.exe CreateProcessWithLogonW failed: 2`, cleanup: `${userRoot}\\AppData\\Local\\Temp\\runs` },
  };
  const payload = buildSupportPayload(report, { CODEX_HOME: codexHome, LOCALAPPDATA: `${userRoot}\\AppData\\Local`, APPDATA: `${userRoot}\\AppData\\Roaming` });
  const serialized = JSON.stringify(payload);
  assert.equal(payload.environment.standalonePackages[0].aliasCount, 1);
  assert.doesNotMatch(serialized, /Alice/);
  assert.doesNotMatch(serialized, /C:\\Users/i);
  assert.doesNotMatch(serialized, /AppData/i);
  assert.doesNotMatch(serialized, /config\.toml/i);
  assert.doesNotMatch(serialized, /codex\.exe/i);
  assert.doesNotMatch(serialized, /0\.146\.0-x86_64-pc-windows-msvc/i);
  assert.doesNotMatch(serialized, /danger\.rules/i);
});

test('standalone resources without smoke are not complete and do not prove helper resolution', () => {
  const inventory = {
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: {
      complete: false,
      probeEligible: true,
      installType: 'standalone',
      helperLayout: 'STANDALONE_RESOURCES',
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      helperResolutionProven: false,
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
    },
  };
  const summary = summarizeAssessment(inventory, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false });
  assert.equal(summary.activeCli.bundleStatus, 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION NOT TESTED');
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'NOT_TESTED');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.activeCli.bundleStatus.includes('COMPLETE'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE'), false);
  assert.doesNotMatch(summary.nextSteps.join('\n'), /update or reinstall/i);
  assert.match(summary.nextSteps.join('\n'), /controlled runtime preflight/i);
});

function standaloneInventoryWithSandboxHelp(error = null, state = 'AVAILABLE_BUT_SETUP_FAILED') {
  return {
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    doctor: { ok: true },
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    sandboxWindowsState: state,
    sandboxSetupFailed: state === 'AVAILABLE_BUT_SETUP_FAILED',
    sandboxHelpError: error,
    sandboxHelpRuntimeEvidence: error
      ? buildSandboxRuntimeEvidence(error, {
        step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
      })
      : null,
    activeBundle: {
      complete: false,
      probeEligible: true,
      installType: 'standalone',
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
      resourceVersionMatchesActive: true,
      standalonePackage: { releaseVersion: '0.146.0' },
    },
    standalonePackages: [],
  };
}

test('configuration-only preserves setup-helper resolution failure observed during sandbox help inventory', () => {
  const summary = summarizeAssessment(
    standaloneInventoryWithSandboxHelp('orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT'),
    [],
    null,
    { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false }
  );
  assert.equal(summary.activeCli.helperResolution, 'FAILED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.sandboxRuntime, 'FAILED – HELPER NOT RESOLVABLE');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
});

test('guided decline preserves sandbox-help runtime failure while declining only later boundary probes', () => {
  const summary = summarizeAssessment(
    standaloneInventoryWithSandboxHelp('orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT'),
    [],
    null,
    { assessmentMode: ASSESSMENT_MODES.GUIDED_LIVE_PROBES_SKIPPED, execpolicyRun: true, boundaryAssessmentDeclined: true }
  );
  assert.equal(summary.activeCli.helperResolution, 'FAILED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.sandboxRuntime, 'FAILED – HELPER NOT RESOLVABLE');
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED'), true);
});

test('command-runner process failure observed during sandbox help confirms helper resolution only', () => {
  const summary = summarizeAssessment(
    standaloneInventoryWithSandboxHelp('codex-command-runner.exe CreateProcessWithLogonW failed: 2'),
    [],
    null,
    { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false }
  );
  assert.equal(summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.sandboxRuntime, 'FAILED – PROCESS CREATION FAILED');
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
});

test('generic elevation failure observed during sandbox help leaves helper resolution untested', () => {
  const summary = summarizeAssessment(
    standaloneInventoryWithSandboxHelp('requested operation requires elevation (os error 740)'),
    [],
    null,
    { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false }
  );
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.sandboxRuntime, 'FAILED');
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), true);
});

test('successful sandbox help without smoke leaves helper and runtime untested', () => {
  const summary = summarizeAssessment(
    standaloneInventoryWithSandboxHelp(null, 'AVAILABLE'),
    [],
    null,
    { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false }
  );
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'NOT_TESTED');
  assert.equal(summary.sandboxRuntime, 'NOT TESTED');
  assert.equal(summary.boundary, 'NOT TESTED');
});

test('declined standalone live probes do not claim helper resolution', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: {
      complete: false,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
    },
  }, [], null, { assessmentMode: ASSESSMENT_MODES.GUIDED_LIVE_PROBES_SKIPPED, execpolicyRun: true, boundaryAssessmentDeclined: true });
  assert.equal(summary.sandboxRuntime, 'NOT RUN');
  assert.equal(summary.activeCli.bundleStatus, 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION NOT TESTED');
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.recommendations.find((item) => item.code === 'BOUNDARY_ASSESSMENT_DECLINED')?.severity, 'INFO');
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE'), false);
  assert.doesNotMatch(summary.nextSteps.join('\n'), /update or reinstall/i);
  assert.match(summary.nextSteps.join('\n'), /controlled runtime preflight and optional live probes/i);
});

test('partial standalone resource layout retains the update or reinstall recommendation', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: {
      complete: false,
      probeEligible: false,
      installType: 'standalone',
      resourceLayout: 'PARTIAL',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: false,
    },
  }, [], null, { assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY, execpolicyRun: false });
  assert.equal(summary.recommendations.find((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE')?.severity, 'ACTION_RECOMMENDED');
  assert.match(summary.nextSteps.join('\n'), /update or reinstall/i);
  assert.match(summary.nextSteps.join('\n'), /standalone package.*complete required resource layout/i);
});

test('failed active standalone helper keeps the specific diagnostic without a generic incomplete-bundle recommendation', () => {
  const activeBundle = {
    complete: false,
    probeEligible: true,
    installType: 'standalone',
    resourceLayout: 'COMPLETE',
    helperResolution: 'NOT_TESTED',
    runtimeStartup: 'NOT_TESTED',
    standaloneResourcesFound: true,
    standaloneRequiredResourcesPresent: true,
    resourceVersionMatchesActive: true,
    standalonePackage: { releaseVersion: '0.146.0' },
  };
  const testedBundleMetadata = {
    installType: 'standalone',
    complete: false,
    probeEligible: true,
    resourceLayout: 'COMPLETE',
    helperResolution: 'NOT_TESTED',
    runtimeStartup: 'NOT_TESTED',
    standaloneResourcesFound: true,
    standaloneRequiredResourcesPresent: true,
    resourceVersionMatchesActive: true,
    releaseVersion: '0.146.0',
  };
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle,
    standalonePackages: [],
    sandboxWindowsState: 'AVAILABLE',
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
  }, [], {
    status: 'SETUP_FAILED',
    codexSource: 'ACTIVE_CLI',
    codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    testedCodexVersion: 'codex-cli 0.146.0',
    testedBundleMetadata,
    smoke: { passed: false, stderr: 'orchestrator_helper_launch_failed: program not found' },
    probes: [],
    runtimeEvidence: buildSandboxRuntimeEvidence('orchestrator_helper_launch_failed: program not found', {
      step: 'SANDBOX_SMOKE', codexSource: 'ACTIVE_CLI',
      codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    }),
    error: 'orchestrator_helper_launch_failed: program not found',
  }, { execpolicyRun: false });
  assert.equal(summary.activeCli.helperResolution, 'FAILED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.recommendations.find((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED')?.severity, 'ACTION_RECOMMENDED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_CLI_BUNDLE_INCOMPLETE'), false);
  assert.equal(summary.nextSteps.filter((item) => /update or reinstall/i.test(item)).length, 0);
});

test('unclassified elevation setup failure retains the generic setup diagnostic', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: { complete: true, probeEligible: true, installType: 'classic', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED',
  }, [], {
    status: 'SETUP_FAILED',
    codexSource: 'ACTIVE_CLI',
    testedCodexVersion: 'codex-cli 0.146.0',
    smoke: { passed: false, stderr: 'requested operation requires elevation (os error 740)' },
    probes: [],
    error: 'requested operation requires elevation (os error 740)',
  }, { execpolicyRun: false });
  assert.equal(summary.recommendations.find((item) => item.code === 'SANDBOX_SETUP_FAILED')?.severity, 'ACTION_RECOMMENDED');
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED'), false);
});

test('successful smoke confirms runtime startup but not sandbox boundary pass by itself', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.146.0',
    config: { warnings: [] },
    activeBundle: {
      complete: false,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
    },
  }, [], {
    status: 'SMOKE_COMPLETED', codexSource: 'ACTIVE_CLI', codexProcessStarted: true,
    smoke: { passed: true, codexProcessStarted: true }, probes: [],
  }, { execpolicyRun: false });
  assert.equal(summary.sandboxRuntime, 'READY');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.activeCli.bundleStatus, 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION CONFIRMED');
  assert.equal(summary.activeCli.helperResolution, 'CONFIRMED');
  assert.equal(summary.activeCli.runtimeStartup, 'READY');
  assert.equal(summary.recommendations.some((item) => item.code === 'ACTIVE_BUNDLE_BOUNDARY_PASS'), false);
});

test('ready runtime with incomplete method evidence recommends runner review instead of another availability check', () => {
  const probes = completeBoundaryProbes();
  for (const probe of probes) {
    if (probe.location === 'outside' && ['powershell', 'node'].includes(probe.method)) {
      probe.assessment = 'TEST_ERROR';
      probe.errorTargetMatched = false;
      probe.targetIdentityStatus = 'NOT REPORTED';
    }
  }
  const inventory = {
    codexVersion: 'codex-cli 0.145.0',
    config: { warnings: [] },
    sandboxWindowsState: 'AVAILABLE',
    activeBundle: {
      installType: 'standalone', complete: false, probeEligible: true, resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED', standaloneResourcesFound: true,
    },
  };
  const sandbox = completedBoundarySandbox({
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    testedCodexVersion: 'codex-cli 0.146.0-alpha.3.1',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
    testedBundleMetadata: { installType: 'standalone', resourceLayout: 'COMPLETE', probeEligible: true },
    probes,
  });
  const summary = summarizeAssessment(inventory, [], sandbox, { execpolicyRun: false });
  assert.equal(summary.sandboxRuntime, 'READY');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.methodCoverage, '1/3');
  assert.match(summary.nextSteps.join('\n'), /Review the incomplete method evidence/);
  assert.doesNotMatch(summary.nextSteps.join('\n'), /When the Windows sandbox state is AVAILABLE/);
});

test('helper resolution diagnostics require explicit setup-helper missing evidence', () => {
  assert.equal(detectSandboxHelperResolutionFailure('codex-windows-sandbox-setup.exe failed with os error 740'), false);
  assert.equal(detectSandboxHelperResolutionFailure('requested operation requires elevation for setup helper'), false);
  assert.equal(detectSandboxHelperResolutionFailure('access denied while running codex-windows-sandbox-setup.exe'), false);
  assert.equal(detectSandboxHelperResolutionFailure('program not found: unrelated-helper.exe'), false);
  assert.equal(detectSandboxHelperResolutionFailure('orchestrator_helper_launch_failed: program not found'), true);
  assert.equal(detectSandboxHelperResolutionFailure('codex-windows-sandbox-setup.exe ENOENT'), true);
  assert.equal(detectSandboxHelperResolutionFailure('setup-helper-not-resolved'), true);
});

function createSyntheticStandalonePackage(directory, executableContent = 'synthetic') {
  fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(directory, 'codex-resources'), { recursive: true });
  fs.writeFileSync(path.join(directory, 'bin', 'codex.exe'), executableContent);
  fs.writeFileSync(path.join(directory, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
  fs.writeFileSync(path.join(directory, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
}

test('foreign executable inside a standalone release tree cannot inherit package resources', (t) => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-foreign-'));
  t.after(() => fs.rmSync(codexHome, { recursive: true, force: true }));
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release, 'canonical executable');
  const canonicalExecutable = path.join(release, 'bin', 'codex.exe');
  const foreignExecutable = path.join(release, 'tools', 'codex.exe');
  fs.mkdirSync(path.dirname(foreignExecutable), { recursive: true });
  fs.writeFileSync(foreignExecutable, 'foreign executable');

  const relativePath = path.relative(release, foreignExecutable);
  assert.equal(relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath), false);
  assert.notEqual(canonicalExistingPathKey(foreignExecutable), canonicalExistingPathKey(canonicalExecutable));

  const bundle = inspectCodexBundle(foreignExecutable, {
    activeVersion: 'codex-cli 0.146.0',
    standalonePackages: discoverStandalonePackages(codexHome),
  });
  assert.equal(bundle.standaloneResourcesFound, false);
  assert.equal(bundle.resourceLayout, 'MISSING');
  assert.equal(bundle.probeEligible, false);

  const plan = selectCodexProbePlan({
    activeCodexPath: foreignExecutable,
    codexVersion: 'codex-cli 0.146.0',
    activeBundle: bundle,
    sandboxHelperInPath: false,
    sandboxWindowsState: 'AVAILABLE',
    matchingCompleteBundles: [],
    newerCompleteBundles: [],
    completeBundles: [],
  });
  assert.equal(plan.ready, false);
  assert.equal(plan.candidates.length, 0);
});

test('nested and quoted-path foreign executables remain detached from standalone resources', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "canary O'Brien standalone "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = path.join(root, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release, 'canonical executable');
  const packages = discoverStandalonePackages(root);
  const foreignExecutables = [
    path.join(release, 'bin', 'foreign', 'codex.exe'),
    path.join(release, 'tools', "Client's Tools", 'codex.exe'),
    path.join(root, 'outside release', 'codex.exe'),
  ];
  for (const foreignExecutable of foreignExecutables) {
    fs.mkdirSync(path.dirname(foreignExecutable), { recursive: true });
    fs.writeFileSync(foreignExecutable, 'foreign executable');
    const bundle = inspectCodexBundle(foreignExecutable, {
      activeVersion: 'codex-cli 0.146.0',
      standalonePackages: packages,
    });
    assert.equal(bundle.standaloneResourcesFound, false, foreignExecutable);
    assert.equal(bundle.standaloneRequiredResourcesPresent, false, foreignExecutable);
    assert.equal(bundle.resourceLayout, 'MISSING', foreignExecutable);
    assert.equal(bundle.probeEligible, false, foreignExecutable);
    assert.equal(bundle.standaloneResourceBinding, null, foreignExecutable);
  }
});

test('canonical standalone executable and a real file alias retain resource eligibility', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "canary O'Brien canonical "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = path.join(root, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release, 'canonical executable');
  const canonicalExecutable = path.join(release, 'bin', 'codex.exe');
  const aliasExecutable = path.join(release, 'tools', 'codex-alias.exe');
  fs.mkdirSync(path.dirname(aliasExecutable), { recursive: true });
  fs.linkSync(canonicalExecutable, aliasExecutable);
  const packages = discoverStandalonePackages(root);

  for (const executable of [canonicalExecutable, aliasExecutable]) {
    const bundle = inspectCodexBundle(executable, {
      activeVersion: 'codex-cli 0.146.0',
      standalonePackages: packages,
    });
    assert.equal(bundle.standaloneResourcesFound, true);
    assert.equal(bundle.resourceLayout, 'COMPLETE');
    assert.equal(bundle.probeEligible, true);
    assert.equal(validateStandaloneResourceBinding(bundle.standaloneResourceBinding, executable).valid, true);
  }
});

test('probe plan binds current alias to the canonical standalone executable identity', (t) => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-plan-binding-'));
  t.after(() => fs.rmSync(codexHome, { recursive: true, force: true }));
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(codexHome, 'packages', 'standalone', 'current');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  const currentExecutable = path.join(current, 'bin', 'codex.exe');
  const bundle = inspectCodexBundle(currentExecutable, {
    activeVersion: 'codex-cli 0.146.0',
    standalonePackages: discoverStandalonePackages(codexHome),
  });
  const plan = selectCodexProbePlan({
    activeCodexPath: currentExecutable,
    codexVersion: 'codex-cli 0.146.0',
    activeBundle: bundle,
    sandboxHelperInPath: false,
    sandboxWindowsState: 'AVAILABLE',
    sandboxFullAutoAvailable: true,
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    matchingCompleteBundles: [],
    newerCompleteBundles: [],
    completeBundles: [],
  });
  assert.equal(plan.ready, true);
  assert.equal(plan.source, 'ACTIVE_CLI');
  assert.equal(validateStandaloneResourceBinding(plan.standaloneResourceBinding, plan.codexExe).valid, true);
});

test('standalone executable identity change before execution fails closed without runtime evidence', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-revalidate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = path.join(root, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release, 'original executable');
  const executable = path.join(release, 'bin', 'codex.exe');
  const bundle = inspectCodexBundle(executable, {
    activeVersion: 'codex-cli 0.146.0',
    standalonePackages: discoverStandalonePackages(root),
  });
  const plan = selectCodexProbePlan({
    activeCodexPath: executable,
    codexVersion: 'codex-cli 0.146.0',
    activeBundle: bundle,
    sandboxHelperInPath: false,
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    matchingCompleteBundles: [],
    newerCompleteBundles: [],
    completeBundles: [],
  });
  const originalExecutable = path.join(release, 'bin', 'codex-original.exe');
  fs.renameSync(executable, originalExecutable);
  fs.writeFileSync(executable, 'replacement executable');

  const sandbox = runSandboxProbes({
    appRoot: path.join(root, 'app'),
    sandboxWindowsState: plan.sandboxState,
    sandboxCommandContract: plan.sandboxCommandContract,
    codexExe: plan.codexExe,
    codexSource: plan.source,
    testedCodexVersion: plan.testedVersion,
    activeCodexVersion: plan.activeVersion,
    isAlternativeExecutable: plan.isAlternativeExecutable,
    versionMismatch: plan.versionMismatch,
    testedBundleMetadata: plan.testedBundleMetadata,
    standaloneResourceBinding: plan.standaloneResourceBinding,
    executableRunBinding: plan.executableRunBinding,
  });
  assert.equal(sandbox.status, 'SETUP_FAILED');
  assert.equal(sandbox.setupFailureCode, 'EXECUTABLE_IDENTITY_MISMATCH');
  assert.equal(sandbox.resourceBindingStatus, 'FAILED');
  assert.deepEqual(sandbox.probes, []);
  assert.equal(sandbox.layout, undefined);
  assert.equal(sandbox.runtimeEvidence, undefined);
  assert.equal(fs.existsSync(path.join(root, 'app', 'runs')), false);

  const inventory = {
    platform: 'win32', release: 'synthetic', nodeVersion: process.version,
    codexInstalled: true, codexVersion: 'codex-cli 0.146.0', activeCodexPath: executable,
    activeBundle: bundle, standalonePackages: discoverStandalonePackages(root),
    completeBundles: [], matchingCompleteBundles: [], newerCompleteBundles: [],
    doctor: { status: 'NOT_RUN', ok: false }, config: { warnings: [] }, ruleFiles: [],
    sandboxWindowsState: 'AVAILABLE',
  };
  const summary = summarizeAssessment(inventory, [], sandbox, { assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.testedBundle, null);
  assert.equal(summary.recommendations.some((item) => item.code === 'EXECUTABLE_IDENTITY_MISMATCH'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);

  const report = writeReport({ inventory, rules: [], sandbox, appRoot: path.join(root, 'report-app'), assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  const supportText = fs.readFileSync(report.supportTxtPath, 'utf8');
  const supportJson = fs.readFileSync(report.supportJsonPath, 'utf8');
  for (const output of [supportText, supportJson]) {
    assert.match(output, /EXECUTABLE_IDENTITY_MISMATCH/);
    assert.doesNotMatch(output, /expectedObjectIdentity|fs:\d|codex-original|replacement executable/);
    assert.equal(output.includes(root), false);
  }
});

test('alternative standalone identity mismatch remains targeted to the selected but untested alternative', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-alternative-revalidate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const release = path.join(root, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release, 'alternative executable');
  const executable = path.join(release, 'bin', 'codex.exe');
  const testedBundle = inspectCodexBundle(executable, {
    standalonePackages: discoverStandalonePackages(root),
  });
  const inventory = {
    codexVersion: 'codex-cli 0.146.0',
    activeCodexPath: path.join(root, 'active', 'codex.exe'),
    activeBundle: { complete: false, probeEligible: false, installType: 'classic', resourceLayout: 'MISSING' },
    sandboxHelperInPath: false,
    sandboxWindowsState: 'AVAILABLE_BUT_SETUP_FAILED',
    completeBundles: [],
    alternativeExecutables: [{
      ...testedBundle,
      executablePath: executable,
      derivedVersion: 'codex-cli 0.146.0',
      versionEvidenceSource: 'PACKAGE_METADATA',
      filesystemIdentity: { status: 'PROVEN', key: resolveFilesystemIdentity(executable).key, canonicalPath: executable },
    }],
    matchingCompleteBundles: [],
    newerCompleteBundles: [],
    doctor: { status: 'COMPLETED', ok: true },
    config: { warnings: [] },
    ruleFiles: [],
  };
  const plan = selectCodexProbePlan(inventory);
  assert.equal(plan.source, 'ALTERNATIVE_EXECUTABLE');
  assert.equal(plan.derivedVersionRelation, 'MATCHING_COMPLETE_BUNDLE');
  assert.equal(plan.isAlternativeExecutable, true);
  const selectedExecutableBinding = {
    selectedExecutablePath: executable,
    expectedFilesystemIdentityKey: resolveFilesystemIdentity(executable).key,
  };
  const originalExecutable = path.join(release, 'bin', 'codex-original.exe');
  fs.renameSync(executable, originalExecutable);
  fs.writeFileSync(executable, 'replacement executable');

  const sandbox = runSandboxProbes({
    sandboxWindowsState: plan.sandboxState,
    sandboxCommandContract: plan.sandboxCommandContract,
    codexExe: plan.codexExe,
    codexSource: plan.source,
    testedCodexVersion: plan.testedVersion,
    activeCodexVersion: plan.activeVersion,
    isAlternativeExecutable: plan.isAlternativeExecutable,
    versionMismatch: plan.versionMismatch,
    testedBundleMetadata: plan.testedBundleMetadata,
    standaloneResourceBinding: plan.standaloneResourceBinding,
    selectedExecutableBinding,
  });
  const summary = summarizeAssessment(inventory, [], sandbox, { assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  assert.equal(summary.testedBundle, null);
  assert.equal(summary.recommendations.some((item) => item.code === 'EXECUTABLE_IDENTITY_MISMATCH' && item.target === 'SELECTED_ALTERNATIVE'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'EXECUTABLE_IDENTITY_MISMATCH' && item.target === 'ACTIVE_CLI'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED' && item.target === 'TESTED_BUNDLE'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED' && item.target === 'TESTED_BUNDLE'), false);
});

function diagnosticPathKey(value) {
  if (process.platform === 'win32') return canonicalizeWindowsPath(value).toLowerCase();
  return path.resolve(value);
}

function compareRealpaths(left, right, resolver) {
  try {
    return diagnosticPathKey(resolver(left)) === diagnosticPathKey(resolver(right));
  } catch (error) {
    return `unavailable:${error?.code || 'ERROR'}`;
  }
}

function compactIdentity(filePath) {
  const identity = resolveFilesystemIdentity(filePath);
  return {
    method: identity?.method || 'none',
    objectKey: identity?.objectIdentity?.key || null,
  };
}

function compactLink(filePath, releasePath) {
  try {
    const stat = fs.lstatSync(filePath);
    let linkType = 'other';
    if (stat.isSymbolicLink()) linkType = 'symlink-or-junction';
    else if (stat.isDirectory()) linkType = 'directory';
    else if (stat.isFile()) linkType = 'file';
    let target = 'not-a-link';
    if (stat.isSymbolicLink()) {
      try {
        const resolvedTarget = path.resolve(path.dirname(filePath), fs.readlinkSync(filePath));
        target = diagnosticPathKey(resolvedTarget) === diagnosticPathKey(releasePath)
          ? 'release-target'
          : 'other-target';
      } catch (error) {
        target = `unavailable:${error?.code || 'ERROR'}`;
      }
    }
    return { linkType, target };
  } catch (error) {
    return { linkType: `unavailable:${error?.code || 'ERROR'}`, target: 'unavailable' };
  }
}

function relativeDiagnosticPath(value, root) {
  const relativePath = path.relative(root, value);
  if (!relativePath) return '.';
  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) return `<outside-root>/${path.basename(value)}`;
  return relativePath.split(path.sep).join('/');
}

function standaloneLinkFailureDiagnostic(current, release, packages, discoveries = [
  { source: 'current', dir: current },
  { source: 'release', dir: release },
]) {
  const standaloneRoot = path.dirname(current);
  const currentExecutable = path.join(current, 'bin', 'codex.exe');
  const releaseExecutable = path.join(release, 'bin', 'codex.exe');
  return JSON.stringify({
    current: { ...compactLink(current, release), identity: compactIdentity(current) },
    release: { ...compactLink(release, release), identity: compactIdentity(release) },
    nativeRealpathEqual: compareRealpaths(current, release, fs.realpathSync.native),
    realpathEqual: compareRealpaths(current, release, fs.realpathSync),
    currentExecutableIdentity: compactIdentity(currentExecutable),
    releaseExecutableIdentity: compactIdentity(releaseExecutable),
    packageCount: packages.length,
    discoveries: discoveries.map((discovery) => ({
      source: discovery.source,
      path: relativeDiagnosticPath(discovery.dir, standaloneRoot),
      normalizedPath: relativeDiagnosticPath(normalizeDiscoveryPathForComparison(discovery.dir), normalizeDiscoveryPathForComparison(standaloneRoot)),
    })),
    packages: packages.map((standalonePackage) => ({
      sources: standalonePackage.sources,
      releaseDir: relativeDiagnosticPath(standalonePackage.releaseDir, standaloneRoot),
      aliases: standalonePackage.aliases.map((alias) => relativeDiagnosticPath(alias, standaloneRoot)),
      aliasCount: standalonePackage.aliases.length,
    })),
  });
}

test('standalone current symlink or junction is deduplicated with its release target', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-current-'));
  const standaloneRoot = path.join(codexHome, 'packages', 'standalone');
  const release = path.join(standaloneRoot, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(standaloneRoot, 'current');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  const currentExecutable = path.join(current, 'bin', 'codex.exe');
  const currentIdentity = resolveFilesystemIdentity(current);
  const releaseIdentity = resolveFilesystemIdentity(release);
  assert.equal(currentIdentity.linkType, 'SYMLINK_OR_JUNCTION');
  assert.equal(currentIdentity.key, releaseIdentity.key);
  assert.equal(canonicalExistingPathKey(currentExecutable), canonicalExistingPathKey(path.join(release, 'bin', 'codex.exe')));
  const packages = discoverStandalonePackages(codexHome);
  const diagnostic = standaloneLinkFailureDiagnostic(current, release, packages);
  assert.equal(resolveFilesystemIdentity(currentExecutable).method, 'stat', diagnostic);
  assert.equal(resolveFilesystemIdentity(path.join(release, 'bin', 'codex.exe')).method, 'stat', diagnostic);
  assert.equal(packages.length, 1, diagnostic);
  assert.equal(packages[0].releaseVersion, '0.146.0');
  assert.deepEqual([...packages[0].sources].sort(), ['current', 'release']);
  assert.equal(diagnosticPathKey(packages[0].releaseDir), diagnosticPathKey(release), diagnostic);
  assert.deepEqual(packages[0].aliases.map(diagnosticPathKey), [diagnosticPathKey(current)], diagnostic);
  const bundle = inspectCodexBundle(currentExecutable, {
    codexHome,
    activeVersion: 'codex-cli 0.146.0',
    standalonePackages: packages,
  });
  assert.equal(bundle.installType, 'standalone');
  assert.equal(bundle.standalonePackage.releaseVersion, '0.146.0');
  assert.equal(bundle.resourceLayout, 'COMPLETE');
  assert.equal(bundle.probeEligible, true);
  assert.equal(bundle.helperResolution, 'NOT_TESTED');
  assert.equal(bundle.runtimeStartup, 'NOT_TESTED');
  const releaseBundle = inspectCodexBundle(path.join(release, 'bin', 'codex.exe'), {
    codexHome,
    activeVersion: 'codex-cli 0.146.0',
    standalonePackages: packages,
  });
  assert.equal(
    diagnosticPathKey(releaseBundle.standalonePackage.releaseDir),
    diagnosticPathKey(bundle.standalonePackage.releaseDir),
  );
  assert.equal(
    canonicalExistingPathKey(releaseBundle.standalonePackage.executablePath),
    canonicalExistingPathKey(bundle.standalonePackage.executablePath),
  );
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('standalone directory symlink resolves to one release package', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-symlink-'));
  const standaloneRoot = path.join(codexHome, 'packages', 'standalone');
  const release = path.join(standaloneRoot, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(standaloneRoot, 'current');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  const packages = discoverStandalonePackages(codexHome);
  const diagnostic = standaloneLinkFailureDiagnostic(current, release, packages);
  assert.equal(packages.length, 1, diagnostic);
  assert.deepEqual([...packages[0].sources].sort(), ['current', 'release']);
  assert.equal(diagnosticPathKey(packages[0].releaseDir), diagnosticPathKey(release), diagnostic);
  assert.deepEqual(packages[0].aliases.map(diagnosticPathKey), [diagnosticPathKey(current)], diagnostic);
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('standalone package identity follows the executable filesystem object', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-hardlink-'));
  const first = path.join(root, '0.146.0-x86_64-pc-windows-msvc');
  const second = path.join(root, '0.146.0-copy-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(first);
  fs.mkdirSync(path.join(second, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(second, 'codex-resources'), { recursive: true });
  fs.linkSync(path.join(first, 'bin', 'codex.exe'), path.join(second, 'bin', 'codex.exe'));
  fs.writeFileSync(path.join(second, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
  fs.writeFileSync(path.join(second, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
  const packages = deduplicateStandalonePackageCandidates([
    { dir: first, source: 'release' },
    { dir: second, source: 'release' },
  ]);
  assert.equal(canonicalExistingPathKey(first) === canonicalExistingPathKey(second), false);
  assert.equal(canonicalExistingPathKey(path.join(first, 'bin', 'codex.exe')), canonicalExistingPathKey(path.join(second, 'bin', 'codex.exe')));
  assert.equal(packages.length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test('standalone package merging is independent of candidate order', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-order-'));
  const release = path.join(root, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(root, 'current');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  const candidates = [
    { dir: current, source: 'current' },
    { dir: release, source: 'release' },
  ];
  const normalizeResult = (packages) => packages.map((standalonePackage) => ({
    releaseDir: diagnosticPathKey(standalonePackage.releaseDir),
    releaseVersion: standalonePackage.releaseVersion,
    source: standalonePackage.source,
    sources: standalonePackage.sources,
    aliases: standalonePackage.aliases.map(diagnosticPathKey),
    resourceLayout: standalonePackage.resourceLayout,
  }));
  assert.deepEqual(
    normalizeResult(deduplicateStandalonePackageCandidates(candidates)),
    normalizeResult(deduplicateStandalonePackageCandidates([...candidates].reverse())),
  );
  const merged = deduplicateStandalonePackageCandidates(candidates);
  assert.equal(diagnosticPathKey(merged[0].releaseDir), diagnosticPathKey(release));
  assert.deepEqual(merged[0].aliases.map(diagnosticPathKey), [diagnosticPathKey(current)]);
  fs.rmSync(root, { recursive: true, force: true });
});

test('Windows discovery path comparison collapses namespace case slash and separator variants', () => {
  const direct = 'C:\\Users\\Runner\\.codex\\packages\\standalone\\releases\\0.146.0-x86_64-pc-windows-msvc';
  const variants = [
    `\\\\?\\${direct}`,
    direct.toUpperCase(),
    direct.replaceAll('\\\\', '/'),
    'C:\\Users\\Runner\\.codex\\packages\\standalone\\releases\\\\0.146.0-x86_64-pc-windows-msvc',
  ];
  const expected = normalizeDiscoveryPathForComparison(direct, 'win32');
  for (const variant of variants) {
    assert.equal(normalizeDiscoveryPathForComparison(variant, 'win32'), expected);
  }
  assert.equal(
    normalizeDiscoveryPathForComparison('\\\\?\\UNC\\server\\share\\standalone\\current', 'win32'),
    normalizeDiscoveryPathForComparison('\\\\server\\share\\standalone\\current', 'win32'),
  );
});

test('duplicate current discovery paths produce one visible alias', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-duplicate-alias-'));
  const release = path.join(root, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(root, 'current');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  const candidates = [
    { dir: current, source: 'current' },
    { dir: current, source: 'current' },
    { dir: release, source: 'release' },
  ];
  const packages = deduplicateStandalonePackageCandidates(candidates);
  const diagnostic = standaloneLinkFailureDiagnostic(current, release, packages, candidates);
  assert.equal(packages.length, 1, diagnostic);
  assert.deepEqual(packages[0].sources, ['current', 'release'], diagnostic);
  assert.deepEqual(packages[0].aliases.map(diagnosticPathKey), [diagnosticPathKey(current)], diagnostic);
  fs.rmSync(root, { recursive: true, force: true });
});

test('distinct visible discovery paths remain separate aliases of one package', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-multiple-aliases-'));
  const release = path.join(root, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(root, 'current');
  const preview = path.join(root, 'preview');
  createSyntheticStandalonePackage(release);
  fs.symlinkSync(release, current, process.platform === 'win32' ? 'junction' : 'dir');
  fs.symlinkSync(release, preview, process.platform === 'win32' ? 'junction' : 'dir');
  const candidates = [
    { dir: preview, source: 'current' },
    { dir: release, source: 'release' },
    { dir: current, source: 'current' },
  ];
  const packages = deduplicateStandalonePackageCandidates(candidates);
  const diagnostic = standaloneLinkFailureDiagnostic(current, release, packages, candidates);
  assert.equal(packages.length, 1, diagnostic);
  assert.equal(diagnosticPathKey(packages[0].releaseDir), diagnosticPathKey(release), diagnostic);
  assert.deepEqual(
    packages[0].aliases.map(diagnosticPathKey).sort(),
    [current, preview].map(diagnosticPathKey).sort(),
    diagnostic,
  );
  assert.equal(packages[0].aliases.some((alias) => diagnosticPathKey(alias) === diagnosticPathKey(release)), false, diagnostic);
  fs.rmSync(root, { recursive: true, force: true });
});

test('standalone current copy and same-version release remain separate filesystem identities', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-copy-'));
  const standaloneRoot = path.join(codexHome, 'packages', 'standalone');
  const current = path.join(standaloneRoot, 'current');
  const release = path.join(standaloneRoot, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  for (const directory of [current, release]) {
    fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(directory, 'codex-resources'), { recursive: true });
    fs.writeFileSync(path.join(directory, 'bin', 'codex.exe'), 'synthetic');
    fs.writeFileSync(path.join(directory, 'codex-resources', 'codex-windows-sandbox-setup.exe'), 'synthetic');
    fs.writeFileSync(path.join(directory, 'codex-resources', 'codex-command-runner.exe'), 'synthetic');
  }
  const packages = discoverStandalonePackages(codexHome);
  assert.equal(packages.length, 2);
  assert.notEqual(canonicalExistingPathKey(current), canonicalExistingPathKey(release));
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('same-version standalone release directories remain separate without filesystem identity', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-same-version-'));
  const releases = path.join(codexHome, 'packages', 'standalone', 'releases');
  for (const name of ['0.146.0-x86_64-pc-windows-msvc', '0.146.0-aarch64-pc-windows-msvc']) {
    const directory = path.join(releases, name);
    fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(directory, 'bin', 'codex.exe'), 'synthetic');
  }
  const packages = discoverStandalonePackages(codexHome);
  assert.equal(packages.length, 2);
  assert.deepEqual(packages.map((entry) => entry.releaseVersion), ['0.146.0', '0.146.0']);
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('Windows namespace and case variants retain the same existing-path identity', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-filesystem-identity-'));
  const file = path.join(temp, 'MixedCase', 'codex.exe');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, 'synthetic');
  const baseline = canonicalExistingPathKey(file);
  if (process.platform === 'win32') {
    assert.equal(canonicalExistingPathKey(`\\\\?\\${file}`), baseline);
    assert.equal(canonicalExistingPathKey(file.toUpperCase()), baseline);
  } else {
    assert.equal(canonicalExistingPathKey(file), baseline);
  }
  fs.rmSync(temp, { recursive: true, force: true });
});

test('broken standalone current link is conservative and does not merge with a release', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-standalone-broken-current-'));
  const standaloneRoot = path.join(codexHome, 'packages', 'standalone');
  const release = path.join(standaloneRoot, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const current = path.join(standaloneRoot, 'current');
  const removedTarget = path.join(standaloneRoot, 'removed-release');
  fs.mkdirSync(path.join(release, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(release, 'bin', 'codex.exe'), 'synthetic');
  fs.mkdirSync(removedTarget, { recursive: true });
  fs.symlinkSync(removedTarget, current, process.platform === 'win32' ? 'junction' : 'dir');
  fs.rmSync(removedTarget, { recursive: true, force: true });
  const packages = discoverStandalonePackages(codexHome);
  assert.equal(packages.length, 1);
  assert.deepEqual(packages[0].sources, ['release']);
  assert.notEqual(canonicalExistingPathKey(current), canonicalExistingPathKey(release));
  fs.rmSync(codexHome, { recursive: true, force: true });
});

test('failed alternative standalone smoke reports staged evidence instead of a complete bundle', () => {
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.145.0',
    config: { warnings: [] },
    activeBundle: { complete: false, probeEligible: false, resourceLayout: 'MISSING' },
  }, [], {
    status: 'SETUP_FAILED',
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    testedCodexVersion: 'codex-cli 0.146.0',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
    testedBundleMetadata: {
      installType: 'standalone',
      complete: false,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
      releaseVersion: '0.146.0',
    },
    smoke: { passed: false, stderr: 'orchestrator_helper_launch_failed: program not found' },
    probes: [],
    runtimeEvidence: buildSandboxRuntimeEvidence('orchestrator_helper_launch_failed: program not found', {
      step: 'SANDBOX_SMOKE', codexSource: 'NEWER_COMPLETE_BUNDLE',
      codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    }),
    error: 'orchestrator_helper_launch_failed: program not found',
  }, { execpolicyRun: false });
  assert.equal(summary.testedBundle.resourceLayout, 'COMPLETE');
  assert.equal(summary.testedBundle.helperResolution, 'FAILED');
  assert.equal(summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(summary.testedBundle.boundaryStatus, 'TEST ERROR');
  assert.equal(summary.testedBundle.bundleStatus, 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION FAILED');
  assert.notEqual(summary.testedBundle.bundleStatus, 'COMPLETE');
});

function targetedStandaloneInventory({
  error = null,
  sandboxState = error ? 'AVAILABLE_BUT_SETUP_FAILED' : 'AVAILABLE',
  doctorOk = false,
} = {}) {
  return {
    platform: 'win32',
    release: 'test-release',
    nodeVersion: process.version,
    nodeRuntimeSource: 'TEST',
    nodeInPath: true,
    npmInPath: false,
    elevated: false,
    codexInstalled: true,
    codexVersion: 'codex-cli 0.145.0',
    activeCodexPath: 'C:\\synthetic\\active\\codex.exe',
    activeCodexIdentity: ACTIVE_EXECUTABLE_IDENTITY,
    activeBundle: {
      installType: 'standalone',
      complete: false,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
      resourceVersionMatchesActive: true,
      releaseVersion: '0.145.0',
      missing: [],
    },
    standalonePackages: [],
    sandboxWindowsState: sandboxState,
    sandboxWindowsAvailable: sandboxState === 'AVAILABLE',
    sandboxSetupFailed: sandboxState === 'AVAILABLE_BUT_SETUP_FAILED',
    sandboxHelpError: error,
    sandboxHelpRuntimeEvidence: error
      ? buildSandboxRuntimeEvidence(error, {
        step: 'SANDBOX_HELP', codexSource: 'ACTIVE_CLI', codexExecutableIdentity: ACTIVE_EXECUTABLE_IDENTITY,
      })
      : null,
    doctor: { status: doctorOk ? 'COMPLETED' : 'NOT_RUN', ok: doctorOk, overallStatus: doctorOk ? 'ok' : null },
    codexHome: 'C:\\synthetic\\codex-home',
    authFilePresent: false,
    config: { exists: false, path: 'C:\\synthetic\\codex-home\\config.toml', warnings: [] },
    ruleFiles: [],
    matchingCompleteBundles: [],
    newerCompleteBundles: [],
  };
}

test('skipped Doctor remains non-permissive and consistent across detailed and share-safe reports', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-doctor-skipped-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const inventory = targetedStandaloneInventory({
    error: 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT',
  });
  inventory.doctor = createCodexDoctorInventoryStatus(true);
  const summary = summarizeAssessment(inventory, [], null, {
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
    execpolicyRun: false,
  });

  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.cleanup.status, 'NOT_RUN');
  assert.equal(summary.methodCoverage, 'NOT RUN');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED'), false);

  const written = writeReport({
    inventory,
    rules: [],
    sandbox: null,
    appRoot: root,
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
  });
  const detailText = fs.readFileSync(written.txtPath, 'utf8');
  const supportText = fs.readFileSync(written.supportTxtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(written.supportJsonPath, 'utf8'));
  assert.equal(written.payload.inventory.doctor.status, 'NOT_RUN');
  assert.equal(written.payload.inventory.doctor.ok, false);
  assert.equal(supportJson.environment.doctor.status, 'NOT_RUN');
  assert.equal(supportJson.environment.doctor.ok, false);
  assert.equal(supportJson.environment.doctor.errorPresent, false);
  assert.equal(supportJson.environment.doctor.reason, inventory.doctor.reason);
  for (const output of [detailText, supportText]) {
    assert.match(output, /Codex doctor(?: status)?:\s+NOT_RUN/i);
    assert.match(output, /no Doctor process was started/i);
    assert.doesNotMatch(output, /Doctor passed|Doctor.*(?:authentication|network|update|session)/i);
  }
});

function alternativeStandaloneSandbox({ status = 'COMPLETED', error = null, probes = [] } = {}) {
  const marker = 'synthetic-alternative-boundary-run';
  const boundProbes = probes.map((probe) => ({
    ...probe,
    id: `${probe.location}-workspace-${probe.method}`,
    targetId: `${probe.location}-workspace-${probe.method}`,
    reportedRuntime: probe.method,
    codexProcessStarted: true,
    runMarker: marker,
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
  }));
  return {
    status,
    codexSource: 'NEWER_COMPLETE_BUNDLE',
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    codexProcessStarted: status === 'COMPLETED' && boundProbes.length === 6,
    marker,
    testedCodexVersion: 'codex-cli 0.146.0',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: true,
    testedBundleMetadata: {
      installType: 'standalone',
      complete: false,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
      resourceVersionMatchesActive: true,
      releaseVersion: '0.146.0',
    },
    hostPreflight: { passed: status === 'COMPLETED', filesChecked: status === 'COMPLETED' ? 2 : 0 },
    hostCalibrations: ['powershell', 'cmd', 'node'].map((method) => ({ method, status: 'PASS', passed: true })),
    smoke: status === 'COMPLETED'
      ? { passed: true, codexProcessStarted: true, stderr: '' }
      : { passed: false, codexProcessStarted: true, stderr: error || '' },
    runtimeEvidence: error
      ? buildSandboxRuntimeEvidence(error, {
        step: 'SANDBOX_SMOKE', codexSource: 'NEWER_COMPLETE_BUNDLE', codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
      })
      : null,
    cleanup: status === 'COMPLETED'
      ? { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false, message: 'Synthetic cleanup completed.' }
      : { status: 'NOT_RUN', attempted: false, completed: false, errorPresent: false, message: null },
    probes: boundProbes,
    error,
  };
}

test('active helper failure remains targeted when an alternative bundle passes its boundary', () => {
  const inventory = targetedStandaloneInventory({
    error: 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT',
    doctorOk: true,
  });
  const sandbox = alternativeStandaloneSandbox({
    probes: completeBoundaryProbes(),
  });
  const summary = summarizeAssessment(inventory, [], sandbox, { execpolicyRun: false });

  assert.equal(summary.boundary, 'PASS');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.testedBundle.boundaryStatus, 'PASS');
  assert.equal(summary.activeRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED' && item.target === 'ACTIVE_CLI'), true);
  assert.equal(summary.testedRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'ALTERNATIVE_BUNDLE_BOUNDARY_PASS' && item.target === 'TESTED_BUNDLE'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'SANDBOX_SETUP_FAILED' && item.target === 'ACTIVE_CLI'), false);
  assert.equal(summary.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED' && item.target === 'ACTIVE_CLI'), true);
  assert.match(summary.interpretation.join('\n'), /does not validate the active PATH CLI/i);
  assert.deepEqual(summary.nextSteps, [
    'The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, correct its helper-resolution problem and test that executable separately.',
  ]);
});

test('bundle statistics deduplicate current and release aliases by executable realpath', (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-report-bundle-alias-'));
  const releaseDir = path.join(temp, 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const releaseBin = path.join(releaseDir, 'bin');
  const currentDir = path.join(temp, 'current');
  fs.mkdirSync(releaseBin, { recursive: true });
  fs.writeFileSync(path.join(releaseBin, 'codex.exe'), 'synthetic');
  try {
    fs.symlinkSync(releaseDir, currentDir, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    fs.rmSync(temp, { recursive: true, force: true });
    t.skip(`symlink/junction unavailable: ${error.message}`);
    return;
  }
  const bundles = [
    { executablePath: path.join(currentDir, 'bin', 'codex.exe'), version: 'codex-cli 0.146.0' },
    { executablePath: path.join(releaseBin, 'codex.exe'), version: 'codex-cli 0.146.0' },
  ];
  const statistics = summarizeExecutableBundles(bundles);
  assert.equal(statistics.logicalExecutableCount, 1);
  assert.equal(statistics.discoveredPathCount, 2);
  assert.equal(statistics.aliasPathCount, 1);
  const reversedStatistics = summarizeExecutableBundles([...bundles].reverse());
  assert.deepEqual({
    logicalExecutableCount: reversedStatistics.logicalExecutableCount,
    discoveredPathCount: reversedStatistics.discoveredPathCount,
    aliasPathCount: reversedStatistics.aliasPathCount,
  }, {
    logicalExecutableCount: statistics.logicalExecutableCount,
    discoveredPathCount: statistics.discoveredPathCount,
    aliasPathCount: statistics.aliasPathCount,
  });
  assert.deepEqual(statistics.discoveredPaths.map((value) => path.normalize(value)).sort(), bundles.map((bundle) => path.normalize(bundle.executablePath)).sort());
  const summary = summarizeAssessment({ config: { warnings: [] }, matchingCompleteBundles: bundles }, [], null, {
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
    execpolicyRun: false,
  });
  assert.deepEqual(summary.bundleStatistics.matching, {
    logicalExecutableCount: 1,
    discoveredPathCount: 2,
    aliasPathCount: 1,
  });
  fs.rmSync(temp, { recursive: true, force: true });
});

test('bundle statistics keep distinct same-version executables separate', () => {
  const bundles = [
    { executablePath: 'C:\\standalone-a\\bin\\codex.exe', version: 'codex-cli 0.146.0' },
    { executablePath: 'C:\\standalone-b\\bin\\codex.exe', version: 'codex-cli 0.146.0' },
  ];
  const statistics = summarizeExecutableBundles(bundles);
  assert.equal(statistics.logicalExecutableCount, 2);
  assert.equal(statistics.discoveredPathCount, 2);
  assert.equal(statistics.aliasPathCount, 0);
});

test('active doctor OK is not compared with an alternative bundle runtime failure', () => {
  const inventory = targetedStandaloneInventory({ doctorOk: true });
  const error = 'codex-command-runner.exe CreateProcessWithLogonW failed: 2';
  const summary = summarizeAssessment(
    inventory,
    [],
    alternativeStandaloneSandbox({ status: 'SETUP_FAILED', error }),
    { execpolicyRun: false }
  );

  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'NOT_TESTED');
  assert.equal(summary.testedBundle.helperResolution, 'CONFIRMED');
  assert.equal(summary.testedBundle.runtimeStartup, 'FAILED');
  assert.equal(summary.testedRuntimeDiagnostics.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED' && item.target === 'TESTED_BUNDLE'), true);
  assert.equal(summary.runtimeDiagnostics.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED'), false);
});

test('generic sandbox setup diagnosis is suppressed independently for each target', () => {
  const inventory = targetedStandaloneInventory({
    error: 'orchestrator_helper_launch_failed: codex-windows-sandbox-setup.exe ENOENT',
  });
  const error = 'requested operation requires elevation (os error 740)';
  const summary = summarizeAssessment(
    inventory,
    [],
    alternativeStandaloneSandbox({ status: 'SETUP_FAILED', error }),
    { execpolicyRun: false }
  );

  assert.equal(summary.activeRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED' && item.target === 'ACTIVE_CLI'), true);
  assert.equal(summary.activeRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_FAILED'), false);
  assert.equal(summary.testedRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_FAILED' && item.target === 'TESTED_BUNDLE'), true);
  assert.equal(summary.testedRuntimeDiagnostics.some((item) => item.code === 'SANDBOX_SETUP_HELPER_NOT_RESOLVED'), false);
  assert.equal(summary.recommendations.find((item) => item.code === 'BOUNDARY_NOT_CONFIRMED')?.message, 'The selected sandbox boundary assessment was intended or started, but no fully reliable verdict was produced.');
});

function matchingAlternativeSandbox({ status = 'COMPLETED', probes = [], error = null } = {}) {
  const marker = 'synthetic-matching-alternative-boundary-run';
  const boundProbes = probes.map((probe) => ({
    ...probe,
    id: `${probe.location}-workspace-${probe.method}`,
    targetId: `${probe.location}-workspace-${probe.method}`,
    reportedRuntime: probe.method,
    codexProcessStarted: true,
    runMarker: marker,
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
  }));
  return {
    status,
    codexSource: 'MATCHING_COMPLETE_BUNDLE',
    codexExecutableIdentity: TESTED_EXECUTABLE_IDENTITY,
    codexProcessStarted: status === 'COMPLETED' && boundProbes.length === 6,
    marker,
    testedCodexVersion: 'codex-cli 0.145.0',
    activeCodexVersion: 'codex-cli 0.145.0',
    versionMismatch: false,
    testedBundleMetadata: {
      installType: 'classic',
      complete: true,
      probeEligible: true,
      resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
    },
    hostPreflight: { passed: status === 'COMPLETED', filesChecked: status === 'COMPLETED' ? 2 : 0 },
    hostCalibrations: ['powershell', 'cmd', 'node'].map((method) => ({ method, status: 'PASS', passed: true })),
    smoke: status === 'COMPLETED'
      ? { passed: true, codexProcessStarted: true, stderr: '' }
      : { passed: false, codexProcessStarted: true, stderr: error || '' },
    cleanup: status === 'COMPLETED'
      ? { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false, message: 'Synthetic cleanup completed.' }
      : { status: 'NOT_RUN', attempted: false, completed: false, errorPresent: false, message: null },
    probes: boundProbes,
    error,
  };
}

function incompleteActiveCliInventory() {
  return {
    codexVersion: 'codex-cli 0.145.0',
    config: { warnings: [] },
    activeBundle: {
      installType: 'classic',
      complete: false,
      probeEligible: false,
      resourceLayout: 'MISSING',
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
    },
    standalonePackages: [],
    sandboxWindowsState: 'AVAILABLE',
  };
}

test('same-version matching bundle pass remains alternative evidence', () => {
  const summary = summarizeAssessment(incompleteActiveCliInventory(), [], matchingAlternativeSandbox({
    probes: completeBoundaryProbes(),
  }), { execpolicyRun: false });

  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE BOUNDARY PASSED');
  assert.equal(summary.isAlternativeExecutable, true);
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.testedBundle.boundaryStatus, 'PASS');
  assert.equal(summary.testedBundle.versionMismatch, false);
  assert.equal(summary.recommendations.some((item) => item.code === 'ALTERNATIVE_BUNDLE_BOUNDARY_PASS' && item.target === 'TESTED_BUNDLE'), true);
  assert.match(summary.testedBundle.scopeNote, /same Codex version.*only to that executable.*does not validate the active PATH CLI/i);
  assert.equal(summary.interpretation.includes(summary.testedBundle.scopeNote), true);
});

test('same-version matching bundle test error is targeted to the tested bundle', () => {
  const error = 'requested operation requires elevation (os error 740)';
  const summary = summarizeAssessment(
    incompleteActiveCliInventory(),
    [],
    matchingAlternativeSandbox({ status: 'SETUP_FAILED', error }),
    { execpolicyRun: false }
  );

  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED' && item.target === 'TESTED_BUNDLE'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_NOT_CONFIRMED' && item.target === 'ACTIVE_CLI'), false);
});

test('same-version matching bundle boundary gap is targeted to the tested bundle', () => {
  const summary = summarizeAssessment(incompleteActiveCliInventory(), [], matchingAlternativeSandbox({
    probes: completeBoundaryProbes({ gapMethod: 'powershell' }),
  }), { execpolicyRun: false });

  assert.equal(summary.overall, 'ALTERNATIVE BUNDLE GAP DETECTED');
  assert.equal(summary.activeCli.boundaryStatus, 'NOT TESTED');
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_GAP' && item.target === 'TESTED_BUNDLE'), true);
  assert.equal(summary.recommendations.some((item) => item.code === 'BOUNDARY_GAP' && item.target === 'ACTIVE_CLI'), false);
});

function createSyntheticClassicCodexBundle(directory, executableContent = 'synthetic executable') {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'codex.exe'), executableContent);
  fs.writeFileSync(path.join(directory, 'codex-windows-sandbox-setup.exe'), 'synthetic helper');
  fs.writeFileSync(path.join(directory, 'codex-command-runner.exe'), 'synthetic runner');
  return path.join(directory, 'codex.exe');
}

function supportedSandboxHelpOutput() {
  return [
    'Usage: codex sandbox [OPTIONS] [COMMAND]...',
    '--permission-profile <NAME>',
    '--cd <DIR>',
    '--full-auto',
  ].join('\n');
}

function syntheticInventoryOptions(activeCodexPath, bundlePaths, codexCalls) {
  return {
    platform: 'win32',
    findCommandPath(command) {
      return command === 'codex.exe' ? activeCodexPath : null;
    },
    invokeCodex(args, options) {
      codexCalls.push({ args: [...args], codexExe: options.codexExe });
      assert.equal(options.codexExe, activeCodexPath, 'inventory may invoke only the active PATH CLI');
      if (args[0] === '--version') return { status: 0, stdout: 'codex-cli 0.145.0', stderr: '' };
      return { status: 0, stdout: supportedSandboxHelpOutput(), stderr: '' };
    },
    discoverStandalonePackages: () => [],
    discoverCodexBundlePaths: () => bundlePaths,
    commandInPath: () => false,
    isElevatedWindows: () => false,
    readSafeConfigSummary: (configPath) => ({ exists: false, path: configPath, sandboxMode: null, approvalPolicy: null, defaultPermissions: null, windowsSandbox: null, networkAccess: null, warnings: [] }),
    listRuleFiles: () => [],
    authFileExists: () => false,
  };
}

test('production inventory starts only the active PATH CLI and leaves one or many alternatives filesystem-only', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-inventory-no-alternative-start-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const alternatives = [
    createSyntheticClassicCodexBundle(path.join(root, 'alternative-a')),
    createSyntheticClassicCodexBundle(path.join(root, 'alternative-b')),
  ];
  const codexCalls = [];
  const inventory = getCodexInventory(
    { CODEX_HOME: path.join(root, 'codex-home'), CANARY_NODE_SOURCE: 'TEST' },
    syntheticInventoryOptions(activeCodexPath, alternatives, codexCalls)
  );

  assert.deepEqual(codexCalls.map((call) => call.args), [['--version'], ['sandbox', '--help']]);
  assert.equal(inventory.alternativeExecutables.length, 2);
  for (const candidate of inventory.alternativeExecutables) {
    assert.equal(candidate.filesystemDiscovery, 'DISCOVERED');
    assert.equal(candidate.selectionStatus, 'NOT_SELECTED');
    assert.equal(candidate.diagnosticStatus, 'NOT_RUN');
    assert.equal(candidate.versionConfirmedByExecution, false);
    assert.equal(candidate.tested, false);
    assert.equal(candidate.validatesActiveCli, false);
    assert.equal(candidate.validatesBoundary, false);
  }
});

test('active aliases are not independent alternatives while copies and same-version release directories remain separate', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-alternative-identity-inventory-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const activeAlias = path.join(root, 'active-alias.exe');
  fs.linkSync(activeCodexPath, activeAlias);
  const copy = createSyntheticClassicCodexBundle(path.join(root, 'copy'));
  const firstHome = path.join(root, 'first-home');
  const secondHome = path.join(root, 'second-home');
  const firstRelease = path.join(firstHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  const secondRelease = path.join(secondHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(firstRelease, 'first release executable');
  createSyntheticStandalonePackage(secondRelease, 'second release executable');
  const standalonePackages = [...discoverStandalonePackages(firstHome), ...discoverStandalonePackages(secondHome)];
  const alternatives = inventoryAlternativeCodexExecutables([
    activeAlias,
    copy,
    path.join(firstRelease, 'bin', 'codex.exe'),
    path.join(secondRelease, 'bin', 'codex.exe'),
  ], { activeCodexPath, standalonePackages });

  assert.equal(alternatives.length, 3);
  assert.equal(alternatives.some((candidate) => candidate.executablePath === activeAlias), false);
  assert.equal(alternatives.filter((candidate) => candidate.derivedVersion === '0.146.0').length, 2);
  assert.notEqual(canonicalExistingPathKey(path.join(firstRelease, 'bin', 'codex.exe')), canonicalExistingPathKey(path.join(secondRelease, 'bin', 'codex.exe')));
  assert.equal(alternatives.every((candidate) => candidate.diagnosticStatus === 'NOT_RUN'), true);
});

test('a realpath without filesystem object identity remains unproven and cannot satisfy a selection binding', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-unproven-realpath-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = createSyntheticClassicCodexBundle(root);
  const identity = resolveFilesystemIdentity(executable, {
    statObjectIdentity: () => null,
    realpathNative: (value) => value,
    realpath: (value) => value,
  });
  assert.equal(identity.resolvedPath, path.resolve(executable));
  assert.equal(identity.objectIdentity, null);
  assert.equal(identity.proven, false);
  assert.equal(validateSelectedExecutableBinding({
    selectedExecutablePath: executable,
    expectedFilesystemIdentityKey: identity.key,
  }, executable, {
    resolveFilesystemIdentity: () => identity,
  }).valid, false);
});

test('a broken alternative link stays unproven, separate, and ineligible for a diagnostic start', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-broken-alternative-link-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const brokenLink = path.join(root, 'broken-codex.exe');
  const conflictingPath = path.join(root, 'conflicting-codex.exe');
  const alternatives = [filesystemAlternative(brokenLink, null, {
    exists: false,
    probeEligible: true,
    filesystemIdentity: { status: 'UNPROVEN', key: `broken:${brokenLink}`, canonicalPath: null },
  }), filesystemAlternative(conflictingPath, null, {
    probeEligible: true,
    filesystemIdentity: { status: 'CONFLICT', key: `conflict:${conflictingPath}`, canonicalPath: null, conflict: true },
  })];
  const plan = selectCodexProbePlan({
    activeCodexPath, activeBundle: { probeEligible: false }, sandboxHelperInPath: false,
    sandboxWindowsState: 'UNSUPPORTED', codexVersion: 'codex-cli 0.145.0',
    alternativeExecutables: alternatives, completeBundles: alternatives,
  });
  assert.equal(plan.candidates.length, 0);
});

test('only an explicitly selected and identity-bound alternative may run version and sandbox-help diagnostics', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-selected-alternative-diagnostics-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const alternativeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'alternative'));
  const alternatives = inventoryAlternativeCodexExecutables([alternativeCodexPath], { activeCodexPath, codexHome: root, standalonePackages: [] });
  const inventory = {
    codexVersion: 'codex-cli 0.145.0',
    activeCodexPath,
    activeBundle: { probeEligible: false },
    sandboxHelperInPath: false,
    sandboxWindowsState: 'UNSUPPORTED',
    alternativeExecutables: alternatives,
    completeBundles: alternatives,
  };
  inventory.sandboxProbePlan = selectCodexProbePlan(inventory);
  const candidate = inventory.sandboxProbePlan.candidates[0];
  const calls = [];

  const forged = diagnoseExplicitlySelectedCodexExecutable(inventory, { ...candidate, expectedFilesystemIdentityKey: 'wrong' }, {
    invokeCodex() { calls.push('unexpected'); return { status: 0, stdout: '' }; },
  });
  assert.equal(forged.ready, false);
  assert.equal(forged.diagnosticStatus, 'NOT_RUN');
  assert.deepEqual(calls, []);

  const diagnosed = diagnoseExplicitlySelectedCodexExecutable(inventory, candidate, {
    invokeCodex(args, options) {
      calls.push({ args: [...args], codexExe: options.codexExe });
      assert.equal(options.codexExe, alternativeCodexPath);
      return args[0] === '--version'
        ? { status: 0, stdout: 'codex-cli 0.145.0', stderr: '' }
        : { status: 0, stdout: supportedSandboxHelpOutput(), stderr: '' };
    },
  });
  assert.equal(diagnosed.ready, true);
  assert.deepEqual(calls.map((call) => call.args), [['--version'], ['sandbox', '--help']]);
  assert.equal(validateSelectedExecutableBinding(diagnosed.selectedExecutableBinding, alternativeCodexPath).valid, true);
  assert.equal(alternatives[0].selectionStatus, 'SELECTED');
  assert.equal(alternatives[0].diagnosticStatus, 'COMPLETED');
  assert.equal(alternatives[0].versionConfirmedByExecution, true);
  assert.equal(alternatives[0].tested, false);
});

test('an unparseable selected version fails closed before sandbox-help', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-selected-invalid-version-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const alternativeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'alternative'));
  const alternatives = inventoryAlternativeCodexExecutables([alternativeCodexPath], { activeCodexPath, standalonePackages: [] });
  const inventory = {
    codexVersion: 'codex-cli 0.145.0', activeCodexPath,
    activeBundle: { probeEligible: false }, sandboxHelperInPath: false, sandboxWindowsState: 'UNSUPPORTED',
    alternativeExecutables: alternatives, completeBundles: alternatives,
  };
  const candidate = selectCodexProbePlan(inventory).candidates[0];
  const calls = [];
  const result = diagnoseExplicitlySelectedCodexExecutable(inventory, candidate, {
    invokeCodex(args) {
      calls.push([...args]);
      return { status: 0, stdout: 'not-a-codex-version', stderr: '' };
    },
  });
  assert.equal(result.ready, false);
  assert.match(result.reason, /unparseable version/i);
  assert.deepEqual(calls, [['--version']]);
  assert.equal(alternatives[0].sandboxState, 'NOT_RUN');
});

test('package metadata and executed version remain separate and a mismatch blocks sandbox-help', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-selected-metadata-mismatch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const codexHome = path.join(root, 'codex-home');
  const release = path.join(codexHome, 'packages', 'standalone', 'releases', '0.146.0-x86_64-pc-windows-msvc');
  createSyntheticStandalonePackage(release);
  const alternativeCodexPath = path.join(release, 'bin', 'codex.exe');
  const alternatives = inventoryAlternativeCodexExecutables([alternativeCodexPath], {
    activeCodexPath,
    codexHome,
    standalonePackages: discoverStandalonePackages(codexHome),
  });
  const inventory = {
    platform: 'win32', release: 'synthetic', nodeVersion: process.version, nodeRuntimeSource: 'TEST',
    nodeInPath: false, npmInPath: false, elevated: false, codexInstalled: true,
    codexVersion: 'codex-cli 0.145.0', activeCodexPath, codexHome,
    activeBundle: inspectCodexBundle(activeCodexPath, { standalonePackages: [] }),
    sandboxHelperInPath: false, sandboxWindowsState: 'UNSUPPORTED', sandboxCommandContract: null,
    alternativeExecutables: alternatives, completeBundles: alternatives,
    matchingCompleteBundles: [], newerCompleteBundles: alternatives,
    standalonePackages: discoverStandalonePackages(codexHome),
    config: { exists: false, path: path.join(codexHome, 'config.toml'), warnings: [] },
    ruleFiles: [], authFilePresent: false,
  };
  const candidate = selectCodexProbePlan(inventory).candidates[0];
  const calls = [];
  const result = diagnoseExplicitlySelectedCodexExecutable(inventory, candidate, {
    invokeCodex(args) {
      calls.push([...args]);
      return { status: 0, stdout: 'codex-cli 0.145.0', stderr: '' };
    },
  });
  assert.equal(result.ready, false);
  assert.match(result.reason, /conflicts with.*package metadata/i);
  assert.deepEqual(calls, [['--version']]);
  assert.equal(alternatives[0].derivedVersion, '0.146.0');
  assert.equal(alternatives[0].versionEvidenceSource, 'PACKAGE_METADATA');
  assert.equal(alternatives[0].confirmedVersion, 'codex-cli 0.145.0');
  assert.equal(alternatives[0].confirmedVersionEvidenceSource, 'EXECUTABLE_OUTPUT');

  const report = writeReport({ inventory, rules: [], sandbox: null, appRoot: path.join(root, 'app'), assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  const detailText = fs.readFileSync(report.txtPath, 'utf8');
  const supportText = fs.readFileSync(report.supportTxtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(report.supportJsonPath, 'utf8'));
  assert.match(detailText, /Derived version:\s+0\.146\.0 \(PACKAGE_METADATA\)/);
  assert.match(detailText, /Executed version:\s+codex-cli 0\.145\.0 \(EXECUTABLE_OUTPUT\)/);
  assert.match(supportText, /Metadata-derived version:\s+0\.146\.0 from PACKAGE_METADATA/);
  assert.match(supportText, /Executed version:\s+codex-cli 0\.145\.0 from EXECUTABLE_OUTPUT/);
  assert.equal(supportJson.environment.alternativeExecutables[0].versionEvidenceSource, 'PACKAGE_METADATA');
  assert.equal(supportJson.environment.alternativeExecutables[0].confirmedVersionEvidenceSource, 'EXECUTABLE_OUTPUT');
});

test('an alternative identity change after version diagnostics blocks sandbox-help before a second process start', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-selected-alternative-swap-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const alternativeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'alternative'));
  const alternatives = inventoryAlternativeCodexExecutables([alternativeCodexPath], { activeCodexPath, codexHome: root, standalonePackages: [] });
  const inventory = {
    codexVersion: 'codex-cli 0.145.0', activeCodexPath,
    activeBundle: { probeEligible: false }, sandboxHelperInPath: false, sandboxWindowsState: 'UNSUPPORTED',
    alternativeExecutables: alternatives, completeBundles: alternatives,
  };
  const candidate = selectCodexProbePlan(inventory).candidates[0];
  let calls = 0;
  const result = diagnoseExplicitlySelectedCodexExecutable(inventory, candidate, {
    invokeCodex() {
      calls += 1;
      const oldPath = `${alternativeCodexPath}.old`;
      fs.renameSync(alternativeCodexPath, oldPath);
      fs.writeFileSync(alternativeCodexPath, 'replacement executable');
      return { status: 0, stdout: 'codex-cli 0.145.0', stderr: '' };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.ready, false);
  assert.match(result.reason, /identity changed/i);
});

test('a classic alternative requires the unchanged explicit selection binding before sandbox setup creates files', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-classic-selection-binding-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = createSyntheticClassicCodexBundle(path.join(root, 'alternative'));
  const binding = {
    selectedExecutablePath: executable,
    expectedFilesystemIdentityKey: resolveFilesystemIdentity(executable).key,
  };
  fs.renameSync(executable, `${executable}.old`);
  fs.writeFileSync(executable, 'replacement executable');
  const appRoot = path.join(root, 'app');
  const sandbox = runSandboxProbes({
    appRoot,
    sandboxWindowsState: 'AVAILABLE',
    sandboxCommandContract: TEST_SANDBOX_COMMAND_CONTRACT,
    codexExe: executable,
    codexSource: 'MATCHING_COMPLETE_BUNDLE',
    testedCodexVersion: 'codex-cli 0.145.0',
    activeCodexVersion: 'codex-cli 0.145.0',
    isAlternativeExecutable: true,
    selectedExecutableBinding: binding,
    testedBundleMetadata: { installType: 'classic', resourceLayout: 'COMPLETE', probeEligible: true },
  });
  assert.equal(sandbox.status, 'SETUP_FAILED');
  assert.equal(sandbox.selectionBindingStatus, 'FAILED');
  assert.equal(sandbox.setupFailureCode, 'EXECUTABLE_IDENTITY_MISMATCH');
  assert.equal(sandbox.codexProcessStarted, false);
  assert.equal(fs.existsSync(path.join(appRoot, 'runs')), false);
  const summary = summarizeAssessment({
    codexVersion: 'codex-cli 0.145.0', config: { warnings: [] },
    activeBundle: { complete: false, resourceLayout: 'MISSING' },
  }, [], sandbox, { execpolicyRun: false });
  assert.equal(summary.testedBundle, null);
  assert.equal(summary.boundary, 'NOT TESTED');
  assert.equal(summary.recommendations.find((item) => item.code === 'EXECUTABLE_IDENTITY_MISMATCH')?.title, 'Selected executable identity changed');

  const reportInventory = {
    platform: 'win32', release: 'synthetic', nodeVersion: process.version, nodeRuntimeSource: 'TEST',
    nodeInPath: false, npmInPath: false, elevated: false, codexInstalled: true,
    codexVersion: 'codex-cli 0.145.0', activeCodexPath: null, codexHome: root,
    activeBundle: { complete: false, probeEligible: false, resourceLayout: 'MISSING' },
    sandboxHelperInPath: false, sandboxWindowsState: 'UNSUPPORTED', sandboxCommandContract: null,
    alternativeExecutables: [filesystemAlternative(executable)], matchingCompleteBundles: [], newerCompleteBundles: [],
    standalonePackages: [], config: { exists: false, path: path.join(root, 'config.toml'), warnings: [] },
    ruleFiles: [], authFilePresent: false,
  };
  const report = writeReport({ inventory: reportInventory, rules: [], sandbox, appRoot: path.join(root, 'report-app'), assessmentMode: ASSESSMENT_MODES.SANDBOX_ONLY });
  const detailText = fs.readFileSync(report.txtPath, 'utf8');
  const supportText = fs.readFileSync(report.supportTxtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(report.supportJsonPath, 'utf8'));
  assert.match(detailText, /TESTED BUNDLE[\s\S]*\(not tested\)/);
  assert.doesNotMatch(supportText, /Tested bundle source:/);
  assert.equal(supportJson.summary.testedBundle, null);
});

test('alternative inventory semantics agree across detail and share-safe TXT and JSON reports', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-alternative-report-semantics-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const activeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'active'));
  const alternativeCodexPath = createSyntheticClassicCodexBundle(path.join(root, 'alternative'));
  const codexCalls = [];
  const inventory = getCodexInventory(
    { CODEX_HOME: path.join(root, 'codex-home'), CANARY_NODE_SOURCE: 'TEST' },
    syntheticInventoryOptions(activeCodexPath, [alternativeCodexPath], codexCalls)
  );
  const report = writeReport({ inventory, rules: [], sandbox: null, appRoot: path.join(root, 'app'), assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY });
  const detailText = fs.readFileSync(report.txtPath, 'utf8');
  const detailJson = JSON.parse(fs.readFileSync(report.jsonPath, 'utf8'));
  const supportText = fs.readFileSync(report.supportTxtPath, 'utf8');
  const supportJson = JSON.parse(fs.readFileSync(report.supportJsonPath, 'utf8'));

  assert.match(detailText, /Filesystem discovery:\s+DISCOVERED/);
  assert.match(detailText, /Selection:\s+NOT_SELECTED/);
  assert.match(detailText, /Diagnostic process:\s+NOT_RUN/);
  assert.match(detailText, /Tested bundle:\s+no/);
  assert.equal(detailJson.inventory.alternativeExecutables[0].versionConfirmedByExecution, false);
  assert.equal(detailJson.summary.testedBundle, null);
  assert.match(supportText, /DISCOVERED[\s\S]*NOT_SELECTED \/ NOT_RUN[\s\S]*tested no/);
  assert.equal(supportJson.environment.alternativeExecutables[0].tested, false);
  assert.equal(supportJson.environment.alternativeExecutables[0].validatesActiveCli, false);
  assert.equal(supportJson.environment.alternativeExecutables[0].validatesBoundary, false);
  assert.doesNotMatch(supportText, /\\/);
});
