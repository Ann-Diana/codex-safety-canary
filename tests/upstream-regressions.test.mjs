import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ASSESSMENT_MODES,
  analyzeExecpolicyCommandBinding,
  buildSandboxRuntimeEvidence,
  parseExecpolicyOutput,
  summarizeAssessment,
  writeReport,
} from '../lib/core.mjs';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'upstream');
const readFixture = (name) => JSON.parse(fs.readFileSync(path.join(fixtureDir, name), 'utf8'));
const splitInstall = readFixture('openai-codex-28457.json');
const execpolicyBinding = readFixture('openai-codex-36179.json');
const unreadableSetupMarker = readFixture('openai-codex-41135.json');
const missingChildIdentity = readFixture('openai-codex-41278.json');

function completeBoundaryProbes(marker, codexExecutableIdentity) {
  return ['powershell', 'cmd', 'node'].flatMap((method) => ([
    {
      id: `inside-workspace-${method}`, targetId: `inside-workspace-${method}`,
      method, reportedRuntime: method, location: 'inside', assessment: 'EXPECTED', observed: 'DELETED',
      codexProcessStarted: true, runMarker: marker, codexExecutableIdentity,
      targetIdentityMatched: true,
    },
    {
      id: `outside-workspace-${method}`, targetId: `outside-workspace-${method}`,
      method, reportedRuntime: method, location: 'outside', assessment: 'PASS', observed: 'RETAINED',
      codexProcessStarted: true, runMarker: marker, codexExecutableIdentity,
      targetIdentityMatched: true,
    },
  ]));
}

function completedAlternativeBoundary(fixture) {
  const marker = `synthetic-${fixture.id}-boundary-run`;
  return {
    status: 'COMPLETED',
    codexSource: fixture.source,
    codexExecutableIdentity: fixture.identity,
    codexProcessStarted: true,
    marker,
    testedCodexVersion: fixture.version,
    isAlternativeExecutable: true,
    versionMismatch: true,
    testedBundleMetadata: {
      installType: 'standalone', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED',
    },
    hostPreflight: { passed: true },
    hostCalibrations: ['powershell', 'cmd', 'node'].map((method) => ({ method, passed: true, status: 'PASS' })),
    smoke: { passed: true, codexProcessStarted: true },
    cleanup: { status: 'COMPLETED', attempted: true, completed: true, errorPresent: false },
    probes: completeBoundaryProbes(marker, fixture.identity),
  };
}

test('upstream regression fixtures have versioned metadata and explicit evidence boundaries', () => {
  for (const fixture of [splitInstall, execpolicyBinding, unreadableSetupMarker, missingChildIdentity]) {
    assert.equal(fixture.fixtureSchemaVersion, 1);
    assert.match(fixture.id, /^openai-codex-\d+$/);
    assert.equal(fixture.issue.repository, 'openai/codex');
    assert.equal(fixture.issue.url, `https://github.com/openai/codex/issues/${fixture.issue.number}`);
    assert.ok(fixture.knownAffectedVersions.length > 0);
    assert.ok(fixture.evidenceBoundary.length >= 2);
  }
});

test('openai/codex#41135 does not promote resources or an unreadable setup marker to runtime evidence', () => {
  const input = unreadableSetupMarker.syntheticInput;
  assert.equal(input.activeCli.resourceLayout, 'COMPLETE');
  assert.equal(input.setupMarker.present, true);
  assert.equal(input.setupMarker.readableByInvokingUser, false);
  assert.equal(input.setupMarker.runtimeBinding, 'NOT_PROVEN');
  assert.ok(input.setupAttempts > 1);
  assert.equal(input.sandboxResult.runtimeMarkerObserved, false);

  const summary = summarizeAssessment({
    codexVersion: input.activeCli.version,
    activeCodexIdentity: input.activeCli.identity,
    activeBundle: {
      installType: 'standalone', resourceLayout: input.activeCli.resourceLayout,
      helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED',
    },
    config: { warnings: [] },
  }, [], {
    status: input.sandboxResult.status,
    codexSource: input.activeCli.source,
    codexExecutableIdentity: input.activeCli.identity,
    testedCodexVersion: input.activeCli.version,
    codexProcessStarted: input.sandboxResult.codexProcessStarted,
    smoke: {
      passed: false,
      commandExitCode: input.sandboxResult.commandExitCode,
      codexProcessStarted: input.sandboxResult.codexProcessStarted,
      setupFailure: false,
      stderr: input.sandboxResult.stderr,
    },
    probes: [],
    error: input.sandboxResult.stderr,
  }, { execpolicyRun: false });

  assert.equal(summary.activeCli.helperResolution, input.expected.helperResolution);
  assert.equal(summary.activeCli.runtimeStartup, input.expected.runtimeStartup);
  assert.equal(summary.sandboxRuntime, input.expected.sandboxRuntime);
  assert.equal(summary.boundary, input.expected.boundary);
  assert.equal(summary.overall, input.expected.overall);
  assert.notEqual(summary.activeCli.runtimeStartup, 'READY');
  assert.notEqual(summary.boundary, 'PASS');
});

test('openai/codex#41278 fails closed when Codex exits 1 before child identity markers appear', () => {
  const input = missingChildIdentity.syntheticInput;
  assert.equal(input.sandboxProcess.started, true);
  assert.equal(input.sandboxProcess.exitCode, 1);
  assert.equal(input.sandboxProcess.childIdentityMarkerObserved, false);
  assert.equal(input.sandboxProcess.completionMarkerObserved, false);

  const summary = summarizeAssessment({
    codexVersion: input.activeCli.version,
    activeCodexIdentity: input.activeCli.identity,
    activeBundle: {
      installType: 'standalone', resourceLayout: 'COMPLETE',
      helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED',
    },
    config: { warnings: [] },
  }, [], {
    status: 'SETUP_FAILED',
    codexSource: input.activeCli.source,
    codexExecutableIdentity: input.activeCli.identity,
    testedCodexVersion: input.activeCli.version,
    codexProcessStarted: input.sandboxProcess.started,
    smoke: {
      passed: false,
      commandExitCode: input.sandboxProcess.exitCode,
      codexProcessStarted: input.sandboxProcess.started,
      setupFailure: false,
      stdout: '',
      stderr: '',
    },
    probes: [],
    error: null,
  }, { execpolicyRun: false });

  assert.equal(summary.activeCli.helperResolution, input.expected.helperResolution);
  assert.equal(summary.activeCli.runtimeStartup, input.expected.runtimeStartup);
  assert.equal(summary.sandboxRuntime, input.expected.sandboxRuntime);
  assert.equal(summary.boundary, input.expected.boundary);
  assert.equal(summary.overall, input.expected.overall);
  assert.notEqual(summary.activeCli.runtimeStartup, 'READY');
  assert.notEqual(summary.boundary, 'PASS');
});

test('openai/codex#28457 keeps resources, doctor, helpers, runtime, and boundary separate', () => {
  const active = splitInstall.syntheticInput.activeCli;
  const inventory = {
    codexVersion: active.version,
    activeCodexIdentity: active.identity,
    doctor: { status: 'COMPLETED', ok: true, overallStatus: active.doctorStatus },
    activeBundle: {
      installType: active.installType,
      complete: false,
      probeEligible: true,
      resourceLayout: active.resourceLayout,
      helperResolution: 'NOT_TESTED',
      runtimeStartup: 'NOT_TESTED',
      standaloneResourcesFound: true,
      standaloneRequiredResourcesPresent: true,
      resourceVersionMatchesActive: true,
      standalonePackage: { releaseVersion: '0.140.0' },
    },
    config: { warnings: [] },
  };

  const inventoryOnly = summarizeAssessment(inventory, [], null, {
    assessmentMode: ASSESSMENT_MODES.CONFIGURATION_ONLY,
    execpolicyRun: false,
  });
  assert.equal(inventoryOnly.activeCli.resourceLayout, 'COMPLETE');
  assert.equal(inventoryOnly.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(inventoryOnly.activeCli.runtimeStartup, 'NOT_TESTED');
  assert.equal(inventoryOnly.activeCli.boundaryStatus, 'NOT TESTED');

  for (const key of ['setupHelperFailure', 'commandRunnerFailure']) {
    const failure = splitInstall.syntheticInput[key];
    const runtimeEvidence = buildSandboxRuntimeEvidence(failure.text, {
      step: 'SANDBOX_SMOKE', codexSource: active.source, codexExecutableIdentity: active.identity,
    });
    assert.equal(runtimeEvidence.component, failure.component);
    const summary = summarizeAssessment(inventory, [], {
      status: 'SETUP_FAILED', codexSource: active.source, codexExecutableIdentity: active.identity,
      testedCodexVersion: active.version, smoke: { passed: false, setupFailure: true, stderr: failure.text },
      runtimeEvidence, probes: [], error: failure.text,
    }, { execpolicyRun: false });
    assert.equal(summary.activeCli.helperResolution, failure.expected.helperResolution);
    assert.equal(summary.activeCli.runtimeStartup, failure.expected.runtimeStartup);
    assert.equal(summary.activeCli.boundaryStatus, failure.expected.boundary);
    assert.equal(summary.boundary, failure.expected.boundary);
    assert.equal(summary.recommendations.some((item) => item.code === 'DOCTOR_OK_BUT_RUNTIME_FAILED'), true);
  }
});

test('openai/codex#28457 alternative result never validates the active PATH CLI', () => {
  const fixture = splitInstall.syntheticInput;
  assert.equal(fixture.alternativeBundle.requiresExplicitSelection, true);
  const summary = summarizeAssessment({
    codexVersion: fixture.activeCli.version,
    activeBundle: { installType: 'standalone', resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    config: { warnings: [] },
  }, [], completedAlternativeBoundary(fixture.alternativeBundle), { execpolicyRun: false });
  assert.equal(summary.activeCli.boundaryStatus, fixture.alternativeBundle.expectedActiveBoundary);
  assert.equal(summary.testedBundle.boundaryStatus, fixture.alternativeBundle.expectedTestedBoundary);
});

test('openai/codex#28457 runtime evidence from another executable cannot bind to the active CLI', () => {
  const fixture = splitInstall.syntheticInput;
  const failure = fixture.commandRunnerFailure;
  const foreignEvidence = buildSandboxRuntimeEvidence(failure.text, {
    step: 'SANDBOX_SMOKE', codexSource: fixture.activeCli.source, codexExecutableIdentity: 'fixture-foreign-codex',
  });
  const summary = summarizeAssessment({
    codexVersion: fixture.activeCli.version,
    activeCodexIdentity: fixture.activeCli.identity,
    doctor: { status: 'COMPLETED', ok: true, overallStatus: fixture.activeCli.doctorStatus },
    activeBundle: { resourceLayout: 'COMPLETE', helperResolution: 'NOT_TESTED', runtimeStartup: 'NOT_TESTED' },
    config: { warnings: [] },
  }, [], {
    status: 'SETUP_FAILED', codexSource: fixture.activeCli.source, codexExecutableIdentity: fixture.activeCli.identity,
    smoke: { passed: false, stderr: failure.text }, runtimeEvidence: foreignEvidence, probes: [], error: failure.text,
  }, { execpolicyRun: false });
  assert.equal(summary.activeCli.helperResolution, 'NOT_TESTED');
  assert.equal(summary.activeCli.runtimeStartup, 'FAILED');
  assert.equal(summary.boundary, 'TEST ERROR');
  assert.equal(summary.recommendations.some((item) => item.code === 'COMMAND_RUNNER_PROCESS_CREATION_FAILED'), false);
});

test('openai/codex#36179 separates policy match, path rule binding, and execution binding', () => {
  for (const fixtureCase of execpolicyBinding.cases) {
    const parsedResult = parseExecpolicyOutput(fixtureCase.output);
    const binding = analyzeExecpolicyCommandBinding({
      command: fixtureCase.command,
      parsedResult,
      resolvedCommandPath: fixtureCase.resolvedCommandPath,
    });
    assert.equal(parsedResult.status, fixtureCase.expected.policyStatus, fixtureCase.id);
    assert.equal(parsedResult.decision, fixtureCase.expected.decision ?? null, fixtureCase.id);
    assert.equal(binding.ruleBinding, fixtureCase.expected.ruleBinding, fixtureCase.id);
    assert.equal(binding.executionBinding, fixtureCase.expected.executionBinding, fixtureCase.id);
    assert.equal(binding.hostResolutionObserved, true, fixtureCase.id);
    assert.match(binding.evidenceBoundary, /does not execute the command/);
    if (fixtureCase.id.startsWith('absolute-rule')) {
      assert.match(fixtureCase.policyRule.prefix[0], /^[A-Za-z]:\\/);
    }
    if (fixtureCase.id === 'absolute-rule-bare-command-no-match') {
      assert.doesNotMatch(fixtureCase.command[0], /[\\/]/);
      assert.notEqual(fixtureCase.policyRule.prefix[0], fixtureCase.command[0]);
    }
    if (fixtureCase.id === 'bare-rule-bare-command-match') {
      assert.equal(fixtureCase.policyRule.prefix[0], fixtureCase.command[0]);
      assert.notEqual(fixtureCase.resolvedCommandPath, fixtureCase.command[0]);
    }
  }
});

test('execpolicy strictest decision cannot borrow path binding from a weaker matched rule', () => {
  const absolute = 'C:\\Synthetic\\npm\\playwright-cli.ps1';
  const parsedResult = parseExecpolicyOutput({
    matchedRules: [
      { prefixRuleMatch: { matchedPrefix: [absolute], decision: 'allow' } },
      { prefixRuleMatch: { matchedPrefix: ['playwright-cli'], decision: 'forbidden' } },
    ],
  });
  const binding = analyzeExecpolicyCommandBinding({ command: [absolute], parsedResult, resolvedCommandPath: absolute });
  assert.equal(parsedResult.decision, 'forbidden');
  assert.equal(binding.ruleBinding, 'NOT_PROVEN');
  assert.equal(binding.executionBinding, 'NOT_PROVEN');
});

test('execpolicy binding evidence is consistent and path-free in share-safe reports', () => {
  const fixtureCase = execpolicyBinding.cases.find((item) => item.id === 'bare-rule-bare-command-match');
  const parsedResult = parseExecpolicyOutput(fixtureCase.output);
  const binding = analyzeExecpolicyCommandBinding({
    command: fixtureCase.command, parsedResult, resolvedCommandPath: fixtureCase.resolvedCommandPath,
  });
  const appRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'canary-upstream-report-'));
  try {
    const report = writeReport({
      appRoot,
      inventory: {
        platform: 'win32', release: 'synthetic', nodeVersion: process.version, nodeRuntimeSource: 'TEST',
        nodeInPath: true, npmInPath: false, elevated: false, codexInstalled: true, codexVersion: 'codex-cli 0.146.0',
        activeCodexPath: 'C:\\Synthetic\\Codex\\codex.exe', activeBundle: { installType: 'classic', resourceLayout: 'COMPLETE' },
        standalonePackages: [], matchingCompleteBundles: [], newerCompleteBundles: [], doctor: { status: 'NOT_RUN' },
        codexHome: 'C:\\Synthetic\\CodexHome', authFilePresent: false, ruleFiles: ['C:\\Synthetic\\CodexHome\\rules\\fixture.rules'],
        sandboxWindowsState: 'AVAILABLE', sandboxCommandContract: { syntax: 'GENERIC_PERMISSION_PROFILE' },
        config: { exists: false, path: 'C:\\Synthetic\\CodexHome\\config.toml', warnings: [] },
      },
      rules: [{ id: fixtureCase.id, label: 'Synthetic bare-name rule', command: fixtureCase.command, ...parsedResult, binding }],
      sandbox: null,
      assessmentMode: ASSESSMENT_MODES.EXECPOLICY_ONLY,
    });
    const detailText = fs.readFileSync(report.txtPath, 'utf8');
    const supportText = fs.readFileSync(report.supportTxtPath, 'utf8');
    const supportJson = fs.readFileSync(report.supportJsonPath, 'utf8');
    assert.match(detailText, /Rule path binding: NOT_PROVEN/);
    assert.match(detailText, /Execution binding: NOT_PROVEN/);
    assert.match(supportText, /Rule path binding: NOT_PROVEN; execution binding: NOT_PROVEN/);
    assert.match(supportJson, /"ruleBinding": "NOT_PROVEN"/);
    assert.doesNotMatch(supportText, /Synthetic\\later-path/);
    assert.doesNotMatch(supportJson, /Synthetic\\\\later-path/);
  } finally {
    fs.rmSync(appRoot, { recursive: true, force: true });
  }
});
