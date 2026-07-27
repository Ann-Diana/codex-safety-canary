import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const APP_NAME = 'Codex Safety Canary';
export const APP_DIR_NAME = 'CodexSafetyCanary';
export const APP_VERSION = '0.1.0-alpha.10';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const CODEX_WRAPPER = path.resolve(MODULE_DIR, '..', 'tools', 'invoke-codex.ps1');

export const WINDOWS_SANDBOX_FEATURE_STATES = Object.freeze({
  AVAILABLE: 'AVAILABLE',
  AVAILABLE_BUT_SETUP_FAILED: 'AVAILABLE_BUT_SETUP_FAILED',
  UNSUPPORTED: 'UNSUPPORTED',
  DETECTION_ERROR: 'DETECTION_ERROR',
});

export const ASSESSMENT_MODES = Object.freeze({
  GUIDED: 'GUIDED',
  GUIDED_LIVE_PROBES_SKIPPED: 'GUIDED – LIVE PROBES SKIPPED',
  SANDBOX_ONLY_LIVE_PROBES_SKIPPED: 'SANDBOX ONLY – LIVE PROBES SKIPPED',
  CONFIGURATION_ONLY: 'CONFIGURATION ONLY',
  EXECPOLICY_ONLY: 'EXECPOLICY ONLY',
  SANDBOX_ONLY: 'SANDBOX ONLY',
});

export const RECOMMENDATION_SEVERITIES = Object.freeze({
  INFO: 'INFO',
  OPTIONAL_HARDENING: 'OPTIONAL_HARDENING',
  ACTION_RECOMMENDED: 'ACTION_RECOMMENDED',
  PROTECTION_NOT_CONFIRMED: 'PROTECTION_NOT_CONFIRMED',
  POTENTIAL_SECURITY_GAP: 'POTENTIAL_SECURITY_GAP',
});

export const CODEX_BUNDLE_REQUIRED_FILES = Object.freeze([
  'codex-windows-sandbox-setup.exe',
  'codex-command-runner.exe',
]);

export const CODEX_BUNDLE_OPTIONAL_FILES = Object.freeze([
  'codex-code-mode-host.exe',
]);

export function getAppRoot(env = process.env) {
  const local = env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return path.resolve(local, APP_DIR_NAME);
}

export function getCodexHome(env = process.env) {
  return path.resolve(env.CODEX_HOME || path.join(os.homedir(), '.codex'));
}

export function nowId(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

export function randomId() {
  return crypto.randomBytes(4).toString('hex');
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function isPathInside(child, parent) {
  const rel = path.relative(path.resolve(parent), path.resolve(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function safeRemoveRun(runDir, appRoot) {
  const runsRoot = path.join(path.resolve(appRoot), 'runs');
  const resolved = path.resolve(runDir);
  if (!isPathInside(resolved, runsRoot) || resolved === runsRoot) {
    throw new Error(`Refusing to remove a path outside the Canary runs directory: ${resolved}`);
  }
  fs.rmSync(resolved, { recursive: true, force: true });
}

export function listRuleFiles(codexHome) {
  const rulesDir = path.join(codexHome, 'rules');
  if (!fs.existsSync(rulesDir)) return [];
  return fs.readdirSync(rulesDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.rules'))
    .map((entry) => path.join(rulesDir, entry.name))
    .sort((a, b) => a.localeCompare(b));
}


export function findCommandPath(command) {
  const lookup = process.platform === 'win32' ? 'where.exe' : 'which';
  const result = spawnSync(lookup, [command], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10_000,
  });
  if (result.status !== 0) return null;
  return String(result.stdout || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean) || null;
}

export function commandInPath(command) {
  return Boolean(findCommandPath(command));
}

function replaceAllIgnoreCase(value, search, replacement) {
  const text = String(value ?? '');
  const needle = String(search ?? '');
  if (!needle) return text;
  const lowerText = text.toLowerCase();
  const lowerNeedle = needle.toLowerCase();
  const parts = [];
  let cursor = 0;
  let index = lowerText.indexOf(lowerNeedle, cursor);
  while (index !== -1) {
    parts.push(text.slice(cursor, index), replacement);
    cursor = index + needle.length;
    index = lowerText.indexOf(lowerNeedle, cursor);
  }
  parts.push(text.slice(cursor));
  return parts.join('');
}


function stripTomlComment(line) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote === '"') {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (quote === "'") {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") quote = character;
    else if (character === '#') return line.slice(0, index);
  }
  return line;
}

function parseTomlSectionHeader(line) {
  const content = stripTomlComment(line).trim();
  if (!content.startsWith('[') || !content.endsWith(']') || content.startsWith('[[')) return null;
  return content.slice(1, -1).trim() || null;
}

function findTomlAssignment(line) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote === '"') {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (quote === "'") {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") quote = character;
    else if (character === '=') return index;
  }
  return -1;
}

function parseTomlScalar(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1);
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try { return JSON.parse(trimmed); } catch { return trimmed.slice(1, -1); }
  }
  return trimmed;
}

const TOML_KEY_SEPARATOR = '\\u0000';

const SAFE_TOML_KEYS = new Map([
  ['', new Set(['sandbox_mode', 'approval_policy', 'default_permissions'])],
  ['windows', new Set(['sandbox'])],
  ['sandbox_workspace_write', new Set(['network_access'])],
]);

// This is intentionally not a general TOML parser. It reads only the selected
// single-line scalar settings used by the diagnostic and ignores all others.
function readSelectedTomlValues(text) {
  const values = new Map();
  let section = '';
  for (const rawLine of String(text).split(/\r?\n/)) {
    const nextSection = parseTomlSectionHeader(rawLine);
    if (nextSection != null) {
      section = nextSection;
      continue;
    }
    const line = stripTomlComment(rawLine).trim();
    if (!line) continue;
    const assignment = findTomlAssignment(line);
    if (assignment < 1) continue;
    const key = parseTomlScalar(line.slice(0, assignment));
    if (!SAFE_TOML_KEYS.get(section)?.has(key)) continue;
    const value = parseTomlScalar(line.slice(assignment + 1));
    values.set(`${section}${TOML_KEY_SEPARATOR}${key}`, value);
  }
  return values;
}

export function extractTomlSection(text, sectionName) {
  const selected = [];
  let found = false;
  let active = false;
  for (const line of String(text).split(/\r?\n/)) {
    const currentSection = parseTomlSectionHeader(line);
    if (currentSection != null) {
      if (active) break;
      active = currentSection === sectionName;
      found ||= active;
    } else if (active) {
      selected.push(line);
    }
  }
  return found ? selected.join('\n') : null;
}

export function readSafeConfigSummary(configPath) {
  const result = {
    exists: fs.existsSync(configPath),
    path: configPath,
    sandboxMode: null,
    approvalPolicy: null,
    defaultPermissions: null,
    windowsSandbox: null,
    networkAccess: null,
    warnings: [],
  };
  if (!result.exists) return result;
  const values = readSelectedTomlValues(fs.readFileSync(configPath, 'utf8'));
  const getValue = (section, key) => values.get(`${section}${TOML_KEY_SEPARATOR}${key}`) ?? null;
  result.sandboxMode = getValue('', 'sandbox_mode');
  result.approvalPolicy = getValue('', 'approval_policy');
  result.defaultPermissions = getValue('', 'default_permissions');
  result.windowsSandbox = getValue('windows', 'sandbox');
  const networkAccess = getValue('sandbox_workspace_write', 'network_access');
  if (typeof networkAccess === 'string') {
    if (networkAccess.toLowerCase() === 'true') result.networkAccess = true;
    else if (networkAccess.toLowerCase() === 'false') result.networkAccess = false;
  }

  if (result.sandboxMode === 'danger-full-access' || result.defaultPermissions === ':danger-full-access') {
    result.warnings.push('Full-access configuration detected. Filesystem sandbox boundaries may be disabled.');
  }
  if (result.approvalPolicy === 'never') {
    result.warnings.push('approval_policy = never: Codex will not pause for approval prompts.');
  }
  if (result.networkAccess === true) {
    result.warnings.push('Network access is enabled in :workspace permission profile.');
  }
  return result;
}

export function invokeCodex(args, options = {}) {
  const cwd = options.cwd || process.cwd();
  const timeout = options.timeout ?? 60_000;
  if (process.platform === 'win32') {
    return spawnSync('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', CODEX_WRAPPER,
      ...args,
    ], {
      cwd,
      timeout,
      encoding: 'utf8',
      windowsHide: true,
      env: {
        ...process.env,
        NO_COLOR: '1',
        CANARY_CODEX_EXE: options.codexExe || '',
      },
    });
  }
  return spawnSync('codex', args, {
    cwd,
    timeout,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

export function normalizeCodexVersion(value) {
  const match = String(value || '').match(/codex(?:-cli)?\s+([0-9]+(?:\.[0-9]+){1,3}(?:[-+][^\s]+)?)/i);
  return match ? match[1] : String(value || '').trim().toLowerCase();
}


export function compareCodexVersions(left, right) {
  const parse = (value) => {
    const normalized = normalizeCodexVersion(value);
    const match = normalized.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
    if (!match) return null;
    return {
      core: [Number(match[1]), Number(match[2]), Number(match[3])],
      prerelease: match[4] ? match[4].split('.') : [],
    };
  };
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a.core[index] !== b.core[index]) return a.core[index] > b.core[index] ? 1 : -1;
  }
  if (!a.prerelease.length && !b.prerelease.length) return 0;
  if (!a.prerelease.length) return 1;
  if (!b.prerelease.length) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const av = a.prerelease[index];
    const bv = b.prerelease[index];
    if (av == null) return -1;
    if (bv == null) return 1;
    if (av === bv) continue;
    const an = /^\d+$/.test(av) ? Number(av) : null;
    const bn = /^\d+$/.test(bv) ? Number(bv) : null;
    if (an != null && bn != null) return an > bn ? 1 : -1;
    if (an != null) return -1;
    if (bn != null) return 1;
    return av > bv ? 1 : -1;
  }
  return 0;
}

export function inspectCodexBundle(executablePath) {
  if (!executablePath) {
    return { executablePath: null, directory: null, exists: false, complete: false, missing: [...CODEX_BUNDLE_REQUIRED_FILES], optionalMissing: [...CODEX_BUNDLE_OPTIONAL_FILES] };
  }
  const resolved = path.resolve(executablePath);
  const directory = path.dirname(resolved);
  const missing = CODEX_BUNDLE_REQUIRED_FILES.filter((name) => !fs.existsSync(path.join(directory, name)));
  const optionalMissing = CODEX_BUNDLE_OPTIONAL_FILES.filter((name) => !fs.existsSync(path.join(directory, name)));
  return {
    executablePath: resolved,
    directory,
    exists: fs.existsSync(resolved),
    complete: fs.existsSync(resolved) && missing.length === 0,
    missing,
    optionalMissing,
  };
}

function collectCodexExecutables(root, maxDepth = 2) {
  const results = [];
  const visit = (dir, depth) => {
    if (depth > maxDepth || !fs.existsSync(dir)) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.toLowerCase() === 'codex.exe') results.push(path.resolve(full));
      else if (entry.isDirectory()) visit(full, depth + 1);
    }
  };
  visit(root, 0);
  return results;
}

export function discoverCodexBundlePaths(env = process.env) {
  if (process.platform !== 'win32') return [];
  const local = env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const roots = [
    path.join(local, 'OpenAI', 'Codex', 'bin'),
    path.join(local, 'Programs', 'OpenAI', 'Codex', 'bin'),
  ];
  return [...new Set(roots.flatMap((root) => collectCodexExecutables(root, 2)))];
}

export function selectCodexProbePlan(inventory) {
  if (!inventory) {
    return { ready: false, requiresConfirmation: false, source: null, codexExe: null, reason: 'Codex inventory is unavailable.' };
  }
  if (inventory.activeBundle?.complete || inventory.sandboxHelperInPath) {
    if (inventory.sandboxWindowsState !== WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE) {
      return { ready: false, requiresConfirmation: false, source: null, codexExe: null, reason: `The active CLI bundle is complete, but its Windows sandbox state is ${inventory.sandboxWindowsState || 'UNKNOWN'}.` };
    }
    return {
      ready: true,
      requiresConfirmation: false,
      source: 'ACTIVE_CLI',
      codexExe: inventory.activeCodexPath || null,
      testedVersion: inventory.codexVersion || null,
      activeVersion: inventory.codexVersion || null,
      versionMismatch: false,
      fullAutoAvailable: inventory.sandboxFullAutoAvailable === true,
      reason: null,
    };
  }
  const matchingCandidate = inventory.matchingCompleteBundles?.find((bundle) => bundle.sandboxState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE);
  if (matchingCandidate) {
    return {
      ready: true,
      requiresConfirmation: true,
      source: 'MATCHING_COMPLETE_BUNDLE',
      codexExe: matchingCandidate.executablePath,
      testedVersion: matchingCandidate.version,
      activeVersion: inventory.codexVersion || null,
      versionMismatch: false,
      fullAutoAvailable: matchingCandidate.sandboxFullAutoAvailable === true,
      reason: 'The active CLI bundle is incomplete, but a complete local bundle with the same Codex version was found.',
    };
  }
  const newerCandidate = inventory.newerCompleteBundles?.find((bundle) => bundle.sandboxState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE);
  if (newerCandidate) {
    return {
      ready: true,
      requiresConfirmation: true,
      source: 'NEWER_COMPLETE_BUNDLE',
      codexExe: newerCandidate.executablePath,
      testedVersion: newerCandidate.version,
      activeVersion: inventory.codexVersion || null,
      versionMismatch: true,
      fullAutoAvailable: newerCandidate.sandboxFullAutoAvailable === true,
      reason: 'The active CLI bundle is incomplete. A newer complete local bundle was found, but results will apply only to that alternative bundle.',
    };
  }
  const completeSummary = inventory.completeBundles?.length
    ? ` Complete local bundle(s) were found, but none provide a same-version or newer test-ready sandbox: ${inventory.completeBundles.map((bundle) => `${bundle.version || 'unknown version'} (${bundle.sandboxState || 'unknown sandbox state'})`).join(', ')}.`
    : '';
  return {
    ready: false,
    requiresConfirmation: false,
    source: null,
    codexExe: null,
    reason: `The active CLI bundle is incomplete. Its sandbox state is ${inventory.sandboxWindowsState || 'UNKNOWN'}, and no suitable complete local bundle was found.${completeSummary}`,
  };
}

export function detectWindowsSandboxFeature(helpRun) {
  if (!helpRun || helpRun.error || helpRun.status == null) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR,
      available: false,
      fullAutoAvailable: false,
      setupFailed: false,
      error: helpRun ? compactError(helpRun) : 'Codex sandbox help was not run.',
    };
  }

  const text = `${helpRun.stdout || ''}\n${helpRun.stderr || ''}`;
  if (helpRun.status === 0) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE,
      available: true,
      fullAutoAvailable: /--full-auto\b/i.test(text),
      setupFailed: false,
      error: null,
    };
  }

  if (detectSandboxSetupFailure(helpRun)) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE_BUT_SETUP_FAILED,
      available: false,
      fullAutoAvailable: false,
      setupFailed: true,
      error: compactError(helpRun),
    };
  }

  if (/unrecognized subcommand|unknown command|invalid subcommand|unexpected argument/i.test(text)) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.UNSUPPORTED,
      available: false,
      fullAutoAvailable: false,
      setupFailed: false,
      error: compactError(helpRun),
    };
  }

  return {
    state: WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR,
    available: false,
    fullAutoAvailable: false,
    setupFailed: false,
    error: compactError(helpRun),
  };
}

export function canRunLiveSandboxProbes(inventory) {
  return inventory?.sandboxWindowsState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE;
}

export function launchDetachedProcess(command, args = [], options = {}) {
  const spawnImpl = options.spawnImpl || spawn;
  const spawnOptions = {
    detached: options.detached ?? true,
    stdio: options.stdio ?? 'ignore',
    shell: false,
    // GUI helpers must remain visible. `windowsHide: true` can successfully
    // start Notepad or Explorer while suppressing the window the user needs.
    windowsHide: options.windowsHide ?? false,
  };
  return new Promise((resolve) => {
    let child;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ command, args: [...args], options: spawnOptions, ...result });
    };
    try {
      child = spawnImpl(command, args, spawnOptions);
    } catch (error) {
      finish({ ok: false, error: error.message || String(error) });
      return;
    }
    child.once('spawn', () => {
      try { child.unref?.(); } catch {}
      finish({ ok: true, error: null });
    });
    child.once('error', (error) => {
      finish({ ok: false, error: error.message || String(error) });
    });
  });
}

export function formatExecpolicyCoverage(coverage) {
  if (!coverage || coverage.status === 'NOT_RUN') return 'NOT RUN';
  if (typeof coverage === 'string') return coverage;
  if (coverage.status === 'COMPLETED') return `${coverage.matched ?? 0}/${coverage.total ?? 0}`;
  return coverage.status || 'UNKNOWN';
}

export function formatDiagnosticRecommendationLines(recommendations = []) {
  const lines = [];
  for (const item of recommendations) {
    lines.push(`- ${item.severity} ${item.code}`);
    lines.push(`  Title: ${item.title}`);
    lines.push(`  Explanation: ${item.message}`);
    lines.push(`  Recommendation: ${item.recommendation}`);
  }
  return lines;
}

export function buildSandboxCommandArgs(command, options = {}) {
  const permissionProfile = options.permissionProfile || ':workspace';
  const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
  const args = ['sandbox', '--permission-profile', permissionProfile, '--cd', workspaceDir, '--'];
  args.push(...command);
  return args;
}

export function getCodexInventory(env = process.env) {
  const codexHome = getCodexHome(env);
  const configPath = path.join(codexHome, 'config.toml');
  const activeCodexPath = findCommandPath(process.platform === 'win32' ? 'codex.exe' : 'codex');
  const versionRun = invokeCodex(['--version'], { timeout: 20_000, codexExe: activeCodexPath });
  const installed = versionRun.status === 0;
  const version = installed ? (versionRun.stdout || versionRun.stderr || '').trim() : null;
  const normalizedVersion = normalizeCodexVersion(version);
  const helpRun = installed ? invokeCodex(['sandbox', '--help'], { timeout: 20_000, codexExe: activeCodexPath }) : null;
  const sandboxFeature = installed ? detectWindowsSandboxFeature(helpRun) : {
    state: WINDOWS_SANDBOX_FEATURE_STATES.UNSUPPORTED,
    available: false,
    fullAutoAvailable: false,
    setupFailed: false,
    error: 'Codex CLI is not installed or not executable.',
  };
  const sandboxHelp = helpRun && helpRun.status === 0 ? `${helpRun.stdout}\n${helpRun.stderr}` : '';
  const activeBundle = inspectCodexBundle(activeCodexPath);
  const sandboxHelperInPath = Boolean(findCommandPath('codex-windows-sandbox-setup.exe'));
  const bundlePaths = discoverCodexBundlePaths(env).filter((candidate) => !activeCodexPath || path.resolve(candidate).toLowerCase() !== path.resolve(activeCodexPath).toLowerCase());
  const completeBundles = [];
  for (const candidatePath of bundlePaths) {
    const bundle = inspectCodexBundle(candidatePath);
    if (!bundle.complete) continue;
    const candidateVersionRun = invokeCodex(['--version'], { timeout: 20_000, codexExe: candidatePath });
    if (candidateVersionRun.status !== 0) continue;
    const candidateVersion = String(candidateVersionRun.stdout || candidateVersionRun.stderr || '').trim();
    const candidateHelpRun = invokeCodex(['sandbox', '--help'], { timeout: 20_000, codexExe: candidatePath });
    const candidateSandboxFeature = detectWindowsSandboxFeature(candidateHelpRun);
    const versionComparison = installed ? compareCodexVersions(candidateVersion, version) : null;
    completeBundles.push({
      ...bundle,
      version: candidateVersion,
      normalizedVersion: normalizeCodexVersion(candidateVersion),
      versionMatchesActive: installed && normalizeCodexVersion(candidateVersion) === normalizedVersion,
      versionComparisonToActive: versionComparison,
      sandboxState: candidateSandboxFeature.state,
      sandboxHelpError: candidateSandboxFeature.error,
      sandboxFullAutoAvailable: candidateSandboxFeature.fullAutoAvailable,
    });
  }
  const matchingCompleteBundles = completeBundles.filter((bundle) => bundle.versionMatchesActive);
  const newerCompleteBundles = completeBundles
    .filter((bundle) => bundle.versionComparisonToActive === 1)
    .sort((left, right) => compareCodexVersions(right.version, left.version) || 0);
  const inventory = {
    platform: process.platform,
    release: os.release(),
    nodeVersion: process.version,
    nodeRuntimeSource: env.CANARY_NODE_SOURCE || (commandInPath('node.exe') ? 'PATH' : 'unknown'),
    nodeInPath: commandInPath('node.exe'),
    npmInPath: commandInPath(process.platform === 'win32' ? 'npm.cmd' : 'npm'),
    elevated: isElevatedWindows(),
    codexInstalled: installed,
    codexVersion: version,
    activeCodexPath,
    activeBundle,
    sandboxHelperInPath,
    completeBundles,
    matchingCompleteBundles,
    newerCompleteBundles,
    codexHome,
    authFilePresent: fs.existsSync(path.join(codexHome, 'auth.json')),
    config: readSafeConfigSummary(configPath),
    ruleFiles: listRuleFiles(codexHome),
    sandboxWindowsState: sandboxFeature.state,
    sandboxWindowsAvailable: sandboxFeature.state === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE,
    sandboxFullAutoAvailable: sandboxFeature.state === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE && /--full-auto\b/i.test(sandboxHelp),
    sandboxSetupFailed: sandboxFeature.setupFailed,
    sandboxHelpStatus: helpRun?.status ?? null,
    sandboxHelpError: sandboxFeature.error,
  };
  inventory.sandboxProbePlan = selectCodexProbePlan(inventory);
  return inventory;
}

export function isElevatedWindows() {
  if (process.platform !== 'win32') return false;
  const result = spawnSync('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
  ], { encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  return result.status === 0 && String(result.stdout).trim().toLowerCase() === 'true';
}

export const RULE_PROBES = [
  {
    id: 'powershell-remove-item',
    label: 'PowerShell Remove-Item',
    command: ['powershell.exe', '-NoProfile', '-Command', 'Remove-Item canary.txt -Force'],
  },
  {
    id: 'pwsh-remove-item',
    label: 'PowerShell 7 wrapper',
    command: ['pwsh.exe', '-NoProfile', '-Command', 'Remove-Item canary.txt -Force'],
  },
  {
    id: 'cmd-del',
    label: 'cmd.exe del',
    command: ['cmd.exe', '/d', '/c', 'del', '/f', '/q', 'canary.txt'],
  },
  {
    id: 'node-rm-sync',
    label: 'Node.js fs.rmSync',
    command: ['node.exe', '-e', "require('node:fs').rmSync('canary.txt')"],
  },
  {
    id: 'git-clean',
    label: 'Git clean -fd',
    command: ['git', 'clean', '-fd'],
  },
  {
    id: 'git-reset-hard',
    label: 'Git reset --hard',
    command: ['git', 'reset', '--hard'],
  },
];

export function findDecision(value) {
  if (value == null) return null;
  if (typeof value === 'string') {
    const normalized = value.toLowerCase();
    if (['allow', 'allowed', 'prompt', 'forbidden', 'deny', 'denied', 'block', 'blocked'].includes(normalized)) {
      if (normalized === 'allowed') return 'allow';
      if (normalized === 'deny' || normalized === 'denied' || normalized === 'block' || normalized === 'blocked') return 'forbidden';
      return normalized;
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findDecision(item);
      if (found) return found;
    }
    return null;
  }
  if (typeof value === 'object') {
    for (const key of ['decision', 'strictestDecision', 'strictest_decision', 'result']) {
      if (key in value) {
        const found = findDecision(value[key]);
        if (found) return found;
      }
    }
    for (const item of Object.values(value)) {
      const found = findDecision(item);
      if (found) return found;
    }
  }
  return null;
}

export function parseExecpolicyOutput(output) {
  const parsed = typeof output === 'string' ? JSON.parse(output) : output;
  const decision = findDecision(parsed);
  if (decision) {
    return { parsed, status: 'OK', decision, error: null };
  }
  if (parsed && Array.isArray(parsed.matchedRules) && parsed.matchedRules.length === 0) {
    return { parsed, status: 'NO_MATCH', decision: null, error: null };
  }
  return {
    parsed,
    status: 'UNKNOWN_SCHEMA',
    decision: null,
    error: 'The execpolicy output was valid JSON but did not contain a recognizable decision or an explicit empty matchedRules array.',
  };
}

export function runExecpolicyCoverage(ruleFiles, options = {}) {
  if (!ruleFiles.length) {
    return RULE_PROBES.map((probe) => ({
      ...probe,
      status: 'NO_RULES',
      decision: null,
      raw: null,
      error: 'No user-level .rules files were found.',
    }));
  }
  return RULE_PROBES.map((probe) => {
    const args = ['execpolicy', 'check', '--pretty'];
    for (const file of ruleFiles) args.push('--rules', file);
    args.push('--', ...probe.command);
    const result = invokeCodex(args, { timeout: 30_000, codexExe: options.codexExe });
    if (result.status !== 0) {
      return { ...probe, status: 'ERROR', decision: null, raw: result.stdout, error: compactError(result) };
    }
    const output = String(result.stdout || '').trim();
    try {
      const parsedResult = parseExecpolicyOutput(output);
      return {
        ...probe,
        status: parsedResult.status,
        decision: parsedResult.decision,
        raw: parsedResult.parsed,
        error: parsedResult.error,
      };
    } catch (error) {
      return { ...probe, status: 'INVALID_JSON', decision: null, raw: output, error: error.message };
    }
  });
}

function writeCanary(file, marker) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `Codex Safety Canary synthetic file\n${marker}\n`, 'utf8');
}

function runSandboxCommand(command, cwd, options = {}) {
  const args = buildSandboxCommandArgs(command, {
    permissionProfile: options.permissionProfile || ':workspace',
    workspaceDir: options.workspaceDir || cwd,
  });
  return invokeCodex(args, { cwd, timeout: 45_000, codexExe: options.codexExe });
}

export function detectAccessDenied(result) {
  const text = `${result?.stdout || ''}
${result?.stderr || ''}
${result?.error?.message || ''}`.toLowerCase();
  return [
    /access(?:\s+to[^\r\n]{0,160})?\s+(?:is\s+)?denied/i,
    /zugriff(?:[^\r\n]{0,160})?verweigert/i,
    /permission denied/i,
    /operation not permitted/i,
    /\beacces\b/i,
    /\beperm\b/i,
    /sandbox denied/i,
  ].some((pattern) => pattern.test(text));
}

export function classifySandboxProbe({ before, after, result, definition }) {
  if (!before) return { assessment: 'ERROR', denialEvidence: false };
  const setupFailure = detectSandboxSetupFailure(result);
  if (setupFailure || result?.error?.code === 'ETIMEDOUT' || result?.error) {
    return { assessment: 'TEST_ERROR', denialEvidence: false };
  }
  const observed = after ? 'RETAINED' : 'DELETED';
  const denialEvidence = detectAccessDenied(result);

  if (definition.expected === 'DELETED') {
    if (observed === 'DELETED') return { assessment: 'EXPECTED', denialEvidence };
    if (denialEvidence) return { assessment: 'UNEXPECTED', denialEvidence };
    return { assessment: 'TEST_ERROR', denialEvidence };
  }

  if (definition.expected === 'RETAINED') {
    if (observed === 'DELETED') return { assessment: 'CRITICAL_GAP', denialEvidence };
    if (denialEvidence) return { assessment: 'PASS', denialEvidence };
    return { assessment: 'TEST_ERROR', denialEvidence };
  }

  return { assessment: 'TEST_ERROR', denialEvidence };
}

export function createRunLayout(appRoot = getAppRoot()) {
  const id = `${nowId()}-${randomId()}`;
  const runDir = ensureDir(path.join(appRoot, 'runs', id));
  const workspace = ensureDir(path.join(runDir, 'workspace'));
  const control = ensureDir(path.join(runDir, 'control'));
  return { id, runDir, workspace, control };
}

export function detectSandboxSetupFailure(result) {
  const text = `${result?.stdout || ''}
${result?.stderr || ''}
${result?.error?.message || ''}`.toLowerCase();
  return [
    'spawn setup refresh',
    "couldn't set up",
    'could not set up',
    'windows sandbox failed',
    'requested operation requires elevation',
    'os error 740',
    'setup refresh: failed',
    'orchestrator_helper_launch_failed',
    'codex-windows-sandbox-setup.exe',
    'program not found',
  ].some((needle) => text.includes(needle));
}

export function buildNodeDeleteCommand(file) {
  return [process.execPath, '-e', "require('node:fs').rmSync(process.argv[1])", file];
}

export function runHostDeletionPreflight(layout, marker) {
  const files = [
    path.join(layout.workspace, 'host-preflight-workspace.txt'),
    path.join(layout.control, 'host-preflight-control.txt'),
  ];
  try {
    for (const file of files) {
      writeCanary(file, marker);
      fs.rmSync(file, { force: false });
      if (fs.existsSync(file)) throw new Error(`Host preflight could not delete ${file}`);
    }
    return { passed: true, filesChecked: files.length, error: null };
  } catch (error) {
    return { passed: false, filesChecked: files.length, error: error.stack || error.message };
  }
}

export function runSandboxProbes(options = {}) {
  if (process.platform !== 'win32') {
    return { status: 'UNSUPPORTED', probes: [], cleanup: null, error: 'Live sandbox probes are Windows-only.' };
  }
  if (options.sandboxWindowsState !== WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE) {
    const state = options.sandboxWindowsState || WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR;
    return { status: 'UNAVAILABLE', probes: [], cleanup: null, error: `Live sandbox probes require Windows sandbox state AVAILABLE; current state is ${state}.` };
  }
  const appRoot = options.appRoot || getAppRoot();
  const layout = createRunLayout(appRoot);
  const marker = crypto.randomUUID();
  const probes = [];
  const hostPreflight = runHostDeletionPreflight(layout, marker);
  const permissionProfile = ':workspace';
  if (!hostPreflight.passed) {
    return { status: 'HOST_PREFLIGHT_FAILED', probes, layout, marker, hostPreflight, smoke: null,
      codexExecutable: options.codexExe || null, codexSource: options.codexSource || 'UNKNOWN',
      testedCodexVersion: options.testedCodexVersion || null, activeCodexVersion: options.activeCodexVersion || null,
      versionMismatch: options.versionMismatch === true, permissionProfile, error: hostPreflight.error };
  }

  const smokeMarker = `CODEX_SAFETY_CANARY_READY_${randomId()}`;
  const smokeResult = runSandboxCommand(['cmd.exe', '/d', '/c', 'echo', smokeMarker], layout.workspace, {
    codexExe: options.codexExe, permissionProfile, workspaceDir: layout.workspace,
  });
  const smokeSetupFailure = detectSandboxSetupFailure(smokeResult);
  const smokePassed = smokeResult.status === 0 && !smokeSetupFailure && String(smokeResult.stdout || '').includes(smokeMarker);
  const smoke = { passed: smokePassed, commandExitCode: smokeResult.status, setupFailure: smokeSetupFailure,
    stdout: truncate(smokeResult.stdout), stderr: truncate(smokeResult.stderr) };
  if (!smokePassed) {
    return { status: 'SETUP_FAILED', probes, layout, marker, smoke, hostPreflight,
      codexExecutable: options.codexExe || null, codexSource: options.codexSource || 'UNKNOWN',
      testedCodexVersion: options.testedCodexVersion || null, activeCodexVersion: options.activeCodexVersion || null,
      versionMismatch: options.versionMismatch === true, permissionProfile, error: compactError(smokeResult) };
  }

  const methods = [
    {
      method: 'powershell', label: 'PowerShell',
      command: (file) => ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', `Remove-Item -LiteralPath '${file.replace(/'/g, "''")}' -Force`],
    },
    {
      method: 'cmd', label: 'cmd.exe',
      command: (file) => ['cmd.exe', '/d', '/c', 'del', '/f', '/q', file],
    },
    {
      method: 'node', label: 'Node.js API',
      command: (file) => buildNodeDeleteCommand(file),
    },
  ];

  try {
    for (const method of methods) {
      for (const location of ['inside', 'outside']) {
        const file = location === 'inside'
          ? path.join(layout.workspace, `${method.method}-inside.txt`)
          : path.join(layout.control, `${method.method}-outside.txt`);
        const expected = location === 'inside' ? 'DELETED' : 'RETAINED';
        const definition = {
          id: `${location}-workspace-${method.method}`,
          label: `${method.label}: delete ${location === 'inside' ? 'inside' : 'outside'} workspace`,
          method: method.method,
          location,
          expected,
          file,
          meaning: location === 'inside'
            ? 'The :workspace permission profile should permit deletion inside the selected workspace.'
            : 'The sandbox should prevent deletion outside the selected workspace.',
        };
        writeCanary(file, marker);
        const before = fs.existsSync(file);
        const result = runSandboxCommand(method.command(file), layout.workspace, {
          codexExe: options.codexExe, permissionProfile, workspaceDir: layout.workspace,
        });
        const after = fs.existsSync(file);
        const classification = classifySandboxProbe({ before, after, result, definition });
        probes.push({
          id: definition.id, label: definition.label, method: method.method, location, expected,
          observed: after ? 'RETAINED' : 'DELETED', assessment: classification.assessment,
          commandExitCode: result.status, setupFailure: detectSandboxSetupFailure(result),
          denialEvidence: classification.denialEvidence, stdout: truncate(result.stdout),
          stderr: truncate(result.stderr), meaning: definition.meaning,
        });
      }
    }
    return { status: 'COMPLETED', probes, layout, marker, hostPreflight, smoke,
      codexExecutable: options.codexExe || null, codexSource: options.codexSource || 'UNKNOWN',
      testedCodexVersion: options.testedCodexVersion || null, activeCodexVersion: options.activeCodexVersion || null,
      versionMismatch: options.versionMismatch === true, permissionProfile, error: null };
  } catch (error) {
    return { status: 'ERROR', probes, layout, marker, hostPreflight, smoke,
      codexExecutable: options.codexExe || null, codexSource: options.codexSource || 'UNKNOWN',
      testedCodexVersion: options.testedCodexVersion || null, activeCodexVersion: options.activeCodexVersion || null,
      versionMismatch: options.versionMismatch === true, permissionProfile, error: error.stack || error.message };
  }
}

export function compactError(result) {
  const parts = [];
  if (result.error) parts.push(result.error.message || String(result.error));
  if (result.stderr) parts.push(String(result.stderr).trim());
  if (!parts.length && result.stdout) parts.push(String(result.stdout).trim());
  return parts.filter(Boolean).join('\n').slice(0, 4000) || `Command exited with status ${result.status}`;
}

export function truncate(value, max = 4000) {
  const text = String(value || '').trim();
  return text.length > max ? `${text.slice(0, max)}\n...[truncated]` : text;
}

export function buildRecommendations({ inventory, summary, rules = [], sandbox = null, execpolicyCoverage, assessmentMode = ASSESSMENT_MODES.GUIDED }) {
  const recommendations = [];
  const add = (code, severity, title, message, recommendation) => {
    recommendations.push({ code, severity, title, message, recommendation });
  };

  if (!inventory?.activeBundle?.complete) {
    add(
      'ACTIVE_CLI_BUNDLE_INCOMPLETE',
      RECOMMENDATION_SEVERITIES.ACTION_RECOMMENDED,
      'Active CLI bundle is incomplete',
      'The Codex CLI resolved through PATH is missing one or more Windows sandbox helper files, so this assessment did not validate that active CLI bundle.',
      'Update or reinstall Codex with the official installer, open a new non-administrator PowerShell session, and rerun the Canary against the active CLI.'
    );
  }

  if (sandbox?.versionMismatch === true && summary.boundary === 'PASS') {
    add(
      'ALTERNATIVE_BUNDLE_BOUNDARY_PASS',
      RECOMMENDATION_SEVERITIES.INFO,
      'Alternative bundle boundary passed',
      'A separate complete Codex bundle passed the tested sandbox boundary checks.',
      'Treat this as evidence for the tested alternative bundle only; it does not validate the active PATH CLI.'
    );
  }

  if (summary.activeCli?.boundaryStatus === 'PASS') {
    add(
      'ACTIVE_BUNDLE_BOUNDARY_PASS',
      RECOMMENDATION_SEVERITIES.INFO,
      'Active CLI boundary passed',
      'The active Codex CLI bundle passed all tested sandbox boundary checks.',
      'Keep this report with the tested Codex version and rerun the Canary after Codex, Windows sandbox, permission, or rule changes.'
    );
  }

  if (sandbox?.status === 'SETUP_FAILED' || inventory?.sandboxWindowsState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE_BUT_SETUP_FAILED) {
    add(
      'SANDBOX_SETUP_FAILED',
      RECOMMENDATION_SEVERITIES.ACTION_RECOMMENDED,
      'Sandbox runtime setup failed',
      'The sandbox command syntax exists, but the Windows sandbox runtime was not test-ready.',
      'Review the setup diagnostic, repair or reinstall Codex through the official installer if needed, then rerun the Canary.'
    );
  }

  const boundaryNotAssessedModes = new Set([
    ASSESSMENT_MODES.CONFIGURATION_ONLY,
    ASSESSMENT_MODES.EXECPOLICY_ONLY,
  ]);
  const boundaryAssessmentDeclined = summary.boundaryAssessmentDeclined === true;
  const boundaryNotAssessed = summary.boundary === 'NOT TESTED' && !sandbox && boundaryNotAssessedModes.has(assessmentMode);
  if (boundaryAssessmentDeclined) {
    add(
      'BOUNDARY_ASSESSMENT_DECLINED',
      RECOMMENDATION_SEVERITIES.INFO,
      'Sandbox boundary assessment declined',
      'The offered sandbox boundary assessment was explicitly declined by the user.',
      'Rerun the assessment and answer Y to the live-probe prompt when you want a sandbox boundary verdict.'
    );
  } else if (boundaryNotAssessed) {
    add(
      'BOUNDARY_NOT_ASSESSED_IN_THIS_MODE',
      RECOMMENDATION_SEVERITIES.INFO,
      'Sandbox boundary not assessed in this mode',
      'The sandbox boundary was not assessed because the selected mode does not run live probes.',
      'Run guided live probes from a normal non-administrator Windows session when you want a sandbox boundary assessment.'
    );
  } else if (summary.boundary === 'NOT TESTED' || summary.boundary === 'PARTIAL PASS' || summary.boundary === 'TEST ERROR') {
    add(
      'BOUNDARY_NOT_CONFIRMED',
      RECOMMENDATION_SEVERITIES.PROTECTION_NOT_CONFIRMED,
      'Sandbox boundary not confirmed',
      'The active sandbox boundary was intended or started, but no fully reliable boundary verdict was produced.',
      'Run the disposable sandbox probes from a normal non-administrator Windows session when the sandbox runtime is available.'
    );
  }

  if (summary.boundary === 'GAP') {
    add(
      'BOUNDARY_GAP',
      RECOMMENDATION_SEVERITIES.POTENTIAL_SECURITY_GAP,
      'Potential sandbox boundary gap',
      'A synthetic file outside the selected workspace was deleted during a sandbox probe.',
      'Stop relying on this configuration for filesystem isolation, save the report, and rerun after updating or reinstalling Codex.'
    );
  }

  if (execpolicyCoverage?.status === 'COMPLETED' && execpolicyCoverage.total > 0 && execpolicyCoverage.matched === 0) {
    add(
      'EXECPOLICY_NO_RESTRICTIVE_MATCHES',
      RECOMMENDATION_SEVERITIES.OPTIONAL_HARDENING,
      'No restrictive execpolicy matches',
      'None of the tested command forms matched a prompt or forbidden user-level execpolicy rule. This is additional rule coverage only, not the sandbox boundary result.',
      'Optionally review user-level execpolicy rules for common destructive command forms after separately confirming the sandbox boundary.'
    );
  }

  return recommendations;
}

export function summarizeAssessment(inventory, rules, sandbox, options = {}) {
  const assessmentMode = options.assessmentMode || ASSESSMENT_MODES.GUIDED;
  const boundaryAssessmentDeclined = options.boundaryAssessmentDeclined === true;
  const probes = sandbox?.probes || [];
  const outsideProbes = probes.filter((probe) => probe.location === 'outside');
  const boundaryGap = outsideProbes.some((probe) => probe.assessment === 'CRITICAL_GAP');
  const sandboxRunError = sandbox && ['SETUP_FAILED', 'HOST_PREFLIGHT_FAILED', 'ERROR'].includes(sandbox.status);
  const methods = [...new Set(probes.map((probe) => probe.method).filter(Boolean))];
  const methodResults = methods.map((method) => {
    const inside = probes.find((probe) => probe.method === method && probe.location === 'inside');
    const outside = probes.find((probe) => probe.method === method && probe.location === 'outside');
    return {
      method,
      pass: inside?.assessment === 'EXPECTED' && inside.observed === 'DELETED' && outside?.assessment === 'PASS',
      gap: outside?.assessment === 'CRITICAL_GAP',
      error: !inside || !outside || ['TEST_ERROR', 'ERROR', 'UNEXPECTED'].includes(inside.assessment) || ['TEST_ERROR', 'ERROR', 'UNEXPECTED'].includes(outside.assessment),
    };
  });
  const passedMethods = methodResults.filter((item) => item.pass).length;
  const allMethodsPass = methodResults.length > 0 && passedMethods === methodResults.length;
  const partialMethodsPass = passedMethods > 0 && !allMethodsPass && !boundaryGap;
  const probeError = methodResults.some((item) => item.error);
  const execpolicyRun = options.execpolicyRun ?? rules.length > 0;
  const ruleProtected = rules.filter((probe) => ['prompt', 'forbidden'].includes(probe.decision)).length;
  const execpolicyCoverage = execpolicyRun
    ? { status: 'COMPLETED', matched: ruleProtected, total: rules.length }
    : { status: 'NOT_RUN', matched: null, total: null };
  const riskWarnings = [...(inventory.config?.warnings || [])];
  const insideProbes = probes.filter((probe) => probe.location === 'inside');
  let workspaceDeletion = 'NOT TESTED';
  if (insideProbes.length && insideProbes.every((probe) => probe.assessment === 'EXPECTED' && probe.observed === 'DELETED')) workspaceDeletion = 'ALLOWED INSIDE WORKSPACE UNDER :WORKSPACE PERMISSION PROFILE';
  else if (insideProbes.some((probe) => probe.assessment === 'EXPECTED' && probe.observed === 'DELETED')) workspaceDeletion = 'PARTIAL – RUNTIME DIFFERENCES';
  else if (insideProbes.length) workspaceDeletion = 'CONTROL FAILED';
  let sandboxRuntime = boundaryAssessmentDeclined ? 'NOT RUN' : 'NOT TESTED';
  if (sandbox?.status === 'COMPLETED') sandboxRuntime = 'READY';
  else if (sandbox?.status === 'SETUP_FAILED') sandboxRuntime = /program not found|codex-windows-sandbox-setup\.exe/i.test(sandbox.error || '') ? 'FAILED – HELPER NOT RESOLVABLE' : 'FAILED';
  else if (sandbox?.status === 'HOST_PREFLIGHT_FAILED') sandboxRuntime = 'HOST PREFLIGHT FAILED';
  else if (sandbox?.status === 'ERROR') sandboxRuntime = 'TEST ERROR';
  const alternativeBundle = sandbox?.versionMismatch === true;
  let overall;
  let boundary;
  if (boundaryAssessmentDeclined) {
    overall = assessmentMode === ASSESSMENT_MODES.SANDBOX_ONLY_LIVE_PROBES_SKIPPED ? 'BOUNDARY ASSESSMENT DECLINED' : 'PARTIAL / LIVE PROBES DECLINED';
    boundary = 'NOT TESTED';
  } else if (boundaryGap) { overall = alternativeBundle ? 'ALTERNATIVE BUNDLE GAP DETECTED' : 'CRITICAL GAP DETECTED'; boundary = 'GAP'; }
  else if (allMethodsPass) { overall = alternativeBundle ? 'ALTERNATIVE BUNDLE BOUNDARY PASSED' : 'BOUNDARY TEST PASSED'; boundary = 'PASS'; }
  else if (partialMethodsPass) { overall = alternativeBundle ? 'ALTERNATIVE BUNDLE PARTIAL PASS' : 'BOUNDARY PARTIAL PASS'; boundary = 'PARTIAL PASS'; }
  else if (sandboxRunError || probeError) { overall = alternativeBundle ? 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE' : 'TEST ERROR / INCOMPLETE'; boundary = 'TEST ERROR'; }
  else { overall = 'PARTIAL / NOT FULLY TESTED'; boundary = 'NOT TESTED'; }
  const methodCoverage = methodResults.length ? `${passedMethods}/${methodResults.length}` : 'NOT RUN';
  const activeCliBoundary = sandbox?.codexSource === 'ACTIVE_CLI' ? boundary : 'NOT TESTED';
  const activeCli = {
    version: inventory.codexVersion || null,
    bundleStatus: inventory.activeBundle?.complete ? 'COMPLETE' : 'INCOMPLETE',
    boundaryStatus: activeCliBoundary,
  };
  const testedBundle = sandbox ? {
    source: sandbox.codexSource || 'UNKNOWN',
    version: sandbox.testedCodexVersion || inventory.codexVersion || null,
    bundleStatus: sandbox.codexSource === 'ACTIVE_CLI'
      ? (inventory.activeBundle?.complete ? 'COMPLETE' : 'INCOMPLETE')
      : 'COMPLETE',
    boundaryStatus: boundary,
    methodCoverage,
  } : null;
  const interpretation = [];
  const nextSteps = [];
  if (!inventory.activeBundle?.complete) {
    interpretation.push('The Codex CLI resolved through PATH is incomplete. Its sandbox boundary was not validated by this assessment.');
  } else if (activeCliBoundary === 'PASS') {
    interpretation.push('The active Codex CLI bundle passed the tested :workspace permission profile boundary checks.');
  }
  if (sandbox?.versionMismatch) {
    interpretation.push(`A separate complete bundle (${sandbox.testedCodexVersion || 'unknown version'}) was tested. Its result does not validate the active PATH CLI (${sandbox.activeCodexVersion || 'unknown version'}).`);
  }
  if (execpolicyCoverage.status === 'COMPLETED') {
    interpretation.push(`${ruleProtected} of ${rules.length} tested command forms matched restrictive user-level execpolicy rules. This is additional rule coverage, not the sandbox boundary result.`);
  }
  if (!inventory.activeBundle?.complete) {
    nextSteps.push('Update or reinstall the Codex CLI with the official installer so codex.exe and its Windows sandbox helper executables are installed together.');
    nextSteps.push('Open a new non-administrator PowerShell session and rerun the Canary against the active CLI.');
    nextSteps.push('Do not manually copy helper executables between different Codex versions.');
  } else if (boundary === 'TEST ERROR') {
    nextSteps.push('Review the sandbox diagnostics, correct the runtime setup problem, and rerun the disposable probes.');
  }
  const summary = {
    overall, boundary, sandboxRuntime, workspaceDeletion,
    methodCoverage,
    execpolicyCoverage,
    boundaryAssessmentDeclined,
    riskWarnings,
    activeCli,
    testedBundle,
    interpretation,
    nextSteps,
  };
  summary.recommendations = buildRecommendations({ inventory, summary, rules, sandbox, execpolicyCoverage, assessmentMode });
  return summary;
}


function buildSupportPathReplacements(report) {
  const i = report.inventory || {};
  const sandbox = report.sandbox || {};
  const candidates = [
    i.activeCodexPath,
    i.codexHome,
    i.config?.path,
    sandbox.codexExecutable,
    sandbox.layout?.runDir,
    sandbox.layout?.workspace,
    sandbox.layout?.outsideDir,
    ...(i.ruleFiles || []),
  ].filter(Boolean);
  const replacements = [];
  for (const candidate of candidates) {
    const value = String(candidate);
    replacements.push([value, '%LOCAL_PATH%']);
    const parent = path.dirname(value);
    if (parent && parent !== '.' && parent !== value) replacements.push([parent, '%LOCAL_PATH%']);
  }
  return replacements;
}

function sanitizeSupportText(value, env = process.env, extraReplacements = []) {
  let text = String(value ?? '');
  const replacements = [
    ...extraReplacements,
    [env.CODEX_HOME || '', '%CODEX_HOME%'],
    [env.LOCALAPPDATA || '', '%LOCAL_DATA%'],
    [env.APPDATA || '', '%ROAMING_DATA%'],
    [os.homedir(), '%USERPROFILE%'],
  ].filter(([from]) => from).sort((a, b) => b[0].length - a[0].length);
  for (const [from, to] of replacements) {
    text = replaceAllIgnoreCase(text, from, to);
    text = replaceAllIgnoreCase(text, from.replaceAll('\\', '/'), to);
  }
  text = text.replace(/\\{2,}/g, '\\');
  text = text.replace(/\b[A-Za-z]:\\Users\\[^\\/\r\n]+/gi, '%USERPROFILE%');
  text = text.replace(/\b[A-Za-z]:\/Users\/[^\/\r\n]+/gi, '%USERPROFILE%');
  const usernames = [env.CODEX_HOME, env.LOCALAPPDATA, env.APPDATA, os.homedir()]
    .filter(Boolean)
    .map((value) => String(value).match(/[\\/]Users[\\/]([^\\/]+)/i)?.[1])
    .filter(Boolean);
  for (const username of usernames) {
    text = replaceAllIgnoreCase(text, username, '[USER]');
  }
  return text;
}

export function buildSupportPayload(report, env = process.env) {
  const i = report.inventory;
  const supportPathReplacements = buildSupportPathReplacements(report);
  const cleanText = (value) => sanitizeSupportText(value, env, supportPathReplacements);
  return {
    schemaVersion: 1,
    generatedAt: report.generatedAt,
    tool: report.tool,
    assessmentMode: report.assessmentMode || ASSESSMENT_MODES.GUIDED,
    summary: report.summary,
    recommendations: report.summary?.recommendations || [],
    environment: {
      platform: i.platform,
      windowsRelease: i.release,
      nodeVersion: i.nodeVersion,
      nodeRuntimeSource: i.nodeRuntimeSource,
      nodeInPath: i.nodeInPath,
      npmInPath: i.npmInPath,
      elevated: i.elevated,
      codexInstalled: i.codexInstalled,
      activeCodexVersion: i.codexVersion,
      activeBundleComplete: Boolean(i.activeBundle?.complete),
      activeBundleMissing: i.activeBundle?.missing || [],
      matchingCompleteBundleCount: i.matchingCompleteBundles?.length || 0,
      newerCompleteBundles: (i.newerCompleteBundles || []).map((bundle) => ({
        version: bundle.version,
        sandboxState: bundle.sandboxState,
      })),
      userRuleFileCount: i.ruleFiles?.length || 0,
      sandboxCommandSyntax: i.sandboxWindowsState,
      sandboxRuntime: report.summary?.sandboxRuntime || 'NOT TESTED',
      selectedConfig: {
        sandboxMode: i.config?.sandboxMode ?? null,
        approvalPolicy: i.config?.approvalPolicy ?? null,
        defaultPermissions: i.config?.defaultPermissions ?? null,
        windowsSandbox: i.config?.windowsSandbox ?? null,
        networkAccess: i.config?.networkAccess ?? null,
        warnings: i.config?.warnings || [],
      },
    },
    execpolicy: report.execpolicy.map((probe) => ({
      id: probe.id,
      label: probe.label,
      status: probe.status,
      decision: probe.decision,
      error: probe.error ? cleanText(probe.error) : null,
    })),
    sandbox: report.sandbox ? {
      status: report.sandbox.status,
      source: report.sandbox.codexSource,
      testedCodexVersion: report.sandbox.testedCodexVersion,
      activeCodexVersion: report.sandbox.activeCodexVersion,
      versionMismatch: report.sandbox.versionMismatch,
      permissionProfile: report.sandbox.permissionProfile,
      hostPreflight: report.sandbox.hostPreflight,
      smoke: report.sandbox.smoke ? {
        passed: report.sandbox.smoke.passed,
        commandExitCode: report.sandbox.smoke.commandExitCode,
        setupFailure: report.sandbox.smoke.setupFailure,
        stderr: report.sandbox.smoke.passed ? null : cleanText(report.sandbox.smoke.stderr),
      } : null,
      probes: (report.sandbox.probes || []).map((probe) => ({
        id: probe.id,
        label: probe.label,
        method: probe.method,
        location: probe.location,
        expected: probe.expected,
        observed: probe.observed,
        assessment: probe.assessment,
        commandExitCode: probe.commandExitCode,
        denialEvidence: probe.denialEvidence,
        stderr: ['PASS', 'EXPECTED'].includes(probe.assessment) ? null : cleanText(probe.stderr),
      })),
      error: report.sandbox.error ? cleanText(report.sandbox.error) : null,
      cleanup: report.sandbox.cleanup ? cleanText(report.sandbox.cleanup) : null,
    } : null,
  };
}

export function renderSupportReport(report) {
  const lines = [];
  const add = (...values) => lines.push(...values);
  add('CODEX SAFETY CANARY – SHARE-SAFE SUPPORT REPORT', '=================================================', '');
  add(`Generated: ${report.generatedAt}`);
  add(`Tool:      ${report.tool.name} ${report.tool.version}`, '');
  add('RESULTS', '-------');
  add(`Assessment mode:          ${report.assessmentMode || ASSESSMENT_MODES.GUIDED}`);
  add(`Overall:                  ${report.summary.overall}`);
  add(`Active CLI bundle:        ${report.summary.activeCli?.bundleStatus || 'UNKNOWN'}`);
  add(`Active CLI boundary:      ${report.summary.activeCli?.boundaryStatus || 'NOT TESTED'}`);
  if (report.summary.testedBundle) {
    add(`Tested bundle source:     ${report.summary.testedBundle.source}`);
    add(`Tested bundle version:    ${report.summary.testedBundle.version || '(unknown)'}`);
    add(`Tested bundle boundary:   ${report.summary.testedBundle.boundaryStatus}`);
    add(`Runtime pair coverage:    ${report.summary.testedBundle.methodCoverage}`);
  }
  add(`Execpolicy rule coverage: ${formatExecpolicyCoverage(report.summary.execpolicyCoverage)} (additional rule coverage only)`, '');
  add('INTERPRETATION', '--------------');
  for (const line of report.summary.interpretation || []) add(`- ${line}`);
  add('');
  if (report.recommendations?.length) {
    add('DIAGNOSTIC RECOMMENDATIONS', '--------------------------');
    for (const item of report.recommendations) {
      add(`${item.severity} ${item.code}`);
      add(`  ${item.title}`);
      add(`  ${item.message}`);
      add(`  Recommendation: ${item.recommendation}`);
    }
    add('');
  }
  if (report.summary.nextSteps?.length) {
    add('NEXT STEPS', '----------');
    for (const line of report.summary.nextSteps) add(`- ${line}`);
    add('');
  }
  add('ENVIRONMENT', '-----------');
  add(`Windows release:          ${report.environment.windowsRelease}`);
  add(`Node.js:                  ${report.environment.nodeVersion} (${report.environment.nodeRuntimeSource})`);
  add(`Running elevated:         ${report.environment.elevated ? 'yes' : 'no'}`);
  add(`Active Codex version:     ${report.environment.activeCodexVersion || '(unavailable)'}`);
  add(`Active bundle complete:   ${report.environment.activeBundleComplete ? 'yes' : 'no'}`);
  if (report.environment.activeBundleMissing?.length) add(`Missing bundle files:     ${report.environment.activeBundleMissing.join(', ')}`);
  add(`User rule files:          ${report.environment.userRuleFileCount}`);
  add(`Sandbox command syntax:   ${report.environment.sandboxCommandSyntax || 'UNKNOWN'}`);
  add(`Sandbox runtime:          ${report.environment.sandboxRuntime || 'NOT TESTED'}`, '');
  add('EXECPOLICY', '----------');
  for (const probe of report.execpolicy || []) add(`${probe.label}: ${probe.decision ? probe.decision.toUpperCase() : probe.status}`);
  if (!report.execpolicy?.length) add('(not run)');
  add('');
  add('SANDBOX PROBES', '--------------');
  if (!report.sandbox) add('(not run)');
  else {
    add(`Run status: ${report.sandbox.status}`);
    for (const probe of report.sandbox.probes || []) {
      add(`${probe.label}: ${probe.assessment}`);
      add(`  Expected: ${probe.expected}; observed: ${probe.observed}; exit: ${probe.commandExitCode}`);
      if (probe.stderr) add(`  stderr: ${probe.stderr.replace(/\r?\n/g, ' | ')}`);
    }
  }
  add('', 'This report intentionally omits usernames, credential paths, executable paths, project paths, and raw configuration contents.', '');
  return `${lines.join('\n')}\n`;
}

export function writeReport({ inventory, rules = [], sandbox = null, appRoot = getAppRoot(), assessmentMode = ASSESSMENT_MODES.GUIDED, boundaryAssessmentDeclined = false }) {
  const reportsDir = ensureDir(path.join(appRoot, 'reports'));
  const id = `${nowId()}-${randomId()}`;
  const jsonPath = path.join(reportsDir, `${id}.json`);
  const txtPath = path.join(reportsDir, `${id}.txt`);
  const supportJsonPath = path.join(reportsDir, `${id}-support.json`);
  const supportTxtPath = path.join(reportsDir, `${id}-support.txt`);
  const execpolicyRun = rules.length > 0;
  const summary = summarizeAssessment(inventory, rules, sandbox, { assessmentMode, execpolicyRun, boundaryAssessmentDeclined });
  const payload = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    tool: { name: APP_NAME, version: APP_VERSION },
    assessmentMode,
    inventory,
    summary,
    execpolicy: rules,
    sandbox,
  };
  const supportPayload = buildSupportPayload(payload);
  fs.writeFileSync(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.writeFileSync(txtPath, renderTextReport(payload), 'utf8');
  fs.writeFileSync(supportJsonPath, `${JSON.stringify(supportPayload, null, 2)}\n`, 'utf8');
  fs.writeFileSync(supportTxtPath, renderSupportReport(supportPayload), 'utf8');
  fs.writeFileSync(path.join(reportsDir, 'latest.json'), `${JSON.stringify({ jsonPath, txtPath, supportJsonPath, supportTxtPath }, null, 2)}\n`, 'utf8');
  return { jsonPath, txtPath, supportJsonPath, supportTxtPath, payload, supportPayload };
}

export function renderTextReport(report) {
  const lines = [];
  const add = (...values) => lines.push(...values);
  add('CODEX SAFETY CANARY – WINDOWS', '================================', '');
  add(`Generated: ${report.generatedAt}`);
  add(`Tool:      ${report.tool.name} ${report.tool.version}`, '');
  add('SUMMARY', '-------');
  add(`Assessment mode:         ${report.assessmentMode || ASSESSMENT_MODES.GUIDED}`);
  add(`Overall:                 ${report.summary.overall}`);
  add(`Sandbox command syntax:  ${report.inventory.sandboxWindowsState || 'UNKNOWN'}`);
  add(`Sandbox runtime:         ${report.summary.sandboxRuntime || 'NOT TESTED'}`);
  add(`Sandbox boundary:        ${report.summary.boundary}`);
  add(`Workspace deletion:      ${report.summary.workspaceDeletion}`);
  add(`Runtime pair coverage:   ${report.summary.methodCoverage || 'NOT RUN'}`);
  add(`Execpolicy coverage:     ${formatExecpolicyCoverage(report.summary.execpolicyCoverage)} (additional user-rule coverage only)`, '');
  add('ACTIVE CLI', '----------');
  add(`Version:                 ${report.summary.activeCli?.version || '(unavailable)'}`);
  add(`Bundle:                  ${report.summary.activeCli?.bundleStatus || 'UNKNOWN'}`);
  add(`Boundary status:         ${report.summary.activeCli?.boundaryStatus || 'NOT TESTED'}`, '');
  add('TESTED BUNDLE', '-------------');
  if (!report.summary.testedBundle) add('(not tested)', '');
  else {
    add(`Source:                  ${report.summary.testedBundle.source}`);
    add(`Version:                 ${report.summary.testedBundle.version || '(unavailable)'}`);
    add(`Bundle:                  ${report.summary.testedBundle.bundleStatus}`);
    add(`Boundary status:         ${report.summary.testedBundle.boundaryStatus}`);
    add(`Runtime pair coverage:   ${report.summary.testedBundle.methodCoverage}`, '');
  }
  if (report.summary.riskWarnings.length) {
    add('Configuration warnings:');
    for (const warning of report.summary.riskWarnings) add(`- ${warning}`);
    add('');
  }
  const i = report.inventory;
  add('ENVIRONMENT', '-----------');
  add(`Windows release:         ${i.release}`);
  add(`Node.js:                 ${i.nodeVersion} (${i.nodeRuntimeSource || 'unknown source'})`);
  add(`node in PATH:            ${i.nodeInPath ? 'yes' : 'no'}`);
  add(`npm in PATH:             ${i.npmInPath ? 'yes' : 'no'}`);
  add(`Running elevated:        ${i.elevated ? 'yes – live tests should be rerun non-admin' : 'no'}`);
  add(`Codex installed:         ${i.codexInstalled ? 'yes' : 'no'}`);
  add(`Codex version:           ${i.codexVersion || '(unavailable)'}`);
  add(`Active Codex executable: ${i.activeCodexPath || '(not resolved)'}`);
  add(`Active CLI bundle:       ${i.activeBundle?.complete ? 'complete' : 'incomplete'}`);
  if (i.activeBundle?.missing?.length) add(`Missing beside active CLI: ${i.activeBundle.missing.join(', ')}`);
  add(`Matching complete bundle: ${i.matchingCompleteBundles?.[0]?.executablePath || '(none found)'}`);
  add(`Newer complete bundle:    ${i.newerCompleteBundles?.[0]?.executablePath || '(none found)'}`);
  if (i.newerCompleteBundles?.[0]) add(`Newer bundle version:     ${i.newerCompleteBundles[0].version} (${i.newerCompleteBundles[0].sandboxState})`);
  add(`CODEX_HOME:              ${i.codexHome}`);
  add(`config.toml:             ${i.config.exists ? i.config.path : '(not found)'}`);
  add(`auth.json present:       ${i.authFilePresent ? 'yes (content was not read)' : 'no'}`);
  add(`User rule files:         ${i.ruleFiles.length}`);
  add(`Sandbox command syntax:  ${i.sandboxWindowsState || (i.sandboxWindowsAvailable ? 'AVAILABLE' : 'UNKNOWN')}`);
  if (i.sandboxHelpError) add(`Sandbox diagnostic:      ${String(i.sandboxHelpError).replace(/\r?\n/g, ' | ')}`);
  add('');
  add('SAFE CONFIGURATION SUMMARY', '--------------------------');
  add(`sandbox_mode:            ${i.config.sandboxMode || '(not explicitly set)'}`);
  add(`approval_policy:         ${i.config.approvalPolicy || '(not explicitly set)'}`);
  add(`default_permissions:     ${i.config.defaultPermissions || '(not explicitly set)'}`);
  add(`windows.sandbox:         ${i.config.windowsSandbox || '(not explicitly set)'}`);
  add(`workspace network:       ${i.config.networkAccess == null ? '(not explicitly set)' : i.config.networkAccess}`, '');

  add('EXECPOLICY RULE COVERAGE', '------------------------');
  if (!report.execpolicy.length) add('(not run)', '');
  for (const probe of report.execpolicy) {
    add(`${probe.label}: ${probe.decision ? probe.decision.toUpperCase() : probe.status}`);
    add(`  Command: ${probe.command.join(' ')}`);
    if (probe.error) add(`  Note: ${probe.error}`);
  }
  add('');

  add('WINDOWS SANDBOX PROBES', '-----------------------');
  if (!report.sandbox) {
    add('(not run)', '');
  } else {
    add(`Run status: ${report.sandbox.status}`);
    add(`Codex executable: ${report.sandbox.codexExecutable || '(active PATH command)'}`);
    add(`Executable source: ${report.sandbox.codexSource || 'UNKNOWN'}`);
    add(`Tested Codex version: ${report.sandbox.testedCodexVersion || '(unavailable)'}`);
    if (report.sandbox.versionMismatch) {
      add(`Active Codex version: ${report.sandbox.activeCodexVersion || '(unavailable)'}`);
      add('Scope of result: alternative bundle only; the active PATH CLI remains untested.');
    }
    add(`Permission profile:       ${report.sandbox.permissionProfile || '(not recorded)'}`);
    if (report.sandbox.hostPreflight) add(`Host deletion preflight: ${report.sandbox.hostPreflight.passed ? 'PASS' : 'FAIL'}`);
    if (report.sandbox.smoke) add(`Runtime smoke test: ${report.sandbox.smoke.passed ? 'PASS' : 'FAIL'}`);
    if (report.sandbox.error) add(`Error: ${report.sandbox.error}`);
    for (const probe of report.sandbox.probes || []) {
      add(`${probe.label}: ${probe.assessment}`);
      add(`  Expected: ${probe.expected}; observed: ${probe.observed}; command exit: ${probe.commandExitCode}`);
      add(`  Access-denial evidence: ${probe.denialEvidence ? 'yes' : 'no'}`);
      add(`  Meaning: ${probe.meaning}`);
      if (probe.stderr) add(`  stderr: ${probe.stderr.replace(/\r?\n/g, ' | ')}`);
    }
    add('');
  }

  add('PLAIN-LANGUAGE INTERPRETATION', '-----------------------------');
  for (const line of report.summary.interpretation || []) add(`- ${line}`);
  if (report.summary.recommendations?.length) {
    add('', 'DIAGNOSTIC RECOMMENDATIONS', '--------------------------');
    for (const item of report.summary.recommendations) {
      add(`${item.severity} ${item.code}`);
      add(`  ${item.title}`);
      add(`  ${item.message}`);
      add(`  Recommendation: ${item.recommendation}`);
    }
  }
  add('', '- A boundary PASS requires successful inside-workspace deletion controls under the :workspace permission profile and access-denied evidence for every retained outside file.');
  add('- Retention caused by malformed commands or unrelated failures is reported as TEST_ERROR, not sandbox protection.');
  add('- Execpolicy rules do not make files inside a writable workspace undeletable; their x/y count is additional rule coverage only.');
  add('- The Canary is a diagnostic, not a security certification or a backup system.', '');
  if (report.summary.nextSteps?.length) {
    add('RECOMMENDED NEXT STEPS', '----------------------');
    for (const line of report.summary.nextSteps) add(`- ${line}`);
    add('');
  }
  return `${lines.join('\n')}\n`;
}

export function getLatestReport(appRoot = getAppRoot()) {
  const latest = path.join(appRoot, 'reports', 'latest.json');
  if (!fs.existsSync(latest)) return null;
  try {
    return JSON.parse(fs.readFileSync(latest, 'utf8'));
  } catch {
    return null;
  }
}
