import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const APP_NAME = 'Codex Safety Canary';
export const APP_DIR_NAME = 'CodexSafetyCanary';
export const APP_VERSION = '0.1.0-alpha.11';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const CODEX_WRAPPER = path.resolve(MODULE_DIR, '..', 'tools', 'invoke-codex.ps1');
const CODEX_WRAPPER_EXECUTION_MARKER = '__CODEX_SAFETY_CANARY_EXECUTABLE_STARTED__';

function consumeCodexWrapperExecutionMarker(stderrValue) {
  const stderr = String(stderrValue || '');
  const retained = [];
  let cursor = 0;
  let codexProcessStarted = false;
  while (cursor < stderr.length) {
    const newline = stderr.indexOf('\n', cursor);
    const end = newline === -1 ? stderr.length : newline;
    const rawLine = stderr.slice(cursor, end);
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (line === CODEX_WRAPPER_EXECUTION_MARKER) codexProcessStarted = true;
    else retained.push(stderr.slice(cursor, newline === -1 ? stderr.length : newline + 1));
    if (newline === -1) break;
    cursor = newline + 1;
  }
  return { stderr: retained.join(''), codexProcessStarted };
}

export const WINDOWS_SANDBOX_FEATURE_STATES = Object.freeze({
  AVAILABLE: 'AVAILABLE',
  AVAILABLE_BUT_SETUP_FAILED: 'AVAILABLE_BUT_SETUP_FAILED',
  UNSUPPORTED: 'UNSUPPORTED',
  DETECTION_ERROR: 'DETECTION_ERROR',
});

export const SANDBOX_COMMAND_SYNTAXES = Object.freeze({
  GENERIC_PERMISSION_PROFILE: 'GENERIC_PERMISSION_PROFILE',
  UNKNOWN: 'UNKNOWN',
});

export const EXECPOLICY_BINDING_STATES = Object.freeze({
  CONFIRMED: 'CONFIRMED',
  NOT_PROVEN: 'NOT_PROVEN',
  NO_MATCH: 'NO_MATCH',
  UNKNOWN_SCHEMA: 'UNKNOWN_SCHEMA',
});

export const EXECPOLICY_EXECUTION_EVIDENCE_BOUNDARY =
  'codex execpolicy check does not execute the command; a policy match or observed host resolution does not prove the path used by a later execution.';

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

export const DIAGNOSTIC_TARGETS = Object.freeze({
  ACTIVE_CLI: 'ACTIVE_CLI',
  SELECTED_ALTERNATIVE: 'SELECTED_ALTERNATIVE',
  TESTED_BUNDLE: 'TESTED_BUNDLE',
});

export const CODEX_BUNDLE_REQUIRED_FILES = Object.freeze([
  'codex-windows-sandbox-setup.exe',
  'codex-command-runner.exe',
]);

export const CODEX_BUNDLE_OPTIONAL_FILES = Object.freeze([
  'codex-code-mode-host.exe',
]);

export const STANDALONE_RESOURCE_FILES = Object.freeze({
  setupHelper: 'codex-windows-sandbox-setup.exe',
  commandRunner: 'codex-command-runner.exe',
  ripgrep: 'rg.exe',
});

export const CODEX_DOCTOR_STATES = Object.freeze({
  NOT_RUN: 'NOT_RUN',
  UNAVAILABLE: 'UNAVAILABLE',
  COMPLETED: 'COMPLETED',
  ERROR: 'ERROR',
});

export const CODEX_DOCTOR_SKIP_REASON =
  'Skipped by Canary policy; no Doctor process was started and no Doctor-derived diagnostics were collected.';

export const RESOURCE_LAYOUT_STATES = Object.freeze({
  COMPLETE: 'COMPLETE',
  PARTIAL: 'PARTIAL',
  MISSING: 'MISSING',
});

export const HELPER_RESOLUTION_STATES = Object.freeze({
  NOT_TESTED: 'NOT_TESTED',
  CONFIRMED: 'CONFIRMED',
  FAILED: 'FAILED',
});

export const RUNTIME_STARTUP_STATES = Object.freeze({
  NOT_TESTED: 'NOT_TESTED',
  READY: 'READY',
  FAILED: 'FAILED',
});

export const CLEANUP_STATES = Object.freeze({
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  NOT_RUN: 'NOT_RUN',
  INVALID: 'INVALID',
});

export const SHARE_SAFE_SHARING_NOTICE = Object.freeze({
  redactedCategories: Object.freeze([
    'local usernames',
    'absolute local paths',
    'credential paths',
    'raw configuration contents',
  ]),
  retainedCategories: Object.freeze([
    'diagnostic version information',
    'installation information',
    'runtime information',
    'security-status information',
  ]),
  reviewBeforePublicSharing: true,
});

function formatEnglishList(items) {
  if (items.length < 2) return items[0] || '';
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, and ${items.at(-1)}`;
}

export function formatShareSafeSharingNotice(notice = SHARE_SAFE_SHARING_NOTICE) {
  const redacted = formatEnglishList(notice.redactedCategories || []);
  const retained = formatEnglishList(notice.retainedCategories || []);
  const review = notice.reviewBeforePublicSharing ? ' Review it before public sharing.' : '';
  return `This support report removes ${redacted}. It retains ${retained}.${review}`;
}

export function createCleanupResult(status, message = null) {
  if (status === CLEANUP_STATES.COMPLETED) {
    return { status, attempted: true, completed: true, errorPresent: false, message };
  }
  if (status === CLEANUP_STATES.FAILED) {
    return { status, attempted: true, completed: false, errorPresent: true, message };
  }
  if (status === CLEANUP_STATES.NOT_RUN) {
    return { status, attempted: false, completed: false, errorPresent: false, message: null };
  }
  throw new Error(`Unsupported cleanup status: ${status}`);
}

export function normalizeCleanupResult(cleanup) {
  if (!cleanup || typeof cleanup !== 'object' || Array.isArray(cleanup)) {
    return { ...createCleanupResult(CLEANUP_STATES.NOT_RUN), valid: false };
  }
  const attempted = cleanup.attempted === true;
  const completed = cleanup.completed === true;
  const errorPresent = cleanup.errorPresent === true;
  const message = typeof cleanup.message === 'string' ? cleanup.message : null;
  const validCompleted = cleanup.status === CLEANUP_STATES.COMPLETED && attempted && completed && !errorPresent;
  const validFailed = cleanup.status === CLEANUP_STATES.FAILED && attempted && !completed && errorPresent;
  const validNotRun = cleanup.status === CLEANUP_STATES.NOT_RUN && !attempted && !completed && !errorPresent;
  if (validCompleted || validFailed || validNotRun) {
    return { status: cleanup.status, attempted, completed, errorPresent, message, valid: true };
  }
  return { status: CLEANUP_STATES.INVALID, attempted, completed, errorPresent, message, valid: false };
}

const EXPECTED_BOUNDARY_METHODS = Object.freeze(['powershell', 'cmd', 'node']);

export function isAlternativeExecutable(sandbox) {
  return Boolean(sandbox && sandbox.codexSource !== 'ACTIVE_CLI');
}

function sandboxProcessWasStarted(sandbox) {
  const probes = sandbox?.probes || [];
  return sandbox?.codexProcessStarted === true
    || sandbox?.smoke?.codexProcessStarted === true
    || (sandbox?.codexProcessStarted == null && Boolean(sandbox?.smoke || probes.length || sandbox?.runtimeEvidence));
}

function sandboxProcessStartIsConfirmed(sandbox) {
  return sandbox?.codexProcessStarted === true && sandbox?.smoke?.codexProcessStarted === true;
}

export function describeAlternativeExecutableScope({ versionMismatch = false, testedVersion = null, activeVersion = null } = {}) {
  if (versionMismatch) {
    return `A separate executable (${testedVersion || 'unknown version'}) was tested. Its result applies only to that executable and does not validate the active PATH CLI (${activeVersion || 'unknown version'}).`;
  }
  return 'A separate executable with the same Codex version was tested. Its result applies only to that executable and does not validate the active PATH CLI.';
}

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
  if (fs.existsSync(resolved)) throw new Error(`Disposable run folder still exists after cleanup: ${resolved}`);
}

export function listRuleFiles(codexHome) {
  const rulesDir = path.join(codexHome, 'rules');
  if (!fs.existsSync(rulesDir)) return [];
  return fs.readdirSync(rulesDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.rules'))
    .map((entry) => path.join(rulesDir, entry.name))
    .sort((a, b) => a.localeCompare(b));
}


function firstCommandLookupPath(output) {
  return String(output || '')
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .split('\n')
    .map((line) => line.trim())
    .find(Boolean) || null;
}

export function findCommandPath(command, options = {}) {
  const spawnSyncImpl = options.spawnSyncImpl || spawnSync;
  const platform = options.platform || process.platform;
  const lookup = platform === 'win32' ? 'where.exe' : 'which';
  const result = spawnSyncImpl(lookup, [command], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10_000,
  });
  if (result.status === 0) return firstCommandLookupPath(result.stdout);
  if (platform !== 'win32') return null;

  const powershellScript = [
    "$name = [Environment]::GetEnvironmentVariable('CANARY_COMMAND_LOOKUP', 'Process')",
    '$resolved = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue |',
    '  Select-Object -First 1 -ExpandProperty Source',
    'if ($resolved) { [Console]::Out.Write($resolved) }',
  ].join('\n');
  const fallback = spawnSyncImpl('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', powershellScript,
  ], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10_000,
    env: { ...process.env, CANARY_COMMAND_LOOKUP: String(command) },
  });
  return fallback.status === 0 ? firstCommandLookupPath(fallback.stdout) : null;
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
  const platform = options.platform || process.platform;
  const spawn = options.spawnSync || spawnSync;
  if (platform === 'win32') {
    const result = spawn('powershell.exe', [
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
    const markerResult = consumeCodexWrapperExecutionMarker(result.stderr);
    return {
      ...result,
      stderr: markerResult.stderr,
      codexProcessStarted: markerResult.codexProcessStarted,
    };
  }
  const result = spawn('codex', args, {
    cwd,
    timeout,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { ...result, codexProcessStarted: !result.error && result.status != null };
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

function filePresent(filePath) {
  return Boolean(filePath && fs.existsSync(filePath));
}

function normalizeFilesystemPath(value, platform = process.platform) {
  if (platform !== 'win32') return path.resolve(String(value));
  let normalized = String(value).replaceAll('/', '\\');
  const lower = normalized.toLowerCase();
  const namespaceUncPrefix = '\\\\?\\unc\\';
  const namespacePrefix = '\\\\?\\';
  if (lower.startsWith(namespaceUncPrefix)) {
    normalized = `\\\\${normalized.slice(namespaceUncPrefix.length)}`;
  } else if (lower.startsWith(namespacePrefix)) {
    normalized = normalized.slice(namespacePrefix.length);
  }
  return path.win32.normalize(normalized);
}

export function normalizeDiscoveryPathForComparison(value, platform = process.platform) {
  const normalized = normalizeFilesystemPath(value, platform);
  const absolutePath = platform === 'win32'
    ? (path.win32.isAbsolute(normalized) ? normalized : path.win32.resolve(normalized))
    : path.resolve(normalized);
  const comparisonPath = normalizeFilesystemPath(absolutePath, platform);
  return platform === 'win32' ? comparisonPath.toLowerCase() : comparisonPath;
}

function pathKey(filePath) {
  return normalizeDiscoveryPathForComparison(filePath);
}

function usableRealPath(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function statObjectIdentity(filePath) {
  try {
    const stat = fs.statSync(filePath, { bigint: true });
    const dev = typeof stat.dev === 'bigint' ? stat.dev : BigInt(stat.dev);
    const ino = typeof stat.ino === 'bigint' ? stat.ino : BigInt(stat.ino);
    if (dev < 0n || ino <= 0n) return null;
    return {
      key: `fs:${dev}:${ino}`,
      dev: String(dev),
      ino: String(ino),
    };
  } catch {
    return null;
  }
}

function findNearestLink(filePath) {
  let cursor = path.resolve(filePath);
  const suffix = [];
  while (true) {
    try {
      if (fs.lstatSync(cursor).isSymbolicLink()) {
        const rawTarget = fs.readlinkSync(cursor);
        return {
          target: path.resolve(path.dirname(cursor), rawTarget),
          suffix,
        };
      }
    } catch {}
    const parent = path.dirname(cursor);
    if (parent === cursor) return null;
    suffix.unshift(path.basename(cursor));
    cursor = parent;
  }
}

function resolveExplicitLinkTarget(filePath) {
  let candidate = path.resolve(filePath);
  let linkFound = false;
  for (let hop = 0; hop < 32; hop += 1) {
    const link = findNearestLink(candidate);
    if (!link) return { linkFound, linkTarget: linkFound ? candidate : null };
    candidate = path.resolve(link.target, ...link.suffix);
    linkFound = true;
  }
  return { linkFound, linkTarget: null };
}

export function resolveFilesystemIdentity(filePath, options = {}) {
  if (!filePath) return null;
  const resolveObjectIdentity = options.statObjectIdentity || statObjectIdentity;
  const resolveNativeRealPath = options.realpathNative || fs.realpathSync.native;
  const resolveRealPath = options.realpath || fs.realpathSync;
  const absolutePath = path.resolve(filePath);
  const objectIdentity = resolveObjectIdentity(absolutePath);
  const explicitLink = resolveExplicitLinkTarget(absolutePath);
  const linkTarget = explicitLink.linkTarget;
  const linkType = explicitLink.linkFound ? 'SYMLINK_OR_JUNCTION' : 'NONE';

  let resolvedPath = null;
  let resolutionMethod = 'path-fallback';
  for (const candidate of linkTarget ? [linkTarget, absolutePath] : [absolutePath]) {
    try {
      const nativeResult = resolveNativeRealPath(candidate);
      if (usableRealPath(nativeResult)) {
        resolvedPath = nativeResult;
        resolutionMethod = 'realpath-native';
        break;
      }
    } catch {}
    try {
      const fallbackResult = resolveRealPath(candidate);
      if (usableRealPath(fallbackResult)) {
        resolvedPath = fallbackResult;
        resolutionMethod = 'realpath';
        break;
      }
    } catch {}
  }

  const normalizedPath = normalizeFilesystemPath(resolvedPath || absolutePath);
  const identityKeys = [
    objectIdentity?.key || null,
    linkTarget ? resolveObjectIdentity(linkTarget)?.key || null : null,
    resolvedPath ? resolveObjectIdentity(resolvedPath)?.key || null : null,
  ].filter(Boolean);
  const conflict = new Set(identityKeys).size > 1;
  const unresolvedLink = explicitLink.linkFound && (!linkTarget || !objectIdentity);
  const proven = !conflict && !unresolvedLink && Boolean(objectIdentity);
  return {
    absolutePath,
    linkType,
    linkTarget: linkTarget ? normalizeFilesystemPath(linkTarget) : null,
    resolvedPath: normalizedPath,
    resolutionMethod,
    method: objectIdentity ? 'stat' : resolutionMethod,
    objectIdentity,
    conflict,
    unresolvedLink,
    proven,
    key: conflict
      ? `conflict:${normalizeDiscoveryPathForComparison(absolutePath)}`
      : (objectIdentity?.key || (process.platform === 'win32' ? normalizedPath.toLowerCase() : normalizedPath)),
  };
}

export function canonicalExistingPathKey(filePath) {
  return resolveFilesystemIdentity(filePath)?.key || null;
}

function executableObjectIdentityKey(filePath) {
  return resolveFilesystemIdentity(filePath)?.objectIdentity?.key || null;
}

export function validateSelectedExecutableBinding(binding, executablePath, options = {}) {
  if (!binding || !executablePath || !binding.selectedExecutablePath || !binding.expectedFilesystemIdentityKey) {
    return { valid: false, code: 'EXECUTABLE_IDENTITY_MISMATCH' };
  }
  const currentIdentity = (options.resolveFilesystemIdentity || resolveFilesystemIdentity)(executablePath);
  const selectedPathMatches = pathKey(binding.selectedExecutablePath) === pathKey(executablePath);
  const valid = Boolean(
    selectedPathMatches
    && currentIdentity
    && currentIdentity.proven === true
    && currentIdentity.objectIdentity?.key
    && currentIdentity.key === binding.expectedFilesystemIdentityKey
  );
  return { valid, code: valid ? null : 'EXECUTABLE_IDENTITY_MISMATCH' };
}

function createStandaloneResourceBinding(executablePath, standalonePackage) {
  if (!executablePath || !standalonePackage?.executablePath) return null;
  const selectedExecutableIdentity = executableObjectIdentityKey(executablePath);
  const canonicalExecutableIdentity = executableObjectIdentityKey(standalonePackage.executablePath);
  if (!selectedExecutableIdentity || selectedExecutableIdentity !== canonicalExecutableIdentity) return null;
  return {
    selectedExecutablePath: path.resolve(executablePath),
    canonicalExecutablePath: path.resolve(standalonePackage.executablePath),
    expectedObjectIdentity: selectedExecutableIdentity,
  };
}

export function validateStandaloneResourceBinding(binding, executablePath) {
  if (!binding || !executablePath || !binding.selectedExecutablePath || !binding.canonicalExecutablePath || !binding.expectedObjectIdentity) {
    return { valid: false, code: 'EXECUTABLE_IDENTITY_MISMATCH' };
  }
  const selectedExecutableIdentity = executableObjectIdentityKey(executablePath);
  const plannedExecutableIdentity = executableObjectIdentityKey(binding.selectedExecutablePath);
  const canonicalExecutableIdentity = executableObjectIdentityKey(binding.canonicalExecutablePath);
  const valid = Boolean(
    selectedExecutableIdentity
    && selectedExecutableIdentity === binding.expectedObjectIdentity
    && plannedExecutableIdentity === binding.expectedObjectIdentity
    && canonicalExecutableIdentity === binding.expectedObjectIdentity
  );
  return { valid, code: valid ? null : 'EXECUTABLE_IDENTITY_MISMATCH' };
}

function realPathKey(filePath) {
  return canonicalExistingPathKey(filePath) || pathKey(filePath);
}

export function summarizeExecutableBundles(bundles = []) {
  const executablesByRealPath = new Map();
  const discoveredPaths = new Map();
  for (const bundle of bundles) {
    if (!bundle?.executablePath) continue;
    const executablePath = path.resolve(bundle.executablePath);
    const visiblePaths = [...new Set([
      executablePath,
      ...(Array.isArray(bundle.discoveredPaths) ? bundle.discoveredPaths.map((value) => path.resolve(value)) : []),
    ])];
    for (const visiblePath of visiblePaths) {
      const visiblePathKey = pathKey(visiblePath);
      if (!discoveredPaths.has(visiblePathKey)) discoveredPaths.set(visiblePathKey, visiblePath);
    }
    const key = realPathKey(executablePath);
    const existing = executablesByRealPath.get(key);
    if (existing) {
      for (const visiblePath of visiblePaths) {
        const visiblePathKey = pathKey(visiblePath);
        if (!existing.discoveredPaths.some((value) => pathKey(value) === visiblePathKey)) {
          existing.discoveredPaths.push(visiblePath);
        }
      }
      continue;
    }
    executablesByRealPath.set(key, {
      realPathKey: key,
      representative: bundle,
      discoveredPaths: visiblePaths,
    });
  }
  const logicalExecutables = [...executablesByRealPath.values()];
  const discoveredPathCount = discoveredPaths.size;
  return {
    logicalExecutableCount: logicalExecutables.length,
    discoveredPathCount,
    aliasPathCount: Math.max(0, discoveredPathCount - logicalExecutables.length),
    logicalExecutables,
    discoveredPaths: [...discoveredPaths.values()],
  };
}

function buildPublishedBundleStatistics(inventory) {
  const publish = (bundles) => {
    const statistics = summarizeExecutableBundles(bundles);
    return {
      logicalExecutableCount: statistics.logicalExecutableCount,
      discoveredPathCount: statistics.discoveredPathCount,
      aliasPathCount: statistics.aliasPathCount,
    };
  };
  return {
    matching: publish(inventory?.matchingCompleteBundles || []),
    newer: publish(inventory?.newerCompleteBundles || []),
  };
}

export function parseStandaloneReleaseVersion(name) {
  const text = String(name || '');
  const match = text.match(/^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)(?:-(?:x86_64|aarch64|i686)-|$)/);
  return match ? match[1] : null;
}

function inspectStandaloneDirectory(releaseDir, source = 'release') {
  const identity = resolveFilesystemIdentity(releaseDir);
  const resolved = identity?.resolvedPath || path.resolve(releaseDir);
  const binDir = path.join(resolved, 'bin');
  const codexResourcesDir = path.join(resolved, 'codex-resources');
  const codexPathDir = path.join(resolved, 'codex-path');
  const files = {
    executable: path.join(binDir, 'codex.exe'),
    setupHelper: path.join(codexResourcesDir, STANDALONE_RESOURCE_FILES.setupHelper),
    commandRunner: path.join(codexResourcesDir, STANDALONE_RESOURCE_FILES.commandRunner),
    ripgrep: path.join(codexPathDir, STANDALONE_RESOURCE_FILES.ripgrep),
  };
  const exists = Object.fromEntries(Object.entries(files).map(([key, value]) => [key, filePresent(value)]));
  const requiredResourcesMissing = [
    exists.setupHelper ? null : STANDALONE_RESOURCE_FILES.setupHelper,
    exists.commandRunner ? null : STANDALONE_RESOURCE_FILES.commandRunner,
  ].filter(Boolean);
  const sources = [source];
  const resourceLayout = !fs.existsSync(codexResourcesDir) && !filePresent(files.executable)
    ? RESOURCE_LAYOUT_STATES.MISSING
    : (filePresent(files.executable) && requiredResourcesMissing.length === 0 ? RESOURCE_LAYOUT_STATES.COMPLETE : RESOURCE_LAYOUT_STATES.PARTIAL);
  return {
    installType: 'standalone',
    source,
    sources,
    aliases: [],
    releaseDir: resolved,
    releaseName: path.basename(resolved),
    releaseVersion: parseStandaloneReleaseVersion(path.basename(resolved)),
    binDir,
    codexResourcesDir,
    codexPathDir,
    executablePath: files.executable,
    files,
    exists,
    resourcesFound: fs.existsSync(codexResourcesDir),
    codexPathFound: fs.existsSync(codexPathDir),
    requiredResourcesMissing,
    requiredResourcesPresent: requiredResourcesMissing.length === 0,
    resourceLayout,
    optionalResourcesMissing: exists.ripgrep ? [] : [STANDALONE_RESOURCE_FILES.ripgrep],
  };
}

function standaloneSourceRank(source) {
  if (source === 'current') return 0;
  if (source === 'release') return 1;
  return 2;
}

function compareStandaloneDiscoveries(left, right) {
  const sourceOrder = standaloneSourceRank(left.source) - standaloneSourceRank(right.source);
  if (sourceOrder !== 0) return sourceOrder;
  const normalizedOrder = left.normalizedDiscoveryPath.localeCompare(right.normalizedDiscoveryPath);
  if (normalizedOrder !== 0) return normalizedOrder;
  return left.discoveryPath.localeCompare(right.discoveryPath);
}

function packageAtRepresentativeReleasePath(standalonePackage, releaseDir) {
  const representativeReleaseDir = path.resolve(releaseDir);
  const binDir = path.join(representativeReleaseDir, 'bin');
  const codexResourcesDir = path.join(representativeReleaseDir, 'codex-resources');
  const codexPathDir = path.join(representativeReleaseDir, 'codex-path');
  const files = {
    executable: path.join(binDir, 'codex.exe'),
    setupHelper: path.join(codexResourcesDir, STANDALONE_RESOURCE_FILES.setupHelper),
    commandRunner: path.join(codexResourcesDir, STANDALONE_RESOURCE_FILES.commandRunner),
    ripgrep: path.join(codexPathDir, STANDALONE_RESOURCE_FILES.ripgrep),
  };
  return {
    ...standalonePackage,
    releaseDir: representativeReleaseDir,
    releaseName: path.basename(representativeReleaseDir),
    releaseVersion: parseStandaloneReleaseVersion(path.basename(representativeReleaseDir)),
    binDir,
    codexResourcesDir,
    codexPathDir,
    executablePath: files.executable,
    files,
  };
}

export function deduplicateStandalonePackageCandidates(candidates = []) {
  const packagesByIdentity = new Map();
  for (const candidate of candidates) {
    const inspected = inspectStandaloneDirectory(candidate.dir, candidate.source);
    if (!filePresent(inspected.executablePath) && !inspected.resourcesFound && !inspected.codexPathFound) continue;
    const discoveryPath = path.resolve(candidate.dir);
    const normalizedDiscoveryPath = normalizeDiscoveryPathForComparison(discoveryPath);
    const identityPath = inspected.exists.executable
      ? path.join(candidate.dir, 'bin', 'codex.exe')
      : candidate.dir;
    const packageIdentity = resolveFilesystemIdentity(identityPath);
    const key = packageIdentity?.key || pathKey(identityPath);
    const discovery = {
      source: candidate.source,
      discoveryPath,
      normalizedDiscoveryPath,
      packageIdentity,
      inspectedReleaseDir: inspected.releaseDir,
      package: inspected,
    };
    const existing = packagesByIdentity.get(key);
    if (existing) {
      existing.discoveries.push(discovery);
      continue;
    }
    packagesByIdentity.set(key, {
      packageIdentity,
      discoveries: [discovery],
    });
  }
  const packages = [...packagesByIdentity.values()].map((entry) => {
    const discoveries = [...entry.discoveries].sort(compareStandaloneDiscoveries);
    const representativeDiscovery = discoveries.find((discovery) => discovery.source === 'release') || discoveries[0];
    const standalonePackage = representativeDiscovery.source === 'release'
      ? packageAtRepresentativeReleasePath(representativeDiscovery.package, representativeDiscovery.discoveryPath)
      : representativeDiscovery.package;
    const sources = [...new Set(discoveries.map((discovery) => discovery.source))]
      .sort((left, right) => standaloneSourceRank(left) - standaloneSourceRank(right));
    const representativePathKey = normalizeDiscoveryPathForComparison(standalonePackage.releaseDir);
    const uniqueDiscoveryPaths = new Map();
    for (const discovery of discoveries) {
      if (!uniqueDiscoveryPaths.has(discovery.normalizedDiscoveryPath)) {
        uniqueDiscoveryPaths.set(discovery.normalizedDiscoveryPath, discovery.discoveryPath);
      }
    }
    const aliases = [...uniqueDiscoveryPaths.entries()]
      .filter(([normalizedDiscoveryPath]) => normalizedDiscoveryPath !== representativePathKey)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([, discoveryPath]) => discoveryPath);
    return {
      ...standalonePackage,
      source: sources.includes('current') ? 'current' : sources[0],
      sources,
      aliases,
    };
  });
  return packages.sort((left, right) => String(left.releaseName).localeCompare(String(right.releaseName)));
}

export function discoverStandalonePackages(codexHome = getCodexHome()) {
  const standaloneRoot = path.join(path.resolve(codexHome), 'packages', 'standalone');
  const candidates = [];
  const current = path.join(standaloneRoot, 'current');
  if (fs.existsSync(current)) candidates.push({ dir: current, source: 'current' });
  const releasesDir = path.join(standaloneRoot, 'releases');
  if (fs.existsSync(releasesDir)) {
    try {
      for (const entry of fs.readdirSync(releasesDir, { withFileTypes: true })) {
        if (entry.isDirectory()) candidates.push({ dir: path.join(releasesDir, entry.name), source: 'release' });
      }
    } catch {}
  }
  return deduplicateStandalonePackageCandidates(candidates);
}

function findStandalonePackageForExecutable(executablePath, packages = []) {
  if (!executablePath) return null;
  const executableIdentity = executableObjectIdentityKey(executablePath);
  if (!executableIdentity) return null;
  return packages.find((bundle) => executableObjectIdentityKey(bundle.executablePath) === executableIdentity) || null;
}

export function inspectCodexBundle(executablePath, options = {}) {
  if (!executablePath) {
    return {
      executablePath: null, directory: null, exists: false, complete: false,
      installType: 'unknown', helperLayout: 'UNRESOLVED',
      missing: [...CODEX_BUNDLE_REQUIRED_FILES], optionalMissing: [...CODEX_BUNDLE_OPTIONAL_FILES],
      resourceLayout: RESOURCE_LAYOUT_STATES.MISSING,
      helperResolution: HELPER_RESOLUTION_STATES.NOT_TESTED,
      runtimeStartup: RUNTIME_STARTUP_STATES.NOT_TESTED,
      standaloneResourcesFound: false, standaloneRequiredResourcesPresent: false,
      helperResolutionProven: false,
      probeEligible: false,
    };
  }
  const resolved = path.resolve(executablePath);
  const filesystemIdentity = resolveFilesystemIdentity(resolved);
  const directory = path.dirname(resolved);
  const executableExists = fs.existsSync(resolved);
  const missing = CODEX_BUNDLE_REQUIRED_FILES.filter((name) => !fs.existsSync(path.join(directory, name)));
  const optionalMissing = CODEX_BUNDLE_OPTIONAL_FILES.filter((name) => !fs.existsSync(path.join(directory, name)));
  const directComplete = executableExists && missing.length === 0;
  const standalonePackages = options.standalonePackages || (options.codexHome ? discoverStandalonePackages(options.codexHome) : []);
  const directStandalonePackage = findStandalonePackageForExecutable(resolved, standalonePackages);
  const standaloneResourceBinding = createStandaloneResourceBinding(resolved, directStandalonePackage);
  const standalonePackage = standaloneResourceBinding ? directStandalonePackage : null;
  const isStandaloneExecutable = Boolean(standalonePackage);
  const standaloneResourcesFound = Boolean(standalonePackage?.resourcesFound);
  const standaloneRequiredResourcesPresent = Boolean(standalonePackage?.requiredResourcesPresent);
  const standaloneResourceLayout = standalonePackage?.resourceLayout || RESOURCE_LAYOUT_STATES.MISSING;
  const runtimeStartup = options.runtimeStartup || RUNTIME_STARTUP_STATES.NOT_TESTED;
  const helperResolution = options.helperResolution || HELPER_RESOLUTION_STATES.NOT_TESTED;
  const helperResolutionProven = helperResolution === HELPER_RESOLUTION_STATES.CONFIRMED && runtimeStartup === RUNTIME_STARTUP_STATES.READY;
  const probeEligible = directComplete || (isStandaloneExecutable && standaloneResourceLayout === RESOURCE_LAYOUT_STATES.COMPLETE);
  return {
    executablePath: resolved,
    directory,
    exists: executableExists,
    complete: directComplete,
    probeEligible,
    installType: standalonePackage ? 'standalone' : 'classic',
    helperLayout: directComplete ? 'BESIDE_EXECUTABLE' : (standaloneResourcesFound ? 'STANDALONE_RESOURCES' : 'UNRESOLVED'),
    missing,
    optionalMissing,
    standalonePackage: standalonePackage ? {
      source: standalonePackage.source,
      sources: standalonePackage.sources || [standalonePackage.source],
      aliases: standalonePackage.aliases || [],
      releaseDir: standalonePackage.releaseDir,
      releaseName: standalonePackage.releaseName,
      releaseVersion: standalonePackage.releaseVersion,
      executablePath: standalonePackage.executablePath,
      binDir: standalonePackage.binDir,
      codexResourcesDir: standalonePackage.codexResourcesDir,
      codexPathDir: standalonePackage.codexPathDir,
      files: standalonePackage.files,
      exists: standalonePackage.exists,
      resourcesFound: standalonePackage.resourcesFound,
      codexPathFound: standalonePackage.codexPathFound,
      requiredResourcesMissing: standalonePackage.requiredResourcesMissing,
      requiredResourcesPresent: standalonePackage.requiredResourcesPresent,
      resourceLayout: standalonePackage.resourceLayout,
      optionalResourcesMissing: standalonePackage.optionalResourcesMissing,
    } : null,
    resourceLayout: standalonePackage ? standaloneResourceLayout : (directComplete ? RESOURCE_LAYOUT_STATES.COMPLETE : RESOURCE_LAYOUT_STATES.MISSING),
    helperResolution,
    runtimeStartup,
    standaloneResourcesFound,
    standaloneRequiredResourcesPresent,
    standaloneRequiredResourcesMissing: standalonePackage?.requiredResourcesMissing || [],
    resourceVersionMatchesActive: standalonePackage && options.activeVersion
      ? normalizeCodexVersion(standalonePackage.releaseVersion) === normalizeCodexVersion(options.activeVersion)
      : null,
    helperResolutionProven,
    standaloneResourceBinding,
    filesystemIdentity: filesystemIdentity ? {
      status: filesystemIdentity.conflict ? 'CONFLICT' : (filesystemIdentity.proven ? 'PROVEN' : 'UNPROVEN'),
      canonicalPath: filesystemIdentity.proven ? filesystemIdentity.resolvedPath : null,
      resolutionMethod: filesystemIdentity.resolutionMethod,
      key: filesystemIdentity.key,
      conflict: filesystemIdentity.conflict,
    } : {
      status: 'UNPROVEN', canonicalPath: null, resolutionMethod: 'unavailable', key: null,
    },
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

export function discoverCodexBundlePaths(env = process.env, options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== 'win32') return [];
  const local = env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const codexHome = getCodexHome(env);
  const roots = [
    path.join(local, 'OpenAI', 'Codex', 'bin'),
    path.join(local, 'Programs', 'OpenAI', 'Codex', 'bin'),
    path.join(codexHome, 'packages', 'standalone', 'current', 'bin'),
    path.join(codexHome, 'packages', 'standalone', 'releases'),
  ];
  return [...new Set(roots.flatMap((root) => collectCodexExecutables(root, 3)))];
}

function alternativeVersionEvidence(bundle) {
  const derivedVersion = bundle?.standalonePackage?.releaseVersion || null;
  return {
    derivedVersion,
    versionEvidenceSource: derivedVersion ? 'PACKAGE_METADATA' : 'UNKNOWN',
    versionConfirmedByExecution: false,
    confirmedVersion: null,
  };
}

export function inventoryAlternativeCodexExecutables(bundlePaths = [], options = {}) {
  const activeCodexPath = options.activeCodexPath || null;
  const activeIdentityKey = activeCodexPath ? realPathKey(activeCodexPath) : null;
  const inspected = [];
  for (const candidatePath of bundlePaths) {
    const candidateIdentityKey = realPathKey(candidatePath);
    if (activeIdentityKey && candidateIdentityKey === activeIdentityKey) continue;
    const bundle = inspectCodexBundle(candidatePath, {
      codexHome: options.codexHome,
      standalonePackages: options.standalonePackages,
    });
    inspected.push({
      ...bundle,
      ...alternativeVersionEvidence(bundle),
      filesystemDiscovery: 'DISCOVERED',
      selectionStatus: 'NOT_SELECTED',
      diagnosticStatus: 'NOT_RUN',
      sandboxState: 'NOT_RUN',
      tested: false,
      validatesActiveCli: false,
      validatesBoundary: false,
    });
  }
  return summarizeExecutableBundles(inspected).logicalExecutables.map(({ representative, discoveredPaths }) => ({
    ...representative,
    discoveredPaths,
  }));
}

function alternativeSourceFromVersion(candidateVersion, activeVersion) {
  if (!candidateVersion || !activeVersion) return 'ALTERNATIVE_EXECUTABLE';
  const comparison = compareCodexVersions(candidateVersion, activeVersion);
  if (comparison === 0) return 'MATCHING_COMPLETE_BUNDLE';
  if (comparison === 1) return 'NEWER_COMPLETE_BUNDLE';
  return 'ALTERNATIVE_EXECUTABLE';
}

function findBoundAlternativeInventoryRecord(inventory, candidate) {
  if (!candidate?.codexExe || !candidate?.expectedFilesystemIdentityKey) return null;
  return (inventory?.alternativeExecutables || []).find((record) => (
    record.executablePath === candidate.codexExe
    && record.filesystemIdentity?.key === candidate.expectedFilesystemIdentityKey
  )) || null;
}

export function diagnoseExplicitlySelectedCodexExecutable(inventory, candidate, options = {}) {
  const record = findBoundAlternativeInventoryRecord(inventory, candidate);
  if (!record) {
    return { ready: false, reason: 'The selected executable is not bound to a current inventory candidate.', diagnosticStatus: 'NOT_RUN' };
  }
  const selectedExecutableBinding = {
    selectedExecutablePath: record.executablePath,
    expectedFilesystemIdentityKey: candidate.expectedFilesystemIdentityKey,
  };
  const initialBinding = validateSelectedExecutableBinding(selectedExecutableBinding, record.executablePath);
  if (record.filesystemIdentity?.status !== 'PROVEN' || !initialBinding.valid) {
    return { ready: false, reason: 'The selected executable identity could not be proven unchanged.', diagnosticStatus: 'NOT_RUN' };
  }

  record.selectionStatus = 'SELECTED';
  record.diagnosticStatus = 'STARTED';
  candidate.selectionStatus = 'SELECTED';
  candidate.diagnosticStatus = 'STARTED';
  const runner = options.invokeCodex || invokeCodex;
  const versionRun = runner(['--version'], { timeout: 20_000, codexExe: record.executablePath });
  if (versionRun.status !== 0) {
    record.diagnosticStatus = 'ERROR';
    candidate.diagnosticStatus = 'ERROR';
    return { ready: false, reason: 'The selected executable did not complete its version diagnostic.', diagnosticStatus: 'ERROR' };
  }
  const confirmedVersion = String(versionRun.stdout || versionRun.stderr || '').trim();
  record.confirmedVersion = confirmedVersion;
  record.versionConfirmedByExecution = true;
  record.confirmedVersionEvidenceSource = 'EXECUTABLE_OUTPUT';
  candidate.testedVersion = confirmedVersion;
  candidate.confirmedVersionEvidenceSource = 'EXECUTABLE_OUTPUT';
  const versionComparison = inventory?.codexVersion ? compareCodexVersions(confirmedVersion, inventory.codexVersion) : null;
  const metadataComparison = record.derivedVersion
    ? compareCodexVersions(confirmedVersion, record.derivedVersion)
    : null;
  if (versionComparison == null || (record.derivedVersion && metadataComparison !== 0)) {
    record.diagnosticStatus = 'ERROR';
    candidate.diagnosticStatus = 'ERROR';
    record.confirmedSource = 'ALTERNATIVE_EXECUTABLE';
    candidate.source = 'ALTERNATIVE_EXECUTABLE';
    return {
      ...candidate,
      ready: false,
      reason: versionComparison == null
        ? 'The selected executable returned an unparseable version. No sandbox help process was started.'
        : 'The executed version conflicts with the selected package metadata. No sandbox help process was started.',
      testedVersion: confirmedVersion,
      diagnosticStatus: 'ERROR',
    };
  }
  const helpBinding = validateSelectedExecutableBinding(selectedExecutableBinding, record.executablePath);
  if (!helpBinding.valid) {
    record.diagnosticStatus = 'ERROR';
    candidate.diagnosticStatus = 'ERROR';
    return { ready: false, reason: 'The selected executable identity changed after its version diagnostic. No sandbox help process was started.', diagnosticStatus: 'ERROR' };
  }
  const helpRun = runner(['sandbox', '--help'], { timeout: 20_000, codexExe: record.executablePath });
  const sandboxFeature = detectWindowsSandboxFeature(helpRun);
  record.diagnosticStatus = helpRun.status === 0 ? 'COMPLETED' : 'ERROR';
  candidate.diagnosticStatus = record.diagnosticStatus;
  record.sandboxState = sandboxFeature.state;
  record.sandboxHelpError = sandboxFeature.error;
  record.sandboxFullAutoAvailable = sandboxFeature.fullAutoAvailable;
  record.sandboxCommandContract = sandboxFeature.commandContract;

  const source = alternativeSourceFromVersion(confirmedVersion, inventory?.codexVersion || null);
  record.confirmedSource = source;
  record.versionMismatch = versionComparison === 1;
  candidate.source = source;
  candidate.versionMismatch = versionComparison === 1;
  candidate.sandboxState = sandboxFeature.state;
  candidate.sandboxCommandContract = sandboxFeature.commandContract;
  candidate.selectedExecutableBinding = selectedExecutableBinding;
  const ready = record.probeEligible === true
    && (versionComparison === 0 || versionComparison === 1)
    && sandboxFeature.state === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE
    && sandboxCommandContractSupported(sandboxFeature.commandContract);
  const scopeNote = versionComparison === 0 || versionComparison === 1
    ? describeAlternativeExecutableScope({
      versionMismatch: versionComparison === 1,
      testedVersion: confirmedVersion,
      activeVersion: inventory?.codexVersion || null,
    })
    : 'A separate executable was selected for bounded diagnostics, but it is not eligible for live probes. It does not validate the active PATH CLI or sandbox boundary.';
  return {
    ...candidate,
    ready,
    reason: ready ? null : 'The selected executable is not test-ready after its bound diagnostics.',
    source,
    testedVersion: confirmedVersion,
    activeVersion: inventory?.codexVersion || null,
    isAlternativeExecutable: true,
    versionMismatch: versionComparison === 1,
    fullAutoAvailable: sandboxFeature.fullAutoAvailable === true,
    sandboxState: sandboxFeature.state,
    sandboxCommandContract: sandboxFeature.commandContract,
    testedBundleMetadata: buildProbeBundleMetadata(record),
    standaloneResourceBinding: record.standaloneResourceBinding || null,
    selectedExecutableBinding,
    scopeNote,
    diagnosticStatus: record.diagnosticStatus,
  };
}

export function selectCodexProbePlan(inventory) {
  if (!inventory) {
    return { ready: false, requiresConfirmation: false, requiresSelection: false, candidates: [], source: null, codexExe: null, reason: 'Codex inventory is unavailable.' };
  }
  const candidates = [];
  const seenExecutables = new Set();
  const addCandidate = (candidate) => {
    if (!candidate.codexExe) return;
    const key = realPathKey(candidate.codexExe);
    if (seenExecutables.has(key)) return;
    seenExecutables.add(key);
    candidates.push(candidate);
  };
  const activeProbeEligible = inventory.activeBundle?.probeEligible || inventory.sandboxHelperInPath;
  if (activeProbeEligible
      && inventory.sandboxWindowsState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE
      && sandboxCommandContractSupported(inventory.sandboxCommandContract)) {
    addCandidate({
      source: 'ACTIVE_CLI',
      codexExe: inventory.activeCodexPath || null,
      testedVersion: inventory.codexVersion || null,
      activeVersion: inventory.codexVersion || null,
      isAlternativeExecutable: false,
      versionMismatch: false,
      fullAutoAvailable: inventory.sandboxFullAutoAvailable === true,
      sandboxState: inventory.sandboxWindowsState,
      sandboxCommandContract: inventory.sandboxCommandContract,
      testedBundleMetadata: buildProbeBundleMetadata(inventory.activeBundle),
      standaloneResourceBinding: inventory.activeBundle?.standaloneResourceBinding || null,
      scopeNote: null,
      reason: null,
    });
  }
  const alternativeInventory = [...(inventory.alternativeExecutables || [])].sort((left, right) => {
    const rank = (candidate) => {
      const relation = alternativeSourceFromVersion(candidate.derivedVersion, inventory.codexVersion || null);
      if (relation === 'MATCHING_COMPLETE_BUNDLE') return 0;
      if (relation === 'NEWER_COMPLETE_BUNDLE') return 1;
      return 2;
    };
    return rank(left) - rank(right);
  });
  for (const alternative of alternativeInventory) {
    if (alternative.probeEligible !== true || alternative.filesystemIdentity?.status !== 'PROVEN') continue;
    const derivedSource = alternativeSourceFromVersion(alternative.derivedVersion, inventory.codexVersion || null);
    addCandidate({
      source: 'ALTERNATIVE_EXECUTABLE',
      derivedVersionRelation: derivedSource,
      codexExe: alternative.executablePath,
      expectedFilesystemIdentityKey: alternative.filesystemIdentity.key,
      testedVersion: null,
      displayedVersion: alternative.derivedVersion || null,
      versionEvidenceSource: alternative.versionEvidenceSource || 'UNKNOWN',
      activeVersion: inventory.codexVersion || null,
      isAlternativeExecutable: true,
      versionMismatch: false,
      derivedVersionMismatch: derivedSource === 'NEWER_COMPLETE_BUNDLE',
      fullAutoAvailable: false,
      sandboxState: 'NOT_RUN',
      sandboxCommandContract: detectSandboxCommandContract(null),
      testedBundleMetadata: buildProbeBundleMetadata(alternative),
      standaloneResourceBinding: alternative.standaloneResourceBinding || null,
      selectedExecutableBinding: null,
      selectionStatus: 'NOT_SELECTED',
      diagnosticStatus: 'NOT_RUN',
      tested: false,
      scopeNote: 'Filesystem discovery only. This executable has not been selected, started, tested, or used to validate the active PATH CLI or sandbox boundary.',
      reason: 'A probe-eligible filesystem candidate was found. Explicit selection is required before its version or sandbox syntax may be diagnosed.',
    });
  }
  if (candidates.length) {
    const selectedByDefault = candidates[0];
    return {
      ready: true,
      requiresConfirmation: candidates.length === 1 && selectedByDefault.isAlternativeExecutable,
      requiresSelection: candidates.length > 1,
      candidates,
      ...selectedByDefault,
    };
  }
  const completeSummary = inventory.completeBundles?.length
    ? ' Probe-eligible local bundle(s) were found, but none have a provable identity suitable for explicit selection.'
    : '';
  const activeReason = activeProbeEligible
    ? `The active CLI bundle is probe-eligible, but its Windows sandbox state is ${inventory.sandboxWindowsState || 'UNKNOWN'}.`
    : `The active CLI bundle is incomplete. Its sandbox state is ${inventory.sandboxWindowsState || 'UNKNOWN'}, and no suitable probe-eligible local bundle was found.`;
  return {
    ready: false,
    requiresConfirmation: false,
    requiresSelection: false,
    candidates: [],
    source: null,
    codexExe: null,
    reason: `${activeReason}${completeSummary}`,
  };
}

function buildProbeBundleMetadata(bundle) {
  if (!bundle) return null;
  return {
    installType: bundle.installType || 'unknown',
    complete: bundle.complete === true,
    probeEligible: bundle.probeEligible === true,
    helperLayout: bundle.helperLayout || 'UNRESOLVED',
    resourceLayout: bundle.resourceLayout || RESOURCE_LAYOUT_STATES.MISSING,
    helperResolution: bundle.helperResolution || HELPER_RESOLUTION_STATES.NOT_TESTED,
    runtimeStartup: bundle.runtimeStartup || RUNTIME_STARTUP_STATES.NOT_TESTED,
    standaloneResourcesFound: bundle.standaloneResourcesFound === true,
    standaloneRequiredResourcesPresent: bundle.standaloneRequiredResourcesPresent === true,
    resourceVersionMatchesActive: bundle.resourceVersionMatchesActive ?? null,
    releaseVersion: bundle.standalonePackage?.releaseVersion || bundle.releaseVersion || null,
  };
}

export function detectSandboxCommandContract(helpRun) {
  const text = `${helpRun?.stdout || ''}\n${helpRun?.stderr || ''}`;
  const usageLine = text
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('Usage:')) || null;
  const commandArgumentsSupported = usageLine === 'Usage: codex sandbox [OPTIONS] [COMMAND]...';
  const permissionProfileSupported = text.includes('--permission-profile <NAME>');
  const workingDirectorySupported = text.includes('--cd <DIR>');
  const supported = helpRun?.status === 0
    && commandArgumentsSupported
    && permissionProfileSupported
    && workingDirectorySupported;
  return {
    syntax: supported ? SANDBOX_COMMAND_SYNTAXES.GENERIC_PERMISSION_PROFILE : SANDBOX_COMMAND_SYNTAXES.UNKNOWN,
    supported,
    usageLine,
    commandArgumentsSupported,
    permissionProfileSupported,
    workingDirectorySupported,
    fullAutoAvailable: text.includes('--full-auto'),
    reason: supported
      ? null
      : 'The sandbox help output did not prove the generic command, permission-profile, and working-directory syntax required by the Canary.',
  };
}

function sandboxCommandContractSupported(contract) {
  return contract?.supported === true
    && contract.syntax === SANDBOX_COMMAND_SYNTAXES.GENERIC_PERMISSION_PROFILE
    && contract.commandArgumentsSupported === true
    && contract.permissionProfileSupported === true
    && contract.workingDirectorySupported === true;
}

export function detectWindowsSandboxFeature(helpRun) {
  const commandContract = detectSandboxCommandContract(helpRun);
  if (!helpRun || helpRun.error || helpRun.status == null) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR,
      available: false,
      fullAutoAvailable: false,
      setupFailed: false,
      error: helpRun ? compactError(helpRun) : 'Codex sandbox help was not run.',
      commandContract,
    };
  }

  const text = `${helpRun.stdout || ''}\n${helpRun.stderr || ''}`;
  if (helpRun.status === 0 && commandContract.supported) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE,
      available: true,
      fullAutoAvailable: commandContract.fullAutoAvailable,
      setupFailed: false,
      error: null,
      commandContract,
    };
  }

  if (helpRun.status === 0) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.UNSUPPORTED,
      available: false,
      fullAutoAvailable: false,
      setupFailed: false,
      error: commandContract.reason,
      commandContract,
    };
  }

  if (detectSandboxSetupFailure(helpRun)) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE_BUT_SETUP_FAILED,
      available: false,
      fullAutoAvailable: false,
      setupFailed: true,
      error: compactError(helpRun),
      commandContract,
    };
  }

  if (/unrecognized subcommand|unknown command|invalid subcommand|unexpected argument/i.test(text)) {
    return {
      state: WINDOWS_SANDBOX_FEATURE_STATES.UNSUPPORTED,
      available: false,
      fullAutoAvailable: false,
      setupFailed: false,
      error: compactError(helpRun),
      commandContract,
    };
  }

  return {
    state: WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR,
    available: false,
    fullAutoAvailable: false,
    setupFailed: false,
    error: compactError(helpRun),
    commandContract,
  };
}

export function canRunLiveSandboxProbes(inventory) {
  return inventory?.sandboxWindowsState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE
    && sandboxCommandContractSupported(inventory?.sandboxCommandContract);
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
    const target = item.target ? ` [${item.target}]` : '';
    lines.push(`- ${item.severity} ${item.code}${target}`);
    lines.push(`  Title: ${item.title}`);
    lines.push(`  Explanation: ${item.message}`);
    lines.push(`  Recommendation: ${item.recommendation}`);
  }
  return lines;
}

export function buildSandboxCommandArgs(command, options = {}) {
  if (!sandboxCommandContractSupported(options.commandContract)) {
    throw new Error('A verified generic sandbox command contract is required before building a live command.');
  }
  const permissionProfile = options.permissionProfile || ':workspace';
  const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
  const args = ['sandbox'];
  if (options.fullAuto === true && options.commandContract.fullAutoAvailable === true) args.push('--full-auto');
  args.push('--permission-profile', permissionProfile, '--cd', workspaceDir, '--');
  args.push(...command);
  return args;
}

export function createCodexDoctorInventoryStatus(codexInstalled) {
  if (!codexInstalled) {
    return {
      status: CODEX_DOCTOR_STATES.UNAVAILABLE,
      ok: false,
      overallStatus: null,
      installationStatus: null,
      runtimeStatus: null,
      warningCount: null,
      error: null,
      reason: 'Codex CLI is unavailable; no Doctor process was started.',
    };
  }
  return {
    status: CODEX_DOCTOR_STATES.NOT_RUN,
    ok: false,
    overallStatus: null,
    installationStatus: null,
    runtimeStatus: null,
    warningCount: null,
    error: null,
    reason: CODEX_DOCTOR_SKIP_REASON,
  };
}

export function authFileExists(codexHome, fileSystem = fs) {
  return fileSystem.existsSync(path.join(codexHome, 'auth.json'));
}

export function getCodexInventory(env = process.env, options = {}) {
  const platform = options.platform || process.platform;
  const resolveCommand = options.findCommandPath || findCommandPath;
  const runCodex = options.invokeCodex || invokeCodex;
  const discoverPackages = options.discoverStandalonePackages || discoverStandalonePackages;
  const discoverBundlePaths = options.discoverCodexBundlePaths || discoverCodexBundlePaths;
  const commandAvailable = options.commandInPath || commandInPath;
  const checkElevation = options.isElevatedWindows || isElevatedWindows;
  const readConfig = options.readSafeConfigSummary || readSafeConfigSummary;
  const readRules = options.listRuleFiles || listRuleFiles;
  const checkAuthFile = options.authFileExists || authFileExists;
  const codexHome = getCodexHome(env);
  const configPath = path.join(codexHome, 'config.toml');
  const activeCodexPath = resolveCommand(platform === 'win32' ? 'codex.exe' : 'codex');
  const activeCodexIdentity = executableObjectIdentityKey(activeCodexPath);
  const versionRun = runCodex(['--version'], { timeout: 20_000, codexExe: activeCodexPath });
  const installed = versionRun.status === 0;
  const version = installed ? (versionRun.stdout || versionRun.stderr || '').trim() : null;
  const normalizedVersion = normalizeCodexVersion(version);
  const helpRun = installed ? runCodex(['sandbox', '--help'], { timeout: 20_000, codexExe: activeCodexPath }) : null;
  const sandboxFeature = installed ? detectWindowsSandboxFeature(helpRun) : {
    state: WINDOWS_SANDBOX_FEATURE_STATES.UNSUPPORTED,
    available: false,
    fullAutoAvailable: false,
    setupFailed: false,
    error: 'Codex CLI is not installed or not executable.',
    commandContract: detectSandboxCommandContract(null),
  };
  const standalonePackages = discoverPackages(codexHome);
  const doctor = createCodexDoctorInventoryStatus(installed);
  const activeBundle = inspectCodexBundle(activeCodexPath, { codexHome, activeVersion: normalizedVersion, standalonePackages });
  const sandboxHelperInPath = Boolean(resolveCommand('codex-windows-sandbox-setup.exe'));
  const bundlePaths = discoverBundlePaths(env, { platform });
  const alternativeExecutables = inventoryAlternativeCodexExecutables(bundlePaths, {
    activeCodexPath, codexHome, standalonePackages,
  });
  const completeBundles = alternativeExecutables.filter((bundle) => bundle.probeEligible === true);
  for (const bundle of completeBundles) {
    bundle.versionMatchesActive = installed
      && bundle.derivedVersion != null
      && normalizeCodexVersion(bundle.derivedVersion) === normalizedVersion;
    bundle.versionComparisonToActive = installed && bundle.derivedVersion
      ? compareCodexVersions(bundle.derivedVersion, version)
      : null;
  }
  const matchingCompleteBundles = completeBundles.filter((bundle) => bundle.versionMatchesActive === true);
  const newerCompleteBundles = completeBundles
    .filter((bundle) => bundle.versionComparisonToActive === 1)
    .sort((left, right) => compareCodexVersions(right.derivedVersion, left.derivedVersion) || 0);
  const inventory = {
    platform,
    release: os.release(),
    nodeVersion: process.version,
    nodeRuntimeSource: env.CANARY_NODE_SOURCE || (commandAvailable('node.exe') ? 'PATH' : 'unknown'),
    nodeInPath: commandAvailable('node.exe'),
    npmInPath: commandAvailable(platform === 'win32' ? 'npm.cmd' : 'npm'),
    elevated: checkElevation(),
    codexInstalled: installed,
    codexVersion: version,
    activeCodexPath,
    activeCodexIdentity,
    activeBundle,
    standalonePackages,
    doctor,
    sandboxHelperInPath,
    alternativeExecutables,
    completeBundles,
    matchingCompleteBundles,
    newerCompleteBundles,
    codexHome,
    authFilePresent: checkAuthFile(codexHome),
    config: readConfig(configPath),
    ruleFiles: readRules(codexHome),
    sandboxWindowsState: sandboxFeature.state,
    sandboxWindowsAvailable: sandboxFeature.state === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE,
    sandboxFullAutoAvailable: sandboxFeature.state === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE && sandboxFeature.fullAutoAvailable === true,
    sandboxCommandContract: sandboxFeature.commandContract,
    sandboxSetupFailed: sandboxFeature.setupFailed,
    sandboxHelpStatus: helpRun?.status ?? null,
    sandboxHelpError: sandboxFeature.error,
    sandboxHelpRuntimeEvidence: buildSandboxRuntimeEvidence(helpRun, {
      step: 'SANDBOX_HELP',
      codexSource: 'ACTIVE_CLI',
      codexExecutableIdentity: activeCodexIdentity,
    }),
  };
  const inventoryRuntimeObservation = deriveSandboxRuntimeObservation(inventory, null);
  inventory.activeBundle = {
    ...inventory.activeBundle,
    helperResolution: inventoryRuntimeObservation.helperResolution,
    runtimeStartup: inventoryRuntimeObservation.runtimeStartup,
    helperResolutionProven: inventoryRuntimeObservation.helperResolution === HELPER_RESOLUTION_STATES.CONFIRMED
      && inventoryRuntimeObservation.runtimeStartup === RUNTIME_STARTUP_STATES.READY,
  };
  inventory.runtimeObservation = inventoryRuntimeObservation;
  inventory.runtimeDiagnostics = buildRuntimeDiagnostics(inventory, null);
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

const EXECPOLICY_DECISION_FIELDS = Object.freeze(['decision', 'strictestDecision', 'strictest_decision']);
const EXECPOLICY_DECISION_RANK = Object.freeze({ allow: 0, prompt: 1, forbidden: 2 });

function normalizeExecpolicyDecision(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.toLowerCase();
  if (normalized === 'allow' || normalized === 'allowed') return 'allow';
  if (normalized === 'prompt') return 'prompt';
  if (['forbidden', 'deny', 'denied', 'block', 'blocked'].includes(normalized)) return 'forbidden';
  return null;
}

function readExplicitDecisionFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { decisions: [], invalid: false };
  const decisions = [];
  for (const field of EXECPOLICY_DECISION_FIELDS) {
    if (!Object.hasOwn(value, field)) continue;
    const decision = normalizeExecpolicyDecision(value[field]);
    if (!decision) return { decisions: [], invalid: true };
    decisions.push(decision);
  }
  return { decisions, invalid: false };
}

function readTopLevelExecpolicyDecisions(parsed) {
  const direct = readExplicitDecisionFields(parsed);
  if (direct.invalid) return direct;
  const decisions = [...direct.decisions];
  if (Object.hasOwn(parsed, 'result')) {
    const resultDecision = normalizeExecpolicyDecision(parsed.result);
    if (resultDecision) decisions.push(resultDecision);
    else {
      const nestedResult = readExplicitDecisionFields(parsed.result);
      if (nestedResult.invalid || nestedResult.decisions.length === 0) return { decisions: [], invalid: true };
      decisions.push(...nestedResult.decisions);
    }
  }
  return { decisions, invalid: false };
}

function readMatchedRuleDecision(rule) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return null;
  const direct = readExplicitDecisionFields(rule);
  if (direct.invalid) return null;
  const prefix = readExplicitDecisionFields(rule.prefixRuleMatch);
  if (prefix.invalid) return null;
  const decisions = [...direct.decisions, ...prefix.decisions];
  if (decisions.length === 0) return null;
  return strictestExecpolicyDecision(decisions);
}

function strictestExecpolicyDecision(decisions) {
  return decisions.reduce((strictest, decision) => (
    strictest == null || EXECPOLICY_DECISION_RANK[decision] > EXECPOLICY_DECISION_RANK[strictest]
      ? decision
      : strictest
  ), null);
}

function analyzeExecpolicySchema(parsed) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { status: 'UNKNOWN_SCHEMA', decision: null, reason: 'The execpolicy output was not an expected JSON object.' };
  }
  const aggregate = readTopLevelExecpolicyDecisions(parsed);
  if (aggregate.invalid) {
    return { status: 'UNKNOWN_SCHEMA', decision: null, reason: 'A recognized top-level execpolicy decision field contained an unknown value.' };
  }
  const aggregateDecision = strictestExecpolicyDecision(aggregate.decisions);
  if (!Object.hasOwn(parsed, 'matchedRules')) {
    return aggregateDecision
      ? { status: 'OK', decision: aggregateDecision, reason: null }
      : { status: 'UNKNOWN_SCHEMA', decision: null, reason: 'No recognized top-level execpolicy decision field was present.' };
  }
  if (!Array.isArray(parsed.matchedRules)) {
    return { status: 'UNKNOWN_SCHEMA', decision: null, reason: 'The recognized matchedRules field was not an array.' };
  }
  if (parsed.matchedRules.length === 0) {
    return aggregateDecision
      ? { status: 'OK', decision: aggregateDecision, reason: null }
      : { status: 'NO_MATCH', decision: null, reason: null };
  }
  const ruleDecisions = parsed.matchedRules.map(readMatchedRuleDecision);
  if (ruleDecisions.some((decision) => decision == null)) {
    return { status: 'UNKNOWN_SCHEMA', decision: null, reason: 'A matched rule did not contain exactly one recognized decision in the supported rule structure.' };
  }
  const strictestRuleDecision = strictestExecpolicyDecision(ruleDecisions);
  return {
    status: 'OK',
    decision: strictestExecpolicyDecision([aggregateDecision, strictestRuleDecision].filter(Boolean)),
    reason: null,
  };
}

export function findDecision(value) {
  const analysis = analyzeExecpolicySchema(value);
  return analysis.status === 'OK' ? analysis.decision : null;
}

export function parseExecpolicyOutput(output) {
  const parsed = typeof output === 'string' ? JSON.parse(output) : output;
  const analysis = analyzeExecpolicySchema(parsed);
  if (analysis.status === 'OK' || analysis.status === 'NO_MATCH') {
    return { parsed, status: analysis.status, decision: analysis.decision, error: null };
  }
  return {
    parsed,
    status: 'UNKNOWN_SCHEMA',
    decision: null,
    error: analysis.reason,
  };
}

function execpolicyCommandForm(commandToken) {
  const token = String(commandToken || '');
  if (path.win32.isAbsolute(token) || path.isAbsolute(token)) return 'ABSOLUTE_PATH';
  if (token.includes('\\') || token.includes('/')) return 'RELATIVE_PATH';
  return token ? 'BARE_NAME' : 'UNKNOWN';
}

function sameExecpolicyCommandToken(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (path.win32.isAbsolute(left) || path.win32.isAbsolute(right)) {
    return normalizeDiscoveryPathForComparison(left, 'win32') === normalizeDiscoveryPathForComparison(right, 'win32');
  }
  if (path.isAbsolute(left) || path.isAbsolute(right)) {
    return normalizeDiscoveryPathForComparison(left) === normalizeDiscoveryPathForComparison(right);
  }
  return left === right;
}

function matchedExecpolicyRuleBindings(parsed) {
  if (!Array.isArray(parsed?.matchedRules)) return [];
  return parsed.matchedRules
    .map((rule) => ({
      prefix: rule?.prefixRuleMatch?.matchedPrefix,
      decision: readMatchedRuleDecision(rule),
    }))
    .filter(({ prefix, decision }) => decision && Array.isArray(prefix) && prefix.every((token) => typeof token === 'string'));
}

export function analyzeExecpolicyCommandBinding({ command, parsedResult, resolvedCommandPath = null } = {}) {
  const requestedCommand = Array.isArray(command) ? command : [];
  const commandToken = requestedCommand[0] || null;
  const commandForm = execpolicyCommandForm(commandToken);
  let ruleBinding = EXECPOLICY_BINDING_STATES.NOT_PROVEN;
  if (parsedResult?.status === 'NO_MATCH') {
    ruleBinding = EXECPOLICY_BINDING_STATES.NO_MATCH;
  } else if (parsedResult?.status === 'UNKNOWN_SCHEMA') {
    ruleBinding = EXECPOLICY_BINDING_STATES.UNKNOWN_SCHEMA;
  } else if (parsedResult?.status === 'OK' && commandForm === 'ABSOLUTE_PATH') {
    const controllingRules = matchedExecpolicyRuleBindings(parsedResult.parsed)
      .filter(({ decision }) => decision === parsedResult.decision);
    const everyControllingRuleIsExact = controllingRules.length > 0
      && controllingRules.every(({ prefix }) => sameExecpolicyCommandToken(prefix[0], commandToken));
    if (everyControllingRuleIsExact) ruleBinding = EXECPOLICY_BINDING_STATES.CONFIRMED;
  }
  return {
    commandForm,
    ruleBinding,
    executionBinding: EXECPOLICY_BINDING_STATES.NOT_PROVEN,
    hostResolutionObserved: Boolean(resolvedCommandPath),
    resolvedCommandPath: resolvedCommandPath || null,
    evidenceBoundary: EXECPOLICY_EXECUTION_EVIDENCE_BOUNDARY,
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
      binding: analyzeExecpolicyCommandBinding({
        command: probe.command,
        parsedResult: { status: 'NO_RULES', parsed: null },
        resolvedCommandPath: (options.resolveCommandPath || findCommandPath)(probe.command[0]),
      }),
    }));
  }
  return RULE_PROBES.map((probe) => {
    const resolvedCommandPath = (options.resolveCommandPath || findCommandPath)(probe.command[0]);
    const args = ['execpolicy', 'check', '--pretty'];
    for (const file of ruleFiles) args.push('--rules', file);
    args.push('--', ...probe.command);
    const result = invokeCodex(args, { timeout: 30_000, codexExe: options.codexExe });
    if (result.status !== 0) {
      return {
        ...probe, status: 'ERROR', decision: null, raw: result.stdout, error: compactError(result),
        binding: analyzeExecpolicyCommandBinding({ command: probe.command, parsedResult: { status: 'ERROR' }, resolvedCommandPath }),
      };
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
        binding: analyzeExecpolicyCommandBinding({ command: probe.command, parsedResult, resolvedCommandPath }),
      };
    } catch (error) {
      return {
        ...probe, status: 'INVALID_JSON', decision: null, raw: output, error: error.message,
        binding: analyzeExecpolicyCommandBinding({ command: probe.command, parsedResult: { status: 'UNKNOWN_SCHEMA' }, resolvedCommandPath }),
      };
    }
  });
}

function writeCanary(file, marker) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `Codex Safety Canary synthetic file\n${marker}\n`, 'utf8');
}

function runSandboxCommand(command, cwd, options = {}) {
  if (options.selectedExecutableBinding) {
    const binding = validateSelectedExecutableBinding(options.selectedExecutableBinding, options.codexExe);
    if (!binding.valid) {
      return {
        status: null,
        stdout: '',
        stderr: '',
        codexProcessStarted: false,
        error: new Error('The selected executable identity changed. No Codex process was started.'),
      };
    }
  }
  const args = buildSandboxCommandArgs(command, {
    permissionProfile: options.permissionProfile || ':workspace',
    workspaceDir: options.workspaceDir || cwd,
    commandContract: options.commandContract,
    fullAuto: options.fullAuto === true,
  });
  const result = invokeCodex(args, { cwd, timeout: 45_000, codexExe: options.codexExe });
  return { ...result, codexProcessStarted: result.codexProcessStarted === true };
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

function parseStructuredProbeRecord(result) {
  const lines = [result?.stdout, result?.stderr]
    .filter(Boolean)
    .flatMap((value) => String(value).split(/\r?\n/));
  for (const line of lines) {
    const text = line.trim();
    if (!text.startsWith('{') || !text.endsWith('}')) continue;
    try {
      const parsed = JSON.parse(text);
      if (parsed?.codexSafetyCanaryProbe === 1) return parsed;
    } catch {
      continue;
    }
  }
  return null;
}

function extractCmdOperationOutput(result, targetId) {
  const lines = [result?.stdout, result?.stderr]
    .filter(Boolean)
    .flatMap((value) => String(value).split(/\r?\n/));
  const startMarker = `CODEX_CANARY_CMD_OUTPUT_BEGIN:${targetId}`;
  const endMarker = `CODEX_CANARY_CMD_OUTPUT_END:${targetId}`;
  const start = lines.findIndex((line) => line.trim() === startMarker);
  if (start < 0) return null;
  const end = lines.findIndex((line, index) => index > start && line.trim() === endMarker);
  if (end < 0) return null;
  return lines.slice(start + 1, end).join('\n');
}

export function canonicalizeWindowsPath(value) {
  if (!value) return null;
  return normalizeFilesystemPath(value, 'win32').toLowerCase();
}

export function sameWindowsPath(left, right) {
  const leftKey = canonicalizeWindowsPath(left);
  const rightKey = canonicalizeWindowsPath(right);
  return leftKey != null && rightKey != null && leftKey === rightKey;
}

function nativeWin32CodeFromHResult(value) {
  if (!Number.isInteger(value)) return null;
  return value & 0xffff;
}

function detectUnrelatedProbeFailure(result) {
  const text = `${result?.stdout || ''}\n${result?.stderr || ''}\n${result?.error?.message || ''}`.toLowerCase();
  return [
    'syntaxerror',
    'parsererror',
    'command not found',
    'is not recognized as an internal or external command',
    'access to network is denied',
    'network access is denied',
    'wrapper error',
    'orchestrator_helper_launch_failed',
  ].some((marker) => text.includes(marker));
}

export function deriveProbeExecutionEvidence({ before, after, result, definition, hostCalibration = null }) {
  const record = parseStructuredProbeRecord(result);
  const targetIdentityMatched = Boolean(record) && record.targetId === definition.id
    && (!record.targetPath || sameWindowsPath(record.targetPath, definition.file));
  const commandStarted = record?.commandStarted === true;
  const operationAttempted = record?.operationAttempted === true;
  const exitCode = Number.isInteger(result?.status) ? result.status : (record?.exitCode ?? null);
  const unrelatedFailureDetected = detectUnrelatedProbeFailure(result);
  const reportedErrorTarget = record?.runtime === 'powershell'
    ? (record?.errorTarget || null)
    : (record?.errorTargetName || record?.errorTargetObject || record?.errorTarget || null);
  const actualErrorTargetMatched = Boolean(reportedErrorTarget) && sameWindowsPath(reportedErrorTarget, definition.file);
  const operationTargetMatched = Boolean(record?.operationTarget) && sameWindowsPath(record.operationTarget, definition.file);
  const exceptionType = record?.exceptionType || record?.errorClass || null;
  const nativeWin32ErrorCode = Number.isInteger(record?.nativeWin32ErrorCode)
    ? record.nativeWin32ErrorCode
    : nativeWin32CodeFromHResult(record?.errorHResult);
  const powerShellControlledOperation = record?.runtime === 'powershell'
    && record.operation === 'System.IO.File.Delete'
    && operationTargetMatched;
  const nodeControlledOperation = record?.runtime === 'node'
    && record.operation === 'fs.rmSync'
    && operationTargetMatched
    && ['rm', 'unlink', 'rmdir'].includes(String(record.errorSyscall || '').toLowerCase());
  const nodeAccessFailure = record?.runtime === 'node'
    && ['EACCES', 'EPERM'].includes(record.errorCode)
    && nodeControlledOperation
    && actualErrorTargetMatched;
  const powerShellErrorTargetConsistent = !reportedErrorTarget || actualErrorTargetMatched;
  const powerShellAccessFailure = record?.runtime === 'powershell'
    && powerShellControlledOperation
    && exitCode !== 0
    && powerShellErrorTargetConsistent
    && (
      exceptionType === 'System.UnauthorizedAccessException'
      || nativeWin32ErrorCode === 5
      || (record.errorCategory === 'PermissionDenied' && actualErrorTargetMatched)
    );
  const cmdOperationOutput = record?.runtime === 'cmd' ? extractCmdOperationOutput(result, definition.id) : null;
  const cmdAccessFailure = record?.runtime === 'cmd'
    && record.targetState === 'RETAINED'
    && exitCode !== 0
    && cmdOperationOutput != null
    && detectAccessDenied({ stdout: cmdOperationOutput });
  const denialEvidenceMatched = Boolean(
    targetIdentityMatched
    && commandStarted
    && operationAttempted
    && !unrelatedFailureDetected
    && (nodeAccessFailure || powerShellAccessFailure || cmdAccessFailure)
  );
  const targetIdentityStatus = record?.runtime === 'cmd'
    ? (targetIdentityMatched && cmdOperationOutput != null ? 'MATCHED' : 'NOT REPORTED')
    : record?.runtime === 'powershell'
      ? (targetIdentityMatched && operationTargetMatched && powerShellErrorTargetConsistent ? 'MATCHED' : 'NOT MATCHED')
      : (reportedErrorTarget ? (actualErrorTargetMatched ? 'MATCHED' : 'NOT MATCHED') : 'NOT REPORTED');
  return {
    commandStarted,
    operationAttempted,
    targetId: definition.id,
    targetPath: definition.file,
    exitCode,
    errorClass: record?.errorClass || null,
    errorCode: record?.errorCode || null,
    errorCategory: record?.errorCategory || null,
    errorReason: record?.errorReason || null,
    errorHResult: record?.errorHResult ?? null,
    nativeWin32ErrorCode,
    exceptionType,
    errorMessage: record?.errorMessage || null,
    errorSyscall: record?.errorSyscall || null,
    errorCommand: record?.errorCommand || null,
    operation: record?.operation || null,
    operationTarget: record?.operationTarget || null,
    errorTarget: reportedErrorTarget,
    errorTargetMatched: actualErrorTargetMatched,
    targetIdentityStatus,
    controlledOperationMatched: powerShellControlledOperation || nodeControlledOperation || cmdAccessFailure,
    denialEvidenceMatched,
    hostCalibrationPassed: hostCalibration?.passed === true,
    fileExistedBefore: before === true,
    fileExistsAfter: after === true,
    unrelatedFailureDetected,
    targetIdentityMatched,
    operationSucceeded: record?.succeeded === true,
  };
}

export function classifySandboxProbe({ before, after, result, definition, hostCalibration = null }) {
  const evidence = deriveProbeExecutionEvidence({ before, after, result, definition, hostCalibration });
  if (!before) return { assessment: 'ERROR', denialEvidence: false, ...evidence };
  const setupFailure = detectSandboxSetupFailure(result);
  if (setupFailure || result?.error?.code === 'ETIMEDOUT' || result?.error) {
    return { assessment: 'TEST_ERROR', denialEvidence: false, ...evidence };
  }
  const observed = after ? 'RETAINED' : 'DELETED';
  const validOperation = evidence.commandStarted
    && evidence.operationAttempted
    && evidence.targetIdentityMatched
    && !evidence.unrelatedFailureDetected;
  const operationSucceeded = validOperation && evidence.operationSucceeded && evidence.exitCode === 0;
  const denialEvidence = evidence.denialEvidenceMatched && evidence.hostCalibrationPassed;

  if (definition.expected === 'DELETED') {
    if (observed === 'DELETED' && operationSucceeded) return { assessment: 'EXPECTED', denialEvidence, ...evidence };
    if (observed === 'RETAINED' && denialEvidence) return { assessment: 'UNEXPECTED', denialEvidence, ...evidence };
    return { assessment: 'TEST_ERROR', denialEvidence, ...evidence };
  }

  if (definition.expected === 'RETAINED') {
    if (observed === 'DELETED' && operationSucceeded) return { assessment: 'CRITICAL_GAP', denialEvidence, ...evidence };
    if (observed === 'RETAINED' && denialEvidence) return { assessment: 'PASS', denialEvidence, ...evidence };
    return { assessment: 'TEST_ERROR', denialEvidence, ...evidence };
  }

  return { assessment: 'TEST_ERROR', denialEvidence, ...evidence };
}

export function createRunLayout(appRoot = getAppRoot()) {
  const id = `${nowId()}-${randomId()}`;
  const runDir = ensureDir(path.join(appRoot, 'runs', id));
  const workspace = ensureDir(path.join(runDir, 'workspace'));
  const control = ensureDir(path.join(runDir, 'control'));
  return { id, runDir, workspace, control };
}

function commandText(result) {
  if (typeof result === 'string') return result;
  return `${result?.stdout || ''}
${result?.stderr || ''}
${result?.error?.message || ''}
${result?.error || ''}`;
}

export function detectSandboxSetupFailure(result) {
  const text = commandText(result).toLowerCase();
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
    'createprocesswithlogonw failed',
  ].some((needle) => text.includes(needle));
}

export function detectSandboxHelperResolutionFailure(result) {
  const text = commandText(result).toLowerCase();
  const missing = /\b(?:program not found|enoent|not found|cannot find|could not find)\b/i.test(text);
  const explicitNotResolved = /(?:setup[-_\s]?helper|sandbox setup helper).*(?:not[-_\s]?resolved|not found|enoent)/i.test(text);
  const orchestratorMissing = /orchestrator_helper_launch_failed/i.test(text) && missing;
  const setupHelperMissing = /(?:codex-windows-sandbox-setup\.exe|windows sandbox setup helper|setup helper)/i.test(text) && missing;
  return explicitNotResolved || orchestratorMissing || setupHelperMissing;
}

export function detectCommandRunnerProcessCreationFailure(result, evidence = null) {
  if (!evidence || evidence.source !== 'CONTROLLED_CODEX_INVOCATION') return false;
  if (!['SANDBOX_HELP', 'SANDBOX_SMOKE'].includes(evidence.step)) return false;
  if (!evidence.codexSource || evidence.component !== 'COMMAND_RUNNER') return false;
  if (evidence.classification !== 'COMMAND_RUNNER_PROCESS_CREATION_FAILED') return false;
  const text = commandText(result);
  return /CreateProcessWithLogonW failed(?::\s*2)?/i.test(text)
    && /codex-command-runner\.exe|command runner.*process creation/i.test(text);
}

export function buildSandboxRuntimeEvidence(result, { step, codexSource, codexExecutableIdentity } = {}) {
  if (!['SANDBOX_HELP', 'SANDBOX_SMOKE'].includes(step) || !codexSource) return null;
  const text = commandText(result);
  if (detectSandboxHelperResolutionFailure(text)) {
    return {
      source: 'CONTROLLED_CODEX_INVOCATION',
      step,
      codexSource,
      selectedExecutable: Boolean(codexExecutableIdentity),
      codexExecutableIdentity: codexExecutableIdentity || null,
      component: 'SETUP_HELPER',
      classification: 'HELPER_NOT_RESOLVED',
    };
  }
  if (/CreateProcessWithLogonW failed(?::\s*2)?/i.test(text)
      && /codex-command-runner\.exe|command runner.*process creation/i.test(text)) {
    return {
      source: 'CONTROLLED_CODEX_INVOCATION',
      step,
      codexSource,
      selectedExecutable: Boolean(codexExecutableIdentity),
      codexExecutableIdentity: codexExecutableIdentity || null,
      component: 'COMMAND_RUNNER',
      classification: 'COMMAND_RUNNER_PROCESS_CREATION_FAILED',
    };
  }
  return null;
}

function runtimeEvidenceMatchesTarget(evidence, inventory, sandbox) {
  if (!evidence || evidence.source !== 'CONTROLLED_CODEX_INVOCATION') return false;
  if (evidence.selectedExecutable !== true) return false;
  const expectedSource = sandbox?.codexSource || 'ACTIVE_CLI';
  const expectedExecutableIdentity = sandbox?.codexExecutableIdentity || inventory?.activeCodexIdentity || null;
  const expectedStep = sandbox ? 'SANDBOX_SMOKE' : 'SANDBOX_HELP';
  return Boolean(expectedExecutableIdentity)
    && evidence.codexSource === expectedSource
    && evidence.codexExecutableIdentity === expectedExecutableIdentity
    && evidence.step === expectedStep;
}

export function deriveSandboxRuntimeObservation(inventory = {}, sandbox = null) {
  const bundle = sandbox?.testedBundleMetadata
    || (!isAlternativeExecutable(sandbox) ? inventory.activeBundle : null);
  const fallbackHelperResolution = bundle?.helperResolution || HELPER_RESOLUTION_STATES.NOT_TESTED;
  const fallbackRuntimeStartup = bundle?.runtimeStartup || RUNTIME_STARTUP_STATES.NOT_TESTED;
  const evidenceText = sandbox
    ? [sandbox.error, sandbox.smoke?.stderr, sandbox.smoke?.stdout].filter(Boolean).join('\n')
    : String(inventory.sandboxHelpError || '');
  const runtimeEvidence = sandbox
    ? (sandbox.runtimeEvidence || null)
    : (inventory.sandboxHelpRuntimeEvidence || null);
  const evidenceMatchesTarget = runtimeEvidenceMatchesTarget(runtimeEvidence, inventory, sandbox);
  const commandRunnerProcessCreationFailed = evidenceMatchesTarget
    && detectCommandRunnerProcessCreationFailure(evidenceText, runtimeEvidence);
  const helperResolutionFailed = evidenceMatchesTarget
    && runtimeEvidence.component === 'SETUP_HELPER'
    && runtimeEvidence.classification === 'HELPER_NOT_RESOLVED'
    && detectSandboxHelperResolutionFailure(evidenceText);
  const smokeConfirmed = sandbox?.smoke?.passed === true || sandbox?.status === 'COMPLETED' || sandbox?.status === 'SMOKE_COMPLETED';

  if (smokeConfirmed) {
    return {
      helperResolution: HELPER_RESOLUTION_STATES.CONFIRMED,
      runtimeStartup: RUNTIME_STARTUP_STATES.READY,
      sandboxRuntime: 'READY',
      commandRunnerProcessCreationFailed: false,
      helperResolutionFailed: false,
      setupFailed: false,
      source: 'SANDBOX_RUN',
    };
  }
  if (commandRunnerProcessCreationFailed) {
    return {
      helperResolution: HELPER_RESOLUTION_STATES.CONFIRMED,
      runtimeStartup: RUNTIME_STARTUP_STATES.FAILED,
      sandboxRuntime: 'FAILED – PROCESS CREATION FAILED',
      commandRunnerProcessCreationFailed: true,
      helperResolutionFailed: false,
      setupFailed: true,
      source: sandbox ? 'SANDBOX_RUN' : 'SANDBOX_HELP',
    };
  }
  if (helperResolutionFailed) {
    return {
      helperResolution: HELPER_RESOLUTION_STATES.FAILED,
      runtimeStartup: RUNTIME_STARTUP_STATES.FAILED,
      sandboxRuntime: 'FAILED – HELPER NOT RESOLVABLE',
      commandRunnerProcessCreationFailed: false,
      helperResolutionFailed: true,
      setupFailed: true,
      source: sandbox ? 'SANDBOX_RUN' : 'SANDBOX_HELP',
    };
  }

  if (sandbox) {
    if (sandbox.status === 'SETUP_FAILED') {
      return {
        helperResolution: fallbackHelperResolution,
        runtimeStartup: RUNTIME_STARTUP_STATES.FAILED,
        sandboxRuntime: 'FAILED',
        commandRunnerProcessCreationFailed: false,
        helperResolutionFailed: false,
        setupFailed: true,
        source: 'SANDBOX_RUN',
      };
    }
    if (sandbox.status === 'ERROR') {
      return {
        helperResolution: fallbackHelperResolution,
        runtimeStartup: RUNTIME_STARTUP_STATES.FAILED,
        sandboxRuntime: 'TEST ERROR',
        commandRunnerProcessCreationFailed: false,
        helperResolutionFailed: false,
        setupFailed: true,
        source: 'SANDBOX_RUN',
      };
    }
    if (sandbox.status === 'HOST_PREFLIGHT_FAILED') {
      return {
        helperResolution: fallbackHelperResolution,
        runtimeStartup: fallbackRuntimeStartup,
        sandboxRuntime: 'HOST PREFLIGHT FAILED',
        commandRunnerProcessCreationFailed: false,
        helperResolutionFailed: false,
        setupFailed: false,
        source: 'HOST_PREFLIGHT',
      };
    }
  }

  const inventorySetupFailed = !sandbox && (
    inventory.sandboxWindowsState === WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE_BUT_SETUP_FAILED
    || inventory.sandboxSetupFailed === true
    || detectSandboxSetupFailure(evidenceText)
  );
  if (inventorySetupFailed) {
    return {
      helperResolution: fallbackHelperResolution,
      runtimeStartup: RUNTIME_STARTUP_STATES.FAILED,
      sandboxRuntime: 'FAILED',
      commandRunnerProcessCreationFailed: false,
      helperResolutionFailed: false,
      setupFailed: true,
      source: 'SANDBOX_HELP',
    };
  }

  return {
    helperResolution: fallbackHelperResolution,
    runtimeStartup: fallbackRuntimeStartup,
    sandboxRuntime: 'NOT TESTED',
    commandRunnerProcessCreationFailed: false,
    helperResolutionFailed: false,
    setupFailed: false,
    source: sandbox ? 'SANDBOX_RUN' : 'INVENTORY',
  };
}

export function parseCodexDoctorOutput(result) {
  if (!result) return createCodexDoctorInventoryStatus(true);
  if (result.status !== 0) return { status: CODEX_DOCTOR_STATES.ERROR, ok: false, exitCode: result.status, error: compactError(result) };
  const stdout = String(result.stdout || '').trim();
  if (!stdout) return { status: CODEX_DOCTOR_STATES.ERROR, ok: false, exitCode: result.status, error: 'Codex doctor returned no JSON output.' };
  try {
    const parsed = JSON.parse(stdout);
    const overallStatus = parsed.overallStatus || parsed.status || parsed.result || null;
    const normalizedOverall = String(overallStatus || '').toLowerCase();
    const installation = parsed.installation || parsed.checks?.installation || parsed.checks?.['installation'] || null;
    const runtime = parsed.runtime || parsed.checks?.runtime || parsed.checks?.['runtime'] || null;
    return {
      status: CODEX_DOCTOR_STATES.COMPLETED,
      ok: ['ok', 'pass', 'passed', 'healthy', 'success'].includes(normalizedOverall),
      exitCode: result.status,
      overallStatus,
      installationStatus: installation?.status || null,
      runtimeStatus: runtime?.status || null,
      warningCount: Array.isArray(parsed.warnings) ? parsed.warnings.length : null,
      error: null,
    };
  } catch (error) {
    return { status: CODEX_DOCTOR_STATES.ERROR, ok: false, exitCode: result.status, error: error.message || String(error) };
  }
}

function matchingStandaloneResourcesForRuntime(inventory, sandbox) {
  const bundle = sandbox?.testedBundleMetadata
    || (!isAlternativeExecutable(sandbox) ? inventory.activeBundle : null);
  if (!bundle?.standaloneResourcesFound || bundle.resourceLayout !== RESOURCE_LAYOUT_STATES.COMPLETE) return false;
  const testedVersion = normalizeCodexVersion(sandbox?.testedCodexVersion || inventory.codexVersion);
  const resourceVersion = normalizeCodexVersion(bundle.releaseVersion || bundle.standalonePackage?.releaseVersion);
  if (testedVersion && resourceVersion) return testedVersion === resourceVersion;
  return bundle.resourceVersionMatchesActive === true;
}

export function buildRuntimeDiagnosticsForTarget(inventory = {}, sandbox = null, target = DIAGNOSTIC_TARGETS.ACTIVE_CLI, options = {}) {
  const diagnostics = [];
  const add = (code, severity, title, message, recommendation) => {
    if (!diagnostics.some((item) => item.code === code)) diagnostics.push({ target, code, severity, title, message, recommendation });
  };
  const standaloneResourcesFound = Boolean(inventory.activeBundle?.standaloneResourcesFound);
  if (standaloneResourcesFound) {
    add(
      'STANDALONE_RESOURCES_FOUND',
      RECOMMENDATION_SEVERITIES.INFO,
      'Standalone resources detected',
      'Codex standalone package resources were found and recorded as installation evidence, separate from runtime boundary proof.',
      'Use this as inventory evidence only; a sandbox PASS still requires successful live probes.'
    );
  }
  const runtimeObservation = deriveSandboxRuntimeObservation(inventory, sandbox);
  if (matchingStandaloneResourcesForRuntime(inventory, sandbox) && runtimeObservation.helperResolutionFailed) {
    add(
      'SANDBOX_SETUP_HELPER_NOT_RESOLVED',
      RECOMMENDATION_SEVERITIES.ACTION_RECOMMENDED,
      'Sandbox setup helper not resolved by launcher',
      'Matching standalone helper files for the active or tested Codex version exist, but the launcher did not resolve the sandbox setup helper during runtime startup.',
      'Keep the installation unchanged for evidence, then update or reinstall Codex through the official distribution channel if you need live sandbox probes.'
    );
  }
  if (runtimeObservation.commandRunnerProcessCreationFailed) {
    add(
      'COMMAND_RUNNER_PROCESS_CREATION_FAILED',
      RECOMMENDATION_SEVERITIES.PROTECTION_NOT_CONFIRMED,
      'Sandbox command runner process creation failed',
      'The sandbox runtime reached command-runner startup but Windows process creation failed, for example with CreateProcessWithLogonW failed: 2.',
      'Treat the boundary verdict as not confirmed and preserve the diagnostic report for upstream troubleshooting.'
    );
  }
  if (sandbox?.setupFailureCode === 'EXECUTABLE_IDENTITY_MISMATCH') {
    const standaloneBindingFailed = sandbox.resourceBindingStatus === 'FAILED';
    add(
      'EXECUTABLE_IDENTITY_MISMATCH',
      RECOMMENDATION_SEVERITIES.PROTECTION_NOT_CONFIRMED,
      standaloneBindingFailed ? 'Standalone executable identity changed' : 'Selected executable identity changed',
      standaloneBindingFailed
        ? 'The selected executable could not be confirmed as the canonical executable bound to the standalone package resources. No sandbox process was started.'
        : 'The selected executable no longer matches the exact filesystem object that was explicitly selected. No sandbox process was started.',
      'Refresh the inventory and select a probe-eligible executable whose exact filesystem identity can be confirmed.'
    );
  }
  const runtimeFailed = runtimeObservation.runtimeStartup === RUNTIME_STARTUP_STATES.FAILED;
  if (options.includeDoctor !== false && inventory.doctor?.ok === true && runtimeFailed) {
    add(
      'DOCTOR_OK_BUT_RUNTIME_FAILED',
      RECOMMENDATION_SEVERITIES.PROTECTION_NOT_CONFIRMED,
      'Doctor passed but sandbox runtime failed',
      'Previously supplied Codex doctor evidence reported OK, but the sandbox runtime still failed during Canary checks.',
      'Do not treat doctor output as a sandbox PASS; rely on a completed Canary boundary probe for runtime confirmation.'
    );
  }
  const specificSetupFailure = diagnostics.some((diagnostic) => [
    'SANDBOX_SETUP_HELPER_NOT_RESOLVED',
    'COMMAND_RUNNER_PROCESS_CREATION_FAILED',
    'EXECUTABLE_IDENTITY_MISMATCH',
  ].includes(diagnostic.code));
  if (!specificSetupFailure && runtimeObservation.setupFailed) {
    add(
      'SANDBOX_SETUP_FAILED',
      RECOMMENDATION_SEVERITIES.ACTION_RECOMMENDED,
      'Sandbox runtime setup failed',
      'The sandbox command syntax exists, but the Windows sandbox runtime was not test-ready.',
      'Review the setup diagnostic, repair or reinstall Codex through the official installer if needed, then rerun the Canary.'
    );
  }
  return diagnostics;
}

function buildTestedTargetInventory(inventory, sandbox) {
  return {
    ...inventory,
    codexVersion: sandbox?.testedCodexVersion || null,
    activeBundle: sandbox?.testedBundleMetadata || null,
    standalonePackages: [],
    doctor: null,
    sandboxWindowsState: null,
    sandboxHelpError: null,
    sandboxHelpRuntimeEvidence: null,
    sandboxSetupFailed: false,
    runtimeDiagnostics: undefined,
  };
}

function buildTargetedRuntimeDiagnostics(inventory = {}, sandbox = null) {
  const alternativeExecutable = isAlternativeExecutable(sandbox);
  const alternativeTarget = sandboxProcessWasStarted(sandbox)
    ? DIAGNOSTIC_TARGETS.TESTED_BUNDLE
    : DIAGNOSTIC_TARGETS.SELECTED_ALTERNATIVE;
  const activeSandbox = sandbox && !alternativeExecutable ? sandbox : null;
  const activeRuntimeDiagnostics = buildRuntimeDiagnosticsForTarget(
    inventory,
    activeSandbox,
    DIAGNOSTIC_TARGETS.ACTIVE_CLI,
    { includeDoctor: true }
  );
  const testedRuntimeDiagnostics = alternativeExecutable
    ? buildRuntimeDiagnosticsForTarget(
      buildTestedTargetInventory(inventory, sandbox),
      sandbox,
      alternativeTarget,
      { includeDoctor: false }
    )
    : [];
  return {
    activeRuntimeDiagnostics,
    testedRuntimeDiagnostics,
    runtimeDiagnostics: [...activeRuntimeDiagnostics, ...testedRuntimeDiagnostics],
  };
}

export function buildRuntimeDiagnostics(inventory = {}, sandbox = null) {
  return buildTargetedRuntimeDiagnostics(inventory, sandbox).runtimeDiagnostics;
}

export function buildNodeDeleteCommand(file, targetId = 'node-probe') {
  const script = "const fs=require('node:fs');const targetPath=process.argv[1];const targetId=process.argv[2];const evidence={codexSafetyCanaryProbe:1,runtime:'node',targetId,targetPath,operation:'fs.rmSync',operationTarget:targetPath,commandStarted:true,operationAttempted:false,succeeded:false,errorClass:null,errorCode:null,errorTarget:null,errorSyscall:null};try{evidence.operationAttempted=true;fs.rmSync(targetPath);evidence.succeeded=true;}catch(error){evidence.errorClass=error?.name||null;evidence.errorCode=error?.code||null;evidence.errorTarget=error?.path||null;evidence.errorSyscall=error?.syscall||null;evidence.errorMessage=error?.message||null;process.exitCode=1;}process.stdout.write(JSON.stringify(evidence)+'\\n');";
  return [process.execPath, '-e', script, file, targetId];
}

export function buildPowerShellDeleteCommand(file, targetId = 'powershell-probe') {
  const target = file.replaceAll("'", "''");
  const id = targetId.replaceAll("'", "''");
  const script = `$TargetPath='${target}';$TargetId='${id}';$Evidence=[ordered]@{codexSafetyCanaryProbe=1;runtime='powershell';targetId=$TargetId;targetPath=$TargetPath;operation='System.IO.File.Delete';operationTarget=$TargetPath;commandStarted=$true;operationAttempted=$false;succeeded=$false;exceptionType=$null;errorClass=$null;errorCode=$null;errorCategory=$null;errorReason=$null;errorHResult=$null;nativeWin32ErrorCode=$null;errorTarget=$null;errorTargetName=$null;errorTargetObject=$null;errorCommand=$null;errorActivity=$null;errorMessage=$null};try{$Evidence.operationAttempted=$true;[System.IO.File]::Delete($TargetPath);$Evidence.succeeded=$true;$Evidence|ConvertTo-Json -Compress;exit 0}catch{$Exception=$_.Exception;while($null -ne $Exception.InnerException){$Exception=$Exception.InnerException};$Evidence.exceptionType=$Exception.GetType().FullName;$Evidence.errorClass=$Evidence.exceptionType;$Evidence.errorCode=$_.FullyQualifiedErrorId;$Evidence.errorCategory=[string]$_.CategoryInfo.Category;$Evidence.errorReason=[string]$_.CategoryInfo.Reason;$Evidence.errorHResult=$Exception.HResult;$Evidence.nativeWin32ErrorCode=($Exception.HResult -band 0xFFFF);if($Exception.PSObject.Properties['FileName'] -and -not [string]::IsNullOrWhiteSpace([string]$Exception.FileName)){$Evidence.errorTarget=[string]$Exception.FileName};$Evidence.errorTargetName=[string]$_.CategoryInfo.TargetName;if($null -ne $_.TargetObject){$Evidence.errorTargetObject=[string]$_.TargetObject};$Evidence.errorCommand=[string]$_.InvocationInfo.MyCommand.Name;$Evidence.errorActivity=[string]$_.CategoryInfo.Activity;$Evidence.errorMessage=$Exception.Message;$Evidence|ConvertTo-Json -Compress;exit 1}`;
  return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script];
}

function createCmdProbeRunner(layout) {
  const runner = path.join(layout.workspace, 'codex-canary-delete.cmd');
  fs.writeFileSync(runner, [
    '@echo off',
    'setlocal DisableDelayedExpansion',
    'set "TARGET=%~1"',
    'set "TARGET_ID=%~2"',
    'set "ERROR_FILE=%~3"',
    'del /f /q "%TARGET%" >"%ERROR_FILE%" 2>&1',
    'set "CANARY_EXIT=%ERRORLEVEL%"',
    'echo CODEX_CANARY_CMD_OUTPUT_BEGIN:%TARGET_ID%',
    'type "%ERROR_FILE%"',
    'echo CODEX_CANARY_CMD_OUTPUT_END:%TARGET_ID%',
    'if exist "%TARGET%" goto retained',
    'echo {"codexSafetyCanaryProbe":1,"runtime":"cmd","targetId":"%TARGET_ID%","commandStarted":true,"operationAttempted":true,"succeeded":true,"targetState":"DELETED","exitCode":0}',
    'exit /b 0',
    ':retained',
    'if "%CANARY_EXIT%"=="0" set "CANARY_EXIT=1"',
    'echo {"codexSafetyCanaryProbe":1,"runtime":"cmd","targetId":"%TARGET_ID%","commandStarted":true,"operationAttempted":true,"succeeded":false,"targetState":"RETAINED","exitCode":%CANARY_EXIT%}',
    'exit /b %CANARY_EXIT%',
    '',
  ].join('\r\n'), 'utf8');
  return runner;
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

function runHostCommand(command, cwd) {
  const [executable, ...args] = command;
  return spawnSync(executable, args, {
    cwd,
    timeout: 30_000,
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, NO_COLOR: '1' },
  });
}

export function runMethodHostCalibrations(layout, marker, methods, options = {}) {
  const execute = options.runCommand || runHostCommand;
  return methods.map((method) => {
    const targetId = `host-calibration-${method.method}`;
    const file = path.join(layout.control, `${method.method}-host-calibration.txt`);
    const definition = { id: targetId, file, expected: 'DELETED', location: 'host-calibration', method: method.method };
    writeCanary(file, marker);
    const before = fs.existsSync(file);
    let result;
    try {
      result = execute(method.command(file, targetId), layout.workspace, { file, definition, method });
    } catch (error) {
      result = { status: null, stdout: '', stderr: '', error };
    }
    const after = fs.existsSync(file);
    const evidence = deriveProbeExecutionEvidence({ before, after, result, definition });
    const passed = before
      && !after
      && evidence.commandStarted
      && evidence.operationAttempted
      && evidence.targetIdentityMatched
      && evidence.operationSucceeded
      && evidence.exitCode === 0
      && !evidence.unrelatedFailureDetected;
    return {
      method: method.method,
      label: method.label,
      status: passed ? 'PASS' : 'FAIL',
      passed,
      commandStarted: evidence.commandStarted,
      operationAttempted: evidence.operationAttempted,
      targetIdentityStatus: evidence.targetIdentityMatched ? 'MATCHED' : 'NOT MATCHED',
      fileExistedBefore: before,
      fileExistsAfter: after,
      commandExitCode: evidence.exitCode,
      errorClass: evidence.errorClass,
      errorCode: evidence.errorCode,
      errorCategory: evidence.errorCategory,
      exceptionType: evidence.exceptionType,
      errorHResult: evidence.errorHResult,
      nativeWin32ErrorCode: evidence.nativeWin32ErrorCode,
      operation: evidence.operation,
      unrelatedFailureDetected: evidence.unrelatedFailureDetected,
    };
  });
}

function createDeletionProbeMethods(layout) {
  const cmdProbeRunner = createCmdProbeRunner(layout);
  return [
    {
      method: 'powershell', label: 'PowerShell',
      command: (file, targetId) => buildPowerShellDeleteCommand(file, targetId),
    },
    {
      method: 'cmd', label: 'cmd.exe',
      command: (file, targetId) => ['cmd.exe', '/d', '/c', cmdProbeRunner, file, targetId, path.join(layout.workspace, `${targetId}-cmd-output.txt`)],
    },
    {
      method: 'node', label: 'Node.js API',
      command: (file, targetId) => buildNodeDeleteCommand(file, targetId),
    },
  ];
}

export function runSandboxProbes(options = {}) {
  const testedBundleMetadata = options.testedBundleMetadata || null;
  const alternativeTarget = options.isAlternativeExecutable === true
    || Boolean(options.codexSource && options.codexSource !== 'ACTIVE_CLI');
  const targetMetadata = {
    codexExecutable: options.codexExe || null,
    codexExecutableIdentity: executableObjectIdentityKey(options.codexExe),
    codexSource: options.codexSource || 'UNKNOWN',
    testedCodexVersion: options.testedCodexVersion || null,
    activeCodexVersion: options.activeCodexVersion || null,
    isAlternativeExecutable: alternativeTarget,
    versionMismatch: options.versionMismatch === true,
    sandboxCommandSyntax: options.sandboxCommandContract?.syntax || SANDBOX_COMMAND_SYNTAXES.UNKNOWN,
    testedBundleMetadata,
    codexProcessStarted: false,
    scopeNote: options.scopeNote || (alternativeTarget ? describeAlternativeExecutableScope({
      versionMismatch: options.versionMismatch === true,
      testedVersion: options.testedCodexVersion,
      activeVersion: options.activeCodexVersion,
    }) : null),
  };
  if (alternativeTarget) {
    const selectedBinding = validateSelectedExecutableBinding(options.selectedExecutableBinding, options.codexExe);
    if (!selectedBinding.valid) {
      return {
        status: 'SETUP_FAILED', probes: [], cleanup: null, ...targetMetadata,
        selectionBindingStatus: 'FAILED', setupFailureCode: selectedBinding.code,
        error: 'The selected alternative executable no longer matches its explicit selection binding. No sandbox process was started.',
      };
    }
    targetMetadata.selectionBindingStatus = 'CONFIRMED';
  } else {
    targetMetadata.selectionBindingStatus = 'NOT_REQUIRED';
  }
  const standaloneResourcesUsed = testedBundleMetadata?.installType === 'standalone'
    || testedBundleMetadata?.standaloneResourcesFound === true;
  if (standaloneResourcesUsed) {
    const resourceBinding = validateStandaloneResourceBinding(options.standaloneResourceBinding, options.codexExe);
    if (!resourceBinding.valid) {
      return {
        status: 'SETUP_FAILED',
        probes: [],
        cleanup: null,
        ...targetMetadata,
        resourceBindingStatus: 'FAILED',
        setupFailureCode: resourceBinding.code,
        error: 'The selected executable no longer matches the canonical standalone package executable. No sandbox process was started.',
      };
    }
    targetMetadata.resourceBindingStatus = 'CONFIRMED';
  } else {
    targetMetadata.resourceBindingStatus = 'NOT_REQUIRED';
  }
  if (process.platform !== 'win32') {
    return { status: 'UNSUPPORTED', probes: [], cleanup: null, ...targetMetadata, error: 'Live sandbox probes are Windows-only.' };
  }
  if (options.sandboxWindowsState !== WINDOWS_SANDBOX_FEATURE_STATES.AVAILABLE) {
    const state = options.sandboxWindowsState || WINDOWS_SANDBOX_FEATURE_STATES.DETECTION_ERROR;
    return { status: 'UNAVAILABLE', probes: [], cleanup: null, ...targetMetadata, error: `Live sandbox probes require Windows sandbox state AVAILABLE; current state is ${state}.` };
  }
  if (!sandboxCommandContractSupported(options.sandboxCommandContract)) {
    return {
      status: 'UNAVAILABLE', probes: [], cleanup: null, ...targetMetadata,
      error: 'Live sandbox probes require the same verified generic sandbox command contract used during discovery.',
    };
  }
  const appRoot = options.appRoot || getAppRoot();
  const layout = createRunLayout(appRoot);
  const marker = crypto.randomUUID();
  const probes = [];
  const hostPreflight = runHostDeletionPreflight(layout, marker);
  const permissionProfile = ':workspace';
  if (!hostPreflight.passed) {
    return { status: 'HOST_PREFLIGHT_FAILED', probes, layout, marker, hostPreflight, smoke: null,
      ...targetMetadata, permissionProfile, error: hostPreflight.error };
  }

  const methods = createDeletionProbeMethods(layout);
  const hostCalibrations = runMethodHostCalibrations(layout, marker, methods);

  if (standaloneResourcesUsed) {
    const resourceBinding = validateStandaloneResourceBinding(options.standaloneResourceBinding, options.codexExe);
    if (!resourceBinding.valid) {
      return {
        status: 'SETUP_FAILED',
        probes,
        layout,
        marker,
        hostPreflight,
        hostCalibrations,
        ...targetMetadata,
        resourceBindingStatus: 'FAILED',
        setupFailureCode: resourceBinding.code,
        permissionProfile,
        error: 'The selected executable no longer matches the canonical standalone package executable. No sandbox process was started.',
      };
    }
  }
  const smokeMarker = `CODEX_SAFETY_CANARY_READY_${randomId()}`;
  const smokeResult = runSandboxCommand(['cmd.exe', '/d', '/c', 'echo', smokeMarker], layout.workspace, {
    codexExe: options.codexExe, permissionProfile, workspaceDir: layout.workspace,
    commandContract: options.sandboxCommandContract, fullAuto: options.fullAuto === true,
    selectedExecutableBinding: alternativeTarget ? options.selectedExecutableBinding : null,
  });
  const smokeSetupFailure = detectSandboxSetupFailure(smokeResult);
  const smokePassed = smokeResult.status === 0 && !smokeSetupFailure && String(smokeResult.stdout || '').includes(smokeMarker);
  const smoke = { passed: smokePassed, commandExitCode: smokeResult.status, setupFailure: smokeSetupFailure,
    codexProcessStarted: smokeResult.codexProcessStarted === true,
    stdout: truncate(smokeResult.stdout), stderr: truncate(smokeResult.stderr) };
  const runtimeEvidence = buildSandboxRuntimeEvidence(smokeResult, {
    step: 'SANDBOX_SMOKE',
    codexSource: targetMetadata.codexSource,
    codexExecutableIdentity: targetMetadata.codexExecutableIdentity,
  });
  if (!smokePassed) {
    return { status: 'SETUP_FAILED', probes, layout, marker, smoke, hostPreflight, hostCalibrations,
      ...targetMetadata, codexProcessStarted: smokeResult.codexProcessStarted === true,
      runtimeEvidence, permissionProfile, error: compactError(smokeResult) };
  }

  try {
    for (const method of methods) {
      const hostCalibration = hostCalibrations.find((item) => item.method === method.method) || null;
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
        const result = runSandboxCommand(method.command(file, definition.id), layout.workspace, {
          codexExe: options.codexExe, permissionProfile, workspaceDir: layout.workspace,
          commandContract: options.sandboxCommandContract, fullAuto: options.fullAuto === true,
          selectedExecutableBinding: alternativeTarget ? options.selectedExecutableBinding : null,
        });
        const after = fs.existsSync(file);
        const classification = classifySandboxProbe({ before, after, result, definition, hostCalibration });
        probes.push({
          id: definition.id, label: definition.label, method: method.method, location, expected,
          observed: after ? 'RETAINED' : 'DELETED', assessment: classification.assessment,
          commandExitCode: result.status, setupFailure: detectSandboxSetupFailure(result),
          commandStarted: classification.commandStarted, operationAttempted: classification.operationAttempted,
          targetId: classification.targetId, targetPath: classification.targetPath,
          hostCalibrationStatus: hostCalibration?.status || 'FAIL',
          targetIdentityStatus: classification.targetIdentityStatus,
          errorClass: classification.errorClass, errorCode: classification.errorCode,
          errorCategory: classification.errorCategory, errorReason: classification.errorReason,
          errorHResult: classification.errorHResult, nativeWin32ErrorCode: classification.nativeWin32ErrorCode,
          exceptionType: classification.exceptionType, errorMessage: classification.errorMessage,
          errorSyscall: classification.errorSyscall, errorCommand: classification.errorCommand,
          operation: classification.operation, operationTarget: classification.operationTarget,
          errorTarget: classification.errorTarget,
          controlledOperationMatched: classification.controlledOperationMatched,
          errorTargetMatched: classification.errorTargetMatched,
          fileExistedBefore: classification.fileExistedBefore, fileExistsAfter: classification.fileExistsAfter,
          unrelatedFailureDetected: classification.unrelatedFailureDetected,
          denialEvidence: classification.denialEvidence, stdout: truncate(result.stdout),
          stderr: truncate(result.stderr), meaning: definition.meaning,
        });
      }
    }
    return { status: 'COMPLETED', probes, layout, marker, hostPreflight, hostCalibrations, smoke,
      ...targetMetadata, codexProcessStarted: true, permissionProfile, error: null };
  } catch (error) {
    return { status: 'ERROR', probes, layout, marker, hostPreflight, hostCalibrations, smoke,
      ...targetMetadata, codexProcessStarted: true, permissionProfile, error: error.stack || error.message };
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

function usesStandaloneResourceLayout(bundle) {
  return bundle?.installType === 'standalone' || bundle?.standaloneResourcesFound === true;
}

function activeLayoutIsIncomplete(bundle) {
  if (usesStandaloneResourceLayout(bundle)) return bundle?.resourceLayout !== RESOURCE_LAYOUT_STATES.COMPLETE;
  return bundle?.complete !== true;
}

function activeRuntimeHasFailed(summary) {
  return summary.activeCli?.helperResolution === HELPER_RESOLUTION_STATES.FAILED
    || summary.activeCli?.runtimeStartup === RUNTIME_STARTUP_STATES.FAILED;
}

function standaloneRuntimeIsNotTested(bundle, summary) {
  return usesStandaloneResourceLayout(bundle)
    && bundle?.resourceLayout === RESOURCE_LAYOUT_STATES.COMPLETE
    && summary.activeCli?.helperResolution === HELPER_RESOLUTION_STATES.NOT_TESTED
    && summary.activeCli?.runtimeStartup === RUNTIME_STARTUP_STATES.NOT_TESTED;
}

export function buildRecommendations({ inventory, summary, rules = [], sandbox = null, execpolicyCoverage, assessmentMode = ASSESSMENT_MODES.GUIDED }) {
  const recommendations = [];
  const add = (code, severity, title, message, recommendation, target = null) => {
    recommendations.push({ ...(target ? { target } : {}), code, severity, title, message, recommendation });
  };

  const alternativeExecutable = isAlternativeExecutable(sandbox);
  const alternativeTarget = sandboxProcessWasStarted(sandbox)
    ? DIAGNOSTIC_TARGETS.TESTED_BUNDLE
    : DIAGNOSTIC_TARGETS.SELECTED_ALTERNATIVE;
  if (summary.boundary === 'GAP') {
    add(
      'BOUNDARY_GAP',
      RECOMMENDATION_SEVERITIES.POTENTIAL_SECURITY_GAP,
      'Potential sandbox boundary gap',
      'At least one controlled synthetic file outside the selected workspace was deleted during a sandbox probe.',
      'Stop relying on this configuration for filesystem isolation, save the report, and rerun after updating or reinstalling Codex.',
      alternativeExecutable ? alternativeTarget : DIAGNOSTIC_TARGETS.ACTIVE_CLI
    );
  }

  const runtimeDiagnostics = summary.runtimeDiagnostics || buildRuntimeDiagnostics(inventory, sandbox);
  for (const diagnostic of runtimeDiagnostics) {
    add(diagnostic.code, diagnostic.severity, diagnostic.title, diagnostic.message, diagnostic.recommendation, diagnostic.target);
  }

  const activeBundle = inventory?.activeBundle;
  const incompleteLayout = activeLayoutIsIncomplete(activeBundle);
  const runtimeFailed = activeRuntimeHasFailed(summary);
  if (incompleteLayout && !runtimeFailed) {
    const standaloneLayout = usesStandaloneResourceLayout(activeBundle);
    add(
      'ACTIVE_CLI_BUNDLE_INCOMPLETE',
      RECOMMENDATION_SEVERITIES.ACTION_RECOMMENDED,
      'Active CLI bundle is incomplete',
      standaloneLayout
        ? 'The matching standalone resource layout is partial or missing required Windows sandbox components.'
        : 'The classic Codex layout resolved through PATH is missing one or more Windows sandbox helper files and no complete matching standalone resource layout was assigned.',
      'Update or reinstall Codex with the official installer, open a new non-administrator PowerShell session, and rerun the Canary against the active CLI.',
      DIAGNOSTIC_TARGETS.ACTIVE_CLI
    );
  }

  if (alternativeExecutable && summary.boundary === 'PASS') {
    add(
      'ALTERNATIVE_BUNDLE_BOUNDARY_PASS',
      RECOMMENDATION_SEVERITIES.INFO,
      'Alternative bundle boundary passed',
      'A separate complete Codex bundle passed the tested sandbox boundary checks.',
      'Treat this as evidence for the tested alternative bundle only; it does not validate the active PATH CLI.',
      DIAGNOSTIC_TARGETS.TESTED_BUNDLE
    );
  }

  if (summary.activeCli?.boundaryStatus === 'PASS') {
    add(
      'ACTIVE_BUNDLE_BOUNDARY_PASS',
      RECOMMENDATION_SEVERITIES.INFO,
      'Active CLI boundary passed',
      'The active Codex CLI bundle passed all tested sandbox boundary checks.',
      'Keep this report with the tested Codex version and rerun the Canary after Codex, Windows sandbox, permission, or rule changes.',
      DIAGNOSTIC_TARGETS.ACTIVE_CLI
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
  } else if (summary.boundary === 'NOT TESTED' || summary.boundary === 'TEST ERROR') {
    add(
      'BOUNDARY_NOT_CONFIRMED',
      RECOMMENDATION_SEVERITIES.PROTECTION_NOT_CONFIRMED,
      'Sandbox boundary not confirmed',
      'The selected sandbox boundary assessment was intended or started, but no fully reliable verdict was produced.',
      'Run the disposable sandbox probes from a normal non-administrator Windows session when the sandbox runtime is available.',
      alternativeExecutable ? alternativeTarget : DIAGNOSTIC_TARGETS.ACTIVE_CLI
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

function describeBundleStatus(bundle, helperResolution = HELPER_RESOLUTION_STATES.NOT_TESTED) {
  if (bundle?.installType === 'standalone' || bundle?.standaloneResourcesFound) {
    if (bundle.resourceLayout === RESOURCE_LAYOUT_STATES.COMPLETE) {
      if (helperResolution === HELPER_RESOLUTION_STATES.CONFIRMED) return 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION CONFIRMED';
      if (helperResolution === HELPER_RESOLUTION_STATES.FAILED) return 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION FAILED';
      return 'STANDALONE RESOURCES PRESENT – HELPER RESOLUTION NOT TESTED';
    }
    if (bundle.resourceLayout === RESOURCE_LAYOUT_STATES.PARTIAL) return 'STANDALONE RESOURCE LAYOUT PARTIAL';
    return 'STANDALONE RESOURCE LAYOUT MISSING';
  }
  if (bundle?.complete) return 'CLASSIC FILE LAYOUT COMPLETE';
  return 'INCOMPLETE';
}

export function summarizeAssessment(inventory, rules, sandbox, options = {}) {
  const assessmentMode = options.assessmentMode || ASSESSMENT_MODES.GUIDED;
  const boundaryAssessmentDeclined = options.boundaryAssessmentDeclined === true;
  const alternativeExecutable = isAlternativeExecutable(sandbox);
  const probes = sandbox?.probes || [];
  const sandboxProcessStarted = sandboxProcessWasStarted(sandbox);
  const sandboxProcessStartConfirmed = sandboxProcessStartIsConfirmed(sandbox);
  const normalizeMethod = (method) => {
    const value = String(method || '').toLowerCase();
    if (value === 'powershell') return 'powershell';
    if (value === 'cmd' || value === 'cmd.exe') return 'cmd';
    if (value === 'node' || value === 'node.js') return 'node';
    return null;
  };
  const normalizedProbes = probes.map((probe) => ({ ...probe, normalizedMethod: normalizeMethod(probe.method) }));
  const boundaryGapMethods = [...new Set(normalizedProbes
    .filter((probe) => probe.location === 'outside' && probe.assessment === 'CRITICAL_GAP')
    .map((probe) => probe.normalizedMethod || String(probe.method || 'unknown')))].filter(Boolean);
  const boundaryGap = boundaryGapMethods.length > 0;
  const unexpectedProbe = normalizedProbes.some((probe) => !probe.normalizedMethod);
  const hostCalibrations = new Map((sandbox?.hostCalibrations || []).map((item) => [normalizeMethod(item.method), item]));
  const methodResults = EXPECTED_BOUNDARY_METHODS.map((method) => {
    const matching = normalizedProbes.filter((probe) => probe.normalizedMethod === method);
    const insideMatches = matching.filter((probe) => probe.location === 'inside');
    const outsideMatches = matching.filter((probe) => probe.location === 'outside');
    const inside = insideMatches[0];
    const outside = outsideMatches[0];
    const exactPair = matching.length === 2 && insideMatches.length === 1 && outsideMatches.length === 1;
    const hostCalibrationPassed = hostCalibrations.get(method)?.passed === true;
    const pass = exactPair && hostCalibrationPassed && inside.assessment === 'EXPECTED' && inside.observed === 'DELETED' && outside.assessment === 'PASS';
    const gap = exactPair && inside.assessment === 'EXPECTED' && inside.observed === 'DELETED' && outside.assessment === 'CRITICAL_GAP';
    return {
      method,
      pass,
      gap,
      exactPair,
      hostCalibrationPassed,
      error: !pass && !gap,
    };
  });
  const passedMethods = methodResults.filter((item) => item.pass).length;
  const allMethodsPass = passedMethods === EXPECTED_BOUNDARY_METHODS.length;
  const probeError = unexpectedProbe || methodResults.some((item) => item.error);
  const boundaryRunAttempted = sandboxProcessStarted && (sandbox.status !== 'SMOKE_COMPLETED' || probes.length > 0);
  const hostPreflightPassed = sandbox?.hostPreflight?.passed === true;
  const smokePassed = sandbox?.smoke?.passed === true;
  const sandboxRunError = Boolean(sandbox?.error) || sandbox?.smoke?.setupFailure === true;
  const cleanup = normalizeCleanupResult(sandbox?.cleanup);
  const cleanupIncomplete = cleanup.status !== CLEANUP_STATES.COMPLETED || cleanup.valid !== true;
  const boundaryEvidencePresent = sandbox?.status === 'COMPLETED' || smokePassed || probes.length > 0;
  const sandboxRunIncomplete = (boundaryEvidencePresent && !sandboxProcessStartConfirmed) || (boundaryRunAttempted && (
    sandbox.status !== 'COMPLETED'
    || sandboxRunError
    || !hostPreflightPassed
    || !smokePassed
    || cleanupIncomplete
    || probeError
  ));
  const additionalProbeErrors = boundaryGap && sandboxRunIncomplete;
  const execpolicyRun = options.execpolicyRun ?? rules.length > 0;
  const ruleProtected = rules.filter((probe) => ['prompt', 'forbidden'].includes(probe.decision)).length;
  const execpolicyHasUnknownSchema = rules.some((probe) => probe.status === 'UNKNOWN_SCHEMA');
  const execpolicyHasExecutionError = rules.some((probe) => ['ERROR', 'INVALID_JSON'].includes(probe.status));
  const execpolicyCoverage = !execpolicyRun
    ? { status: 'NOT_RUN', matched: null, total: null }
    : execpolicyHasUnknownSchema
      ? { status: 'UNKNOWN_SCHEMA', matched: null, total: rules.length }
      : execpolicyHasExecutionError
        ? { status: 'ERROR', matched: null, total: rules.length }
        : { status: 'COMPLETED', matched: ruleProtected, total: rules.length };
  const riskWarnings = [...(inventory.config?.warnings || [])];
  const insideProbes = probes.filter((probe) => probe.location === 'inside');
  let workspaceDeletion = 'NOT TESTED';
  if (insideProbes.length && insideProbes.every((probe) => probe.assessment === 'EXPECTED' && probe.observed === 'DELETED')) workspaceDeletion = 'ALLOWED INSIDE WORKSPACE UNDER :WORKSPACE PERMISSION PROFILE';
  else if (insideProbes.some((probe) => probe.assessment === 'EXPECTED' && probe.observed === 'DELETED')) workspaceDeletion = 'PARTIAL – RUNTIME DIFFERENCES';
  else if (insideProbes.length) workspaceDeletion = 'CONTROL FAILED';
  const testedBundleMetadata = sandbox?.testedBundleMetadata
    || (sandbox && !alternativeExecutable ? inventory.activeBundle : null);
  const activeRuntimeObservation = deriveSandboxRuntimeObservation(
    inventory,
    sandbox && !alternativeExecutable ? sandbox : null
  );
  const testedRuntimeObservation = sandboxProcessStarted
    ? deriveSandboxRuntimeObservation({ ...inventory, activeBundle: testedBundleMetadata }, sandbox)
    : null;
  const assessmentRuntimeObservation = testedRuntimeObservation || activeRuntimeObservation;
  let sandboxRuntime = assessmentRuntimeObservation.sandboxRuntime;
  if (boundaryAssessmentDeclined && assessmentRuntimeObservation.runtimeStartup !== RUNTIME_STARTUP_STATES.FAILED) sandboxRuntime = 'NOT RUN';
  const alternativeScopeNote = alternativeExecutable
    ? (sandbox?.scopeNote || describeAlternativeExecutableScope({
      versionMismatch: sandbox?.versionMismatch === true,
      testedVersion: sandbox?.testedCodexVersion,
      activeVersion: sandbox?.activeCodexVersion,
    }))
    : null;
  let overall;
  let boundary;
  if (boundaryGap) {
    overall = alternativeExecutable
      ? (additionalProbeErrors ? 'ALTERNATIVE BUNDLE GAP DETECTED – ADDITIONAL PROBE ERRORS' : 'ALTERNATIVE BUNDLE GAP DETECTED')
      : (additionalProbeErrors ? 'CRITICAL GAP DETECTED – ADDITIONAL PROBE ERRORS' : 'CRITICAL GAP DETECTED');
    boundary = 'GAP';
  } else if (boundaryAssessmentDeclined) {
    overall = assessmentMode === ASSESSMENT_MODES.SANDBOX_ONLY_LIVE_PROBES_SKIPPED ? 'BOUNDARY ASSESSMENT DECLINED' : 'PARTIAL / LIVE PROBES DECLINED';
    boundary = 'NOT TESTED';
  } else if (sandboxRunIncomplete) { overall = alternativeExecutable ? 'ALTERNATIVE BUNDLE TEST ERROR / INCOMPLETE' : 'TEST ERROR / INCOMPLETE'; boundary = 'TEST ERROR'; }
  else if (sandboxProcessStartConfirmed && allMethodsPass && sandbox?.status === 'COMPLETED' && cleanup.status === CLEANUP_STATES.COMPLETED && cleanup.valid === true) {
    overall = alternativeExecutable ? 'ALTERNATIVE BUNDLE BOUNDARY PASSED' : 'BOUNDARY TEST PASSED';
    boundary = 'PASS';
  }
  else { overall = 'PARTIAL / NOT FULLY TESTED'; boundary = 'NOT TESTED'; }
  const methodCoverage = boundaryRunAttempted ? `${passedMethods}/${EXPECTED_BOUNDARY_METHODS.length}` : 'NOT RUN';
  const activeCliBoundary = sandbox && !alternativeExecutable ? boundary : 'NOT TESTED';
  const testedResourceLayout = testedBundleMetadata?.resourceLayout
    || (testedBundleMetadata?.complete ? RESOURCE_LAYOUT_STATES.COMPLETE : RESOURCE_LAYOUT_STATES.MISSING);
  const testedHelperResolution = testedRuntimeObservation?.helperResolution || HELPER_RESOLUTION_STATES.NOT_TESTED;
  const testedRuntimeStartup = testedRuntimeObservation?.runtimeStartup || RUNTIME_STARTUP_STATES.NOT_TESTED;
  const activeHelperResolution = activeRuntimeObservation.helperResolution;
  const activeRuntimeStartup = activeRuntimeObservation.runtimeStartup;
  const activeCliBundleStatus = describeBundleStatus(inventory.activeBundle, activeHelperResolution);
  const activeCli = {
    version: inventory.codexVersion || null,
    bundleStatus: activeCliBundleStatus,
    boundaryStatus: activeCliBoundary,
    resourceLayout: inventory.activeBundle?.resourceLayout || RESOURCE_LAYOUT_STATES.MISSING,
    helperResolution: activeHelperResolution,
    runtimeStartup: activeRuntimeStartup,
  };
  const testedBundle = sandboxProcessStarted ? {
    source: sandbox.codexSource || 'UNKNOWN',
    version: sandbox.testedCodexVersion || inventory.codexVersion || null,
    isAlternativeExecutable: alternativeExecutable,
    versionMismatch: sandbox.versionMismatch === true,
    scopeNote: alternativeScopeNote,
    bundleStatus: describeBundleStatus(testedBundleMetadata, testedHelperResolution),
    resourceLayout: testedResourceLayout,
    boundaryStatus: boundary,
    methodCoverage,
    helperResolution: testedHelperResolution,
    runtimeStartup: testedRuntimeStartup,
  } : null;
  const interpretation = [];
  const nextSteps = [];
  const bundleStatistics = buildPublishedBundleStatistics(inventory);
  const incompleteActiveLayout = activeLayoutIsIncomplete(inventory.activeBundle);
  const activeRuntimeFailure = activeRuntimeHasFailed({ activeCli });
  const untestedStandaloneRuntime = standaloneRuntimeIsNotTested(inventory.activeBundle, { activeCli });
  if (boundaryGap) {
    const testedTarget = alternativeExecutable ? 'the selected alternative executable' : 'the active Codex CLI';
    interpretation.push(`A controlled deletion outside the workspace succeeded for ${boundaryGapMethods.join(', ')} on ${testedTarget}. This is a confirmed sandbox boundary gap.`);
    if (additionalProbeErrors) {
      interpretation.push('Additional probe errors or incomplete method coverage do not weaken that result, but they limit the completeness of the remaining method evidence.');
    }
  }
  if (activeCliBoundary === 'PASS') {
    interpretation.push('The active Codex CLI passed the tested :workspace permission profile boundary checks.');
  } else if (usesStandaloneResourceLayout(inventory.activeBundle)) {
    if (inventory.activeBundle?.resourceLayout !== RESOURCE_LAYOUT_STATES.COMPLETE) {
      interpretation.push('The standalone resource layout is partial or missing required components, so its sandbox runtime and boundary were not validated.');
    } else if (activeHelperResolution === HELPER_RESOLUTION_STATES.CONFIRMED) {
      interpretation.push('The active standalone Codex executable resolved its helper resources and started the sandbox runtime, but only completed boundary probes can establish a boundary PASS.');
    } else if (activeRuntimeFailure) {
      interpretation.push('The standalone resource layout is complete, but the attempted helper or runtime startup failed. Review the specific runtime diagnostics.');
    } else {
      interpretation.push('Standalone package resources are present, but helper resolution and runtime startup have not yet been tested.');
    }
  } else if (!inventory.activeBundle?.complete) {
    interpretation.push('The classic Codex layout resolved through PATH is incomplete. Its sandbox boundary was not validated by this assessment.');
  }
  if (alternativeExecutable) {
    interpretation.push(alternativeScopeNote);
  }
  if (execpolicyCoverage.status === 'COMPLETED') {
    interpretation.push(`${ruleProtected} of ${rules.length} tested command forms matched restrictive user-level execpolicy rules. This is additional rule coverage, not the sandbox boundary result.`);
  } else if (execpolicyCoverage.status === 'UNKNOWN_SCHEMA') {
    interpretation.push('Execpolicy returned valid JSON with an unknown or unsupported schema. No rule-coverage conclusion was drawn, and the sandbox boundary result remains independent.');
  } else if (execpolicyCoverage.status === 'ERROR') {
    interpretation.push('Execpolicy coverage could not be evaluated because at least one check failed or returned invalid JSON. The sandbox boundary result remains independent.');
  }
  if (activeCliBoundary !== 'PASS') {
    if (boundary === 'TEST ERROR' && sandboxRuntime === 'READY') {
      nextSteps.push('Review the incomplete method evidence and rerun after the diagnostic runner has been corrected or updated.');
    } else if (alternativeExecutable && boundary === 'PASS' && activeCliBoundary === 'NOT TESTED') {
      if (activeHelperResolution === HELPER_RESOLUTION_STATES.FAILED) {
        nextSteps.push('The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, correct its helper-resolution problem and test that executable separately.');
      } else if (activeRuntimeFailure) {
        nextSteps.push('The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, correct its runtime-startup problem and test that executable separately.');
      } else if (incompleteActiveLayout) {
        nextSteps.push('The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, correct its incomplete file or resource layout and test that executable separately.');
        nextSteps.push('Do not manually copy helper executables, PATH entries, or standalone resources between different Codex versions.');
      } else {
        nextSteps.push('The selected alternative executable passed the tested boundary checks. To validate the active PATH CLI, run the controlled runtime preflight and boundary probes against that executable separately.');
      }
    } else if (incompleteActiveLayout && !activeRuntimeFailure) {
      nextSteps.push(usesStandaloneResourceLayout(inventory.activeBundle)
        ? 'Update or reinstall Codex through the official distribution channel so the matching standalone package has a complete required resource layout.'
        : 'Update or reinstall the Codex CLI with the official installer so codex.exe and its Windows sandbox helper executables are installed together.');
      nextSteps.push('Open a new non-administrator PowerShell session and rerun the Canary against the active CLI.');
      nextSteps.push('Do not manually copy helper executables, PATH entries, or standalone resources between different Codex versions.');
    } else if (untestedStandaloneRuntime) {
      nextSteps.push('When the Windows sandbox state is AVAILABLE, run the controlled runtime preflight and optional live probes to test helper resolution, runtime startup, and the sandbox boundary.');
    } else if (activeRuntimeFailure || boundary === 'TEST ERROR') {
      nextSteps.push('Review the sandbox diagnostics, correct the runtime setup problem, and rerun the disposable probes.');
    }
  }
  if (additionalProbeErrors) {
    nextSteps.unshift('Treat the confirmed boundary gap as the primary result, then review and rerun the additional incomplete or failed probe methods separately.');
  }
  const {
    activeRuntimeDiagnostics,
    testedRuntimeDiagnostics,
    runtimeDiagnostics,
  } = buildTargetedRuntimeDiagnostics(inventory, sandbox);
  const summary = {
    overall, boundary, sandboxRuntime, workspaceDeletion,
    cleanup,
    additionalProbeErrors,
    boundaryGapMethods,
    isAlternativeExecutable: alternativeExecutable,
    methodCoverage,
    execpolicyCoverage,
    boundaryAssessmentDeclined,
    riskWarnings,
    activeCli,
    testedBundle,
    activeRuntimeDiagnostics,
    testedRuntimeDiagnostics,
    runtimeDiagnostics,
    interpretation,
    nextSteps,
    bundleStatistics,
  };
  summary.recommendations = buildRecommendations({ inventory, summary, rules, sandbox, execpolicyCoverage, assessmentMode });
  return summary;
}


function looksLikeLocalPath(value) {
  const text = String(value || '');
  return /^[A-Za-z]:[\\/]/.test(text) || text.includes('\\') || text.includes('/');
}

function collectBundlePathCandidates(bundle, candidates) {
  if (!bundle) return;
  candidates.push(
    bundle.executablePath,
    bundle.directory,
    bundle.releaseDir,
    bundle.binDir,
    bundle.codexResourcesDir,
    bundle.codexPathDir,
    bundle.standalonePackage?.releaseDir,
    bundle.standalonePackage?.binDir,
    bundle.standalonePackage?.codexResourcesDir,
    bundle.standalonePackage?.codexPathDir,
    bundle.standalonePackage?.executablePath,
  );
  for (const value of Object.values(bundle.files || {})) candidates.push(value);
  for (const value of Object.values(bundle.standalonePackage?.files || {})) candidates.push(value);
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
  collectBundlePathCandidates(i.activeBundle, candidates);
  for (const bundle of i.completeBundles || []) collectBundlePathCandidates(bundle, candidates);
  for (const bundle of i.matchingCompleteBundles || []) collectBundlePathCandidates(bundle, candidates);
  for (const bundle of i.newerCompleteBundles || []) collectBundlePathCandidates(bundle, candidates);
  for (const bundle of i.standalonePackages || []) collectBundlePathCandidates(bundle, candidates);
  const replacements = [];
  for (const candidate of candidates) {
    if (!looksLikeLocalPath(candidate)) continue;
    const value = String(candidate);
    replacements.push([value, '%LOCAL_PATH%']);
    const parent = path.dirname(value);
    if (parent && parent !== '.' && parent !== value) replacements.push([parent, '%LOCAL_PATH%']);
  }
  return replacements;
}

function isPathSeparator(character) {
  return character === '\\' || character === '/';
}

function isAsciiLetter(character) {
  if (!character) return false;
  const code = character.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isWhitespaceCharacter(character) {
  return character === ' ' || character === '\t' || character === '\r' || character === '\n';
}

function isWindowsPathStart(text, index) {
  const drivePath = isAsciiLetter(text[index])
    && text[index + 1] === ':'
    && isPathSeparator(text[index + 2]);
  if (drivePath) return true;
  if (!isPathSeparator(text[index]) || text[index + 1] !== text[index]) return false;
  let cursor = index + 2;
  const serverStart = cursor;
  while (cursor < text.length && !isPathSeparator(text[cursor]) && !isWhitespaceCharacter(text[cursor])) cursor += 1;
  if (cursor === serverStart || !isPathSeparator(text[cursor])) return false;
  cursor += 1;
  const shareStart = cursor;
  while (cursor < text.length
    && !isPathSeparator(text[cursor])
    && !isWhitespaceCharacter(text[cursor])
    && !',;"\'<>|'.includes(text[cursor])) cursor += 1;
  return cursor > shareStart;
}

function findWindowsPathEnd(text, start) {
  const quote = start > 0 && (text[start - 1] === '"' || text[start - 1] === "'") ? text[start - 1] : null;
  let cursor = start;
  if (quote === "'") {
    let closingQuote = -1;
    while (cursor < text.length && !'\r\n"<>|'.includes(text[cursor])) {
      if (text[cursor] === "'") closingQuote = cursor;
      cursor += 1;
    }
    return closingQuote >= start ? closingQuote : cursor;
  }
  while (cursor < text.length) {
    const character = text[cursor];
    if (quote && character === quote) break;
    if (!quote && '\r\n"<>|'.includes(character)) break;
    cursor += 1;
  }
  if (!quote) {
    while (cursor > start && '.)]}'.includes(text[cursor - 1])) cursor -= 1;
  }
  return cursor;
}

function redactUnknownWindowsPaths(value) {
  const text = String(value ?? '');
  let output = '';
  let copyFrom = 0;
  let cursor = 0;
  while (cursor < text.length) {
    if (!isWindowsPathStart(text, cursor)) {
      cursor += 1;
      continue;
    }
    const end = findWindowsPathEnd(text, cursor);
    output += `${text.slice(copyFrom, cursor)}%LOCAL_PATH%`;
    cursor = Math.max(end, cursor + 3);
    copyFrom = cursor;
  }
  return `${output}${text.slice(copyFrom)}`;
}

function collapseRedactionPlaceholderPaths(value) {
  let text = String(value ?? '');
  const placeholders = ['%LOCAL_PATH%', '%CODEX_HOME%', '%LOCAL_DATA%', '%ROAMING_DATA%', '%USERPROFILE%'];
  for (const placeholder of placeholders) {
    let cursor = 0;
    while (cursor < text.length) {
      const start = text.toLowerCase().indexOf(placeholder.toLowerCase(), cursor);
      if (start < 0) break;
      const suffixStart = start + placeholder.length;
      if (!isPathSeparator(text[suffixStart])) {
        const possibleRemainderEnd = findWindowsPathEnd(text, start);
        const possibleRemainder = text.slice(suffixStart, possibleRemainderEnd);
        if (!possibleRemainder.includes('\\') && !possibleRemainder.includes('/')) {
          cursor = suffixStart;
          continue;
        }
      }
      const end = findWindowsPathEnd(text, start);
      text = `${text.slice(0, suffixStart)}${text.slice(end)}`;
      cursor = suffixStart;
    }
  }
  return text;
}

function extractWindowsUsername(value) {
  const parts = String(value || '').replaceAll('/', '\\').split('\\');
  const usersIndex = parts.findIndex((part) => part.toLowerCase() === 'users');
  return usersIndex >= 0 ? parts[usersIndex + 1] || null : null;
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
  text = redactUnknownWindowsPaths(text);
  text = collapseRedactionPlaceholderPaths(text);
  const usernames = [env.CODEX_HOME, env.LOCALAPPDATA, env.APPDATA, os.homedir()]
    .filter(Boolean)
    .map(extractWindowsUsername)
    .filter(Boolean);
  for (const username of usernames) {
    text = replaceAllIgnoreCase(text, username, '[USER]');
  }
  text = replaceAllIgnoreCase(text, 'codex.exe', 'Codex executable');
  return text;
}

function sanitizeSupportValue(value, cleanText) {
  if (value == null) return value;
  if (typeof value === 'string') return cleanText(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeSupportValue(item, cleanText));
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeSupportValue(item, cleanText)]));
  }
  return value;
}

function supportValueContainsBackslash(value) {
  if (typeof value === 'string') return value.includes('\\');
  if (Array.isArray(value)) return value.some(supportValueContainsBackslash);
  if (value && typeof value === 'object') return Object.values(value).some(supportValueContainsBackslash);
  return false;
}

export function buildSupportPayload(report, env = process.env) {
  const i = report.inventory;
  const matchingBundleStatistics = summarizeExecutableBundles(i.matchingCompleteBundles || []);
  const newerBundleStatistics = summarizeExecutableBundles(i.newerCompleteBundles || []);
  const supportPathReplacements = buildSupportPathReplacements(report);
  const cleanText = (value) => sanitizeSupportText(value, env, supportPathReplacements);
  const cleanup = normalizeCleanupResult(report.summary?.cleanup || report.sandbox?.cleanup);
  const supportCleanup = {
    status: cleanup.status,
    attempted: cleanup.attempted,
    completed: cleanup.completed,
    errorPresent: cleanup.errorPresent,
    valid: cleanup.valid,
  };
  const supportPayload = {
    schemaVersion: 1,
    generatedAt: report.generatedAt,
    tool: report.tool,
    sharingNotice: {
      redactedCategories: [...SHARE_SAFE_SHARING_NOTICE.redactedCategories],
      retainedCategories: [...SHARE_SAFE_SHARING_NOTICE.retainedCategories],
      reviewBeforePublicSharing: SHARE_SAFE_SHARING_NOTICE.reviewBeforePublicSharing,
    },
    assessmentMode: report.assessmentMode || ASSESSMENT_MODES.GUIDED,
    summary: { ...report.summary, cleanup: supportCleanup },
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
      activeInstallType: i.activeBundle?.installType || 'unknown',
      activeHelperLayout: i.activeBundle?.helperLayout || 'UNRESOLVED',
      activeResourceLayout: report.summary.activeCli?.resourceLayout || i.activeBundle?.resourceLayout || 'MISSING',
      activeHelperResolution: report.summary.activeCli?.helperResolution || i.activeBundle?.helperResolution || 'NOT_TESTED',
      activeRuntimeStartup: report.summary.activeCli?.runtimeStartup || i.activeBundle?.runtimeStartup || 'NOT_TESTED',
      activeStandaloneResourcesFound: i.activeBundle?.standaloneResourcesFound === true,
      activeStandaloneResourcesComplete: i.activeBundle?.standaloneRequiredResourcesPresent === true,
      activeBundleComplete: Boolean(i.activeBundle?.complete),
      activeBundleMissing: i.activeBundle?.missing || [],
      alternativeExecutableCount: i.alternativeExecutables?.length || 0,
      alternativeExecutables: (i.alternativeExecutables || []).map((candidate) => ({
        filesystemDiscovery: candidate.filesystemDiscovery || 'DISCOVERED',
        identityStatus: candidate.filesystemIdentity?.status || 'UNPROVEN',
        probeEligible: candidate.probeEligible === true,
        derivedVersion: candidate.derivedVersion || null,
        versionEvidenceSource: candidate.versionEvidenceSource || 'UNKNOWN',
        versionConfirmedByExecution: candidate.versionConfirmedByExecution === true,
        confirmedVersion: candidate.versionConfirmedByExecution ? candidate.confirmedVersion : null,
        confirmedVersionEvidenceSource: candidate.versionConfirmedByExecution
          ? (candidate.confirmedVersionEvidenceSource || 'EXECUTABLE_OUTPUT')
          : null,
        selectionStatus: candidate.selectionStatus || 'NOT_SELECTED',
        diagnosticStatus: candidate.diagnosticStatus || 'NOT_RUN',
        sandboxState: candidate.sandboxState || 'NOT_RUN',
        confirmedSource: candidate.confirmedSource || null,
        tested: candidate.tested === true,
        validatesActiveCli: false,
        validatesBoundary: false,
      })),
      standalonePackageCount: i.standalonePackages?.length || 0,
      standalonePackages: (i.standalonePackages || []).map((bundle) => ({
        source: bundle.source,
        releaseVersion: bundle.releaseVersion,
        resourcesFound: bundle.resourcesFound,
        codexPathFound: bundle.codexPathFound,
        sources: bundle.sources || [bundle.source],
        aliasCount: bundle.aliases?.length || 0,
        requiredResourcesPresent: bundle.requiredResourcesPresent,
        resourceLayout: bundle.resourceLayout || 'MISSING',
        requiredResourcesMissing: bundle.requiredResourcesMissing || [],
        optionalResourcesMissing: bundle.optionalResourcesMissing || [],
      })),
      doctor: i.doctor ? {
        status: i.doctor.status,
        ok: i.doctor.ok === true,
        overallStatus: i.doctor.overallStatus || null,
        installationStatus: i.doctor.installationStatus || null,
        runtimeStatus: i.doctor.runtimeStatus || null,
        warningCount: i.doctor.warningCount ?? null,
        errorPresent: Boolean(i.doctor.error),
        reason: i.doctor.reason || null,
      } : null,
      activeRuntimeDiagnostics: report.summary?.activeRuntimeDiagnostics || i.runtimeDiagnostics || [],
      testedRuntimeDiagnostics: report.summary?.testedRuntimeDiagnostics || [],
      runtimeDiagnostics: report.summary?.runtimeDiagnostics || i.runtimeDiagnostics || [],
      matchingCompleteBundleCount: matchingBundleStatistics.logicalExecutableCount,
      matchingCompleteBundlePathCount: matchingBundleStatistics.discoveredPathCount,
      matchingCompleteBundleAliasCount: matchingBundleStatistics.aliasPathCount,
      newerCompleteBundleCount: newerBundleStatistics.logicalExecutableCount,
      newerCompleteBundlePathCount: newerBundleStatistics.discoveredPathCount,
      newerCompleteBundleAliasCount: newerBundleStatistics.aliasPathCount,
      newerCompleteBundles: newerBundleStatistics.logicalExecutables.map(({ representative }) => ({
        derivedVersion: representative.derivedVersion || null,
        versionEvidenceSource: representative.versionEvidenceSource || 'UNKNOWN',
        versionConfirmedByExecution: representative.versionConfirmedByExecution === true,
        diagnosticStatus: representative.diagnosticStatus || 'NOT_RUN',
      })),
      userRuleFileCount: i.ruleFiles?.length || 0,
      sandboxCommandSyntax: i.sandboxWindowsState,
      sandboxCommandState: i.sandboxWindowsState,
      sandboxCommandContract: i.sandboxCommandContract?.syntax || SANDBOX_COMMAND_SYNTAXES.UNKNOWN,
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
      errorPresent: Boolean(probe.error),
      commandForm: probe.binding?.commandForm || 'UNKNOWN',
      ruleBinding: probe.binding?.ruleBinding || EXECPOLICY_BINDING_STATES.NOT_PROVEN,
      executionBinding: probe.binding?.executionBinding || EXECPOLICY_BINDING_STATES.NOT_PROVEN,
      hostResolutionObserved: probe.binding?.hostResolutionObserved === true,
      evidenceBoundary: probe.binding?.evidenceBoundary || EXECPOLICY_EXECUTION_EVIDENCE_BOUNDARY,
    })),
    sandbox: report.sandbox ? {
      status: report.sandbox.status,
      source: report.sandbox.codexSource,
      testedCodexVersion: report.sandbox.testedCodexVersion,
      activeCodexVersion: report.sandbox.activeCodexVersion,
      isAlternativeExecutable: report.sandbox.isAlternativeExecutable === true,
      versionMismatch: report.sandbox.versionMismatch,
      scopeNote: report.sandbox.scopeNote || report.summary?.testedBundle?.scopeNote || null,
      commandSyntax: report.sandbox.sandboxCommandSyntax || SANDBOX_COMMAND_SYNTAXES.UNKNOWN,
      permissionProfile: report.sandbox.permissionProfile,
      hostPreflight: report.sandbox.hostPreflight ? {
        status: report.sandbox.hostPreflight.passed ? 'PASSED' : 'FAILED',
        passed: report.sandbox.hostPreflight.passed === true,
        filesChecked: report.sandbox.hostPreflight.filesChecked ?? null,
        errorPresent: Boolean(report.sandbox.hostPreflight.error),
      } : null,
      hostCalibrations: (report.sandbox.hostCalibrations || []).map((calibration) => ({
        method: calibration.method,
        status: calibration.status,
        passed: calibration.passed === true,
        commandStarted: calibration.commandStarted === true,
        operationAttempted: calibration.operationAttempted === true,
        targetIdentityStatus: calibration.targetIdentityStatus || 'NOT MATCHED',
        commandExitCode: calibration.commandExitCode,
        errorClass: calibration.errorClass || null,
        exceptionType: calibration.exceptionType || calibration.errorClass || null,
        errorCategory: calibration.errorCategory || null,
        errorCode: calibration.errorCode || null,
        errorHResult: calibration.errorHResult ?? null,
        nativeWin32ErrorCode: calibration.nativeWin32ErrorCode ?? null,
        operation: calibration.operation || null,
      })),
      smoke: report.sandbox.smoke ? {
        passed: report.sandbox.smoke.passed,
        commandExitCode: report.sandbox.smoke.commandExitCode,
        setupFailure: report.sandbox.smoke.setupFailure,
        errorPresent: !report.sandbox.smoke.passed && Boolean(report.sandbox.smoke.stderr),
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
        commandStarted: probe.commandStarted === true,
        operationAttempted: probe.operationAttempted === true,
        hostCalibrationStatus: probe.hostCalibrationStatus || 'FAIL',
        targetIdentityStatus: probe.targetIdentityStatus || 'NOT REPORTED',
        targetId: probe.targetId || probe.id,
        errorClass: probe.errorClass || null,
        exceptionType: probe.exceptionType || probe.errorClass || null,
        errorCategory: probe.errorCategory || null,
        errorCode: probe.errorCode || null,
        errorHResult: probe.errorHResult ?? null,
        nativeWin32ErrorCode: probe.nativeWin32ErrorCode ?? null,
        operation: probe.operation || null,
        errorTargetMatched: probe.errorTargetMatched === true,
        fileExistedBefore: probe.fileExistedBefore === true,
        fileExistsAfter: probe.fileExistsAfter === true,
        unrelatedFailureDetected: probe.unrelatedFailureDetected === true,
        denialEvidence: probe.denialEvidence,
      })),
      errorPresent: Boolean(report.sandbox.error),
      cleanup: supportCleanup,
    } : null,
  };
  return sanitizeSupportValue(supportPayload, cleanText);
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
  add(`Cleanup status:           ${report.summary.cleanup?.status || 'NOT_RUN'}`);
  add(`Active CLI file status:   ${report.summary.activeCli?.bundleStatus || 'UNKNOWN'}`);
  add(`Active resource layout:   ${report.summary.activeCli?.resourceLayout || 'MISSING'}`);
  add(`Active helper resolution: ${report.summary.activeCli?.helperResolution || 'NOT_TESTED'}`);
  add(`Active runtime startup:   ${report.summary.activeCli?.runtimeStartup || 'NOT_TESTED'}`);
  add(`Active CLI boundary:      ${report.summary.activeCli?.boundaryStatus || 'NOT TESTED'}`);
  if (report.summary.testedBundle) {
    add(`Tested bundle source:     ${report.summary.testedBundle.source}`);
    add(`Tested bundle version:    ${report.summary.testedBundle.version || '(unknown)'}`);
    add(`Tested resource layout:   ${report.summary.testedBundle.resourceLayout || 'MISSING'}`);
    add(`Tested helper resolution: ${report.summary.testedBundle.helperResolution || 'NOT_TESTED'}`);
    add(`Tested runtime startup:   ${report.summary.testedBundle.runtimeStartup || 'NOT_TESTED'}`);
    add(`Tested bundle boundary:   ${report.summary.testedBundle.boundaryStatus}`);
    add(`Runtime pair coverage:    ${report.summary.testedBundle.methodCoverage}`);
    if (report.summary.testedBundle.scopeNote) add(`Tested result scope:       ${report.summary.testedBundle.scopeNote}`);
  }
  add(`Execpolicy rule coverage: ${formatExecpolicyCoverage(report.summary.execpolicyCoverage)} (additional rule coverage only)`, '');
  add('INTERPRETATION', '--------------');
  for (const line of report.summary.interpretation || []) add(`- ${line}`);
  add('');
  if (report.recommendations?.length) {
    add('DIAGNOSTIC RECOMMENDATIONS', '--------------------------');
    for (const item of report.recommendations) {
      add(`${item.severity} ${item.code}${item.target ? ` [${item.target}]` : ''}`);
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
  add(`Active install type:      ${report.environment.activeInstallType || 'unknown'}`);
  add(`Active helper layout:     ${report.environment.activeHelperLayout || 'UNRESOLVED'}`);
  add(`Active resource layout:   ${report.environment.activeResourceLayout || 'MISSING'}`);
  add(`Helper resolution:        ${report.environment.activeHelperResolution || 'NOT_TESTED'}`);
  add(`Runtime startup:          ${report.environment.activeRuntimeStartup || 'NOT_TESTED'}`);
  add(`Classic file layout complete: ${report.environment.activeBundleComplete ? 'yes' : 'no'}`);
  if (report.environment.activeBundleMissing?.length) add(`Missing bundle files:     ${report.environment.activeBundleMissing.join(', ')}`);
  add(`Alternative executables discovered: ${report.environment.alternativeExecutableCount || 0}`);
  for (const candidate of report.environment.alternativeExecutables || []) {
    add(`Alternative inventory:    ${candidate.filesystemDiscovery}; identity ${candidate.identityStatus}; probe-eligible ${candidate.probeEligible ? 'yes' : 'no'}`);
    add(`  Metadata-derived version: ${candidate.derivedVersion || '(unknown)'} from ${candidate.versionEvidenceSource}`);
    add(`  Executed version:       ${candidate.versionConfirmedByExecution ? candidate.confirmedVersion : '(not confirmed)'}${candidate.versionConfirmedByExecution ? ` from ${candidate.confirmedVersionEvidenceSource || 'EXECUTABLE_OUTPUT'}` : ''}`);
    add(`  Selection/diagnostic:   ${candidate.selectionStatus} / ${candidate.diagnosticStatus}; tested ${candidate.tested ? 'yes' : 'no'}`);
    add(`  Alternative sandbox:   ${candidate.sandboxState || 'NOT_RUN'}`);
    add('  Scope:                  no active-CLI or sandbox-boundary validation');
  }
  add(`Standalone packages:      ${report.environment.standalonePackageCount || 0}`);
  add(`Matching logical executables: ${report.environment.matchingCompleteBundleCount || 0}`);
  add(`Matching discovered paths: ${report.environment.matchingCompleteBundlePathCount || 0}`);
  add(`Matching alias paths:      ${report.environment.matchingCompleteBundleAliasCount || 0}`);
  add(`Newer logical executables: ${report.environment.newerCompleteBundleCount || 0}`);
  add(`Newer discovered paths:    ${report.environment.newerCompleteBundlePathCount || 0}`);
  add(`Newer alias paths:         ${report.environment.newerCompleteBundleAliasCount || 0}`);
  add(`Codex doctor status:      ${report.environment.doctor?.status || 'NOT_RUN'}${report.environment.doctor?.overallStatus ? ` (${report.environment.doctor.overallStatus})` : ''}`);
  if (report.environment.doctor?.reason) add(`Codex doctor detail:      ${report.environment.doctor.reason}`);
  add(`User rule files:          ${report.environment.userRuleFileCount}`);
  add(`Sandbox command state:    ${report.environment.sandboxCommandState || 'UNKNOWN'}`);
  add(`Sandbox syntax contract:  ${report.environment.sandboxCommandContract || 'UNKNOWN'}`);
  add(`Sandbox runtime:          ${report.environment.sandboxRuntime || 'NOT TESTED'}`, '');
  add('EXECPOLICY', '----------');
  for (const probe of report.execpolicy || []) {
    add(`${probe.label}: ${probe.decision ? probe.decision.toUpperCase() : probe.status}`);
    add(`  Rule path binding: ${probe.ruleBinding}; execution binding: ${probe.executionBinding}`);
    add(`  Host resolution observed: ${probe.hostResolutionObserved ? 'yes' : 'no'}`);
  }
  if (!report.execpolicy?.length) add('(not run)');
  add('');
  add('SANDBOX PROBES', '--------------');
  if (!report.sandbox) add('(not run)');
  else {
    add(`Run status: ${report.sandbox.status}`);
    add(`Sandbox syntax used: ${report.sandbox.commandSyntax || 'UNKNOWN'}`);
    add(`Runtime smoke test: ${report.sandbox.smoke ? (report.sandbox.smoke.passed ? 'PASS' : 'FAIL') : 'NOT RUN'}`);
    for (const calibration of report.sandbox.hostCalibrations || []) {
      add(`Host calibration ${calibration.method}: ${calibration.status}`);
      add(`  Operation: ${calibration.operation || '(not recorded)'}`);
      add(`  Target identity: ${calibration.targetIdentityStatus || 'NOT MATCHED'}`);
      add(`  Exception: ${calibration.exceptionType || calibration.errorClass || '(none)'}`);
      add(`  HResult / native Win32: ${calibration.errorHResult ?? '(none)'} / ${calibration.nativeWin32ErrorCode ?? '(none)'}`);
    }
    for (const probe of report.sandbox.probes || []) {
      add(`${probe.label}: ${probe.assessment}`);
      add(`  Expected: ${probe.expected}; observed: ${probe.observed}; exit: ${probe.commandExitCode}`);
      add(`  Evidence: calibration=${probe.hostCalibrationStatus}; operation=${probe.operation || '(not recorded)'}; target identity=${probe.targetIdentityStatus}; attempted=${probe.operationAttempted ? 'yes' : 'no'}; final=${probe.assessment}`);
      add(`  Exception: ${probe.exceptionType || probe.errorClass || '(none)'}`);
      add(`  Error: ${probe.errorCategory || '(none)'} / ${probe.errorCode || '(none)'}`);
      add(`  HResult / native Win32: ${probe.errorHResult ?? '(none)'} / ${probe.nativeWin32ErrorCode ?? '(none)'}`);
    }
  }
  add('', formatShareSafeSharingNotice(report.sharingNotice), '');
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
  const supportJson = `${JSON.stringify(supportPayload, null, 2)}\n`;
  const supportText = renderSupportReport(supportPayload);
  const supportOutputs = [supportJson, supportText];
  const absolutePathRemaining = supportOutputs.some((output) => {
    for (let index = 0; index < output.length; index += 1) {
      if (isWindowsPathStart(output, index)) return true;
    }
    return false;
  });
  if (absolutePathRemaining || supportValueContainsBackslash(supportPayload) || supportText.includes('\\')) {
    throw new Error('Share-safe report validation failed: a local Windows, UNC, or backslash path fragment remained after redaction.');
  }
  fs.writeFileSync(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.writeFileSync(txtPath, renderTextReport(payload), 'utf8');
  fs.writeFileSync(supportJsonPath, supportJson, 'utf8');
  fs.writeFileSync(supportTxtPath, supportText, 'utf8');
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
  add(`Sandbox command state:   ${report.inventory.sandboxWindowsState || 'UNKNOWN'}`);
  add(`Sandbox runtime:         ${report.summary.sandboxRuntime || 'NOT TESTED'}`);
  add(`Sandbox boundary:        ${report.summary.boundary}`);
  add(`Workspace deletion:      ${report.summary.workspaceDeletion}`);
  add(`Cleanup status:          ${report.summary.cleanup?.status || 'NOT_RUN'}`);
  add(`Runtime pair coverage:   ${report.summary.methodCoverage || 'NOT RUN'}`);
  add(`Execpolicy coverage:     ${formatExecpolicyCoverage(report.summary.execpolicyCoverage)} (additional user-rule coverage only)`, '');
  add('ACTIVE CLI', '----------');
  add(`Version:                 ${report.summary.activeCli?.version || '(unavailable)'}`);
  add(`File status:             ${report.summary.activeCli?.bundleStatus || 'UNKNOWN'}`);
  add(`Resource layout:         ${report.summary.activeCli?.resourceLayout || 'MISSING'}`);
  add(`Helper resolution:       ${report.summary.activeCli?.helperResolution || 'NOT_TESTED'}`);
  add(`Runtime startup:         ${report.summary.activeCli?.runtimeStartup || 'NOT_TESTED'}`);
  add(`Boundary status:         ${report.summary.activeCli?.boundaryStatus || 'NOT TESTED'}`, '');
  add('TESTED BUNDLE', '-------------');
  if (!report.summary.testedBundle) add('(not tested)', '');
  else {
    add(`Source:                  ${report.summary.testedBundle.source}`);
    add(`Version:                 ${report.summary.testedBundle.version || '(unavailable)'}`);
    add(`File status:             ${report.summary.testedBundle.bundleStatus || 'UNKNOWN'}`);
    add(`Resource layout:         ${report.summary.testedBundle.resourceLayout || 'MISSING'}`);
    add(`Helper resolution:       ${report.summary.testedBundle.helperResolution || 'NOT_TESTED'}`);
    add(`Runtime startup:         ${report.summary.testedBundle.runtimeStartup || 'NOT_TESTED'}`);
    add(`Boundary status:         ${report.summary.testedBundle.boundaryStatus}`);
    add(`Runtime pair coverage:   ${report.summary.testedBundle.methodCoverage}`);
    if (report.summary.testedBundle.scopeNote) add(`Result scope:            ${report.summary.testedBundle.scopeNote}`);
    add('');
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
  add(`Active install type:     ${i.activeBundle?.installType || 'unknown'}`);
  add(`Active helper layout:    ${i.activeBundle?.helperLayout || 'UNRESOLVED'}`);
  add(`Active resource layout:  ${report.summary.activeCli?.resourceLayout || i.activeBundle?.resourceLayout || 'MISSING'}`);
  add(`Helper resolution:       ${report.summary.activeCli?.helperResolution || i.activeBundle?.helperResolution || 'NOT_TESTED'}`);
  add(`Runtime startup:         ${report.summary.activeCli?.runtimeStartup || i.activeBundle?.runtimeStartup || 'NOT_TESTED'}`);
  add(`Active probe eligibility: ${i.activeBundle?.probeEligible || i.sandboxHelperInPath ? 'yes' : 'no'}`);
  if (i.activeBundle?.standaloneResourcesFound) add(`Standalone resources:    ${i.activeBundle.standaloneRequiredResourcesPresent ? 'present' : 'partial'}${i.activeBundle.resourceVersionMatchesActive === false ? ' (version mismatch)' : ''}`);
  if (i.activeBundle?.missing?.length) add(`Missing beside active CLI: ${i.activeBundle.missing.join(', ')}`);
  add(`Alternative executables discovered: ${i.alternativeExecutables?.length || 0}`);
  for (const candidate of i.alternativeExecutables || []) {
    add(`Alternative executable:  ${candidate.executablePath}`);
    add(`  Filesystem discovery:  ${candidate.filesystemDiscovery || 'DISCOVERED'}`);
    add(`  Identity:              ${candidate.filesystemIdentity?.status || 'UNPROVEN'}`);
    if (candidate.filesystemIdentity?.canonicalPath) add(`  Canonical path:        ${candidate.filesystemIdentity.canonicalPath}`);
    add(`  Derived version:       ${candidate.derivedVersion || '(unknown)'} (${candidate.versionEvidenceSource || 'UNKNOWN'})`);
    add(`  Executed version:      ${candidate.versionConfirmedByExecution ? candidate.confirmedVersion : '(not confirmed)'}${candidate.versionConfirmedByExecution ? ` (${candidate.confirmedVersionEvidenceSource || 'EXECUTABLE_OUTPUT'})` : ''}`);
    add(`  Selection:             ${candidate.selectionStatus || 'NOT_SELECTED'}`);
    add(`  Diagnostic process:    ${candidate.diagnosticStatus || 'NOT_RUN'}`);
    add(`  Alternative sandbox:   ${candidate.sandboxState || 'NOT_RUN'}`);
    add(`  Tested bundle:         ${candidate.tested === true ? 'yes' : 'no'}`);
    add('  Evidence scope:        no active-CLI or sandbox-boundary validation');
  }
  add(`Standalone packages:     ${i.standalonePackages?.length || 0}`);
  const matchingBundleStatistics = summarizeExecutableBundles(i.matchingCompleteBundles || []);
  const newerBundleStatistics = summarizeExecutableBundles(i.newerCompleteBundles || []);
  add(`Matching logical executables: ${matchingBundleStatistics.logicalExecutableCount}`);
  add(`Matching discovered paths: ${matchingBundleStatistics.discoveredPathCount}`);
  add(`Matching alias paths:     ${matchingBundleStatistics.aliasPathCount}`);
  for (const executablePath of matchingBundleStatistics.discoveredPaths) add(`Matching discovered path: ${executablePath}`);
  add(`Newer logical executables: ${newerBundleStatistics.logicalExecutableCount}`);
  add(`Newer discovered paths:   ${newerBundleStatistics.discoveredPathCount}`);
  add(`Newer alias paths:        ${newerBundleStatistics.aliasPathCount}`);
  for (const executablePath of newerBundleStatistics.discoveredPaths) add(`Newer discovered path:    ${executablePath}`);
  if (i.doctor) {
    add(`Codex doctor:           ${i.doctor.status}${i.doctor.overallStatus ? ` (${i.doctor.overallStatus})` : ''}`);
    if (i.doctor.reason) add(`Codex doctor detail:    ${i.doctor.reason}`);
  }
  if (i.newerCompleteBundles?.[0]) add(`Filesystem-derived newer version: ${i.newerCompleteBundles[0].derivedVersion || '(unknown)'} (${i.newerCompleteBundles[0].versionEvidenceSource || 'UNKNOWN'}; diagnostic ${i.newerCompleteBundles[0].diagnosticStatus || 'NOT_RUN'})`);
  add(`CODEX_HOME:              ${i.codexHome}`);
  add(`config.toml:             ${i.config.exists ? i.config.path : '(not found)'}`);
  add(`auth.json present:       ${i.authFilePresent ? 'yes (content was not read)' : 'no'}`);
  add(`User rule files:         ${i.ruleFiles.length}`);
  add(`Sandbox command state:   ${i.sandboxWindowsState || (i.sandboxWindowsAvailable ? 'AVAILABLE' : 'UNKNOWN')}`);
  add(`Sandbox syntax contract: ${i.sandboxCommandContract?.syntax || SANDBOX_COMMAND_SYNTAXES.UNKNOWN}`);
  if (i.sandboxHelpError) add(`Sandbox diagnostic:      ${String(i.sandboxHelpError).replace(/\r?\n/g, ' | ')}`);
  if (report.summary.runtimeDiagnostics?.length) {
    add('Runtime diagnostics:');
    for (const diagnostic of report.summary.runtimeDiagnostics) add(`- ${diagnostic.severity} ${diagnostic.code}${diagnostic.target ? ` [${diagnostic.target}]` : ''}: ${diagnostic.title}`);
  }
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
    add(`  Rule path binding: ${probe.binding?.ruleBinding || EXECPOLICY_BINDING_STATES.NOT_PROVEN}`);
    add(`  Execution binding: ${probe.binding?.executionBinding || EXECPOLICY_BINDING_STATES.NOT_PROVEN}`);
    add(`  Resolved command now: ${probe.binding?.resolvedCommandPath || '(not resolved)'}`);
    add(`  Evidence boundary: ${probe.binding?.evidenceBoundary || EXECPOLICY_EXECUTION_EVIDENCE_BOUNDARY}`);
    if (probe.error) add(`  Note: ${probe.error}`);
  }
  add('');

  add('WINDOWS SANDBOX PROBES', '-----------------------');
  if (!report.sandbox) {
    add('(not run)', '');
  } else {
    add(`Run status: ${report.sandbox.status}`);
    add(`Sandbox syntax used: ${report.sandbox.sandboxCommandSyntax || SANDBOX_COMMAND_SYNTAXES.UNKNOWN}`);
    add(`Codex executable: ${report.sandbox.codexExecutable || '(active PATH command)'}`);
    add(`Executable source: ${report.sandbox.codexSource || 'UNKNOWN'}`);
    add(`Tested Codex version: ${report.sandbox.testedCodexVersion || '(unavailable)'}`);
    if (report.summary.testedBundle?.isAlternativeExecutable) {
      if (report.sandbox.versionMismatch) {
      add(`Active Codex version: ${report.sandbox.activeCodexVersion || '(unavailable)'}`);
      }
      add(`Scope of result: ${report.summary.testedBundle.scopeNote}`);
    }
    add(`Permission profile:       ${report.sandbox.permissionProfile || '(not recorded)'}`);
    if (report.sandbox.hostPreflight) add(`Host deletion preflight: ${report.sandbox.hostPreflight.passed ? 'PASS' : 'FAIL'}`);
    for (const calibration of report.sandbox.hostCalibrations || []) {
      add(`Host calibration ${calibration.label || calibration.method}: ${calibration.status}`);
      add(`  Operation: ${calibration.operation || '(not recorded)'}`);
      add(`  Target identity: ${calibration.targetIdentityStatus || 'NOT MATCHED'}`);
      add(`  Exception type: ${calibration.exceptionType || calibration.errorClass || '(none)'}`);
      add(`  HResult / native Win32: ${calibration.errorHResult ?? '(none)'} / ${calibration.nativeWin32ErrorCode ?? '(none)'}`);
    }
    if (report.sandbox.smoke) add(`Runtime smoke test: ${report.sandbox.smoke.passed ? 'PASS' : 'FAIL'}`);
    if (report.sandbox.error) add(`Error: ${report.sandbox.error}`);
    for (const probe of report.sandbox.probes || []) {
      add(`${probe.label}: ${probe.assessment}`);
      add(`  Expected: ${probe.expected}; observed: ${probe.observed}; command exit: ${probe.commandExitCode}`);
      add(`  Command started: ${probe.commandStarted ? 'yes' : 'no'}`);
      add(`  Operation attempted: ${probe.operationAttempted ? 'yes' : 'no'}`);
      add(`  Operation: ${probe.operation || '(not recorded)'}`);
      add(`  Host calibration: ${probe.hostCalibrationStatus || 'FAIL'}`);
      add(`  Target identity: ${probe.targetIdentityStatus || 'NOT REPORTED'}`);
      add(`  Target ID: ${probe.targetId || probe.id || '(not recorded)'}`);
      add(`  Target path: ${probe.targetPath || '(not recorded)'}`);
      add(`  Reported error target: ${probe.errorTarget || '(not reported)'}`);
      add(`  Error class/category/code: ${probe.errorClass || '(none)'} / ${probe.errorCategory || '(none)'} / ${probe.errorCode || '(none)'}`);
      add(`  Exception type: ${probe.exceptionType || probe.errorClass || '(none)'}`);
      add(`  Error reason/HResult/native Win32: ${probe.errorReason || '(none)'} / ${probe.errorHResult ?? '(none)'} / ${probe.nativeWin32ErrorCode ?? '(none)'}`);
      if (probe.errorMessage) add(`  Error message: ${probe.errorMessage}`);
      add(`  Unrelated failure: ${probe.unrelatedFailureDetected ? 'yes' : 'no'}`);
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
      add(`${item.severity} ${item.code}${item.target ? ` [${item.target}]` : ''}`);
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
