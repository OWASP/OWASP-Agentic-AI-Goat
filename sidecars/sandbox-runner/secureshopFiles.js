'use strict';

/**
 * Owner-scoped virtual filesystem for future SecureShop sandbox endpoints.
 *
 * The public path space is POSIX-like. Absolute paths and traversal resolve
 * inside one capability root, so `/etc/passwd` names a synthetic lab file and
 * `../server/config/.env` can preserve a traversal lesson without naming a
 * host file. Capabilities are minted here, are exact-format bearer secrets,
 * and must never be accepted from a learner-controlled owner/session ID.
 *
 * Integration limits:
 * - This module does not authenticate HTTP callers. A later route must bind an
 *   authenticated owner/session to a capability kept outside learner input.
 * - Capability registrations are intentionally process-local. Reserved targets
 *   can be reopened by their trusted durable binding after runner restart, but
 *   this module does not authenticate that binding or serialize other runner
 *   processes sharing the same root.
 * - Reserved targets deliberately reject generic reset, destroy, and
 *   cleanup-reconcile calls. retireReservedTarget requires a trusted exact
 *   authorization callback and persists a target-specific cleanup journal.
 *   Incomplete canonical targets and crash-left staging/journal files are
 *   retained as explicit cleanup debt and are never swept here.
 * - createOwnerSession and provisionReservedTarget return bearer capabilities
 *   only to their trusted in-process caller. A later adapter must keep them out
 *   of model prompts, UI DTOs, traces, receipts and logs.
 * - Symlink checks and per-capability serialization protect module-managed
 *   roots. The configured root must be private to this process (0700); this is
 *   not a boundary against another process with the same OS uid mutating it.
 * - This module provides file effects only. It is not a shell/code sandbox.
 * - Session registrations are bounded; byte limits below apply per operation.
 *   A later authenticated adapter must also
 *   enforce per-owner aggregate storage and file-count quotas.
 */

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const fsConstants = require('node:fs').constants;
const path = require('node:path');

const CAPABILITY_RE = /^secureshop-[a-f0-9]{64}$/;
const SESSION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const DEFAULT_MAX_READ_BYTES = 256 * 1024;
const DEFAULT_MAX_WRITE_BYTES = 1024 * 1024;
const MAX_VIRTUAL_PATH_BYTES = 4096;
const RESERVED_CONTROL_VERSION = 1;
const RESERVED_CONTROL_FILE = 'control.json';
const RESERVED_DATA_DIRECTORY = 'data';
const RESERVED_CLEANUP_VERSION = 1;
const FIXTURE_PATHS = Object.freeze([
  '/.env',
  '/server/platform_secrets.json',
  '/server/config/.env',
  '/server/config/platform_secrets.json',
  '/etc/passwd',
  '/home/secureshop/.ssh/id_rsa',
  '/uploads/.keep',
  '/var/run/secureshop-services.json',
]);

class SecureShopFilesError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SecureShopFilesError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new SecureShopFilesError(code, message);
}

function positiveInteger(value, fallback, name) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < 1) {
    fail('INVALID_CONFIGURATION', `${name} must be a positive integer`);
  }
  return selected;
}

function validateBinding(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('INVALID_OWNER_BINDING', 'owner binding is required');
  }
  const ownerId = String(input.ownerId ?? '');
  const sessionId = String(input.sessionId ?? '');
  const role = String(input.role ?? '').toLowerCase();
  if (!ownerId || Buffer.byteLength(ownerId) > 256 || /[\0\r\n]/.test(ownerId)) {
    fail('INVALID_OWNER_BINDING', 'ownerId is invalid');
  }
  if (!SESSION_ID_RE.test(sessionId)) {
    fail('INVALID_OWNER_BINDING', 'sessionId must be a UUID');
  }
  if (!ROLES.has(role)) {
    fail('INVALID_OWNER_BINDING', 'role is invalid');
  }
  return Object.freeze({ ownerId, sessionId: sessionId.toLowerCase(), role });
}

function validateReservedBinding(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)) {
    fail('INVALID_TARGET_BINDING', 'reserved target binding is required');
  }
  const expectedKeys = ['generation', 'launchId', 'ownerId', 'scenarioId', 'targetId'];
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(descriptors).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])
      || Object.getOwnPropertySymbols(input).length
      || keys.some((key) => !Object.prototype.hasOwnProperty.call(descriptors[key], 'value'))) {
    fail('INVALID_TARGET_BINDING', 'reserved target binding is invalid');
  }
  const normalized = {};
  for (const key of ['targetId', 'launchId', 'scenarioId']) {
    const value = descriptors[key].value;
    if (typeof value !== 'string' || !UUID_RE.test(value)) {
      fail('INVALID_TARGET_BINDING', 'reserved target binding is invalid');
    }
    normalized[key] = value.toLowerCase();
  }
  const ownerId = descriptors.ownerId.value;
  const generation = descriptors.generation.value;
  if (typeof ownerId !== 'string' || !/^[1-9][0-9]{0,9}$/.test(ownerId)
      || Number(ownerId) > 2147483647
      || !Number.isSafeInteger(generation) || generation < 1) {
    fail('INVALID_TARGET_BINDING', 'reserved target binding is invalid');
  }
  return Object.freeze({
    targetId: normalized.targetId,
    launchId: normalized.launchId,
    scenarioId: normalized.scenarioId,
    generation,
    ownerId,
  });
}

function reservedControl(binding) {
  return Buffer.from(`${JSON.stringify({
    version: RESERVED_CONTROL_VERSION,
    targetId: binding.targetId,
    launchId: binding.launchId,
    scenarioId: binding.scenarioId,
    generation: binding.generation,
    ownerId: binding.ownerId,
  })}\n`);
}

function validateOperationId(value) {
  if (typeof value !== 'string' || !UUID_RE.test(value)) {
    fail('INVALID_CLEANUP_OPERATION', 'cleanup operationId must be a UUID');
  }
  return value.toLowerCase();
}

function cleanupCoordinates(binding, operationId) {
  return Object.freeze({
    version: RESERVED_CLEANUP_VERSION,
    targetId: binding.targetId,
    launchId: binding.launchId,
    scenarioId: binding.scenarioId,
    generation: binding.generation,
    ownerId: binding.ownerId,
    operationId,
  });
}

function cleanupReceipt(coordinates, completedAt) {
  const canonical = {
    ...coordinates,
    status: 'completed',
    completedAt,
    cleanupPending: false,
  };
  return Object.freeze({ ...canonical, receiptSha256: digest(Buffer.from(JSON.stringify(canonical))) });
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function validateCapability(value) {
  if (typeof value !== 'string' || !CAPABILITY_RE.test(value)) {
    fail('INVALID_CAPABILITY', 'SecureShop capability has an invalid format');
  }
  return value;
}

function validateVirtualPart(value, name) {
  if (typeof value !== 'string' || value.includes('\0')) {
    fail('INVALID_VIRTUAL_PATH', `${name} must be a NUL-free string`);
  }
  if (Buffer.byteLength(value) > MAX_VIRTUAL_PATH_BYTES) {
    fail('INVALID_VIRTUAL_PATH', `${name} is too long`);
  }
}

function resolveVirtualPath(base, requested) {
  validateVirtualPart(base, 'base');
  validateVirtualPart(requested, 'path');
  const normalizedBase = path.posix.resolve('/', base);
  const virtualPath = requested.startsWith('/')
    ? path.posix.resolve('/', requested.slice(1))
    : path.posix.resolve(normalizedBase, requested);
  const segments = virtualPath.split('/').filter(Boolean);
  if (segments.length > 256) fail('INVALID_VIRTUAL_PATH', 'path has too many segments');
  return { virtualPath, segments };
}

function digest(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function isMissing(error) {
  return error && error.code === 'ENOENT';
}

function sanitizeNativeError(error) {
  if (error instanceof SecureShopFilesError) return error;
  return new SecureShopFilesError('FILESYSTEM_OPERATION_FAILED', 'SecureShop virtual filesystem operation failed');
}

async function lstatOrNull(filename) {
  try {
    return await fs.lstat(filename);
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

async function assertDirectoryNotSymlink(directory, code = 'UNSAFE_FILESYSTEM') {
  const stat = await lstatOrNull(directory);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) {
    fail(code, 'filesystem boundary is missing or unsafe');
  }
}

async function makeFixtureTree(directory, randomBytes) {
  const marker = randomBytes(24).toString('hex');
  const sshMarker = randomBytes(24).toString('hex');
  const fixtures = new Map([
    ['.env', Buffer.from(`SECURESHOP_LAB_MARKER=${marker}\nNODE_ENV=training\n`)],
    ['server/platform_secrets.json', Buffer.from(`${JSON.stringify({ lab: true, marker }, null, 2)}\n`)],
    ['server/config/.env', Buffer.from(`SECURESHOP_LAB_MARKER=${marker}\nNODE_ENV=training\n`)],
    ['server/config/platform_secrets.json', Buffer.from(`${JSON.stringify({ lab: true, marker }, null, 2)}\n`)],
    ['etc/passwd', Buffer.from('root:x:0:0:synthetic-root:/root:/bin/false\nsecureshop:x:10001:10001:lab:/home/secureshop:/bin/sh\n')],
    ['home/secureshop/.ssh/id_rsa', Buffer.from(`-----BEGIN SECURESHOP LAB KEY-----\n${sshMarker}\n-----END SECURESHOP LAB KEY-----\n`)],
    ['uploads/.keep', Buffer.alloc(0)],
    ['var/run/secureshop-services.json', Buffer.from('{"catalog":"running","worker":"running"}\n')],
  ]);

  for (const [relative, contents] of fixtures) {
    const filename = path.join(directory, ...relative.split('/'));
    await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await fs.writeFile(filename, contents, { mode: 0o600, flag: 'wx' });
  }
  return FIXTURE_PATHS;
}

function createSecureShopFiles(options = {}) {
  if (!options.root || typeof options.root !== 'string') {
    fail('INVALID_CONFIGURATION', 'root is required');
  }
  if (!path.isAbsolute(options.root)) {
    fail('INVALID_CONFIGURATION', 'root must be absolute');
  }

  const configuredRoot = path.resolve(options.root);
  // Windows cannot use this Node directory-handle fsync contract. Its explicit
  // v2 journal proves file-synced rename/readback, not directory durability.
  const newCleanupVersion = process.platform === 'win32' ? 2 : 1;
  const maxReadBytes = positiveInteger(options.maxReadBytes, DEFAULT_MAX_READ_BYTES, 'maxReadBytes');
  const maxWriteBytes = positiveInteger(options.maxWriteBytes, DEFAULT_MAX_WRITE_BYTES, 'maxWriteBytes');
  const maxSessions = positiveInteger(options.maxSessions, 1024, 'maxSessions');
  const randomBytes = options.randomBytes || crypto.randomBytes;
  const removeTree = options.removeTree || fs.rm;
  const now = options.now || (() => new Date().toISOString());
  if (typeof randomBytes !== 'function') fail('INVALID_CONFIGURATION', 'randomBytes must be a function');
  if (typeof removeTree !== 'function') fail('INVALID_CONFIGURATION', 'removeTree must be a function');
  if (typeof now !== 'function') fail('INVALID_CONFIGURATION', 'now must be a function');

  const registrations = new Map();
  const reservedTargets = new Map();
  const failedProvisioning = new Set();
  const locks = new Map();
  const targetLocks = new Map();
  let canonicalRoot;
  let rootPromise;

  async function ensureRoot() {
    if (!rootPromise) {
      rootPromise = (async () => {
        const before = await lstatOrNull(configuredRoot);
        if (before && (before.isSymbolicLink() || !before.isDirectory())) {
          fail('UNSAFE_FILESYSTEM', 'configured root must be a real directory');
        }
        await fs.mkdir(configuredRoot, { recursive: true, mode: 0o700 });
        await fs.chmod(configuredRoot, 0o700);
        await assertDirectoryNotSymlink(configuredRoot);
        canonicalRoot = await fs.realpath(configuredRoot);
        return canonicalRoot;
      })().catch((error) => {
        rootPromise = undefined;
        throw error;
      });
    }
    await rootPromise;
    await assertDirectoryNotSymlink(configuredRoot);
    const current = await fs.realpath(configuredRoot);
    if (current !== canonicalRoot) fail('UNSAFE_FILESYSTEM', 'configured root changed');
    return canonicalRoot;
  }

  function cleanupJournalPaths(root, targetId) {
    return {
      journal: path.join(root, `.cleanup-${targetId}.json`),
      temporary: path.join(root, `.cleanup-${targetId}.tmp`),
    };
  }

  async function syncDirectory(directory) {
    let handle;
    try {
      handle = await fs.open(directory, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0));
      await handle.sync();
    } catch (error) {
      throw new SecureShopFilesError('CLEANUP_DURABILITY_FAILED', 'reserved target cleanup state could not be made durable');
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  async function writeCleanupJournal(root, targetId, record) {
    const { journal, temporary } = cleanupJournalPaths(root, targetId);
    if (await lstatOrNull(temporary)) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is incomplete');
    }
    let handle;
    try {
      handle = await fs.open(
        temporary,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW || 0),
        0o600,
      );
      await handle.writeFile(Buffer.from(`${JSON.stringify(record)}\n`));
      await handle.sync();
      await handle.close();
      handle = undefined;
      await fs.rename(temporary, journal);
      if (record.version === 2) {
        await readExactControl(journal, Buffer.from(JSON.stringify(record) + '\n'));
      } else {
        await syncDirectory(root);
      }
    } catch (error) {
      if (error instanceof SecureShopFilesError) throw error;
      throw new SecureShopFilesError('CLEANUP_DURABILITY_FAILED', 'reserved target cleanup state could not be made durable');
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  function exactCleanupRecord(record, coordinates) {
    if (!record || typeof record !== 'object' || Array.isArray(record)
        || Object.getPrototypeOf(record) !== Object.prototype) return null;
    if (![1, 2].includes(record.version)
        || record.version === 2 && record.durabilityMode !== 'file_synced_rename_verified') return null;
    const persistedCoordinates = record.version === 2
      ? { ...coordinates, version: 2, durabilityMode: 'file_synced_rename_verified' }
      : coordinates;
    const baseKeys = ['generation', 'launchId', 'operationId', 'ownerId', 'scenarioId', 'status', 'targetId', 'version',
      ...(record.version === 2 ? ['durabilityMode'] : [])];
    const completedKeys = [...baseKeys, 'cleanupPending', 'completedAt', 'receiptSha256'].sort();
    const keys = Object.keys(record).sort();
    const expectedKeys = record.status === 'completed' ? completedKeys : baseKeys.sort();
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return null;
    if (record.status !== 'pending' && record.status !== 'completed') return null;
    for (const key of Object.keys(persistedCoordinates)) {
      if (record[key] !== persistedCoordinates[key]) return 'mismatch';
    }
    if (record.status === 'completed') {
      if (!isCanonicalTimestamp(record.completedAt)) return null;
      if (record.cleanupPending !== false) return null;
      const receipt = cleanupReceipt(persistedCoordinates, record.completedAt);
      if (record.receiptSha256 !== receipt.receiptSha256) return null;
      return { status: 'completed', receipt };
    }
    return { status: 'pending', coordinates: Object.freeze(persistedCoordinates) };
  }

  async function readCleanupJournal(root, coordinates) {
    const { journal, temporary } = cleanupJournalPaths(root, coordinates.targetId);
    if (await lstatOrNull(temporary)) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is incomplete');
    }
    const stat = await lstatOrNull(journal);
    if (!stat) return null;
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 4096) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is invalid');
    }
    let record;
    try {
      record = JSON.parse(await fs.readFile(journal, 'utf8'));
    } catch {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is invalid');
    }
    const checked = exactCleanupRecord(record, coordinates);
    if (checked === 'mismatch') fail('TARGET_BINDING_MISMATCH', 'reserved target cleanup binding does not match');
    if (!checked) fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is invalid');
    return checked;
  }

  async function assertCleanupAuthorized(authorize, coordinates) {
    if (typeof authorize !== 'function') {
      fail('CLEANUP_AUTHORIZATION_REQUIRED', 'trusted cleanup authorization is required');
    }
    let accepted;
    try {
      accepted = await authorize(coordinates);
    } catch {
      fail('CLEANUP_NOT_AUTHORIZED', 'reserved target cleanup was not authorized');
    }
    if (accepted !== true) fail('CLEANUP_NOT_AUTHORIZED', 'reserved target cleanup was not authorized');
  }

  function requireRegistration(capability) {
    validateCapability(capability);
    const registration = registrations.get(capability);
    if (!registration) fail('UNKNOWN_CAPABILITY', 'SecureShop capability is not registered');
    return registration;
  }

  function assertExpectedGeneration(registration, expectedGeneration) {
    if (expectedGeneration === undefined) return;
    if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 1) {
      fail('INVALID_GENERATION', 'expectedGeneration must be a positive integer');
    }
    if (registration.generation !== expectedGeneration) {
      fail('STALE_GENERATION', 'SecureShop filesystem generation is stale');
    }
  }

  function assertActive(registration) {
    if (registration.lifecycle !== 'active') {
      fail('LIFECYCLE_DESTROYING', 'SecureShop filesystem destruction is in progress');
    }
  }

  async function withCapabilityLock(capability, operation) {
    requireRegistration(capability);
    const previous = locks.get(capability) || Promise.resolve();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const tail = previous.then(() => gate);
    locks.set(capability, tail);
    await previous;
    try {
      return await operation(requireRegistration(capability));
    } finally {
      release();
      if (locks.get(capability) === tail) locks.delete(capability);
    }
  }

  async function withTargetLock(targetId, operation) {
    const previous = targetLocks.get(targetId) || Promise.resolve();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const tail = previous.then(() => gate);
    targetLocks.set(targetId, tail);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (targetLocks.get(targetId) === tail) targetLocks.delete(targetId);
    }
  }

  function sessionDirectory(capability, registration = requireRegistration(capability)) {
    return registration.directory || path.join(canonicalRoot, capability);
  }

  function assertCleanupPath(capability, filename, registration = requireRegistration(capability)) {
    const capabilityHex = capability.slice('secureshop-'.length);
    if (path.dirname(filename) !== canonicalRoot) {
      fail('UNSAFE_FILESYSTEM', 'cleanup path escaped the configured root');
    }
    const basename = path.basename(filename);
    if (registration.reservedTarget) {
      const reservedTemporary = basename === `.provision-${registration.binding.targetId}`;
      if (!reservedTemporary) fail('UNSAFE_FILESYSTEM', 'cleanup path is not owned by this target');
      return;
    }
    const ownedTemporary = basename.startsWith(`.retired-${capabilityHex}-`)
      || basename.startsWith(`.reset-${capabilityHex}-`);
    if (basename !== capability && !ownedTemporary) {
      fail('UNSAFE_FILESYSTEM', 'cleanup path is not owned by this capability');
    }
  }

  async function removeOwnedPath(capability, filename, registration) {
    assertCleanupPath(capability, filename, registration);
    const stat = await lstatOrNull(filename);
    if (!stat) return;
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      await fs.unlink(filename);
      return;
    }
    await removeTree(filename, { recursive: true, force: true });
  }

  async function reconcileUnlocked(capability, registration) {
    const pending = [...registration.pendingCleanup];
    let firstFailure;
    for (const filename of pending) {
      try {
        await removeOwnedPath(capability, filename, registration);
        registration.pendingCleanup.delete(filename);
      } catch (error) {
        firstFailure ||= error;
      }
    }
    if (firstFailure) {
      throw new SecureShopFilesError('CLEANUP_RETRY_FAILED', 'retired filesystem cleanup remains pending');
    }
    return registration.pendingCleanup.size;
  }

  async function assertSessionRoot(capability) {
    await ensureRoot();
    const registration = requireRegistration(capability);
    const directory = sessionDirectory(capability, registration);
    await assertDirectoryNotSymlink(directory, 'SESSION_NOT_READY');
    const real = await fs.realpath(directory);
    const expected = path.resolve(directory);
    const insideRoot = expected.startsWith(`${canonicalRoot}${path.sep}`);
    if (!insideRoot || real !== expected) {
      fail('UNSAFE_FILESYSTEM', 'session root escaped the configured root');
    }
    if (registration.reservedTarget) {
      const container = path.dirname(expected);
      await assertDirectoryNotSymlink(container, 'SESSION_NOT_READY');
      if (path.dirname(container) !== canonicalRoot
          || path.basename(container) !== `target-${registration.binding.targetId}`
          || path.basename(expected) !== RESERVED_DATA_DIRECTORY) {
        fail('UNSAFE_FILESYSTEM', 'reserved target root is unsafe');
      }
    } else if (path.dirname(expected) !== canonicalRoot || path.basename(expected) !== capability) {
      fail('UNSAFE_FILESYSTEM', 'session root escaped the configured root');
    }
    return real;
  }

  async function assertNoSymlinks(sessionRoot, segments, allowMissingFinal = false) {
    let cursor = sessionRoot;
    for (let index = 0; index < segments.length; index += 1) {
      cursor = path.join(cursor, segments[index]);
      const stat = await lstatOrNull(cursor);
      if (!stat) {
        if (allowMissingFinal && index === segments.length - 1) return;
        fail('FILE_NOT_FOUND', 'virtual path does not exist');
      }
      if (stat.isSymbolicLink()) fail('SYMLINK_REJECTED', 'symbolic links are not allowed');
      if (index < segments.length - 1 && !stat.isDirectory()) {
        fail('INVALID_VIRTUAL_PATH', 'a path component is not a directory');
      }
    }
  }

  async function ensurePrivateDirectories(sessionRoot, segments) {
    let cursor = sessionRoot;
    for (const segment of segments) {
      cursor = path.join(cursor, segment);
      let stat = await lstatOrNull(cursor);
      if (!stat) {
        try {
          await fs.mkdir(cursor, { mode: 0o700, recursive: false });
        } catch (error) {
          // A competing filesystem actor may have installed the component.
          // Inspect the exact path below rather than trusting EEXIST.
          if (error?.code !== 'EEXIST') throw error;
        }
        stat = await lstatOrNull(cursor);
      }
      if (!stat) fail('FILESYSTEM_OPERATION_FAILED', 'virtual directory could not be created');
      if (stat.isSymbolicLink()) fail('SYMLINK_REJECTED', 'symbolic links are not allowed');
      if (!stat.isDirectory()) fail('INVALID_VIRTUAL_PATH', 'a path component is not a directory');
    }
  }

  async function resetUnlocked(capability, registration) {
    const root = await ensureRoot();
    // A retry must reclaim the previous retired tree before allocating another
    // generation. Otherwise repeated cleanup failures accumulate full lab trees.
    await reconcileUnlocked(capability, registration);
    const suffix = randomBytes(12).toString('hex');
    const staging = path.join(root, `.reset-${capability.slice('secureshop-'.length)}-${suffix}`);
    const target = path.join(root, capability);
    const retired = path.join(root, `.retired-${capability.slice('secureshop-'.length)}-${suffix}`);
    await fs.mkdir(staging, { mode: 0o700, recursive: false });
    let installed = false;
    try {
      const fixturePaths = await makeFixtureTree(staging, randomBytes);
      const current = await lstatOrNull(target);
      if (current) {
        if (current.isSymbolicLink() || !current.isDirectory()) {
          fail('UNSAFE_FILESYSTEM', 'existing session root is unsafe');
        }
        await fs.rename(target, retired);
      }
      try {
        await fs.rename(staging, target);
        installed = true;
      } catch (error) {
        if (current) await fs.rename(retired, target).catch(() => {});
        throw error;
      }
      registration.generation += 1;
      if (current) {
        registration.pendingCleanup.add(retired);
        try {
          await removeOwnedPath(capability, retired);
          registration.pendingCleanup.delete(retired);
        } catch (error) {
          throw new SecureShopFilesError(
            'RESET_CLEANUP_FAILED',
            'new filesystem generation installed but retired generation cleanup failed',
          );
        }
      }
      return Object.freeze({
        generation: registration.generation,
        fixturePaths: Object.freeze(fixturePaths),
      });
    } finally {
      if (!installed) {
        try {
          await removeOwnedPath(capability, staging);
        } catch (error) {
          registration.pendingCleanup.add(staging);
        }
      }
    }
  }

  function mintCapability() {
    let capability;
    do {
      capability = `secureshop-${randomBytes(32).toString('hex')}`;
    } while (registrations.has(capability));
    validateCapability(capability);
    return capability;
  }

  function removeRegistration(capability, registration) {
    registrations.delete(capability);
    if (registration?.reservedTarget
        && reservedTargets.get(registration.binding.targetId) === capability) {
      reservedTargets.delete(registration.binding.targetId);
    }
  }

  async function readExactControl(filename, expected) {
    const before = await lstatOrNull(filename);
    if (!before || !before.isFile() || before.isSymbolicLink() || before.size !== expected.length) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target control metadata is incomplete');
    }
    let handle;
    try {
      handle = await fs.open(
        filename,
        fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0) | (fsConstants.O_NONBLOCK || 0),
      );
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size !== expected.length) {
        fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target control metadata is incomplete');
      }
      const actual = Buffer.alloc(expected.length + 1);
      const { bytesRead } = await handle.read(actual, 0, actual.length, 0);
      if (bytesRead !== expected.length || !actual.subarray(0, bytesRead).equals(expected)) {
        fail('TARGET_BINDING_MISMATCH', 'reserved target control metadata does not match');
      }
    } catch (error) {
      if (error instanceof SecureShopFilesError) throw error;
      throw sanitizeNativeError(error);
    } finally {
      await handle?.close();
    }
  }

  async function validateReservedContainer(container, binding) {
    const root = await ensureRoot();
    const containerStat = await lstatOrNull(container);
    if (!containerStat || !containerStat.isDirectory() || containerStat.isSymbolicLink()) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target state is incomplete');
    }
    const realContainer = await fs.realpath(container);
    if (path.dirname(realContainer) !== root || path.basename(realContainer) !== `target-${binding.targetId}`) {
      fail('UNSAFE_FILESYSTEM', 'reserved target root is unsafe');
    }
    const entries = (await fs.readdir(container)).sort();
    if (entries.length !== 2 || entries[0] !== RESERVED_CONTROL_FILE || entries[1] !== RESERVED_DATA_DIRECTORY) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target state is incomplete');
    }
    await readExactControl(path.join(container, RESERVED_CONTROL_FILE), reservedControl(binding));
    await assertDirectoryNotSymlink(path.join(container, RESERVED_DATA_DIRECTORY), 'TARGET_RECONCILIATION_REQUIRED');
  }

  async function assertTargetCanProvision(root, targetId) {
    const { journal, temporary } = cleanupJournalPaths(root, targetId);
    if (await lstatOrNull(temporary)) {
      fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target cleanup journal is incomplete');
    }
    if (await lstatOrNull(journal)) {
      fail('TARGET_RETIRED', 'reserved target has entered durable retirement');
    }
  }

  function reservedProvisionResult(capability, registration, reopened) {
    const { targetId, launchId, scenarioId, generation, ownerId } = registration.binding;
    return Object.freeze({
      capability,
      targetId,
      launchId,
      scenarioId,
      generation,
      ownerId,
      binding: registration.binding,
      fixturePaths: FIXTURE_PATHS,
      reopened,
    });
  }

  // Reopen a durable reservation without mkdir, chmod, seeding or allocation.
  // Only process-local capability registration is created by this read path.
  async function openExistingReservedTarget(bindingInput) {
    const binding = validateReservedBinding(bindingInput);
    return withTargetLock(binding.targetId, async () => {
      await assertDirectoryNotSymlink(configuredRoot, 'TARGET_RECONCILIATION_REQUIRED');
      const existingRoot = await fs.realpath(configuredRoot);
      if (canonicalRoot && canonicalRoot !== existingRoot) fail('UNSAFE_FILESYSTEM', 'configured root changed');
      canonicalRoot = existingRoot;
      rootPromise ||= Promise.resolve(existingRoot);
      await assertTargetCanProvision(existingRoot, binding.targetId);
      if (await lstatOrNull(path.join(existingRoot, '.provision-' + binding.targetId))) {
        fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target provisioning state requires reconciliation');
      }
      const container = path.join(existingRoot, 'target-' + binding.targetId);
      await validateReservedContainer(container, binding);
      const attached = reservedTargets.get(binding.targetId);
      if (attached) {
        const registration = requireRegistration(attached);
        if (!reservedControl(registration.binding).equals(reservedControl(binding))) {
          fail('TARGET_BINDING_MISMATCH', 'reserved target binding does not match');
        }
        assertActive(registration);
        return reservedProvisionResult(attached, registration, true);
      }
      if (registrations.size >= maxSessions) fail('SESSION_LIMIT_EXCEEDED', 'SecureShop filesystem session limit reached');
      const capability = mintCapability();
      const registration = { binding, generation: binding.generation, lifecycle: 'active',
        pendingCleanup: new Set(), reservedTarget: true, directory: path.join(container, RESERVED_DATA_DIRECTORY) };
      registrations.set(capability, registration);
      reservedTargets.set(binding.targetId, capability);
      return reservedProvisionResult(capability, registration, true);
    });
  }

  async function provisionReservedTarget(bindingInput) {
    const binding = validateReservedBinding(bindingInput);
    return withTargetLock(binding.targetId, async () => {
      const attached = reservedTargets.get(binding.targetId);
      if (attached) {
        const registration = requireRegistration(attached);
        if (!reservedControl(registration.binding).equals(reservedControl(binding))) {
          fail('TARGET_BINDING_MISMATCH', 'reserved target binding does not match');
        }
        assertActive(registration);
        return reservedProvisionResult(attached, registration, true);
      }
      if (registrations.size >= maxSessions) {
        fail('SESSION_LIMIT_EXCEEDED', 'SecureShop filesystem session limit reached');
      }

      const capability = mintCapability();
      const containerName = `target-${binding.targetId}`;
      const registration = {
        binding,
        generation: binding.generation,
        lifecycle: 'active',
        pendingCleanup: new Set(),
        reservedTarget: true,
      };
      // Reserve process-local admission before the first filesystem await.
      registrations.set(capability, registration);
      reservedTargets.set(binding.targetId, capability);
      let staging;
      let createdStaging = false;
      let installed = false;
      try {
        const root = await ensureRoot();
        await assertTargetCanProvision(root, binding.targetId);
        const container = path.join(root, containerName);
        staging = path.join(root, `.provision-${binding.targetId}`);
        registration.directory = path.join(container, RESERVED_DATA_DIRECTORY);
        if (await lstatOrNull(staging)) {
          fail('TARGET_RECONCILIATION_REQUIRED', 'reserved target provisioning state requires reconciliation');
        }
        const current = await lstatOrNull(container);
        let reopened = Boolean(current);
        if (current) {
          await validateReservedContainer(container, binding);
        } else {
          await fs.mkdir(staging, { mode: 0o700, recursive: false });
          createdStaging = true;
          await fs.mkdir(path.join(staging, RESERVED_DATA_DIRECTORY), { mode: 0o700, recursive: false });
          await makeFixtureTree(path.join(staging, RESERVED_DATA_DIRECTORY), randomBytes);
          await fs.writeFile(path.join(staging, RESERVED_CONTROL_FILE), reservedControl(binding), { mode: 0o600, flag: 'wx' });
          await fs.rename(staging, container);
          installed = true;
          reopened = false;
          await validateReservedContainer(container, binding);
        }
        return reservedProvisionResult(capability, registration, reopened);
      } catch (error) {
        let failure = error;
        if (!createdStaging && error?.code === 'EEXIST') {
          failure = new SecureShopFilesError(
            'TARGET_RECONCILIATION_REQUIRED',
            'reserved target provisioning state requires reconciliation',
          );
        }
        if (createdStaging && !installed) {
          registration.pendingCleanup.add(staging);
          registration.lifecycle = 'provision_failed';
          failedProvisioning.add(capability);
        }
        if (!registration.pendingCleanup.size) removeRegistration(capability, registration);
        throw sanitizeNativeError(failure);
      }
    });
  }

  async function retireReservedTarget(bindingInput, options = {}) {
    const binding = validateReservedBinding(bindingInput);
    const operationId = validateOperationId(options.operationId);
    const coordinates = cleanupCoordinates(binding, operationId);
    return withTargetLock(binding.targetId, async () => {
      const root = await ensureRoot();
      await assertCleanupAuthorized(options.authorize, coordinates);
      const attached = reservedTargets.get(binding.targetId);

      const retire = async (registration) => {
        await assertCleanupAuthorized(options.authorize, coordinates);
        if (registration && !reservedControl(registration.binding).equals(reservedControl(binding))) {
          fail('TARGET_BINDING_MISMATCH', 'reserved target binding does not match');
        }
        const journalState = await readCleanupJournal(root, coordinates);
        const container = path.join(root, `target-${binding.targetId}`);
        const containerStat = await lstatOrNull(container);

        if (journalState?.status === 'completed') {
          if (containerStat) fail('TARGET_RECONCILIATION_REQUIRED', 'completed cleanup still has target state');
          await assertCleanupAuthorized(options.authorize, coordinates);
          if (registration) removeRegistration(reservedTargets.get(binding.targetId), registration);
          return journalState.receipt;
        }

        if (!journalState) {
          if (!containerStat) fail('TARGET_NOT_FOUND', 'reserved target does not exist');
          await validateReservedContainer(container, binding);
        } else if (containerStat) {
          await validateReservedContainer(container, binding);
        }

        if (registration) registration.lifecycle = 'retiring';
        const publication = journalState?.coordinates?.version === 2 || newCleanupVersion === 2
          ? Object.freeze({ ...coordinates, version: 2, durabilityMode: 'file_synced_rename_verified' })
          : coordinates;
        // A validated pending v1 may advance under the same exact authorization.
        // A completed v1 was already returned above and is never rewritten.
        if (!journalState || journalState.coordinates.version !== publication.version) {
          await writeCleanupJournal(root, binding.targetId, { ...publication, status: 'pending' });
        }
        await assertCleanupAuthorized(options.authorize, coordinates);
        if (containerStat) {
          try {
            await removeTree(container, { recursive: true, force: true });
            if (publication.version === 1) await syncDirectory(root);
            else if (await lstatOrNull(container)) throw Error('owned target remains');
          } catch {
            throw new SecureShopFilesError('RESERVED_CLEANUP_FAILED', 'reserved target cleanup remains pending');
          }
        }
        await assertCleanupAuthorized(options.authorize, coordinates);

        let completedAt;
        try {
          completedAt = now();
        } catch {
          fail('CLEANUP_DURABILITY_FAILED', 'reserved target cleanup state could not be made durable');
        }
        if (!isCanonicalTimestamp(completedAt)) {
          fail('CLEANUP_DURABILITY_FAILED', 'reserved target cleanup state could not be made durable');
        }
        if (publication.version === 2 && await lstatOrNull(container)) {
          fail('RESERVED_CLEANUP_FAILED', 'reserved target cleanup remains pending');
        }
        const receipt = cleanupReceipt(publication, completedAt);
        await assertCleanupAuthorized(options.authorize, coordinates);
        await writeCleanupJournal(root, binding.targetId, receipt);
        if (publication.version === 2 && await lstatOrNull(container)) {
          fail('RESERVED_CLEANUP_FAILED', 'reserved target cleanup remains uncertain');
        }
        await assertCleanupAuthorized(options.authorize, coordinates);
        if (registration) removeRegistration(reservedTargets.get(binding.targetId), registration);
        return receipt;
      };

      if (!attached) return retire(null);
      return withCapabilityLock(attached, retire);
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function readReservedCleanupReceipt(bindingInput, options = {}) {
    const binding = validateReservedBinding(bindingInput);
    const operationId = validateOperationId(options.operationId);
    const coordinates = cleanupCoordinates(binding, operationId);
    return withTargetLock(binding.targetId, async () => {
      const root = await ensureRoot();
      await assertCleanupAuthorized(options.authorize, coordinates);
      const journalState = await readCleanupJournal(root, coordinates);
      if (!journalState || journalState.status !== 'completed') {
        fail('CLEANUP_RECEIPT_UNAVAILABLE', 'completed reserved target cleanup receipt is unavailable');
      }
      const container = path.join(root, `target-${binding.targetId}`);
      if (await lstatOrNull(container)) {
        fail('TARGET_RECONCILIATION_REQUIRED', 'completed cleanup still has target state');
      }
      await assertCleanupAuthorized(options.authorize, coordinates);
      return journalState.receipt;
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function createOwnerSession(bindingInput) {
    const binding = validateBinding(bindingInput);
    if (registrations.size >= maxSessions) {
      fail('SESSION_LIMIT_EXCEEDED', 'SecureShop filesystem session limit reached');
    }
    const capability = mintCapability();
    const registration = { binding, generation: 0, lifecycle: 'active', pendingCleanup: new Set() };
    registrations.set(capability, registration);
    try {
      const seeded = await withCapabilityLock(capability, (current) => resetUnlocked(capability, current));
      return Object.freeze({ capability, binding, generation: seeded.generation, fixturePaths: seeded.fixturePaths });
    } catch (error) {
      if (registration.pendingCleanup.size) {
        // Keep the admission slot and exact cleanup paths without returning the
        // failed capability. Trusted maintenance can retry after storage recovers.
        registration.lifecycle = 'provision_failed';
        failedProvisioning.add(capability);
      } else removeRegistration(capability, registration);
      throw sanitizeNativeError(error);
    }
  }

  async function reconcileFailedProvisioning() {
    let removed = 0;
    for (const capability of [...failedProvisioning]) {
      try {
        await withCapabilityLock(capability, async (registration) => {
          await ensureRoot();
          await reconcileUnlocked(capability, registration);
          failedProvisioning.delete(capability);
          removeRegistration(capability, registration);
          removed += 1;
        });
      } catch {
        // Keep failures registered and capacity-reserved. Return counts only:
        // neither internal paths nor failed bearer capabilities leave this API.
      }
    }
    return Object.freeze({ removed, remaining: failedProvisioning.size });
  }

  async function readFile(capability, requested, options = {}) {
    return withCapabilityLock(capability, async (registration) => {
      assertActive(registration);
      assertExpectedGeneration(registration, options.expectedGeneration);
      const sessionRoot = await assertSessionRoot(capability);
      const { virtualPath, segments } = resolveVirtualPath(options.base || '/', requested);
      if (segments.length === 0) fail('INVALID_VIRTUAL_PATH', 'virtual path must name a file');
      await assertNoSymlinks(sessionRoot, segments);
      const filename = path.join(sessionRoot, ...segments);
      const finalStat = await fs.lstat(filename);
      if (!finalStat.isFile() || finalStat.isSymbolicLink()) {
        fail('INVALID_VIRTUAL_PATH', 'virtual path must name a regular file');
      }
      const limit = positiveInteger(options.maxBytes, maxReadBytes, 'maxBytes');
      if (limit > maxReadBytes) fail('READ_LIMIT_EXCEEDED', 'requested read limit exceeds configured maximum');
      let handle;
      try {
        handle = await fs.open(
          filename,
          fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0) | (fsConstants.O_NONBLOCK || 0),
        );
        const stat = await handle.stat();
        if (!stat.isFile()) fail('INVALID_VIRTUAL_PATH', 'virtual path must name a regular file');
        if (stat.size > limit) fail('READ_LIMIT_EXCEEDED', 'virtual file exceeds the read limit');
        const output = Buffer.alloc(Math.min(limit + 1, maxReadBytes + 1));
        let offset = 0;
        while (offset < output.length) {
          const { bytesRead } = await handle.read(output, offset, output.length - offset, offset);
          if (bytesRead === 0) break;
          offset += bytesRead;
        }
        if (offset > limit) fail('READ_LIMIT_EXCEEDED', 'virtual file grew beyond the read limit');
        const data = output.subarray(0, offset);
        return Object.freeze({
          generation: registration.generation,
          virtualPath,
          bytes: data.length,
          sha256: digest(data),
          data,
        });
      } catch (error) {
        if (isMissing(error)) fail('FILE_NOT_FOUND', 'virtual path does not exist');
        if (error && error.code === 'ELOOP') fail('SYMLINK_REJECTED', 'symbolic links are not allowed');
        throw sanitizeNativeError(error);
      } finally {
        await handle?.close();
      }
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function writeFile(capability, requested, contents, options = {}) {
    let data;
    try {
      data = Buffer.isBuffer(contents)
        ? Buffer.from(contents)
        : typeof contents === 'string'
          ? Buffer.from(contents, options.encoding || 'utf8')
          : fail('INVALID_CONTENT', 'contents must be a Buffer or string');
    } catch (error) {
      throw sanitizeNativeError(error);
    }
    if (data.length > maxWriteBytes) fail('WRITE_LIMIT_EXCEEDED', 'content exceeds the write limit');
    if (options.createOnly !== undefined && typeof options.createOnly !== 'boolean') {
      fail('INVALID_CONFIGURATION', 'createOnly must be boolean');
    }
    if (options.createParents !== undefined && typeof options.createParents !== 'boolean') {
      fail('INVALID_CONFIGURATION', 'createParents must be a boolean');
    }

    return withCapabilityLock(capability, async (registration) => {
      assertActive(registration);
      assertExpectedGeneration(registration, options.expectedGeneration);
      const sessionRoot = await assertSessionRoot(capability);
      const { virtualPath, segments } = resolveVirtualPath(options.base || '/', requested);
      if (segments.length === 0) fail('INVALID_VIRTUAL_PATH', 'virtual path must name a file');
      const parentSegments = segments.slice(0, -1);
      if (options.createParents === true) await ensurePrivateDirectories(sessionRoot, parentSegments);
      else await assertNoSymlinks(sessionRoot, parentSegments);
      await assertNoSymlinks(sessionRoot, segments, true);
      const parent = path.join(sessionRoot, ...parentSegments);
      const filename = path.join(parent, segments[segments.length - 1]);
      const temporary = path.join(parent, `.write-${crypto.randomBytes(16).toString('hex')}`);
      let handle;
      let published = false;
      try {
        handle = await fs.open(
          temporary,
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW || 0),
          0o600,
        );
        await handle.writeFile(data);
        await handle.sync();
        await handle.close();
        handle = undefined;
        await assertNoSymlinks(sessionRoot, parentSegments);
        const finalStat = await lstatOrNull(filename);
        if (finalStat && finalStat.isSymbolicLink()) fail('SYMLINK_REJECTED', 'symbolic links are not allowed');
        if (options.createOnly === true) {
          // Atomic no-replace publication. No rename/copy fallback is safe here.
          try { await fs.link(temporary, filename); }
          catch (error) {
            if (error?.code === 'EEXIST') fail('FILE_ALREADY_EXISTS', 'owned file already exists');
            throw error;
          }
          published = true;
          await fs.unlink(temporary);
          // File contents are synced; namespace power-loss durability is not claimed.
        } else {
          await fs.rename(temporary, filename);
        }
        return Object.freeze({
          generation: registration.generation,
          virtualPath,
          bytes: data.length,
          sha256: digest(data),
          ...(options.createOnly === true ? { publicationMode: 'file_synced_atomic_link' } : {}),
        });
      } catch (error) {
        // Once linked, retain the destination even when durability is uncertain.
        // The reserved-target lifecycle owns reconciliation and cleanup.
        if (published) fail('FILE_CREATE_UNCERTAIN', 'owned file publication is uncertain');
        throw sanitizeNativeError(error);
      } finally {
        await handle?.close();
        await fs.rm(temporary, { force: true }).catch(() => {});
      }
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function reset(capability, options = {}) {
    return withCapabilityLock(capability, (registration) => {
      assertActive(registration);
      if (registration.reservedTarget) {
        fail('EXTERNAL_LIFECYCLE_REQUIRED', 'reserved target reset requires durable lifecycle coordination');
      }
      assertExpectedGeneration(registration, options.expectedGeneration);
      return resetUnlocked(capability, registration);
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function reconcileCleanup(capability, options = {}) {
    return withCapabilityLock(capability, async (registration) => {
      assertActive(registration);
      if (registration.reservedTarget) {
        fail('EXTERNAL_LIFECYCLE_REQUIRED', 'reserved target cleanup requires durable lifecycle coordination');
      }
      assertExpectedGeneration(registration, options.expectedGeneration);
      await ensureRoot();
      const remaining = await reconcileUnlocked(capability, registration);
      return Object.freeze({ generation: registration.generation, cleanupPending: remaining });
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  async function destroy(capability, options = {}) {
    return withCapabilityLock(capability, async (registration) => {
      if (registration.reservedTarget) {
        fail('EXTERNAL_LIFECYCLE_REQUIRED', 'reserved target cleanup requires durable lifecycle coordination');
      }
      if (options.expectedGeneration === undefined) {
        fail('INVALID_GENERATION', 'destroy requires expectedGeneration');
      }
      assertExpectedGeneration(registration, options.expectedGeneration);
      registration.lifecycle = 'destroying';
      await ensureRoot();
      await reconcileUnlocked(capability, registration);
      try {
        await removeOwnedPath(capability, sessionDirectory(capability));
      } catch (error) {
        throw new SecureShopFilesError('DESTROY_CLEANUP_FAILED', 'SecureShop filesystem destruction failed');
      }
      removeRegistration(capability, registration);
      return Object.freeze({ destroyed: true, generation: registration.generation });
    }).catch((error) => { throw sanitizeNativeError(error); });
  }

  function getOwnerBinding(capability) {
    const registration = requireRegistration(capability);
    return {
      ...registration.binding,
      generation: registration.generation,
      lifecycle: registration.lifecycle,
      cleanupPending: registration.pendingCleanup.size,
    };
  }

  return Object.freeze({
    createOwnerSession,
    destroy,
    getOwnerBinding,
    provisionReservedTarget,
    openExistingReservedTarget,
    readReservedCleanupReceipt,
    readFile,
    reconcileCleanup,
    reconcileFailedProvisioning,
    reset,
    retireReservedTarget,
    writeFile,
  });
}

module.exports = {
  CAPABILITY_RE,
  SecureShopFilesError,
  createSecureShopFiles,
  resolveVirtualPath,
};
