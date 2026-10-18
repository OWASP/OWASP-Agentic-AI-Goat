'use strict';

const crypto = require('node:crypto');
const fsSync = require('node:fs');
const fs = require('node:fs/promises');
const path = require('node:path');

const RECEIPT_VERSION = 'mcp-owned-protected-state.v1';
const MAX_CONFIG_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUN_ID = UUID;
const { O_RDONLY } = fsSync.constants;

class McpProtectedStateError extends Error {
  constructor(code, message) { super(message); this.name = 'McpProtectedStateError'; this.code = code; }
}
const fail = (code, message) => { throw new McpProtectedStateError(code, message); };
const canonical = value => JSON.stringify(value, Object.keys(value).sort());
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function binding(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'generation,platformOwnerId,platformSessionId,targetId'
      || !UUID.test(value.targetId || '') || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1
      || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1
      || !Number.isSafeInteger(value.generation) || value.generation < 0) {
    fail('PROTECTED_STATE_SCOPE_INVALID', 'Exact protected-state scope is required');
  }
  return Object.freeze({ targetId: value.targetId.toLowerCase(), platformOwnerId: value.platformOwnerId,
    platformSessionId: value.platformSessionId, generation: value.generation });
}
async function regularNoLink(file, code) {
  let stat;
  try { stat = await fs.lstat(file); } catch { fail(code, 'Protected-state resource is unavailable'); }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) fail(code, 'Protected-state resource is invalid');
  return stat;
}
async function directoryNoLink(file) {
  let stat;
  try { stat = await fs.lstat(file); } catch { fail('PROTECTED_STATE_SCOPE_INVALID', 'Protected target is unavailable'); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) fail('PROTECTED_STATE_SCOPE_INVALID', 'Protected target is invalid');
}
async function syncDirectory(directory) {
  const handle = await fs.open(directory, O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function syncFile(file) {
  const handle = await fs.open(file, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}
function receipt(value) {
  const body = Object.freeze({ version: RECEIPT_VERSION, ...value });
  return Object.freeze({ ...body, receiptSha256: digest(Buffer.from(canonical(body))) });
}

function createMcpProtectedState({ clock = () => new Date().toISOString() } = {}) {
  async function validateTarget(input, { requireRun = true } = {}) {
    const scope = binding(input.scope);
    if (!path.isAbsolute(input.targetDirectory || '') || (requireRun && !RUN_ID.test(input.runId || ''))) {
      fail('PROTECTED_STATE_SCOPE_INVALID', 'Exact target directory and run are required');
    }
    await directoryNoLink(input.targetDirectory);
    const controlPath = path.join(input.targetDirectory, 'control.json');
    await regularNoLink(controlPath, 'PROTECTED_STATE_SCOPE_INVALID');
    let control;
    try { control = JSON.parse(await fs.readFile(controlPath, 'utf8')); } catch { fail('PROTECTED_STATE_SCOPE_INVALID', 'Protected target control is invalid'); }
    const expected = { version: 1, targetId: scope.targetId, ownerId: scope.platformOwnerId,
      platformSessionId: scope.platformSessionId, generation: scope.generation };
    if (canonical(control) !== canonical(expected)) fail('PROTECTED_STATE_SCOPE_INVALID', 'Protected target binding differs');
    const stateDirectory = path.join(input.targetDirectory, 'protected-state');
    await directoryNoLink(stateDirectory);
    const statePath = path.join(stateDirectory, 'current.json'); const auditPath = path.join(stateDirectory, 'audit.jsonl');
    await regularNoLink(statePath, 'PROTECTED_STATE_CORRUPT'); await regularNoLink(auditPath, 'PROTECTED_STATE_CORRUPT');
    let state;
    try { state = JSON.parse(await fs.readFile(statePath, 'utf8')); } catch { fail('PROTECTED_STATE_CORRUPT', 'Protected state is invalid'); }
    if (!state || state.version !== 1 || !Number.isSafeInteger(state.keyVersion) || state.keyVersion < 1
        || typeof state.auditEnabled !== 'boolean' || Object.keys(state).sort().join(',') !== 'auditEnabled,keyVersion,version') {
      fail('PROTECTED_STATE_CORRUPT', 'Protected state is invalid');
    }
    return { scope, runId: requireRun ? input.runId.toLowerCase() : null, targetDirectory: input.targetDirectory,
      stateDirectory, statePath, auditPath, state };
  }
  async function initializeTarget(input) {
    const scope = binding(input.scope);
    if (!path.isAbsolute(input.targetDirectory || '')) fail('PROTECTED_STATE_SCOPE_INVALID', 'Exact target directory is required');
    await directoryNoLink(input.targetDirectory);
    const stateDirectory = path.join(input.targetDirectory, 'protected-state');
    try {
      await fs.lstat(stateDirectory);
      await validateTarget({ scope, targetDirectory: input.targetDirectory }, { requireRun: false });
      return;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const temporary = path.join(input.targetDirectory, `.protected-state.${crypto.randomUUID()}.tmp`);
    try {
      await fs.mkdir(temporary, { mode: 0o700 });
      const state = await fs.open(path.join(temporary, 'current.json'), 'wx', 0o600);
      try { await state.writeFile(`${JSON.stringify({ version: 1, keyVersion: 1, auditEnabled: true })}\n`); await state.sync(); }
      finally { await state.close(); }
      const audit = await fs.open(path.join(temporary, 'audit.jsonl'), 'wx', 0o600);
      try { await audit.sync(); } finally { await audit.close(); }
      await syncDirectory(temporary);
      await fs.rename(temporary, stateDirectory);
      await syncDirectory(input.targetDirectory);
    } finally { await fs.rm(temporary, { recursive: true, force: true }); }
    await validateTarget({ scope, targetDirectory: input.targetDirectory }, { requireRun: false });
  }
  const open = input => validateTarget(input);
  async function writeState(context, next) {
    const temporary = path.join(context.stateDirectory, `.current.${crypto.randomUUID()}.tmp`);
    try {
      const handle = await fs.open(temporary, 'wx', 0o600);
      try { await handle.writeFile(`${JSON.stringify(next)}\n`); await handle.sync(); } finally { await handle.close(); }
      await fs.rename(temporary, context.statePath);
      await syncDirectory(context.stateDirectory);
    } finally { await fs.rm(temporary, { force: true }); }
  }
  async function audit(context, operation, outcome) {
    if (!context.state.auditEnabled) return false;
    const line = { version: 1, runId: context.runId, operation, outcome, at: clock() };
    const handle = await fs.open(context.auditPath, 'a', 0o600);
    try { await handle.writeFile(`${JSON.stringify(line)}\n`); await handle.sync(); } finally { await handle.close(); }
    return true;
  }
  return Object.freeze({ initializeTarget, validateTarget,
    async readConfiguration(input) {
      const context = await open(input); const configPath = path.join(context.targetDirectory, 'rootfs/opt/app/config/.env');
      const stat = await regularNoLink(configPath, 'PROTECTED_CONFIG_UNAVAILABLE');
      if (stat.size < 1 || stat.size > MAX_CONFIG_BYTES) fail('PROTECTED_CONFIG_UNAVAILABLE', 'Protected configuration size is invalid');
      const bytes = await fs.readFile(configPath);
      const audited = await audit(context, 'read_configuration', 'completed');
      return receipt({ operation: 'read_configuration', ...context.scope, runId: context.runId,
        configSha256: digest(bytes), byteCount: bytes.length, audited, output: bytes.toString('utf8') });
    },
    async rotateKeys(input) {
      const context = await open(input); const labRole = input.labRole;
      if (!['unprivileged', 'privileged'].includes(labRole) || typeof input.enforceAuthorization !== 'boolean') {
        fail('PROTECTED_STATE_ARGUMENTS_INVALID', 'Exact lab role and authorization policy are required');
      }
      const before = context.state.keyVersion;
      if (input.enforceAuthorization && labRole !== 'privileged') {
        const audited = await audit(context, 'rotate_keys', 'denied');
        return receipt({ operation: 'rotate_keys', ...context.scope, runId: context.runId, labRole,
          policy: 'enforced', changed: false, keyVersionBefore: before, keyVersionAfter: before, audited });
      }
      const next = { ...context.state, keyVersion: before + 1 }; await writeState(context, next); context.state = next;
      const audited = await audit(context, 'rotate_keys', 'completed');
      return receipt({ operation: 'rotate_keys', ...context.scope, runId: context.runId, labRole,
        policy: input.enforceAuthorization ? 'enforced' : 'vulnerable', changed: true,
        keyVersionBefore: before, keyVersionAfter: next.keyVersion, audited });
    },
    async setAuditLogging(input) {
      const context = await open(input); const action = input.action;
      if (!['enable', 'disable', 'clear'].includes(action)) fail('PROTECTED_STATE_ARGUMENTS_INVALID', 'Exact audit action is required');
      const auditEnabledBefore = context.state.auditEnabled;
      const prior = (await fs.readFile(context.auditPath, 'utf8')).split('\n').filter(Boolean).length;
      if (action === 'clear') { await fs.truncate(context.auditPath, 0); await syncFile(context.auditPath); }
      else {
        const next = { ...context.state, auditEnabled: action === 'enable' }; await writeState(context, next); context.state = next;
      }
      // Clearing and disabling are the vulnerable telemetry-blinding actions:
      // neither leaves a fresh record that would defeat the lesson. Enabling
      // logging is the legitimate control and records its own restoration.
      const audited = action === 'clear' ? false : await audit(context, `audit_${action}`, 'completed');
      const after = (await fs.readFile(context.auditPath, 'utf8')).split('\n').filter(Boolean).length;
      return receipt({ operation: 'set_audit_logging', ...context.scope, runId: context.runId, action,
        auditEnabledBefore, auditEnabled: context.state.auditEnabled,
        entriesBefore: prior, entriesAfter: after, audited });
    },
    async inspectAudit(input) {
      const context = await open(input); const bytes = await fs.readFile(context.auditPath);
      return receipt({ operation: 'inspect_audit', ...context.scope, runId: context.runId,
        auditEnabled: context.state.auditEnabled, auditSha256: digest(bytes),
        entryCount: bytes.toString('utf8').split('\n').filter(Boolean).length });
    },
  });
}

module.exports = { createMcpProtectedState, McpProtectedStateError, RECEIPT_VERSION };
