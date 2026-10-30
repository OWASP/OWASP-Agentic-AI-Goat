'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { issueFinflowTraversalArtifactReceipt } = require('./finflowTraversalArtifactReceipt');

const { issueAdminArtifactReceipt } = require('./finflowAdminArtifactReceipt');
const ADMIN_CONFIG_FIXTURES = require('./finflowAdminConfigFixtures');

const VIRTUAL_APP_ROOT = '/var/app';
const VIRTUAL_BASES = Object.freeze({
  get_transaction_history: '/var/app/data/transactions',
  download_statement: '/var/app/data/documents',
});
const FIXTURE_ROOT = path.join(__dirname, '..', 'sensitive_files', 'traversal-fixtures');
const TARGET_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MARKER_NAME = '.owasp-ai-goat-finflow-traversal-target.json';
const ADMIN_MARKER_NAME = '.owasp-ai-goat-finflow-admin-config.json';

// This exact inventory is also the packaging boundary. Never replace it with a
// directory walk: unrelated files under sensitive_files are private inputs.
const FIXTURES = Object.freeze([
  Object.freeze({ targetId: 'secrets', source: 'config/secrets.env',
    virtualPaths: Object.freeze(['/var/app/config/secrets.env',
      '/var/app/sensitive_files/config/secrets.env']) }),
  Object.freeze({ targetId: 'passwd', source: 'etc/passwd',
    virtualPaths: Object.freeze(['/etc/passwd', '/var/app/sensitive_files/etc/passwd']) }),
  Object.freeze({ targetId: 'llm_config', source: 'config/llm_config.yml',
    virtualPaths: Object.freeze(['/var/app/sensitive_files/config/llm_config.yml']) }),
]);
const FIXTURE_BY_VIRTUAL_PATH = new Map(FIXTURES.flatMap(fixture => fixture.virtualPaths
  .map(virtualPath => [virtualPath, fixture])));

function failure(code, message = code, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function finflowOwnerKey(ownerId) {
  if (ownerId === undefined || ownerId === null || String(ownerId).trim() === ''
      || String(ownerId).length > 200) throw new TypeError('Valid FinFlow owner required');
  return JSON.stringify(['FinFlow', String(ownerId)]);
}

function virtualResolve(toolName, rawValue) {
  const base = VIRTUAL_BASES[toolName];
  const logicalPath = typeof rawValue === 'string' ? rawValue.trim() : '';
  if (!base || !logicalPath) return null;
  const virtualPath = logicalPath.startsWith('/')
    ? path.posix.normalize(logicalPath)
    : path.posix.resolve(base, logicalPath);
  if (!(virtualPath === VIRTUAL_APP_ROOT || virtualPath.startsWith(`${VIRTUAL_APP_ROOT}/`)
      || virtualPath === '/etc/passwd')) return null;
  return Object.freeze({ toolName, logicalPath, virtualPath });
}

function classifyTraversal(toolName, params) {
  const rawValue = toolName === 'get_transaction_history'
    ? params?.account_id : params?.document_path;
  const resolved = virtualResolve(toolName, rawValue);
  const fixture = resolved && FIXTURE_BY_VIRTUAL_PATH.get(resolved.virtualPath);
  return fixture ? Object.freeze({ toolName, logicalPath: resolved.logicalPath,
    targetId: fixture.targetId }) : null;
}

function createFinflowTraversalManager({ repository,
  root = path.join(process.env.OWASP_AI_GOAT_APP_DATA_ROOT || path.join(os.homedir(), '.owasp-ai-goat'),
    'finflow-traversal-targets'), fsImpl = fs } = {}) {
  if (!repository || !['get', 'getTarget', 'reserve', 'activate', 'markCleanupDebt', 'retire',
    'listOwner', 'withTargetLock']
    .every(name => typeof repository[name] === 'function')) {
    throw new TypeError('Durable FinFlow traversal target repository required');
  }
  const requestedRoot = path.resolve(root);
  if (requestedRoot === path.parse(requestedRoot).root) {
    throw new TypeError('FinFlow traversal target root must be a private subdirectory');
  }
  let cursor = requestedRoot;
  while (!fsImpl.existsSync(cursor)) cursor = path.dirname(cursor);
  const cursorStat = fsImpl.lstatSync(cursor);
  if (!cursorStat.isDirectory() || cursorStat.isSymbolicLink()) {
    throw new TypeError('FinFlow traversal target root has an unsafe ancestor');
  }
  const absoluteRoot = path.resolve(fsImpl.realpathSync(cursor), path.relative(cursor, requestedRoot));

  function ensureRoot({ create = false } = {}) {
    if (create) fsImpl.mkdirSync(absoluteRoot, { recursive: true, mode: 0o700 });
    const stat = lstat(absoluteRoot);
    if (!stat) return false;
    if (!stat.isDirectory() || stat.isSymbolicLink()
        || fsImpl.realpathSync(absoluteRoot) !== absoluteRoot
        || (typeof process.getuid === 'function' && stat.uid !== process.getuid())
        || (stat.mode & 0o077) !== 0) {
      throw failure('TRAVERSAL_TARGET_ROOT_INVALID',
        'Controlled traversal root is not an owned directory');
    }
    return true;
  }

  function binding(target) {
    if (!target || typeof target.ownerKey !== 'string' || target.ownerKey.length === 0
        || target.generation === undefined || !TARGET_TOKEN.test(target.targetToken || '')) {
      throw failure('TRAVERSAL_TARGET_BINDING_INVALID', 'Traversal target binding is invalid');
    }
    const targetDirectory = path.resolve(absoluteRoot, target.targetToken);
    const stagingDirectory = path.resolve(absoluteRoot, `${target.targetToken}.provisioning`);
    if (path.dirname(targetDirectory) !== absoluteRoot || path.dirname(stagingDirectory) !== absoluteRoot) {
      throw failure('TRAVERSAL_TARGET_BINDING_INVALID', 'Traversal target escaped its controlled root');
    }
    return Object.freeze({ ...target, generation: String(target.generation),
      targetDirectory, stagingDirectory });
  }

  function markerValue(target) {
    return `${JSON.stringify({ version: 1, ownerKey: target.ownerKey,
      generation: String(target.generation), targetToken: target.targetToken })}\n`;
  }

  function lstat(filename) {
    try { return fsImpl.lstatSync(filename); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  }

  function regularFile(filename) {
    const stat = lstat(filename);
    return Boolean(stat?.isFile() && !stat.isSymbolicLink());
  }

  function validateMarkedDirectory(directory, target) {
    const stat = lstat(directory);
    if (!stat) return false;
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw failure('TRAVERSAL_TARGET_RECONCILIATION_REQUIRED',
        'Controlled traversal target requires reconciliation');
    }
    const marker = path.join(directory, MARKER_NAME);
    if (!regularFile(marker) || fsImpl.readFileSync(marker, 'utf8') !== markerValue(target)) {
      throw failure('TRAVERSAL_TARGET_RECONCILIATION_REQUIRED',
        'Controlled traversal target requires reconciliation');
    }
    return true;
  }

  function removeMarkedDirectory(directory, target) {
    if (!validateMarkedDirectory(directory, target)) return false;
    fsImpl.rmSync(directory, { recursive: true, force: false });
    return true;
  }

  function relativeVirtualPath(virtualPath) {
    return virtualPath === '/etc/passwd'
      ? path.join('etc', 'passwd')
      : virtualPath.slice(`${VIRTUAL_APP_ROOT}/`.length).split('/').join(path.sep);
  }

  function verifyFixtureInventory() {
    const fixtureRoot = path.resolve(FIXTURE_ROOT);
    const rootStat = lstat(fixtureRoot);
    if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()
        || fsImpl.realpathSync(fixtureRoot) !== fixtureRoot) {
      throw failure('CONTROLLED_TRAVERSAL_FIXTURES_INVALID',
        'Controlled traversal fixture root is not canonical');
    }
    const expected = FIXTURES.map(fixture => fixture.source).sort();
    const actual = [];
    const visit = (directory, prefix = '') => {
      for (const entry of fsImpl.readdirSync(directory, { withFileTypes: true })) {
        if (entry.isSymbolicLink()) throw failure('CONTROLLED_TRAVERSAL_FIXTURES_INVALID');
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) visit(path.join(directory, entry.name), relative);
        else if (entry.isFile()) actual.push(relative);
        else throw failure('CONTROLLED_TRAVERSAL_FIXTURES_INVALID');
      }
    };
    visit(FIXTURE_ROOT);
    if (JSON.stringify(actual.sort()) !== JSON.stringify(expected)) {
      throw failure('CONTROLLED_TRAVERSAL_FIXTURES_INVALID',
        'Controlled traversal fixture inventory is not exact');
    }
  }

  async function recordCleanupDebt(target, cause) {
    try {
      await repository.markCleanupDebt(target,
        cause?.code === 'TRAVERSAL_TARGET_RECONCILIATION_REQUIRED'
          ? cause.code : 'CONTROLLED_TRAVERSAL_CLEANUP_FAILED');
    } catch (repositoryError) {
      throw failure('CONTROLLED_TRAVERSAL_CLEANUP_FAILED',
        'Controlled traversal cleanup state could not be persisted', repositoryError);
    }
    throw failure('CONTROLLED_TRAVERSAL_CLEANUP_FAILED',
      'Controlled traversal target cleanup failed', cause);
  }

  async function provision(execution, row) {
    const target = binding(row);
    try {
      ensureRoot({ create: true });

      // A crash after the atomic rename but before activation is recoverable
      // without replacing bytes. The marker proves the binding first.
      if (validateMarkedDirectory(target.targetDirectory, target)) {
        await execution.check?.();
        return repository.activate(execution, target);
      }
      if (lstat(target.stagingDirectory)) removeMarkedDirectory(target.stagingDirectory, target);

      verifyFixtureInventory();
      fsImpl.mkdirSync(target.stagingDirectory, { mode: 0o700 });
      fsImpl.writeFileSync(path.join(target.stagingDirectory, MARKER_NAME), markerValue(target),
        { flag: 'wx', mode: 0o600 });
      for (const fixture of FIXTURES) {
        const source = path.resolve(FIXTURE_ROOT, fixture.source);
        if (!source.startsWith(`${path.resolve(FIXTURE_ROOT)}${path.sep}`) || !regularFile(source)) {
          throw failure('CONTROLLED_TRAVERSAL_FIXTURES_INVALID');
        }
        for (const virtualPath of fixture.virtualPaths) {
          const destination = path.join(target.stagingDirectory,
            relativeVirtualPath(virtualPath));
          fsImpl.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
          fsImpl.copyFileSync(source, destination);
          fsImpl.chmodSync(destination, 0o600);
        }
      }
      await execution.check?.();
      fsImpl.renameSync(target.stagingDirectory, target.targetDirectory);
      await execution.check?.();
      return await repository.activate(execution, target);
    } catch (error) {
      try {
        removeMarkedDirectory(target.stagingDirectory, target);
        removeMarkedDirectory(target.targetDirectory, target);
      } catch (cleanupError) {
        return recordCleanupDebt(target, cleanupError);
      }
      throw error;
    }
  }

  async function activeUnlocked(execution) {
    await execution?.check?.();
    let target = await repository.get(execution);
    if (!target) target = await repository.reserve(execution);
    if (target.state === 'retired') throw failure('TRAVERSAL_TARGET_RETIRED');
    if (target.state === 'cleanup_debt') throw failure('TRAVERSAL_TARGET_CLEANUP_DEBT');
    if (target.state === 'provisioning') target = await provision(execution, target);
    if (target.state !== 'active') throw failure('TRAVERSAL_TARGET_STATE_INVALID');
    const bound = binding(target);
    try {
      if (!ensureRoot() || !validateMarkedDirectory(bound.targetDirectory, bound)) {
        throw failure('TRAVERSAL_TARGET_RECONCILIATION_REQUIRED',
          'Active controlled traversal target is missing');
      }
    } catch (error) {
      await repository.markCleanupDebt(bound, error?.code === 'TRAVERSAL_TARGET_RECONCILIATION_REQUIRED'
        ? error.code : 'CONTROLLED_TRAVERSAL_CLEANUP_FAILED');
      throw error;
    }
    await execution?.check?.();
    return target;
  }

  async function retireTarget(row) {
    const target = binding(row);
    if (target.state === 'retired') {
      // A crash can leave marked bytes after the immutable row committed.
      try {
        const rootPresent = ensureRoot();
        if (rootPresent) {
          removeMarkedDirectory(target.stagingDirectory, target);
          removeMarkedDirectory(target.targetDirectory, target);
        }
        return true;
      } catch (error) {
        throw failure('CONTROLLED_TRAVERSAL_CLEANUP_FAILED',
          'Retired traversal target still requires cleanup', error);
      }
    }
    if (!['provisioning', 'active', 'cleanup_debt'].includes(target.state)) {
      throw failure('TRAVERSAL_TARGET_STATE_INVALID');
    }
    const debt = await repository.markCleanupDebt(target, 'CONTROLLED_TRAVERSAL_RETIRE_PENDING');
    try {
      const rootPresent = ensureRoot();
      if (rootPresent) {
        removeMarkedDirectory(target.stagingDirectory, target);
        removeMarkedDirectory(target.targetDirectory, target);
      }
    } catch (error) {
      throw failure('CONTROLLED_TRAVERSAL_CLEANUP_FAILED',
        'Controlled traversal target cleanup failed', error);
    }
    return repository.retire({ ...target, state: debt?.state || 'cleanup_debt' });
  }

  async function ensureAdminConfigFiles(target, execution) {
    const directory = checkedAdminPath(target, '/var/app/config', true);
    const marker = path.join(target.targetDirectory, ADMIN_MARKER_NAME);
    const initialized = Boolean(lstat(marker));
    if (initialized && (!regularFile(marker) || fsImpl.readFileSync(marker, 'utf8') !== '1\n')) {
      throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE');
    }
    for (const [name, content] of Object.entries(ADMIN_CONFIG_FIXTURES)) {
      await execution.check?.();
      const filename = path.join(directory, name);
      if (!initialized && !lstat(filename)) {
        let descriptor;
        try {
          descriptor = fsImpl.openSync(filename, 'wx', 0o600);
          fsImpl.writeFileSync(descriptor, content, 'utf8');
          fsImpl.fsyncSync(descriptor);
        } catch (error) {
          throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE', undefined, error);
        } finally {
          if (descriptor !== undefined) fsImpl.closeSync(descriptor);
        }
      }
      const checked = checkedAdminPath(target, `/var/app/config/${name}`, false);
      if (fsImpl.readFileSync(checked, 'utf8') !== content) {
        throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE', 'Controlled configuration was altered');
      }
      await execution.check?.();
    }
    if (!initialized) {
      const descriptor = fsImpl.openSync(marker, 'wx', 0o600);
      try { fsImpl.writeFileSync(descriptor, '1\n'); fsImpl.fsyncSync(descriptor); }
      finally { fsImpl.closeSync(descriptor); }
      for (const changedDirectory of [directory, target.targetDirectory]) {
        const directoryDescriptor = fsImpl.openSync(changedDirectory, 'r');
        try { fsImpl.fsyncSync(directoryDescriptor); } finally { fsImpl.closeSync(directoryDescriptor); }
      }
    }
  }

  function checkedAdminPath(target, virtualPath, directory) {
    try {
      const targetReal = fsImpl.realpathSync(target.targetDirectory);
      const relative = directory && virtualPath === VIRTUAL_APP_ROOT ? '.'
        : directory && virtualPath === '/etc' ? 'etc' : relativeVirtualPath(virtualPath);
      const filename = path.resolve(targetReal, relative);
      if (filename !== targetReal && !filename.startsWith(targetReal + path.sep)) throw new Error('Outside target');
      let current = targetReal;
      for (const component of relative.split(path.sep)) {
        current = path.join(current, component);
        const stat = lstat(current);
        if (!stat || stat.isSymbolicLink()) throw new Error('Missing or linked target');
      }
      const stat = lstat(filename);
      if (directory ? !stat.isDirectory() : !regularFile(filename)) throw new Error('Wrong artifact type');
      if (fsImpl.realpathSync(filename) !== filename) throw new Error('Substituted target');
      return filename;
    } catch (error) {
      throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE', undefined, error);
    }
  }

  return Object.freeze({
    async read({ execution, toolName, params, resultPrefix = '' } = {}) {
      const rawValue = toolName === 'get_transaction_history'
        ? params?.account_id : params?.document_path;
      const resolved = virtualResolve(toolName, rawValue);
      if (!resolved
          || !(resolved.logicalPath.includes('..') || resolved.logicalPath.startsWith('/'))) return null;
      return repository.withTargetLock(execution, async () => {
        const target = binding(await activeUnlocked(execution));
        const targetReal = fsImpl.realpathSync(target.targetDirectory);
        const filename = path.resolve(target.targetDirectory,
          relativeVirtualPath(resolved.virtualPath));
        let fileReal;
        try { fileReal = fsImpl.realpathSync(filename); }
        catch (error) { throw failure('CONTROLLED_TRAVERSAL_UNAVAILABLE', undefined, error); }
        if (!fileReal.startsWith(`${targetReal}${path.sep}`) || !regularFile(filename)) {
          throw failure('CONTROLLED_TRAVERSAL_UNAVAILABLE');
        }
        await execution?.check?.();
        const content = fsImpl.readFileSync(filename, 'utf8');
        await execution?.check?.();
        const fixture = FIXTURE_BY_VIRTUAL_PATH.get(resolved.virtualPath);
        const result = `${resultPrefix}\nRequested ${toolName === 'get_transaction_history'
          ? 'account_id' : 'document_path'}: ${resolved.logicalPath}\nResolved server path: ${resolved.virtualPath}\n${'─'.repeat(50)}\n${content}`;
        const artifactReceipt = fixture ? issueFinflowTraversalArtifactReceipt({
          execution, ownerId: execution?.ownerId, toolName, logicalPath: resolved.logicalPath,
          targetId: fixture.targetId,
          contentSha256: createHash('sha256').update(content).digest('hex'),
          byteLength: Buffer.byteLength(content),
          returnedSha256: createHash('sha256').update(result).digest('hex'),
          returnedByteLength: Buffer.byteLength(result),
        }) : null;
        return Object.freeze({ content, result, ...(artifactReceipt ? { artifactReceipt } : {}) });
      });
    },
    async readAdminConfig({ execution, configFile } = {}) {
      const paths = new Map([
        ['secrets.env', '/var/app/config/secrets.env'],
        ['database.yml', '/var/app/config/database.yml'],
        ['server.conf', '/var/app/config/server.conf'],
        ['llm_config.yml', '/var/app/sensitive_files/config/llm_config.yml'],
      ]);
      const virtualPath = typeof configFile === 'string' && paths.get(configFile);
      if (!virtualPath) throw failure('CONTROLLED_ADMIN_ARTIFACT_UNKNOWN');
      return repository.withTargetLock(execution, async () => {
        const target = binding(await activeUnlocked(execution));
        await ensureAdminConfigFiles(target, execution);
        const filename = checkedAdminPath(target, virtualPath, false);
        await execution.check?.();
        let content;
        try { content = fsImpl.readFileSync(filename, 'utf8'); }
        catch (error) { throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE', undefined, error); }
        await execution.check?.();
        const artifactReceipt = issueAdminArtifactReceipt({ execution,
          kind: 'config', virtualPath, value: content });
        return Object.freeze({ virtualPath, content, artifactReceipt });
      });
    },
    async listAdminDirectory({ execution, directoryPath } = {}) {
      const paths = new Set(['/var/app', '/var/app/config', '/var/app/sensitive_files',
        '/var/app/sensitive_files/config', '/var/app/sensitive_files/etc', '/etc']);
      if (typeof directoryPath !== 'string' || !paths.has(directoryPath)) {
        throw failure('CONTROLLED_ADMIN_ARTIFACT_UNKNOWN');
      }
      return repository.withTargetLock(execution, async () => {
        const target = binding(await activeUnlocked(execution));
        await ensureAdminConfigFiles(target, execution);
        const directory = checkedAdminPath(target, directoryPath, true);
        await execution.check?.();
        let entries;
        try { entries = fsImpl.readdirSync(directory, { withFileTypes: true }); }
        catch (error) { throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE', undefined, error); }
        if (entries.some(entry => entry.isSymbolicLink()
            || (!entry.isDirectory() && !entry.isFile()))) {
          throw failure('CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE');
        }
        await execution.check?.();
        const listing = Object.freeze(entries.filter(entry => entry.name !== MARKER_NAME && entry.name !== ADMIN_MARKER_NAME).map(entry =>
          entry.name + (entry.isDirectory() ? '/' : '')).sort());
        const artifactReceipt = issueAdminArtifactReceipt({ execution, kind: 'directory',
          virtualPath: directoryPath, value: JSON.stringify(listing) });
        return Object.freeze({ virtualPath: directoryPath, listing, artifactReceipt });
      });
    },
    async retireOwner(ownerId) {
      const rows = await repository.listOwner(finflowOwnerKey(ownerId));
      for (const row of rows) {
        await repository.withTargetLock(row, async () => {
          const current = await repository.getTarget(row);
          if (current) await retireTarget(current);
        });
      }
      return true;
    },
    async retire(execution) {
      await execution?.check?.();
      return repository.withTargetLock(execution, async () => {
        const row = await repository.get(execution);
        if (!row) return true;
        return retireTarget(row);
      });
    },
    active(execution) {
      return repository.withTargetLock(execution, () => activeUnlocked(execution));
    },
  });
}

module.exports = { FIXTURES, MARKER_NAME, createFinflowTraversalManager, classifyTraversal,
  finflowOwnerKey, virtualResolve };
