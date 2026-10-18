'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const util = require('node:util');
const crypto = require('node:crypto');

const {
  CAPABILITY_RE,
  createSecureShopFiles,
  resolveVirtualPath,
} = require('../sidecars/sandbox-runner/secureshopFiles');

const OWNER_A = Object.freeze({
  ownerId: 'student-17',
  role: 'customer',
  sessionId: '94bf15e0-20f4-4ced-99df-10cf35f64bd2',
});
const OWNER_B = Object.freeze({
  ownerId: 'merchant-4',
  role: 'merchant',
  sessionId: 'c9ae29f8-9b5e-40d3-b92d-e711557e4031',
});
const RESERVED_A = Object.freeze({
  targetId: '41ed0e59-42ca-47ab-98df-608f45a18304',
  launchId: '9242e9ec-4ec3-4a3e-b039-e744e2bb487c',
  scenarioId: 'b8d34278-1d15-46c6-9767-3865290f058f',
  generation: 7,
  ownerId: '17',
});
const RESERVED_B = Object.freeze({
  targetId: 'ee4d3cf1-6d29-466e-932e-2fcf9463c9eb',
  launchId: '81de3ebf-404f-4e40-82a0-9374de0ff63a',
  scenarioId: '70f5747a-b504-458d-a553-fbab901928f0',
  generation: 3,
  ownerId: '18',
});

async function fixture(options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshop-files-'));
  const root = path.join(directory, 'sessions');
  const files = createSecureShopFiles({ root, maxReadBytes: 256, maxWriteBytes: 64, ...options });
  return {
    directory,
    files,
    root,
    cleanup: () => fs.rm(directory, { recursive: true, force: true }),
  };
}

function rejectsCode(promise, code) {
  return assert.rejects(promise, (error) => error && error.code === code);
}

test('virtual resolution keeps absolute paths and traversal inside the virtual namespace', () => {
  assert.deepEqual(resolveVirtualPath('/uploads/avatars', '../../../server/config/.env'), {
    virtualPath: '/server/config/.env',
    segments: ['server', 'config', '.env'],
  });
  assert.equal(resolveVirtualPath('/uploads', '/etc/passwd').virtualPath, '/etc/passwd');
  assert.equal(resolveVirtualPath('/', '../../../../../../tmp/host-secret').virtualPath, '/tmp/host-secret');
});

test('capabilities are minted, exact-format, owner-bound, and valid-looking unknown keys fail closed', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  assert.match(owner.capability, CAPABILITY_RE);
  assert.deepEqual(f.files.getOwnerBinding(owner.capability), {
    ...OWNER_A,
    generation: 1,
    lifecycle: 'active',
    cleanupPending: 0,
  });

  await rejectsCode(f.files.readFile('student-17', '/etc/passwd'), 'INVALID_CAPABILITY');
  await rejectsCode(f.files.readFile(`secureshop-${'a'.repeat(64)}`, '/etc/passwd'), 'UNKNOWN_CAPABILITY');
  await rejectsCode(f.files.createOwnerSession({ ...OWNER_A, sessionId: 'student-chosen' }), 'INVALID_OWNER_BINDING');
});

test('each owner receives real isolated synthetic files with unpredictable markers', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const a = await f.files.createOwnerSession(OWNER_A);
  const b = await f.files.createOwnerSession(OWNER_B);
  const aEnv = await f.files.readFile(a.capability, '/server/config/.env');
  const bEnv = await f.files.readFile(b.capability, '/server/config/.env');

  assert.match(aEnv.data.toString(), /^SECURESHOP_LAB_MARKER=[a-f0-9]{48}$/m);
  assert.notEqual(aEnv.data.toString(), bEnv.data.toString());
  assert.notEqual(aEnv.sha256, bEnv.sha256);
  assert.equal(aEnv.virtualPath, '/server/config/.env');
  assert.equal(aEnv.bytes, aEnv.data.length);
});

test('intended traversal reads real files in the same owner namespace only', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const a = await f.files.createOwnerSession(OWNER_A);
  const b = await f.files.createOwnerSession(OWNER_B);
  const traversed = await f.files.readFile(a.capability, '../server/config/.env', { base: '/uploads' });
  const direct = await f.files.readFile(a.capability, '/server/config/.env');
  const other = await f.files.readFile(b.capability, '/server/config/.env');

  assert.equal(traversed.virtualPath, '/server/config/.env');
  assert.deepEqual(traversed.data, direct.data);
  assert.notDeepEqual(traversed.data, other.data);
  await rejectsCode(
    f.files.readFile(a.capability, `/${b.capability}/server/config/.env`),
    'FILE_NOT_FOUND',
  );
});

test('host absolute paths are virtual and cannot reach a file outside the session root', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const hostSecret = path.join(f.directory, 'host-private.txt');
  await fs.writeFile(hostSecret, 'HOST_PRIVATE_CANARY');

  await rejectsCode(f.files.readFile(owner.capability, hostSecret), 'FILE_NOT_FOUND');
  await rejectsCode(
    f.files.readFile(owner.capability, `../../../../${hostSecret}`),
    'FILE_NOT_FOUND',
  );
});

test('read and write reject final and ancestor symlinks', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const sessionRoot = path.join(f.root, owner.capability);
  const hostSecret = path.join(f.directory, 'host-private.txt');
  await fs.writeFile(hostSecret, 'HOST_PRIVATE_CANARY');
  await fs.symlink(hostSecret, path.join(sessionRoot, 'uploads', 'final-link'));
  await fs.symlink(f.directory, path.join(sessionRoot, 'uploads', 'parent-link'));

  await rejectsCode(f.files.readFile(owner.capability, 'final-link', { base: '/uploads' }), 'SYMLINK_REJECTED');
  await rejectsCode(f.files.writeFile(owner.capability, 'final-link', 'overwrite', { base: '/uploads' }), 'SYMLINK_REJECTED');
  await rejectsCode(f.files.readFile(owner.capability, 'parent-link/host-private.txt', { base: '/uploads' }), 'SYMLINK_REJECTED');
  await rejectsCode(f.files.writeFile(owner.capability, 'parent-link/new.txt', 'escape', { base: '/uploads' }), 'SYMLINK_REJECTED');
  await rejectsCode(f.files.writeFile(owner.capability, 'parent-link/nested/new.txt', 'escape', {
    base: '/uploads', createParents: true,
  }), 'SYMLINK_REJECTED');
  assert.equal(await fs.readFile(hostSecret, 'utf8'), 'HOST_PRIVATE_CANARY');
  await assert.rejects(fs.access(path.join(f.directory, 'new.txt')));
});

test('special files are rejected before a FIFO read can block', { skip: process.platform === 'win32' }, async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const fifo = path.join(f.root, owner.capability, 'uploads', 'blocking-pipe');
  const made = spawnSync('mkfifo', [fifo], { stdio: 'ignore', timeout: 1000 });
  if (made.error || made.status !== 0) {
    t.skip('mkfifo is unavailable');
    return;
  }
  await Promise.race([
    rejectsCode(f.files.readFile(owner.capability, '/uploads/blocking-pipe'), 'INVALID_VIRTUAL_PATH'),
    new Promise((_, reject) => setTimeout(() => reject(new Error('FIFO read blocked')), 500)),
  ]);
});

test('bounded writes persist exact bytes and bounded reads fail before returning oversized content', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const payload = Buffer.from('real isolated upload bytes');
  const written = await f.files.writeFile(owner.capability, 'avatar.txt', payload, { base: '/uploads' });
  const read = await f.files.readFile(owner.capability, '/uploads/avatar.txt');
  assert.equal(written.virtualPath, '/uploads/avatar.txt');
  assert.equal(written.sha256, read.sha256);
  assert.deepEqual(read.data, payload);

  await rejectsCode(f.files.writeFile(owner.capability, 'large.bin', Buffer.alloc(65), { base: '/uploads' }), 'WRITE_LIMIT_EXCEEDED');
  await rejectsCode(f.files.readFile(owner.capability, '/server/config/.env', { maxBytes: 8 }), 'READ_LIMIT_EXCEEDED');
  await rejectsCode(f.files.readFile(owner.capability, '/server/config/.env', { maxBytes: 257 }), 'READ_LIMIT_EXCEEDED');
  await rejectsCode(f.files.readFile(owner.capability, '/uploads'), 'INVALID_VIRTUAL_PATH');
});

test('nested writes create private parents only when explicitly requested', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const virtualPath = '/uploads/product_manuals/7/operation-manual';
  await rejectsCode(f.files.writeFile(owner.capability, virtualPath, 'manual'), 'FILE_NOT_FOUND');
  const written = await f.files.writeFile(owner.capability, virtualPath, 'manual', { createParents: true });
  assert.equal(written.virtualPath, virtualPath);
  assert.equal((await f.files.readFile(owner.capability, virtualPath)).data.toString(), 'manual');

  const root = path.join(f.root, owner.capability);
  for (const relative of ['uploads/product_manuals', 'uploads/product_manuals/7']) {
    const stat = await fs.lstat(path.join(root, relative));
    assert.equal(stat.isDirectory(), true);
    assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.mode & 0o777, 0o700);
  }
  await rejectsCode(f.files.writeFile(owner.capability, '/uploads/other/file', 'x', {
    createParents: 'yes',
  }), 'INVALID_CONFIGURATION');
});

test('reset removes mutations, increments generation, and reseeds different evidence', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const before = await f.files.readFile(owner.capability, '/server/config/.env');
  await f.files.writeFile(owner.capability, '/uploads/student.txt', 'student mutation');
  const reset = await f.files.reset(owner.capability);
  const after = await f.files.readFile(owner.capability, '/server/config/.env');

  assert.equal(reset.generation, 2);
  assert.equal(after.generation, 2);
  assert.notEqual(after.sha256, before.sha256);
  await rejectsCode(f.files.readFile(owner.capability, '/uploads/student.txt'), 'FILE_NOT_FOUND');
});

test('writes and reset serialize so reset cannot leave a stale in-flight mutation', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const write = f.files.writeFile(owner.capability, '/uploads/race.txt', Buffer.alloc(64, 7));
  const reset = f.files.reset(owner.capability);
  await Promise.all([write, reset]);
  await rejectsCode(f.files.readFile(owner.capability, '/uploads/race.txt'), 'FILE_NOT_FOUND');
  assert.equal(f.files.getOwnerBinding(owner.capability).generation, 2);
});

test('expected generation fences stale work after reset', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  await f.files.reset(owner.capability, { expectedGeneration: 1 });
  await rejectsCode(
    f.files.writeFile(owner.capability, '/uploads/stale.txt', 'must not land', { expectedGeneration: 1 }),
    'STALE_GENERATION',
  );
  await rejectsCode(
    f.files.readFile(owner.capability, '/etc/passwd', { expectedGeneration: 1 }),
    'STALE_GENERATION',
  );
  await rejectsCode(f.files.readFile(owner.capability, '/uploads/stale.txt'), 'FILE_NOT_FOUND');
});

test('cleanup failure cannot leave the installed reset under a stale generation', async (t) => {
  let failCleanup = false;
  const f = await fixture({
    removeTree: async (...args) => {
      if (failCleanup) throw new Error(`private native path must not escape: ${args[0]}`);
      return fs.rm(...args);
    },
  });
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const before = await f.files.readFile(owner.capability, '/server/config/.env');
  failCleanup = true;
  await assert.rejects(
    f.files.reset(owner.capability, { expectedGeneration: 1 }),
    (error) => {
      assert.equal(error.code, 'RESET_CLEANUP_FAILED');
      assert.doesNotMatch(error.message, new RegExp(f.directory.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.doesNotMatch(JSON.stringify(error), /private native path/);
      assert.doesNotMatch(util.inspect(error), /private native path|secureshop-[a-f0-9]{64}/);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
  assert.deepEqual(f.files.getOwnerBinding(owner.capability), {
    ...OWNER_A,
    generation: 2,
    lifecycle: 'active',
    cleanupPending: 1,
  });
  await rejectsCode(
    f.files.readFile(owner.capability, '/server/config/.env', { expectedGeneration: 1 }),
    'STALE_GENERATION',
  );
  const after = await f.files.readFile(owner.capability, '/server/config/.env', { expectedGeneration: 2 });
  assert.notEqual(after.sha256, before.sha256);
  failCleanup = false;
  assert.deepEqual(await f.files.reconcileCleanup(owner.capability, { expectedGeneration: 2 }), {
    generation: 2,
    cleanupPending: 0,
  });
  assert.equal(f.files.getOwnerBinding(owner.capability).cleanupPending, 0);
});

test('reset retries cannot accumulate retired generations while cleanup remains unavailable', async (t) => {
  let failCleanup = true;
  const f = await fixture({ removeTree: async (...args) => {
    if (failCleanup) throw new Error('synthetic cleanup outage');
    return fs.rm(...args);
  } });
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  await rejectsCode(f.files.reset(owner.capability, { expectedGeneration: 1 }), 'RESET_CLEANUP_FAILED');
  const names = (await fs.readdir(f.root)).sort();
  const current = await f.files.readFile(owner.capability, '/server/config/.env');
  for (let attempt = 0; attempt < 3; attempt++) {
    await rejectsCode(f.files.reset(owner.capability, { expectedGeneration: 2 }), 'CLEANUP_RETRY_FAILED');
    assert.deepEqual((await fs.readdir(f.root)).sort(), names);
    assert.equal(f.files.getOwnerBinding(owner.capability).generation, 2);
    assert.equal((await f.files.readFile(owner.capability, '/server/config/.env')).sha256, current.sha256);
  }
  failCleanup = false;
  const reset = await f.files.reset(owner.capability, { expectedGeneration: 2 });
  assert.equal(reset.generation, 3);
  assert.deepEqual(await fs.readdir(f.root), [owner.capability]);
});

test('destroy is generation-fenced, removes only registered roots, and revokes queued operations', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const unrelated = path.join(f.root, 'operator-owned-do-not-sweep');
  await fs.mkdir(unrelated);
  await fs.writeFile(path.join(unrelated, 'keep.txt'), 'keep');

  await rejectsCode(f.files.destroy(owner.capability), 'INVALID_GENERATION');
  await rejectsCode(f.files.destroy(owner.capability, { expectedGeneration: 2 }), 'STALE_GENERATION');
  const destruction = f.files.destroy(owner.capability, { expectedGeneration: 1 });
  const queuedRead = f.files.readFile(owner.capability, '/etc/passwd');
  assert.deepEqual(await destruction, { destroyed: true, generation: 1 });
  await rejectsCode(queuedRead, 'UNKNOWN_CAPABILITY');
  await rejectsCode(f.files.readFile(owner.capability, '/etc/passwd'), 'UNKNOWN_CAPABILITY');
  await rejectsCode(Promise.resolve().then(() => f.files.getOwnerBinding(owner.capability)), 'UNKNOWN_CAPABILITY');
  await assert.rejects(fs.access(path.join(f.root, owner.capability)));
  assert.equal(await fs.readFile(path.join(unrelated, 'keep.txt'), 'utf8'), 'keep');
});

test('partial destroy failure fences a queued operation and keeps exact-path retry state', async (t) => {
  let failCleanup = true;
  const f = await fixture({
    removeTree: async (...args) => {
      if (failCleanup) {
        await fs.rm(...args);
        throw new Error('native cleanup detail after partial deletion');
      }
      return fs.rm(...args);
    },
  });
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession(OWNER_A);
  const failedDestruction = assert.rejects(
    f.files.destroy(owner.capability, { expectedGeneration: 1 }),
    (error) => error.code === 'DESTROY_CLEANUP_FAILED' && !util.inspect(error).includes('native cleanup detail'),
  );
  const queuedRead = rejectsCode(f.files.readFile(owner.capability, '/etc/passwd'), 'LIFECYCLE_DESTROYING');
  await failedDestruction;
  await queuedRead;
  assert.deepEqual(f.files.getOwnerBinding(owner.capability), {
    ...OWNER_A,
    generation: 1,
    lifecycle: 'destroying',
    cleanupPending: 0,
  });
  await rejectsCode(f.files.readFile(owner.capability, '/etc/passwd'), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.writeFile(owner.capability, '/uploads/late.txt', 'late'), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.reset(owner.capability), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.reconcileCleanup(owner.capability), 'LIFECYCLE_DESTROYING');
  failCleanup = false;
  assert.deepEqual(await f.files.destroy(owner.capability, { expectedGeneration: 1 }), {
    destroyed: true,
    generation: 1,
  });
});

test('session admission reserves capacity before awaits and destruction releases it', async (t) => {
  const f = await fixture({ maxSessions: 2 });
  t.after(f.cleanup);
  const results = await Promise.allSettled([
    f.files.createOwnerSession(OWNER_A),
    f.files.createOwnerSession(OWNER_B),
    f.files.createOwnerSession(OWNER_A),
  ]);
  assert.deepEqual(results.map(r => r.status), ['fulfilled', 'fulfilled', 'rejected']);
  assert.equal(results[2].reason.code, 'SESSION_LIMIT_EXCEEDED');
  assert.equal((await fs.readdir(f.root)).length, 2);
  await f.files.destroy(results[0].value.capability, { expectedGeneration: 1 });
  const replacement = await f.files.createOwnerSession(OWNER_A);
  assert.notEqual(replacement.capability, results[0].value.capability);
  assert.equal((await fs.readdir(f.root)).length, 2);
});

test('failed provisioning retains its capacity reservation and exact cleanup paths until recovery', async (t) => {
  let failSeed = true;
  let failCleanup = true;
  const f = await fixture({ maxSessions: 1,
    randomBytes(length) {
      if (failSeed && length === 24) throw new Error('synthetic provisioning failure');
      return crypto.randomBytes(length);
    },
    removeTree: (...args) => {
      if (failCleanup) throw new Error('synthetic cleanup failure');
      return fs.rm(...args);
    },
  });
  t.after(f.cleanup);
  await assert.rejects(f.files.createOwnerSession(OWNER_A));
  const orphaned = await fs.readdir(f.root);
  assert.equal(orphaned.length, 1);
  assert.match(orphaned[0], /^\.reset-/);
  for (let i = 0; i < 3; i++) {
    await rejectsCode(f.files.createOwnerSession(OWNER_A), 'SESSION_LIMIT_EXCEEDED');
    assert.deepEqual(await f.files.reconcileFailedProvisioning(), { removed: 0, remaining: 1 });
    assert.deepEqual(await fs.readdir(f.root), orphaned);
  }
  // An unrelated directory must survive maintenance; it is not a tracked path.
  await fs.mkdir(path.join(f.root, 'unrelated'));
  failCleanup = false;
  assert.deepEqual(await f.files.reconcileFailedProvisioning(), { removed: 1, remaining: 0 });
  assert.deepEqual(await fs.readdir(f.root), ['unrelated']);
  failSeed = false;
  const replacement = await f.files.createOwnerSession(OWNER_A);
  assert.equal(replacement.generation, 1);
});

test('unsafe configured roots fail closed', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshop-files-root-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'target');
  const linkedRoot = path.join(directory, 'linked-root');
  await fs.mkdir(target);
  await fs.symlink(target, linkedRoot);
  const files = createSecureShopFiles({ root: linkedRoot });
  await rejectsCode(files.createOwnerSession(OWNER_A), 'UNSAFE_FILESYSTEM');
});

test('reserved target reopens exact persisted bytes after restart without reseeding', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const first = await f.files.provisionReservedTarget(RESERVED_A);
  assert.equal(first.reopened, false);
  assert.equal(first.generation, 7);
  assert.deepEqual(
    {
      targetId: first.targetId,
      launchId: first.launchId,
      scenarioId: first.scenarioId,
      generation: first.generation,
      ownerId: first.ownerId,
    },
    RESERVED_A,
    'trusted caller can verify the full returned reservation binding before using the capability',
  );
  assert.deepEqual(first.binding, RESERVED_A);
  assert.match(first.capability, CAPABILITY_RE);
  const original = await f.files.readFile(first.capability, '/server/config/.env', { expectedGeneration: 7 });
  await f.files.writeFile(first.capability, '/uploads/learner.txt', 'preserved mutation', { expectedGeneration: 7 });

  const restarted = createSecureShopFiles({ root: f.root, maxReadBytes: 256, maxWriteBytes: 64 });
  const reopened = await restarted.provisionReservedTarget(RESERVED_A);
  assert.equal(reopened.reopened, true);
  assert.equal(reopened.generation, 7);
  assert.notEqual(reopened.capability, first.capability);
  const after = await restarted.readFile(reopened.capability, '/server/config/.env', { expectedGeneration: 7 });
  const mutation = await restarted.readFile(reopened.capability, '/uploads/learner.txt', { expectedGeneration: 7 });
  assert.equal(after.sha256, original.sha256, 'reopen must not reseed fixture evidence');
  assert.equal(mutation.data.toString(), 'preserved mutation');
  assert.equal('capability' in after, false, 'learner-visible file receipts do not contain the local bearer');
});

test('reserved target binding is exact both in-process and after restart', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const first = await f.files.provisionReservedTarget(RESERVED_A);
  const repeated = await f.files.provisionReservedTarget({ ...RESERVED_A });
  assert.equal(repeated.capability, first.capability);
  assert.equal(repeated.reopened, true);
  await rejectsCode(
    f.files.provisionReservedTarget({ ...RESERVED_A, generation: 8 }),
    'TARGET_BINDING_MISMATCH',
  );

  const restarted = createSecureShopFiles({ root: f.root });
  for (const changed of [
    { ownerId: '19' },
    { launchId: RESERVED_B.launchId },
    { scenarioId: RESERVED_B.scenarioId },
    { generation: 8 },
  ]) {
    await rejectsCode(
      restarted.provisionReservedTarget({ ...RESERVED_A, ...changed }),
      'TARGET_BINDING_MISMATCH',
    );
  }
  const valid = await restarted.provisionReservedTarget(RESERVED_A);
  assert.equal(valid.reopened, true, 'binding failures must not replace the valid target');
});

test('partial reserved state and symlinked control boundaries fail closed without replacement', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  await fs.mkdir(f.root, { recursive: true });
  const partial = path.join(f.root, `target-${RESERVED_A.targetId}`);
  await fs.mkdir(partial);
  await fs.mkdir(path.join(partial, 'data'));
  await rejectsCode(f.files.provisionReservedTarget(RESERVED_A), 'TARGET_RECONCILIATION_REQUIRED');
  assert.deepEqual(await fs.readdir(partial), ['data']);

  const linked = path.join(f.root, `target-${RESERVED_B.targetId}`);
  await fs.symlink(f.directory, linked);
  await rejectsCode(f.files.provisionReservedTarget(RESERVED_B), 'TARGET_RECONCILIATION_REQUIRED');
  assert.equal((await fs.lstat(linked)).isSymbolicLink(), true);
});

test('restart detects and preserves the one target-specific provisioning stage', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  await fs.mkdir(f.root, { recursive: true });
  const staging = path.join(f.root, `.provision-${RESERVED_A.targetId}`);
  await fs.mkdir(staging);
  await fs.writeFile(path.join(staging, 'partial-marker'), 'retain for reconciliation');

  await rejectsCode(f.files.provisionReservedTarget(RESERVED_A), 'TARGET_RECONCILIATION_REQUIRED');
  const restarted = createSecureShopFiles({ root: f.root });
  await rejectsCode(restarted.provisionReservedTarget(RESERVED_A), 'TARGET_RECONCILIATION_REQUIRED');
  assert.deepEqual(await fs.readdir(staging), ['partial-marker']);
  assert.equal(await fs.readFile(path.join(staging, 'partial-marker'), 'utf8'), 'retain for reconciliation');
  await assert.rejects(fs.lstat(path.join(f.root, `target-${RESERVED_A.targetId}`)), { code: 'ENOENT' });
});

test('reserved target control metadata is outside the learner virtual namespace', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(RESERVED_A);
  const container = path.join(f.root, `target-${RESERVED_A.targetId}`);
  const control = path.join(container, 'control.json');
  const before = await fs.readFile(control);

  await rejectsCode(f.files.readFile(target.capability, '../../control.json'), 'FILE_NOT_FOUND');
  await f.files.writeFile(target.capability, '../../control.json', 'learner data', { expectedGeneration: 7 });
  assert.deepEqual(await fs.readFile(control), before);
  assert.equal(
    (await f.files.readFile(target.capability, '/control.json')).data.toString(),
    'learner data',
  );
});

test('reserved targets stay separated and require the external lifecycle to reset or destroy', async (t) => {
  const f = await fixture();
  t.after(f.cleanup);
  const a = await f.files.provisionReservedTarget(RESERVED_A);
  const b = await f.files.provisionReservedTarget(RESERVED_B);
  const aEnv = await f.files.readFile(a.capability, '/server/config/.env', { expectedGeneration: 7 });
  const bEnv = await f.files.readFile(b.capability, '/server/config/.env', { expectedGeneration: 3 });
  assert.notEqual(aEnv.sha256, bEnv.sha256);
  await rejectsCode(
    f.files.readFile(a.capability, `/target-${RESERVED_B.targetId}/data/server/config/.env`),
    'FILE_NOT_FOUND',
  );
  await rejectsCode(f.files.reset(a.capability, { expectedGeneration: 7 }), 'EXTERNAL_LIFECYCLE_REQUIRED');
  await rejectsCode(f.files.reconcileCleanup(a.capability, { expectedGeneration: 7 }), 'EXTERNAL_LIFECYCLE_REQUIRED');
  await rejectsCode(f.files.destroy(a.capability, { expectedGeneration: 7 }), 'EXTERNAL_LIFECYCLE_REQUIRED');

  const restarted = createSecureShopFiles({ root: f.root });
  const reopened = await restarted.provisionReservedTarget(RESERVED_A);
  assert.equal(reopened.reopened, true, 'generic lifecycle calls must not permit same-target resurrection');
  assert.equal((await restarted.readFile(reopened.capability, '/server/config/.env')).sha256, aEnv.sha256);
});
