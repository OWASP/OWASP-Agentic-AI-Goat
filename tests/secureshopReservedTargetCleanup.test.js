'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createSecureShopFiles } = require('../sidecars/sandbox-runner/secureshopFiles');

const BINDING = Object.freeze({
  targetId: '41ed0e59-42ca-47ab-98df-608f45a18304',
  launchId: '9242e9ec-4ec3-4a3e-b039-e744e2bb487c',
  scenarioId: 'b8d34278-1d15-46c6-9767-3865290f058f',
  generation: 7,
  ownerId: '17',
});
const OTHER = Object.freeze({
  targetId: 'ee4d3cf1-6d29-466e-932e-2fcf9463c9eb',
  launchId: '81de3ebf-404f-4e40-82a0-9374de0ff63a',
  scenarioId: '70f5747a-b504-458d-a553-fbab901928f0',
  generation: 3,
  ownerId: '18',
});
const OPERATION = '65f7fa42-b4b5-4dfa-a838-891f542e1452';
const OTHER_OPERATION = '8cb991f9-75cc-4a45-886e-29004f328617';
const COMPLETED_AT = '2026-09-13T19:30:00.000Z';

async function fixture(options = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'secureshop-reserved-cleanup-'));
  const root = path.join(directory, 'sessions');
  return {
    directory,
    root,
    files: createSecureShopFiles({ root, now: () => COMPLETED_AT, ...options }),
    cleanup: () => fs.rm(directory, { recursive: true, force: true }),
  };
}

function rejectsCode(promise, code) {
  return assert.rejects(promise, error => error?.code === code);
}

function allow(calls = []) {
  return async coordinates => {
    calls.push(coordinates);
    return true;
  };
}

test('reserved cleanup is authorized, durable, idempotent, private, and terminal across restart', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  await f.files.writeFile(target.capability, '/uploads/effect.txt', 'real effect', { expectedGeneration: 7 });
  const calls = [];
  const receipt = await f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION,
    authorize: allow(calls),
  });

  assert.equal(calls.length >= 6, true);
  assert.equal(calls.every(call => call === calls[0]), true, 'all authorization checks reuse one immutable scope');
  assert.equal(Object.isFrozen(calls[0]), true);
  assert.deepEqual(calls[0], { version: 1, ...BINDING, operationId: OPERATION });
  const canonical = {
    version: 1, ...BINDING, operationId: OPERATION,
    status: 'completed', completedAt: COMPLETED_AT, cleanupPending: false,
  };
  assert.deepEqual(receipt, {
    ...canonical,
    receiptSha256: crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex'),
  });
  const serialized = JSON.stringify(receipt);
  assert.equal(serialized.includes(f.root), false);
  assert.equal(serialized.includes(target.capability), false);
  await rejectsCode(f.files.readFile(target.capability, '/uploads/effect.txt'), 'UNKNOWN_CAPABILITY');

  const retry = await f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION,
    authorize: allow(),
  });
  assert.deepEqual(retry, receipt);
  const verified = await f.files.readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION,
    authorize: allow(),
  });
  assert.deepEqual(verified, receipt);

  const restarted = createSecureShopFiles({ root: f.root });
  await rejectsCode(restarted.provisionReservedTarget(BINDING), 'TARGET_RETIRED');
  assert.deepEqual(await restarted.readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION,
    authorize: allow(),
  }), receipt);
});

test('cleanup requires literal trusted authorization and cannot mint a receipt by reading', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  for (const authorize of [undefined, async () => false, async () => ({ authorized: true }), async () => { throw new Error('private'); }]) {
    await rejectsCode(f.files.retireReservedTarget(BINDING, { operationId: OPERATION, authorize }),
      authorize ? 'CLEANUP_NOT_AUTHORIZED' : 'CLEANUP_AUTHORIZATION_REQUIRED');
  }
  await rejectsCode(f.files.readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION,
    authorize: allow(),
  }), 'CLEANUP_RECEIPT_UNAVAILABLE');
  assert.equal((await f.files.readFile(target.capability, '/etc/passwd')).bytes > 0, true);
  assert.deepEqual((await fs.readdir(f.root)).sort(), [`target-${BINDING.targetId}`]);
});

test('failed removal leaves fenced durable debt and the exact operation resumes after restart', async t => {
  let failRemove = true;
  const f = await fixture({ removeTree: async (...args) => {
    if (failRemove) throw new Error(`do not expose ${args[0]}`);
    return fs.rm(...args);
  } });
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  await assert.rejects(
    f.files.retireReservedTarget(BINDING, { operationId: OPERATION, authorize: allow() }),
    error => error.code === 'RESERVED_CLEANUP_FAILED' && !String(error).includes(f.root),
  );
  await rejectsCode(f.files.readFile(target.capability, '/etc/passwd'), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.writeFile(target.capability, '/uploads/late', 'late'), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OTHER_OPERATION, authorize: allow(),
  }), 'TARGET_BINDING_MISMATCH');

  failRemove = false;
  const restarted = createSecureShopFiles({ root: f.root, now: () => COMPLETED_AT });
  const receipt = await restarted.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  });
  assert.equal(receipt.status, 'completed');
  await rejectsCode(restarted.provisionReservedTarget(BINDING), 'TARGET_RETIRED');
});

test('retirement holds the capability queue and prevents a later read from returning after deletion starts', async t => {
  let enteredRemove;
  let releaseRemove;
  const removing = new Promise(resolve => { enteredRemove = resolve; });
  const held = new Promise(resolve => { releaseRemove = resolve; });
  const f = await fixture({ removeTree: async (...args) => {
    enteredRemove();
    await held;
    return fs.rm(...args);
  } });
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  const retirement = f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  });
  await removing;

  let readSettled = false;
  const queuedRead = f.files.readFile(target.capability, '/etc/passwd')
    .finally(() => { readSettled = true; });
  const queuedRejection = rejectsCode(queuedRead, 'UNKNOWN_CAPABILITY');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(readSettled, false, 'later file effects wait behind the terminal cleanup operation');

  releaseRemove();
  await retirement;
  await queuedRejection;
});

test('authority revoked while retirement waits for an admitted file effect prevents retirement', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  const originalOpen = fs.open;
  let enteredRead;
  let releaseRead;
  const readEntered = new Promise(resolve => { enteredRead = resolve; });
  const readHeld = new Promise(resolve => { releaseRead = resolve; });
  fs.open = async (filename, ...args) => {
    if (String(filename).endsWith(path.join('data', 'etc', 'passwd'))) {
      enteredRead();
      await readHeld;
    }
    return originalOpen.call(fs, filename, ...args);
  };
  t.after(() => { fs.open = originalOpen; });

  const admittedRead = f.files.readFile(target.capability, '/etc/passwd');
  await readEntered;
  let authorized = true;
  let firstCheck;
  const checked = new Promise(resolve => { firstCheck = resolve; });
  const retirement = f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION,
    authorize: async () => {
      firstCheck();
      return authorized;
    },
  });
  await checked;
  authorized = false;
  releaseRead();
  assert.equal((await admittedRead).bytes > 0, true);
  await rejectsCode(retirement, 'CLEANUP_NOT_AUTHORIZED');
  fs.open = originalOpen;
  assert.equal((await f.files.readFile(target.capability, '/etc/passwd')).bytes > 0, true);
});

test('authority revoked after removal leaves pending debt and publishes no completed receipt', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  let checks = 0;
  const authorize = async () => {
    checks += 1;
    return checks !== 4;
  };
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize,
  }), 'CLEANUP_NOT_AUTHORIZED');
  assert.equal(checks, 4);
  await assert.rejects(fs.access(path.join(f.root, `target-${BINDING.targetId}`)));
  await rejectsCode(f.files.readFile(target.capability, '/etc/passwd'), 'LIFECYCLE_DESTROYING');
  await rejectsCode(f.files.readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'CLEANUP_RECEIPT_UNAVAILABLE');

  const restarted = createSecureShopFiles({ root: f.root, now: () => COMPLETED_AT });
  assert.equal((await restarted.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  })).status, 'completed');
});

test('authority revoked after the durable completion commit suppresses return but preserves exact replay', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const target = await f.files.provisionReservedTarget(BINDING);
  let checks = 0;
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION,
    authorize: async () => {
      checks += 1;
      return checks !== 6;
    },
  }), 'CLEANUP_NOT_AUTHORIZED');
  assert.equal(checks, 6);
  await rejectsCode(f.files.readFile(target.capability, '/etc/passwd'), 'LIFECYCLE_DESTROYING');

  const committed = await f.files.readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION, authorize: allow(),
  });
  assert.equal(committed.status, 'completed');
  assert.equal(committed.cleanupPending, false);
  const retry = await f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  });
  assert.deepEqual(retry, committed);
  await rejectsCode(f.files.readFile(target.capability, '/etc/passwd'), 'UNKNOWN_CAPABILITY');
});

test('remove-then-error remains pending and finalizes without recreating the absent target', async t => {
  const f = await fixture({ removeTree: async (...args) => {
    await fs.rm(...args);
    throw new Error('failure after removal');
  } });
  t.after(f.cleanup);
  await f.files.provisionReservedTarget(BINDING);
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'RESERVED_CLEANUP_FAILED');
  await assert.rejects(fs.access(path.join(f.root, `target-${BINDING.targetId}`)));

  const restarted = createSecureShopFiles({ root: f.root, now: () => COMPLETED_AT });
  assert.equal((await restarted.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  })).status, 'completed');
});

test('cleanup completion requires canonical UTC receipt time and rejects malformed persisted proof', async t => {
  for (const timestamp of ['2026-09-13T19:30:00Z', '2026-09-13T12:30:00-07:00']) {
    const invalid = await fixture({ now: () => timestamp });
    t.after(invalid.cleanup);
    await invalid.files.provisionReservedTarget(BINDING);
    await rejectsCode(invalid.files.retireReservedTarget(BINDING, {
      operationId: OPERATION, authorize: allow(),
    }), 'CLEANUP_DURABILITY_FAILED');
    await rejectsCode(invalid.files.readReservedCleanupReceipt(BINDING, {
      operationId: OPERATION, authorize: allow(),
    }), 'CLEANUP_RECEIPT_UNAVAILABLE');
  }

  const f = await fixture();
  t.after(f.cleanup);
  await f.files.provisionReservedTarget(BINDING);
  await f.files.retireReservedTarget(BINDING, { operationId: OPERATION, authorize: allow() });
  const journal = path.join(f.root, `.cleanup-${BINDING.targetId}.json`);
  const invalidCanonical = {
    version: 1, ...BINDING, operationId: OPERATION, status: 'completed',
    completedAt: '2026-09-13T12:30:00-07:00', cleanupPending: false,
  };
  await fs.writeFile(journal, `${JSON.stringify({
    ...invalidCanonical,
    receiptSha256: crypto.createHash('sha256').update(JSON.stringify(invalidCanonical)).digest('hex'),
  })}\n`);
  await rejectsCode(createSecureShopFiles({ root: f.root }).readReservedCleanupReceipt(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_RECONCILIATION_REQUIRED');
});

test('unknown, mismatched, incomplete, symlinked, and temporary target state fails closed', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_NOT_FOUND');

  await f.files.provisionReservedTarget(BINDING);
  await rejectsCode(f.files.retireReservedTarget({ ...BINDING, ownerId: '18' }, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_BINDING_MISMATCH');
  await fs.writeFile(path.join(f.root, `target-${BINDING.targetId}`, 'unexpected'), 'partial');
  await rejectsCode(f.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_RECONCILIATION_REQUIRED');

  const symlinkRoot = await fixture();
  t.after(symlinkRoot.cleanup);
  await fs.mkdir(symlinkRoot.root, { recursive: true });
  await fs.symlink(symlinkRoot.directory, path.join(symlinkRoot.root, `target-${OTHER.targetId}`));
  await rejectsCode(symlinkRoot.files.retireReservedTarget(OTHER, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_RECONCILIATION_REQUIRED');

  const temporaryRoot = await fixture();
  t.after(temporaryRoot.cleanup);
  await temporaryRoot.files.provisionReservedTarget(BINDING);
  await fs.writeFile(path.join(temporaryRoot.root, `.cleanup-${BINDING.targetId}.tmp`), 'incomplete');
  await rejectsCode(temporaryRoot.files.retireReservedTarget(BINDING, {
    operationId: OPERATION, authorize: allow(),
  }), 'TARGET_RECONCILIATION_REQUIRED');
  await rejectsCode(createSecureShopFiles({ root: temporaryRoot.root }).provisionReservedTarget(BINDING),
    'TARGET_RECONCILIATION_REQUIRED');
});

test('nonreserved reset and destroy behavior remains available', async t => {
  const f = await fixture();
  t.after(f.cleanup);
  const owner = await f.files.createOwnerSession({
    ownerId: 'student-17', role: 'customer', sessionId: BINDING.launchId,
  });
  assert.equal((await f.files.reset(owner.capability, { expectedGeneration: 1 })).generation, 2);
  assert.deepEqual(await f.files.destroy(owner.capability, { expectedGeneration: 2 }), {
    destroyed: true, generation: 2,
  });
});
