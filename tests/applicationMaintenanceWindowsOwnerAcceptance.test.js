'use strict';
// Controlled owner-schema/guard checks only: no native observation or database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const processIdentity = require('../scripts/lib/setup-local-process-identity');
const proof = require('../server/database/postgres/applicationMaintenanceRecoveryProof');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');
const hash = value => createHash('sha256').update(value).digest('hex');
const controlFile = path.resolve('server/database/postgres/applicationMaintenanceRecoveryControl.js');

function windowsOwner(pid = process.pid) {
  const parent = pid === 1 ? 2 : 1;
  return {
    version: 3, workspaceSha256: 'a'.repeat(64), installationId: randomUUID(), operationId: randomUUID(),
    platform: 'win32', hostSha256: 'b'.repeat(64), bootFileTime: '100', currentSid: 'S-1-5-21-123',
    ancestors: [{ pid, ppid: parent, sid: 'S-1-5-21-123', creationFileTime: '300' }],
    boundary: { kind: 'root', process: { pid: parent, ppid: 0, sid: 'S-1-5-21-123', creationFileTime: '200' } },
    ancestry: 'observed-supported-chain',
  };
}
const invalid = [
  o => { o.unexpected = true; }, o => { o.ancestry = 'complete-supported-chain'; },
  o => { o.platform = 'linux'; }, o => { o.currentSid = 'S-1-05-21-123'; },
  o => { o.bootFileTime = '0'; }, o => { o.ancestors[0].creationFileTime = '200'; },
  o => { o.boundary.process.pid = o.ancestors[0].pid; }, o => { o.boundary.process.ppid = 4; },
  o => { o.ancestors[0].pid = 2147483648; }, o => { o.ancestors[0].extra = true; },
];

// Execute the exact conditional from each production guard, with the actual
// schema selector. Surrounding admission/dirty-profile flows have separate
// controlled regression suites; extracting a guard does not qualify those flows.
function guard(file, variable) {
  const source = fs.readFileSync(file, 'utf8');
  const matches = [...source.matchAll(/if\((!processIdentity\.isSupportedLocalAncestorBinding\((owner|recoveryOwner)\).*?)\)throw/g)];
  const selected = matches.filter(match => match[2] === variable);
  assert.equal(selected.length, 1, 'exactly one production owner guard');
  const evaluate = new Function('processIdentity', 'owner', 'recoveryOwner', 'process', `return !(${selected[0][1]});`);
  return value => evaluate(processIdentity, value, value, process);
}
for (const [label, file, variable, currentPid] of [
  ['admission capture', 'server/services/applicationMaintenanceInprocessAdmission.js', 'owner', true],
  ['dirty original observation', 'server/services/applicationMaintenanceDirtyProfile.js', 'owner', false],
  ['dirty recovery capture', 'server/services/applicationMaintenanceDirtyProfile.js', 'recoveryOwner', true],
]) {
  test(`${label}: exact runtime guard admits valid v3 and v2, denies malformed v3 and preserves PID fence`, () => {
    const accepts = guard(file, variable);
    assert.equal(accepts(windowsOwner()), true);
    assert.equal(accepts({ version: 2, ancestry: 'complete-supported-chain', ancestors: [{ pid: process.pid }] }), true);
    for (const change of invalid) { const value = windowsOwner(); change(value); assert.equal(accepts(value), false); }
    assert.equal(accepts(windowsOwner(process.pid === 1 ? 3 : 1)), !currentPid);
    assert.equal(accepts({ version: 1, ancestry: 'unqualified' }), false);
  });
}

function session(ownerRecord = windowsOwner(), callbacks = {}) {
  const identity = {}, expected = { epoch: '2', operationId: randomUUID(), installationId: randomUUID() };
  let held = true, phaseAllowed = true;
  const value = {
    identity, lease: {}, expected, closureSha256: 'c'.repeat(64), installationBindingSha256: 'd'.repeat(64), ownerRecord,
    assertCurrent() { assert(held, 'lease no longer held'); callbacks.current?.(); },
    assertPhaseCurrent() { assert(held && phaseAllowed, 'phase no longer current'); },
    acceptJournalSnapshot() {}, acceptPublication() {},
  };
  return { identity, expected, value, make: () => proof.createVerifiedRecoverySession(value),
    release: () => { held = false; }, denyPhase: () => { phaseAllowed = false; } };
}
test('public recovery session admits strict Windows v3 without granting authority to copied tokens', () => {
  const f = session(), s = f.make(), token = proof.issueVerifiedRecoveryProof(s, f.identity, 'claim');
  const context = { identity: f.identity, phase: 'claim', expected: f.expected };
  assert.throws(() => proof.assertVerifiedRecoveryProof({ ...token }, context));
  const accepted = proof.assertVerifiedRecoveryProof(token, context);
  assert.deepEqual(accepted.ownerRecord, f.value.ownerRecord);
  assert.equal(accepted.proofDigest.length, 64);
  assert.throws(() => proof.assertVerifiedRecoveryProof(token, context));
  assert.throws(() => proof.issueVerifiedRecoveryProof(s, f.identity, 'claim'));
  proof.closeVerifiedRecoverySession(s);
  assert.throws(() => proof.sessionState(s, f.identity));
});
test('public recovery session rejects malformed Windows record before current-authority callback', () => {
  for (const change of invalid) {
    const owner = windowsOwner(); change(owner); let checks = 0;
    const f = session(owner, { current: () => { checks++; } });
    assert.throws(f.make, { code: 'APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE' });
    assert.equal(checks, 0);
  }
});
test('v3 schema acceptance preserves proof identity, phase, epoch and current-lease fences', () => {
  for (const kind of ['identity', 'phase', 'epoch', 'current-phase', 'released']) {
    const f = session(), s = f.make(), token = proof.issueVerifiedRecoveryProof(s, f.identity, 'claim');
    const context = { identity: f.identity, phase: 'claim', expected: f.expected };
    if (kind === 'identity') context.identity = {};
    if (kind === 'phase') context.phase = 'finish';
    if (kind === 'epoch') context.expected = { ...f.expected, epoch: '3' };
    if (kind === 'current-phase') f.denyPhase();
    if (kind === 'released') f.release();
    assert.throws(() => proof.assertVerifiedRecoveryProof(token, context));
    assert.throws(() => proof.assertVerifiedRecoveryProof(token, { identity: f.identity, phase: 'claim', expected: f.expected }));
    proof.closeVerifiedRecoverySession(s);
  }
});

function control(capturedOwner) {
  const module = { exports: {} }, realRequire = createRequire(controlFile), calls = [];
  let state = { epoch: '1', operation_id: randomUUID(), installation_id: randomUUID(), state: 'clean' };
  vm.runInThisContext(`(function(require,module,exports,process){${fs.readFileSync(controlFile, 'utf8')}\n})`)(
    name => name.endsWith('setup-local-process-identity') ? {
      ...processIdentity, captureLocalAncestorBinding: binding => ({ ...capturedOwner, installationId: binding.installationId, operationId: binding.operationId }),
    } : realRequire(name), module, module.exports, process);
  const instance = module.exports.createRecoveryControl({ mode: 'maintenance', identity: {},
    async query(sql, args) { calls.push([sql, args]); if (sql.startsWith('UPDATE dvaia_maintenance.control SET epoch')) state = { ...state, epoch: '2', state: 'dirty', operation_id: args[0] }; return { rows: [] }; },
    async lock() {}, async read() { return { ...state }; }, async upgrade() {}, reserve() {}, admit: x => x,
    async transaction(work) { const prior = { ...state }; try { return await work(); } catch (error) { state = prior; throw error; } },
  });
  return { instance, calls, state: () => state };
}
function admission() {
  return { version: 1, profile: 'upgrade-canonical16-v1', workspaceRoot: process.cwd(), publicationId: randomUUID(),
    publicationSha256: 'b'.repeat(64), sourceManifestSha256: 'c'.repeat(64), stores: requiredStoreManifest.map((s, i) => ({
      storeKey: s.schema, clusterIdentifier: '123', databaseOid: i + 1, databaseName: `dvaia_${s.schema}`,
      runtimeRole: s.runtimeRole, migrationRole: `dvaia_${s.schema}_migration`, deliveryRole: s.schema === 'ctf' ? 'dvaia_ctf_delivery' : null,
      endpointPolicySha256: 'd'.repeat(64),
    })) };
}
test('legacy fixture control captures valid v3 and stores exact owner digest but no execution admission', async () => {
  const f = control(windowsOwner()), token = await f.instance.beginRecoveryEligible(admission());
  assert.equal(token.epoch, '2');
  const [, args] = f.calls.find(([sql]) => sql.startsWith('INSERT INTO dvaia_maintenance.epoch_bindings'));
  assert.equal(JSON.parse(args[7]).version, 3);
  assert.equal(hash(args[7]), args[8]);
  assert.equal(f.calls.filter(([sql]) => sql.startsWith('INSERT INTO dvaia_maintenance.epoch_stores')).length, 16);
  assert(!f.calls.some(([sql]) => sql.includes('epoch_execution_admissions')));
});
test('legacy fixture control rejects malformed v3 and foreign capture PID before dirty writes', async () => {
  for (const change of [...invalid, o => { o.ancestors[0].pid = process.pid === 1 ? 3 : 1; o.ancestors[0].ppid = 2; o.boundary.process.pid = 2; }]) {
    const owner = windowsOwner(); change(owner); const f = control(owner);
    await assert.rejects(f.instance.beginRecoveryEligible(admission()), { code: 'APPLICATION_MAINTENANCE_BINDING_INVALID' });
    assert.equal(f.calls.length, 0); assert.equal(f.state().state, 'clean');
  }
});
test('legacy fixture control retains v2 acceptance and rejects unqualified v1', async () => {
  const f = control({ version: 2, ancestry: 'complete-supported-chain', ancestors: [{ pid: process.pid }], hostSha256: 'b'.repeat(64), workspaceSha256: 'a'.repeat(64) });
  assert.equal((await f.instance.beginRecoveryEligible(admission())).epoch, '2');
  const g = control({ version: 1, ancestry: 'unqualified' });
  await assert.rejects(g.instance.beginRecoveryEligible(admission()), { code: 'APPLICATION_MAINTENANCE_BINDING_INVALID' });
  assert.equal(g.calls.length, 0);
});
test('strict selector preserves canonical Windows bounds, uppercase setup UUIDs and foreign SID boundary', () => {
  const value = windowsOwner(); value.installationId = value.installationId.toUpperCase(); value.operationId = value.operationId.toUpperCase();
  value.boundary.kind = 'foreign-sid'; value.boundary.process.sid = 'S-1-5-18'; value.boundary.process.ppid = 4;
  assert.equal(processIdentity.isSupportedLocalAncestorBinding(value), true);
  for (const change of [o => { o.boundary.process.sid = o.currentSid; }, o => { o.bootFileTime = '18446744073709551616'; }, o => { o.currentSid = 'S-1-5-4294967296'; }]) {
    const malformed = structuredClone(value); change(malformed); assert.equal(processIdentity.isSupportedLocalAncestorBinding(malformed), false);
  }
});

// Reuse the existing controlled full-flow fixtures without registering their
// tests again or copying their source. Override only their documented identity
// dependency seam; filesystem/source/SQL boundaries remain those fixtures.
function fixtureSuite(file, capture) {
  file = path.resolve(file);
  const registrations = new Map(), req = createRequire(file), module = { exports: {} };
  const fixtureVm = { ...vm, runInThisContext(source) {
    const compiled = vm.runInThisContext(source);
    return (...args) => {
      const priorRequire = args[0];
      args[0] = name => {
        const dependency = priorRequire(name);
        return name.endsWith('setup-local-process-identity') ? {
          ...dependency, isSupportedLocalAncestorBinding: processIdentity.isSupportedLocalAncestorBinding,
          captureLocalAncestorBinding: capture,
        } : dependency;
      };
      return compiled(...args);
    };
  } };
  vm.runInThisContext(`(function(require,module,exports,__dirname){${fs.readFileSync(file, 'utf8')}\nmodule.exports={fixture:typeof fixture==='function'?fixture:null};\n})`)(
    name => name === 'node:test' ? (title, callback) => registrations.set(title, callback)
      : name === 'node:vm' ? fixtureVm : req(name), module, module.exports, path.dirname(file));
  return { ...module.exports, registrations };
}
test('controlled full admission flow captures v3 through actual selector and preserves changed-byte refusal', async () => {
  const captured = [], suite = fixtureSuite('tests/applicationMaintenanceInprocess.test.js', binding => {
    const value = { ...windowsOwner(), installationId: binding.installationId, operationId: binding.operationId, workspaceSha256: hash(binding.workspaceRoot) };
    captured.push(value); return value;
  });
  const callback = suite.registrations.get('prepared admission derives observations and private IDs internally; changed bytes after observation deny');
  assert.equal(typeof callback, 'function'); await callback();
  assert.equal(captured.length, 2); assert(captured.every(value => value.version === 3));
  assert.notEqual(captured[0].operationId, captured[1].operationId);
});
test('controlled full dirty recovery admits v3 original and observer, then rechecks physical absence', async () => {
  const suite = fixtureSuite('tests/applicationMaintenanceDirtyProfile.test.js', () => windowsOwner());
  const f = suite.fixture({ windows: true }), original = windowsOwner(process.pid + 1);
  f.snapshot.rows.epoch_bindings[0].owner_record = original;
  assert.equal((await f.run()).recordedProcessesAbsent, true);
  await f.prepare(); assert.equal(f.captured().ownerRecord.version, 3);
  f.present(original); assert.throws(() => f.captured().assertCurrent(), /present/);
});
test('controlled full dirty flow denies malformed original, malformed observer and foreign captured PID', async () => {
  const validSuite = fixtureSuite('tests/applicationMaintenanceDirtyProfile.test.js', () => windowsOwner());
  const original = validSuite.fixture({ windows: true });
  original.snapshot.rows.epoch_bindings[0].owner_record = { ...windowsOwner(), unexpected: true };
  await assert.rejects(original.run(), { code: 'APPLICATION_MAINTENANCE_PROFILE_UNAVAILABLE' });
  assert.equal(original.counts().inspections, 0);
  for (const change of [o => { o.currentSid = 'S-1-05-21-123'; }, o => {
    o.ancestors[0].pid = process.pid === 1 ? 3 : 1; o.ancestors[0].ppid = 2; o.boundary.process.pid = 2;
  }]) {
    const suite = fixtureSuite('tests/applicationMaintenanceDirtyProfile.test.js', () => { const value = windowsOwner(); change(value); return value; });
    const f = suite.fixture({ windows: true }); f.snapshot.rows.epoch_bindings[0].owner_record = windowsOwner();
    await assert.rejects(f.prepare(), { code: 'APPLICATION_MAINTENANCE_PROFILE_UNAVAILABLE' });
    assert.equal(f.captured(), undefined);
  }
});
