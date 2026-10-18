'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createFinflowTraversalManager, finflowOwnerKey } = require('../../server/services/finflowTraversalArtifacts');

function createRepository() {
  const rows = new Map();
  const tails = new Map();
  let ordinal = 1;
  const key = value => `${value.ownerKey}:${value.durableGeneration ?? value.generation}`;
  const clone = row => row ? Object.freeze({ ...row }) : null;
  return {
    rows,
    async withTargetLock(value, work) {
      const targetKey = key(value);
      const previous = tails.get(targetKey) || Promise.resolve();
      let release;
      const tail = new Promise(resolve => { release = resolve; });
      tails.set(targetKey, tail);
      await previous;
      try { return await work(); }
      finally { release(); if (tails.get(targetKey) === tail) tails.delete(targetKey); }
    },
    async get(value) { return clone(rows.get(key(value))); },
    async getTarget(value) { return clone(rows.get(key(value))); },
    async reserve(value) {
      const targetKey = key(value);
      if (!rows.has(targetKey)) rows.set(targetKey, { ownerKey: value.ownerKey,
        generation: String(value.durableGeneration),
        targetToken: `20000000-0000-4000-8000-${String(ordinal++).padStart(12, '0')}`,
        state: 'provisioning', cleanupErrorCode: null });
      return clone(rows.get(targetKey));
    },
    async activate(_execution, target) {
      rows.set(key(target), { ...rows.get(key(target)), state: 'active', cleanupErrorCode: null });
      return clone(rows.get(key(target)));
    },
    async listOwner(ownerKey) {
      return [...rows.values()].filter(row => row.ownerKey === ownerKey).map(clone);
    },
    async markCleanupDebt(target, cleanupErrorCode) {
      const current = rows.get(key(target));
      if (current.state !== 'retired') rows.set(key(target), { ...current,
        state: 'cleanup_debt', cleanupErrorCode });
      return clone(rows.get(key(target)));
    },
    async retire(target) {
      rows.set(key(target), { ...rows.get(key(target)), state: 'retired', cleanupErrorCode: null });
      return true;
    },
  };
}

function createTraversalFixture(t, { baseDirectory = os.tmpdir() } = {}) {
  const root = fs.mkdtempSync(path.join(baseDirectory, 'finflow-authority-'));
  const repository = createRepository();
  const manager = createFinflowTraversalManager({ repository, root });
  const cleanup = () => fs.rmSync(root, { recursive: true, force: true });
  t?.after(cleanup);
  return { root, repository, manager, cleanup };
}

function execution(ownerId, generation = '4', runId = `run-${ownerId}-${generation}`) {
  return Object.freeze({ ownerId: String(ownerId), ownerKey: finflowOwnerKey(ownerId),
    runId, durableGeneration: String(generation), check: async () => {} });
}

module.exports = { createTraversalFixture, execution };
