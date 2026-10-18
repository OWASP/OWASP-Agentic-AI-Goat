'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

// Controlled adapter tests only. `durable: true` from a family adapter means
// this injected completion interface was used; it proves no database persistence,
// genuine model execution, or learner credit. Existing evaluators decide outcomes.
function controlledObjectiveBoundary(options = {}, ownerField = 'platformUserId') {
  const owner = options[ownerField] ?? 7;
  assert.ok(Number.isSafeInteger(Number(owner)) && Number(owner) > 0);
  const execution = {
    runId: randomUUID(), ownerKey: JSON.stringify(['controlled-fixture', String(owner)]),
    check: async () => {}, ...options.execution,
  };
  assert.equal(typeof execution.runId, 'string');
  assert.ok(execution.runId.length > 0);
  assert.equal(typeof execution.check, 'function');
  const attempts = new WeakMap();
  const completionService = options.completionService || {
    async beginAttempt(input) {
      assert.equal(input.userId, owner);
      assert.equal(input.execution.runId, execution.runId);
      assert.equal(input.execution.check, execution.check);
      await input.execution.check();
      const attempt = Object.freeze({});
      attempts.set(attempt, { execution: input.execution, workshopKey: input.workshopKey });
      return attempt;
    },
    async evaluate(packet) {
      const bound = attempts.get(packet.attempt);
      assert.ok(bound, 'evaluation must use its captured attempt');
      assert.equal(packet.userId, owner);
      assert.equal(packet.execution, bound.execution);
      assert.equal(packet.workshopKey, bound.workshopKey);
      await packet.execution.check();
      assert.equal(typeof options.judge, 'function', 'fixture must supply its evaluator');
      const judgment = await options.judge(packet);
      await packet.execution.check();
      return { judgment, completed: judgment.verdict === 'pass' };
    },
  };
  return { ...options, [ownerField]: owner, execution, completionService };
}

function controlledObjectiveGraph(graph) {
  return (input, deps) => {
    const boundary = controlledObjectiveBoundary({
      platformUserId: input.platformUserId, execution: deps.execution,
      completionService: deps.completionService, judge: deps.objectiveJudge,
    });
    return graph({ ...input, platformUserId: boundary.platformUserId }, {
      ...deps, execution: boundary.execution, completionService: boundary.completionService,
    });
  };
}

async function waitForFixtureEntry(entered, pending, timeoutMs = 2000) {
  let timer;
  try {
    await Promise.race([entered, pending.then(() => {
      throw Error('Controlled run completed before fixture entry');
    }), new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('Controlled fixture entry timed out')), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

module.exports = { controlledObjectiveBoundary, controlledObjectiveGraph, waitForFixtureEntry };
