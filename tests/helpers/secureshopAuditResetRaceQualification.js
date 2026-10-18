'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

// Starts one admitted audit and holds its worker until the shared coordinator
// aborts it.  This is intentionally a controlled worker seam; actual-model
// qualification remains a separate gate.
async function qualifyAuditResetRace({ runner, conversations, scope, persona, purpose,
  agents, identity, setWorkerGate, captureIdentity, ledger, requestedCount = 20 } = {}) {
  if (typeof runner?.run !== 'function' || typeof conversations?.create !== 'function'
      || !scope || !persona || typeof setWorkerGate !== 'function' || !agents?.query
      || !identity?.query || typeof captureIdentity !== 'function' || typeof ledger?.getRun !== 'function') {
    throw new TypeError('Audit reset race dependencies are required');
  }
  const session = await conversations.create(scope, persona, purpose);
  const requestId = randomUUID();
  let enteredResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  let releaseResolve;
  const released = new Promise(resolve => { releaseResolve = resolve; });
  let aborted = false;
  const gate = Object.freeze({
    enter() { enteredResolve(); },
    release() { releaseResolve(); },
    abort() { aborted = true; releaseResolve(); },
    wait(signal) {
      return new Promise((resolve, reject) => {
        const onAbort = () => { aborted = true; releaseResolve(); reject(signal.reason); };
        signal?.addEventListener('abort', onAbort, { once: true });
        released.then(() => { signal?.removeEventListener('abort', onAbort); resolve(); });
        if (signal?.aborted) onAbort();
      });
    },
  });
  setWorkerGate(gate);
  const controller = new AbortController();
  const pending = runner.run({ scope, persona, sessionId: session.id, requestId, requestedCount, signal: controller.signal });
  // Attach immediately so reset-triggered rejection cannot become an
  // unhandled rejection while the aggregate reset is draining the run.
  const outcome = pending.then(value => ({ value }), error => ({ error }));

  let timeout;
  try {
    await Promise.race([entered, outcome.then(result => { throw result.error || new Error('Audit run completed before worker gate'); }), new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('Audit race worker did not enter')), 10000);
    })]);
  } catch (error) {
    controller.abort(error);
    gate.abort();
    await outcome;
    throw error;
  } finally { clearTimeout(timeout); }
  return Object.freeze({
    sessionId: session.id, requestId, pending, outcome,
    async assertRejected() {
      const settled = await outcome;
      assert.ok(settled.error, 'reset race must reject the in-flight run');
      assert.ok(settled.error?.name === 'AbortError' || /reset|stale|conversation/i.test(settled.error?.message || ''));
      assert.equal(aborted, true, 'reset must abort the in-flight audit worker');
      const rows = (await agents.query('SELECT run_id FROM secureshop_agents.bound_audit_runs WHERE request_id=$1',[requestId])).rows;
      assert.equal(rows.length, 0, 'stale in-flight run must not publish an audit row');
      if (identity?.query) {
        const credited = (await identity.query("SELECT count(*)::integer AS count FROM workshop_platform.objective_contributions WHERE user_id=$1 AND objective_id='ss_audit_instruction_followed'", [scope.platformOwnerId])).rows[0];
        assert.equal(credited.count, 0, 'stale in-flight run must not earn objective credit');
      }
      const execution = captureIdentity();
      assert.ok(execution?.runId, 'race must capture its durable run');
      const run = await ledger.getRun(execution.runId, execution.ownerKey);
      assert.ok(['cancelled','interrupted','failed'].includes(run?.status));
      await assert.rejects(ledger.readCompletedEffect(execution, `${requestId}:audit-summary-job`), { name: 'AbortError' });
      const effects = (await identity.query('SELECT status FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND effect_key=$3',
        [execution.runId, execution.ownerKey, `${requestId}:audit-summary-job`])).rows;
      assert.equal(effects.length, 1);
      assert.equal(effects[0].status, 'uncertain');
      assert.equal((await identity.query('SELECT count(*)::integer AS count FROM workshop_platform.objective_judgments WHERE user_id=$1 AND run_id=$2',[scope.platformOwnerId,execution.runId])).rows[0].count, 0);
      return true;
    },
    async close() { controller.abort(new Error('Race qualification cleanup')); gate.abort(); await outcome; },
  });
}

module.exports = { qualifyAuditResetRace };
