'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createObjectiveRegradeService } = require('../server/services/objectiveRegradeService');

function fixture(original, { resolver, onAdmission = () => {}, retry, baseCheck = async () => {} } = {}) {
  const calls = { admitted: 0, evaluated: 0 };
  let runOptions;
  const service = createObjectiveRegradeService({
    receipts: { getRecovery: async () => original, ...(resolver ? { assertRecoveryAuthority: resolver } : {}) },
    completion: { retry: async args => { calls.evaluated++; return retry ? retry(args) : { controlled: true }; } },
    coordinatorFactory: () => ({ run: async (_owner, options, work) => {
      calls.admitted++;
      runOptions=options;
      onAdmission();
      return work({ runId: randomUUID(), check: baseCheck });
    } }),
  });
  return { service, calls, getOptions:()=>runOptions, request: { userId: 1, evaluationId: randomUUID() } };
}

test('required persona recovery without a resolver stops before run admission or Judge work', async () => {
  const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true });
  await assert.rejects(f.service(f.request), { code: 'PERSONA_EVALUATION_UNAVAILABLE' });
  assert.deepEqual(f.calls, { admitted: 0, evaluated: 0 });
});

test('required recovery resolves only original receipt coordinates and rechecks after admission', async () => {
  let checks = 0, resolved;
  const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true }, {
    resolver: async value => { resolved = value; return Object.freeze({ check: async () => { checks++; } }); },
    retry: async ({ execution }) => { await execution.check(); return { controlled: true }; },
  });
  assert.deepEqual(await f.service(f.request), { controlled: true });
  assert.deepEqual(resolved, f.request);
  assert.equal(checks, 3);
  assert.deepEqual(f.calls, { admitted: 1, evaluated: 1 });
});

test('revocation between admission checks prevents completion service work', async () => {
  let revoked = false;
  const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true }, {
    resolver: async () => ({ check: async () => { if (revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); } }),
    onAdmission: () => { revoked = true; },
  });
  await assert.rejects(f.service(f.request), { code: 'SHOP_AUTH_INVALID' });
  assert.deepEqual(f.calls, { admitted: 1, evaluated: 0 });
});

test('required marker rejects null or malformed resolver results before admission', async () => {
  for (const result of [null, {}, { check: true }]) {
    const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true }, {
      resolver: async () => result,
    });
    await assert.rejects(f.service(f.request), { code: 'PERSONA_EVALUATION_UNAVAILABLE' });
    assert.deepEqual(f.calls, { admitted: 0, evaluated: 0 });
  }
});

test('a reset during awaited persona validation is caught by the second execution check', async () => {
  let checks = 0, reset = false;
  const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true }, {
    resolver: async () => ({ check: async () => { if (++checks === 2) { await Promise.resolve(); reset = true; } } }),
    baseCheck: async () => { if (reset) throw Object.assign(Error('reset'), { code: 'STALE_GENERATION' }); },
  });
  await assert.rejects(f.service(f.request), { code: 'STALE_GENERATION' });
  assert.deepEqual(f.calls, { admitted: 1, evaluated: 0 });
});

test('actual completion retry rejects revoked authority after a held controlled Judge response', { timeout: 2000 }, async () => {
  const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');
  const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
  const rubric = { family: 'SecureShop', scenario: 'authority-test', objectiveId: 'authority_test', version: 'v1',
    mode: 'vuln', requiredFacts: [], criteria: [{ id: 'proof', description: 'Observed effect', allowedSources: ['tool_result'] }] };
  const prepared = prepareJudgeInput({ rubric, evidence: [{ id: 'effect', source: 'tool_result', content: 'Controlled owned effect' }], facts: {} });
  assert.equal(prepared.evidenceError, undefined);
  const receipt = { evaluationId: randomUUID(), runId: randomUUID(), rubricVersion: rubric.version, evidenceDigest: prepared.evidenceDigest };
  const entered = Promise.withResolvers(), response = Promise.withResolvers();
  let revoked = false, commits = 0;
  const completion = createObjectiveCompletionService({
    progress: { getGeneration: async () => 0 },
    receipts: { beginEvaluation: async () => {}, beginRetry: async () => ({ receipt, packet: prepared.packet }),
      recordVerdict: async () => { commits++; throw Error('Unexpected verdict commit'); } },
    judge: async () => { entered.resolve(); return response.promise; },
  });
  const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: true }, {
    resolver: async () => ({ check: async () => { if (revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); } }),
    retry: args => completion.retry(args),
  });
  const pending = f.service(f.request);
  await entered.promise;
  revoked = true;
  response.resolve({ verdict: 'pass', criteria: [], explanation: 'Controlled response' });
  await assert.rejects(pending, { code: 'SHOP_AUTH_INVALID' });
  assert.equal(commits, 0);
});

test('malformed persisted persona markers cannot select historical unbound behavior', async () => {
  for (const marker of [null, 'true', 1, {}, []]) {
    const f = fixture({ owner_key: JSON.stringify(['SecureShop', 'owned']), persona_authority_required: marker });
    await assert.rejects(f.service(f.request), { code: 'PERSONA_EVALUATION_UNAVAILABLE' });
    assert.deepEqual(f.calls, { admitted: 0, evaluated: 0 });
  }
});

test('old-schema and explicitly unbound recovery retain the existing path', async () => {
  for (const marker of [undefined, false]) {
    const row = { owner_key: JSON.stringify(['ARIA', 'owned']) };
    if (marker !== undefined) row.persona_authority_required = marker;
    const f = fixture(row);
    assert.deepEqual(await f.service(f.request), { controlled: true });
    assert.deepEqual(f.calls, { admitted: 1, evaluated: 1 });
    assert.equal(f.getOptions().timeoutMs,undefined);
  }
});

test('only a persisted canonical Audit retry receives the extended owner budget and Judge wrapper',async()=>{
  const row={owner_key:JSON.stringify(['SecureShop','owned']),workshop_key:'secureshop_agent_security',
    family:'SecureShop',scenario:'bound_audit_summary',objective_id:'ss_audit_instruction_followed'};
  let seen;
  const f=fixture(row,{retry:async args=>{seen=args;return{controlled:true};}});
  assert.deepEqual(await f.service(f.request),{controlled:true});
  assert.equal(f.getOptions().timeoutMs,120000);
  assert.equal(typeof seen.retryJudge,'function');
  assert.ok(Number.isFinite(seen.execution.auditDeadline));
  const other=fixture({...row,objective_id:'ss_audit_sql_extraction'},{retry:async args=>{seen=args;return{controlled:true};}});
  await other.service(other.request);
  assert.equal(other.getOptions().timeoutMs,undefined);
  assert.equal(seen.retryJudge,undefined);
});

test('missing recovery and malformed owner scope never admit retry work', async () => {
  for (const [row, code] of [[null, 'NOT_FOUND'], [{ owner_key: 'invalid' }, 'RETRY_NOT_ALLOWED'],
    [{ owner_key: JSON.stringify(['ARIA']) }, 'RETRY_NOT_ALLOWED']]) {
    const f = fixture(row);
    await assert.rejects(f.service(f.request), { code });
    assert.deepEqual(f.calls, { admitted: 0, evaluated: 0 });
  }
});
