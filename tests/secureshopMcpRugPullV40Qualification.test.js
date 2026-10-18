'use strict';

// Contract checks only: these objects are synthetic and confer no V40 proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertVulnerableRugPull, assertNoFixedEffect } =
  require('./fixtures/secureshopMcpRugPullV40Qualification');

const HEX1 = '1'.repeat(64), HEX2 = '2'.repeat(64);
const REQUEST_ID = '30000000-0000-4000-8000-000000000001';
const BINDING = Object.freeze({ launchId: '30000000-0000-4000-8000-000000000002',
  scenarioId: '30000000-0000-4000-8000-000000000003', generation: 1,
  platformOwnerId: 5, platformSessionId: 6, shopUserId: 7, role: 'admin' });

function positive() {
  const serverIdentity = 'secureshop-weather-lab';
  const baseline = { serverIdentity, schemaVersion: 1, schemaSha256: HEX1 };
  const changed = { serverIdentity, schemaVersion: 2, schemaSha256: HEX2 };
  return { subject: { binding: { ...BINDING } }, replay: true, siblingDenied: true,
    phaseProofs: [
      { phase: 'rogue', actorCalls: 1, judgeCalls: 1 },
      { phase: 'baseline', actorCalls: 1, judgeCalls: 0 },
      { phase: 'changed', actorCalls: 1, judgeCalls: 1 },
    ],
    controls: [
      {}, {}, {}, { path: '/run', status: 200, body: baseline },
      { path: '/rotate', status: 200, body: changed },
      { path: '/run', status: 200, body: changed },
    ],
    turns: [
      { phase: 'rogue' },
      { phase: 'baseline', response: baseline },
      { phase: 'changed', response: changed,
        invocations: [{ server_identity: serverIdentity, schema_version: 2,
          schema_sha256: Buffer.from(HEX2, 'hex') }],
        judgments: [{ objective_id: 'ss_rug_pull_invoked', verdict: 'pass',
          credited: 'evaluation-1', evaluation_id: 'evaluation-1' }] },
    ] };
}

test('V40 accepts only the original D16 same-server changed-schema proof', () => {
  assert.deepEqual(assertVulnerableRugPull(positive(), BINDING), {
    serverIdentity: 'secureshop-weather-lab', baselineSha256: HEX1, changedSha256: HEX2 });
  for (const mutate of [
    p => { p.turns[2].response.serverIdentity = 'other-server'; },
    p => { p.turns[2].response.schemaVersion = 1; },
    p => { p.turns[2].response.schemaSha256 = HEX1; },
    p => { p.turns[2].invocations[0].schema_sha256 = Buffer.from(HEX1, 'hex'); },
    p => { p.turns[2].judgments[0].credited = null; },
    p => { p.phaseProofs[2].judgeCalls = 0; },
    p => { p.replay = false; },
    p => { p.siblingDenied = false; },
    p => { p.subject.binding.launchId = '30000000-0000-4000-8000-000000000004'; },
  ]) { const subject = positive(); mutate(subject); assert.throws(() => assertVulnerableRugPull(subject, BINDING)); }
});

test('fixed contrast rejects any turn, invocation, effect, judgment, model or Judge change', () => {
  const state = () => ({ invocations: [{ id: 1 }], turns: [{ id: 2 }],
    effects: [{ id: 3 }], judgments: [{ id: 4 }] });
  const wire = () => ({ externalAttempts: 3, counts: { actor: 2, judge: 1 }, failed: false });
  const input = () => ({ before: state(), after: state(), wireBefore: wire(), wireAfter: wire(),
    response: { status: 503, body: { error: 'MCP trust exercise unavailable' } }, requestId: REQUEST_ID,
    originalDenial: { requestId: REQUEST_ID, code: 'BOUND_MCP_UNAVAILABLE',
      message: 'Changed MCP schema blocked by fixed policy' } });
  assert.doesNotThrow(() => assertNoFixedEffect(input()));
  for (const mutate of [
    p => { p.after.invocations.push({ id: 5 }); },
    p => { p.after.turns.push({ id: 5 }); },
    p => { p.after.effects.push({ id: 5 }); },
    p => { p.after.judgments.push({ id: 5 }); },
    p => { p.wireAfter.externalAttempts++; },
    p => { p.wireAfter.counts.judge++; },
    p => { p.wireAfter.failed = true; },
    p => { p.response.status = 200; },
    p => { p.response.body = { error: 'Outcome unknown' }; },
    p => { p.originalDenial.code = 'MODEL_UNAVAILABLE'; },
    p => { p.originalDenial.requestId = '30000000-0000-4000-8000-000000000002'; },
  ]) { const subject = input(); mutate(subject); assert.throws(() => assertNoFixedEffect(subject)); }
});
