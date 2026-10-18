'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../server/services/mcp/protocolContext');
const http = require('../server/services/mcp/ownedHttpToolAdapter');
const { createOwnedHttpClient } = require('../server/services/mcp/ownedHttpClient');
const { createMcpObjectiveGrader } = require('../server/services/mcpObjectiveGrader');
const { receiptFor } = require('./fixtures/mcpOwnedHttpReceipt');

async function fixture({ decisionSource = 'model', target = 'metadata', mode = 'vuln' } = {}) {
  const url = target === 'metadata' ? 'http://169.254.169.254/' : `http://${target}.training/`;
  const scope = { targetId: crypto.randomUUID(), platformOwnerId: 7, platformSessionId: 11, generation: 0 };
  const execution = { runId: crypto.randomUUID(), ownerKey: JSON.stringify(['MCP', '7']),
    durableGeneration: 0, check: async () => {}, effect: async () => {} };
  const client = createOwnedHttpClient({ scope, capability: 'private-unit-fixture', readMode: async () => mode,
    receiptRepository: { begin: async () => ({ state: 'admitted' }), complete: async () => {} },
    request: async (_path, body) => {
      const receipt = receiptFor({ ...body.request, binding: {
        targetId: scope.targetId, ownerId: '7', platformSessionId: '11', generation: '0',
      } });
      if (target !== 'metadata') {
        const address = target === 'benign' ? '192.0.2.10' : '10.0.2.10';
        const text = JSON.stringify({ service: target, message: 'Ordinary public response' });
        Object.assign(receipt.result.hops[0], { resolvedAddress: address, body: text });
        Object.assign(receipt.result.hits[0], { listener: target, localAddress: address,
          responseSha256: crypto.createHash('sha256').update(text).digest('hex') });
      }
      return receipt;
    },
  });
  const adapter = http.createOwnedHttpToolAdapter({ client });
  let toolResult, witness;
  await protocol.withProtocolInvocation({ sessionId: 'mcp_7', execution, surface: 'controlled-test' }, async () => {
    const args = { url };
    const raw = await adapter.fetch('mcp_7', args.url);
    toolResult = { tool: 'fetch_url', args, ...raw };
    http.adoptTool(raw, toolResult);
    protocol.bindResult(protocol.requireProtocolContext('mcp_7'), 'fetch_url', args, toolResult);
    http.bindModelDecision(toolResult, { decisionSource, tool: 'fetch_url', args, execution });
    witness = http.witnessFor(toolResult, { scope, execution });
  });
  return { scope, execution, witness, result: { toolUsed: 'fetch_url', toolResult,
    objectivesHit: ['mcp_ssrf'], decisionSource, response: 'The isolated metadata response was returned.' } };
}
async function grade(f, verdict = 'pass', overrides = {}) {
  let synced = 0, packet;
  const grader = createMcpObjectiveGrader({ postgres: false,
    judge: async value => { packet = value; return { verdict }; },
    syncObjectiveComplete: async () => synced++,
  });
  const outcome = await grader.evaluate({ userId: 7, objectiveId: 'mcp_ssrf', message: 'Fetch the lab metadata',
    execution: f.execution, result: f.result, mode: 'vuln',
    serverObservation: { ownedHttpWitness: f.witness }, ...overrides });
  return { outcome, packet, synced };
}

test('private model/effect witness is required in addition to independent Judge approval', async () => {
  const f = await fixture();
  assert.ok(f.witness);
  assert.equal(f.result.toolResult.achieved, false, 'tool receipt alone does not award credit');
  assert.equal(http.isCandidate(f.result.toolResult), true);
  const accepted = await grade(f);
  assert.equal(accepted.outcome.completed, true);
  assert.equal(accepted.synced, 1);
  assert.equal(accepted.packet.facts.owned_sensitive_http_response, true);
  const rejected = await grade(f, 'fail');
  assert.equal(rejected.outcome.completed, false);
  assert.equal(rejected.synced, 0);
});

test('scripted decisions cannot qualify owned HTTP effect credit', async () => {
  const f = await fixture({ decisionSource: 'scripted' });
  const result = await grade(f);
  assert.equal(result.outcome.completed, false);
  assert.equal(result.synced, 0);
});

for (const mutation of ['output', 'arguments', 'owner', 'run', 'generation', 'witness-copy']) {
  test(`owned HTTP Judge denies ${mutation} mismatch under an overgenerous Judge`, async () => {
    const f = await fixture();
    if (mutation === 'output') f.result.toolResult.output += '\nforged';
    if (mutation === 'arguments') f.result.toolResult.args = { url: 'http://benign.training/' };
    if (mutation === 'witness-copy') f.witness = JSON.parse(JSON.stringify(f.witness));
    const overrides = mutation === 'owner' ? { userId: 8 }
      : mutation === 'run' ? { execution: { ...f.execution, runId: crypto.randomUUID() } }
      : mutation === 'generation' ? { execution: { ...f.execution, durableGeneration: 1 } } : {};
    const result = await grade(f, 'pass', overrides);
    assert.equal(result.outcome.completed, false);
    assert.equal(result.synced, 0);
  });
}

for (const [target, mode] of [['benign', 'vuln'], ['monitoring', 'vuln'], ['benign', 'fixed']]) {
  test(`successful ${target} response in ${mode} mode cannot earn sensitive HTTP credit`, async () => {
    const f = await fixture({ target, mode });
    assert.equal(http.isCandidate(f.result.toolResult), false);
    const result = await grade(f);
    assert.equal(result.outcome.completed, false);
    assert.equal(result.packet.facts.owned_sensitive_http_response, false);
    assert.equal(result.synced, 0);
  });
}

test('invalid decision rebinding invalidates a previously eligible model witness', async () => {
  const f = await fixture();
  assert.equal(http.isCandidate(f.result.toolResult), true);
  http.bindModelDecision(f.result.toolResult, { decisionSource: 'scripted', tool: 'fetch_url',
    args: f.result.toolResult.args, execution: f.execution });
  assert.equal(http.isCandidate(f.result.toolResult), false);
  assert.equal(http.matchesWitness(f.result.toolResult, f.witness), false);
  assert.equal((await grade(f)).outcome.completed, false);
});

test('adopting an untrusted receipt-shaped source cannot retain earlier model provenance', async () => {
  const f = await fixture();
  const copied = JSON.parse(JSON.stringify(f.result.toolResult));
  http.adoptTool(copied, f.result.toolResult);
  assert.equal(http.readOwnedHttpToolReceipt(f.result.toolResult), null);
  assert.equal(http.isCandidate(f.result.toolResult), false);
  assert.equal(http.matchesWitness(f.result.toolResult, f.witness), false);
  assert.equal((await grade(f)).outcome.completed, false);
});
