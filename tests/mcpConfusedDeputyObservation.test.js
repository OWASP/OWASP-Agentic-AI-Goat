'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../server/services/mcp/protocolContext');
const deputy = require('../server/services/mcp/confusedDeputyObservation');
const reportPayload = require('../server/services/mcp/reportPayload');
const { runMcpWorkshopGraph } = require('../server/agent-runtime/mcpWorkshopGraph');
const { TOOL_DEFINITIONS } = require('../server/services/mcp/toolRegistry');

const targetId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const defaultArgs = Object.freeze({
  to: ' outside@example.test ',
  body: 'Send this to outside@example.test for the incident review.',
});

function execution(owner = 7, generation = 3, runId = crypto.randomUUID()) {
  return { ownerKey: JSON.stringify(['MCP', String(owner)]), durableGeneration: generation, runId,
    check: async () => {}, trace: async () => {}, effect: async (_key, work) => work() };
}

async function privateTool({ args = defaultArgs, run = execution(), observationEffect = 'mcp_tool_0_send_report',
  protocolEffect = observationEffect } = {}) {
  const owner = Number(JSON.parse(run.ownerKey)[1]);
  const scope = Object.freeze({ targetId, platformOwnerId: owner, platformSessionId: 71,
    generation: Number(run.durableGeneration) });
  const protectedContent = 'DB_PASSWORD=owned-training-secret';
  const recipient = reportPayload.recipient(args.to);
  const body = reportPayload.externalPayload(args.body, protectedContent);
  const invocation = await protocol.withProtocolInvocation({ sessionId: `mcp_${owner}`, execution: run,
    surface: 'chat', effectKey: protocolEffect }, async () => {
    const intentId = deputy.intentIdFor(run.runId, observationEffect);
    const delivered = deputy.bindDelivery({ ok: true, messageId: `mcp-${intentId}@dvaia.local` }, {
      scope, intentId, runId: run.runId, effectKey: observationEffect, to: recipient,
      subject: 'Operations report', body, messageId: `mcp-${intentId}@dvaia.local`,
    });
    const raw = deputy.bindTool(delivered, { output: 'delivered', objective: 'mcp_confused_deputy',
      achieved: true, real: true }, protectedContent);
    const result = { tool: 'send_report', args: { ...args }, ...raw };
    deputy.adoptTool(raw, result);
    protocol.bindResult(protocol.requireProtocolContext(`mcp_${owner}`), 'send_report', args, result);
    return result;
  });
  return { result: invocation.toolResult, run, scope, args, protectedContent, body };
}

test('deputy evidence becomes readable only after the graph binds the exact model-selected SDK call', async () => {
  const item = await privateTool({});
  assert.equal(deputy.readTool(item.result), null);
  assert.equal(deputy.isTrustedModelDecision(item.result), false);
  deputy.bindModelDecision(item.result, { decisionSource: 'model', tool: 'send_report',
    args: item.args, execution: item.run });
  const observation = deputy.readTool(item.result);
  assert.equal(deputy.isTrustedModelDecision(item.result), true);
  assert.equal(observation.to, 'outside@example.test');
  assert.equal(observation.body, item.body);
  assert.equal(observation.protectedContent, item.protectedContent);
  assert.equal(JSON.stringify(item.result).includes(item.scope.targetId), false);
  assert.equal(JSON.stringify(item.result).includes(item.protectedContent), false);

  item.result.args = { to: 'mutated@example.test', body: 'mutable public DTO' };
  item.result.decisionSource = 'scripted';
  assert.equal(deputy.readTool(item.result), observation,
    'the accepted private binding does not reread mutable public result fields');
  assert.equal(deputy.readTool({ ...item.result }), null, 'a copied public result cannot inherit private provenance');
});

test('an empty model-selected covering note remains valid when the tool attaches real protected bytes', async () => {
  const item = await privateTool({ args: { to: 'outside@example.test', body: '' } });
  deputy.bindModelDecision(item.result, { decisionSource: 'model', tool: 'send_report',
    args: item.args, execution: item.run });
  const observation = deputy.readTool(item.result);
  assert.equal(observation.body,
    `${reportPayload.ATTACHMENT_MARKER}${item.protectedContent}`);
  assert.equal(deputy.isTrustedModelDecision(item.result), true);
});

test('scripted labels, mismatched arguments, coordinates and effect receipts cannot mint deputy evidence', async () => {
  const cases = [
    { label: 'scripted decision', bind: item => ({ decisionSource: 'scripted', tool: 'send_report', args: item.args, execution: item.run }) },
    { label: 'wrong tool', bind: item => ({ decisionSource: 'model', tool: 'read_file', args: item.args, execution: item.run }) },
    { label: 'changed recipient', bind: item => ({ decisionSource: 'model', tool: 'send_report',
      args: { ...item.args, to: 'other@example.test' }, execution: item.run }) },
    { label: 'changed body', bind: item => ({ decisionSource: 'model', tool: 'send_report',
      args: { ...item.args, body: 'different' }, execution: item.run }) },
    { label: 'wrong run', bind: item => ({ decisionSource: 'model', tool: 'send_report', args: item.args,
      execution: { ...item.run, runId: crypto.randomUUID() } }) },
    { label: 'wrong owner', bind: item => ({ decisionSource: 'model', tool: 'send_report', args: item.args,
      execution: { ...item.run, ownerKey: JSON.stringify(['MCP', '8']) } }) },
    { label: 'wrong generation', bind: item => ({ decisionSource: 'model', tool: 'send_report', args: item.args,
      execution: { ...item.run, durableGeneration: item.run.durableGeneration + 1 } }) },
  ];
  for (const entry of cases) {
    const item = await privateTool({});
    deputy.bindModelDecision(item.result, entry.bind(item));
    assert.equal(deputy.readTool(item.result), null, entry.label);
    assert.equal(deputy.isTrustedModelDecision(item.result), false, entry.label);
  }

  const wrongEffect = await privateTool({ observationEffect: 'mcp_tool_0_send_report',
    protocolEffect: 'different-sdk-effect' });
  deputy.bindModelDecision(wrongEffect.result, { decisionSource: 'model', tool: 'send_report',
    args: wrongEffect.args, execution: wrongEffect.run });
  assert.equal(deputy.readTool(wrongEffect.result), null);
});

test('the indirect raw observation seam cannot bypass the deputy model-decision gate', async () => {
  const item = await privateTool({ observationEffect: 'mcp_indirect_injection_consequence' });
  assert.equal(deputy.readTool(item.result), null);
  assert.equal(deputy.readIndirectTool(item.result)?.effectKey, 'mcp_indirect_injection_consequence');
  const direct = await privateTool({});
  assert.equal(deputy.readIndirectTool(direct.result), null);
});

test('the graph binds actual provider decisions but withholds scripted mock selections', async () => {
  async function run(provider) {
    const run = execution();
    let calls = 0;
    const args = { to: 'outside@example.test', body: 'incident cover note' };
    const model = provider === 'mock' ? { provider: 'mock' } : {
      provider: 'ollama',
      async chatWithTools() {
        calls += 1;
        return { content: JSON.stringify(calls === 1 ? { tool: 'send_report', params: args }
          : { tool: 'none', params: {} }) };
      },
    };
    const result = await runMcpWorkshopGraph({ message: 'send the report', sandbox: {
      toolListTools: () => TOOL_DEFINITIONS.filter(item => item.name === 'send_report'),
    } }, {
      model, execution: run,
      detectIntent: () => ({ tool: 'send_report', params: args, intent: 'send_report' }),
      resolveInjectionIntent: async () => null,
      executeTool: async (_tool, selected, _sandbox, options) => (await privateTool({ args: selected,
        run, observationEffect: options.effectKey })).result,
      detectObjectives: () => ['mcp_confused_deputy'],
      phraseReply: async () => 'done',
    });
    return result;
  }

  const selected = await run('ollama');
  assert.equal(selected.decisionSource, 'model');
  assert.equal(deputy.isTrustedModelDecision(selected.toolResult), true);
  assert.ok(deputy.readTool(selected.toolResult));

  const scripted = await run('mock');
  assert.equal(scripted.decisionSource, 'scripted');
  assert.equal(deputy.isTrustedModelDecision(scripted.toolResult), false);
  assert.equal(deputy.readTool(scripted.toolResult), null);
});
