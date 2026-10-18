'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

for (const family of ['aria', 'nova']) {
  for (const reason of ['blocked', 'duplicate_action', 'tool_budget', 'model_finished', 'decision_unavailable']) {
    test(`${family} retains ${reason} in sanitized ledger events with exact presentation provenance and sanitized chat DTO`, async () => {
      const events = [];
      let decisions = 0, effects = 0;
      const tool = family === 'aria' ? 'search_products' : 'search_papers';
      const parameter = family === 'aria' ? 'searchTerm' : 'query';
      // Controlled simulation of the live-provider interface; no real-model or credit claim.
      const model = { provider: 'ollama', async generateResponse(prompt) {
        if (!prompt.includes('Select exactly one tool')) return { response: 'Controlled summary' };
        decisions++;
        if (reason === 'decision_unavailable') return { response: 'invalid JSON' };
        if (reason === 'model_finished') return { response: JSON.stringify({ tool: 'general_chat', params: {} }) };
        return { response: JSON.stringify({ tool, params: {
          [parameter]: reason === 'duplicate_action' ? 'private-search-marker' : `query-${decisions}`,
        } }) };
      } };
      const agent = require(`../server/services/${family}AgentService`).createAgent({
        model,
        store: { getHistory: async () => [], saveMessage: async () => {},
          [family === 'aria' ? 'searchProducts' : 'searchPapers']: async () => { effects++; return []; } },
        runLedger: { begin: async () => ({ durableGeneration: 0 }), assertCurrent: async () => {},
          finish: async () => {}, recordEvent: async (_context, event) => events.push(event),
          effect: async (_context, _key, work) => work() },
      });
      const message = reason === 'blocked' ? (family === 'aria' ? 'UNION SELECT NULL' : '$gt') : 'Perform the requested searches';
      const result = await agent.chat('73', message, [], reason === 'blocked' ? 'fixed' : 'vuln');
      const terminal = events.filter(event => event.data?.terminationReason || event.data?.errorCode === 'REQUEST_BLOCKED');
      assert.equal(terminal.length, 1);
      assert.equal(terminal[0].node, 'persist');
      assert.equal(terminal[0].type, 'node_end');
      assert.ok(terminal[0].data.durationMs >= 0);
      assert.deepEqual(terminal[0].data, { durationMs: terminal[0].data.durationMs,
        ...(reason === 'blocked' ? { errorCode: 'REQUEST_BLOCKED' } : { terminationReason: reason }), toolSteps: effects });
      assert.equal(effects, reason === 'duplicate_action' ? 1 : reason === 'tool_budget' ? 4 : 0);
      assert.equal(JSON.stringify(terminal).includes('private-search-marker'), false);
      assert.deepEqual(Object.keys(result).sort(), [...(effects?['presentation']:[]),'response', 'toolObservations', 'toolResult', 'toolUsed']);
      if(effects){
        const sha=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
        const display=family==='aria'?'No products found matching your search.':'No papers found matching your query.';
        assert.equal(result.response,['**Model explanation:**\n\nControlled summary',...Array.from({length:effects},()=>`**Tool result — ${tool} (server-rendered):**\n\n${display}`)].join('\n\n'));
        const p=result.presentation;assert.equal(p.version,'workshop-result-presentation-v1');assert.equal(p.family,family.toUpperCase());assert.equal(typeof p.runId,'string');assert.ok(p.runId.length);
        assert.deepEqual(p.narrative,{text:'Controlled summary',source:'model',errorCode:null,sha256:sha('Controlled summary')});assert.equal(p.responseSha256,sha(result.response));
        assert.deepEqual(p.blocks,result.toolObservations.map((o,index)=>({index,tool,effectKey:o.effectKey,resultSha256:sha('[]'),displaySha256:sha(display)})));
        assert.equal(new Set(p.blocks.map(b=>b.effectKey)).size,effects);
      }
    });
  }
}

test('termination reason vocabulary remains compatible with the applied PostgreSQL constraint', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { traceData } = require('../server/agent-runtime/runTraceStore');
  const migration = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0057_graph_agent_outcome.sql'), 'utf8');
  const clause = migration.match(/metadata->>'terminationReason' IN \(([^)]+)\)/)[1];
  for (const reason of ['duplicate_action', 'tool_budget', 'model_finished', 'decision_unavailable']) {
    assert.ok(clause.includes(`'${reason}'`));
    assert.equal(traceData({ terminationReason: reason }).terminationReason, reason);
  }
  assert.deepEqual(traceData({ terminationReason: 'blocked' }), {});
  assert.deepEqual(traceData({ errorCode: 'REQUEST_BLOCKED', toolSteps: 0 }), { errorCode: 'REQUEST_BLOCKED', toolSteps: 0 });
  assert.deepEqual(traceData({ responseSource: 'model' }), { responseSource: 'model' });
  assert.deepEqual(traceData({ responseSource: 'untrusted-value' }), {});
});

test('explicit nonlive decision provider is rejected before dispatch or effects',async()=>{
 const {requestDecision}=require('../server/agent-runtime/workshopDecisions');
 for(const provider of ['fixture','controlled','mock'])await assert.rejects(requestDecision({name:'ARIA',model:{provider,generateResponse(){assert.fail('Nonlive provider must not dispatch');}}},{message:'Search products',history:[],toolObservations:[]},{signal:new AbortController().signal}),/No live model decision/);
});
