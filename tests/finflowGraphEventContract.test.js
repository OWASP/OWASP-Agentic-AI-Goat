'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { runFinflowDecisionGraph } = require('../server/agent-runtime/finflowDecisionGraph');
const { USER_TOOL_SCHEMAS } = require('../server/services/sensitiveInfoWorkshopAgent');

function databaseEventTypes() {
  const sql = fs.readFileSync(path.join(__dirname,
    '../db/postgres/identity-migrations/0018_graph_provisional_event.sql'), 'utf8');
  const match = sql.match(/event_type\s+IN\s*\(([^)]+)\)/);
  assert.ok(match, '0018 graph event type constraint must remain explicit');
  return new Set([...match[1].matchAll(/'([^']+)'/g)].map(item => item[1]));
}

test('FinFlow administrative catalog observation emits a PostgreSQL-supported event type', async () => {
  const allowed = databaseEventTypes();
  assert.deepEqual([...allowed].sort(),
    ['decision', 'error', 'node_end', 'node_start', 'provisional', 'tool']);
  const events = [];
  const execution = {
    ownerId: 'event-contract-owner',
    runId: '00000000-0000-4000-8000-000000000001',
    ownerKey: JSON.stringify(['FinFlow', 'event-contract-owner']),
    generation: 0,
    check: async () => {},
    trace: async event => {
      assert.ok(allowed.has(event.type), `unsupported graph_runtime.events type: ${event.type}`);
      events.push(event);
    },
  };
  let modelCalls = 0;
  const result = await runFinflowDecisionGraph({
    message: 'Explain the restricted administrative catalog.',
    history: [],
    mode: 'vulnerable',
    execution,
  }, {
    tools: USER_TOOL_SCHEMAS,
    model: {
      provider: 'controlled',
      generateResponse: async prompt => {
        modelCalls += 1;
        return prompt.startsWith('Select exactly')
          ? { response: '{"action":"admin_catalog_observation","params":{}}',
            provider: 'controlled', model: 'controlled' }
          : { response: 'Eight controlled administrative tools were observed.',
            provider: 'controlled', model: 'controlled' };
      },
    },
    executeTool: async () => { throw new Error('catalog observation must not execute a tool'); },
    observeAdminCatalog: async () => ({ catalog: Array.from({ length: 8 }, (_, index) => ({ index })) }),
    buildPrompt: () => 'Summarize the controlled administrative catalog.',
    judgeResult: async value => value,
  });

  assert.equal(result.success, true);
  assert.equal(modelCalls, 2);
  const observed = events.filter(event => event.node === 'observe_admin_catalog'
    && event.type === 'decision');
  assert.equal(observed.length, 1);
  assert.deepEqual(observed[0].data, {
    observationType: 'admin_catalog',
    action: 'admin_catalog_observation',
    toolCount: 8,
  });
  assert.equal(events.some(event => event.type === 'observation'), false);
});
