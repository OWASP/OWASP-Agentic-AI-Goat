'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createSecureShopAuditSummaryGraph } = require('../../server/agent-runtime/secureshopAuditSummaryGraph');
const { createAuditSummaryObservation } = require('../../server/services/secureshopAuditSummaryObservation');
const { createSecureShopModelQualifier } = require('../../server/services/secureshopModelQualification');
const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');

// Actual model/source qualification of the execution core only. This helper's
// local effect receipt is not a platform ledger receipt and earns no credit.
async function qualifyAuditGraph({ snapshot, scope, evidenceRoot }) {
  const messages = [], traces = [], effects = [], calls = [];
  const actor = new OllamaProvider({ baseUrl: process.env.OLLAMA_BASE_URL, model: 'llama3.1:8b' });
  const provider = Object.fromEntries(['chat', 'finalResponse'].map(method => [method, async input => {
    const response = await actor[method](input);
    calls.push({ method, provider: response.provider, model: response.model, mocked: response.mocked,
      stopReason: response.stop_reason, responseMode: response.responseMode || null });
    return response;
  }]));
  let source = null;
  const run = createSecureShopAuditSummaryGraph({ provider, qualifyModel: createSecureShopModelQualifier(actor),
    Trace: class {
      record(row) { traces.push({ event_id: randomUUID(), ...row }); }
      async flush() { await fs.writeFile(path.join(evidenceRoot, 'audit-model-traces.json'), JSON.stringify(traces), { mode: 0o600 }); }
    },
    store: {
      async appendUserMessage(_id, content) { messages.push({ role: 'user', content }); },
      async appendAssistantMessage(_id, content) { messages.push({ role: 'assistant', content }); },
      async appendAssistantToolCalls(_id, calls) { messages.push({ role: 'assistant', content: '', tool_calls: calls.map(call => ({
        id: call.id, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) },
      })) }); },
      async appendToolResult(_id, tool_call_id, content) { messages.push({ role: 'tool', tool_call_id, content }); },
      async getMessages() { return [...messages]; }, async remainingBudget() { return 100000; }, async addUsedTokens() {},
    },
    async readObservation({ requestedCount, signal }) {
      const events = await Array.fromAsync(snapshot.rows({ scope, requestedCount, signal, checkCurrent: async () => {} }));
      source = createAuditSummaryObservation({ events, requestedCount, hasMore: false });
      return source;
    },
  });
  const result = await run({ sessionId: randomUUID(), requestedCount: 20, persona: { id: 3, role: 'admin' },
    signal: AbortSignal.timeout(90000), check: async () => {},
    async effectWithReceipt(key, callback) {
      const value = await callback(); const receipt = { status: 'completed', effectKey: key, qualificationOnly: true };
      effects.push(receipt); return { value, receipt };
    },
  });
  assert.deepEqual(calls.map(call => call.method), ['chat', 'finalResponse']);
  assert.ok(calls.every(call => call.provider === 'ollama' && call.model === 'llama3.1:8b' && call.mocked === false));
  assert.equal(calls[1].responseMode, 'structured_final');
  assert.equal(effects.length, 1); assert.ok(source.row_count > 0);
  assert.equal(messages.find(row => row.role === 'tool').content, JSON.stringify(source));
  assert.ok(result.summary.trim());
  const evidence = { version: 1, scope, calls, sourceCount: source.row_count,
    logSha256: source.source_manifest.logSha256, sourcesSha256: source.source_manifest.sourcesSha256,
    result, qualificationOnly: true, objectiveCredit: false };
  const spool = await require('../../server/services/secureshopAuditObservationSpool').spoolAuditObservation({
    root:evidenceRoot,scope,runId:randomUUID(),requestedCount:20,checkCurrent:async()=>{},
    rows:snapshot.rows({scope,requestedCount:20,checkCurrent:async()=>{}}),
  });
  try {
    const worker = await require('../../server/services/secureshopAuditWorkerHost').runSecureShopAuditWorker({
      spool,baseUrl:process.env.OLLAMA_BASE_URL,model:'llama3.1:8b',persona:{id:3,role:'admin'},checkCurrent:async()=>{},
    });
    assert.equal(worker.rowCount,source.row_count);assert.equal(worker.objectiveCredit,false);
    for(const [name,reference] of Object.entries(worker.artifacts)) {
      const bytes=await fs.readFile(path.join(spool.directory,`${name}.json`));
      assert.equal(require('node:crypto').createHash('sha256').update(bytes).digest('hex'),reference.sha256);
      assert.equal(bytes.length,reference.bytes);
    }
    evidence.worker={result:worker,sourceVerified:true,artifactsVerified:true};
  } finally { await spool.dispose(); }
  await fs.writeFile(path.join(evidenceRoot, 'audit-model-qualification.json'), JSON.stringify(evidence), { mode: 0o600 });
  return evidence;
}
module.exports = { qualifyAuditGraph };
