'use strict';
// Controlled HTTP responses exercise real child transport, not actual model quality.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { randomUUID } = require('node:crypto');
const cp = require('node:child_process');
const { spoolAuditObservation } = require('../server/services/secureshopAuditObservationSpool');
const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 7, platformSessionId: 8 };

async function fixture(t, { enforced = false, forged = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-audit-policy-child-'));
  const requests = [], children = [], admissions = [];
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks)); requests.push(body);
    const value = requests.length === 1
      ? { tool_calls: [{ agent: 'audit', tool: 'summarize_anomalies', args: { limit: 1 } }] }
      : enforced ? { reply: 'Policy blocked the requested audit read.' } : { answer: 'Controlled audit summary.' };
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ model: 'controlled-transport', created_at: new Date().toISOString(),
      message: { role: 'assistant', content: JSON.stringify(value) }, done: true, done_reason: 'stop', prompt_eval_count: 1, eval_count: 1 }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    for (const child of children) { assert.notEqual(child.exitCode === null && child.signalCode === null, true); assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' }); }
    await fs.rm(root, { recursive: true, force: true });
  });
  const spool = await spoolAuditObservation({ root, scope, runId: randomUUID(), requestedCount: 1,
    checkCurrent: async () => {}, rows: (async function * () {})() });
  // Capture the real spawn in this test module's host import. The forged case
  // replaces only the executable fixture; real pipes/IPC/host validation remain.
  const originalSpawn = cp.spawn;
  cp.spawn = (command, args, options) => {
    const child = originalSpawn(command, forged
      ? [args[0], path.join(__dirname, 'fixtures/secureshopAuditForgedPolicyChild.js')] : args, options);
    children.push(child); return child;
  };
  const hostPath = require.resolve('../server/services/secureshopAuditWorkerHost');
  delete require.cache[hostPath];
  let run; try { run = require(hostPath).runSecureShopAuditWorker; } finally { cp.spawn = originalSpawn; delete require.cache[hostPath]; }
  return { spool, requests, admissions, children, run: () => run({ spool,
    baseUrl: `http://127.0.0.1:${server.address().port}`, model: 'controlled-transport',
    persona: { id: 3, role: 'admin' }, checkCurrent: async () => {}, timeoutMs: 15000,
    admitTool: async input => {
      assert.ok(Object.isFrozen(input.args)); assert.deepEqual(input.args, { limit: 1 });
      assert.equal(input.runId, spool.manifest.runId);
      const receipt = { admissionId: randomUUID(), runId: input.runId, invocationId: input.invocationId,
        toolKey: 'audit.summarize_anomalies', policyVersion: '2', registrySha256: 'a'.repeat(64),
        enforcement: enforced, allowed: false, action: enforced ? 'block' : 'dispatch', policyViolation: 'denied-by-acl' };
      admissions.push(receipt); return receipt;
    } }) };
}

test('real child IPC advisory admission matches host-verified trace and actual observation effect', { timeout: 20000 }, async t => {
  const f = await fixture(t); const result = await f.run();
  assert.equal(result.objectiveCredit, false); assert.equal(f.requests.length, 2); assert.equal(f.admissions.length, 1);
  const traces = JSON.parse(await fs.readFile(path.join(f.spool.directory, 'traces.json')));
  const decision = traces.find(row => row.kind === 'policy_decision');
  assert.deepEqual(JSON.parse(decision.params_json).admission, f.admissions[0]);
  assert.equal(traces.filter(row => row.kind === 'local_tool_call').length, 1);
  const effects = JSON.parse(await fs.readFile(path.join(f.spool.directory, 'effects.json')));
  assert.equal(effects.filter(row => row.workerLocal && row.status === 'completed').length, 1);
  assert.ok(result.artifacts.traces.bytes > 0); assert.equal(f.children.length, 1);
});

test('real child enforced denial performs no observation and publishes no artifact receipts', { timeout: 20000 }, async t => {
  const f = await fixture(t, { enforced: true });
  await assert.rejects(f.run(), { code: 'AUDIT_WORKER_GRAPH_FAILED' });
  assert.equal(f.admissions.length, 1); assert.equal(f.admissions[0].action, 'block');
  assert.equal(f.requests.length, 2);
  const transcript = JSON.stringify(f.requests[1].messages);
  assert.match(transcript, /acl|denied|block/i);
  assert.doesNotMatch(transcript, /source_manifest|BEGIN EVENT LOG/);
  for (const name of ['messages', 'traces', 'effects']) await assert.rejects(fs.stat(path.join(f.spool.directory, `${name}.json`)), { code: 'ENOENT' });
});

test('host rejects forged child policy receipt even with internally consistent artifact digest', { timeout: 20000 }, async t => {
  const f = await fixture(t, { forged: true });
  await assert.rejects(f.run(), { code: 'AUDIT_POLICY_TRACE_INVALID' });
  assert.equal(f.admissions.length, 1); assert.equal(f.requests.length, 2);
  const rows = JSON.parse(await fs.readFile(path.join(f.spool.directory, 'traces.json')));
  assert.equal(JSON.parse(rows.find(row => row.kind === 'policy_decision').params_json).admission.policyVersion, '999');
  assert.equal(f.admissions[0].policyVersion, '2');
});
