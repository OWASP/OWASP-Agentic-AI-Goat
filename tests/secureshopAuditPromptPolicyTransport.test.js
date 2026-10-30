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

async function fixture(t, { enforced = false, forged = false, promptPolicySnapshot }  = {}) {
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
      ? [args[0], path.join(__dirname, 'fixtures/secureshopAuditForgedPromptPolicyChild.js')] : args, options);
    children.push(child); return child;
  };
  const hostPath = require.resolve('../server/services/secureshopAuditWorkerHost');
  delete require.cache[hostPath];
  let run; try { run = require(hostPath).runSecureShopAuditWorker; } finally { cp.spawn = originalSpawn; delete require.cache[hostPath]; }
  return { spool, requests, admissions, children, run: () => run({ spool,
    baseUrl: `http://127.0.0.1:${server.address().port}`, model: 'controlled-transport',
    promptPolicySnapshot, persona: { id: 3, role: 'admin' }, checkCurrent: async () => {}, timeoutMs: 15000,
    admitTool: async input => {
      assert.ok(Object.isFrozen(input.args)); assert.deepEqual(input.args, { limit: 1 });
      assert.equal(input.runId, spool.manifest.runId);
      const receipt = { admissionId: randomUUID(), runId: input.runId, invocationId: input.invocationId,
        toolKey: 'audit.summarize_anomalies', policyVersion: '2', registrySha256: 'a'.repeat(64),
        enforcement: enforced, allowed: false, action: enforced ? 'block' : 'dispatch', policyViolation: 'denied-by-acl' };
      admissions.push(receipt); return receipt;
    } }) };
}


const {buildPolicySnapshot}=require('../server/services/secureshopPromptPolicySnapshot');
function snapshot(role='admin') {const rendered='CONTROLLED IMMUTABLE POLICY '+ 'x'.repeat(32768);return buildPolicySnapshot({policyVersion:'7',role,policies:[{name:'owned-policy',rendered,renderedSha256:require('node:crypto').createHash('sha256').update(rendered).digest('hex'),targets:[role]}]});}
test('actual child transports >16KiB immutable snapshot into controlled provider input and host verifies trace', {timeout:20000},async t=>{
 const admitted=snapshot(),f=await fixture(t,{promptPolicySnapshot:admitted});const result=await f.run();
 assert.equal(result.objectiveCredit,false);assert.equal(f.requests.length,2);
 assert.ok(JSON.stringify(f.requests[0].messages).includes(admitted.policies[0].rendered));
 const rows=JSON.parse(await fs.readFile(path.join(f.spool.directory,'traces.json'))),policy=rows.filter(r=>r.kind==='prompt_policy_snapshot');
 assert.equal(policy.length,1);assert.deepEqual(JSON.parse(policy[0].result_json),{policyVersion:'7',sha256:admitted.sha256,role:'admin',policyCount:1});
});
test('host rejects forged snapshot receipt despite internally consistent artifact digest',{timeout:20000},async t=>{
 const f=await fixture(t,{promptPolicySnapshot:snapshot(),forged:true});await assert.rejects(f.run(),{code:'AUDIT_PROMPT_POLICY_TRACE_INVALID'});assert.equal(f.children.length,1);
});
test('nonadmin or tampered parent snapshots fail before spawning or provider calls',async t=>{
 for(const value of [snapshot('customer'),{...snapshot(),sha256:'0'.repeat(64)}]){const f=await fixture(t,{promptPolicySnapshot:value});await assert.rejects(f.run());assert.equal(f.children.length,0);assert.equal(f.requests.length,0);}
});
