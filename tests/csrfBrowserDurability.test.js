'use strict';
process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createCsrfBrowserExecutor } = require('../server/services/csrfBrowserExecutor');
const { createCsrfBrowserWorkflow } = require('../server/services/csrfBrowserWorkflow');
const { runCsrfAgentGraph } = require('../server/agent-runtime/csrfAgentGraph');
const { getOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const sandboxMod = require('../server/services/csrfVictimSandbox');

test('admitted effect is persisted before delayed narration, and browser shutdown cannot grade it', { timeout: 15000 }, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-csrf-durable-effect-'));
  const stateFile = path.join(directory, 'victim.json');
  const attackerOrigin = 'http://attacker.durable.invalid', victimOrigin = 'http://victim.durable.invalid';
  const executor = createCsrfBrowserExecutor({ attackerOrigin, victimOrigin, timeoutMs: 10000 });
  t.after(async () => { await executor.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const sandbox = new sandboxMod.CsrfVictimSandbox('owned-durable-browser');
  // An owned file persistence adapter makes the ordering observable without a
  // working database. Native PostgreSQL persistence is qualified separately.
  sandbox.flush = () => fs.writeFile(stateFile, JSON.stringify(sandbox.tab('post').victim));
  const before = sandbox.tab('post').victim.account.balance;
  const controller = new AbortController();
  const execution = { ownerKey: '["CSRF","17"]', runId: 'durable-browser', generation: 0,
    signal: controller.signal, check: async () => controller.signal.throwIfAborted() };
  let reachedNarration;
  const narration = new Promise(resolve => { reachedNarration = resolve; });
  const dependencies = {
    getUserKey: req => String(req.user.id), getUserId: req => req.user.id,
    sessionIdFor: () => sandbox.sessionId, tabOf: () => 'post', detectForgedVector: () => 'direct_post',
    victimSandbox: { ...sandboxMod, getOrCreateSandbox: () => sandbox },
    csrfAgent: { chat: (sessionId, tab, message, opts) => runCsrfAgentGraph(sessionId, tab, message, opts, {
      sandboxMod: { ...sandboxMod, getOrCreateSandbox: () => sandbox }, model: { provider: 'mock' },
      detectIntent: () => ({ intent: 'attack', action: 'transfer', params: { amount: 17, to: 'fixture' } }),
      INJECTION_RE: /never-match/, GUARDED_ACTIONS: new Set(), resolveObjectives: () => ['csrf_p1'],
      phraseAttack: async () => {
        const signal = getOwnerExecution().signal;
        assert.equal(JSON.parse(await fs.readFile(stateFile, 'utf8')).account.balance, before - 17);
        reachedNarration();
        await new Promise((_resolve, reject) => {
          if (signal.aborted) return reject(signal.reason);
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
      },
    }) },
    recordActivity: async () => {}, getCompleted: async () => new Set(),
    pushCsrfEvent: () => {}, syncWorkshopStarted: async () => {},
  };
  let grades = 0;
  const work = createCsrfBrowserWorkflow({ executor }).run({ execution, userId: 17,
    objectiveId: 'csrf_p1', tab: 'post', attackerOrigin, victimOrigin,
    html: `<form method="POST" action="${victimOrigin}/api/workshop/csrf/agent-action"><input name="tab" value="post"><input name="message" value="transfer 17"></form><script>document.forms[0].submit()</script>`,
    victimCookie: { name: 'owned_victim', value: 'synthetic-only' }, actionHandlerDeps: dependencies,
    finalGrade: async () => { grades++; },
  });
  const rejected = assert.rejects(work, { code: 'CSRF_BROWSER_CLOSED' });
  await Promise.race([narration, work.then(() => { throw new Error('Expected delayed narration'); })]);
  await executor.close();
  await rejected;
  assert.equal(JSON.parse(await fs.readFile(stateFile, 'utf8')).account.balance, before - 17);
  assert.equal(grades, 0, 'persisted action alone cannot replace browser response evidence');
});
