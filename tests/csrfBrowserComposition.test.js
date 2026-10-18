'use strict';
process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { createCsrfBrowserExecutor } = require('../server/services/csrfBrowserExecutor');
const { createCsrfBrowserWorkflow } = require('../server/services/csrfBrowserWorkflow');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { getOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { createCsrfObjectiveGrader } = require('../server/services/csrfObjectiveGrader');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const { CsrfVictimSandbox } = require('../server/services/csrfVictimSandbox');
const victimOrigin = 'http://victim.lab.invalid';
const attackerOrigin = 'http://attacker.lab.invalid';
const victimPath = '/api/workshop/csrf/agent-action';

test('browser, private attempt and parser compose under one owner execution with real sandbox delta', { timeout: 60000 }, async t => {
  const executor = createCsrfBrowserExecutor({ attackerOrigin, victimOrigin, victimPath });
  t.after(() => executor.close());
  const liveJudge = process.env.CSRF_LIVE_JUDGE === '1' ? createCsrfObjectiveGrader({ postgres: false,
    judge: createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama', model: 'llama3.1:8b', baseURL: 'http://localhost:11434' }) }) }) : null;
  const runs = createRunCoordinator({ family: 'CSRF', ledger: null });
  const sandbox = new CsrfVictimSandbox(`owned-browser-${randomBytes(8).toString('hex')}`);
  for (const vector of ['direct_get', 'direct_post', 'fetch']) for (const defended of [false, true]) {
    const tab = vector === 'direct_get' ? 'get' : 'post';
    const objectiveId = tab === 'get' ? (defended ? 'csrf_g3' : 'csrf_g2') : defended ? 'csrf_p3' : vector === 'fetch' ? 'csrf_p2' : 'csrf_p1';
    sandbox.setDefenses(tab, defended);
    const before = sandbox.tab(tab).victim.account.balance;
    const marker = randomBytes(12).toString('hex');
    let html = `<form method="POST" action="${victimOrigin}${victimPath}"><input name="tab" value="post"><input name="message" value="${marker}"></form><script>document.forms[0].submit()</script>`;
    if (vector === 'direct_get') html = `<img src="${victimOrigin}${victimPath}?tab=get&message=${marker}">`;
    if (vector === 'fetch') html = `<script>fetch('${victimOrigin}${victimPath}',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({tab:'post',message:'${marker}'})})</script>`;
    let effects = 0;
    await runs.run('17', {}, async execution => {
      const actionHandlerDeps = {
        getUserKey: req => String(req.user.id), getUserId: req => req.user.id,
        sessionIdFor: () => 'owned-browser', victimSandbox: { VECTORS: { [vector]: { crossSite: true } }, getOrCreateSandbox: () => sandbox },
        tabOf: req => req.query.tab || req.body.tab,
        detectForgedVector: () => vector,
        csrfAgent: { chat: async (_session, tab, message) => {
          assert.equal(getOwnerExecution().runId, execution.runId);
          assert.equal(message, marker, 'exact raw payload instruction reached production handler');
          await execution.check(); effects++;
          // Actor is an explicit fixture; handler and transport are production code.
          const result = sandbox.forge(tab, vector, 'transfer', { amount: 10 });
          return { toolResult: result, objectivesHit: [objectiveId], response: result.outcome, victimState: sandbox.getTabState(tab) };
        } },
        recordActivity: async owner => assert.equal(owner, '17'), getCompleted: async () => new Set(),
        creditObjective: async () => false, pushCsrfEvent: owner => assert.equal(owner, '17'),
        syncWorkshopStarted: async userId => assert.equal(userId, 17),
      };
      let grades = 0;
      const workflow = createCsrfBrowserWorkflow({ executor });
      const result = await workflow.run({ execution, userId: 17, tab,
        objectiveId, html,
        attackerOrigin, victimOrigin, victimPath, actionHandlerDeps,
        victimCookie: { name: 'owned_victim', value: randomBytes(24).toString('hex') },
        finalGrade: async packet => {
          await packet.check(); grades++;
          assert.equal(packet.activity.result.blocked, defended);
          assert.equal(packet.responseStatus, defended ? 403 : 200);
          if (!liveJudge) return { completed: false }; // No LLM/DB credit in default fixture.
          const result = await liveJudge.evaluate({ userId: 17, objectiveId: packet.objectiveId,
            execution: packet.execution, snapshot: {}, activity: packet.activity,
            receipt: packet.receipt });
          assert.equal(result.completed, true, JSON.stringify(result.judgment));
          return result;
        } });
      assert.equal(result.browser.responseStatus, defended ? 403 : 200);
      assert.equal(result.browser.responseObserved, true);
      assert.equal(result.graded, true);
      assert.equal(grades, 1);
      assert.equal(effects, defended ? 0 : 1);
    });
    assert.equal(sandbox.tab(tab).victim.account.balance, before - (defended ? 0 : 10));
  }
});
