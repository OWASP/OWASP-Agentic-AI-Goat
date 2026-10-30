'use strict';
// Read-only local inference: synthetic server observations, no inbox/network tools.
process.env.JUDGE_PROVIDER = 'ollama';
process.env.JUDGE_MODEL = 'llama3.1:8b';
const fs = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { CRITERIA, createCsrfObjectiveGrader } = require('../../server/services/csrfObjectiveGrader');
const { ATTACKER_ORIGIN, BROWSER_OBJECTIVES, issueCsrfBrowserReceipt } = require('../../server/services/csrfBrowserReceipt');
const { fixtures } = require('../fixtures/csrfJudgeCases');
(async () => {
 const grader = createCsrfObjectiveGrader({ postgres: false });
 const rows = [];
 for (const objectiveId of Object.keys(CRITERIA)) {
  for (const positive of [true, false]) {
   const [sourceActivity, sourceReceipt] = positive ? fixtures[objectiveId] : [{ result: { blocked: true, changed: {} } }, {}];
   const activity = structuredClone(sourceActivity);
   if (positive && activity?.result?.executed === true && activity.result.changed
     && Object.keys(activity.result.changed).length > 0) activity.result.stateChanged = true;
   const execution = { check: async () => {}, runId: randomUUID(), ownerKey: JSON.stringify(['CSRF', '7']), generation: 0 };
   let receipt = sourceReceipt;
   if (positive && BROWSER_OBJECTIVES.includes(objectiveId)) {
    const post = objectiveId.startsWith('csrf_p');
    receipt = issueCsrfBrowserReceipt({
     binding: { runId: execution.runId, ownerKey: execution.ownerKey, generation: execution.generation,
      objectiveId, tab: post ? 'post' : 'get', payloadDigest: createHash('sha256').update(`trusted-fixture:${objectiveId}`).digest('hex') },
     observation: { method: post ? 'POST' : 'GET', frameOrigin: ATTACKER_ORIGIN,
      resourceType: objectiveId === 'csrf_p2' ? 'fetch' : post ? 'document' : 'image', cookiePresent: true },
     responseStatus: ['csrf_g3', 'csrf_p3'].includes(objectiveId) ? 403 : 200,
     execution, activity,
    });
   }
   const result = await grader.evaluate({ userId: 7, objectiveId, execution,
    snapshot: positive ? { reconCount: 2, xssEmailRead: true, ragFiredCount: 2, defenses: { enabled: objectiveId.endsWith('3') } } : {}, activity, receipt });
   const row = { objectiveId, positive, expected: positive ? 'pass' : 'not_pass', actual: result.judgment.verdict,
    completed: result.completed,
    evidenceBoundary: BROWSER_OBJECTIVES.includes(objectiveId) && positive
     ? 'trusted private receipt fixture; no browser executed'
     : 'synthetic server observation; no browser executed',
    explanation: result.judgment.explanation, model: result.judgment.model, judgeVersion: result.judgment.judgeVersion, rubricVersion: result.judgment.rubricVersion };
   rows.push(row); console.log(JSON.stringify(row));
   fs.writeFileSync('/tmp/owasp-ai-goat-csrf-8b-results.json', JSON.stringify(rows, null, 2));
  }
 }
})().catch(error => { console.error(error); process.exitCode = 1; });
