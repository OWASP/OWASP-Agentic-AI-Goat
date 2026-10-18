'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createCsrfObjectiveGrader } = require('../server/services/csrfObjectiveGrader');
const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { issueCsrfBrowserReceipt } = require('../server/services/csrfBrowserReceipt');
for (const objectiveId of ['csrf_g3', 'csrf_p3']) for (const mode of ['vuln', 'fixed', null]) {
  test(`${objectiveId} uses captured canonical ${mode} mode independently of token defense`, async () => {
    let stamp = 'before', calls = 0, captured;
    const execution = {runId:randomUUID(),ownerKey:'["CSRF","7"]',generation:0,check:async()=>{}};
    const service = createObjectiveCompletionService({
      progress:{getGeneration:async()=>0,getEvaluationScope:async()=>({generation:0,mode,modeStamp:stamp})},
      receipts:{beginEvaluation:async scope=>{
        assert.equal(scope.expectedMode,mode);
        if(scope.expectedModeStamp!==stamp)throw Object.assign(Error('stale mode'),{code:'MODE_CHANGED'});
        assert.equal(scope.mode,mode??'vuln');
        assert.equal(scope.rubricVersion,'csrf-defense-mode-v10');
        captured=scope;return {...scope,generation:0,verdict:null};
      },recordVerdict:async ({result})=>({...captured,result,verdict:result.verdict,disposition:'awarded'})},
      judge:createObjectiveJudge({model:{generate:async()=>{calls++;return {response:JSON.stringify({verdict:'pass',explanation:'Enabled token defense blocked this request.',criteria:[{id:'observed_outcome',satisfied:true,evidenceRefs:['action']}]}),provider:'controlled',model:'controlled'};}}})
    });
    const grader=createCsrfObjectiveGrader({postgres:true,completionService:service});
    const attempt=await grader.begin(7,execution);
    const activity={result:{blocked:true,defenses:{csrfToken:true},vector:objectiveId==='csrf_g3'?'direct_get':'direct_post',stateChanged:false}};
    const receipt=issueCsrfBrowserReceipt({execution,activity,binding:{...execution,objectiveId,tab:objectiveId==='csrf_g3'?'get':'post',payloadDigest:'a'.repeat(64)},observation:{method:objectiveId==='csrf_g3'?'GET':'POST',resourceType:objectiveId==='csrf_g3'?'image':'document',frameOrigin:'http://attacker.csrf.invalid',cookiePresent:true},responseStatus:403});
    const args={userId:7,objectiveId,execution,attempt,snapshot:{},activity,receipt};
    assert.equal((await grader.evaluate(args)).completed,true);
    assert.equal(calls,1);
    await assert.rejects(grader.evaluate({...args,attempt:{...attempt}}),{code:'ATTEMPT_SCOPE_MISMATCH'});
    stamp='changed-and-restored';
    await assert.rejects(grader.evaluate(args),{code:'MODE_CHANGED'});
    assert.equal(calls,1);
  });
}
