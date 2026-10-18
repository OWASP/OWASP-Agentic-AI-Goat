'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAttemptFence,projection}=require('../server/services/csrfEmailMode');
test('null canonical mode remains null while fixed coverage spans the workshop',()=>{assert.equal(projection(null).mode,null);assert.equal(projection(null).effectiveMode,'vuln');assert.deepEqual(projection('fixed').fixedObjectiveIds,require('../server/services/csrfVictimSandbox').ALL_OBJECTIVES);assert.throws(()=>projection('other'));});
test('exact admitted session and canonical mode stamp checked across each boundary',async()=>{
 const attempt={userId:7,mode:null,modeStamp:'default',generation:0};let scope={...attempt},currentSession='17';const execution={check:async()=>{}};
 const check=createAttemptFence({attempt,execution,platformSessionId:'17',progress:{getEvaluationScope:async()=>scope},checkSession:async()=>{if(currentSession!=='17')throw Object.assign(Error('revoked or replaced'),{code:'SESSION_REVOKED'});}});
 await check();currentSession='18';await assert.rejects(check(),{code:'SESSION_REVOKED'});currentSession='17';scope={...attempt,mode:'vuln',modeStamp:'new'};await assert.rejects(check(),{code:'MODE_MISMATCH'});scope={...attempt,generation:1};await assert.rejects(check(),{code:'MODE_MISMATCH'});
});
test('code-only session revocation is safe401, never mode409',()=>{const {publicScopeDenial}=require('../server/services/csrfEmailMode');assert.deepEqual(publicScopeDenial({code:'SESSION_REVOKED',message:'private'}),{status:401,body:{error:'Canonical session is no longer current.',code:'SESSION_REVOKED'}});assert.equal(publicScopeDenial({code:'MODE_MISMATCH'}).status,409);assert.equal(publicScopeDenial(Error('private')),null);});
