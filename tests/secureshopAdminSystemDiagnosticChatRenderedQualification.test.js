'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {assertPrivateReceipt,FLAGS,SCOPE,diagnosticDependencies}=require('./postgres/secureshopAdminSystemDiagnosticChatRendered.integration.test');

const valid=()=>Object.fromEntries([
  ...FLAGS.map(key=>[key,true]),['scope',SCOPE],['actorCalls',4],['roleTurns',2],
  ['judgeCalls',0],['executorCalls',1],['errors',[]],
]);

test('rendered diagnostic chat receipt requires both model turns, one executor effect, and no Judge',()=>{
  assert.doesNotThrow(()=>assertPrivateReceipt(valid()));
  for(const [key,value] of [['actorCalls',3],['actorCalls',15],['roleTurns',1],
    ['judgeCalls',1],['executorCalls',0],['executorCalls',2],
    ['physicalFixedDenial',false],['lostAckExactGetRecovery',false],
    ['noObjectiveCredit',false]]) {
    assert.throws(()=>assertPrivateReceipt({...valid(),[key]:value}),key);
  }
  assert.throws(()=>assertPrivateReceipt({...valid(),invented:true}));
});

test('diagnostic composition takes the exact prepared grading, audit, client, and mode authority',()=>{
  const client={},grading={},agentsPool={},composition={personaAuth:{authenticatePersona(){}}},
    reset={audit:{agents:{}}},modeAuthority={};
  const value=diagnosticDependencies({client,grading,agentsPool,composition,reset,modeAuthority});
  assert.deepEqual(Object.keys(value).sort(),['systemDiagnosticClient','preparedGrading',
    'agentsPool','audit','authenticatePersona','modeAuthority'].sort());
  assert.equal(value.systemDiagnosticClient,client);
  assert.equal(value.modeAuthority,modeAuthority);
  assert.equal(value.audit,reset.audit.agents);
});
