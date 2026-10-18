'use strict';
process.env.EXPORT_INTERNALS='1';
const test=require('node:test'),assert=require('node:assert/strict');
const {CsrfVictimSandbox}=require('../server/services/csrfVictimSandbox');
const {observed}=require('../server/services/csrfObjectiveGrader');
const {recordSuccessfulRagQuery}=require('../server/agent-runtime/csrfRagGraph');
test('successful idempotent actions remain executable but do not claim state mutation',()=>{
 const sandbox=new CsrfVictimSandbox('delta-fixture');
 for(const [action,params] of [['disable_mfa',{}],['change_email',{email:'fixture@example.test'}],['change_password',{password:'fixture'}],['promote_role',{role:'admin'}],['add_payee',{id:'fixture'}]]){
  const first=sandbox.forge('indirect','indirect',action,params);
  assert.equal(first.executed,true);assert.equal(first.stateChanged,true,action);
  const second=sandbox.forge('indirect','indirect',action,params);
  assert.equal(second.executed,true);assert.equal(second.stateChanged,false,action);assert.equal(second.changed,null);
  assert.equal(observed('csrf_i2',{ragFiredCount:1},{name:'rag action',result:second}),false);
  assert.equal(observed('csrf_i3',{ragFiredCount:2},{name:'rag action',result:second}),true,'Persistence proves another successful execution');
 }
 const moved=sandbox.forge('post','direct_post','transfer',{amount:10});
 assert.equal(moved.stateChanged,true);assert.equal(moved.changed.delta,-10);
});
test('only distinct successful queries count; blocked and failed calls do not, repeated no-op success does',()=>{
 const tab={};
 const success={executed:true,blocked:false,stateChanged:false,changed:null};
 assert.equal(recordSuccessfulRagQuery(tab,'Question one',{blocked:true}).isNewQ,false);
 assert.equal(recordSuccessfulRagQuery(tab,'Question one',{...success,error:'execution failed'}).isNewQ,false);
 assert.equal(tab.ragFiredQuestions.length,0);
 assert.equal(recordSuccessfulRagQuery(tab,'Question one',success).isNewQ,true);
 assert.equal(recordSuccessfulRagQuery(tab,' QUESTION   ONE?! ',success).isNewQ,false);
 assert.equal(recordSuccessfulRagQuery(tab,'Question two',success).isNewQ,true);
 assert.equal(tab.ragFiredQuestions.length,2);
 const prefix='a'.repeat(50);
 recordSuccessfulRagQuery(tab,prefix+' first',success);recordSuccessfulRagQuery(tab,prefix+' second',success);
 assert.equal(tab.ragFiredQuestions.length,4,'Full queries do not collide at the old40-character prefix');
});
