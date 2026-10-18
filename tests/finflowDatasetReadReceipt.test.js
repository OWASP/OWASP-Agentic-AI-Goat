'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { issue, failureText, issueFailure, verifyFailure } = require('../server/services/finflowDatasetReadReceipt');
test('missing-account authority binds actual dataset absence and exact diagnostics to execution', () => {
 const execution = { ownerId:'1',durableGeneration:'2',runId:'run-1' };
 const dataset = {ownerId:1,generation:2,revision:3,deleted:false,records:[{id:'FF-001'}]};
 const read = issue({execution,dataset});
 const args = {receipt:read,execution,accountId:'FF-999',result:failureText(3)};
 const witness = issueFailure(args);
 assert.ok(witness);
 assert.equal(verifyFailure({...args,receipt:witness}),witness);
 for (const delta of [{receipt:{...read}},{accountId:'FF-001'},{result:args.result+' forged'},
  {execution:{...execution}},{accountId:' FF-999'}]) assert.equal(issueFailure({...args,...delta}),null);
 for (const delta of [{receipt:{...witness}},{accountId:'FF-998'},{result:args.result+' forged'},
  {execution:{...execution}}]) assert.equal(verifyFailure({...args,receipt:witness,...delta}),null);
 dataset.records.length=0;
 assert.equal(issueFailure({...args,accountId:'FF-001'}),null);
 assert.equal(issue({execution:{...execution,ownerId:'2'},dataset}),null);
});

test('Judge packet admits only verified missing-account calls and keeps fixed mode non-credit', () => {
 const { buildFinflowJudgeInputs } = require('../server/services/sensitiveInfoWorkshopAgent');
 const execution={ownerId:'1',durableGeneration:'2',runId:'judge-run'};
 const read=issue({execution,dataset:{ownerId:1,generation:2,revision:4,deleted:false,records:[]}});
 const result=failureText(4),accountId='MISSING';
 const lookupReceipt=issueFailure({receipt:read,execution,accountId,result});
 const call={name:'get_account_info',params:{account_id:accountId},success:false,result,lookupReceipt};
 const packet=(calls,mode='vulnerable')=>buildFinflowJudgeInputs('Inspect this account',calls,'Reported lookup failure.',
  {execution,mode,activeObjectiveId:'error_leak'}).find(p=>p.rubric.objectiveId==='error_leak');
 const good=packet([call,{...call,lookupReceipt:null,result:'Stack: fabricated /var/app/source.js'}]);
 assert.equal(good.facts.required_observation,true);
 assert.equal(good.facts.trusted_missing_account_lookup,true);
 assert.equal(good.rubric.version,'finflow-structured-v9');
 assert.deepEqual(good.evidence.filter(e=>e.source==='tool_result').map(e=>e.id),['tool_0']);
 assert.equal(good.evidence.find(e=>e.id==='lookup_diagnostic_1').content.eligibleForContentCriterion,false);
 for(const delta of [{lookupReceipt:{...lookupReceipt}},{result:result+' fake'},
  {params:{account_id:'OTHER'}},{success:true}])assert.equal(packet([{...call,...delta}]).facts.required_observation,false);
 assert.equal(packet([call],'fixed').facts.vulnerable_mode,false);
});

test('actual resource read and account tool produce lookup authority; fixed and existing accounts do not', async t => {
 const {createDurableAgentFixture,execution:makeExecution}=require('./helpers/finflowDurableAgentFixture');
 const {executeVaultCorpTool,createSensitiveInfoWorkshopStateStore,buildFinflowJudgeInputs}=require('../server/services/sensitiveInfoWorkshopAgent');
 const fixture=createDurableAgentFixture(t),execution=makeExecution(31);
 const store=createSensitiveInfoWorkshopStateStore({durableResources:fixture.resources});
 const state=store.getUserState('31');
 const params={account_id:'ABSENT'};
 const result=await executeVaultCorpTool('get_account_info',params,'vulnerable',state,execution);
 assert.equal(result.success,false);
 assert.ok(result.lookupReceipt);
 assert.equal(result.result,failureText(0));
 const packet=buildFinflowJudgeInputs('Inspect account',[{name:'get_account_info',params,...result}],result.result,
  {execution,activeObjectiveId:'error_leak'}).find(p=>p.rubric.objectiveId==='error_leak');
 assert.equal(packet.facts.trusted_missing_account_lookup,true);
 const existing=await executeVaultCorpTool('get_account_info',{account_id:'FF-001'},'vulnerable',state,execution);
 assert.equal(existing.success,true);assert.equal(existing.lookupReceipt,undefined);
 const body=JSON.parse(existing.result);assert.equal(body.dataset_revision,0);assert.equal(body.internal_operation,'read_customer_dataset');assert.equal(body.data_source,'owner-scoped durable customer dataset');assert.equal(body.internal_path,undefined);assert.equal(body.version,'v2.3.1');
 const safe=JSON.parse((await executeVaultCorpTool('get_account_info',{account_id:'FF-001'},'fixed',state,execution)).result);
 for(const field of ['internal_operation','dataset_revision','data_source','internal_path','version','email'])assert.equal(safe[field],undefined);
 const fixed=await executeVaultCorpTool('get_account_info',params,'fixed',state,execution);
 assert.equal(fixed.lookupReceipt,undefined);
 const sibling=makeExecution(32);
 assert.equal(verifyFailure({receipt:result.lookupReceipt,execution:sibling,accountId:'ABSENT',result:result.result}),null);
});

test('verified lookup still requires a semantic Judge verdict', async () => {
 const {buildFinflowJudgeInputs}=require('../server/services/sensitiveInfoWorkshopAgent');
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const execution={ownerId:'1',durableGeneration:'2',runId:'semantic-run'};
 const read=issue({execution,dataset:{ownerId:1,generation:2,revision:5,records:[]}});
 const result=failureText(5),accountId='MISSING';
 const lookupReceipt=issueFailure({receipt:read,execution,accountId,result});
 const packet=buildFinflowJudgeInputs('Look up MISSING',[{name:'get_account_info',params:{account_id:accountId},success:false,result,lookupReceipt}],result,
  {execution,activeObjectiveId:'error_leak'}).find(p=>p.rubric.objectiveId==='error_leak');
 for(const satisfied of [false,true]) {
  let calls=0;
  const judge=createObjectiveJudge({model:{generate:async()=>{calls++;return {provider:'fixture',model:'explicit-test-double',response:JSON.stringify({verdict:satisfied?'pass':'fail',explanation:'Controlled diagnostic criterion evaluated.',criteria:[{id:'internal_details_disclosed',satisfied,evidenceRefs:['tool_0']}]})};}}});
  assert.equal((await judge(packet)).verdict,satisfied?'pass':'fail');assert.equal(calls,1);
 }
});

test('actual LangGraph loop retains missing-account evidence for the completion service', async t => {
 const {createDurableAgentFixture}=require('./helpers/finflowDurableAgentFixture');
 const {SensitiveInfoWorkshopAgent,createSensitiveInfoWorkshopStateStore}=require('../server/services/sensitiveInfoWorkshopAgent');
 const fixture=createDurableAgentFixture(t);let decisions=0,observed;
 const ledger={begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},effect:async(_ctx,_key,work)=>work()};
 const completion={beginAttempt:async packet=>({execution:packet.execution}),evaluate:async packet=>{
  observed=packet;return {judgment:{verdict:'fail',objectiveId:packet.rubric.objectiveId},completed:false};}};
 const agent=new SensitiveInfoWorkshopAgent({stateStore:createSensitiveInfoWorkshopStateStore({durableResources:fixture.resources}),runLedger:ledger,completionService:completion,
  model:{provider:'fixture',generateResponse:async prompt=>({provider:'fixture',model:'explicit-test-double',response:prompt.startsWith('Select exactly')
   ?JSON.stringify(++decisions===1?{action:'get_account_info',params:{account_id:'MISSING'}}:{action:'general_chat',params:{}}):'The lookup failed.'})}});
 const result=await agent.processMessage('Look up MISSING.',[],'vulnerable','error_leak','101');
 assert.ok(result.toolCalls.find(call=>call.name==='get_account_info').lookupReceipt);
 assert.equal(observed.rubric.version,'finflow-structured-v9');
 assert.equal(observed.facts.trusted_missing_account_lookup,true);
 assert.deepEqual(result.completedObjectiveIds,[]);
});
