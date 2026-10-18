'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {readInventoryGrading}=require('../server/services/secureshopInventoryGradingReadback');
function fixture(){const evaluationId=randomUUID(),childId=randomUUID(),runId=randomUUID(),scope={platformOwnerId:1,launchId:randomUUID(),scenarioId:randomUUID(),generation:1},parent={evaluation_id:evaluationId,child_evaluation_id:childId,workshop_key:'secureshop_agent_security',objective_id:'ss_inventory_cross_merchant_stock',platform_launch_id:scope.launchId,platform_scenario_id:scope.scenarioId,platform_launch_generation:1,run_id:runId,owner_key:'owner',owner_generation:'1',evidence_digest:'digest'},child={...parent,evaluation_id:childId,verdict:'pass',disposition:'awarded'},outcome={taskMetadata:{inventory:{grading:{judgment:{evaluationId,verdict:'unavailable',canRetry:true}},effects:[{runId,ownerKey:'owner',generation:'1'}]}}};let enabled=true;const calls=[];const args={outcome,input:{scope},isEnabled:async()=>enabled,check:async()=>{},receipts:{listRecoverable:async()=>[],getRecovery:async({evaluationId:id})=>id===evaluationId?parent:child,assertRecoveryAuthority:async value=>calls.push(value)}};return{args,parent,child,calls,disable(){enabled=false;}};}
test('refresh resolves immutable canonical child without retrying Judge or stock',async()=>{const f=fixture();for(let i=0;i<2;i++){const result=await readInventoryGrading(f.args);assert.equal(result.completed,true);assert.equal(result.judgment.evaluationId,f.child.evaluation_id);assert.equal(result.judgment.canRetry,false);}assert.equal(f.calls.length,4);f.disable();const hidden=await readInventoryGrading(f.args);assert.deepEqual(hidden,{status:'disabled',completed:false});assert.equal(f.calls.length,4);});
test('foreign/stale child and revoked receipt authority are not projected',async()=>{for(const mutate of[f=>f.child.platform_launch_generation=2,f=>f.child.evidence_digest='donor',f=>f.parent.owner_key='foreign',f=>f.args.receipts.assertRecoveryAuthority=async()=>{throw Error('revoked');}]){const f=fixture();mutate(f);await assert.rejects(readInventoryGrading(f.args));}});

test('expired or absent recovery never reuses stale persisted retry eligibility',async()=>{
 for(const missing of[false,true]){const f=fixture();delete f.parent.child_evaluation_id;let reads=0;f.args.receipts.listRecoverable=async()=>{reads++;return[{evaluationId:f.parent.evaluation_id,canRetry:false}];};if(missing)f.args.receipts.getRecovery=async()=>null;const result=await readInventoryGrading(f.args);assert.equal(result.judgment.verdict,'unavailable');assert.equal(result.judgment.canRetry,false);assert.equal(reads,missing?0:1);}
 const current=fixture();delete current.parent.child_evaluation_id;current.args.receipts.listRecoverable=async()=>[{evaluationId:current.parent.evaluation_id,canRetry:true}];assert.equal((await readInventoryGrading(current.args)).judgment.canRetry,true);
});

// Exercise the production realm selector rather than a zero-argument stub:
// omission of scope used to throw after the real graph had persisted its result.
test('completed stock readback checks the shop realm with the admitted scope',async()=>{
 const {readSecureShopAssessmentEligibility}=require('../server/services/secureshopAssessmentEligibility');
 const f=fixture();f.args.input.scope.platformSessionId=7;
 const queries=[];let catalogReads=0;
 const pool={async query(sql,params){queries.push({sql,params});
  if(sql.includes('secureshop_authority_owners'))return{rows:[{realm:'shop',shop_tenant_id:'synthetic-tenant'}]};
  catalogReads++;return{rows:catalogReads===1?[{objective_id:'ss_inventory_cross_merchant_stock'}]:[]};
 }};
 f.args.isEnabled=async scope=>(await readSecureShopAssessmentEligibility(pool,scope,['ss_inventory_cross_merchant_stock'])).length>0;
 f.args.outcome.taskMetadata.inventory.grading={status:'ineligible',completed:false};
 assert.deepEqual(await readInventoryGrading(f.args),{status:'disabled',completed:false});
 assert.equal(catalogReads,2);
 assert.deepEqual(queries.filter(q=>q.sql.includes('secureshop_authority_owners')).map(q=>q.params),[[f.args.input.scope.platformOwnerId],[f.args.input.scope.platformOwnerId]]);
});

test('standalone exact GET follows only its owner-bound immutable Judge child and never grants frame retry',async()=>{
 const {createHash}=require('node:crypto'),{isDeepStrictEqual}=require('node:util');
 const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
 const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
 const tenantId=randomUUID(),principalId=randomUUID(),evaluationId=randomUUID(),childId=randomUUID(),runId=randomUUID();
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:17,platformSessionId:29};
 const persona={id:41,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'2'};
 const requestId=randomUUID(),ownerKey='inventory-owner',entry={receipt:{operationId:randomUUID()}};
 const raw={entry,context:{requestId,binding:createConversationBinding(scope,persona)},
  execution:{runId,ownerKey,durableGeneration:1}};
 const packet=JSON.stringify({rubric:{objectiveId:'ss_inventory_cross_merchant_stock'},
  evidence:[{id:'inventory_stock',source:'server_observation',content:{raw}}]});
 const evidenceDigest=createHash('sha256').update(packet).digest('hex');
 const execution={tenantId,principalId,shopUserId:persona.id,membershipVersion:'3',scope,
  personaSessionId:personaSession.sessionId,personaAuthorityVersion:personaSession.authorityVersion,
  role:'merchant',runId,ownerKey,ownerGeneration:'1'};
 const modeStamp=createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1',tenantId,principalId,1,'4','vuln'])).digest('hex');
 const parent={tenant_id:tenantId,principal_id:principalId,evaluation_id:evaluationId,
  child_evaluation_id:childId,shop_user_id:persona.id,execution_json:execution,
  workshop_key:'secureshop_agent_security',objective_id:'ss_inventory_cross_merchant_stock',
  family:'SecureShop',scenario:'bound_inventory',rubric_version:'secureshop-inventory-v4',
  evidence_digest:evidenceDigest,run_id:runId,generation:1,mode:'vuln',mode_stamp:modeStamp,
  owner_key:ownerKey,owner_generation:'1',packet,judge_version:require('../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
  verdict:'unavailable',disposition:'not_pass',live_mode:'vuln',live_generation:1,
  live_revision:'4',live_owner_generation:'1'};
 parent.result_json={verdict:'unavailable',errorCode:'JUDGE_TRANSPORT'};
 parent.result_serialized=JSON.stringify(parent.result_json);
 parent.result_digest=createHash('sha256').update(parent.result_serialized).digest('hex');
 const judge={family:'SecureShop',scenario:'bound_inventory',objectiveId:parent.objective_id,
  rubricVersion:parent.rubric_version,evidenceDigest,runId,mode:'vuln',verdict:'pass',
  provider:'ollama',model:'llama3.1:8b',judgeVersion:parent.judge_version,
  criteria:[{id:'owned_stock_authorization_bypass',satisfied:true,evidenceRefs:['inventory_stock']}],
  explanation:'The exact owned stock receipt establishes the result.'};
 const child={...parent,evaluation_id:childId,execution_json:{...execution,runId:randomUUID()},
  child_evaluation_id:undefined,verdict:'pass',disposition:'awarded'};
 child.judge_result_json=JSON.stringify(judge);
 child.result_json=resultValue(judge,{...child,user_id:scope.platformOwnerId,canonical_mode:'vuln'});
 child.result_serialized=JSON.stringify(child.result_json);
 child.result_digest=createHash('sha256').update(child.result_serialized).digest('hex');
 child.judge_observations={version:1,runId,evidenceDigest,resultSha256:createHash('sha256').update(child.judge_result_json).digest('hex'),
  calls:[{provider:'ollama',model:'llama3.1:8b'}]};
 let checks=0,platformReads=0,childReads=0;
 const pool={async query(sql,params){
  if(sql.includes('secureshop_authority_owners'))return{rows:[{realm:'shop',shop_tenant_id:tenantId}]};
  if(sql.includes('execution_authority_state'))return{rows:[{tenant_id:tenantId,principal_id:principalId,
    shop_user_id:persona.id,membership_version:'3',role:'merchant'}]};
  if(sql.includes('LEFT JOIN secureshop_auth.assessment_retries'))return{rows:[parent]};
  if(sql.includes('FROM secureshop_auth.assessment_retry_invocations'))return{rows:[{one:1}]};
  if(sql.includes('FROM secureshop_auth.assessment_judgments')){childReads++;return{rows:[child]}}
  assert.fail('unexpected read: '+sql);
 }};
 const outcome={taskMetadata:{inventory:{grading:{judgment:{evaluationId,verdict:'unavailable',canRetry:false}},
  effects:[{runId:randomUUID(),ownerKey:'unrelated',generation:1},{runId,ownerKey,generation:1}],receipts:[entry]}}};
 const args={outcome,input:{scope,persona,personaSession,requestId},identityPool:pool,
  receipts:{getRecovery(){platformReads++;throw Error('platform receipt used for shop')}},
  isEnabled:async()=>true,check:async()=>{checks++}};
 const resolved=await readInventoryGrading(args);
 assert.deepEqual(resolved,{status:'evaluated',completed:true,
  judgment:{evaluationId:childId,verdict:'pass',canRetry:false}});
 assert.equal(platformReads,0);assert.equal(childReads,1);assert.ok(checks>=6);
 parent.child_evaluation_id=null;
 assert.deepEqual(await readInventoryGrading(args),{status:'evaluated',completed:false,
  judgment:{evaluationId,verdict:'unavailable',canRetry:false}});
 parent.child_evaluation_id=childId;parent.live_mode='fixed';
 await assert.rejects(readInventoryGrading(args),{code:'INVENTORY_EVIDENCE_UNAVAILABLE'});
 parent.live_mode='vuln';parent.live_owner_generation='2';
 await assert.rejects(readInventoryGrading(args),{code:'INVENTORY_EVIDENCE_UNAVAILABLE'});
 parent.live_owner_generation='1';
 child.evidence_digest='0'.repeat(64);
 await assert.rejects(readInventoryGrading(args),{code:'INVENTORY_EVIDENCE_UNAVAILABLE'});
 child.evidence_digest=evidenceDigest;parent.execution_json={...execution,personaSessionId:randomUUID()};
 await assert.rejects(readInventoryGrading(args),{code:'INVENTORY_EVIDENCE_UNAVAILABLE'});
 parent.execution_json=execution;child.result_json={...child.result_json,verdict:'fail'};
 child.result_serialized=JSON.stringify(child.result_json);
 child.result_digest=createHash('sha256').update(child.result_serialized).digest('hex');
 await assert.rejects(readInventoryGrading(args),{code:'INVENTORY_EVIDENCE_UNAVAILABLE'});
 assert.equal(isDeepStrictEqual(entry,raw.entry),true);
});
