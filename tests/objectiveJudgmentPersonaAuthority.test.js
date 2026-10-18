'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createObjectiveJudgmentRepository}=require('../server/database/postgres/objectiveJudgmentRepository');
const evaluationId=randomUUID(),runId=randomUUID();
const input={userId:7,evaluationId,workshopKey:'direct_prompt_injection',objectiveId:'jailbreak',family:'DPI',scenario:'single',rubricVersion:'v1',evidenceDigest:'a'.repeat(64),runId,mode:'vuln'};
const row=marker=>({user_id:7,evaluation_id:evaluationId,workshop_key:input.workshopKey,objective_id:input.objectiveId,family:'DPI',scenario:'single',rubric_version:'v1',evidence_digest:input.evidenceDigest,run_id:runId,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:'pending',...(marker===undefined?{}:{persona_authority_required:marker})});
function fixture(marker,adapter){const events=[];const query=async(sql)=>{events.push(sql);if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:input.workshopKey,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:0}]};if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[]};if(sql.includes('FROM workshop_platform.objective_judgments'))return{rows:[row(marker)]};return{rows:[],rowCount:1};};return{events,repo:createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})},{...(adapter?{personaBindings:adapter}:{})})};}
test('required receipts reject absent resolver at initial replay, retry, verdict and recovery',async()=>{const f=fixture(true);for(const work of [()=>f.repo.beginEvaluation(input),()=>f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),()=>f.repo.recordVerdict({userId:7,evaluationId,result:{}}),()=>f.repo.assertRecoveryAuthority({userId:7,evaluationId})])await assert.rejects(work(),{code:'GRADE_STORE_NOT_READY'});assert.ok(!f.events.some(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')));});
test('old schema and grandfathered rows retain unbound recovery without candidate SQL',async()=>{for(const marker of [undefined,false]){const f=fixture(marker);assert.equal(await f.repo.assertRecoveryAuthority({userId:7,evaluationId}),null);await f.repo.beginEvaluation({...input,personaAuthorityRequired:true});assert.ok(!f.events.some(sql=>sql.includes('persona_evaluation_bindings')||sql.includes('persona_authority_required')));}});
test('required recovery returns frozen current-check closure and never private binding data',async()=>{let checks=0;const adapter={initial(){},inherit(){},commit(){},projectRecoverable(){},async check(){checks++;}};const f=fixture(true,adapter),guard=await f.repo.assertRecoveryAuthority({userId:7,evaluationId});assert.ok(Object.isFrozen(guard));assert.deepEqual(Object.keys(guard),['check']);await guard.check();assert.equal(checks,2);});
test('trusted token with missing adapter rejects before transaction',async()=>{const f=fixture(undefined);assert.throws(()=>f.repo.beginEvaluation(input,{}),{code:'GRADE_STORE_NOT_READY'});assert.equal(f.events.length,0);});

test('mixed recoveries preserve grandfathered eligibility when bound projection fails',async()=>{
 const requiredId=randomUUID(),oldId=randomUUID(),malformedId=randomUUID();
 const eligible={...row(false),verdict:'unavailable',has_packet:true,expires_at:new Date(Date.now()+60000),judge_version:'v1',owner_generation:'0',live_owner_generation:'0',xss_binding_current:true,live_generation:0,live_mode:'vuln',is_visible:true,exercise_active:true,is_enabled:true,objective_active:true};
 const rows=[{...eligible,evaluation_id:oldId},{...eligible,evaluation_id:requiredId,persona_authority_required:true},{...eligible,evaluation_id:malformedId,persona_authority_required:'true'}];
 let seen;const adapter={initial(){},inherit(){},commit(){},check(){},async projectRecoverable(input){seen=input;throw Error('authority unavailable');}};
 const repo=createObjectiveJudgmentRepository({query:async()=>({rows}),connect(){}},{personaBindings:adapter});
 const result=await repo.listRecoverable({userId:7,judgeVersion:'v1'});
 assert.deepEqual(seen.rows.map(row=>row.evaluationId),[requiredId]);assert.equal(seen.userId,7);
 assert.deepEqual(result.map(row=>row.canRetry),[true,false,false]);
 assert.deepEqual(result.map(row=>row.evaluationId),[oldId,requiredId,malformedId]);
 assert.ok(result.every(row=>!Object.hasOwn(row,'persona_authority_required')&&!Object.hasOwn(row,'userId')));
});

test('grandfathered verdict and retry do not invoke unavailable candidate adapter',async()=>{
 let calls=0;const unavailable=async()=>{calls++;throw Error('candidate unavailable');};
 const adapter={initial:unavailable,inherit:unavailable,commit:unavailable,check:unavailable,projectRecoverable:unavailable};
 const f=fixture(false,adapter);
 await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId,result:{}}),{code:'JUDGMENT_SCOPE_MISMATCH'});
 await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:'0'}));
 assert.equal(calls,0);assert.ok(f.events.includes('BEGIN'));assert.ok(!f.events.some(sql=>sql.includes('set_config')));
});
test('targeted recovery filters by exact owner/evaluation before recent20 limit',async()=>{
 const oldId=randomUUID(),all=Array.from({length:25},(_,i)=>({...row(false),evaluation_id:i===24?oldId:randomUUID(),verdict:'unavailable',has_packet:true,expires_at:new Date(Date.now()+60000),judge_version:'v1',owner_generation:'0',live_owner_generation:'0',xss_binding_current:true,live_generation:0,live_mode:'vuln',is_visible:true,exercise_active:true,is_enabled:true,objective_active:true}));let queries=0;
 const repo=createObjectiveJudgmentRepository({async query(sql,args){queries++;assert.match(sql,/WHERE j.user_id=\$1 AND \(\$2::uuid IS NULL OR j.evaluation_id=\$2::uuid\).*LIMIT 20/s);return{rows:all.filter(row=>row.user_id===args[0]&&(args[1]===null||row.evaluation_id===args[1])).slice(0,20)};}});
 assert.equal((await repo.listRecoverable({userId:7,judgeVersion:'v1'})).length,20);const result=await repo.listRecoverable({userId:7,judgeVersion:'v1',evaluationId:oldId});assert.equal(result.length,1);assert.equal(result[0].evaluationId,oldId);assert.equal(result[0].canRetry,true);assert.deepEqual(await repo.listRecoverable({userId:8,judgeVersion:'v1',evaluationId:oldId}),[]);await assert.rejects(repo.listRecoverable({userId:7,judgeVersion:'v1',evaluationId:'bad'}));assert.equal(queries,3);
});

function retryAdmissionFixture({verdict='pass',disabled=false,stale=false,revoked=false,foreign=false,inheritFailure=null,changeBeforeEffect=false}={}){
 const calls={checks:0,inherits:0,sql:[]};
 const stored={...row(true),verdict,owner_generation:'0',packet:'{}',expires_at:new Date(Date.now()+60000),result_json:{errorCode:'JUDGE_UNAVAILABLE'}};
 const query=async(sql,args)=>{calls.sql.push(sql);if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:stored.workshop_key,is_visible:!disabled,exercise_active:true,catalog_active:true,is_enabled:true}]};if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:stale?1:0}]};if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[]};if(sql.includes('FROM workshop_platform.objective_judgments'))return{rows:foreign||args[0]!==7?[]:[stored]};return{rows:[],rowCount:1};};
 const adapter={initial(){},commit(){},projectRecoverable(){},async check(){calls.checks++;if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},async inherit(){calls.inherits++;if(changeBeforeEffect){stored.verdict='pass';return arguments[1]({query},{personaAuthorityRequired:true});}throw inheritFailure||Error('unexpected effect');}};
 return{calls,stored,repo:createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})},{personaBindings:adapter})};
}
test('persona terminal retry rejects before cross-store effect and leaves receipt untouched',async()=>{
 const f=retryAdmissionFixture(),before=structuredClone(f.stored);
 await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),{code:'RETRY_NOT_ALLOWED'});
 assert.equal(f.calls.inherits,0);assert.equal(f.calls.checks,2);assert.deepEqual(f.stored,before);
 assert.ok(!f.calls.sql.some(sql=>/^(UPDATE|INSERT INTO workshop_platform\.(objective_judgments|grade_packets))/.test(sql)));
});
test('foreign, disabled, stale and revoked retry scopes do not reveal terminal eligibility',async()=>{
 for(const [options,code]of [[{foreign:true},'NOT_FOUND'],[{disabled:true},'OBJECTIVE_DISABLED'],[{stale:true},'STALE_GENERATION'],[{revoked:true},'SHOP_AUTH_INVALID']]){
  const f=retryAdmissionFixture(options);await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),{code});assert.equal(f.calls.inherits,0);
 }
});
test('eligible retry preserves actual cross-store uncertainty unchanged',async()=>{
 const uncertain=Object.assign(Error('commit acknowledgement lost'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});
 const f=retryAdmissionFixture({verdict:'unavailable',inheritFailure:uncertain});
 await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),e=>e===uncertain);assert.equal(f.calls.inherits,1);
});

test('retry eligibility is rechecked under the effect write lock after admission',async()=>{const f=retryAdmissionFixture({verdict:'unavailable',changeBeforeEffect:true});await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),{code:'RETRY_NOT_ALLOWED'});assert.equal(f.calls.inherits,1);assert.equal(f.calls.sql.filter(sql=>sql.includes('pg_advisory_xact_lock')&&sql.includes('$1')).length>=2,true);assert.ok(!f.calls.sql.some(sql=>sql.startsWith('UPDATE workshop_platform.grade_packets')));});

// Historical normalized v1 audit: no decisionSummary and original three citations.
function historicalInventoryReplayFixture({pending=false,generation=0,foreign=false,launch=false,staleLaunch=false,contribution=true}={}){
 const stored={...row(false),workshop_key:'secureshop_agent_security',objective_id:'ss_inventory_cross_merchant_stock',family:'SecureShop',scenario:'bound_inventory',rubric_version:'secureshop-inventory-v3',verdict:pending?null:'pass',disposition:pending?'pending':'awarded'};
 const classification={requestRelation:'implements_request',authorizationRelation:'violates_merchant_ownership',requestExcerpt:'change stock',policyExcerpt:'own products only',selectedProductId:22};
 const effectSummary='Stock mutation for product 22, retailer 18: 5 to 8.';
 const original={family:stored.family,scenario:stored.scenario,objectiveId:stored.objective_id,rubricVersion:stored.rubric_version,evidenceDigest:stored.evidence_digest,runId:stored.run_id,mode:'vuln',verdict:'pass',attempts:1,provider:'controlled',model:'controlled',criteria:[{id:'owned_stock_authorization_bypass',satisfied:true,evidenceRefs:['inventory_stock'],citations:[classification.requestExcerpt,classification.policyExcerpt,effectSummary].map(quote=>({evidenceId:'inventory_stock',quote}))}],inventoryStockComparison:{version:'inventory-ownership-comparison-v1',stages:[{stage:'instruction',attempts:1,provider:'controlled',model:'controlled',completed:true,responseSha256:['b'.repeat(64)]}],observation:{version:'inventory-ownership-comparison-v1',relation:'verified_unauthorized_mutation',sourceSha256:'c'.repeat(64),classification,merchantId:12,retailerId:18,productId:22,changed:true,vulnerable:true,effectSummary}}};
 const reorder=value=>Array.isArray(value)?value.map(reorder):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).reverse().map(([k,v])=>[k,reorder(v)])):value;
 stored.result_json=reorder(original);stored.result_digest=require('node:crypto').createHash('sha256').update(JSON.stringify(original)).digest('hex');
 if(launch)Object.assign(stored,{platform_launch_id:randomUUID(),platform_scenario_id:'review',platform_launch_generation:0,platform_session_id:9});
 const events=[];
 const query=async(sql,args)=>{events.push(sql);
  if(sql.includes('SELECT platform_session_id FROM identity.secureshop_launches'))return{rows:[{platform_session_id:9}]};
  if(sql.includes('FROM identity.secureshop_launches l'))return{rows:staleLaunch?[]:[{launch_id:stored.platform_launch_id}]};
  if(sql.includes('FROM workshop_platform.objective_contributions'))return{rows:contribution?[{exists:1}]:[],rowCount:contribution?1:0};
  if(sql.includes('FROM workshop_platform.objective_judgments'))return{rows:foreign||args[0]!==7?[]:[stored]};
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:stored.workshop_key,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};
  if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation}]};
  if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
  return{rows:[],rowCount:1};
 };
 return{stored,original,events,repo:createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})})};
}
test('finalized historical inventory receipt replays original and JSONB reordered objects without reinterpretation',async()=>{
 const f=historicalInventoryReplayFixture(),before=structuredClone(f.stored);
 assert.notEqual(JSON.stringify(f.original),JSON.stringify(f.stored.result_json));
 assert.throws(()=>require('../server/database/postgres/objectiveJudgmentRepository').resultValue(f.original,f.stored),{code:'BAD_REQUEST'});
 for(const result of [f.original,structuredClone(f.stored.result_json)]){
  const receipt=await f.repo.recordVerdict({userId:7,evaluationId,result});assert.equal(receipt.disposition,'awarded');assert.deepEqual(receipt.result,before.result_json);
 }
 assert.deepEqual(f.stored,before);assert.ok(f.events.includes('COMMIT'));
 assert.ok(!f.events.some(sql=>/^(UPDATE|INSERT INTO workshop_platform\.(completions|objective_judgments|objective_contributions))/.test(sql)));
});
test('historical replay shortcut rejects changed or extended audit and never admits pending legacy verdicts',async()=>{
 for(const change of [r=>r.inventoryStockComparison.observation.retailerId=12,r=>r.inventoryStockComparison.observation.extra=true,r=>r.criteria[0].citations.reverse()]){
  const f=historicalInventoryReplayFixture(),r=structuredClone(f.original);change(r);await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId,result:r}),{code:'BAD_REQUEST'});assert.ok(f.events.includes('ROLLBACK'));
 }
 const f=historicalInventoryReplayFixture({pending:true});await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId,result:f.original}),{code:'BAD_REQUEST'});
});
test('exact historical replay retains owner launch contribution and reset fences',async()=>{
 for(const [options,code]of [[{foreign:true},'NOT_FOUND'],[{launch:true,staleLaunch:true},'STALE_GENERATION'],[{launch:true,contribution:false},'GRADE_STORE_NOT_READY']]){
  const f=historicalInventoryReplayFixture(options);await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId,result:f.original}),{code});
 }
 const bound=historicalInventoryReplayFixture({launch:true});assert.equal((await bound.repo.recordVerdict({userId:7,evaluationId,result:bound.original})).disposition,'awarded');
 const stale=historicalInventoryReplayFixture({generation:1}),receipt=await stale.repo.recordVerdict({userId:7,evaluationId,result:stale.original});assert.equal(receipt.disposition,'stale_generation');assert.equal(receipt.historicalDisposition,'awarded');
 assert.ok(!stale.events.some(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')));
});

test('SecureShop release exclusions override stale platform enablement for retry and recovery',async()=>{
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  const f=retryAdmissionFixture({verdict:'unavailable'});Object.assign(f.stored,{workshop_key:'secureshop_agent_security',objective_id:id});
  const before=structuredClone(f.stored);await assert.rejects(f.repo.beginRetry({userId:7,evaluationId,judgeVersion:'v1',ownerGeneration:0}),{code:'OBJECTIVE_DISABLED'});
  assert.equal(f.calls.inherits,0);assert.deepEqual(f.stored,before);
  const eligible={...f.stored,has_packet:true,expires_at:new Date(Date.now()+60000),judge_version:'v1',owner_generation:'0',live_owner_generation:'0',xss_binding_current:true,live_generation:0,live_mode:'vuln',is_visible:true,exercise_active:true,is_enabled:true,objective_active:true,persona_authority_required:false};
  const repo=createObjectiveJudgmentRepository({query:async()=>({rows:[eligible]}),connect(){throw Error('No write');}});
  const rows=await repo.listRecoverable({userId:7,judgeVersion:'v1'});assert.equal(rows.length,1);assert.equal(rows[0].canRetry,false);
 }
});

test('SecureShop release exclusions deny new platform admission and cannot award an existing pending receipt',async()=>{
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  let existing=false;const sqls=[];const launch={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:9};
  const stored={...row(false),workshop_key:'secureshop_agent_security',objective_id:id,family:'SecureShop',scenario:'agent_loop'};
  const query=async(sql,p=[])=>{sqls.push(sql);
   if(sql.includes('FROM identity.secureshop_launches l'))return{rows:[{launch_id:launch.launchId}]};
   if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:stored.workshop_key,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};
   if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:0}]};
   if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[]};
   if(sql.includes('FROM workshop_platform.objective_judgments'))return{rows:existing?[structuredClone(stored)]:[]};
   if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){Object.assign(stored,{verdict:p[2],result_json:JSON.parse(p[3]),result_digest:p[4],disposition:p[5]});return{rows:[structuredClone(stored)]};}
   return{rows:[],rowCount:1};
  };
  const repo=createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
  await assert.rejects(repo.beginEvaluation({...input,workshopKey:stored.workshop_key,objectiveId:id,family:stored.family,scenario:stored.scenario,instanceScope:launch}),{code:'OBJECTIVE_DISABLED'});
  existing=true;
  const saved=await repo.recordVerdict({userId:7,evaluationId,result:{family:stored.family,scenario:stored.scenario,objectiveId:id,rubricVersion:stored.rubric_version,evidenceDigest:stored.evidence_digest,runId:stored.run_id,mode:'vuln',verdict:'pass',criteria:[{id:'effect',satisfied:true,evidenceRefs:['effect']}],explanation:'Controlled pass',provider:'ollama',model:'controlled'}});
  assert.equal(saved.disposition,'hidden');
  assert.ok(!sqls.some(sql=>/INSERT INTO workshop_platform\.(completions|objective_contributions)|accept_secureshop_objective_contribution/.test(sql)));
 }
});
