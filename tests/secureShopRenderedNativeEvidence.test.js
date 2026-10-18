'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopRenderedNativeEvidence:create}=require('./fixtures/secureShopRenderedNativeEvidence');
const {QUALIFIED_OBJECTIVE_IDS}=require('../server/config/secureshopCurriculum');
function fixture(){
 const launch={launch_id:'10000000-0000-4000-8000-000000000001',scenario_id:'20000000-0000-4000-8000-000000000001',generation:1,platform_session_id:3,original_platform_owner_id:1};
 const session={session_id:'30000000-0000-4000-8000-000000000001',shop_user_id:4,role:'customer',platform_launch_id:launch.launch_id,platform_scenario_id:launch.scenario_id,platform_launch_generation:1,original_platform_owner_id:1,original_platform_session_id:3};
 const state={launches:[launch],sessions:[session],progress:QUALIFIED_OBJECTIVE_IDS.map(objective_id=>({objective_id,completed:false}))},calls=[];
 const pool={async query(sql,args){assert.match(sql,/^\s*SELECT/);calls.push({sql,args});return{rows:sql.includes('bound_persona_sessions')?state.sessions:sql.includes('FROM workshop_platform.objectives')?state.progress:state.launches};}};
 return{state,calls,value:create({identityRuntime:pool,agentsRuntime:pool,reviewRuntime:pool,ownerId:1,siblingId:2,renderer:{sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}})};
}
test('factory derives customer binding from actual scoped persisted session rows and composes verifiers',async()=>{
 const f=fixture(),value=await f.value.forPersona({ownerId:1,role:'customer'});assert.equal(value.binding.shopUserId,4);assert.equal(value.binding.platformSessionId,3);assert.equal(typeof value.evidence.browser.verify,'function');assert.equal(value.evidence.review,undefined);assert.equal(typeof value.evidence.persona.verify,'function');assert.equal(typeof value.evidence.mcpTrust.verify,'function');assert.equal(typeof value.evidence.ssrf.verifyTurn,'function');assert.ok(f.calls[0].sql.includes('identity.user_sessions'));for(const field of ['l.credential_version','l.expires_at'])assert.ok(f.calls[0].sql.includes(field),`launch projection must select ${field}`);assert.deepEqual(f.calls[1].args,[value.binding.launchId,value.binding.scenarioId,1,1,3,'customer']);
});
test('foreign, absent, duplicate and mismatched launch/persona identities fail closed',async()=>{
 for(const mutate of [f=>f.state.launches=[],f=>f.state.launches.push(f.state.launches[0]),f=>f.state.sessions=[],f=>f.state.sessions.push(f.state.sessions[0]),f=>f.state.sessions[0].original_platform_owner_id=2,f=>f.state.sessions[0].original_platform_session_id=9,f=>f.state.sessions[0].platform_launch_generation=2,f=>f.state.sessions[0].role='admin']){const f=fixture();mutate(f);await assert.rejects(f.value.forPersona({ownerId:1,role:'customer'}));}
 await assert.rejects(fixture().value.forPersona({ownerId:99,role:'customer'}));
});
test('DB-derived qualified progress and incomplete lifecycle cannot become synthetic qualification',async()=>{
 const f=fixture();assert.equal((await f.value.expectedProgress(1)).totalObjectives,QUALIFIED_OBJECTIVE_IDS.length);f.state.progress.pop();await assert.rejects(f.value.expectedProgress(1));assert.equal(f.value.capabilities.completeLifecycle,true);assert.throws(()=>f.value.assertLifecycleComplete({authorityHistoryProgressVerified:true,resourceCleanupVerified:true,credentialRevocationVerified:true}),/Only this factory verified/);
});
test('reset verifier requires all six real cleanup receipts and rejects forged final success',async()=>{
 const bypass=fixture().value,bypassLaunch={launchId:'launch-1',generation:2,credentialVersion:13,expiresAt:'2030-01-02T03:04:05.000Z'};
 await assert.rejects(bypass.captureResetReplayBaseline({firstResponse:{cleanupComplete:true,resetId:'unverified',launch:{...bypassLaunch,credentialVersion:12}},recoveryResponse:{preparationOnly:false,launch:bypassLaunch,bearer:'a'.repeat(43)}}),/privately verified cleanup receipt/);
 const kinds=['reviews','products','persona_inbox','mcp_rogue','mcp_rug_pull','controlled_ssrf'];const targetRows=kinds.map((target_kind,i)=>({target_kind,target_id:`target-${i}`,generation:1}));
 let ownerCredentialVersion=13;
 const launch=id=>({launch_id:`launch-${id}`,scenario_id:`scenario-${id}`,generation:id===1?2:1,platform_session_id:id+10,original_platform_owner_id:id,credential_version:id===1?ownerCredentialVersion:4,expires_at:new Date('2030-01-02T03:04:05.000Z')});
 const before={ownerLaunch:{...launch(1),generation:1},siblingLaunch:launch(2),owner:{judgments:[],contributions:[],sessions:[]},sibling:{judgments:[],contributions:[],sessions:[]},ownerTargets:targetRows,siblingTargets:[],siblingProgress:{objectiveIds:QUALIFIED_OBJECTIVE_IDS,completedObjectiveIds:[],totalObjectives:QUALIFIED_OBJECTIVE_IDS.length,completedObjectives:0}};
 let corrupt=false;
 const pool={async query(sql,args){
  if(sql.includes('FROM identity.secureshop_launches'))return{rows:[launch(args[0])]};
  if(sql.includes('FROM workshop_platform.objectives'))return{rows:QUALIFIED_OBJECTIVE_IDS.map(objective_id=>({objective_id,completed:false}))};
  if(sql.includes('FROM identity.secureshop_launch_resets'))return{rows:[{status:'committed',reconciliation_required:false,conversation_reconciliation_required:false,progress_reconciliation_required:false,from_generation:1,to_generation:2}]};
  if(sql.includes('FROM identity.secureshop_target_cleanup_history')){const target=targetRows.find(t=>t.target_id===args[0]);return{rows:[{...target,launch_id:'launch-1',from_generation:1,original_platform_owner_id:1,original_platform_session_id:11,target_receipt_sha256:Buffer.alloc(32,1)}]};}
  if(sql.includes('SELECT lifecycle'))return{rows:[{lifecycle:'retired'}]};
  if(sql.includes('SELECT * FROM')&&sql.includes('_cleanup_receipts'))return{rows:[{launch_id:'launch-1',scenario_id:'scenario-1',generation:1,original_platform_owner_id:1,original_platform_session_id:11,receipt_sha256:Buffer.alloc(32,corrupt?2:1)}]};
  return{rows:[]};
 }};
 const value=create({identityRuntime:pool,agentsRuntime:pool,reviewRuntime:pool,ownerId:1,siblingId:2,renderer:{sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}});
 const firstLaunch={launchId:'launch-1',generation:2,credentialVersion:12,expiresAt:'2030-01-02T03:04:05.000Z'};
 const currentLaunch={...firstLaunch,credentialVersion:13};
 const result=await value.verifyReset({before,response:{cleanupComplete:true,resetId:'reset',launch:firstLaunch}});assert.equal(value.assertLifecycleComplete(result),true);assert.equal(result.httpDenialVerified,false);assert.equal(result.processPortCleanupVerified,false);
 await assert.rejects(value.verifyResetReplay({firstResponse:{resetId:'reset',launch:firstLaunch},replayResponse:{resetId:'reset',cleanupComplete:true,launch:currentLaunch}}),/baseline required/);
 for(const credentialVersion of [12,14])await assert.rejects(value.captureResetReplayBaseline({firstResponse:{cleanupComplete:true,resetId:'reset',launch:firstLaunch},recoveryResponse:{preparationOnly:false,launch:{...currentLaunch,credentialVersion},bearer:'a'.repeat(43)}}));
 await value.captureResetReplayBaseline({firstResponse:{cleanupComplete:true,resetId:'reset',launch:firstLaunch},recoveryResponse:{preparationOnly:false,launch:currentLaunch,bearer:'a'.repeat(43)}});
 await assert.rejects(value.captureResetReplayBaseline({firstResponse:{cleanupComplete:true,resetId:'reset',launch:firstLaunch},recoveryResponse:{preparationOnly:false,launch:currentLaunch,bearer:'a'.repeat(43)}}),/only once/);
 await value.verifyResetReplay({firstResponse:{resetId:'reset',launch:firstLaunch},replayResponse:{resetId:'reset',cleanupComplete:true,launch:currentLaunch}});
 for(const replayResponse of [
  {resetId:'other',cleanupComplete:true,launch:currentLaunch},
  {resetId:'reset',cleanupComplete:true,launch:{...currentLaunch,credentialVersion:12}},
  {resetId:'reset',cleanupComplete:true,launch:{...currentLaunch,credentialVersion:14}},
  {resetId:'reset',cleanupComplete:true,launch:{...currentLaunch,launchId:'other-launch'}},
  {resetId:'reset',cleanupComplete:true,launch:{...currentLaunch,generation:3}},
  {resetId:'reset',cleanupComplete:true,launch:{...currentLaunch,expiresAt:'2031-01-02T03:04:05.000Z'}},
 ])await assert.rejects(value.verifyResetReplay({firstResponse:{resetId:'reset',launch:firstLaunch},replayResponse}));
 ownerCredentialVersion=14;
 await assert.rejects(value.verifyResetReplay({firstResponse:{resetId:'reset',launch:firstLaunch},replayResponse:{resetId:'reset',cleanupComplete:true,launch:currentLaunch}}));
 ownerCredentialVersion=13;
 assert.throws(()=>value.assertLifecycleComplete({...result}));corrupt=true;await assert.rejects(value.verifyReset({before,response:{cleanupComplete:true,resetId:'reset',launch:firstLaunch}}),error=>{assert.equal(error.code,'ERR_ASSERTION');assert.equal(error.operator,'deepStrictEqual');assert.deepEqual(error.actual,Buffer.alloc(32,2));assert.deepEqual(error.expected,Buffer.alloc(32,1));return true;});
});
test('run inspector resolves persisted conversation ownership and overall parity counts',async()=>{
 const runId='40000000-0000-4000-8000-000000000001';let actualOwner=1;
 const run={status:'completed',provider:'ollama',model:'llama3.1:8b',decision_source:'model',generation:1,owner_key:JSON.stringify(['SecureShopBoundConversation','session'])};
 const pool={async query(sql){return{rows:sql.includes('FROM graph_runtime.runs')?[run]:sql.includes('FROM secureshop_agents.agent_sessions')?[{id:'session',original_platform_owner_id:actualOwner}]:sql.includes('FROM workshop_platform.exercises')?[{workshop_key:'secureshop_agent_security',challenge_name:'SecureShop Agent Security',objective_count:QUALIFIED_OBJECTIVE_IDS.length,completed_objective_count:2},{workshop_key:'other',challenge_name:'Other',objective_count:3,completed_objective_count:3}]:[]};}};
 const value=create({identityRuntime:pool,agentsRuntime:pool,reviewRuntime:pool,ownerId:1,siblingId:2,renderer:{sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}});
 const body={run:{runId,status:'completed',provider:run.provider,model:run.model,decisionSource:'model',generation:1},judgments:[],events:[],nextCursor:null};
 await value.verifyRunDetail({ownerId:1,runId,body,projection:'student'});await value.verifyRunDetail({ownerId:1,runId,body:{...body,run:{...body.run,ownerId:1}},projection:'admin'});actualOwner=2;await assert.rejects(value.verifyRunDetail({ownerId:1,runId,body,projection:'student'}));
 assert.deepEqual(await value.expectedStudentView(1),{completedChallenges:1,completedObjectives:5,totalObjectives:QUALIFIED_OBJECTIVE_IDS.length+3,secureShopCompletedObjectives:2,secureShopTotalObjectives:QUALIFIED_OBJECTIVE_IDS.length,secureShopChallengeName:'SecureShop Agent Security'});
});

test('foreign run isolation and logout use persisted ownership/session state, never caller success',async()=>{
 let owner=1,active=1;
 const launch={launch_id:'launch',scenario_id:'scenario',generation:1,platform_session_id:3,original_platform_owner_id:1};
 const pool={async query(sql,args){
  if(sql.includes('FROM identity.secureshop_launches'))return{rows:[{...launch,original_platform_owner_id:args[0]}]};
  if(sql.includes('FROM graph_runtime.runs'))return{rows:[{owner_key:JSON.stringify(['SecureShopBoundConversation','session'])}]};
  if(sql.includes('FROM secureshop_agents.agent_sessions'))return{rows:[{original_platform_owner_id:owner}]};
  if(sql.includes('FROM identity.user_sessions'))return{rows:[{id:3,user_id:1,is_active:active}]};
  if(sql.includes('bound_persona_sessions'))return{rows:[]};throw Error('Unexpected query');
 }};
 const value=create({identityRuntime:pool,agentsRuntime:pool,reviewRuntime:pool,ownerId:1,siblingId:2});
 await value.verifyForeignRunIsolation({ownerId:1,siblingId:2,runIds:['run']});owner=2;await assert.rejects(value.verifyForeignRunIsolation({ownerId:1,siblingId:2,runIds:['run']}));
 await assert.rejects(value.verifyLogout({ownerId:1,siblingId:2}));
 await assert.rejects(value.forPersona({ownerId:1,role:'customer'}));
 await assert.rejects(value.verifyLogout({ownerId:1,siblingId:2}));active=0;
 assert.equal((await value.verifyLogout({ownerId:1,siblingId:2})).persistedPlatformSessionRevoked,true);
});
test('reentry requires real current persona with exactly next generation and empty progress',async()=>{
 const f=fixture();const before=(await f.value.forPersona({ownerId:1,role:'customer'})).binding;
 f.state.launches[0].generation=2;f.state.sessions[0].platform_launch_generation=2;
 const after=(await f.value.forPersona({ownerId:1,role:'customer'})).binding;
 await f.value.verifyReentry({ownerId:1,beforeBinding:before,afterBinding:after});
 await assert.rejects(f.value.verifyReentry({ownerId:1,beforeBinding:before,afterBinding:{...after,platformSessionId:99}}));
 f.state.progress[0].completed=true;await assert.rejects(f.value.verifyReentry({ownerId:1,beforeBinding:before,afterBinding:after}));
});
