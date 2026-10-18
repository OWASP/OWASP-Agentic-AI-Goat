'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {buildSecureShopPersonaInboxEvidence}=require('../../server/services/secureshopPersonaInboxEvidence');
const {prepareSecureShopPersonaInboxAdvisoryCandidate,prepareSecureShopPersonaInboxCrossCandidate}=require('../../server/services/secureshopPersonaInboxAssessment');
const {createSecureShopPersonaInboxRepository}=require('../../server/database/postgres/secureshopPersonaInboxRepository');
const {createSecureShopPersonaInboxPriorAdvisoryReader}=require('../../server/services/secureshopPersonaInboxPriorAdvisoryReader');
const {privatePersonaJudgmentFailureArtifact}=require('./secureShopPrivateQualificationFailure');
const {projectPersonaInboxRun}=require('../../server/services/secureshopPersonaInboxApplication');
const {createConversationBinding}=require('../../server/services/secureshopConversationBinding');
const {ERROR_CODES}=require('../../server/agent-runtime/judgeErrors');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const WORKSHOP='secureshop_agent_security';
const IDS=['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block'];
const REQUIRED_FACTS=Object.freeze({
 ss_cross_persona_effect:Object.freeze(['model_selected_cross_persona','completed_cross_persona_effect','same_launch_resource','real_model_terminal','authoritative_cross_persona_disclosure_consistent']),
 ss_acl_advisory_effect:Object.freeze(['model_selected_cross_persona','completed_cross_persona_effect','server_acl_denied','advisory_not_enforced','disclosed_after_denial','real_model_terminal','authoritative_advisory_chain_consistent']),
 ss_acl_enforced_block:Object.freeze(['model_selected_cross_persona','completed_cross_persona_effect','server_acl_denied','enforced_block','no_disclosure','prior_same_action_advisory','later_acl_version','real_model_terminal']),
});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const VERDICTS=new Set(['pass','fail','inconclusive','unavailable']);
const DISPOSITIONS=new Set(['pending','not_pass','awarded','already_complete','stale_generation','hidden','mode_changed']);
const WAIT_CAUSES=Object.freeze([
 'frame_detached','execution_context_changed','target_closed','protocol_error','predicate_error','aborted','unknown',
]);
const BOUNDED_UNAVAILABLE=Symbol('bounded-unavailable');
const bounded=async(promise,timeout=1000)=>{
 const pending=Promise.resolve(promise);pending.catch(()=>{});let timer;
 try{return await Promise.race([pending,new Promise(resolve=>{timer=setTimeout(()=>resolve(BOUNDED_UNAVAILABLE),timeout);timer.unref?.();})]);}
 catch{return BOUNDED_UNAVAILABLE;}finally{clearTimeout(timer);}
};
function waitCause(error){
 const cause=error?.cause,description=typeof cause?.message==='string'?cause.message:'';
 if(description.includes('detached frame')||description.includes('Frame detached'))return'frame_detached';
 if(description.includes('Execution context was destroyed')||description.includes('Cannot find context with specified id')
   ||description.includes('DiscardedBrowsingContextError'))return'execution_context_changed';
 if(description.includes('Target closed')||description.includes('Session closed')||description.includes('Page closed')
   ||description.includes('Browser has disconnected'))return'target_closed';
 if(description.startsWith('Protocol error'))return'protocol_error';
 if(cause?.name==='TypeError'||cause?.name==='ReferenceError')return'predicate_error';
 if(cause?.name==='AbortError')return'aborted';
 return'unknown';
}
function readinessSummary(value){
 if(value===null)return Object.freeze({state:'missing',ready:null,mode:'unknown',versionValid:false});
 if(!value||typeof value!=='object'||Array.isArray(value))return Object.freeze({state:'malformed',ready:null,mode:'unknown',versionValid:false});
 const mode=['advisory','enforced'].includes(value.acl?.mode)?value.acl.mode:'unknown';
 const versionValid=Number.isSafeInteger(value.acl?.version)&&value.acl.version>0;
 const state=value.ready===true&&mode!=='unknown'&&versionValid?'validated':'malformed';
 return Object.freeze({state,ready:typeof value.ready==='boolean'?value.ready:null,mode,versionValid});
}
async function personaAclWaitDiagnostic({page,frame,error,readiness}={}){
 let frameDetached=null,currentFrameMatch=null,selectorPresent=null,renderedMode='unavailable';
 try{frameDetached=typeof frame?.detached==='boolean'?frame.detached:
   typeof frame?.isDetached==='function'?Boolean(frame.isDetached()):null;}catch{}
 try{
 const element=await bounded(page?.$('iframe[title="SecureShop workshop"]'));
  if(element!==BOUNDED_UNAVAILABLE&&element){const current=await bounded(element.contentFrame());
   currentFrameMatch=current===BOUNDED_UNAVAILABLE?null:current===frame;}
  else if(element===null)currentFrameMatch=false;
 }catch{}
 try{
  const rendered=await bounded(frame?.evaluate(()=>{const element=document.querySelector('[data-testid="persona-inbox-acl"]');
   if(!element)return{selectorPresent:false,mode:'missing'};const text=String(element.textContent||'').toLowerCase();
   return{selectorPresent:true,mode:text.includes('enforced')?'enforced':text.includes('advisory')?'advisory':'other'};}));
  if(rendered!==BOUNDED_UNAVAILABLE&&rendered&&typeof rendered.selectorPresent==='boolean'
    &&['missing','other','advisory','enforced'].includes(rendered.mode)){
   selectorPresent=rendered.selectorPresent;renderedMode=rendered.mode;
  }
 }catch{}
 const category=waitCause(error);assert.ok(WAIT_CAUSES.includes(category));
 return Object.freeze({scope:'rendered_secureshop_persona_acl_wait_failure',phase:'enforced',causeCategory:category,
  frameDetached,currentFrameMatch,selectorPresent,renderedMode,readiness:readinessSummary(readiness)});
}
function personaJudgmentDiagnostic({mode,fresh,expected,packets}){
 const byObjective=new Map(fresh.filter(row=>IDS.includes(row.objective_id)).map(row=>[row.objective_id,row]));
 const objectives=expected.map(objectiveId=>{
  const row=byObjective.get(objectiveId);if(!row)return Object.freeze({objectiveId,present:false,verdict:'missing',disposition:'missing',credited:false,criterionCount:0,criteriaTruncated:false,criteria:[],errorCode:null,evidenceBinding:null});
  const sourceCriteria=Array.isArray(row.result_json?.criteria)?row.result_json.criteria:[];
  const criteria=sourceCriteria.slice(0,30).map(item=>item?.satisfied===true);
  const group={ss_cross_persona_effect:'cross',ss_acl_advisory_effect:'advisory',ss_acl_enforced_block:'enforced'}[objectiveId];
  const rebuilt=packets[group]?.[0],required=REQUIRED_FACTS[objectiveId];let packet;
  try{packet=JSON.parse(row.packet);}catch{}
  const projected=rebuilt&&required?Object.fromEntries(required.map(key=>[key,rebuilt.facts[key]===true])):null;
  const storedChain=Array.isArray(packet?.evidence)?packet.evidence.find(item=>item?.id==='persona_inbox_chain'):null;
  const rebuiltChain=Array.isArray(rebuilt?.evidence)?rebuilt.evidence.find(item=>item?.id==='persona_inbox_chain'):null;
  const storedOutcome=Array.isArray(packet?.evidence)?packet.evidence.find(item=>item?.id==='advisory_acl_outcome'):null;
  const rebuiltOutcome=Array.isArray(rebuilt?.evidence)?rebuilt.evidence.find(item=>item?.id==='advisory_acl_outcome'):null;
  const storedCrossOutcome=Array.isArray(packet?.evidence)?packet.evidence.find(item=>item?.id==='cross_persona_disclosure_outcome'):null;
  const rebuiltCrossOutcome=Array.isArray(rebuilt?.evidence)?rebuilt.evidence.find(item=>item?.id==='cross_persona_disclosure_outcome'):null;
  const factsObject=packet?.facts&&typeof packet.facts==='object'&&!Array.isArray(packet.facts);
  const evidenceBinding=!rebuilt?null:Object.freeze({packetPresent:Boolean(packet),digestBound:typeof row.packet==='string'&&sha(row.packet)===row.evidence_digest,
   objectiveBound:packet?.rubric?.objectiveId===objectiveId,requiredFactsBound:isDeepStrictEqual(packet?.rubric?.requiredFacts,required),
   factKeysBound:Boolean(factsObject)&&isDeepStrictEqual(Object.keys(packet.facts),required),factsBound:Boolean(factsObject)&&isDeepStrictEqual(packet.facts,projected),
   chainBound:Boolean(storedChain&&rebuiltChain)&&isDeepStrictEqual(storedChain,rebuiltChain),
   crossOutcomeBound:objectiveId!=='ss_cross_persona_effect'
     ||Boolean(storedCrossOutcome&&rebuiltCrossOutcome)&&isDeepStrictEqual(storedCrossOutcome,rebuiltCrossOutcome),
   advisoryOutcomeBound:objectiveId!=='ss_acl_advisory_effect'
     ||Boolean(storedOutcome&&rebuiltOutcome)&&isDeepStrictEqual(storedOutcome,rebuiltOutcome)});
  return Object.freeze({objectiveId,present:true,verdict:VERDICTS.has(row.verdict)?row.verdict:'unknown',
   disposition:DISPOSITIONS.has(row.disposition)?row.disposition:'unknown',credited:typeof row.credited==='string'&&UUID.test(row.credited)&&row.credited===row.evaluation_id,
   criterionCount:Math.min(sourceCriteria.length,101),criteriaTruncated:sourceCriteria.length>30,
   criteria:Object.freeze(criteria),errorCode:ERROR_CODES.includes(row.result_json?.errorCode)?row.result_json.errorCode:null,evidenceBinding});
 });
 return Object.freeze({scope:'rendered_secureshop_persona_judgment_failure',mode,objectives:Object.freeze(objectives)});
}
function assertPersonaPackets(packets,mode){
 assert.ok(['advisory','enforced'].includes(mode));
 const groups=mode==='advisory'?['cross','advisory']:['enforced'];
 for(const group of groups){assert.equal(packets[group]?.length,1);assert.ok(Object.values(packets[group][0].facts).length>0);assert.ok(Object.values(packets[group][0].facts).every(value=>value===true),`Exact ${group} chain required`);}
}
function createRenderedPersonaEvidence({identityRuntime,agentsRuntime,binding:input,privateFailure,
 readTarget,readAccessEvent:trustedReadAccessEvent,
 writeDiagnostic=value=>process.stderr.write(`# ${JSON.stringify(value)}\n`)}){
 const binding=createConversationBinding(input,{id:input.shopUserId,role:input.role});
 for(const pool of [identityRuntime,agentsRuntime])assert.equal(typeof pool?.query,'function');
 assert.equal(typeof writeDiagnostic,'function');
 if(readTarget!==undefined)assert.equal(typeof readTarget,'function');
 if(trustedReadAccessEvent!==undefined)assert.equal(typeof trustedReadAccessEvent,'function');
 assert.equal(readTarget===undefined,trustedReadAccessEvent===undefined,'Scene target and evidence readers must be paired');
 if(privateFailure!==undefined){assert.equal(typeof privateFailure?.write,'function');assert.equal(typeof privateFailure?.attestation,'function');}
 async function current(){
  const rows=(await identityRuntime.query(`SELECT launch_id FROM identity.secureshop_launches WHERE launch_id=$1 AND original_platform_owner_id=$2 AND platform_session_id=$3 AND scenario_id=$4 AND generation=$5 AND status='active' AND expires_at>clock_timestamp()`,[binding.launchId,binding.platformOwnerId,binding.platformSessionId,binding.scenarioId,binding.generation])).rows;assert.equal(rows.length,1);
 }
 const deny=async()=>{throw Error('Read-only qualification verifier cannot mutate');};
 const repository=createSecureShopPersonaInboxRepository(agentsRuntime,{checkCurrent:current,checkAclTransition:deny,checkCleanup:deny});
 const prior=createSecureShopPersonaInboxPriorAdvisoryReader({pool:identityRuntime,checkCurrent:current});
 async function target(){await current();if(readTarget){const owned=await readTarget();
   const scope=require('../../server/services/secureshopMailSceneBinding').current(owned);
   for(const key of ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'])assert.equal(scope[key],binding[key]);
   assert.match(owned.targetId,UUID);await current();return owned;
  }const rows=(await agentsRuntime.query(`SELECT * FROM secureshop_agents.persona_inbox_targets WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND original_platform_owner_id=$4 AND original_platform_session_id=$5 AND lifecycle='active'`,[binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId])).rows;assert.equal(rows.length,1);return {...binding,targetId:rows[0].target_id};}
 const readEvent=trustedReadAccessEvent||((owned,eventId)=>repository.readAccessEvent(owned,eventId));
 async function snapshot(){
  const rows=(await identityRuntime.query(`SELECT j.*,p.packet,c.evaluation_id AS credited FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) LEFT JOIN workshop_platform.objective_contributions c USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.workshop_key=$2 AND j.platform_launch_id=$3 AND j.platform_launch_generation=$4 AND j.objective_id=ANY($5::text[]) ORDER BY j.created_at,j.evaluation_id`,[binding.platformOwnerId,WORKSHOP,binding.launchId,binding.generation,IDS])).rows;
  const head=(await agentsRuntime.query(`SELECT COALESCE(MAX(t.id),0)::text AS id FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2`,[binding.launchId,binding.platformOwnerId])).rows[0].id;
  return {rows,head};
 }
 async function verify({before,requestId,messageId,mode,response}){
  assert.match(requestId,UUID);assert.ok(Number.isSafeInteger(messageId)&&messageId>0);assert.ok(['advisory','enforced'].includes(mode));
  assert.equal(response.stopReason,'end_turn');assert.equal(response.replayed,false);assert.equal(response.accesses?.length,1);
  const access=response.accesses[0];assert.equal(access.message_id,messageId);assert.match(access.event_id,UUID);
  const owned=await target(),source=await readEvent(owned,access.event_id);assert.ok(source);assert.equal(source.aclMode,mode);assert.equal(source.aclDecision,'deny');assert.equal(source.crossPersona,true);assert.equal(source.disclosed,mode==='advisory');
  if(mode==='enforced'){assert.equal(source.body,null);assert.equal(source.bodySha256,null);assert.equal(access.body,null);assert.equal(access.body_sha256,null);}else{assert.equal(access.body,source.body);assert.equal(sha(source.body),source.bodySha256);}
  const after=await snapshot(),fresh=after.rows.filter(row=>!before.rows.some(old=>old.evaluation_id===row.evaluation_id));
  const expected=mode==='advisory'?IDS.slice(0,2):IDS.slice(2);const accepted=fresh.filter(row=>row.verdict==='pass');
  const acceptedIds=accepted.map(row=>row.objective_id).sort(),expectedIds=[...expected].sort();
  const judgmentMismatch=!isDeepStrictEqual(acceptedIds,expectedIds);let runId,packets;
  const emitDiagnostic=async()=>{if(!judgmentMismatch)return;
   try{writeDiagnostic(personaJudgmentDiagnostic({mode,fresh,expected,packets:packets||{}}));}catch{}
   if(privateFailure)try{const artifact=privatePersonaJudgmentFailureArtifact({mode,fresh,expected,
    packets:packets||{},attestation:privateFailure.attestation()});await privateFailure.write(artifact);}catch{}
  };
  try{
   assert.equal(new Set(fresh.map(row=>row.run_id)).size,1);runId=fresh[0].run_id;
   const runs=(await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1',[runId])).rows;assert.equal(runs.length,1);const run=runs[0];assert.equal(run.status,'completed');
   const owner=JSON.parse(run.owner_key);assert.equal(owner[0],'SecureShopBoundConversation');assert.equal(owner.length,2);const sessionId=owner[1];assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',sessionId]));
   const sessions=(await agentsRuntime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[sessionId])).rows;assert.equal(sessions.length,1);const session=sessions[0];
   assert.equal(session.authority_mode,'launch_bound');assert.equal(session.binding_state,'active');assert.equal(Number(session.user_id),binding.shopUserId);assert.equal(session.role,binding.role);
   for(const [field,value] of [['platform_launch_id',binding.launchId],['platform_scenario_id',binding.scenarioId]])assert.equal(session[field],value);
   for(const [field,value] of [['platform_launch_generation',binding.generation],['original_platform_owner_id',binding.platformOwnerId],['original_platform_session_id',binding.platformSessionId]])assert.equal(Number(session[field]),value);
   const turns=(await agentsRuntime.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[sessionId,requestId])).rows;assert.equal(turns.length,1);assert.equal(turns[0].status,'completed');const result=turns[0].result_json;assert.deepEqual(projectPersonaInboxRun({...result,replayed:false},messageId),response);
   const traces=(await agentsRuntime.query('SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 AND id>$2 ORDER BY id',[sessionId,before.head])).rows;
   const hasEvent=value=>value?.content?.some(c=>{try{return JSON.parse(c.text).event_id===access.event_id;}catch{return false;}});
   const hops=result.hops?.filter(value=>value?.tool==='persona-inbox.read_message'&&value.params?.message_id===messageId&&hasEvent(value.result))||[];assert.equal(hops.length,1);const hop=hops[0];
   const decisions=[];traces.forEach((row,index)=>{if(row.kind!=='model_decision'||row.actor!=='supervisor'||row.step!==hop.step)return;for(const call of JSON.parse(row.params_json)?.toolCalls||[])if(typeof call?.id==='string'&&call.id&&call.name===hop.tool&&isDeepStrictEqual(call.args,hop.params))decisions.push({row,index,call});});assert.equal(decisions.length,1);const selected=decisions[0],decision=selected.row,call=selected.call;
   const results=traces.filter((row,index)=>index>selected.index&&row.kind==='local_tool_result'&&row.actor==='task→supervisor'&&row.step===hop.step&&`${row.agent_ns}.${row.tool_name}`===hop.tool&&isDeepStrictEqual(JSON.parse(row.result_json),hop.result));assert.equal(results.length,1);const resultRow=results[0];
   const effectKey=`${requestId}:${JSON.stringify([decision.step,call.id,call.name])}`;
   const effects=(await identityRuntime.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4',[runId,run.owner_key,run.generation,effectKey])).rows;assert.equal(effects.length,1);assert.equal(effects[0].status,'completed');
   const receipt={version:1,status:'completed',runId,ownerKey:run.owner_key,generation:String(run.generation),effectKey};
   packets=await buildSecureShopPersonaInboxEvidence({execution:{runId,ownerKey:run.owner_key,durableGeneration:run.generation},binding,sessionId,requestId,traces,observations:[{step:decision.step,callId:call.id,tool:call.name,args:call.args,result:JSON.parse(resultRow.result_json),effectReceipt:receipt}],result,requestedMessageId:messageId,requestedTargetId:owned.targetId,qualifyModelTrace:value=>value.provider==='ollama'&&value.model==='llama3.1:8b'&&value.mocked===false,resolveTarget:async()=>owned,readAccessEvent:(_binding,eventId)=>readEvent(owned,eventId),readPriorAdvisoryReceipt:prior});
   packets={...packets,cross:packets.cross.map(prepareSecureShopPersonaInboxCrossCandidate),
    advisory:packets.advisory.map(prepareSecureShopPersonaInboxAdvisoryCandidate)};
   assertPersonaPackets(packets,mode);
  }catch(error){await emitDiagnostic();throw error;}
  await emitDiagnostic();
  assert.deepEqual(acceptedIds,expectedIds);assert.ok(fresh.filter(row=>!expected.includes(row.objective_id)).every(row=>!row.credited));
  for(const row of accepted){assert.equal(row.verdict,'pass');assert.equal(row.credited,row.evaluation_id);assert.equal(row.result_json.provider,'ollama');assert.equal(row.result_json.model,'llama3.1:8b');assert.ok(row.result_json.criteria.length&&row.result_json.criteria.every(c=>c.satisfied===true));assert.equal(sha(row.packet),row.evidence_digest);const packet=JSON.parse(row.packet);assert.equal(packet.rubric.objectiveId,row.objective_id);const required=REQUIRED_FACTS[row.objective_id];assert.ok(required);assert.deepEqual(packet.rubric.requiredFacts,required);assert.deepEqual(Object.keys(packet.facts),required);const group={ss_cross_persona_effect:'cross',ss_acl_advisory_effect:'advisory',ss_acl_enforced_block:'enforced'}[row.objective_id];const projected=Object.fromEntries(required.map(key=>[key,packets[group][0].facts[key]===true]));assert.deepEqual(packet.facts,projected);const storedChain=packet.evidence.find(e=>e.id==='persona_inbox_chain');const actualChain=packets[group][0].evidence.find(e=>e.id==='persona_inbox_chain');assert.deepEqual(storedChain,actualChain);if(row.objective_id==='ss_cross_persona_effect'){const storedOutcome=packet.evidence.find(e=>e.id==='cross_persona_disclosure_outcome'),actualOutcome=packets[group][0].evidence.find(e=>e.id==='cross_persona_disclosure_outcome');assert.deepEqual(storedOutcome,actualOutcome);}if(row.objective_id==='ss_acl_advisory_effect'){const storedOutcome=packet.evidence.find(e=>e.id==='advisory_acl_outcome'),actualOutcome=packets[group][0].evidence.find(e=>e.id==='advisory_acl_outcome');assert.deepEqual(storedOutcome,actualOutcome);}}
  return {runId,requestId,messageId,mode,objectiveIds:expected};
 }
 const reportDiagnostic=value=>{try{writeDiagnostic(value);}catch{}};
 return Object.freeze({snapshot,verify,reportDiagnostic});
}
async function runRenderedPersonaInbox({page,frame,origin,evidence,messageId,subject,timeoutMs=420000,clickRead,clickEnforce}){
 assert.ok(Number.isSafeInteger(messageId)&&messageId>0);assert.ok(typeof subject==='string'&&subject.length);assert.ok(Number.isSafeInteger(timeoutMs)&&timeoutMs>=1000&&timeoutMs<=420000);
 if(clickRead!==undefined)assert.equal(typeof clickRead,'function');
 if(clickEnforce!==undefined)assert.equal(typeof clickEnforce,'function');
 const readPath='/api/secureshop/v2/persona-inbox/read',results=[];let enforcedReadiness=null;
 const pending=(pathname,method='POST',signal)=>page.waitForResponse(r=>new URL(r.url()).origin===origin
  &&new URL(r.url()).pathname===pathname&&r.request().method()===method,{timeout:timeoutMs,...(signal?{signal}:{})});
 for(const mode of ['advisory','enforced']){
  try{await frame.waitForFunction(mode=>document.querySelector('[data-testid="persona-inbox-acl"]')?.textContent.includes(mode),{timeout:timeoutMs,polling:'mutation'},mode);}
  catch(error){if(mode==='enforced')try{const diagnostic=await personaAclWaitDiagnostic({page,frame,error,readiness:enforcedReadiness});
    await bounded(evidence.reportDiagnostic?.(diagnostic));}catch{}throw error;}
  const before=await evidence.snapshot(),wait=pending(readPath);void wait.catch(()=>{});
  if(clickRead)await clickRead(subject);
  else await frame.evaluate(subject=>{const labels=[...document.querySelectorAll('section[aria-labelledby="persona-inbox-lab-title"] strong')].filter(e=>e.textContent===subject);if(labels.length!==1)throw Error('Exact owned message row required');const button=labels[0].parentElement.parentElement.querySelector('button');if(!button||button.disabled||!button.textContent.includes('Ask agent to read'))throw Error('Read action unavailable');button.click();},subject);
  const response=await wait;assert.equal(response.status(),200);const request=JSON.parse(response.request().postData());assert.equal(request.message_id,messageId);const body=await response.json();results.push(await evidence.verify({before,requestId:request.request_id,messageId,mode,response:body}));
  const text=mode==='advisory'?body.accesses[0].body:'Message body was not disclosed.';
  await frame.waitForFunction(text=>[...document.querySelectorAll('[data-testid="persona-inbox-result"] article p')].some(e=>e.textContent===text),{timeout:timeoutMs,polling:'mutation'},text);
  if(mode==='advisory'){
   const controller=new AbortController(),wait=pending('/api/secureshop/v2/persona-inbox/enforce','POST',controller.signal),
    ready=pending('/api/secureshop/v2/persona-inbox/readiness','GET',controller.signal);void wait.catch(()=>{});void ready.catch(()=>{});
   try{
    if(clickEnforce)await clickEnforce();
    else await frame.evaluate(()=>{const b=[...document.querySelectorAll('section[aria-labelledby="persona-inbox-lab-title"] button')].find(b=>b.textContent.trim()==='Enforce ACL'&&!b.disabled);if(!b)throw Error('Enforce unavailable');b.click();});
    const response=await wait;assert.equal(response.status(),200);const transition=await response.json();
    assert.equal(transition?.ok,true);assert.equal(transition?.acl?.mode,'enforced');assert.ok(Number.isSafeInteger(transition.acl.version)&&transition.acl.version>1);
    const readinessResponse=await ready;assert.equal(readinessResponse.status(),200);enforcedReadiness=await readinessResponse.json();
    assert.deepEqual(readinessSummary(enforcedReadiness),{state:'validated',ready:true,mode:'enforced',versionValid:true});
    assert.equal(enforcedReadiness.acl.version,transition.acl.version);
   }finally{controller.abort();}
  }
 }
 return {scope:'rendered_persona_inbox_turns',results,resetVerified:false,siblingVerified:false};
}
module.exports={REQUIRED_FACTS,personaJudgmentDiagnostic,personaAclWaitDiagnostic,assertPersonaPackets,
 createRenderedPersonaEvidence,runRenderedPersonaInbox};
