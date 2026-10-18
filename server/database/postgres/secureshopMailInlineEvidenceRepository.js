'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {productScene}=require('../../services/secureshopMailSceneBinding');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PURPOSE='secureshop_mail_summary';
const fail=()=>Object.assign(Error('Mail inline original source unavailable'),{code:'MAIL_INLINE_SOURCE_UNAVAILABLE'});
const parse=value=>{if(value==null)return null;try{return JSON.parse(value);}catch{throw fail();}};
// SELECT-only assembly behind the production protected saved-mail reader. This
// reader never invokes the summary graph, ordinary mail write, or HTTP adapter.
function createMailInlineEvidenceRepository({identityPool,conversationRepository,readSavedSource}={}){
 if([identityPool?.query,conversationRepository?.getTraceEvents,readSavedSource].some(fn=>typeof fn!=='function'))
  throw TypeError('Mail inline source dependencies required');
 return Object.freeze({async readSource(context,{sessionId,requestId,signal}={}){
  if(!UUID.test(sessionId||'')||!UUID.test(requestId||''))throw fail();
  const saved=await readSavedSource(context,{sessionId,requestId,signal});
  if(typeof saved?.check!=='function')throw fail();
  const check=async()=>{signal?.throwIfAborted();await saved.check();signal?.throwIfAborted();};
  await check();
  const raw=saved.binding,held=productScene(raw.target||raw),b=createConversationBinding(raw.scope,raw.persona),result=saved.turn;
  const m=result?.taskMetadata?.mailSummary;
  if(!held?.scene||b.role!=='merchant'||raw.operationId!==requestId||result.sessionId!==sessionId
   ||m?.version!==1||m.purpose!==PURPOSE||m.requestId!==requestId||m.targetId!==raw.targetId
   ||m.mode!==raw.mode||!equal(m.personaSession,raw.personaSession)||!UUID.test(m.runId||'')||!Array.isArray(m.traceEventIds)
   ||m.traceEventIds.length<5||m.traceEventIds.length>128||m.traceEventIds.some(id=>!UUID.test(id||''))
   ||new Set(m.traceEventIds).size!==m.traceEventIds.length||!equal(m.originalRead,saved.originalRead)
   ||!equal(m.httpRecord,saved.httpRecord)||!equal(m.targetReceipt,saved.targetReceipt))throw fail();
  const rawTraces=await conversationRepository.getTraceEvents(sessionId,b,m.traceEventIds,PURPOSE);await check();
  if(!Array.isArray(rawTraces)||rawTraces.length!==m.traceEventIds.length
   ||rawTraces.some((row,i)=>row.event_id!==m.traceEventIds[i]||row.session_id!==sessionId))throw fail();
  // Persist only deterministic provenance columns; DB timestamps/latency are not
  // model evidence and must not make reconstruction depend on driver Date DTOs.
  const traces=rawTraces.map(row=>Object.fromEntries(['event_id','session_id','step','actor','kind','agent_ns',
   'tool_name','params_json','result_json','provider','policy_violation'].filter(k=>row[k]!==undefined).map(k=>[k,row[k]])));
  const owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const runs=(await identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
   FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
   WHERE r.run_id=$1 AND r.owner_key=$2 AND r.status='completed'`,[m.runId,owner])).rows;await check();
  const run=runs.length===1?runs[0]:null;
  if(!run||run.run_id!==m.runId||run.owner_key!==owner||run.status!=='completed'
   ||typeof run.generation!=='string'||!/^(0|[1-9]\d*)$/.test(run.generation))throw fail();
  const execution={runId:run.run_id,ownerKey:owner,durableGeneration:run.generation};
  function observation(tool,receipt,original){
   const decisions=traces.filter(row=>row.kind==='model_decision'&&row.actor==='supervisor'
    &&parse(row.params_json)?.decision==='tool_use'&&parse(row.params_json)?.toolCalls?.some(call=>call.name===tool));
   if(decisions.length!==1)throw fail();
   const decision=decisions[0],calls=parse(decision.params_json).toolCalls;
   if(calls.length!==1||typeof calls[0].id!=='string'||!calls[0].id||!equal(calls[0].args,{}))throw fail();
   const call=calls[0],results=traces.filter(row=>row.kind===(tool==='email.read_thread'?'local_tool_result':'mcp_result')&&row.actor==='task→supervisor'
    &&row.step===decision.step&&`${row.agent_ns}.${row.tool_name}`===tool);
   if(results.length!==1||traces.indexOf(results[0])<=traces.indexOf(decision))throw fail();
   const expected={version:1,runId:run.run_id,ownerKey:owner,generation:run.generation,
    effectKey:`${requestId}:${JSON.stringify([decision.step,call.id,tool])}`,status:'completed'};
   if(!equal(receipt,expected))throw fail();
   // These tools have distinct local/external observation streams. Each
   // source has exactly one observation in its stream, so both indexes are 0.
   const expectedObservation={index:0,step:decision.step,callId:call.id,tool,args:call.args,result:parse(results[0].result_json),effectReceipt:receipt};
   if(!equal(original,expectedObservation))throw fail();
   // TEXT trace is the original JSON serialization; JSONB metadata may reorder keys.
   return expectedObservation;
  }
  const readObservation=observation('email.read_thread',m.readEffectReceipt,m.readObservation);
  const summaryObservation=observation('email.summarize_thread',m.summaryEffectReceipt,m.summaryObservation);
  if(summaryObservation.step<=readObservation.step)throw fail();
  const keys=[readObservation.effectReceipt.effectKey,summaryObservation.effectReceipt.effectKey];
  const effects=(await identityPool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,e.effect_key,e.status
   FROM graph_runtime.effects e JOIN graph_runtime.owners o ON o.owner_key=e.owner_key AND o.generation=e.generation
   WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=ANY($4::text[]) AND e.status='completed'`,
  [run.run_id,owner,run.generation,keys])).rows;await check();
  if(effects.length!==2||new Set(effects.map(e=>e.effect_key)).size!==2||effects.some(e=>!keys.includes(e.effect_key)
   ||e.run_id!==run.run_id||e.owner_key!==owner||e.generation!==run.generation||e.status!=='completed'))throw fail();
  const binding={scope:raw.scope,targetId:raw.targetId,operationId:raw.operationId,
   persona:raw.persona,personaSession:raw.personaSession,mode:raw.mode};
  const scene={sceneId:held.scene.sceneId,sceneGeneration:held.scene.sceneGeneration,grantId:held.scene.grantId,productTargetId:held.targetId};
  return structuredClone({binding,scene,selected:saved.selected,originalRead:saved.originalRead,inlineBinding:saved.inlineBinding,
   turn:{sessionId,requestId,...saved.savedRequest,execution,traces,result,readObservation,summaryObservation},run,
   effects:keys.map(key=>effects.find(e=>e.effect_key===key)),http:{record:saved.httpRecord,targetReceipt:saved.targetReceipt}});
 }});
}
module.exports={createMailInlineEvidenceRepository};
