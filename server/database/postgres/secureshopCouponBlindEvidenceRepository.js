'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const Probe=require('../../services/secureshopCouponProbeContract');
const Request=require('../../services/secureshopCouponProbeRequest');
const {witness}=require('../../services/secureshopCouponBlindEvidence');
const UUID=require('../../services/secureshopCouponContract').UUID;
const fail=()=>Object.assign(Error('Coupon probe original unavailable'),{code:'COUPON_BLIND_SOURCE_UNAVAILABLE'});
function createCouponBlindEvidenceRepository({identityPool,conversationRepository,readSavedSource,readCouponProbeReceipt,readCouponProbeReference}={}){
 if([identityPool?.query,conversationRepository?.getTraceEvents,readSavedSource,readCouponProbeReceipt,readCouponProbeReference].some(f=>typeof f!=='function'))throw TypeError('Coupon source dependencies required');
 return Object.freeze({async readSource(context,{sessionId,requestId,signal}={}){
  if(!UUID.test(sessionId||'')||!UUID.test(requestId||''))throw fail();
  const saved=await readSavedSource(context,{sessionId,requestId,signal});
  if(typeof saved?.check!=='function'||!saved.state)throw fail();
  const check=async()=>{signal?.throwIfAborted();await saved.check();signal?.throwIfAborted();};await check();
  const state=saved.state,result=saved.turn,m=result?.taskMetadata?.couponProbe;
  let requestIdentity;try{requestIdentity=Request.saved(m);}catch{throw fail();}
  if(m?.version!==Request.version(requestIdentity.protocol)
   ||saved.savedRequest?.message!==requestIdentity.message||m.purpose!=='secureshop_coupon_probe'||m.sessionId!==sessionId||m.requestId!==requestId
   ||!equal(m.sourceBinding,state.sourceBinding)||!Array.isArray(m.probes)||m.probes.length<3||m.probes.length>(requestIdentity.protocol?7:8)
   ||!Array.isArray(m.traceEventIds)||m.traceEventIds.length>256||new Set(m.traceEventIds).size!==m.traceEventIds.length)throw fail();
  const b=createConversationBinding(state.scope,state.persona);
  const raw=await conversationRepository.getTraceEvents(sessionId,b,m.traceEventIds,'secureshop_coupon_probe');await check();
  if(raw.length!==m.traceEventIds.length||raw.some((r,i)=>r.event_id!==m.traceEventIds[i]||r.session_id!==sessionId))throw fail();
  const traces=raw.map(r=>Object.fromEntries(['event_id','session_id','step','actor','kind','agent_ns','tool_name','params_json','result_json','provider','policy_violation'].filter(k=>r[k]!==undefined).map(k=>[k,r[k]])));
  const owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const runs=(await identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
   FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
   WHERE r.run_id=$1 AND r.owner_key=$2 AND r.status='completed'`,[m.execution.runId,owner])).rows;await check();
  const run=runs[0];if(runs.length!==1||run.run_id!==m.execution.runId||run.owner_key!==owner
   ||run.generation!==m.execution.generation||run.status!=='completed')throw fail();
  const probes=[];
  for(const p of m.probes){
   const request=Probe.request({version:1,lookup:{scope:state.scope,operationId:p.operationId,persona:state.persona,
    personaSession:state.personaSession,mode:state.couponMode.snapshot.mode,code:p.code,coupons:m.couponBank},execution:p.execution});
   const receipt=await readCouponProbeReceipt({scope:state.scope,targetId:p.receipt.targetId,operationId:p.operationId,requestSha256:p.receipt.requestSha256},{signal});await check();
   if(!receipt||!equal(Probe.receipt(receipt,request),p.receipt))throw fail();
   probes.push(structuredClone(p));
  }
  const keys=[...probes.map(p=>p.observation.effectReceipt.effectKey),
   ...(m.version===3&&m.arithmetic?[m.arithmetic.observation.effectReceipt.effectKey]:[])];
  const rows=(await identityPool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,e.effect_key,e.status
   FROM graph_runtime.effects e JOIN graph_runtime.owners o ON o.owner_key=e.owner_key AND o.generation=e.generation
   WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=ANY($4::text[]) AND e.status='completed'`,[run.run_id,owner,run.generation,keys])).rows;await check();
  if(rows.length!==keys.length||new Set(keys).size!==keys.length||new Set(rows.map(r=>r.effect_key)).size!==keys.length
   ||rows.some(r=>!keys.includes(r.effect_key)||r.run_id!==run.run_id||r.owner_key!==owner||r.generation!==run.generation||r.status!=='completed'))throw fail();
  const w=witness(probes);if(!w)throw fail();
  const yes=probes.find(p=>p.operationId===w.trueOperationId);
  const privateReference=await readCouponProbeReference({scope:state.scope,targetId:yes.receipt.targetId,operationId:yes.operationId,requestSha256:yes.receipt.requestSha256,position:w.position},{signal});await check();
  const source={binding:{scope:state.scope,persona:state.persona,personaSession:state.personaSession},sourceBinding:state.sourceBinding,
   turn:{sessionId,requestId,...saved.savedRequest,text:result.text,stopReason:result.stopReason,steps:result.steps,
    hops:result.hops.map(h=>({step:h.step,tool:h.tool,params:h.params,result:h.result})),traces},
   run,effects:keys.map(k=>rows.find(r=>r.effect_key===k)),couponBank:m.couponBank,probes,
   ...(m.version===3?{arithmetic:structuredClone(m.arithmetic),
    ...(Object.hasOwn(m,'continuation')?{continuation:structuredClone(m.continuation)}:{})}:{})};
  return structuredClone({source,privateReference});
 }});
}
module.exports={createCouponBlindEvidenceRepository};
