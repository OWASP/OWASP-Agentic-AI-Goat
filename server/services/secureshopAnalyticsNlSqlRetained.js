"use strict";
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('./secureshopConversationPurpose');
const {readAnalyticsNlSqlOriginal}=require('./secureshopAnalyticsNlSqlEvidence');
const PURPOSE=SECURESHOP_CONVERSATION_PURPOSES.analytics;
const fail=()=>Object.assign(Error('Retained Analytics NL SQL evidence unavailable'),{code:'ANALYTICS_NL_SQL_ORIGINAL_UNAVAILABLE'});
const need=value=>{if(!value)throw fail();};
function comparableTrace(row){
 const result={};for(const [key,value] of Object.entries(row)){
  if(key==='id'||key==='ts')continue;
  result[key]=['params_json','result_json'].includes(key)&&typeof value==='string'?JSON.parse(value):value;
 }return result;
}
// Recheck original immutable readbacks and live authority only. No actor,
// target provisioning, tool execution, or Judge invocation is available here.
function createAnalyticsNlSqlRetained({foundation,requests,conversations,identityPool,modeAuthority,qualifyModel}={}){
 for(const fn of [foundation?.recover,requests?.read,conversations?.getBoundSession,conversations?.getTraceEvents,
  identityPool?.query,modeAuthority?.capture,modeAuthority?.assertToken,qualifyModel])if(typeof fn!=='function')throw TypeError('Retained Analytics evidence dependencies required');
 return Object.freeze({async assertRetainedPacket({packet,scope,persona,personaSession}={}){
  try {
   const source=readAnalyticsNlSqlOriginal(packet,qualifyModel);need(source);
   // Detach caller authority before the first await and retain it for rechecks.
   scope=structuredClone(scope);persona=structuredClone(persona);personaSession=structuredClone(personaSession);
   const binding=createConversationBinding(scope,persona),{sessionId,requestId}=source.context;
   need(equal(binding,source.context.binding));
   need(!Object.hasOwn(source.result,'taskMetadata')&&!Object.hasOwn(source.result,'modeCapability'));
   const expectedMetadata={analytics:{version:1,personaSession,receipt:source.receipt,
    effectReceipt:source.observations[0].effectReceipt,provider:source.projection.provider,model:source.projection.model}};
   const assertCurrent=async()=>{
    try {
     const token=modeAuthority.assertToken(await modeAuthority.capture(scope));
     need(token?.mode?.mode==='vuln'&&equal(token.mode,source.receipt.mode)&&typeof token.assertCurrent==='function');
     await token.assertCurrent();
     const saved=await requests.read({scope,persona,personaSession,requestId});
     need(saved?.status==='completed'&&saved.sessionId===sessionId&&saved.requestId===requestId
      &&saved.question===source.question&&equal(saved.modeSnapshot,source.receipt.mode));
     const {taskMetadata,modeCapability,...originalResult}=saved.result||{};
     need(equal(originalResult,source.result)&&equal(taskMetadata,expectedMetadata)
      &&equal(modeCapability,source.projection.modeCapability));
     const recovered=await foundation.recover({scope,persona,personaSession,requestId,signal:undefined});
     need(equal(recovered,{status:'completed',...source.projection}));
     const session=await conversations.getBoundSession(sessionId);
     need(session?.id===sessionId&&session.state==='active'&&session.purpose===PURPOSE&&equal(session.binding,binding));
     const ids=source.traces.map(row=>row.event_id);
     const traces=await conversations.getTraceEvents(sessionId,binding,ids,PURPOSE);
     need(Array.isArray(traces)&&equal(traces.map(row=>row.event_id),ids)
      &&traces.every((row,i)=>row.session_id===sessionId&&/^[1-9][0-9]*$/.test(String(row.id))
       &&(!i||BigInt(row.id)>BigInt(traces[i-1].id)))
      &&equal(traces.map(comparableTrace),source.traces.map(comparableTrace)));
     const x=source.execution;
     const run=await identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
      FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
      WHERE r.run_id=$1 AND r.owner_key=$2 AND r.generation=$3 AND r.status='completed'`,[x.runId,x.ownerKey,x.durableGeneration]);
     need(run.rows?.length===1&&equal(run.rows[0],{run_id:x.runId,owner_key:x.ownerKey,generation:x.durableGeneration,status:'completed'}));
     const e=source.observations[0].effectReceipt;
     const effect=await identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4 AND status='completed'`,
      [x.runId,x.ownerKey,x.durableGeneration,e.effectKey]);
     need(effect.rows?.length===1&&equal(effect.rows[0],{run_id:x.runId,owner_key:x.ownerKey,generation:x.durableGeneration,effect_key:e.effectKey,status:'completed'}));
     const reread=await requests.read({scope,persona,personaSession,requestId});
     need(equal(reread,saved));await token.assertCurrent();
    }catch{throw fail();}
   };
   await assertCurrent();return Object.freeze({assertCurrent});
  }catch{throw fail();}
 }});
}
module.exports={createAnalyticsNlSqlRetained};
