'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding,createLaunchScope}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const {createHash}=require('node:crypto');
const {validateSource}=require('../../services/secureshopMcpDescriptionEvidence');
const fail=()=>Object.assign(Error('Registered description source unavailable'),{code:'MCP_DESCRIPTION_SOURCE_UNAVAILABLE'});
// Preserve exact original TEXT traces; convert SQL bytea only in the detached proof.
function serial(value){if(value instanceof Uint8Array)return Buffer.from(value).toString('hex');if(value instanceof Date)return value.toISOString();if(Array.isArray(value))return value.map(serial);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,serial(v)]));return value;}
function createMcpDescriptionEvidenceRepository({identityPool,launches,conversationRepository,journal,registryRepository,invocationJournal,current,qualifyModelTrace}={}){
 for(const fn of [launches?.assertCurrent,identityPool?.query,conversationRepository?.getTraceEvents,journal?.readRegisteredAdminRequest,registryRepository?.readAssessmentManifest,invocationJournal?.readCompleted,current,qualifyModelTrace])if(typeof fn!=='function')throw TypeError('Description source dependencies required');
 const conversations=require('../../services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRepository,launches});
 return Object.freeze({async readSource(context,{sessionId,requestId,signal}={}){
  const held=await current(context,{requestId,signal}),{state,check}=held;
  await check();const binding=createConversationBinding(state.scope,state.persona);
  await conversations.assertOwned(sessionId,binding,state.persona,'general');
  const row=await journal.readRegisteredAdminRequest({sessionId,requestId,binding}),meta=row?.result_json?.taskMetadata?.registeredAdmin,capture=row?.result_json?.taskMetadata?.registeredDescription;
  await check();if(row?.status!=='completed'||meta?.version!==3||!capture||row.session_id!==sessionId||row.request_id!==requestId)throw fail();
  const personaHash=createHash('sha256').update(JSON.stringify(['registered-admin-persona-v1',binding,state.personaSession.sessionId,state.personaSession.authorityVersion])).digest('hex');
  const encoded=JSON.stringify({version:1,message:meta.message,personaSessionSha256:personaHash});
  if(meta.personaSessionSha256!==personaHash||!equal(meta.execution,state.sourceBinding.registeredMode)||row.request_hash!==createTurnRequest({sessionId,requestId,binding,message:encoded}).hash)throw fail();
  const publications=await registryRepository.readAssessmentManifest({...context,entries:capture.entries});await check();
  const traces=await conversationRepository.getTraceEvents(sessionId,binding,meta.traceEventIds,'general');await check();
  const ids=new Set();for(const t of traces){if(t.kind==='mcp_result'){const v=JSON.parse(t.result_json);if(v?._meta?.ownedRegistryInvocation?.request?.operationId)ids.add(v._meta.ownedRegistryInvocation.request.operationId);}}
  if(ids.size!==1)throw fail();
  const stored=await invocationJournal.readCompleted({scope:binding,invocationId:[...ids][0]});await check();
  const req=stored?.envelope?.request,owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  if(req?.requestId!==requestId)throw fail();
  const runs=(await identityPool.query('SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status FROM graph_runtime.runs r JOIN graph_runtime.owners g ON g.owner_key=r.owner_key AND g.generation=r.generation WHERE r.run_id=$1 AND r.owner_key=$2',[req.runId,owner])).rows;
  const effects=(await identityPool.query('SELECT e.run_id,e.owner_key,e.generation::text AS generation,e.effect_key,e.status FROM graph_runtime.effects e JOIN graph_runtime.owners g ON g.owner_key=e.owner_key AND g.generation=e.generation WHERE e.run_id=$1 AND e.owner_key=$2 AND e.effect_key=$3',[req.runId,owner,stored.envelope.effectKey])).rows;
  await check();if(runs.length!==1||effects.length!==1)throw fail();
  const source=serial({binding:{scope:createLaunchScope(binding),persona:state.persona,personaSession:state.personaSession},sourceBinding:state.sourceBinding,turn:{sessionId,requestId,record:row},publications,stored,traces,run:runs[0],effects});
  try{validateSource(source,qualifyModelTrace);}catch{throw fail();}await check();return {source};
 }});
}
module.exports={createMcpDescriptionEvidenceRepository};
