'use strict';
// Real shared LangGraph runner with controlled provider, authority and persistence.
// Does not establish actual model calls, PostgreSQL containment or Judge credit.
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto');
const {createSecureShopBoundAnalytics}=require('../../server/services/secureshopBoundAnalytics');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
const persona={id:3,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
const sql="SELECT username FROM shop_users UNION SELECT secret FROM teaching_secrets -- intentionally raw";
const {hash:canonicalHash}=require('../../sidecars/analytics-sql-target/contract');
const sha=v=>createHash('sha256').update(v).digest('hex');
function fixture(options={}){
 const sessions=new Map(),messages=new Map(),requests=new Map(),traces=[],queries=[];let calls=0,finalCalls=0;
 const repo={async getBoundSession(id){return sessions.get(id);},async acquireBoundSession({id,binding,purpose}){
   const prior=[...sessions.values()].find(s=>JSON.stringify(s.binding)===JSON.stringify(binding)&&s.purpose===purpose);if(prior)return prior;
   const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;
  },async activateBoundSession(id){sessions.get(id).state='active';return true;},async getMessages(id){return structuredClone(messages.get(id)||[]);},
  async appendMessage(id,_binding,m){messages.set(id,[...(messages.get(id)||[]),structuredClone(m)]);},async getTokens(){return 0;},async addTokens(){},async appendTraces(_id,_binding,rows){traces.push(...structuredClone(rows));}};
 const journal={async claim({requestId,requestDigest}){if(requests.has(requestId))return requests.get(requestId);const value={status:'claimed',claimId:requestId};requests.set(requestId,value);return value;},async complete({requestId,result}){requests.set(requestId,{status:'completed',claimId:requestId,result:structuredClone(result)});},async markUncertain(){}};
 const coordinator={async run(_owner,opts,work){const admitted=await opts.admit();if(admitted.skip)return admitted.value;const runId=randomUUID();return work({runId,ownerKey:'analytics-owner',generation:1,durableGeneration:'1',signal:opts.signal,check:async()=>{},effect:async(_key,fn)=>fn(),effectWithReceipt:async(key,fn)=>({value:await fn(),receipt:options.missingEffect?null:{version:1,runId,ownerKey:'analytics-owner',generation:'1',status:'completed',effectKey:`${opts.idempotencyKey}:${key}`}}),trace:async()=>{}});}};
 let revoked=false;
 const authority={capture:async({scope,personaId,role,...session})=>({binding:{...scope,personaId,role,...session,...options.fenceBinding},assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},withPersonaEffect:async fn=>fn({})})};
 const provider={async chat(){calls++;return{stop_reason:'tool_use',tool_uses:[{id:'query-1',name:options.tool||'analytics.execute_query',args:options.args||{sql}}],provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,...options.decision};},async finalResponse(){finalCalls++;return{stop_reason:'end_turn',responseMode:'structured_final',text:'Observed synthetic secret',provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,...options.final};}};
 const target={targetId:randomUUID(),scope,sourceManifestSha256:'a'.repeat(64)};
 const ownedQuery={resolve:async()=>target,schema:'shop_users(username text); teaching_secrets(secret text)',async execute(input){queries.push(input);if(options.revokeAfterQuery)revoked=true;const result={sql:input.sql,columns:['username'],rows:[{username:'SYNTHETIC_ONLY'}],row_count:1,error:null};
  const receipt={version:1,operationId:input.operationId,targetId:target.targetId,scope:input.scope,runId:input.runId,requestId:input.requestId,sessionId:input.sessionId,callId:input.callId,sqlSha256:sha(input.sql),sourceManifestSha256:'a'.repeat(64),resultSha256:canonicalHash(result),result};
  if(options.mutateReceipt)options.mutateReceipt(receipt);return receipt;}};
 const effectiveQuery=options.ownedQuery||ownedQuery;
 const service=createSecureShopBoundAnalytics({launches:{assertCurrent:async()=>{}},conversationRepository:repo,journal,coordinator,provider,personaAuthority:authority,ownedQuery:effectiveQuery});
 const input={scope,persona,personaSession,question:'Show customer names',requestId:randomUUID(),signal:undefined};
 return{service,input,traces,queries,sessions,messages,calls:()=>calls,finalCalls:()=>finalCalls};
}

module.exports={fixture};
