'use strict';
const {withTransaction}=require('./index');
const fail=(code,message)=>Object.assign(new Error(message),{code});
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
function validate({userId,requestId,execution}){
 if(!Number.isSafeInteger(userId)||userId<1||userId>2147483647||!uuid(requestId)||!uuid(execution?.runId)
  ||execution.ownerKey!==JSON.stringify(['MCP',String(userId)])||typeof execution.check!=='function'
  ||!/^(0|[1-9][0-9]*)$/.test(String(execution.durableGeneration)))throw fail('BAD_REQUEST','Valid request and current execution required');
}
async function current(client,execution){
 const owner=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[execution.ownerKey])).rows[0];
 if(!owner||String(owner.generation)!==String(execution.durableGeneration))throw fail('STALE_GENERATION','Request predates reset');
 const run=(await client.query('SELECT owner_key,generation,status FROM graph_runtime.runs WHERE run_id=$1 FOR UPDATE',[execution.runId])).rows[0];
 if(!run||run.owner_key!==execution.ownerKey||String(run.generation)!==String(owner.generation)||run.status!=='running')throw fail('STALE_RUN','Request run is not active');
}
function createMcpRequestRepository(pool){
 return {
  async admit({userId,requestId,execution,userText}){
   validate({userId,requestId,execution});
   if(typeof userText!=='string'||!userText.length||Buffer.byteLength(userText)>16384)throw fail('BAD_REQUEST','Invalid message');
   await execution.check();
   return withTransaction(pool,async client=>{
    await current(client,execution);
    const prior=(await client.query(`SELECT q.*,r.status FROM workshop_conversations.requests q
     JOIN graph_runtime.runs r ON r.run_id=q.run_id WHERE q.user_id=$1 AND q.request_id=$2`,[userId,requestId])).rows[0];
    if(prior){
     if(prior.owner_key!==execution.ownerKey||String(prior.generation)!==String(execution.durableGeneration))throw fail('STALE_REQUEST','Request belongs to an earlier conversation');
     if(prior.user_text!==userText)throw fail('IDEMPOTENCY_CONFLICT','Request message differs');
     if(prior.response_json!==null&&prior.status==='completed')return {state:'replay',response:prior.response_json};
     throw fail('REQUEST_UNCERTAIN','Request was already started; tools must not be repeated');
    }
    const count=(await client.query('SELECT count(*)::int AS n FROM workshop_conversations.requests WHERE owner_key=$1 AND generation=$2',[execution.ownerKey,execution.durableGeneration])).rows[0].n;
    if(count>=200)throw fail('CONVERSATION_LIMIT','Conversation request limit reached');
    await client.query('INSERT INTO workshop_conversations.requests(user_id,request_id,owner_key,generation,run_id,user_text) VALUES($1,$2,$3,$4,$5,$6)',[userId,requestId,execution.ownerKey,execution.durableGeneration,execution.runId,userText]);
    return {state:'admitted'};
   });
  },
  async complete({userId,requestId,execution,response}){
   validate({userId,requestId,execution});
   if(!response||typeof response!=='object'||Array.isArray(response))throw fail('BAD_REQUEST','Response object required');
   if(typeof response.response!=='string'||!response.response.length||Buffer.byteLength(response.response)>32768)throw fail('BAD_REQUEST','Bounded assistant response required');
   let serialized;try{serialized=JSON.stringify(response);}catch{throw fail('BAD_REQUEST','Serializable response required');}
   if(!serialized||Buffer.byteLength(serialized)>65536)throw fail('BAD_REQUEST','Response exceeds limit');
   await execution.check();
   return withTransaction(pool,async client=>{
    await current(client,execution);
    const row=(await client.query('SELECT run_id,response_json,user_text FROM workshop_conversations.requests WHERE user_id=$1 AND request_id=$2 FOR UPDATE',[userId,requestId])).rows[0];
    if(!row||row.run_id.toLowerCase()!==execution.runId.toLowerCase())throw fail('REQUEST_OWNER_MISMATCH','Only the admitted run can complete a request');
    if(row.response_json!==null){
     const equal=(await client.query('SELECT $1::jsonb=$2::jsonb AS equal',[JSON.stringify(row.response_json),serialized])).rows[0].equal;
     if(!equal)throw fail('IDEMPOTENCY_CONFLICT','Completed response differs');
     return {replayed:true};
    }
    await client.query('UPDATE workshop_conversations.requests SET response_json=$3::jsonb WHERE user_id=$1 AND request_id=$2',[userId,requestId,serialized]);
    await client.query('INSERT INTO workshop_conversations.turns(run_id,user_id,owner_key,generation,user_text,assistant_text) VALUES($1,$2,$3,$4,$5,$6)',[execution.runId,userId,execution.ownerKey,execution.durableGeneration,row.user_text,response.response]);
    return {replayed:false};
   });
  },
 };
}
module.exports={createMcpRequestRepository};
