'use strict';
const {withTransaction}=require('./index');

function invalid(code,message){return Object.assign(new Error(message),{code});}
function scope(userId){
 if(!Number.isSafeInteger(userId)||userId<1||userId>2147483647)throw invalid('BAD_REQUEST','Valid user required');
 return JSON.stringify(['MCP',String(userId)]);
}
function content(value,max){
 if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>max)throw invalid('BAD_REQUEST','Invalid conversation content');
 return value;
}
function executionScope(userId,execution){
 const ownerKey=scope(userId);
 if(execution?.ownerKey!==ownerKey||typeof execution.check!=='function'
  ||typeof execution.runId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(execution.runId)
  ||!/^(0|[1-9][0-9]*)$/.test(String(execution.durableGeneration)))throw invalid('BAD_REQUEST','Current MCP execution required');
 return ownerKey;
}

// Not mounted until the draft schema and native lifecycle tests are qualified.
function createMcpConversationRepository(pool){
 return {
  async clearBeforeCurrentGeneration(userId){
   const ownerKey=scope(userId);
   return withTransaction(pool,async client=>{
    const owner=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[ownerKey])).rows[0];
    if(!owner)return {removedTurns:0};
    const removed=await client.query('DELETE FROM workshop_conversations.turns WHERE user_id=$1 AND owner_key=$2 AND generation<$3',[userId,ownerKey,owner.generation]);
    await client.query('UPDATE workshop_conversations.requests SET user_text=NULL,response_json=NULL WHERE user_id=$1 AND owner_key=$2 AND generation<$3',[userId,ownerKey,owner.generation]);
    return {removedTurns:removed.rowCount};
   });
  },
  async append({userId,execution,userText,assistantText}){
   const ownerKey=executionScope(userId,execution);
   userText=content(userText,16384);assistantText=content(assistantText,32768);
   await execution.check();
   return withTransaction(pool,async client=>{
    // Row locking shares reset's generation-update boundary. Do not acquire
    // the run's session advisory lock on this second pooled connection.
    const owner=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[ownerKey])).rows[0];
    if(!owner||String(owner.generation)!==String(execution.durableGeneration))throw invalid('STALE_GENERATION','Conversation predates reset');
    const run=(await client.query('SELECT owner_key,generation,status FROM graph_runtime.runs WHERE run_id=$1 FOR UPDATE',[execution.runId])).rows[0];
    if(!run||run.owner_key!==ownerKey||String(run.generation)!==String(owner.generation)||run.status!=='running')throw invalid('STALE_RUN','Conversation run is not active');
    const prior=(await client.query('SELECT user_id,owner_key,generation,user_text,assistant_text FROM workshop_conversations.turns WHERE run_id=$1',[execution.runId])).rows[0];
    if(prior){
     if(prior.user_id!==userId||prior.owner_key!==ownerKey||String(prior.generation)!==String(owner.generation)||prior.user_text!==userText||prior.assistant_text!==assistantText)throw invalid('IDEMPOTENCY_CONFLICT','Conversation turn differs');
     return {replayed:true};
    }
    const count=(await client.query('SELECT count(*)::int AS n FROM workshop_conversations.turns WHERE owner_key=$1 AND generation=$2',[ownerKey,owner.generation])).rows[0].n;
    if(count>=200)throw invalid('CONVERSATION_LIMIT','Reset the conversation before adding more turns');
    await client.query('INSERT INTO workshop_conversations.turns(run_id,user_id,owner_key,generation,user_text,assistant_text) VALUES($1,$2,$3,$4,$5,$6)',[execution.runId,userId,ownerKey,owner.generation,userText,assistantText]);
    return {replayed:false};
   });
  },
  async list(userId){
   const ownerKey=scope(userId);
   // A stored response is visible only once its run completes. Failed runs
   // and old generations never become conversational evidence on reload.
   return (await pool.query(`SELECT t.run_id AS "runId",t.user_text AS "userText",t.assistant_text AS "assistantText",t.created_at AS "createdAt"
    FROM workshop_conversations.turns t JOIN graph_runtime.owners o ON o.owner_key=t.owner_key AND o.generation=t.generation
    JOIN graph_runtime.runs r ON r.run_id=t.run_id AND r.owner_key=t.owner_key AND r.generation=t.generation AND r.status='completed'
    WHERE t.user_id=$1 AND t.owner_key=$2 ORDER BY t.created_at,t.run_id LIMIT 200`,[userId,ownerKey])).rows;
  },
 };
}
module.exports={createMcpConversationRepository};
