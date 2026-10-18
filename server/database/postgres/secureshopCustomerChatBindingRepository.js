'use strict';
const {createHash}=require('node:crypto');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {executionScope}=require('../../services/secureshopSceneBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=code=>Object.assign(new Error('Customer chat binding unavailable'),{code});
function capture({sessionId,requestId,scope,persona,personaSession,target,message}){
 const b=createConversationBinding(scope,persona),s=target?.scene,e=executionScope(target);
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!UUID.test(personaSession?.sessionId||'')
  ||!isPositive(personaSession?.authorityVersion)||!s||!UUID.test(s.sceneId||'')||!UUID.test(s.grantId||'')
  ||!UUID.test(target.targetId||'')||!Number.isSafeInteger(s.sceneGeneration)||s.sceneGeneration<1
  ||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k=>e[k]!==b[k])
  ||typeof message!=='string'||!message.trim()||Buffer.byteLength(message,'utf8')>16384)throw fail('INVALID_ARGUMENT');
 const row={sessionId:sessionId.toLowerCase(),requestId:requestId.toLowerCase(),launchId:b.launchId,scenarioId:b.scenarioId,
  generation:b.generation,ownerId:b.platformOwnerId,executionSessionId:b.platformSessionId,personaId:b.shopUserId,
  personaSessionId:personaSession.sessionId.toLowerCase(),authorityVersion:String(personaSession.authorityVersion),
  sceneId:s.sceneId.toLowerCase(),sceneGeneration:s.sceneGeneration,grantId:s.grantId.toLowerCase(),targetId:target.targetId.toLowerCase()};
 row.envelopeSha256=createHash('sha256').update(JSON.stringify(['customer-chat-v1',row,message])).digest('hex');
 row.requestHash=createTurnRequest({sessionId,requestId,binding:b,message}).hash;
 return Object.freeze(row);
}
function isPositive(value){return typeof value==='string'&&/^[1-9]\d*$/.test(value)&&BigInt(value)<=9223372036854775807n;}
const DB=['session_id','request_id','launch_id','scenario_id','generation','owner_id','execution_session_id','persona_id','persona_session_id','authority_version','scene_id','scene_generation','grant_id','target_id','envelope_sha256','request_hash'];
const JS=['sessionId','requestId','launchId','scenarioId','generation','ownerId','executionSessionId','personaId','personaSessionId','authorityVersion','sceneId','sceneGeneration','grantId','targetId','envelopeSha256','requestHash'];
function same(row, expected){return DB.every((key,i)=>String(row[key])===String(expected[JS[i]]));}
function createCustomerChatBindingRepository({pool}={}){
 if(typeof pool?.connect!=='function')throw new TypeError('Customer chat binding pool required');
 return Object.freeze({
  capture,
  async reserve(input){
   const expected=capture(input),c=await pool.connect();
   try{await c.query('BEGIN');
    const owner=(await c.query(`SELECT id FROM secureshop_agents.agent_sessions WHERE id=$1 AND authority_mode='launch_bound'
      AND binding_state='active' AND conversation_purpose='secureshop_customer_chat' AND platform_launch_id=$2
      AND platform_scenario_id=$3 AND platform_launch_generation=$4 AND original_platform_owner_id=$5
      AND original_platform_session_id=$6 AND user_id=$7 AND role='customer' FOR SHARE`,
     [expected.sessionId,expected.launchId,expected.scenarioId,expected.generation,expected.ownerId,expected.executionSessionId,expected.personaId])).rows;
    if(owner.length!==1)throw fail('CONVERSATION_UNAVAILABLE');
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`customer-chat:${expected.sessionId}`]);
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`customer-chat-owner:${expected.ownerId}:${expected.personaId}:${expected.requestId}`]);
    const occupied=(await c.query('SELECT session_id FROM secureshop_agents.customer_chat_turn_bindings WHERE owner_id=$1 AND persona_id=$2 AND request_id=$3',
      [expected.ownerId,expected.personaId,expected.requestId])).rows[0];
    if(occupied&&occupied.session_id!==expected.sessionId)throw fail('TURN_REQUEST_CONFLICT');
    const existing=(await c.query('SELECT * FROM secureshop_agents.customer_chat_turn_bindings WHERE session_id=$1 AND request_id=$2',
      [expected.sessionId,expected.requestId])).rows[0];
    if(existing){if(!same(existing,expected))throw fail('TURN_REQUEST_CONFLICT');await c.query('COMMIT');return expected;}
    const count=Number((await c.query('SELECT count(*)::integer AS n FROM secureshop_agents.customer_chat_turn_bindings WHERE session_id=$1',[expected.sessionId])).rows[0].n);
    if(count>=64)throw fail('TURN_CAPACITY');
    await c.query(`INSERT INTO secureshop_agents.customer_chat_turn_bindings (${DB.join(',')}) VALUES (${DB.map((_,i)=>'$'+(i+1)).join(',')})`,JS.map(k=>expected[k]));
    await c.query('COMMIT');return expected;
   }catch(error){try{await c.query('ROLLBACK')}catch{}throw error}finally{c.release()}
  },
  async read({sessionId,requestId,scope,persona}){
   const b=createConversationBinding(scope,persona);
   if(!UUID.test(sessionId||'')||!UUID.test(requestId||''))throw fail('INVALID_ARGUMENT');
   const c=await pool.connect();try{
    const rows=(await c.query(`SELECT t.* FROM secureshop_agents.customer_chat_turn_bindings t
      JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE t.session_id=$1 AND t.request_id=$2 AND s.authority_mode='launch_bound'
      AND s.conversation_purpose='secureshop_customer_chat' AND s.binding_state='active'
      AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
      AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role=$9`,
     [sessionId.toLowerCase(),requestId.toLowerCase(),b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role])).rows;
    return rows.length===1?Object.freeze(rows[0]):null;
   }finally{c.release()}
  },
  async readLatestCatalogPage({sessionId,scope,persona,personaSession,target}){
   const b=createConversationBinding(scope,persona),s=target?.scene;
   if(b.role!=='customer'||!UUID.test(sessionId||'')||!UUID.test(personaSession?.sessionId||'')
    ||!isPositive(personaSession?.authorityVersion)||!s||!UUID.test(s.sceneId||'')
    ||!UUID.test(s.grantId||'')||!UUID.test(target.targetId||'')
    ||!Number.isSafeInteger(s.sceneGeneration)||s.sceneGeneration<1)throw fail('INVALID_ARGUMENT');
   const c=await pool.connect();try{
    const rows=(await c.query(`SELECT t.*,tr.result_json,tr.request_hash AS turn_request_hash,
        tr.request_version AS turn_request_version
      FROM secureshop_agents.customer_chat_turn_bindings t
      JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      JOIN secureshop_agents.turn_requests tr ON tr.session_id=t.session_id AND tr.request_id=t.request_id
      WHERE t.session_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4
        AND t.owner_id=$5 AND t.execution_session_id=$6 AND t.persona_id=$7
        AND t.persona_session_id=$8 AND t.authority_version=$9
        AND t.scene_id=$10 AND t.scene_generation=$11 AND t.grant_id=$12 AND t.target_id=$13
        AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.conversation_purpose='secureshop_customer_chat' AND s.role='customer' AND s.user_id=$7
        AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
        AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
        AND tr.status='completed' AND tr.request_version=1
        AND tr.result_json->>'stopReason'='end_turn'
        AND jsonb_typeof(tr.result_json #> '{taskMetadata,customerChat,catalogPageSource}')='object'
      ORDER BY t.created_at DESC,t.request_id DESC LIMIT 1`,
     [sessionId.toLowerCase(),b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,
      b.shopUserId,personaSession.sessionId.toLowerCase(),personaSession.authorityVersion,
      s.sceneId,s.sceneGeneration,s.grantId,target.targetId])).rows;
    return rows[0]?Object.freeze(rows[0]):null;
   }finally{c.release()}
  },
 });
}
module.exports={createCustomerChatBindingRepository,capture};
