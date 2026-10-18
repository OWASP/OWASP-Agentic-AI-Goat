'use strict';
const {createHash}=require('node:crypto');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=code=>Object.assign(Error('Analytics request unavailable'),{code});
const digest=value=>createHash('sha256').update(value).digest('hex');
const columns=['launch_id','scenario_id','generation','platform_owner_id','platform_session_id','persona_id','role'];
function binding(input){const scope=createLaunchScope(input.scope),p=input.persona,v=input.personaSession?.authorityVersion;
 if(!Number.isSafeInteger(p?.id)||p.id<1||!['merchant','admin'].includes(p.role)||!UUID.test(input.personaSession?.sessionId)||typeof v!=='string'||!/^[1-9][0-9]{0,18}$/.test(v)||BigInt(v)>9223372036854775807n)throw fail('SHOP_AUTH_INVALID');
 return {scope,persona:{id:p.id,role:p.role},personaSession:{sessionId:input.personaSession.sessionId,authorityVersion:v}};}
const values=x=>[x.scope.launchId,x.scope.scenarioId,x.scope.generation,x.scope.platformOwnerId,x.scope.platformSessionId,x.persona.id,x.persona.role];
const where=prefix=>columns.map((c,i)=>`${prefix}${c}=$${i+1}`).join(' AND ');
function createAnalyticsRequestRepository({personaAuthority}={}){
 if(typeof personaAuthority?.capture!=='function')throw TypeError('Canonical persona authority required');
 async function transaction(raw,work){const input=binding(raw),fence=await personaAuthority.capture({scope:input.scope,personaId:input.persona.id,role:input.persona.role,...input.personaSession});
  const expected={...input.scope,personaId:input.persona.id,role:input.persona.role,...input.personaSession};
  if(typeof fence?.withPersonaEffect!=='function'||typeof fence.assertRemoteAdmission!=='function'||Object.keys(expected).some(k=>fence.binding?.[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
  await fence.assertRemoteAdmission();const result=await fence.withPersonaEffect(client=>work(client,input));await fence.assertRemoteAdmission();return result;
 }
 function original(row,input){if(row.persona_session_id!==input.personaSession.sessionId||String(row.authority_version)!==input.personaSession.authorityVersion)throw fail('SHOP_AUTH_INVALID');}
 function requestId(input){if(!UUID.test(input.requestId))throw fail('ANALYTICS_INVALID_ARGUMENT');return input.requestId;}
 return Object.freeze({
  async admit(raw){const id=requestId(raw),sessionId=raw.sessionId,question=raw.question;
   if(!UUID.test(sessionId)||typeof question!=='string'||!question.trim()||!question.isWellFormed()||question.includes('\0')||Buffer.byteLength(question)>8192)throw fail('ANALYTICS_INVALID_ARGUMENT');const hash=digest(question);const mode=raw.modeSnapshot?require('../../services/secureshopAnalyticsModeAuthority').checkedMode(raw.modeSnapshot):null;
   return transaction(raw,async(client,input)=>{
    // withPersonaEffect already serializes owner+launch across all shop sessions.
    const args=[...values(input),id];const existing=(await client.query(`SELECT * FROM secureshop_agents.analytics_request_admissions WHERE ${where('')} AND request_id=$8`,args)).rows[0];
    if(existing){original(existing,input);if(existing.session_id!==sessionId||existing.question_sha256!==hash||existing.question===null)throw fail('ANALYTICS_REQUEST_CONFLICT');return Object.freeze({created:false,sessionId,requestId:id});}
    const count=Number((await client.query(`SELECT count(*) AS count FROM secureshop_agents.analytics_request_admissions WHERE ${where('')}`,values(input))).rows[0].count);if(count>=256)throw fail('ANALYTICS_REQUEST_CAPACITY');
    await client.query(`INSERT INTO secureshop_agents.analytics_request_admissions(${columns.join(',')},request_id,persona_session_id,authority_version,session_id,question_sha256,question${mode?',mode_snapshot':''}) VALUES(${Array.from({length:mode?14:13},(_,i)=>'$'+(i+1)).join(',')})`,[...args,input.personaSession.sessionId,input.personaSession.authorityVersion,sessionId,hash,question,...(mode?[mode]:[])]);
    return Object.freeze({created:true,sessionId,requestId:id});
   });
  },
  async history(raw){
   const limit=raw.limit;if(!Number.isSafeInteger(limit)||limit<1||limit>50)throw fail('ANALYTICS_INVALID_ARGUMENT');
   let cursor=null;if(raw.cursor!==null&&raw.cursor!==undefined){try{cursor=JSON.parse(Buffer.from(raw.cursor,'base64url').toString('utf8'));if(!Array.isArray(cursor)||cursor.length!==2||typeof cursor[0]!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(cursor[0])||!Number.isFinite(Date.parse(cursor[0]))||!UUID.test(cursor[1])||Buffer.from(JSON.stringify(cursor)).toString('base64url')!==raw.cursor)throw Error();}catch{throw fail('ANALYTICS_INVALID_ARGUMENT');}}
   return transaction(raw,async(client,input)=>{
    const rows=(await client.query(`SELECT request_id,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at FROM secureshop_agents.analytics_request_admissions WHERE ${where('')} AND persona_session_id=$8 AND authority_version=$9 AND question IS NOT NULL ${cursor?'AND (created_at,request_id)<($10::timestamptz,$11::uuid)':''} ORDER BY created_at DESC,request_id DESC LIMIT $${cursor?12:10}`,[...values(input),input.personaSession.sessionId,input.personaSession.authorityVersion,...(cursor||[]),limit+1])).rows;
    const page=rows.slice(0,limit),last=page.at(-1);return Object.freeze({requests:page.map(row=>Object.freeze({requestId:row.request_id,createdAt:row.created_at})),nextCursor:rows.length>limit?Buffer.from(JSON.stringify([last.created_at,last.request_id])).toString('base64url'):null});
   });
  },
  // Private readback packet only. Application validates canonical result/receipt
  // before projecting HTTP. No graph, conversation allocation or model here.
  async read(raw){const id=requestId(raw);return transaction(raw,async(client,input)=>{
   const row=(await client.query(`SELECT a.*,t.status AS turn_status,t.request_hash,t.request_version,t.result_json FROM secureshop_agents.analytics_request_admissions a JOIN secureshop_agents.agent_sessions s ON s.id=a.session_id LEFT JOIN secureshop_agents.turn_requests t ON t.session_id=a.session_id AND t.request_id=a.request_id WHERE ${where('a.')} AND a.request_id=$8 AND s.binding_state='active' AND s.authority_mode='launch_bound' AND s.conversation_purpose='secureshop_analytics'`,[...values(input),id])).rows[0];
   if(!row)return null;original(row,input);if(row.question===null||digest(row.question)!==row.question_sha256)throw fail('ANALYTICS_REQUEST_CONFLICT');
   if(row.turn_status){const {createTurnRequest}=require('../../services/secureshopTurnRequest');const expected=createTurnRequest({sessionId:row.session_id,requestId:id,binding:{...input.scope,shopUserId:input.persona.id,role:input.persona.role},message:row.question,version:row.request_version});if(expected.hash!==row.request_hash)throw fail('ANALYTICS_REQUEST_CONFLICT');}
   if(row.turn_status&&!['started','uncertain','completed'].includes(row.turn_status))throw fail('ANALYTICS_REQUEST_CONFLICT');
   return Object.freeze({sessionId:row.session_id,requestId:id,question:row.question,...(row.mode_snapshot?{modeSnapshot:structuredClone(row.mode_snapshot)}:{}),status:row.turn_status||'admitted',result:row.turn_status==='completed'?structuredClone(row.result_json):null});
  });},
 });
}
module.exports={createAnalyticsRequestRepository};
