'use strict';

// Exact original summary projection, admitted by the current branded scene grant.
const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const { withTransaction } = require('../database/postgres/index');
const { executionScope, assertSceneGrant, withSceneLease } = require('./secureshopSceneBinding');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BIRTH = ['targetId','launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const SESSION_COLUMNS = ['platform_launch_id','platform_scenario_id','platform_launch_generation',
  'original_platform_owner_id','original_platform_session_id','user_id','role'];
const fail = () => Object.assign(Error('Product summary source unavailable'), { code: 'PRODUCT_SUMMARY_SOURCE_UNAVAILABLE' });
const need = ok => { if (!ok) throw fail(); };
const parse = value => { try { return JSON.parse(value); } catch { throw fail(); } };
const byteSize = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const coordinates = b => [b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role];
const predicate = (alias, start) => SESSION_COLUMNS.map((column, index) => `${alias}.${column}=$${start+index}`).join(' AND ');
const TURN_COLUMNS = `tr.session_id,tr.request_id,tr.request_version,tr.request_hash,tr.status,tr.result_json,
 CASE WHEN octet_length(s.messages_json)<=1048576 THEN s.messages_json ELSE NULL END AS messages_json,
 s.platform_launch_id,s.platform_scenario_id,s.platform_launch_generation,
 s.original_platform_owner_id,s.original_platform_session_id,s.user_id,s.role`;
const { validateProductSummarySourceContract } = require('./secureshopProductSummarySourceContract');
function number(value) { const n=Number(value); need(Number.isSafeInteger(n)&&n>0); return n; }
function createProductSummarySourceReader({agentsPool,identityPool,reviewPool,current,qualifyModel}={}) {
  for(const dependency of [agentsPool?.query,identityPool?.query,reviewPool?.connect,current,qualifyModel])
    if(typeof dependency!=='function')throw TypeError('Product summary source dependencies required');
  async function query(state, pool, sql, params) {
    await state.check(); const result=await pool.query(sql,params); await state.check(); return result;
  }
  async function admitted(state, work) {
    need(state && typeof state.check==='function' && state.target?.scene && state.binding?.role==='customer'
      && state.persona?.role==='customer' && state.persona.id===state.binding.shopUserId);
    const b=createConversationBinding(state.binding,state.persona), target=state.target;
    need(equal(b,state.binding) && equal(createLaunchScope(b),executionScope(target)));
    await state.check();
    return withSceneLease(target,()=>withTransaction(reviewPool,async client=>{
      await assertSceneGrant(client,target);
      const rows=(await query(state,client,`SELECT t.target_id FROM secureshop_review.product_targets t
        WHERE t.target_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4
        AND t.original_platform_owner_id=$5 AND t.original_platform_session_id=$6
        AND t.lifecycle='active' FOR SHARE OF t`,BIRTH.map(key=>target[key]))).rows;
      need(rows.length===1);
      const result=await work(client);
      await assertSceneGrant(client,target);await state.check();return result;
    }));
  }
  async function original(state,row,purpose,kind,expectedBinding) {
    need(row?.status==='completed' && row.request_version===1 && UUID.test(row.session_id||'') && UUID.test(row.request_id||'')
      && row.result_json && byteSize(row.result_json)<=262144 && typeof row.messages_json==='string');
    const binding=createConversationBinding({launchId:row.platform_launch_id,scenarioId:row.platform_scenario_id,
      generation:number(row.platform_launch_generation),platformOwnerId:number(row.original_platform_owner_id),
      platformSessionId:number(row.original_platform_session_id)},{id:number(row.user_id),role:row.role});
    need(equal(binding,expectedBinding));
    const result=row.result_json,origin=result.taskMetadata?.productSummaryOrigin;
    need(origin?.version===1 && equal(origin.binding,binding) && origin.source?.sessionId===row.session_id
      && origin.source?.requestId===row.request_id && UUID.test(origin.runId||'')
      && UUID.test(origin.personaSession?.sessionId||'') && /^[1-9]\d*$/.test(origin.personaSession?.authorityVersion||''));
    if(kind==='consumer')need(equal(origin.personaSession,state.personaSession));
    const messages=parse(row.messages_json);need(Array.isArray(messages));
    const matches=new Set();
    for(const message of messages){
      if(message?.role!=='user'||typeof message.content!=='string'||Buffer.byteLength(message.content)>65536)continue;
      if(createTurnRequest({sessionId:row.session_id,requestId:row.request_id,binding,message:message.content}).hash===row.request_hash)matches.add(message.content);
    }
    need(matches.size===1);
    const ids=origin.traceEventIds;need(Array.isArray(ids)&&ids.length>=4&&ids.length<=4096
      && ids.every(id=>UUID.test(id||''))&&new Set(ids).size===ids.length);
    const traces=(await query(state,agentsPool,`WITH original_traces AS (
      SELECT t.event_id,t.id::text AS id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,
       t.params_json,t.result_json,t.provider,t.policy_violation
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.id=$1 AND s.authority_mode='launch_bound' AND s.conversation_purpose=$2
       AND ${predicate('s',3)} AND t.event_id=ANY($10::text[])
    ) SELECT * FROM original_traces WHERE
      (SELECT COALESCE(sum(octet_length(row_to_json(o)::text)),0) FROM original_traces o)<=1048576
      ORDER BY id::bigint`,[row.session_id,purpose,...coordinates(binding),ids])).rows;
    need(traces.length===ids.length && equal(traces.map(trace=>trace.event_id),ids));
    const tool='summarizer.summarize_product';
    const hops=result.hops?.filter(hop=>hop.tool===tool);need(hops?.length===1);
    const hop=hops[0];need(hop.error===null&&hop.policyViolation===null);
    const decisions=traces.filter(trace=>trace.kind==='model_decision'&&trace.actor==='supervisor'
      &&trace.step===hop.step&&parse(trace.params_json||'null')?.decision==='tool_use');
    need(decisions.length===1);
    const calls=parse(decisions[0].params_json).toolCalls;
    need(Array.isArray(calls)&&calls.length===1&&calls[0].name===tool&&equal(calls[0].args,hop.params)
      &&typeof calls[0].id==='string'&&calls[0].id.length>0&&Buffer.byteLength(calls[0].id)<=128);
    const owner=JSON.stringify(['SecureShopBoundConversation',row.session_id]);
    // Historical completed generation is evidence. Current authority belongs to
    // the consumer scene; joining graph owners' *current* generation is wrong.
    const runs=(await query(state,identityPool,`SELECT run_id,owner_key,generation::text AS generation,status
      FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2 AND status='completed'`,[origin.runId,owner])).rows;
    need(runs.length===1);
    const effectKey=`${row.request_id}:${JSON.stringify([hop.step,calls[0].id,tool])}`;
    const effects=(await query(state,identityPool,`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4 AND status='completed'`,
    [origin.runId,owner,runs[0].generation,effectKey])).rows;
    need(effects.length===1);
    return freeze({origin,original:{binding,personaSession:origin.personaSession,sessionId:row.session_id,
      requestId:row.request_id,message:[...matches][0],requestVersion:row.request_version,requestHash:row.request_hash,
      status:row.status,traceEventIds:ids,traces,result,run:runs[0],effect:effects[0]}});
  }
  return async function readProductSummarySource(context,request) {
    need(UUID.test(request?.sessionId||'')&&UUID.test(request?.requestId||'')&&Object.keys(request).sort().join(',')==='requestId,sessionId');
    const state=await current(context);
    return admitted(state,async()=>{
      const rows=(await query(state,agentsPool,`SELECT ${TURN_COLUMNS}
        FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
        WHERE tr.request_id=$1 AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound'
        AND ${predicate('s',3)} LIMIT 2`,[request.requestId,PURPOSES.productAssist,...coordinates(state.binding)])).rows;
      need(rows.length===1&&rows[0].session_id===request.sessionId);
      const captured=await original(state,rows[0],PURPOSES.productAssist,'consumer',state.binding);
      need(equal(captured.origin.execution,state.execution));
      try {
        const result=validateProductSummarySourceContract({...captured,target:state.target,qualifyModel});
        await state.check();return freeze(result);
      } catch(error) { if(error?.code==='PRODUCT_SUMMARY_SOURCE_INVALID')throw fail();throw error; }
    });
  };
}
module.exports={createProductSummarySourceReader};
