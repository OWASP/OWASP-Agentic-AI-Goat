'use strict';

const { normalize } = require('./secureshopBoundMailRepository');
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const { createTurnRequest } = require('../../services/secureshopTurnRequest');
const { consumeMailExecutionCapability } = require('../../services/secureshopMailExecutionCapability');
const { operationId } = require('../../services/secureshopBoundMailGraph');
const mailScene = require('../../services/secureshopMailSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = code => Object.assign(Error('Mail uncertainty unavailable'), { code });
const T = 'secureshop_agents.bound_mail_';
function thread(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw fail('INVALID_ARGUMENT');
  return value;
}
function coordinates(b) {
  return [b.scope.launchId,b.scope.scenarioId,b.scope.generation,
    b.scope.platformOwnerId,b.scope.platformSessionId,b.persona.id,b.persona.role];
}
function message(b,threadId) {
  return JSON.stringify({version:1,targetId:b.targetId,threadId,mode:b.mode,
    operationId:b.operationId,personaSession:b.personaSession});
}
function exactFence(fence,b) {
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(typeof fence?.withPersonaEffect!=='function'||typeof fence?.assertRemoteAdmission!=='function'
    ||!fence.binding||Object.keys(expected).some(key=>fence.binding[key]!==expected[key]))
    throw fail('SHOP_AUTH_INVALID');
  return fence;
}
function stage(value,b,expected) {
  const source=consumeMailExecutionCapability(value,expected);
  const binding=createConversationBinding(b.scope,b.persona);
  if(!source.binding || ['launchId','scenarioId','generation','platformOwnerId',
    'platformSessionId','shopUserId','role'].some(key=>source.binding[key]!==binding[key])
    ||source.requestId!==b.operationId||source.personaSession?.sessionId!==b.personaSession.sessionId
    ||source.personaSession?.authorityVersion!==b.personaSession.authorityVersion
    ||![source.sessionId,source.claimId,source.runId].every(id=>typeof id==='string'&&UUID.test(id))
    ||typeof source.requestHash!=='string'||! /^[a-f0-9]{64}$/.test(source.requestHash))
    throw fail('MAIL_STAGE_UNAVAILABLE');
  return source;
}
async function locked(client,b,threadId) {
  await client.query("SET LOCAL statement_timeout='3000ms'");
  await client.query("SET LOCAL lock_timeout='3000ms'");
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',
    [`secureshop-mail-thread:${b.targetId}:${b.persona.id}:${threadId}`]);
}
function createMailUncertainRepository({pool,personaAuthority}={}) {
  if(typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function')
    throw TypeError('Mail uncertainty store and persona authority required');
  async function withFence(raw,provided,work) {
    const b=normalize(raw);
    const fence=exactFence(provided||personaAuthority.capture({scope:b.scope,
      personaId:b.persona.id,role:b.persona.role,...b.personaSession}),b);
    const result=await mailScene.withLease(b,()=>fence.withPersonaEffect(async client=>{
      await mailScene.assertGrant(client,b);
      const value=await work(client,b);
      await mailScene.assertGrant(client,b);
      return value;
    }));
    await fence.assertRemoteAdmission();
    return result;
  }
  return Object.freeze({
    async admitThread(raw,threadId,capability,fence) {
      threadId=thread(threadId);
      return withFence(raw,fence,async(client,b)=>{
        const source=stage(capability,b,'thread_admission');
        await locked(client,b,threadId);
        const blocked=(await client.query(`SELECT EXISTS(
          SELECT 1 FROM ${T}unresolved_detaches d
          LEFT JOIN secureshop_agents.lab_mail_operation_receipts sent
            ON sent.operation_id=d.send_operation_id AND sent.target_id=d.target_id AND sent.action='send'
          LEFT JOIN ${T}preexecution_rejections rejection
            ON rejection.session_id=d.session_id AND rejection.request_id=d.request_id
          JOIN secureshop_agents.turn_requests old
            ON old.session_id=d.session_id AND old.request_id=d.request_id
          WHERE d.target_id=$1 AND d.persona_id=$2 AND d.thread_id=$3
            AND old.status='uncertain' AND sent.operation_id IS NULL
            AND rejection.request_id IS NULL) AS blocked`,
        [b.targetId,b.persona.id,threadId])).rows[0].blocked;
        const args=[source.sessionId,b.operationId,source.claimId,source.requestHash,
          source.runId,b.targetId,b.persona.id,b.personaSession.sessionId,
          b.personaSession.authorityVersion,threadId,b.mode,blocked];
        await client.query(`INSERT INTO ${T}thread_attempts
          (session_id,request_id,claim_id,request_hash,run_id,target_id,persona_id,
           persona_session_id,authority_version,thread_id,mode,blocked)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
          ON CONFLICT(session_id,request_id) DO NOTHING`,args);
        const row=(await client.query(`SELECT claim_id,request_hash,run_id,target_id,
          persona_id,persona_session_id,authority_version,thread_id,mode,blocked
          FROM ${T}thread_attempts WHERE session_id=$1 AND request_id=$2`,args.slice(0,2))).rows[0];
        if(!row||row.claim_id!==source.claimId||row.request_hash!==source.requestHash
          ||row.run_id!==source.runId||row.target_id!==b.targetId
          ||row.persona_id!==b.persona.id||row.persona_session_id!==b.personaSession.sessionId
          ||String(row.authority_version)!==b.personaSession.authorityVersion
          ||Number(row.thread_id)!==threadId||row.mode!==b.mode||row.blocked!==blocked)
          throw fail('MAIL_THREAD_CONFLICT');
        return !blocked;
      });
    },
    async recordRejected(raw,threadId,capability,stageName,fence) {
      threadId=thread(threadId);
      const expected=stageName==='thread_admission'?'thread_admission_rejected'
        :stageName==='prompt_policy_admission'?'prompt_policy_admission_rejected':null;
      if(!expected)throw fail('MAIL_STAGE_UNAVAILABLE');
      return withFence(raw,fence,async(client,b)=>{
        const source=stage(capability,b,expected);
        await locked(client,b,threadId);
        const args=[source.sessionId,b.operationId,source.claimId,source.requestHash,
          source.runId,b.targetId,b.persona.id,threadId,b.mode,stageName];
        await client.query(`INSERT INTO ${T}preexecution_rejections
          (session_id,request_id,claim_id,request_hash,run_id,target_id,persona_id,thread_id,mode,stage)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,args);
        const changed=await client.query(`UPDATE secureshop_agents.turn_requests
          SET status='uncertain',finished_at=clock_timestamp()
          WHERE session_id=$1 AND request_id=$2 AND claim_id=$3 AND request_hash=$4 AND status='started'`,
        args.slice(0,4));
        if(changed.rowCount!==1)throw fail('MAIL_STAGE_UNAVAILABLE');
        return true;
      });
    },
    async readRejected(raw) {
      return withFence(raw,null,async(client,b)=>{
        const rows=(await client.query(`SELECT rejection.*,tr.status,tr.request_version,
          attempt.persona_session_id,attempt.authority_version
          FROM ${T}preexecution_rejections rejection
          JOIN ${T}thread_attempts attempt USING(session_id,request_id)
          JOIN secureshop_agents.turn_requests tr USING(session_id,request_id)
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE rejection.request_id=$1 AND rejection.target_id=$2 AND rejection.persona_id=$3
            AND rejection.mode=$4 AND s.conversation_purpose='secureshop_mail_reply'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND s.platform_launch_id=$5 AND s.platform_scenario_id=$6
            AND s.platform_launch_generation=$7 AND s.original_platform_owner_id=$8
            AND s.original_platform_session_id=$9 AND s.user_id=$3 AND s.role=$10`,
        [b.operationId,b.targetId,b.persona.id,b.mode,b.scope.launchId,
          b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,
          b.scope.platformSessionId,b.persona.role])).rows;
        if(!rows.length)return null;
        if(rows.length!==1)throw fail('MAIL_RECOVERY_AMBIGUOUS');
        const row=rows[0];
        const hash=createTurnRequest({sessionId:row.session_id,requestId:b.operationId,
          binding:createConversationBinding(b.scope,b.persona),version:row.request_version,
          message:message(b,Number(row.thread_id))}).hash;
        if(row.status!=='uncertain'||hash!==row.request_hash
          ||row.persona_session_id!==b.personaSession.sessionId
          ||String(row.authority_version)!==b.personaSession.authorityVersion)
          throw fail('MAIL_RECOVERY_MISMATCH');
        return Object.freeze({threadId:Number(row.thread_id),stage:row.stage});
      });
    },
    async keepUnresolved(raw,threadId) {
      threadId=thread(threadId);
      return withFence(raw,null,async(client,b)=>{
        await locked(client,b,threadId);
        const rows=(await client.query(`SELECT tr.session_id,tr.claim_id,tr.request_hash,
          tr.request_version,tr.status
          FROM secureshop_agents.turn_requests tr
          JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
          WHERE tr.request_id=$1 AND s.conversation_purpose='secureshop_mail_reply'
            AND s.authority_mode='launch_bound' AND s.binding_state='active'
            AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
            AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5
            AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role=$8 FOR UPDATE OF tr`,
        [b.operationId,...coordinates(b)])).rows;
        if(rows.length!==1)throw fail('MAIL_UNRESOLVED_UNAVAILABLE');
        const row=rows[0],hash=createTurnRequest({sessionId:row.session_id,
          requestId:b.operationId,binding:createConversationBinding(b.scope,b.persona),
          version:row.request_version,message:message(b,threadId)}).hash;
        if(row.status!=='uncertain'||row.request_hash!==hash)
          throw fail('MAIL_UNRESOLVED_UNAVAILABLE');
        const sendId=operationId(b.operationId,'reply');
        const terminal=(await client.query(`SELECT
          EXISTS(SELECT 1 FROM ${T}preexecution_rejections
            WHERE session_id=$1 AND request_id=$2) AS rejected,
          EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_operation_receipts
            WHERE operation_id=$3 AND target_id=$4 AND action='send') AS sent`,
        [row.session_id,b.operationId,sendId,b.targetId])).rows[0];
        if(terminal.rejected||terminal.sent)throw fail('MAIL_RECOVERY_REQUIRED');
        const active=(await client.query(`SELECT EXISTS(
          SELECT 1 FROM ${T}thread_attempts a
          LEFT JOIN secureshop_agents.turn_requests tr
            ON tr.session_id=a.session_id AND tr.request_id=a.request_id
          LEFT JOIN ${T}preexecution_rejections rejection
            ON rejection.session_id=a.session_id AND rejection.request_id=a.request_id
          WHERE a.target_id=$1 AND a.persona_id=$2 AND a.thread_id=$3
            AND a.request_id<>$4 AND a.created_at >= (
              SELECT old.created_at FROM secureshop_agents.turn_requests old
              WHERE old.session_id=$5 AND old.request_id=$4)
            AND (tr.status IS NULL OR tr.status='started'
              OR (tr.status='uncertain' AND rejection.request_id IS NULL))) AS active`,
        [b.targetId,b.persona.id,threadId,b.operationId,row.session_id])).rows[0].active;
        if(active)throw fail('MAIL_THREAD_CONFLICT');
        await client.query(`INSERT INTO ${T}unresolved_detaches
          (session_id,request_id,claim_id,request_hash,target_id,persona_id,
           persona_session_id,authority_version,thread_id,mode,send_operation_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
          ON CONFLICT(session_id,request_id) DO NOTHING`,
        [row.session_id,b.operationId,row.claim_id,row.request_hash,b.targetId,
          b.persona.id,b.personaSession.sessionId,b.personaSession.authorityVersion,
          threadId,b.mode,sendId]);
        const detached=(await client.query(`SELECT claim_id,request_hash,target_id,
          persona_id,persona_session_id,authority_version,thread_id,mode,send_operation_id
          FROM ${T}unresolved_detaches
          WHERE session_id=$1 AND request_id=$2`,[row.session_id,b.operationId])).rows[0];
        if(!detached||detached.claim_id!==row.claim_id||detached.request_hash!==row.request_hash
          ||detached.target_id!==b.targetId||detached.persona_id!==b.persona.id
          ||detached.persona_session_id!==b.personaSession.sessionId
          ||String(detached.authority_version)!==b.personaSession.authorityVersion
          ||Number(detached.thread_id)!==threadId||detached.mode!==b.mode
          ||detached.send_operation_id!==sendId)throw fail('MAIL_THREAD_CONFLICT');
        return Object.freeze({requestId:b.operationId,threadId});
      });
    },
  });
}
module.exports={createMailUncertainRepository};
