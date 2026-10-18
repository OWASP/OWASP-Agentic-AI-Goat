'use strict';
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { createSavedAssessmentOutcomeReader } = require('./secureshopSavedAssessmentOutcomeReader');
const { captureAssessmentPublicationScope } = require('./secureshopAssessmentPublicationScope');
const { readSecureShopAssessmentEligibility } = require('./secureshopAssessmentEligibility');
const { normalize } = require('../database/postgres/secureshopBoundMailRepository');
const { prepareJudgeInput, rubricSchema } = require('../agent-runtime/objectiveJudge');
const { OBJECTIVE, MAIL_HTML_INJECTION_RUBRIC: RUBRIC,
  buildMailHtmlInjectionCandidate } = require('./secureshopMailHtmlInjectionEvidence');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WORKSHOP = 'secureshop_agent_security', PURPOSE = 'persona_inbox';
const fail = () => Object.assign(new Error('Agent mail HTML assessment unavailable'),
  { code: 'MAIL_HTML_INJECTION_ASSESSMENT_UNAVAILABLE' });
const status = value => Object.freeze({ completed: false, status: value, modelEvaluated: false });
const requestMessage = state => JSON.stringify([OBJECTIVE, state.raw.operationId,
  state.sourceSessionId, state.sourceRequestId, state.messageId, state.publication.binding]);
function createMailHtmlInjectionAssessment({ identityPool, agentsPool, launches, conversationRepository,
  coordinator, journal, personaAuthority, personaBindings, receipts, progress,
  publicationModes, judge, savedMailEvidence, originalReader, browserQualification,
  resolveRetainedBinding, qualifyModel } = {}) {
  for (const fn of [identityPool?.query, agentsPool?.query, launches?.assertCurrent,
    conversationRepository?.getBoundSession, conversationRepository?.acquireBoundSession,
    coordinator?.run, journal?.claim, journal?.complete, journal?.markUncertain,
    personaAuthority?.capture, personaBindings?.capture, judge, savedMailEvidence?.readHeader,
    originalReader?.read, browserQualification?.qualifyInjection,
    browserQualification?.readComponent, resolveRetainedBinding,
    publicationModes?.getEvaluationScope, qualifyModel])
    if (typeof fn !== 'function') throw new TypeError('Canonical agent mail HTML assessment dependencies required');
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator }), admission = createTurnAdmission({ journal });
  const capture = createAssessmentPersonaCapture(personaBindings), scopes = new WeakMap();
  const completion = createObjectiveCompletionService({ receipts, progress, judge, ...capture.options,
    captureInstanceScope: execution => { const scope = scopes.get(execution); if (!scope) throw fail(); return scope; } });
  const savedOutcome = createSavedAssessmentOutcomeReader({ identityPool, objectiveId: OBJECTIVE,
    rubric: RUBRIC, role: 'merchant' });
  const enabled = async scope => (await readSecureShopAssessmentEligibility(identityPool, scope,
    [OBJECTIVE])).includes(OBJECTIVE);
  async function authority({ binding: raw, requestId, sourceSessionId, sourceRequestId,
    messageId, signal } = {}) {
    if (![requestId, sourceSessionId, sourceRequestId].every(value => UUID.test(value || ''))
        || new Set([requestId, sourceSessionId, sourceRequestId]).size !== 3
        || !Number.isSafeInteger(messageId) || messageId < 1) throw fail();
    const rawBinding = normalize(await resolveRetainedBinding(normalize(raw)));
    const binding = createConversationBinding(rawBinding.scope, rawBinding.persona);
    if (binding.role !== 'merchant') throw fail();
    const session = rawBinding.personaSession;
    const fence = personaAuthority.capture({ scope: binding, personaId: binding.shopUserId,
      role: 'merchant', ...session });
    const publication = await captureAssessmentPublicationScope(publicationModes,
      binding.platformOwnerId, signal, binding);
    const check = async () => { signal?.throwIfAborted(); await launches.assertCurrent(binding);
      await fence.assertRemoteAdmission();
      const current = normalize(await resolveRetainedBinding(normalize(raw)));
      if (!equal(current, rawBinding)) throw fail();
      await publication.assertCurrent(); signal?.throwIfAborted(); };
    await check();
    return { raw: rawBinding, binding, persona: { id: binding.shopUserId, role: 'merchant' },
      personaSession: session, fence, publication, check, signal, requestId,
      sourceSessionId, sourceRequestId, messageId };
  }
  const eligible = async state => state.raw.mode === 'vuln'
    && state.publication.binding.mode === 'vuln' && await enabled(state.binding);
  async function readSources(state) {
    await state.check();
    const saved = await savedMailEvidence.readHeader(state.raw); await state.check();
    const original = await originalReader.read({ binding: state.raw,
      sessionId: state.sourceSessionId, requestId: state.sourceRequestId,
      messageId: state.messageId, check: state.check, signal: state.signal });
    await state.check(); return { saved, original };
  }
  async function retained(state, packet, canonicalExecution) {
    let input; try { input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet); }
    catch { throw fail(); }
    if (!equal(input?.rubric, rubricSchema.parse({ ...RUBRIC, mode: 'vuln' })) || !await eligible(state)) throw fail();
    const source = input.evidence?.find(row => row.id === 'mail_agent_html_source')?.content;
    const browser = input.evidence?.find(row => row.id === 'mail_agent_html_browser')?.content;
    const receipt = browser?.effectReceipt;
    if (source?.source?.sessionId !== state.sourceSessionId
        || source?.source?.requestId !== state.sourceRequestId
        || source.messageId !== state.messageId || source.operationId !== state.raw.operationId
        || !canonicalExecution || receipt?.runId !== canonicalExecution.runId
        || receipt.ownerKey !== canonicalExecution.ownerKey
        || String(receipt.generation) !== String(canonicalExecution.generation)
        || receipt.effectKey !== `${state.requestId}:mail-agent-html:${state.messageId}`) throw fail();
    const rows = (await identityPool.query(`SELECT e.owner_key AS "ownerKey",e.generation::text AS generation,
      e.effect_key AS "effectKey",e.run_id AS "runId",e.status,r.status AS "runStatus",
      o.generation::text AS "liveGeneration" FROM graph_runtime.effects e
      JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
      JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
      WHERE e.owner_key=$1 AND e.generation=$2 AND e.effect_key=$3 AND e.run_id=$4 AND e.status='completed'`,
    [canonicalExecution.ownerKey, canonicalExecution.generation,
      receipt.effectKey, canonicalExecution.runId])).rows;
    await state.check();
    if (rows.length !== 1 || !equal(rows[0], { runId: canonicalExecution.runId,
      ownerKey: canonicalExecution.ownerKey, generation: String(canonicalExecution.generation),
      effectKey: receipt.effectKey, status: 'completed', runStatus: 'completed',
      liveGeneration: String(canonicalExecution.generation) })) throw fail();
    const current = await readSources(state), component = await browserQualification.readComponent();
    await state.check(); if (!equal(component, browser.component)) throw fail();
    const rebuilt = buildMailHtmlInjectionCandidate({ ...current,
      effect: { receipt, value: { ...browser, component } },
      execution: { runId: canonicalExecution.runId, ownerKey: canonicalExecution.ownerKey,
        durableGeneration: canonicalExecution.generation, effectKey: receipt.effectKey, requestId: state.requestId }, qualifyModel });
    const prepared = rebuilt && prepareJudgeInput({ rubric: { ...RUBRIC, mode: 'vuln' }, ...rebuilt }), saved = prepareJudgeInput(input);
    if (!prepared || prepared.evidenceError || saved.evidenceError
        || prepared.packet !== saved.packet || prepared.evidenceDigest !== saved.evidenceDigest) throw fail();
    return prepared;
  }
  async function readOutcome(input) {
    const state = await authority(input); if (!await eligible(state)) return status('ineligible');
    const b = state.binding;
    const rows = (await agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,t.request_version,t.status,t.result_json
      FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
      AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
      AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
      AND s.user_id=$7 AND s.role='merchant' LIMIT 2`, [state.requestId,b.launchId,b.scenarioId,b.generation,
      b.platformOwnerId,b.platformSessionId,b.shopUserId])).rows;
    await state.check(); if (!rows.length) return status('unconfirmed'); if (rows.length !== 1) throw fail();
    const row = rows[0]; await conversations.assertOwned(row.session_id,b,state.persona,PURPOSE);
    const request = createTurnRequest({ sessionId: row.session_id, requestId: state.requestId,
      binding: b, message: requestMessage(state) });
    if (row.request_id !== state.requestId || row.request_hash !== request.hash
        || Number(row.request_version) !== request.version) throw fail();
    if (row.status !== 'completed') return status('unconfirmed');
    if (equal(row.result_json, status('ineligible'))) return status('ineligible');
    return savedOutcome.read({ binding: b, personaSession: state.personaSession,
      publication: state.publication.binding,
      assessmentOwnerKey: JSON.stringify(['SecureShopBoundConversation',row.session_id]),
      turnResult: row.result_json,
      prepareRetainedPacket: (packet, execution) => retained(state, packet, execution),
      check: state.check });
  }
  async function runAttempt(input) {
    const state = await authority(input); if (!await eligible(state)) return status('ineligible');
    const sources = await readSources(state);
    const actor = capture.prepare(state.binding,state.fence);
    const session = await conversations.create(state.binding,state.persona,PURPOSE); let prepared;
    const prepare = async () => { await state.check(); prepared = await admission.prepare({
      sessionId: session.id, requestId: state.requestId, binding: state.binding,
      message: requestMessage(state) }); return prepared.status === 'completed'
      ? { skip: true, value: prepared.outcome } : { skip: false, value: prepared }; };
    try {
      const outcome = await turns.run(session.id,state.binding,state.persona,{signal:state.signal,
        idempotencyKey:state.requestId,conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
        const check=async()=>{await boundary.check();await state.check();};await check();
        if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
        return admission.execute(prepared,{...boundary,check},async()=>{
          const execution={runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
            durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check};
          scopes.set(execution,state.binding);capture.bind(execution,actor);
          const attempt=await completion.beginAttempt({userId:state.binding.platformOwnerId,
            workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});await check();
          if(attempt.mode!=='vuln'||!await eligible(state))return status('ineligible');
          const effectKey=`${state.requestId}:mail-agent-html:${state.messageId}`;
          const effect=await boundary.effectWithReceipt(`mail-agent-html:${state.messageId}`,async()=>{
            await check();const value=await browserQualification.qualifyInjection({html:sources.saved.payload.body_html,
              learnerHtml:sources.saved.payload.body_markdown,messageId:state.messageId,signal:boundary.signal});
            await check();return value;});
          const current=await readSources(state);if(!equal(current,sources))throw fail();
          const candidate=buildMailHtmlInjectionCandidate({...current,effect,
            execution:{...execution,effectKey,requestId:state.requestId},qualifyModel});if(!candidate)return status('ineligible');
          const result=await completion.evaluate({userId:state.binding.platformOwnerId,
            workshopKey:WORKSHOP,objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,
            rubric:{...RUBRIC,mode:'vuln'},...candidate});await check();
          return {completed:result.completed===true,judgment:result.judgment};
        },state.fence);
      });
      await state.check();if(outcome.replayed===true)return readOutcome(input);
      if(equal(outcome.result,status('ineligible')))return status('ineligible');
      return Object.freeze({...outcome.result,replayed:false});
    } catch(error){await admission.abandon(prepared);throw error;}
  }
  async function assertRetainedPacket({ packet, scope, persona, personaSession, signal } = {}) {
    let input; try { input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet); }
    catch { throw fail(); }
    const checked = prepareJudgeInput(input), source = input?.evidence?.find(row => row.id === 'mail_agent_html_source')?.content;
    if (checked.evidenceError || checked.packet !== (typeof packet === 'string' ? packet : checked.packet)
        || !source?.binding || !equal(source.binding.scope, scope) || !equal(source.binding.persona, persona)
        || !equal(source.binding.personaSession, personaSession)) throw fail();
    const state = await authority({ binding: source.binding, requestId: source.assessmentRequestId,
      sourceSessionId: source.source?.sessionId, sourceRequestId: source.source?.requestId,
      messageId: source.messageId, signal });
    const check = async () => {
      await state.check();
      const browser = input.evidence.find(row => row.id === 'mail_agent_html_browser')?.content;
      const receipt = browser?.effectReceipt, prepared = prepareJudgeInput(input), b = state.binding;
      const rows = (await identityPool.query(`SELECT j.*,e.tenant_id AS current_tenant_id,
        e.principal_id AS current_principal_id,s.membership_version::text AS current_membership_version,
        g.generation::text AS live_owner_generation FROM secureshop_auth.execution_authority_state e
        JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
        JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
        JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
        JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
        WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
        AND p.shop_user_id=$3 AND j.objective_id=$4 AND j.run_id=$5 AND j.owner_key=$6
        AND j.packet=$7 AND j.evidence_digest=$8 AND NOT EXISTS (
          SELECT 1 FROM secureshop_auth.assessment_retries retry
          WHERE retry.tenant_id=j.tenant_id AND retry.principal_id=j.principal_id
          AND retry.child_id=j.evaluation_id) LIMIT 2`, [b.platformSessionId,b.platformOwnerId,b.shopUserId,
          OBJECTIVE,receipt?.runId,receipt?.ownerKey,prepared.packet,prepared.evidenceDigest])).rows;
      await state.check(); if (rows.length !== 1) throw fail();
      const row=rows[0], execution=row.execution_json, publication=state.publication.binding;
      if(row.workshop_key!==WORKSHOP||row.objective_id!==OBJECTIVE||Number(row.shop_user_id)!==b.shopUserId
        ||row.family!==RUBRIC.family||row.scenario!==RUBRIC.scenario||row.rubric_version!==RUBRIC.version
        ||row.mode!=='vuln'||row.mode!==publication.mode||Number(row.generation)!==publication.generation
        ||row.mode_stamp!==publication.modeStamp||row.run_id!==receipt.runId||row.owner_key!==receipt.ownerKey
        ||String(row.owner_generation)!==String(receipt.generation)||String(row.live_owner_generation)!==String(receipt.generation)
        ||execution?.runId!==row.run_id||execution.tenantId!==row.current_tenant_id
        ||execution.principalId!==row.current_principal_id||execution.membershipVersion!==row.current_membership_version
        ||!equal(execution.scope,createLaunchScope(state.binding))||execution.personaSessionId!==state.personaSession.sessionId
        ||execution.personaAuthorityVersion!==state.personaSession.authorityVersion||execution.role!=='merchant'
        ||prepared.evidenceError||row.packet!==prepared.packet||row.evidence_digest!==prepared.evidenceDigest) throw fail();
      await retained(state,input,{runId:row.run_id,ownerKey:row.owner_key,generation:String(row.owner_generation)});
    };
    await check(); return Object.freeze({assertCurrent:check});
  }
  return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,runAttempt,readOutcome,assertRetainedPacket});
}
module.exports={createMailHtmlInjectionAssessment};
