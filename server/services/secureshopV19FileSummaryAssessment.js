'use strict';

const {
  randomUUID,
  createHash
} = require('node:crypto');
const {
  isDeepStrictEqual: equal
} = require('node:util');
const {
  executionScope
} = require('./secureshopSceneBinding');
const {
  createConversationBinding,
  createLaunchScope
} = require('./secureshopConversationBinding');
const {
  createBoundConversationService
} = require('./secureshopBoundConversation');
const {
  createBoundTurns
} = require('./secureshopBoundTurns');
const {
  createTurnAdmission
} = require('./secureshopTurnAdmission');
const {
  createTurnRequest
} = require('./secureshopTurnRequest');
const {
  captureFeatureMode
} = require('./secureshopFeatureModeAuthority');
const {
  createAssessmentPersonaCapture
} = require('./secureshopAssessmentPersonaCapture');
const {
  captureAssessmentPublicationScope
} = require('./secureshopAssessmentPublicationScope');
const {
  readSecureShopAssessmentEligibility
} = require('./secureshopAssessmentEligibility');
const {
  createObjectiveCompletionService
} = require('./secureshopObjectiveCompletionService');
const {
  createSavedAssessmentOutcomeReader
} = require('./secureshopSavedAssessmentOutcomeReader');
const {
  prepareJudgeInput
} = require('../agent-runtime/objectiveJudge');
const {
  SUMMARY_OBJECTIVE: OBJECTIVE,
  SUMMARY_RUBRIC: RUBRIC,
  SUMMARY_PURPOSE: SOURCE_PURPOSE,
  buildFileSummaryCandidate
} = require('./secureshopV19FileSummaryEvidence');
const PURPOSE = 'persona_inbox';
const WORKSHOP = 'secureshop_agent_security';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = () => Object.assign(new Error('File summary assessment unavailable'), {
  code: 'FILE_SUMMARY_ASSESSMENT_UNAVAILABLE',
  executionBoundary: true
});
const status = value => Object.freeze({
  completed: false,
  status: value,
  modelEvaluated: false
});
function assessmentRequestId(sessionId, requestId) {
  if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')) throw fail();
  const bytes = createHash('sha256').update(JSON.stringify([OBJECTIVE, sessionId, requestId])).digest();
  bytes[6] = bytes[6] & 15 | 80;
  bytes[8] = bytes[8] & 63 | 128;
  const h = bytes.subarray(0, 16).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const message = (state, source) => JSON.stringify([OBJECTIVE, state.source, source.retained.receipt.receiptSha256, state.personaSession, state.mode.snapshot, state.publication.binding]);
function createV19FileSummaryAssessment({
  identityPool,
  agentsPool,
  launches,
  conversationRepository,
  coordinator,
  journal,
  personaAuthority,
  personaBindings,
  scenes,
  modeAuthority,
  sourceReader,
  receipts,
  progress,
  publicationModes,
  judge,
  qualifyModel
} = {}) {
  for (const fn of [identityPool?.query, agentsPool?.query, launches?.assertCurrent, conversationRepository?.getBoundSession, conversationRepository?.acquireBoundSession, conversationRepository?.getTraceEvents, coordinator?.run, journal?.readFileSummaryRequest, journal?.claim, journal?.complete, journal?.markUncertain, personaAuthority?.capture, personaBindings?.capture, scenes?.readRetained, modeAuthority?.capture, modeAuthority?.assertToken, sourceReader?.read, publicationModes?.getEvaluationScope, judge, qualifyModel]) if (typeof fn !== 'function') throw TypeError('File summary assessment dependencies required');
  const conversations = createBoundConversationService({
    conversations: conversationRepository,
    launches
  });
  const turns = createBoundTurns({
    conversations,
    coordinator
  });
  const admission = createTurnAdmission({
    journal
  });
  const capture = createAssessmentPersonaCapture(personaBindings);
  const scopes = new WeakMap(),
    packets = new WeakMap();
  const savedOutcome = createSavedAssessmentOutcomeReader({
    identityPool,
    objectiveId: OBJECTIVE,
    rubric: RUBRIC,
    role: 'customer'
  });
  const completion = createObjectiveCompletionService({
    receipts,
    progress,
    ...capture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw fail();
      return scope;
    },
    judge: async input => {
      const expected = packets.get(input.execution),
        actual = prepareJudgeInput(input);
      if (!expected || actual.evidenceError || actual.packet !== expected.packet || actual.evidenceDigest !== expected.evidenceDigest) throw fail();
      return judge(input);
    }
  });
  const enabled = async binding => (await readSecureShopAssessmentEligibility(identityPool, binding, [OBJECTIVE])).includes(OBJECTIVE);
  async function authority({
    scope,
    persona,
    personaSession,
    sessionId,
    requestId,
    signal
  }) {
    const binding = createConversationBinding(scope, persona),
      key = assessmentRequestId(sessionId, requestId);
    if (binding.role !== 'customer' || !UUID.test(personaSession?.sessionId || '') || typeof personaSession.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(personaSession.authorityVersion)) throw fail();
    const customer = Object.freeze({
      id: binding.shopUserId,
      role: 'customer'
    });
    const session = Object.freeze({
      sessionId: personaSession.sessionId.toLowerCase(),
      authorityVersion: personaSession.authorityVersion
    });
    const fence = await personaAuthority.capture({
      scope: binding,
      personaId: customer.id,
      role: 'customer',
      ...session
    });
    const expected = {
      ...createLaunchScope(binding),
      personaId: customer.id,
      role: 'customer',
      ...session
    };
    if (typeof fence?.assertRemoteAdmission !== 'function' || !Object.keys(expected).every(k => fence.binding?.[k] === expected[k])) throw fail();
    const mode = await captureFeatureMode(modeAuthority, binding, 'file_summary');
    const target = await scenes.readRetained(binding);
    if (!target?.scene || !UUID.test(target.targetId || '') || !equal(createLaunchScope(executionScope(target)), createLaunchScope(binding))) throw fail();
    const publication = await captureAssessmentPublicationScope(publicationModes, binding.platformOwnerId, signal, binding);
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding);
      await fence.assertRemoteAdmission();
      await conversations.assertOwned(sessionId, binding, customer, SOURCE_PURPOSE);
      await mode.assertCurrent();
      await publication.assertCurrent();
      const current = await scenes.readRetained(binding);
      if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene) || !equal(createLaunchScope(executionScope(current)), createLaunchScope(binding))) throw fail();
      signal?.throwIfAborted();
    };
    const checkAtEffect = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding);
      await conversations.assertOwned(sessionId, binding, customer, SOURCE_PURPOSE);
      await (mode.assertCurrentAtEffect || mode.assertCurrent).call(mode);
      await publication.assertCurrentAtEffect();
      const current = await scenes.readRetained(binding);
      if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
          || !equal(createLaunchScope(executionScope(current)), createLaunchScope(binding))) throw fail();
      signal?.throwIfAborted();
    };
    await check();
    return Object.freeze({
      binding,
      customer,
      personaSession: session,
      fence,
      mode,
      target,
      publication,
      check,
      checkAtEffect,
      signal,
      key,
      source: {
        sessionId,
        requestId
      }
    });
  }
  async function original(state) {
    await state.check();
    const {
      sessionId,
      requestId
    } = state.source;
    const row = await journal.readFileSummaryRequest({
      sessionId,
      requestId,
      binding: state.binding,
      purpose: SOURCE_PURPOSE
    });
    await state.check();
    if (!row || row.status !== 'completed') return null;
    const turn = row.result_json,
      meta = turn?.taskMetadata?.boundFileSummary;
    if (!meta || !Array.isArray(meta.traceEventIds) || meta.traceEventIds.length < 4 || meta.traceEventIds.length > 128 || !UUID.test(meta.operationId || '') || meta.outcome !== 'read' || !meta.attachmentReceipt) return null;
    const retained = await sourceReader.read({
      scope: state.binding,
      persona: state.customer,
      personaSession: state.personaSession,
      sessionId, requestId, receipt: meta.attachmentReceipt, check: state.check,
      checkAtEffect: state.checkAtEffect,
      target: state.target,
      mode: state.mode.snapshot,
      signal: state.signal
    });
    await state.check();
    if (!retained) return null;
    const receipt = meta.graphEffect;
    if (!receipt || typeof receipt.runId !== 'string' || typeof receipt.ownerKey !== 'string' || typeof receipt.generation !== 'string' || typeof receipt.effectKey !== 'string') throw fail();
    const rows = (await identityPool.query(`SELECT e.run_id,e.owner_key,
      e.generation::text AS generation,e.effect_key,e.status,
      r.status AS run_status,o.generation::text AS live_generation
      FROM graph_runtime.effects e
      JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
      JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
      WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4 LIMIT 2`, [receipt.runId, receipt.ownerKey, receipt.generation, receipt.effectKey])).rows;
    await state.check();
    if (rows.length !== 1) throw fail();
    const traces = await conversationRepository.getTraceEvents(sessionId, state.binding, meta.traceEventIds, SOURCE_PURPOSE);
    await state.check();
    const candidate = buildFileSummaryCandidate({
      binding: state.binding,
      personaSession: state.personaSession,
      row,
      traces,
      retained,
      graphEffect: rows[0],
      qualifyModel
    });
    return candidate ? Object.freeze({
      row,
      candidate,
      retained
    }) : null;
  }
  const eligible = async state => state.mode.snapshot.mode === 'vuln' && state.publication.binding.mode === 'vuln' && (await enabled(state.binding));
  async function retained(state, packet, canonicalExecution) {
    let input;
    try {
      input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet);
    } catch {
      throw fail();
    }
    if (!canonicalExecution || input?.rubric?.version !== RUBRIC.version || !equal(input?.evidence?.[0]?.content?.sessionId, state.source.sessionId) || !equal(input?.evidence?.[0]?.content?.requestId, state.source.requestId) || !(await eligible(state))) throw fail();
    const source = await original(state);
    if (!source) throw fail();
    const current = prepareJudgeInput({
      rubric: RUBRIC,
      ...source.candidate
    });
    const saved = prepareJudgeInput(input);
    if (current.evidenceError || saved.evidenceError || current.packet !== saved.packet || current.evidenceDigest !== saved.evidenceDigest) throw fail();
    let owner;
    try {
      owner = JSON.parse(canonicalExecution.ownerKey);
    } catch {
      throw fail();
    }
    if (!Array.isArray(owner) || owner.length !== 2 || owner[0] !== 'SecureShopBoundConversation' || !UUID.test(owner[1] || '')) throw fail();
    await conversations.assertOwned(owner[1], state.binding, state.customer, PURPOSE);
    await state.check();
    return current;
  }
  async function readOutcome(input) {
    const state = await authority(input);
    if (!(await eligible(state))) return status('ineligible');
    let source;
    try { source = await original(state); } catch (error) {
      if (error?.code === 'FILE_SUMMARY_EVIDENCE_SIZE_LIMIT') return Object.freeze({ completed: false, status: 'unavailable', modelEvaluated: false, reason: 'evidence_size_limit' });
      throw error;
    }
    if (!source) return status('ineligible');
    const b = state.binding;
    const rows = (await agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,
      t.request_version,t.status,t.result_json FROM secureshop_agents.turn_requests t
      JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE t.request_id=$1 AND s.authority_mode='launch_bound'
      AND s.binding_state='active' AND s.conversation_purpose='persona_inbox'
      AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
      AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5
      AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role='customer' LIMIT 2`, [state.key, b.launchId, b.scenarioId, b.generation, b.platformOwnerId, b.platformSessionId, b.shopUserId])).rows;
    await state.check();
    if (!rows.length) return status('unconfirmed');
    if (rows.length !== 1) throw fail();
    const row = rows[0];
    await conversations.assertOwned(row.session_id, b, state.customer, PURPOSE);
    const expected = createTurnRequest({
      sessionId: row.session_id,
      requestId: state.key,
      binding: b,
      message: message(state, source)
    });
    if (row.request_id !== state.key || row.request_hash !== expected.hash || Number(row.request_version) !== expected.version) throw fail();
    if (row.status !== 'completed') return status('unconfirmed');
    if (equal(row.result_json, status('ineligible'))) return status('ineligible');
    const evaluationId = row.result_json?.judgment?.evaluationId;
    if (!UUID.test(evaluationId || '')) throw fail();
    const versions = (await identityPool.query(`SELECT j.rubric_version
      FROM secureshop_auth.execution_authority_state e
      JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
      JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id
        AND j.principal_id=e.principal_id
      WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1
        AND e.expires_at>clock_timestamp() AND p.shop_user_id=$3
        AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`, [b.platformSessionId, b.platformOwnerId, b.shopUserId, evaluationId, OBJECTIVE])).rows;
    await state.check();
    if (versions.length !== 1 || versions[0].rubric_version !== RUBRIC.version) throw fail();
    return savedOutcome.read({
      binding: b,
      personaSession: state.personaSession,
      publication: state.publication.binding,
      assessmentOwnerKey: JSON.stringify(['SecureShopBoundConversation', row.session_id]),
      turnResult: row.result_json,
      prepareRetainedPacket: (packet, execution) => retained(state, packet, execution),
      check: state.check
    });
  }
  async function runAttempt(input) {
    const state = await authority(input);
    if (!(await eligible(state))) return status('ineligible');
    let source;
    try { source = await original(state); } catch (error) {
      if (error?.code === 'FILE_SUMMARY_EVIDENCE_SIZE_LIMIT') return Object.freeze({ completed: false, status: 'unavailable', modelEvaluated: false, reason: 'evidence_size_limit' });
      throw error;
    }
    if (!source) return status('ineligible');
    const actor = capture.prepare(state.binding, state.fence);
    const session = await conversations.create(state.binding, state.customer, PURPOSE);
    let prepared;
    const prepare = async () => {
      await state.check();
      prepared = await admission.prepare({
        sessionId: session.id,
        requestId: state.key,
        binding: state.binding,
        message: message(state, source)
      });
      return prepared.status === 'completed' ? {
        skip: true,
        value: prepared.outcome
      } : {
        skip: false,
        value: prepared
      };
    };
    try {
      const outcome = await turns.run(session.id, state.binding, state.customer, {
        signal: state.signal,
        idempotencyKey: state.key,
        conversationPurpose: PURPOSE,
        admit: prepare
      }, async boundary => {
        let sourceCheck;
        const check = async () => {
          await boundary.check();
          await state.check();
          if (sourceCheck) await sourceCheck();
          await boundary.check();
        };
        await check();
        if (!prepared) {
          await prepare();
          if (prepared.status === 'completed') return prepared.outcome;
        }
        return admission.execute(prepared, {
          ...boundary,
          check
        }, async () => {
          const execution = Object.freeze({
            runId: boundary.identity.runId,
            ownerKey: boundary.identity.ownerKey,
            durableGeneration: boundary.identity.durableGeneration,
            signal: boundary.signal,
            check
          });
          scopes.set(execution, state.binding);
          capture.bind(execution, actor);
          const attempt = await completion.beginAttempt({
            userId: state.binding.platformOwnerId,
            workshopKey: WORKSHOP,
            objectiveId: OBJECTIVE,
            execution
          });
          await check();
          if (attempt.mode !== 'vuln' || !(await eligible(state))) return status('ineligible');
          const current = await original(state);
          if (!current || !equal(current.candidate, source.candidate)) return status('ineligible');
          const packet = prepareJudgeInput({
            rubric: RUBRIC,
            ...source.candidate
          });
          if (packet.evidenceError) throw fail();
          packets.set(execution, packet);
          sourceCheck = async () => {
            const again = await original(state);
            if (!again || !equal(again.candidate, source.candidate) || !(await eligible(state))) throw fail();
          };
          await check();
          const result = await completion.evaluate({
            userId: state.binding.platformOwnerId,
            workshopKey: WORKSHOP,
            objectiveId: OBJECTIVE,
            evaluationId: randomUUID(),
            execution,
            attempt,
            rubric: RUBRIC,
            ...source.candidate
          });
          await check();
          return {
            completed: result.completed === true,
            judgment: result.judgment
          };
        }, state.fence);
      });
      await state.check();
      if (outcome.replayed === true) return readOutcome(input);
      if (equal(outcome.result, status('ineligible'))) return status('ineligible');
      return Object.freeze({
        ...outcome.result,
        replayed: false
      });
    } catch (error) {
      await admission.abandon(prepared);
      throw error;
    }
  }
  async function assertRetainedPacket({
    packet,
    scope,
    persona,
    personaSession,
    signal
  }) {
    let input;
    try {
      input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet);
    } catch {
      throw fail();
    }
    const ref = input?.evidence?.[0]?.content;
    const state = await authority({
      scope,
      persona,
      personaSession,
      sessionId: ref?.sessionId,
      requestId: ref?.requestId,
      signal
    });
    const check = async () => {
      await state.check();
      const prepared = prepareJudgeInput(input),
        b = state.binding;
      if (prepared.evidenceError || !SHA.test(prepared.evidenceDigest)) throw fail();
      const rows = (await identityPool.query(`SELECT j.*,
        e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
        s.membership_version::text AS current_membership_version,
        g.generation::text AS live_owner_generation
        FROM secureshop_auth.execution_authority_state e
        JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
        JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
        JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id
          AND j.principal_id=e.principal_id
        JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
        WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1
          AND e.expires_at>clock_timestamp() AND p.shop_user_id=$3
          AND j.objective_id=$4 AND j.packet=$5 AND j.evidence_digest=$6
          AND NOT EXISTS (SELECT 1 FROM secureshop_auth.assessment_retries retry
            WHERE retry.tenant_id=j.tenant_id AND retry.principal_id=j.principal_id
              AND retry.child_id=j.evaluation_id) LIMIT 2`, [b.platformSessionId, b.platformOwnerId, b.shopUserId, OBJECTIVE, prepared.packet, prepared.evidenceDigest])).rows;
      await state.check();
      if (rows.length !== 1) throw fail();
      const row = rows[0],
        execution = row.execution_json,
        p = state.publication.binding;
      if (row.workshop_key !== WORKSHOP || row.objective_id !== OBJECTIVE || Number(row.shop_user_id) !== b.shopUserId || row.family !== RUBRIC.family || row.scenario !== RUBRIC.scenario || row.rubric_version !== RUBRIC.version || row.mode !== 'vuln' || row.mode !== p.mode || Number(row.generation) !== p.generation || row.mode_stamp !== p.modeStamp || String(row.owner_generation) !== String(row.live_owner_generation) || execution?.runId !== row.run_id || execution.tenantId !== row.current_tenant_id || execution.principalId !== row.current_principal_id || execution.membershipVersion !== row.current_membership_version || !equal(execution.scope, createLaunchScope(b)) || execution.personaSessionId !== state.personaSession.sessionId || execution.personaAuthorityVersion !== state.personaSession.authorityVersion || execution.role !== 'customer' || row.packet !== prepared.packet || row.evidence_digest !== prepared.evidenceDigest) throw fail();
      await retained(state, input, {
        runId: row.run_id,
        ownerKey: row.owner_key,
        generation: String(row.owner_generation)
      });
    };
    await check();
    return Object.freeze({
      assertCurrent: check
    });
  }
  return Object.freeze({
    objectiveId: OBJECTIVE,
    completionService: completion,
    runAttempt,
    readOutcome,
    assertRetainedPacket
  });
}
module.exports = {
  createV19FileSummaryAssessment,
  assessmentRequestId
};
