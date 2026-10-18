'use strict';

const {
  randomUUID
} = require('node:crypto');
const {judgeFailureCode,canRetryJudgeError} = require('../agent-runtime/judgeErrors');
const judgeModule = require('../agent-runtime/objectiveJudge');
const {
  userId,
  key,
  error
} = require('../database/postgres/workshopPlatformSupport');
const {projectJudgment}=require('../agent-runtime/dpiSemanticCreditPolicy');
const SECURESHOP_WORKSHOP_KEY = 'secureshop_agent_security';
const DPI_SELECTED_JUDGE_TIMEOUT_MS = 180000;

function isExtendedSelectedDpiScope(workshopKey, rubric) {
  if (workshopKey !== 'direct_prompt_injection' || rubric?.family !== 'DPI'
      || rubric.scenario !== 'aws_assistant' || rubric.mode !== 'vuln') return false;
  const selected = require('../agent-runtime/dpiSelectedTaskComparison');
  const protocol = selected.getSelectedProtocol(rubric.dpiAnswerComparison?.protocolVersion);
  return ([selected.JAILBREAK_VERSION, selected.ROLE_PLAYING_VERSION, selected.CONTEXT_JAILBREAK_VERSION, selected.CONTEXT_ROLE_PLAYING_VERSION, selected.COMPACT_CONTEXT_JAILBREAK_VERSION, selected.COMPACT_CONTEXT_ROLE_PLAYING_VERSION].includes(protocol?.version))
    && rubric.objectiveId === protocol.objective
    && rubric.version === protocol.rubricVersion
    && rubric.dpiAnswerComparison?.primary === true
    && rubric.dpiAnswerComparison.objective === protocol.objective
    && rubric.dpiPolicyBinding === 'dpi-policy-binding-v2';
}

function captureXssScope(execution, uid, workshopKey, objectiveId) {
  if (execution?.scopeBinding === undefined) {
    if (workshopKey === 'xss_workshop' && execution?.scope !== undefined) {
      throw error('ATTEMPT_SCOPE_MISMATCH', 'Scoped XSS execution requires its protected binding');
    }
    return null;
  }
  if (workshopKey !== 'xss_workshop') throw error('ATTEMPT_SCOPE_MISMATCH', 'XSS scope cannot grade another workshop');
  const {captureXssJudgmentScope} = require('./xssJudgmentScope');
  const binding = captureXssJudgmentScope(execution.scopeBinding, {userId:uid, runId:execution.runId, objectiveId});
  const canonical = require('../agent-runtime/durableGeneration').canonicalDurableGeneration;
  if (binding.ownerKey !== execution.ownerKey || binding.parentGeneration !== canonical(execution.durableGeneration)) {
    throw error('ATTEMPT_SCOPE_MISMATCH', 'XSS scope differs from protected execution');
  }
  return binding;
}

function enforceRequiredFacts(result, packet) {
  if (result?.verdict !== 'pass' || !packet) return result;
  const missing = packet.rubric.requiredFacts.filter(id => packet.facts?.[id] !== true);
  if (!missing.length) return result;
  // The persistence boundary independently enforces observed prerequisites,
  // even if a Judge implementation mistakenly returns pass. Apply on retries
  // as well as first evaluations; use the immutable prepared evidence packet.
  return { ...result, verdict: 'fail', criteria: [],
    explanation: 'Required server-observed evidence is missing; no completion was awarded.',
    errorCode: 'REQUIRED_FACTS_NOT_SATISFIED' };
}
function createObjectiveCompletionService({
  receipts,
  progress,
  judge,
  prepareJudgeInput = judgeModule.prepareJudgeInput,
  captureInstanceScope,
  capturePersonaEvaluation
} = {}) {
  if (!receipts?.beginEvaluation || !receipts?.recordVerdict || !progress?.getGeneration) throw new TypeError('Explicit receipt and canonical progress stores are required');
  if(capturePersonaEvaluation!==undefined&&typeof capturePersonaEvaluation!=='function')throw new TypeError('Trusted persona evaluation capture required');
  const defaultJudge = judge === undefined ? judgeModule.createObjectiveJudge() : judge;
  const extendedSelectedDpiJudge = judge === undefined
    ? judgeModule.createObjectiveJudge({ dpiAnswerTimeoutMs: DPI_SELECTED_JUDGE_TIMEOUT_MS })
    : null;
  const selectJudge = (workshopKey, rubric) => {
    if (judge !== undefined) return judge;
    const timing = require('./mcp/timing');
    return timing.isMcpReconScope({ ...rubric, workshopKey })
      ? judgeModule.createObjectiveJudge({ timeoutMs: timing.createMcpReconTiming().judgeTimeoutMs })
      : isExtendedSelectedDpiScope(workshopKey, rubric)
        ? extendedSelectedDpiJudge
      : defaultJudge;
  };
  const attempts = new WeakMap();
  const personaEvaluations = new WeakMap();
  async function check(execution) {
    if (typeof execution?.check !== 'function') throw error('EXECUTION_REQUIRED', 'Protected owner execution is required');
    if (execution.signal?.aborted) throw execution.signal.reason || error('CANCELLED', 'Evaluation cancelled');
    await execution.check();
  }
  return {
    async hasPrerequisite({ userId: uid, workshopKey, objectiveId, execution, attempt }) {
      uid = userId(uid);
      key(workshopKey); key(objectiveId);
      await check(execution);
      if (attempts.get(attempt) !== execution || attempt.userId !== uid
        || attempt.workshopKey !== workshopKey || attempt.runId !== (execution.runId || null)) {
        throw error('ATTEMPT_SCOPE_MISMATCH', 'Capture a matching attempt before checking prerequisites');
      }
      if (typeof progress.getObjectiveCompletionState !== 'function') {
        throw error('GRADE_STORE_NOT_READY', 'Canonical prerequisite storage is unavailable');
      }
      const state = await progress.getObjectiveCompletionState(uid, workshopKey, objectiveId,
        { expectedGeneration: attempt.generation });
      await check(execution);
      if (state?.generation !== attempt.generation) throw error('STALE_GENERATION', 'Prerequisite scope changed');
      return state.completed === true;
    },
    async retry({userId: uid,evaluationId,execution,retryJudge}) {
      await check(execution);
      const recovery=await receipts.beginRetry({userId:uid,evaluationId,judgeVersion:judgeModule.JUDGE_VERSION,ownerGeneration:execution.durableGeneration});
      await check(execution);
      const receipt=recovery.receipt;
      if(retryJudge!==undefined&&(typeof retryJudge!=='function'||receipt.workshopKey!=='secureshop_agent_security'
        ||receipt.family!=='SecureShop'||receipt.scenario!=='bound_audit_summary'
        ||receipt.objectiveId!=='ss_audit_instruction_followed'))throw error('RETRY_NOT_ALLOWED','Audit retry scope required');
      if(receipt.verdict) return {judgment:{...projectJudgment(receipt),evaluationId:receipt.evaluationId,canRetry:false},receipt,completed:['awarded','already_complete'].includes(receipt.disposition),replayed:true,retryRunId:execution.runId,retryExhausted:receipt.verdict==='unavailable'};
      const packet=JSON.parse(recovery.packet);
      const prepared=prepareJudgeInput(packet);
      if(prepared.evidenceError || prepared.evidenceDigest!==receipt.evidenceDigest || prepared.rubric.version!==receipt.rubricVersion) throw error('EVIDENCE_INVALID','Stored grading packet does not match receipt');
      let result;
      try { result=await (retryJudge||selectJudge(receipt.workshopKey,packet.rubric))({...packet,execution:{...execution,runId:receipt.runId,
        emit:execution.trace || execution.emit,
        ...(recovery.auditCheckpoints?.length?{auditContinuation:recovery.auditCheckpoints}:{})}}); }
      catch(cause) {
        await check(execution);
        if(cause?.name==='AbortError')throw cause;
        result={family:receipt.family,scenario:receipt.scenario,objectiveId:receipt.objectiveId,rubricVersion:receipt.rubricVersion,evidenceDigest:receipt.evidenceDigest,runId:receipt.runId,mode:receipt.mode,errorCode:judgeFailureCode(cause),verdict:'unavailable',criteria:[],explanation:'Judge unavailable',provider:null,model:null,usage:null};
      }
      await check(execution);
      result=enforceRequiredFacts(result,JSON.parse(prepared.packet));
      const committed=await receipts.recordVerdict({userId:uid,evaluationId:receipt.evaluationId,result});
      await check(execution);
      return {judgment:{...projectJudgment(committed),evaluationId:receipt.evaluationId,canRetry:false},receipt:committed,completed:['awarded','already_complete'].includes(committed.disposition),replayed:false,retryRunId:execution.runId,retryExhausted:committed.verdict==='unavailable'};
    },
    async beginAttempt({
      userId: uid,
      workshopKey,
      objectiveId,
      execution
    }) {
      uid = userId(uid);
      key(workshopKey);
      if (objectiveId !== undefined) key(objectiveId);
      const xssScope = captureXssScope(execution, uid, workshopKey, objectiveId);
      await check(execution);
      // Native stores atomically capture mode and generation before evidence exists.
      // Generation-only injected stores remain supported for existing unit fixtures.
      const scope = progress.getEvaluationScope
        ? await progress.getEvaluationScope(uid, workshopKey)
        : { generation: await progress.getGeneration(uid, workshopKey) };
      await check(execution);
      let instanceScope = null;
      if (workshopKey === SECURESHOP_WORKSHOP_KEY) {
        if (typeof captureInstanceScope !== 'function') {
          throw error('GRADE_STORE_NOT_READY', 'SecureShop launch-bound grading is unavailable');
        }
        // The launch binding comes from the protected server execution closure.
        // No route, rubric, evidence, or model field can supply this authority.
        // Lazy loading preserves every legacy completion composition and its
        // focused isolated fixture until SecureShop grading is activated.
        const { createLaunchScope } = require('./secureshopConversationBinding');
        instanceScope = createLaunchScope(await captureInstanceScope(execution, {
          userId: uid, workshopKey, objectiveId
        }));
        if (instanceScope.platformOwnerId !== uid) {
          throw error('ATTEMPT_SCOPE_MISMATCH', 'SecureShop launch owner does not match the grading owner');
        }
        await check(execution);
      }
      let personaEvaluation;
      if(capturePersonaEvaluation){
        await check(execution);
        personaEvaluation=await capturePersonaEvaluation(execution,Object.freeze({userId:uid,workshopKey,objectiveId}));
        await check(execution);
        if(!personaEvaluation||typeof personaEvaluation!=='object'||Array.isArray(personaEvaluation))throw error('PERSONA_EVALUATION_UNAVAILABLE','Trusted persona evaluation capture unavailable');
      }
      const attempt = Object.freeze({
        userId: uid,
        workshopKey,
        objectiveId,
        generation: scope.generation,
        mode: scope.mode,
        modeStamp: scope.modeStamp,
        runId: execution.runId || null,
        instanceScope,
        xssScope
      });
      attempts.set(attempt, execution);
      if(capturePersonaEvaluation)personaEvaluations.set(attempt,personaEvaluation);
      return attempt;
    },
    async evaluate({
      userId: uid,
      workshopKey,
      rubric,
      evidence,
      facts = {},
      execution,
      evaluationId = randomUUID(),
      attempt
    }) {
      uid = userId(uid);
      await check(execution);
      if (attempts.get(attempt) !== execution || attempt.userId !== uid || attempt.workshopKey !== workshopKey || attempt.objectiveId !== undefined && attempt.objectiveId !== rubric?.objectiveId || attempt.runId !== (execution.runId || null)) throw error('ATTEMPT_SCOPE_MISMATCH', 'Capture a matching attempt before generating evidence');
      const xssScope = captureXssScope(execution, uid, workshopKey, rubric?.objectiveId);
      if (JSON.stringify(xssScope) !== JSON.stringify(attempt.xssScope ?? null)) {
        throw error('ATTEMPT_SCOPE_MISMATCH', 'XSS authority changed after attempt capture');
      }
      const prepared = prepareJudgeInput({
        rubric,
        evidence,
        facts
      });
      // The provider sees a detached snapshot, so later caller mutation cannot alter the receipt's digest.
      const snapshot = prepared.evidenceError ? null : JSON.parse(prepared.packet);
      const scope = {
        userId: uid,
        evaluationId,
        workshopKey,
        objectiveId: prepared.rubric.objectiveId,
        family: prepared.rubric.family,
        scenario: prepared.rubric.scenario,
        rubricVersion: prepared.rubric.version,
        evidenceDigest: prepared.evidenceDigest,
        runId: execution.runId || null,
        mode: prepared.rubric.mode,
        recovery: {packet: prepared.evidenceError ? null : prepared.packet, judgeVersion: judgeModule.JUDGE_VERSION, ownerKey: execution.ownerKey, ownerGeneration: execution.durableGeneration},
        expectedGeneration: attempt.generation,
        expectedMode: attempt.mode,
        expectedModeStamp: attempt.modeStamp,
        instanceScope: attempt.instanceScope,
        ...(xssScope ? {xssScope} : {})
      };
      await check(execution);
      const receipt = capturePersonaEvaluation
        ? await receipts.beginEvaluation(scope,personaEvaluations.get(attempt))
        : await receipts.beginEvaluation(scope);
      await check(execution);
      if (receipt.verdict) {
        // A replay needs the same discoverable receipt ID and authoritative packet
        // eligibility as recovery after refresh. Never infer retention from verdict alone.
        let canRetry = false;
        if (receipt.verdict === 'unavailable' && receipt.disposition === 'not_pass'
            && canRetryJudgeError(receipt.result?.errorCode)
            && receipts.getRecovery && execution.ownerKey != null && execution.durableGeneration != null) {
          const recovery = await receipts.getRecovery({ userId: uid, evaluationId });
          await check(execution);
          canRetry = Boolean(recovery?.packet && !recovery.child_evaluation_id
            && recovery.judge_version === judgeModule.JUDGE_VERSION
            && recovery.owner_key === execution.ownerKey
            && recovery.owner_generation === String(execution.durableGeneration)
            && recovery.xss_binding_current !== false
            && (!xssScope || recovery.xss_binding_current === true)
            && new Date(recovery.expires_at).getTime() > Date.now());
        }
        return {
          judgment: { ...projectJudgment(receipt), evaluationId, canRetry },
          receipt,
          completed: receipt.generation === attempt.generation && ['awarded', 'already_complete'].includes(receipt.disposition),
          replayed: true
        };
      }
      const base = {
        family: scope.family,
        scenario: scope.scenario,
        objectiveId: scope.objectiveId,
        rubricVersion: scope.rubricVersion,
        evidenceDigest: scope.evidenceDigest,
        runId: scope.runId,
        mode: scope.mode
      };
      let judgment;
      if (prepared.evidenceError) {
        judgment = {
          ...base,
          verdict: 'inconclusive',
          criteria: [],
          explanation: 'Evidence exceeds supported limits; no completion was awarded.',
          provider: null,
          model: null,
          usage: null
        };
      } else {
        try {
          const auditInitial=scope.workshopKey==='secureshop_agent_security'&&scope.family==='SecureShop'
            &&scope.scenario==='bound_audit_summary'&&scope.objectiveId==='ss_audit_instruction_followed'
            &&snapshot.rubric?.sourceComparison?.promptContract==='audit-compact-source-v1';
          const auditExecution=auditInitial&&typeof receipts.saveAuditCheckpoint==='function'
            ?{...execution,auditCheckpoint:async entry=>{
              await check(execution);
              const saved=await receipts.saveAuditCheckpoint({userId:uid,evaluationId,execution,
                entry:{...entry,runId:scope.runId,evidenceDigest:scope.evidenceDigest,
                  packetSha256:require('../agent-runtime/auditJudgeStageCheckpoint').sha(prepared.packet),
                  judgeVersion:judgeModule.JUDGE_VERSION}});
              await check(execution);return saved;
            }}:execution;
          judgment = await selectJudge(scope.workshopKey,snapshot.rubric)({...snapshot,execution:auditExecution});
        } catch (cause) {
          // A reset/cancellation must propagate; only an ordinary engine failure is recorded as unavailable.
          await check(execution);
          if (cause?.name === 'AbortError') throw cause;
          judgment = {
            ...base,
            verdict: 'unavailable',
            errorCode: judgeFailureCode(cause),
            criteria: [],
            explanation: 'Objective evaluation is temporarily unavailable; no completion was awarded.',
            provider: null,
            model: null,
            usage: null
          };
        }
      }
      await check(execution);
      judgment = enforceRequiredFacts(judgment, snapshot);
      const committed = await receipts.recordVerdict({
        userId: uid,
        evaluationId,
        result: judgment
      });
      await check(execution);
      return {
        judgment: { ...projectJudgment(committed), evaluationId, canRetry: committed.verdict === 'unavailable'
          && committed.disposition === 'not_pass'
          && canRetryJudgeError(committed.result?.errorCode)
          && !prepared.evidenceError
          && execution.ownerKey != null
          && execution.durableGeneration != null },
        receipt: committed,
        completed: ['awarded', 'already_complete'].includes(committed.disposition),
        replayed: false
      };
    }
  };
}
let singleton;
function getObjectiveCompletionService() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw error('GRADE_STORE_NOT_READY', 'Durable PostgreSQL grade storage is required');
  if (!singleton) {
    const {
      getPostgresPlatformStores
    } = require('./postgresPlatformStores');
    const {
      pool,
      progress
    } = getPostgresPlatformStores();
    const {
      createObjectiveJudgmentRepository
    } = require('../database/postgres/objectiveJudgmentRepository');
    singleton = createObjectiveCompletionService({
      receipts: createObjectiveJudgmentRepository(pool),
      progress
    });
  }
  return singleton;
}
module.exports = {
  createObjectiveCompletionService,
  getObjectiveCompletionService
};
