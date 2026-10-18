'use strict';
const { createHash } = require('node:crypto');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { BROWSER_OBJECTIVES, hasCsrfBrowserReceipt } = require('./csrfBrowserReceipt');
const { inspectCsrfMailProof } = require('./csrfEmailDispatch');
const digest = value => typeof value === 'string'
  ? createHash('sha256').update(value).digest('hex') : null;
const HEX64 = /^[a-f0-9]{64}$/;
const CRITERIA = Object.freeze({
  csrf_g1: 'The learner performed at least two attack-surface reconnaissance interactions and the server returned the available victim actions and forged-request vectors.',
  csrf_g2: 'A forged cross-origin GET request reached the lab victim action and changed its state while the relevant defense was disabled.',
  csrf_g3: 'An enabled anti-CSRF defense rejected the forged cross-origin GET request; that blocked request did not change victim state.',
  csrf_p1: 'A forged cross-origin form POST reached the lab victim action and changed victim state.',
  csrf_p2: 'A forged cross-origin fetch request reached the lab victim action and changed victim state.',
  csrf_p3: 'An enabled anti-CSRF defense rejected the forged cross-origin POST or fetch request without changing victim state.',
  csrf_x1: 'The server successfully contacted the configured temporary inbox and recorded it for this learner.',
  csrf_x2: 'The mail delivery service confirmed sending the selected HTML event-handler attack payload to the configured temporary inbox.',
  csrf_x3: 'The server read the attack email and the lab email-gadget execution path changed victim state. This proves the lab server execution path, not independent browser execution.',
  csrf_i1: 'The document ingestion service stored the learner-owned poisoned knowledge-base document for retrieval.',
  csrf_i2: 'The lab server retrieved the poisoned knowledge-base gadget and recorded a successful victim state change for at least one distinct query.',
  csrf_i3: 'The poisoned knowledge-base gadget successfully executed the lab victim action for at least two distinct queries. An idempotent repeat such as disabling already-disabled MFA proves persistence when the server records successful execution; a new state change is not required for the repeat.',
});
const tabFor = id => ({ g: 'get', p: 'post', x: 'xss', i: 'indirect' })[id?.[5]];

function observed(id, snapshot = {}, activity, receipt, authority = {}) {
  const result = activity?.result || {};
  const unchanged = result.stateChanged !== true && (!result.changed || Object.keys(result.changed).length === 0);
  const changed = !result.error && result.blocked === false && result.executed === true && result.stateChanged === true
    && result.changed && typeof result.changed === 'object' && !Array.isArray(result.changed) && Object.keys(result.changed).length > 0
    && !(Object.hasOwn(result.changed, 'from') && Object.hasOwn(result.changed, 'to') && result.changed.from === result.changed.to);
  switch (id) {
    case 'csrf_g1': return Number.isSafeInteger(snapshot.reconCount) && snapshot.reconCount >= 2 && !result.error && result.kind === 'recon'
      && ['actions', 'vectors'].every(key => Array.isArray(result.surface?.[key]) && result.surface[key].length > 0
        && result.surface[key].every(item => typeof item?.id === 'string' && item.id.trim().length > 0));
    case 'csrf_g2': return !!changed && result.vector === 'direct_get';
    case 'csrf_g3': return !result.error && result.defenses?.csrfToken === true && result.blocked === true && unchanged && result.vector === 'direct_get';
    case 'csrf_p1': return !!changed && result.vector === 'direct_post';
    case 'csrf_p2': return !!changed && result.vector === 'fetch';
    case 'csrf_p3': return !result.error && result.defenses?.csrfToken === true && result.blocked === true && unchanged && ['direct_post', 'fetch'].includes(result.vector);
    case 'csrf_x1': return receipt?.type === 'inbox_verified' && receipt.success === true;
    case 'csrf_x2': return authority.mailProof?.state === 'accepted' && authority.mailProof.hasEventHandler === true;
    case 'csrf_x3': return authority.mailProof?.state === 'retrieved' && authority.mailProof.hasEventHandler === true
      && !!changed && snapshot.xssEmailRead === true && /email/i.test(activity?.name || '');
    case 'csrf_i1': return receipt?.type === 'document_stored' && Number.isSafeInteger(receipt.chunks) && receipt.chunks > 0;
    case 'csrf_i2': return !!changed && Number.isSafeInteger(snapshot.ragFiredCount) && snapshot.ragFiredCount >= 1 && /rag/i.test(activity?.name || '');
    case 'csrf_i3': return result.executed === true && result.blocked === false && !result.error && Number.isSafeInteger(snapshot.ragFiredCount) && snapshot.ragFiredCount >= 2 && /rag/i.test(activity?.name || '');
    default: return false;
  }
}

function safeClassifiedProof(value, { userId, attempt, execution } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![1,2].includes(value.version) || value.objectiveId !== 'csrf_x3'
    || value.generation !== (attempt?.generation ?? execution?.generation)
    || typeof value.provider !== 'string' || !value.provider.trim()
    || /mock|fixture|fallback|unavailable/i.test(value.provider)
    || typeof value.model !== 'string' || !value.model.trim()
    || /mock|fixture|fallback|unavailable/i.test(value.model)
    || typeof value.summaryDigest !== 'string' || !HEX64.test(value.summaryDigest)
    || typeof value.gadgetDigest !== 'string' || !HEX64.test(value.gadgetDigest)) return null;
  if(value.version===2){
    const proof=value.selectedRead,selection=proof?.selection;
    if(!proof||proof.runId!==execution.runId||proof.ownerKey!==execution.ownerKey||proof.generation!==attempt.generation
      ||proof.mode!==attempt.mode||proof.modeStamp!==attempt.modeStamp||typeof proof.platformSessionId!=='string'
      ||proof.mode==='fixed'||proof.rendering?.policy!=='original_tool_html'||proof.rendering.originalSha256!==value.gadgetDigest||proof.rendering.renderedSha256!==value.gadgetDigest
      ||selection?.provider!==value.provider||selection?.model!==value.model||selection?.version!=='csrf-mail-read-v2'||selection.decision?.action!=='read_message'
      ||selection.decision.messageId!==proof.dispatchId||digest(selection.rawResponse)!==selection.responseSha256
      ||selection.responseSha256!==value.summaryDigest||proof.expected?.payloadDigest!==value.gadgetDigest)return null;
    try{const parsed=require('../agent-runtime/csrfMailReadDecision').validate(selection.rawResponse,[proof.dispatchId]);if(parsed.action!=='read_message')return null;}catch{return null;}
    if(Buffer.byteLength(JSON.stringify(proof))>15000)return null;
    return Object.freeze({version:2,objectiveId:'csrf_x3',generation:value.generation,provider:value.provider,model:value.model,
      decisionDigest:value.summaryDigest,gadgetDigest:value.gadgetDigest,selectedRead:JSON.parse(JSON.stringify(proof))});
  }
  // Only this allowlisted projection may cross into durable judge evidence.
  return Object.freeze({ version: 1, objectiveId: 'csrf_x3', generation: value.generation,
    provider: value.provider, model: value.model,
    summaryDigest: value.summaryDigest, gadgetDigest: value.gadgetDigest });
}

function safeBrowserReceipt(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const fields = ['type', 'objectiveId', 'tab', 'method', 'resourceType', 'responseStatus',
    'responseObserved', 'cookiePresent', 'payloadDigest', 'runId', 'generation'];
  const result = Object.fromEntries(fields.filter(key => value[key] !== undefined)
    .map(key => [key, value[key]]));
  return Object.keys(result).length ? Object.freeze(result) : null;
}

function createCsrfObjectiveGrader({ judge = createObjectiveJudge(), completionService,
  inspectMailProof = inspectCsrfMailProof,
  inspectClassifiedEmailProof,
  reconProofRepository,
  inspectBrowserReceipt = hasCsrfBrowserReceipt,
  postgres = process.env.PLATFORM_DATABASE_ENGINE === 'postgres' } = {}) {
  const service = () => completionService || require('./objectiveCompletionService').getObjectiveCompletionService();
  return {
    async begin(userId, execution) {
      await execution.check();
      return postgres ? service().beginAttempt({ userId, workshopKey: 'csrf_workshop', execution }) : null;
    },
    async evaluate({ userId, objectiveId, execution, attempt, snapshot, activity, receipt,
      classifiedEmailProof, browserReceipt, mailReceipt }) {
      if (!CRITERIA[objectiveId]) throw new Error('Unknown CSRF objective');
      let reconProof=null;
      if(objectiveId==='csrf_g1'&&(postgres||reconProofRepository)){
        try{const repository=reconProofRepository||require('../database/postgres/csrfReconProofRepository').createCsrfReconProofRepository(require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool);reconProof=await repository.read({execution,userId});}catch(error){await execution.check();}
      }
      // The completion service validates this captured attempt's identity and
      // mode stamp before admitting evidence. A tab's token toggle is separate
      // teaching state; it must never relabel the canonical workshop mode.
      const defenseObjective = ['csrf_g3', 'csrf_p3'].includes(objectiveId);
      const mode = postgres ? (attempt?.mode ?? 'vuln') : (defenseObjective ? 'fixed' : 'vuln');
      const fixedAttackObjective = mode === 'fixed' && ['csrf_g2','csrf_p1','csrf_p2','csrf_x3','csrf_i2','csrf_i3'].includes(objectiveId);
      let classified = null;
      if (objectiveId === 'csrf_x3' && typeof inspectClassifiedEmailProof === 'function') {
        try {
          classified = safeClassifiedProof(await inspectClassifiedEmailProof({ proof: classifiedEmailProof,
            userId, execution, attempt, snapshot, activity, receipt: browserReceipt || receipt }),
          { userId, attempt, execution });
        } catch { classified = null; }
      }
      await execution.check();
      const classifiedObjective = objectiveId === 'csrf_x3';
      const rubric = { family: 'CSRF', scenario: tabFor(objectiveId), objectiveId,
        version: objectiveId==='csrf_g1'?require('./csrfReconProof').VERSION:classifiedObjective ? (classified?.version===2?'csrf-selected-email-v2':'csrf-classified-email-v1') : defenseObjective && postgres ? 'csrf-defense-mode-v10' : 'csrf-observed-v8', mode,
        criteria: [{ id: classifiedObjective ? 'classified_browser_outcome' : 'observed_outcome',
          description: classifiedObjective
            ? (classified?.version===2?'A genuine model selected the exact owned delivered email for reading; the application rendered its original tool HTML, a separately classified browser request changed owned victim state, and all source/session/mode receipts match.':'A server-authenticated model-preserved email payload produced an opaque classified action, and the trusted browser execution changed the learner-owned victim state.')
            : CRITERIA[objectiveId], allowedSources: ['server_observation', 'tool_result'] }],
        requiredFacts: objectiveId==='csrf_g1'?['required_observation','actual_recon_history']:['required_observation'] };
      // Project the server tool DTO: optional runtime fields (for example note:
      // undefined) are not JSON evidence and must not invalidate a real outcome.
      const resultFields = ['kind', 'surface', 'error', 'actions', 'vectors', 'blocked', 'executed', 'stateChanged', 'vector', 'changed', 'outcome', 'defenses'];
      const actionEvidence = activity ? { name: activity.name || '', result: Object.fromEntries(
        resultFields.filter(key => activity.result?.[key] !== undefined)
          .map(key => [key, activity.result[key]])
      ) } : null;
      const mailKind = objectiveId === 'csrf_x2' ? 'accepted' : objectiveId === 'csrf_x3' ? 'retrieved' : null;
      const acceptedMailReceipt = objectiveId === 'csrf_x3' ? (mailReceipt || receipt) : receipt;
      const mailProof = mailKind && typeof inspectMailProof === 'function' ? inspectMailProof(acceptedMailReceipt, {
        kind: mailKind, userId: String(userId), generation: attempt?.generation ?? execution?.generation,
        runId: execution?.runId, ownerKey: execution?.ownerKey, durableGeneration: execution?.durableGeneration,
      }) : null;
      const receiptEvidence = mailProof ? {
        kind: mailKind, state: mailProof.state, dispatchId: mailProof.dispatchId,
        dispatchRunId: mailProof.dispatchRunId, recipientDigest: digest(mailProof.recipient), senderDigest: digest(mailProof.sender),
        providerMessageId: mailProof.providerMessageId, inboxMessageId: mailProof.inboxMessageId || null,
        subjectDigest: mailProof.expected?.subjectDigest || mailProof.subjectDigest,
        logicalBodyDigest: mailProof.expected?.logicalBodyDigest || mailProof.logicalBodyDigest,
        payloadDigest: mailProof.expected?.payloadDigest || mailProof.payloadDigest,
        hasEventHandler: mailProof.hasEventHandler === true,
      } : (mailKind ? null : receipt || null);
      const evidence = [
        { id: 'victim', source: 'server_observation', content: objectiveId === 'csrf_i2' ? { ...snapshot, executionBoundary: 'Lab server gadget interpreter; no independent browser execution claim.' } : snapshot },
        { id: 'action', source: 'tool_result', content: actionEvidence },
        { id: 'receipt', source: 'server_observation', content: receiptEvidence },
      ];
      if (classifiedObjective && browserReceipt) {
        evidence.push({ id: 'browser_receipt', source: 'server_observation', content: safeBrowserReceipt(browserReceipt) });
      }
      const facts = { required_observation: !fixedAttackObjective && observed(objectiveId, snapshot, activity, receipt, { mailProof })
        && (!classifiedObjective || classified !== null)
        && (!classifiedObjective
          ? (!BROWSER_OBJECTIVES.includes(objectiveId)
            || hasCsrfBrowserReceipt({ receipt, execution, activity, userId, objectiveId }))
          : !!browserReceipt && inspectBrowserReceipt({ receipt: browserReceipt, execution, activity, userId, objectiveId })) };
      if(objectiveId==='csrf_g1'){facts.actual_recon_history=require('./csrfReconProof').validProof(reconProof,{ownerKey:execution.ownerKey,runId:execution.runId,generation:execution.durableGeneration});evidence.push({id:'recon_history',source:'server_observation',content:reconProof});}
      if (classifiedObjective) evidence.push({ id: 'classified_email', source: 'server_observation', content: classified });
      if (postgres) return { ...await service().evaluate({ userId, workshopKey: 'csrf_workshop', rubric, evidence, facts, execution, attempt }), durable: true };
      const judgment = await judge({ rubric, evidence, facts, execution });
      await execution.check();
      return { judgment, completed: rubric.requiredFacts.every(id=>facts[id]===true) && judgment.verdict === 'pass', durable: false };
    },
  };
}
module.exports = { CRITERIA, tabFor, observed, createCsrfObjectiveGrader };
