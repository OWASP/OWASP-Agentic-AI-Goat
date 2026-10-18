'use strict';

const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { getObjectiveRubric } = require('../config/objectiveRubrics');
const { createXssBrowserQualification } = require('./xssBrowserQualification');
const { inspectXssMailProof } = require('./xssEmailDispatch');
const { extractStoredUserArtifact } = require('./xssProfileWriteContract');
const { effectiveXssMode } = require('./xssModePolicy');

const EXECUTION_OBJECTIVES = new Set(['xss_r3', 'xss_s3', 'xss_g3', 'xss_e3']);
const STORED_EXECUTION_OBJECTIVES = new Set(['xss_s3', 'xss_g3']);
const BROWSER_OBJECTIVES = new Set(['xss_r2', ...EXECUTION_OBJECTIVES]);
const WORKSHOP_KEY = 'xss_workshop';

function hasHandler(value) {
  return typeof value === 'string' && /\bon(?:error|load|click|mouseover|focus|input|toggle)\s*=|javascript\s*:/i.test(value);
}

function firstElement(value) {
  return typeof value === 'string' ? value.match(/<[a-z][^>]*>/i)?.[0] || null : null;
}

function buildReceipt({ objectiveId, exerciseId, message, response, grading = {}, profileBefore, profileReadback,
  configuredInbox, delivery, mailProof }) {
  const tool = grading.toolCall?.tool || null;
  const result = grading.toolResult || null;
  let valid = false;
  let html = null;
  let emailBodyReturned = false;
  let rawBodyAppended = false;
  const storedEventSources = ['name', 'bio', 'website'].map(field => result?.profile?.[field])
    .filter(value => hasHandler(value) && String(response || '').includes(value));
  switch (objectiveId) {
    case 'xss_r1': valid = exerciseId === 'reflected' && !tool && grading.modelSucceeded !== false && Boolean(String(response || '').trim()); break;
    case 'xss_r2': {
      const element = firstElement(message);
      // This is only a source candidate. Completion additionally requires the
      // isolated browser's learner-element comparison below.
      valid = exerciseId === 'reflected' && Boolean(element) && Boolean(String(response || '').trim());
      break;
    }
    case 'xss_r3': valid = exerciseId === 'reflected' && hasHandler(response); html = response; break;
    case 'xss_s1': valid = exerciseId === 'stored_user' && tool === 'getProfile' && Boolean(result?.profile); break;
    case 'xss_s2': {
      const artifact = extractStoredUserArtifact(message);
      valid = exerciseId === 'stored_user' && tool === 'updateProfile' && result?.success === true &&
        artifact !== null && artifact.field === result.field && artifact.value === result.value &&
        hasHandler(result.value) && profileReadback?.[result.field] === artifact.value;
      break;
    }
    case 'xss_s3':
      valid = exerciseId === 'stored_user' && tool === 'getProfile' && storedEventSources.length > 0;
      html = response;
      break;
    case 'xss_g1': valid = exerciseId === 'stored_llm' && !tool && grading.modelSucceeded !== false && Boolean(String(response || '').trim()) &&
      JSON.stringify(profileBefore || null) === JSON.stringify(profileReadback || null); break;
    case 'xss_g2':
      valid = exerciseId === 'stored_llm' && grading.modelSucceeded !== false && tool === 'updateProfile' && result?.success === true &&
        hasHandler(result.value) && !String(message || '').includes(result.value) && profileReadback?.[result.field] === result.value;
      break;
    case 'xss_g3':
      valid = exerciseId === 'stored_llm' && tool === 'getProfile' && storedEventSources.length > 0;
      html = response;
      break;
    case 'xss_e1': valid = exerciseId === 'email' && tool === 'listEmails' && Boolean(configuredInbox) && Array.isArray(result?.emails); break;
    case 'xss_e2': valid = mailProof?.kind === 'accepted' && delivery?.smtpAccepted === true && delivery?.success === true && Boolean(delivery.canonicalRecipient) &&
      delivery.canonicalRecipient === delivery.configuredRecipient && hasHandler(delivery.payload); break;
    case 'xss_e3':
      emailBodyReturned = mailProof?.kind === 'retrieved' && exerciseId === 'email' && tool === 'getEmail'
        && hasHandler(result?.email?.body);
      rawBodyAppended = emailBodyReturned && String(response || '').includes(result.email.body);
      valid = emailBodyReturned && rawBodyAppended;
      html = response;
      break;
    default: break;
  }
  return { valid, html, tool, result, emailBodyReturned, rawBodyAppended, storedEventSources };
}

function createXssObjectiveGrader({ completionService, judge = createObjectiveJudge(),
  browserQualification = createXssBrowserQualification(), syncObjectiveComplete, readProfileOrigin,
  postgres = process.env.PLATFORM_DATABASE_ENGINE === 'postgres' }) {
  const service = () => completionService || require('./objectiveCompletionService').getObjectiveCompletionService();
  return {
    async begin(userId, objectiveId, execution) {
      await execution.check();
      if (userId === null || userId === undefined) return null;
      return postgres
        ? service().beginAttempt({ userId, workshopKey: WORKSHOP_KEY, objectiveId, execution })
        : { generation: execution.generation };
    },
    async evaluate({ userId, objectiveId, exerciseId, message, response, grading, profileBefore, profileReadback,
      configuredInbox, delivery, execution, attempt }) {
      const mode = effectiveXssMode(attempt?.mode);
      const rubric = getObjectiveRubric(WORKSHOP_KEY, objectiveId, mode);
      if (!rubric) return { completed: false, judgment: { objectiveId, mode, verdict: 'inconclusive',
        explanation: mode === 'fixed'
          ? 'Fixed rendering keeps this attack objective inert; no fixed defense objective is defined for it.'
          : 'No applicable objective rubric is available.' } };
      if (!attempt || userId === null || userId === undefined) return { completed: false, judgment: {
        objectiveId, verdict: 'inconclusive', explanation: 'Sign in with a workshop account to record judged objective progress.' } };
      const mailProof = inspectXssMailProof(objectiveId === 'xss_e2' ? delivery : grading?.toolResult?.email,
        { kind: objectiveId === 'xss_e2' ? 'accepted' : 'retrieved', userId, generation: attempt.generation,
          runId: execution.runId, ownerKey: execution.ownerKey, durableGeneration: execution.durableGeneration });
      const receipt = buildReceipt({ objectiveId, exerciseId, message, response, grading, profileBefore, profileReadback, configuredInbox, delivery, mailProof });
      const storedValueReturned = STORED_EXECUTION_OBJECTIVES.has(objectiveId) && receipt.storedEventSources.length > 0;
      let originEvidence = { modelProfileOriginCurrent: false, canonicalModelSaveCompleted: false, eventSources: [], checks: [{ field: null, reason: 'origin_reader_unavailable' }] };
      if (['xss_g2', 'xss_g3'].includes(objectiveId)) {
        if (typeof readProfileOrigin === 'function') {
          originEvidence = await require('./xssStoredOriginEvidence').createXssStoredOriginEvidence({
            readCurrent: readProfileOrigin,
            hasPrerequisite: input => service().hasPrerequisite(input),
          })({ objectiveId, userKey: String(userId), platformUserId: Number(userId), grading, execution, attempt });
        }
        receipt.valid = receipt.valid && originEvidence.modelProfileOriginCurrent
          && (objectiveId !== 'xss_g3' || originEvidence.canonicalModelSaveCompleted);
        if (objectiveId === 'xss_g3') receipt.storedEventSources = originEvidence.eventSources
          .filter(value => String(response || '').includes(value));
        if (objectiveId === 'xss_g3' && !receipt.storedEventSources.length) receipt.valid = false;
      }
      let browser = null;
      const browserHtml = objectiveId === 'xss_r2' ? response : receipt.html;
      if (receipt.valid && BROWSER_OBJECTIVES.has(objectiveId) && browserHtml) {
        browser = await browserQualification.qualify(browserHtml, { signal: execution.signal,
          ...(objectiveId === 'xss_r2' ? { learnerHtml: message } : {}),
          ...(objectiveId === 'xss_e3' ? { eventSource: receipt.result.email.body } : {}),
          ...(STORED_EXECUTION_OBJECTIVES.has(objectiveId) ? { eventSources: receipt.storedEventSources } : {}) });
        if (objectiveId === 'xss_e3' || STORED_EXECUTION_OBJECTIVES.has(objectiveId)) browser = { ...browser, executed: browser?.targetEventExecuted === true };
        await execution.check();
      }
      const receiptValid = receipt.valid && (objectiveId !== 'xss_r2' || (browser?.learnerElementPreserved === true && (browser?.elementCount || 0) > 0));
      const facts = {
        model_profile_origin_current: originEvidence.modelProfileOriginCurrent,
        canonical_model_save_completed: originEvidence.canonicalModelSaveCompleted,
        stored_value_returned: storedValueReturned,
        attributed_browser_execution: STORED_EXECUTION_OBJECTIVES.has(objectiveId) && browser?.targetEventExecuted === true,
        objective_signal_detected: receiptValid,
        vulnerable_mode: mode === 'vuln',
        fixed_mode: mode === 'fixed',
        server_receipt_valid: receiptValid,
        isolated_browser_executed: browser?.executed === true,
        raw_html_preserved: objectiveId === 'xss_r2' && receiptValid,
        dom_element_created: objectiveId === 'xss_r2' && (browser?.elementCount || 0) > 0,
        stored_payload_returned: ['xss_s3', 'xss_g3'].includes(objectiveId) && receiptValid,
        actual_model_response: grading?.modelSucceeded === true,
        raw_html_dom_preserved: objectiveId === 'xss_r2' && receiptValid,
        email_body_returned: objectiveId === 'xss_e3' && receipt.emailBodyReturned,
        raw_body_appended: objectiveId === 'xss_e3' && receipt.rawBodyAppended,
        email_xss_execution_chain: objectiveId === 'xss_e3' && receipt.emailBodyReturned && receipt.rawBodyAppended && browser?.executed === true,
      };
      const evidence = [
        { id: 'request', source: 'student_input', content: message || '' },
        { id: 'tool_receipt', source: 'tool_result', content: {
          tool: receipt.tool, result: receipt.result, profileBefore: profileBefore || null, profileReadback: profileReadback || null,
          delivery: delivery || null, configuredInbox: configuredInbox || null,
        } },
        { id: 'server_receipt', source: 'server_observation', content: {
          exerciseId, receiptValid, authenticatedOwnerId: String(userId),
          rawLearnerElement: objectiveId === 'xss_r2' ? firstElement(message) : null,
          outputContainsRawLearnerElement: objectiveId === 'xss_r2' ? browser?.learnerElementPreserved === true : null,
          storedPayloadReturned: ['xss_s3', 'xss_g3'].includes(objectiveId) ? receipt.valid : null,
          actualModelResponse: grading?.modelSucceeded === true,
          ...(['xss_g2', 'xss_g3'].includes(objectiveId) ? { modelProfileOriginCurrent: originEvidence.modelProfileOriginCurrent, canonicalModelSaveCompleted: originEvidence.canonicalModelSaveCompleted, profileOrigins: originEvidence.origins || [], profileOriginChecks: originEvidence.checks || [] } : {}),
          emailBodyReturned: objectiveId === 'xss_e3' ? receipt.emailBodyReturned : null,
          rawBodyAppended: objectiveId === 'xss_e3' ? receipt.rawBodyAppended : null,
          mailProvenance: mailProof || null,
          mode, browserQualification: browser ? {
            provenance: 'isolated_qualification_browser', executed: browser.executed,
            ...((objectiveId === 'xss_e3' || STORED_EXECUTION_OBJECTIVES.has(objectiveId)) ? { targetEventExecuted: browser.targetEventExecuted === true } : {}),
            ...(objectiveId === 'xss_r2' ? { learnerElementPreserved: browser.learnerElementPreserved === true } : {}),
            markers: browser.markers ?? [], eventAttributes: browser.eventAttributes ?? [],
            interactions: browser.interactions || [], blockedExternalRequests: browser.blockedRequests || [],
            syntheticCookieOnly: browser.syntheticCookieOnly ?? false,
            finalCookieIsSyntheticOnly: browser.finalCookieIsSyntheticOnly ?? null,
            elementCount: browser.elementCount ?? 0, reason: browser.reason || 'unknown',
          } : null,
          browserReportNonceAccepted: false,
        } },
      ];
      if (objectiveId === 'xss_e3') {
        const record = evidence.find(item => item.id === 'server_receipt');
        const { exerciseId, receiptValid, authenticatedOwnerId, emailBodyReturned,
          rawBodyAppended, mailProvenance, mode, browserQualification } = record.content;
        record.content = { exerciseId, receiptValid, authenticatedOwnerId,
          emailBodyReturned, rawBodyAppended, mailProvenance, mode, browserQualification,
          email_xss_execution_chain: facts.email_xss_execution_chain };
        // Other exercises' model/profile/DOM flags are not requirements of this
        // tool-body execution chain. Keep every requirement of this objective.
        for (const key of Object.keys(facts)) if (!rubric.requiredFacts.includes(key)) delete facts[key];
      }
      if (rubric.criteria.some(criterion => criterion.allowedSources.includes('assistant_response'))) {
        evidence.splice(1, 0, { id: 'answer', source: 'assistant_response', content: response || '' });
      }
      // Exact fact-only criteria need one unambiguous server receipt. Keeping
      // unrelated request/tool records in these packets made the small local
      // model produce invalid evidence references despite schema repair.
      const judgeEvidence = ['xss_r2', 'xss_e3'].includes(objectiveId)
        ? evidence.filter(item => item.id === 'server_receipt')
        : evidence;
      if (postgres) {
        const grade = await service().evaluate({ userId, workshopKey: WORKSHOP_KEY, rubric, evidence: judgeEvidence, facts, execution, attempt });
        return { ...grade, qualification: browser };
      }
      const judgment = await judge({ rubric, evidence: judgeEvidence, facts, execution });
      await execution.check();
      if (judgment.verdict !== 'pass') return { completed: false, judgment, qualification: browser };
      await syncObjectiveComplete(userId, WORKSHOP_KEY, objectiveId, objectiveId, exerciseId);
      await execution.check();
      return { completed: true, judgment, qualification: browser };
    },
    close: () => browserQualification.close(),
  };
}

module.exports = { createXssObjectiveGrader, buildReceipt, hasHandler, EXECUTION_OBJECTIVES, BROWSER_OBJECTIVES };
