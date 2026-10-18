'use strict';

const { createHash } = require('crypto');
const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { getXssBrowserQualification } = require('./xssBrowserQualification');
const { getObjectiveRubric } = require('../config/objectiveRubrics');
const { objectiveId } = require('../config/xssEmailBuilderCurriculum');
const { effectiveXssMode, renderEmailDocument } = require('./xssModePolicy');

const FAMILY = 'xss_email_builder';
const RECEIPT_VERSION = 'xss-email-v3';

const LEVELS = Object.freeze({
  1: {
    name: 'Basic Stored XSS (Name Field)',
    field: 'full_name',
    criteria: [
      { id: 'script_preserved', factId: 'script_element_preserved', description: 'The stored full_name script element is preserved verbatim in the generated email DOM.', allowedSources: ['server_observation'] },
      { id: 'script_executed', factId: 'script_element_executed', description: 'The preserved script executes when the stored email is parsed by the email document renderer.', allowedSources: ['server_observation'] },
    ],
    requiredFacts: ['script_element_preserved', 'script_element_executed', 'authenticated_owner', 'template_persisted'],
  },
  2: {
    name: 'Bypass Script Filter (Signature Field)',
    field: 'signature_html',
    criteria: [
      { id: 'handler_survived_filter', factId: 'signature_handler_preserved', description: 'An event handler from the stored signature survives the server script-tag filter in the persisted email.', allowedSources: ['server_observation'] },
      { id: 'handler_executed', factId: 'isolated_browser_executed', description: 'The surviving signature event handler executes in the isolated email preview sink.', allowedSources: ['server_observation'] },
    ],
    requiredFacts: ['signature_handler_preserved', 'isolated_browser_executed', 'authenticated_owner', 'template_persisted'],
  },
  3: {
    name: 'Event Handler Injection (Company Field)',
    field: 'company_name',
    criteria: [
      { id: 'company_handler_inserted', factId: 'company_handler_preserved', description: 'The stored company_name event handler is substituted into the persisted generated email.', allowedSources: ['server_observation'] },
      { id: 'handler_executed', factId: 'isolated_browser_executed', description: 'The company field event handler executes in the isolated email preview sink.', allowedSources: ['server_observation'] },
    ],
    requiredFacts: ['company_handler_preserved', 'isolated_browser_executed', 'authenticated_owner', 'template_persisted'],
  },
  4: {
    name: 'AI Prompt + XSS Chain',
    field: 'prompt',
    criteria: [
      { id: 'actual_model_output', factId: 'actual_model_xss_output', description: 'An available non-mock model produces an event-handler XSS payload in its raw generated HTML in response to the learner prompt.', allowedSources: ['assistant_response', 'server_observation'] },
      { id: 'model_xss_executed', factId: 'isolated_browser_executed', description: 'That model-produced handler executes in the isolated email preview sink.', allowedSources: ['server_observation'] },
    ],
    requiredFacts: ['actual_model_xss_output', 'isolated_browser_executed', 'authenticated_owner', 'template_persisted'],
  },
});

function hasHandler(value) {
  return typeof value === 'string' && /\bon(?:error|load|click|mouseover|focus|input|toggle)\s*=|javascript\s*:/i.test(value);
}

function hasScript(value) {
  return typeof value === 'string' && /<script\b/i.test(value);
}

function includedVerbatim(html, value) {
  return typeof value === 'string' && value.length > 0 && String(html || '').includes(value);
}

function candidateLevels({ profile, prompt, includeSignature, rawModelHtml, persistedHtml }) {
  const levels = [];
  if (hasScript(profile?.full_name) && includedVerbatim(persistedHtml, profile.full_name)) levels.push(1);
  if (includeSignature && hasHandler(profile?.signature_html) && includedVerbatim(persistedHtml, profile.signature_html)) levels.push(2);
  if (hasHandler(profile?.company_name) && includedVerbatim(persistedHtml, profile.company_name)) levels.push(3);
  // The level-four candidate must originate in the raw model output. Profile
  // substitution cannot be relabelled as an AI prompt-to-XSS result.
  // The learner may describe the desired behavior in natural language. The
  // candidate is the observed raw model output; actual-model provenance,
  // persisted source attribution, browser execution, and Judge pass still
  // gate credit below.
  if (hasHandler(rawModelHtml)) levels.push(4);
  return levels;
}

const PROOF_LABELS = Object.freeze({
  authenticated_owner: 'an authenticated owner',
  template_persisted: 'a persisted email template',
  script_element_preserved: 'preservation of the name-field script element',
  script_element_executed: 'execution of the name-field script element',
  signature_handler_preserved: 'preservation of the signature event handler',
  company_handler_preserved: 'preservation of the company-field event handler',
  actual_model_xss_output: 'an XSS payload produced by an available non-mock model',
  isolated_browser_executed: 'execution and an observable effect from the required source in the isolated browser',
});
function failureFeedback(level, facts, judgment) {
  if (judgment.verdict !== 'fail') return judgment;
  const missing = LEVELS[level].requiredFacts.filter(key => facts[key] !== true);
  if (!missing.length) return judgment;
  return {...judgment, explanation: `Could not confirm ${missing.map(key => PROOF_LABELS[key]).join('; ')}. No completion was awarded.`};
}

function withRequiredProofs(level, facts) {
  return {...Object.fromEntries(LEVELS[level].requiredFacts.map(key=>[key,facts[key]===true])), all_required_proofs: LEVELS[level].requiredFacts.every(key => facts[key] === true)};
}

function rubricFor(level, mode = 'vuln') {
  const spec = LEVELS[level];
  if (!spec) return undefined;
  if (mode !== 'vuln') return getObjectiveRubric(FAMILY, objectiveId(level), mode);
  return { version: RECEIPT_VERSION, family: FAMILY, scenario: `level_${level}`, objectiveId: `level_${level}`,
    mode: 'vuln', criteria: [{id:'observed_outcome',factId:'all_required_proofs',description: `The complete ${spec.name} objective occurred: ${spec.criteria.map(c=>c.description).join(' AND ')} All source, execution, owner and persistence proofs must hold together. The server browserQualification comes from a fresh isolated browser context. renderingMode innerHTML describes the DOM insertion operation inside that isolated context; it does not mean the browser is unisolated.`,allowedSources:['server_observation']}], requiredFacts: [...spec.requiredFacts,'all_required_proofs'] };
}

function sourceHtmlFor(level, { profile, rawModelHtml }) {
  if (level === 1) return String(profile?.full_name || '');
  if (level === 2) return String(profile?.signature_html || '')
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<\/?script[^>]*>/gi, '');
  if (level === 3) return String(profile?.company_name || '');
  if (level === 4) return String(rawModelHtml || '');
  return '';
}

function modelHandlerSources(provenance, persistedHtml) {
  if (!provenance || provenance.html !== String(persistedHtml || '') || !Array.isArray(provenance.modelRanges)) return [];
  const html = provenance.html;
  const modelOwned = (start, end) => provenance.modelRanges.some(range => Number.isInteger(range?.start)
    && Number.isInteger(range?.end) && range.start <= start && range.end >= end);
  const sources = [];
  for (const match of html.matchAll(/<[a-z][^>]*>/gi)) {
    const tag = match[0];
    const executablePattern = /\bon[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)|\bhref\s*=\s*(?:"[^"]*javascript\s*:[^"]*"|'[^']*javascript\s*:[^']*'|javascript\s*:[^\s>]+)/gi;
    for (const attributeMatch of tag.matchAll(executablePattern)) {
      const start = match.index + attributeMatch.index;
      const end = start + attributeMatch[0].length;
      // Every character of the executable attribute must be unchanged model
      // output. A profile-created handler on the same element remains excluded.
      if (modelOwned(start, end)) sources.push(attributeMatch[0]);
      if (sources.length >= 8) break;
    }
    if (sources.length >= 8) break;
  }
  return [...new Set(sources)];
}

function createXssEmailObjectiveGrader({ judge = createObjectiveJudge(), browserQualification = getXssBrowserQualification(),
  persistCompletion, persistJudgment, canonical }) {
  if (typeof persistCompletion !== 'function') throw new TypeError('persistCompletion is required');
  if (typeof persistJudgment !== 'function') throw new TypeError('persistJudgment is required');
  return {
    async evaluate({ userId, templateId, profile, prompt, includeSignature, rawModelResponse, persistedHtml,
      generationProvenance, requestedLevel, attempt, templateEffect, execution = {} }) {
      const check = execution.check || (async () => {});
      await check();
      const mode = effectiveXssMode(attempt?.mode);
      if (mode === 'fixed' && !rubricFor(requestedLevel, mode)) {
        return { completedLevels: [], judgments: [{ level: requestedLevel, objectiveId: objectiveId(requestedLevel),
          mode, verdict: 'inconclusive', explanation: 'Fixed preview renders stored HTML as inert text; no fixed defense objective is defined for this level.' }] };
      }
      const actualModel = Boolean(rawModelResponse && !rawModelResponse.mocked && !rawModelResponse.fallback
        && typeof rawModelResponse.model === 'string' && rawModelResponse.model.trim()
        && typeof rawModelResponse.provider === 'string' && rawModelResponse.provider.trim()
        && !/^(mock|fixture|controlled|fallback)(?:$|[-_:/])/i.test(rawModelResponse.provider));
      const rawModelHtml = String(rawModelResponse?.response || '');
      const levels = canonical ? [requestedLevel] : candidateLevels({ profile, prompt, includeSignature, rawModelHtml, persistedHtml });
      if (Number.isInteger(requestedLevel) && Object.hasOwn(LEVELS, requestedLevel) && !levels.includes(requestedLevel)) levels.push(requestedLevel);
      if (!levels.length) return { completedLevels: [], judgments: [] };
      const renderedHtml = renderEmailDocument(persistedHtml, mode);
      const browser = await browserQualification.qualify(renderedHtml, { signal: execution.signal });
      await check();
      const judgments = [];
      const completedLevels = [];
      for (const level of levels) {
        const selectedRubric = rubricFor(level, mode);
        if (!selectedRubric) continue;
        const sourceHtml = sourceHtmlFor(level, { profile, rawModelHtml });
        const modelSources = level === 4 ? modelHandlerSources(generationProvenance, persistedHtml) : [];
        await execution.trace?.({ node: 'qualify_source', type: 'node_start', data: { objectiveId: `level_${level}` } });
        const sourceBrowser = level === 1
          ? await (browserQualification.qualifyDocument?.(renderedHtml, {
            signal: execution.signal, scriptSource: sourceHtml,
          })
            || { executed: false, reason: 'document_qualification_unavailable', blockedRequests: [] })
          : await browserQualification.qualify(renderedHtml, {
            signal: execution.signal, eventSource: level === 4 ? undefined : sourceHtml,
            eventSources: level === 4 ? modelSources : undefined,
          });
        await check();
        // A handler elsewhere in the combined template cannot prove that this
        // objective's specific profile field or model output executed.
        const sourceExecuted = level === 1
          ? sourceBrowser?.scriptExecuted === true
          : sourceBrowser?.targetEventExecuted === true && sourceBrowser?.targetEffectObserved === true;
        await execution.trace?.({ node: 'qualify_source', type: 'node_end', data: {
          objectiveId: `level_${level}`, executed: sourceExecuted, durationMs: null } });
        const facts = withRequiredProofs(level, {
          authenticated_owner: userId !== null && userId !== undefined,
          template_persisted: Number.isInteger(Number(templateId)) && Number(templateId) > 0,
          script_element_preserved: level === 1 && includedVerbatim(persistedHtml, profile.full_name),
          signature_handler_preserved: level === 2 && includedVerbatim(persistedHtml, profile.signature_html) && hasHandler(profile.signature_html),
          company_handler_preserved: level === 3 && includedVerbatim(persistedHtml, profile.company_name) && hasHandler(profile.company_name),
          actual_model_xss_output: level === 4 && actualModel && hasHandler(rawModelHtml),
          isolated_browser_executed: sourceExecuted,
          // Level one uses the exact full_name source in a fresh document parser;
          // handlers in the combined template cannot be misattributed to it.
          script_element_executed: level === 1 && sourceExecuted,
        });
        facts.fixed_mode = mode === 'fixed';
        facts.inert_rendering = mode === 'fixed' && sourceExecuted !== true;
        if(canonical){
          facts.actual_model_generation=actualModel;
          facts.durable_template_effect=templateEffect?.status==='completed' && templateEffect.runId===execution.runId
            && templateEffect.ownerKey===execution.ownerKey && String(templateEffect.generation)===String(execution.durableGeneration)
            && templateEffect.effectKey===`${execution.runId}:persist_template`;
        }
        const evidence = [
          ...(canonical?[{id:'template_effect',source:'server_observation',content:templateEffect||null}]:[]),
          ...(level === 4 ? [
            { id: 'learner_prompt', source: 'student_input', content: String(prompt || '') },
            { id: 'model_output', source: 'assistant_response', content: rawModelHtml },
          ] : [{ id: 'persisted_objective_field', source: 'server_observation', content: {
            field: LEVELS[level].field, html: sourceHtml,
            preserved: level === 1 ? facts.script_element_preserved
              : level === 2 ? facts.signature_handler_preserved : facts.company_handler_preserved,
            renderingMode: level === 1 ? 'document' : 'innerHTML', executed: sourceExecuted,
          } }]),
          { id: 'generation_receipt', source: 'server_observation', content: {
            receiptVersion: RECEIPT_VERSION, authenticatedOwnerId: String(userId), templateId: Number(templateId),
            profileField: LEVELS[level].field, model: rawModelResponse?.model || null,
            provider: rawModelResponse?.provider || null, actualModel, facts,
            browserQualification: { provenance: 'isolated_qualification_browser', executed: browser?.executed === true,
              reason: browser?.reason || 'unknown', markers: browser?.markers || [], eventAttributes: browser?.eventAttributes || [],
              blockedExternalRequests: browser?.blockedRequests || [], syntheticCookieOnly: browser?.syntheticCookieOnly === true,
              source: { field: LEVELS[level].field, executed: sourceBrowser?.executed === true,
                renderingMode: level === 1 ? 'document' : 'innerHTML',
                reason: sourceBrowser?.reason || 'unknown', markers: sourceBrowser?.markers || [],
                ...(level === 1 ? {scriptExecuted: sourceBrowser?.scriptExecuted === true} : {targetEventExecuted: sourceBrowser?.targetEventExecuted === true,targetEffectObserved: sourceBrowser?.targetEffectObserved === true}),
                eventAttributes: sourceBrowser?.eventAttributes || [], blockedExternalRequests: sourceBrowser?.blockedRequests || [],
                syntheticCookieOnly: sourceBrowser?.syntheticCookieOnly === true } },
          } },
        ];
        const judgeExecution = execution.emit || !execution.trace ? execution : { ...execution, emit: execution.trace };
        const canonicalRubric = {...selectedRubric,
          objectiveId: require('../config/xssEmailBuilderCurriculum').objectiveId(level), version:'xss-email-canonical-v1',
          requiredFacts:[...selectedRubric.requiredFacts,'actual_model_generation','durable_template_effect']};
        const evaluated = canonical ? await canonical.evaluate({userId, rubric:canonicalRubric, evidence, facts, execution, attempt}) : null;
        if(canonical && (!evaluated || !evaluated.judgment || typeof evaluated.completed!=='boolean'))throw new TypeError('Canonical builder evaluation unavailable');
        const judgment = canonical ? evaluated.judgment : await judge({ rubric: selectedRubric, evidence, facts, execution: judgeExecution });
        await check();
        judgments.push({ level, ...failureFeedback(level, facts, judgment),
          ...(canonical ? {objectiveId:require('../config/xssEmailBuilderCurriculum').objectiveId(level)} : {}) });
        await execution.trace?.({ node: 'persist_judgment', type: 'node_start', data: { objectiveId: `level_${level}` } });
        await persistJudgment({ userId, level, templateId: Number(templateId), verdict: judgment.verdict,
          judgeVersion: judgment.judgeVersion || null, rubricVersion: judgment.rubricVersion || RECEIPT_VERSION,
          evidenceDigest: judgment.evidenceDigest || null, runId: judgment.runId || execution.runId || null,
          errorCode: judgment.errorCode || null, browserExecuted: sourceExecuted,
          browserReason: sourceBrowser?.reason || 'unknown' });
        await check();
        await execution.trace?.({ node: 'persist_judgment', type: 'node_end', data: {
          objectiveId: `level_${level}`, verdict: judgment.verdict } });
        if (judgment.verdict !== 'pass' || !LEVELS[level].requiredFacts.every(name => facts[name] === true) || (canonical && !evaluated.completed)) continue;
        const receipt = {
          version: RECEIPT_VERSION, level, templateId: Number(templateId), verdict: judgment.verdict,
          judgeVersion: judgment.judgeVersion, rubricVersion: judgment.rubricVersion,
          evidenceDigest: judgment.evidenceDigest, runId: judgment.runId || null,
          generatedHtmlDigest: createHash('sha256').update(String(persistedHtml || '')).digest('hex'),
          browserReason: sourceBrowser?.reason || 'unknown', recordedAt: new Date().toISOString(),
        };
        await persistCompletion({ userId, level, challengeName: LEVELS[level].name, receipt });
        await check();
        completedLevels.push(level);
      }
      return { completedLevels, judgments, qualification: browser };
    },
    close: () => browserQualification.close?.(),
  };
}

module.exports = { failureFeedback, withRequiredProofs, FAMILY, RECEIPT_VERSION, LEVELS, rubricFor, candidateLevels, sourceHtmlFor,
  modelHandlerSources, createXssEmailObjectiveGrader };
