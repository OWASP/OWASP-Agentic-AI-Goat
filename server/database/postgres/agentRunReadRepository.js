'use strict';

const SECURESHOP_FAMILY = 'SecureShopBoundConversation';
// These families use [family, platformUserId] owner keys and are also the
// deletion run-drain catalog. SecureShop conversation keys need a persisted
// resolver and must never be added to that direct-owner drain list.
const RUN_FAMILIES = Object.freeze(['ARIA', 'NOVA', 'ARIA:legacy', 'NOVA:legacy', 'CodeBot', 'RAG', 'XSS', 'XSS_EMAIL', 'CSRF', 'MCP', 'DPI', 'IndirectEmail', 'ExcessiveAgency', 'FinFlow', 'IPI', 'CTF', 'LegacySensitiveInfo', 'SensitiveLookup']);
const OBSERVABLE_RUN_FAMILIES = Object.freeze([...RUN_FAMILIES, SECURESHOP_FAMILY]);
const DIRECT_RUN_FAMILIES = RUN_FAMILIES;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function ownerKey(family, userId) { return JSON.stringify([family, String(userId)]); }
function ownerKeys(userId, family) { return (family ? [family] : DIRECT_RUN_FAMILIES)
  .filter(name => name !== SECURESHOP_FAMILY).map(name => ownerKey(name, userId)); }
function parseOwner(value) {
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length !== 2 || !OBSERVABLE_RUN_FAMILIES.includes(parsed[0])) return null;
    if (parsed[0] === SECURESHOP_FAMILY) return UUID.test(String(parsed[1]))
      ? { family: parsed[0], ownerId: null, conversationId: String(parsed[1]).toLowerCase() } : null;
    return { family: parsed[0], ownerId: String(parsed[1]) };
  } catch { return null; }
}
function encodeCursor(run) {
  const startedAt = run.cursorStartedAt || new Date(run.startedAt).toISOString();
  return Buffer.from(JSON.stringify({ startedAt, runId: run.runId })).toString('base64url');
}
function decodeCursor(value) {
  if (!value || typeof value !== 'string' || value.length > 300) throw new TypeError('Invalid cursor');
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    if (Object.keys(parsed).sort().join(',') !== 'runId,startedAt' || !UUID.test(parsed.runId) || Number.isNaN(Date.parse(parsed.startedAt))) throw new Error();
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})Z$/.test(parsed.startedAt)) throw new Error();
    return { runId: parsed.runId, startedAt: parsed.startedAt };
  } catch { throw new TypeError('Invalid cursor'); }
}
function publicRun(row, includeOwner = false, resolvedOwnerId) {
  const owner = parseOwner(row.ownerKey || row.owner_key);
  if (!owner) return null;
  const platformOwnerId = owner.family === SECURESHOP_FAMILY ? resolvedOwnerId : owner.ownerId;
  if (platformOwnerId == null) return null;
  const run = { runId: row.runId, family: owner.family, generation: row.generation, status: row.status,
    provider: row.provider || null, model: row.model || null, decisionSource: row.decisionSource || null,
    lastNode: row.lastNode || null, startedAt: row.startedAt, finishedAt: row.finishedAt || null };
  if (row.tokens !== null && row.tokens !== undefined && Number(row.tokens) > 0) run.tokens = Number(row.tokens);
  if (includeOwner) run.ownerId = String(platformOwnerId);
  return run;
}

// Receipt metadata is intentionally a small, non-content projection.  The
// run inspector needs to distinguish a model verdict from the canonical
// completion decision, but must never expose the stored grading packet or
// result JSON.
// Optional historical observation, derived only from the retained server packet.
// Null/pruned retry packets and malformed data leave the ordinary receipt intact.
function mailBrowserObservation(row) {
  try {
    if (row.source && row.source !== 'canonical') return null;
    if (row.family !== 'SecureShop' || row.scenario !== 'bound_mail_browser'
      || row.objectiveId !== 'ss_mail_stored_browser_execution' || row.rubricVersion !== 'secureshop-mail-browser-v1'
      || row.mode !== 'vuln' || !UUID.test(row.evaluationId || '') || !UUID.test(row.runId || '')
      || row.packetEvaluationId !== row.evaluationId || row.packetModeMatches !== true
      || !/^[1-9][0-9]*$/.test(String(row.packetUserId)) || typeof row.observationPacket !== 'string'
      || Buffer.byteLength(row.observationPacket) > 100000 || !digest(row.evidenceDigest)
      || require('node:crypto').createHash('sha256').update(row.observationPacket).digest('hex') !== row.evidenceDigest) return null;
    const packet = JSON.parse(row.observationPacket), rubric = packet.rubric;
    if (rubric?.family !== row.family || rubric.scenario !== row.scenario || rubric.objectiveId !== row.objectiveId
      || rubric.version !== row.rubricVersion || rubric.mode !== row.mode || !Array.isArray(packet.evidence) || packet.evidence.length !== 1) return null;
    const evidence = packet.evidence[0], c = evidence.content, facts = packet.facts;
    if (evidence.id !== 'mail_browser' || evidence.source !== 'server_observation' || c?.version !== 1
      || c.component?.id !== 'SecureShop.MailMessageBody' || !digest(c.component.sourceSha256) || !digest(c.component.artifactSha256)
      || !digest(c.requestSha256) || !digest(c.htmlSha256) || !digest(c.sendReceipt?.contentSha256)
      || c.binding?.mode !== 'vuln' || c.sendReceipt.senderId !== c.binding.persona?.id
      || !Number.isSafeInteger(c.sendReceipt.email_id) || c.sendReceipt.email_id < 1
      || String(c.binding.scope?.platformOwnerId) !== String(row.packetUserId)
      || c.effectReceipt?.version !== 1 || c.effectReceipt.status !== 'completed'
      || c.effectReceipt.runId !== row.runId || typeof row.packetOwnerKey !== 'string'
      || c.effectReceipt.ownerKey !== row.packetOwnerKey || row.packetOwnerGeneration == null
      || String(c.effectReceipt.generation) !== String(row.packetOwnerGeneration)
      || typeof c.effectReceipt.effectKey !== 'string' || !c.effectReceipt.effectKey.length) return null;
    const b = c.browser;
    if (!b || ['executed','targetEventExecuted','targetEffectObserved','syntheticCookieOnly','finalCookieIsSyntheticOnly'].some(k => typeof b[k] !== 'boolean')
      || !Array.isArray(b.markers) || b.markers.length > 100 || !facts
      || facts.owned_saved_mail !== true || facts.actual_inbox_component !== true
      || facts.completed_browser_effect !== true || facts.vulnerable_mode !== true) return null;
    const attributed = b.executed && b.targetEventExecuted && b.targetEffectObserved && b.syntheticCookieOnly && b.finalCookieIsSyntheticOnly && b.markers.length > 0;
    if (facts.attributed_browser_execution !== attributed) return null;
    return { version: 'saved-mail-browser-observation-v1', componentMounted: true, browserEffectCompleted: true,
      attributedExecution: attributed, targetEffectObserved: b.targetEffectObserved, provenanceDigest: row.evidenceDigest };
  } catch { return null; }
}

function publicJudgment(row) {
  if (!row) return null;
  const verdict = row.verdict ?? null;
  const allowedSources = new Set(['canonical', 'ctf', 'legacy_sensitive', 'xss_email']);
  const projected = {
    source: allowedSources.has(row.source) ? row.source : 'canonical',
    receiptId: bounded(row.receiptId ?? row.receipt_id ?? row.evaluationId ?? row.evaluation_id ?? row.runId ?? row.run_id),
    evaluationId: bounded(row.evaluationId ?? row.evaluation_id),
    runId: bounded(row.runId ?? row.run_id),
    workshopKey: bounded(row.workshopKey ?? row.workshop_key),
    objectiveId: bounded(row.objectiveId ?? row.objective_id),
    family: bounded(row.family),
    scenario: bounded(row.scenario),
    rubricVersion: bounded(row.rubricVersion ?? row.rubric_version),
    evidenceDigest: digest(row.evidenceDigest ?? row.evidence_digest),
    configDigest: digest(row.configDigest ?? row.config_digest),
    explanation: bounded(row.explanation, 1000),
    criteria: safeCriteria(row.criteria),
    judgeProvider: bounded(row.judgeProvider ?? row.judge_provider ?? row.provider),
    judgeModel: bounded(row.judgeModel ?? row.judge_model ?? row.model),
    usage: safeUsage(row.usage),
    generation: row.generation,
    mode: bounded(row.mode),
    canonicalMode: bounded(row.canonicalMode ?? row.canonical_mode),
    verdict: bounded(verdict),
    disposition: bounded(row.disposition ?? (verdict == null ? 'pending' : 'not_pass')),
    createdAt: row.createdAt ?? row.created_at,
    evaluatedAt: row.evaluatedAt ?? row.evaluated_at ?? null,
    errorCode: bounded(row.errorCode ?? row.error_code),
    childEvaluationId: bounded(row.childEvaluationId ?? row.child_evaluation_id),
  };
  if(projected.family==='SecureShop'&&projected.scenario==='bound_pricing'
    &&projected.objectiveId==='ss_pricing_false_grounding'
    &&projected.rubricVersion==='secureshop-pricing-grounding-v2'&&projected.criteria){
    projected.criteria=projected.criteria.map(({citations,...criterion})=>criterion);
  }
  if(projected.family==='DPI'&&projected.objectiveId==='obfuscation'&&projected.mode==='fixed'&&['dpi-obfuscation-v9','dpi-obfuscation-v10'].includes(projected.rubricVersion)){
    projected.explanation='Fixed mode cannot earn attack credit; this does not establish that the actor stayed in scope.';projected.criteria=[];return projected;
  }
  if(row.disposition==='grading_unqualified'){projected.gradingStatus='pending';projected.gradingDisposition='grading_unqualified';}
  if (projected.family === 'SecureShop' && projected.scenario === 'indirect_content'
      && projected.objectiveId === 'ss_content_persist' && projected.rubricVersion === 'secureshop-review-content-v2'
      && row.reviewModeration?.version === 'review-persistence-source-v1') {
    try {
      projected.reviewModeration = require('../../agent-runtime/reviewModerationAudit').normalizeReviewModerationAudit(
        row.reviewModeration, { verdict, criteria: projected.criteria, attempts: row.attempts,
          provider: projected.judgeProvider, model: projected.judgeModel });
    } catch { /* Invalid audit data is never projected as validated provenance. */ }
  }
  const mailObservation = mailBrowserObservation(row);
  if (mailObservation) projected.serverObservation = mailObservation;
  const comparisonVersion = bounded(row.comparisonVersion ?? row.comparison_version, 100);
  const observation = safeSemanticObservation(row.semanticObservation ?? row.semantic_observation, comparisonVersion, verdict);
  if (comparisonVersion==='email-material-action-v1') {
    try {
      if(projected.family!=='IPI'||projected.scenario!=='email'||projected.objectiveId!=='email_trigger_injection'||projected.rubricVersion!=='ipi-email-material-action-v5'||projected.mode!=='vuln'||!observation)throw Error('Wrong email material scope');
      const stages=safeComparisonStages(row.comparisonStages??row.comparison_stages,comparisonVersion);
      if(!stages||row.attempts!==stages.reduce((n,s)=>n+s.attempts,0)||(verdict==='pass'&&(stages.length!==3||stages.some(s=>!s.completed||s.attempts<1))))throw Error('Invalid material stage audit');
      observation.materialSupport=require('../../agent-runtime/sourceComparisonVerifier').normalizeEmailMaterialAudit(observation,{verdict,criteria:projected.criteria,errorCode:projected.errorCode});
      projected.semanticObservation=observation;
    } catch { return projected; }
  } else if (observation) projected.semanticObservation = observation;
  const comparisonStages = safeComparisonStages(row.comparisonStages ?? row.comparison_stages, comparisonVersion);
  if (comparisonVersion && comparisonStages) {
    projected.comparisonVersion = comparisonVersion;
    projected.comparisonStages = comparisonStages;
  }
  return projected;
}

function bounded(value, maximum = 160) {
  if (typeof value !== 'string') return null;
  const text = value;
  return text.length > maximum ? `${text.slice(0, maximum - 1)}…` : text;
}
function digest(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value) ? value : null;
}
function accepted(value) { return value === true || value === 1 || value === '1' || value === 'true'; }
function safeUsage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const usage = {};
  for (const key of ['inputTokens', 'outputTokens', 'totalTokens']) {
    if (Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] >= 0) usage[key] = value[key];
  }
  return Object.keys(usage).length ? usage : null;
}
function safeCriteria(value) {
  if (!Array.isArray(value)) return null;
  return value.slice(0, 100).flatMap(item => {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string' || typeof item.satisfied !== 'boolean') return [];
    const sourceRefs = Array.isArray(item.evidenceRefs) ? item.evidenceRefs.slice(0, 30)
      .filter(ref => typeof ref === 'string') : [];
    const refs = sourceRefs.map(ref => bounded(ref, 100));
    const permittedRefs = new Set(sourceRefs.filter(ref => ref.length > 0 && ref.length <= 100));
    const criterion = { id: bounded(item.id, 100), satisfied: item.satisfied, evidenceRefs: refs };
    if (item.satisfied && Array.isArray(item.citations) && item.citations.length <= 10) {
      const citations = item.citations.flatMap(citation => {
        if (!citation || typeof citation !== 'object' || Array.isArray(citation)
          || typeof citation.evidenceId !== 'string' || !citation.evidenceId.length || citation.evidenceId.length > 100
          || !permittedRefs.has(citation.evidenceId) || typeof citation.quote !== 'string'
          || !citation.quote.length || citation.quote.length > 1000) return [];
        return [{ evidenceId: citation.evidenceId, quote: citation.quote }];
      });
      if (citations.length) criterion.citations = citations;
    }
    return [criterion];
  });
}
function safeComparisonStages(value, version) {
  const threeStageVersions=['email-material-action-v1','dpi-reference-entailment-v9','source-only-obligation-verified-v4','source-only-obligation-verified-v5','source-only-obligation-verified-v6',
    'pricing-directive-groups-v1','pricing-directive-quotes-v2','pricing-evidence-selection-v3','pricing-semantic-decomposition-v4','pricing-semantic-decomposition-v5','pricing-semantic-decomposition-v6','pricing-grounding-comparison-v1',
    'rag-directive-groups-v1','rag-evidence-selection-v2','rag-semantic-decomposition-v3','rag-semantic-decomposition-v4'];
  const twoStageVersions=['dpi-reference-entailment-v2','dpi-reference-entailment-v3','dpi-reference-entailment-v4',
    'dpi-reference-entailment-v5','dpi-reference-entailment-v6','dpi-reference-entailment-v7','dpi-reference-entailment-v8',
    'source-only-multi-instruction-effect-bound-v3'];
  const order=version==='pricing-semantic-decomposition-v6'?['source','effect','relation','support']:threeStageVersions.includes(version)?['source','effect','support']:twoStageVersions.includes(version)?['source','effect']:null;
  if(!order)return null;
  if (!Array.isArray(value) || !value.length || value.length > order.length) return null;
  const stages=value.flatMap((stage,index)=>{
    if(!stage||typeof stage!=='object'||Array.isArray(stage)||stage.stage!==order[index]
      ||!Number.isSafeInteger(stage.attempts)||stage.attempts<0||stage.attempts>2||typeof stage.completed!=='boolean'
      ||!(stage.provider===null||typeof stage.provider==='string')||!(stage.model===null||typeof stage.model==='string'))return [];
    return [{stage:stage.stage,attempts:stage.attempts,provider:stage.provider===null?null:bounded(stage.provider,100),model:stage.model===null?null:bounded(stage.model,200),completed:stage.completed}];
  });
  return stages.length===value.length?stages:null;
}
function safeSemanticObservation(value, comparisonVersion, verdict) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if(comparisonVersion==='pricing-grounding-comparison-v1'){
    if(value.sourceInstruction?.classification!=='generated_unverified'||value.sourceGrounded!==false
      ||!['verified_measurement','projection_or_estimate','other','uncertain'].includes(value.relation)
      ||typeof value.sourceSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.sourceSha256))return null;
    // Public diagnostics keep the source identity and semantic decision, never source or answer text.
    return {sourceInstruction:{classification:'generated_unverified'},relation:value.relation,
      sourceSha256:value.sourceSha256,sourceGrounded:false};
  }
  if(comparisonVersion==='rag-semantic-decomposition-v4'){
    // Display-only bounded ID projection; never used for grading authority.
    try{
      // This read projection does not grant authority; only admitted field types are exposed.
      if(!['embedded_redirect','ordinary_content','uncertain'].includes(value.sourceInstruction?.classification)||!['complete','uncertain','overflow'].includes(value.extractionCoverage)||![null,'no_omitted_directive','missing','uncertain'].includes(value.independentSourceCoverage)||!Array.isArray(value.directiveGroups)||value.directiveGroups.length>16)return null;
      let count=0;
      const groups=value.directiveGroups.map((g,i)=>{
        if(g.id!==`g${i}`||!Array.isArray(g.conditions)||!g.conditions.length)throw Error('group');
        const conditions=g.conditions.map((c,j)=>{
          if(++count>64||c.id!==`c${j}`||!['action','constraint','uncertain'].includes(c.role)||![null,'action','constraint','uncertain'].includes(c.verifiedRole)||![null,'yes','no','uncertain'].includes(c.execution)||!Array.isArray(c.executionEvidence)||c.executionEvidence.length>64||c.executionEvidence.some(id=>typeof id!=='string'||!/^r(?:0|[1-9]\d*)$/.test(id)))throw Error('condition');
          return {id:c.id,role:c.role,verifiedRole:c.verifiedRole,execution:c.execution,executionEvidence:[...c.executionEvidence]};
        });
        return {id:g.id,conditions};
      });
      return {sourceInstruction:{classification:value.sourceInstruction.classification,sourceQuoteId:null},extractionCoverage:value.extractionCoverage,independentSourceCoverage:value.independentSourceCoverage,directiveGroups:groups};
    }catch{return null;}
  }
  if(['pricing-semantic-decomposition-v5','pricing-semantic-decomposition-v6'].includes(comparisonVersion)){
    // Retain only bounded classifications and statuses. Source, response, task,
    // citations, and model-proposed request text never leave the receipt reader.
    try{
      if(!['embedded_redirect','ordinary_content','uncertain'].includes(value.sourceInstruction?.classification)
        ||!['complete','uncertain','overflow'].includes(value.extractionCoverage)
        ||![null,'no_omitted_directive','missing','uncertain'].includes(value.independentSourceCoverage)
        ||!Array.isArray(value.directiveGroups)||value.directiveGroups.length>16)return null;
      const tri=[null,'yes','no','uncertain'];
      const groups=value.directiveGroups.map((group,index)=>{
        if(!group||typeof group!=='object'||Array.isArray(group)||group.id!==`g${index}`
          ||!['conjunction','unresolved'].includes(group.structure)||!tri.includes(group.faithful)||!tri.includes(group.independent)
          ||![null,'assistant_operative','nonoperative','uncertain'].includes(group.recipient)
          ||![null,'unauthorized','consistent','uncertain'].includes(group.taskRelation)
          ||!tri.includes(group.applicability)||![null,'adopted','mentioned','refused','uncertain'].includes(group.adoption)
          ||!Array.isArray(group.conditions)||!group.conditions.length||group.conditions.length>64)throw Error('group');
        const conditions=group.conditions.map((condition,conditionIndex)=>{
          if(!condition||typeof condition!=='object'||Array.isArray(condition)||condition.id!==`c${conditionIndex}`
            ||!tri.includes(condition.entailed)||![null,'semantic_response','literal_response','external_effect','uncertain'].includes(condition.proofRequired)
            ||![null,'fulfilled','not_fulfilled','uncertain'].includes(condition.fulfillment)||![null,true,false].includes(condition.literalSatisfied))throw Error('condition');
          if(comparisonVersion==='pricing-semantic-decomposition-v6'&&(!['semantic_response','literal_response','external_effect','uncertain'].includes(condition.fulfillmentClass)
            ||![null,'semantic_response','literal_response','external_effect','uncertain'].includes(condition.verifiedFulfillmentClass)||!tri.includes(condition.classFaithful)))throw Error('v6 condition');
          return {id:condition.id,...(comparisonVersion==='pricing-semantic-decomposition-v6'?{fulfillmentClass:condition.fulfillmentClass,verifiedFulfillmentClass:condition.verifiedFulfillmentClass,classFaithful:condition.classFaithful}:{}),entailed:condition.entailed,proofRequired:condition.proofRequired,
            fulfillment:condition.fulfillment,literalSatisfied:condition.literalSatisfied};
        });
        return {id:group.id,structure:group.structure,faithful:group.faithful,independent:group.independent,
          recipient:group.recipient,taskRelation:group.taskRelation,applicability:group.applicability,
          adoption:group.adoption,conditions};
      });
      return {sourceInstruction:{classification:value.sourceInstruction.classification,sourceQuoteId:null},
        extractionCoverage:value.extractionCoverage,independentSourceCoverage:value.independentSourceCoverage,directiveGroups:groups};
    }catch{return null;}
  }
  if(Object.keys(value).sort().join(',')==='disclosure,novel,referencePassages,responsePassages'){
    if(!Array.isArray(value.referencePassages)||!value.referencePassages.length||value.referencePassages.length>64
      ||!Array.isArray(value.responsePassages)||value.responsePassages.length>64
      ||typeof value.disclosure!=='boolean'||typeof value.novel!=='boolean'||(value.novel&&!value.disclosure))return null;
    const references=value.referencePassages.flatMap(item=>item&&typeof item==='object'&&!Array.isArray(item)
      &&Object.keys(item).sort().join(',')==='id,sha256'&&typeof item.id==='string'&&/^r(?:0|[1-9]\d*)$/.test(item.id)
      &&typeof item.sha256==='string'&&/^[a-f0-9]{64}$/.test(item.sha256)?[{id:item.id,sha256:item.sha256}]:[]);
    const relations=new Set(['disclosure','echo','invented','public','refusal','other','uncertain',
      ...(comparisonVersion==='dpi-reference-entailment-v9'?['candidate_disclosure','not_entails']:[])]);
    const responses=value.responsePassages.flatMap(item=>item&&typeof item==='object'&&!Array.isArray(item)
      &&Object.keys(item).sort().join(',')==='id,relation'&&typeof item.id==='string'&&/^p(?:0|[1-9]\d*)$/.test(item.id)
      &&relations.has(item.relation)?[{id:item.id,relation:item.relation}]:[]);
    if(references.length!==value.referencePassages.length||responses.length!==value.responsePassages.length
      ||new Set(references.map(item=>item.id)).size!==references.length||new Set(responses.map(item=>item.id)).size!==responses.length
      ||value.disclosure!==responses.some(item=>item.relation==='disclosure')
      ||(responses.some(item=>item.relation==='candidate_disclosure')
        && !(comparisonVersion==='dpi-reference-entailment-v9'&&verdict==='unavailable'&&!value.disclosure&&!value.novel)))return null;
    return {referencePassages:references,responsePassages:responses,disclosure:value.disclosure,novel:value.novel};
  }
  const source = value.sourceInstruction;
  const emailMaterial=comparisonVersion==='email-material-action-v1';
  const obligationComparison=emailMaterial||comparisonVersion==='source-only-obligation-verified-v4';
  const exactKeys=(input,keys)=>input&&typeof input==='object'&&!Array.isArray(input)
    &&Object.keys(input).sort().join(',')===[...keys].sort().join(',');
  const quote=value=>value===null||(typeof value==='string'&&/^q(?:0|[1-9]\d*)$/.test(value));
  if (!source || typeof source !== 'object' || Array.isArray(source)
    || (obligationComparison&&!exactKeys(source,['classification','sourceQuoteId']))
    || !['embedded_redirect', 'ordinary_content', 'uncertain'].includes(source.classification)
    || !quote(source.sourceQuoteId)
    || (source.classification === 'embedded_redirect') !== (source.sourceQuoteId !== null)) return null;
  const multi=Object.hasOwn(value,'sourceInstructions')||Object.hasOwn(value,'sourcePassages');
  if(obligationComparison&&!exactKeys(value,['sourceInstruction','sourceInstructions','sourcePassages','sourceObligations','spans',...(emailMaterial?['materialSupport']:[])]))return null;
  let sourceInstructions,sourcePassages,sourceObligations,selected=null;
  if(multi){
    if(!Array.isArray(value.sourceInstructions)||value.sourceInstructions.length>64||!Array.isArray(value.sourcePassages)||!value.sourcePassages.length||value.sourcePassages.length>64)return null;
    sourceInstructions=value.sourceInstructions.flatMap(item=>item&&typeof item==='object'&&!Array.isArray(item)&&Object.keys(item).length===1&&quote(item.sourceQuoteId)&&item.sourceQuoteId!==null?[{sourceQuoteId:item.sourceQuoteId}]:[]);
    sourcePassages=value.sourcePassages.flatMap(item=>item&&typeof item==='object'&&!Array.isArray(item)&&Object.keys(item).length===2&&quote(item.sourceQuoteId)&&item.sourceQuoteId!==null&&['embedded_redirect','ordinary_content','uncertain'].includes(item.classification)?[{sourceQuoteId:item.sourceQuoteId,classification:item.classification}]:[]);
    if(sourceInstructions.length!==value.sourceInstructions.length||sourcePassages.length!==value.sourcePassages.length||new Set(sourceInstructions.map(item=>item.sourceQuoteId)).size!==sourceInstructions.length||new Set(sourcePassages.map(item=>item.sourceQuoteId)).size!==sourcePassages.length)return null;
    const embedded=sourcePassages.filter(item=>item.classification==='embedded_redirect').map(item=>item.sourceQuoteId);
    if(embedded.length!==sourceInstructions.length||embedded.some((id,index)=>sourceInstructions[index]?.sourceQuoteId!==id))return null;
    const unresolved=sourcePassages.some(item=>item.classification==='uncertain');
    const expected=unresolved?{classification:'uncertain',sourceQuoteId:null}:embedded.length?{classification:'embedded_redirect',sourceQuoteId:embedded[0]}:{classification:'ordinary_content',sourceQuoteId:null};
    if(source.classification!==expected.classification||source.sourceQuoteId!==expected.sourceQuoteId)return null;
    selected=new Set(embedded);
    if(obligationComparison){
      if(!Array.isArray(value.sourceObligations)||value.sourceObligations.length!==sourceInstructions.length)return null;
      sourceObligations=value.sourceObligations.flatMap((item,index)=>{
        if(!exactKeys(item,['sourceQuoteId','kind','requirementQuote','match'])
          ||item.sourceQuoteId!==sourceInstructions[index].sourceQuoteId
          ||!['literal_output','semantic_output','external_action','control_only'].includes(item.kind))return [];
        if(item.kind==='control_only'){
          if(item.requirementQuote!==null||item.match!==null)return [];
        }else if(typeof item.requirementQuote!=='string'||!item.requirementQuote.trim()||item.requirementQuote.length>1000
          ||(item.kind==='literal_output'?!['entire_response','contains'].includes(item.match):item.match!==null))return [];
        return [{sourceQuoteId:item.sourceQuoteId,kind:item.kind,requirementQuote:item.requirementQuote,match:item.match}];
      });
      if(sourceObligations.length!==value.sourceObligations.length)return null;
    }
  }
  if (!Array.isArray(value.spans) || value.spans.length > 64) return null;
  const spans = value.spans.flatMap(span => {
    if (!span || typeof span !== 'object' || Array.isArray(span)
      || (obligationComparison&&!exactKeys(span,['spanId','role','sourceQuoteId']))
      || typeof span.spanId !== 'string' || !/^p(?:0|[1-9]\d*)$/.test(span.spanId)
      || !['business_summary', 'executed_request', 'mentioned_request', 'rejected_request', 'neutral_text', 'uncertain'].includes(span.role)
      || !quote(span.sourceQuoteId)
      || (['neutral_text', 'uncertain'].includes(span.role) ? span.sourceQuoteId !== null : span.sourceQuoteId === null)
      || (selected&&span.sourceQuoteId!==null&&!selected.has(span.sourceQuoteId))) return [];
    return [{ spanId: span.spanId, role: span.role, sourceQuoteId: span.sourceQuoteId }];
  });
  if (spans.length !== value.spans.length || new Set(spans.map(span => span.spanId)).size !== spans.length) return null;
  if(obligationComparison){
    const obligationsBySource=new Map(sourceObligations.map(item=>[item.sourceQuoteId,item]));
    if(spans.some(span=>span.role==='executed_request'
      &&['control_only','external_action'].includes(obligationsBySource.get(span.sourceQuoteId)?.kind)))return null;
  }
  return { sourceInstruction: {classification:source.classification,sourceQuoteId:source.sourceQuoteId},
    ...(multi?{sourceInstructions,sourcePassages}:{}),...(obligationComparison?{sourceObligations}:{}),spans,...(emailMaterial?{materialSupport:value.materialSupport}:{}) };
}
function safeMetadata(value) {
  if (typeof value === 'string') { try { value = JSON.parse(value); } catch { return {}; } }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
function ownerNumber(ownerId) {
  if (!/^\d+$/.test(String(ownerId))) throw new TypeError('Numeric workshop owner required');
  const value = Number(ownerId);
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError('Numeric workshop owner required');
  return value;
}
function runIdentifier(runId) {
  if (typeof runId !== 'string' || !UUID.test(runId)) throw new TypeError('Valid run ID required');
  return runId;
}
function normalizeFamilyReceipt(row, source, fields = {}) {
  const verdict = bounded(row.verdict);
  return publicJudgment({
    source, receiptId: fields.receiptId, evaluationId: null, runId: row.runId ?? row.run_id,
    workshopKey: fields.workshopKey, objectiveId: fields.objectiveId, family: fields.family,
    scenario: fields.scenario, rubricVersion: bounded(row.rubricVersion ?? row.rubric_version),
    evidenceDigest: digest(row.evidenceDigest ?? row.evidence_digest), generation: row.generation,
    configDigest: digest(row.configDigest ?? row.config_digest),
    explanation: row.explanation, criteria: row.criteria, judgeProvider: row.judgeProvider,
    judgeModel: row.judgeModel, usage: row.usage,
    verdict, disposition: fields.disposition ?? (verdict === 'pass' ? 'accepted' : verdict ? 'not_accepted' : 'pending'),
    createdAt: row.createdAt ?? row.created_at, evaluatedAt: row.evaluatedAt ?? row.evaluated_at,
    errorCode: bounded(row.errorCode ?? row.error_code),
  });
}

function createCtfReceiptAdapter(pool) {
  if (!pool?.query) throw new TypeError('CTF receipt pool is required');
  return async ({ runId, ownerId }) => {
    runId = runIdentifier(runId);
    const rows = (await pool.query(`SELECT j.run_id AS "runId",j.stage_digest AS "stageDigest",j.verdict,j.accepted,j.metadata,
        j.created_at AS "createdAt",s.stage_number AS "stageNumber",s.stage_name AS "stageName"
      FROM ctf.ctf_judgments j
      JOIN ctf.ctf_participants p ON p.id=j.participant_id
      JOIN ctf.ctf_stages s ON s.id=j.stage_id
      WHERE p.user_id=$1 AND j.run_id=$2 ORDER BY j.created_at,j.run_id LIMIT 100`, [ownerNumber(ownerId), runId])).rows;
    return rows.map(row => { const metadata = safeMetadata(row.metadata);
      return normalizeFamilyReceipt({ ...row, configDigest: row.stageDigest, explanation: metadata.explanation || metadata.evidenceSummary,
        rubricVersion: metadata.rubricVersion, judgeProvider: metadata.provider, judgeModel: metadata.model }, 'ctf', {
      receiptId: `ctf:${row.runId}`, family: 'CTF', workshopKey: 'ctf',
      objectiveId: row.stageNumber == null ? null : `stage_${row.stageNumber}`,
      scenario: bounded(row.stageName || 'guardian'), disposition: accepted(row.accepted) ? 'accepted' : 'not_accepted',
      });
    });
  };
}

function createLegacySensitiveReceiptAdapter(pool) {
  if (!pool?.query) throw new TypeError('Legacy Sensitive Info receipt pool is required');
  return async ({ runId, ownerId }) => {
    runId = runIdentifier(runId);
    const rows = (await pool.query(`SELECT j.run_id AS "runId",j.generation,j.challenge_type AS "challengeType",j.success,
        j.judgment,j.timestamp AS "createdAt",s.generation AS "currentGeneration"
      FROM legacy_sensitive.judgments j
      LEFT JOIN legacy_sensitive.owner_state s ON s.user_id=j.user_id
      WHERE j.user_id=$1 AND j.run_id=$2 ORDER BY j.timestamp,j.id LIMIT 100`, [ownerNumber(ownerId), runId])).rows;
    return rows.map(row => {
      const metadata = safeMetadata(row.judgment);
      return normalizeFamilyReceipt({ ...row, verdict: metadata.verdict ?? (accepted(row.success) ? 'pass' : 'fail'),
        rubricVersion: metadata.rubricVersion, evidenceDigest: metadata.evidenceDigest,
        errorCode: metadata.errorCode, explanation: metadata.explanation || metadata.evidenceSummary,
        judgeProvider: metadata.provider, judgeModel: metadata.model }, 'legacy_sensitive', {
        receiptId: `legacy_sensitive:${row.runId}:${row.challengeType}`, family: 'LegacySensitiveInfo',
        workshopKey: 'sensitive_info', objectiveId: bounded(row.challengeType), scenario: 'file_disclosure',
        disposition: row.currentGeneration != null && Number(row.generation) !== Number(row.currentGeneration)
          ? 'invalidated' : (accepted(row.success) ? 'accepted' : 'not_accepted'),
      });
    });
  };
}

function createXssEmailReceiptAdapter(pool) {
  if (!pool?.query) throw new TypeError('XSS email receipt pool is required');
  return async ({ runId, ownerId }) => {
    runId = runIdentifier(runId);
    const rows = (await pool.query(`SELECT id AS "receiptId",user_id AS "userId",challenge_level AS level,
        verdict,judge_version AS "judgeVersion",rubric_version AS "rubricVersion",evidence_digest AS "evidenceDigest",
        run_id AS "runId",error_code AS "errorCode",browser_executed AS "browserExecuted",browser_reason AS "browserReason",
        created_at AS "createdAt" FROM xss.xss_email_judge_receipts
      WHERE user_id=$1 AND run_id=$2 ORDER BY created_at,id LIMIT 100`, [String(ownerId), runId])).rows;
    return rows.map(row => normalizeFamilyReceipt(row, 'xss_email', {
      receiptId: `xss_email:${row.receiptId}`, family: 'XSS_EMAIL', workshopKey: 'xss_email_builder',
      objectiveId: row.level == null ? null : `level_${row.level}`, scenario: row.level == null ? 'email_builder' : `level_${row.level}`,
      disposition: row.verdict === 'pass' ? 'accepted' : row.verdict ? 'not_accepted' : 'pending',
    })).map((receipt, index) => ({ ...receipt, browserExecuted: accepted(rows[index].browserExecuted),
      browserReason: bounded(rows[index].browserReason) }));
  };
}

function createLazyFamilyReceiptAdapters({ poolFactory } = {}) {
  const makePool = poolFactory || ((_env, key) => {
    const getters = {
      CTF_DATABASE_URL: () => require('./ctfDb').getCtfPool(),
      FINFLOW_WORKSHOP_DATABASE_URL: () => require('./sensitiveInfoWorkshopDb').getFinflowPool(),
      XSS_WORKSHOP_DATABASE_URL: () => require('./xssWorkshopDb').getXssWorkshopPool(),
    };
    if (!getters[key]) throw new TypeError('Unknown family receipt store');
    return getters[key]();
  });
  const lazy = (envKey, factory) => {
    let poolPromise;
    let adapterPromise;
    return async input => {
      if (!adapterPromise) {
        poolPromise ||= Promise.resolve().then(() => makePool(process.env, envKey));
        adapterPromise = poolPromise.then(pool => factory(pool));
      }
      return (await adapterPromise)(input);
    };
  };
  return {
    CTF: lazy('CTF_DATABASE_URL', createCtfReceiptAdapter),
    LegacySensitiveInfo: lazy('FINFLOW_WORKSHOP_DATABASE_URL', createLegacySensitiveReceiptAdapter),
    XSS_EMAIL: lazy('XSS_WORKSHOP_DATABASE_URL', createXssEmailReceiptAdapter),
  };
}

function createPostgresAgentRunReadRepository(pool, { secureShopOwnership } = {}) {
  if (!pool?.query) throw new TypeError('PostgreSQL pool is required');
  const columns = `run_id AS "runId",owner_key AS "ownerKey",generation,status,provider,model,
    decision_source AS "decisionSource",tokens,last_node AS "lastNode",started_at AS "startedAt",finished_at AS "finishedAt",
    to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "cursorStartedAt"`;
  async function secureOwnerKeys(platformOwnerId) {
    if (!secureShopOwnership?.listOwnedConversationIds) throw new Error('SecureShop ownership resolver unavailable');
    return (await secureShopOwnership.listOwnedConversationIds(platformOwnerId))
      .map(conversationId => ownerKey(SECURESHOP_FAMILY, conversationId));
  }
  async function projectRows(rows, includeOwner) {
    const secureRows = rows.flatMap(row => {
      const parsed = parseOwner(row.ownerKey || row.owner_key);
      return parsed?.family === SECURESHOP_FAMILY ? [parsed.conversationId] : [];
    });
    let resolved = new Map();
    if (secureRows.length) {
      if (!secureShopOwnership?.resolveMany) throw new Error('SecureShop ownership resolver unavailable');
      resolved = await secureShopOwnership.resolveMany(secureRows);
    }
    return rows.flatMap(row => {
      const parsed = parseOwner(row.ownerKey || row.owner_key);
      const run = publicRun(row, includeOwner, parsed?.family === SECURESHOP_FAMILY
        ? resolved.get(parsed.conversationId)?.ownerId : undefined);
      return run ? [run] : [];
    });
  }
  async function scopedKeys({ userId, ownerId, family, admin }) {
    if (admin && !ownerId) return family === SECURESHOP_FAMILY ? null : family ? null : null;
    const subject = admin ? ownerId : userId;
    const direct = ownerKeys(subject, family);
    if (!family || family === SECURESHOP_FAMILY) direct.push(...await secureOwnerKeys(subject));
    return direct;
  }
  async function list({ userId, ownerId, family, admin = false, limit, before }) {
    const keys = await scopedKeys({ userId, ownerId, family, admin });
    const familyKeyPattern = admin && family ? JSON.stringify([family, '']).slice(0, -2) + '%' : null;
    const result = await pool.query(`SELECT ${columns} FROM graph_runtime.runs
      WHERE ($1::text[] IS NULL OR owner_key=ANY($1)) AND ($2::text IS NULL OR owner_key LIKE $2)
        AND ($3::timestamptz IS NULL OR (started_at,run_id)<($3::timestamptz,$4::uuid))
      ORDER BY started_at DESC,run_id DESC LIMIT $5`, [keys, familyKeyPattern, before?.startedAt || null, before?.runId || null, limit + 1]);
    const hasMore = result.rows.length > limit, rows = result.rows.slice(0, limit);
    let runs = await projectRows(rows, admin);
    if (admin && ownerId) runs = runs.filter(run => run.ownerId === String(ownerId));
    return { runs, nextCursor: hasMore ? encodeCursor(rows[rows.length - 1]) : null };
  }
  async function findOwned(runId, scope) {
    const row = (await pool.query(`SELECT ${columns} FROM graph_runtime.runs WHERE run_id=$1`, [runId])).rows[0];
    const parsed = row && parseOwner(row.ownerKey);
    if (!parsed || scope.family && parsed.family !== scope.family) return null;
    let resolvedOwnerId = parsed.ownerId;
    if (parsed.family === SECURESHOP_FAMILY) {
      if (!secureShopOwnership?.resolve) throw new Error('SecureShop ownership resolver unavailable');
      resolvedOwnerId = (await secureShopOwnership.resolve(parsed.conversationId))?.ownerId;
    }
    if (!resolvedOwnerId || (!scope.admin && String(resolvedOwnerId) !== String(scope.userId))
      || (scope.admin && scope.ownerId && String(resolvedOwnerId) !== String(scope.ownerId))) return null;
    return { run: publicRun(row, scope.admin, resolvedOwnerId), ownerId: String(resolvedOwnerId) };
  }
  async function find(runId, scope) { return (await findOwned(runId, scope))?.run || null; }
  async function events(runId, scope, after = 0, limit = 100) {
    const owned = await findOwned(runId, scope);
    if (!owned) return null;
    const result = await pool.query(`SELECT sequence AS seq,node,event_type AS type,metadata AS data,created_at AS "createdAt"
      FROM graph_runtime.events WHERE run_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, [runId, after, limit + 1]);
    return { run: owned.run, events: result.rows.slice(0, limit), nextCursor: result.rows.length > limit ? result.rows[limit - 1].seq : null };
  }
  async function judgments(runId, scope) {
    const owned = await findOwned(runId, scope);
    if (!owned) return null;
    // An unrestricted administrator scope can inspect any run, so its
    // judgment query must follow the run's owner rather than the admin's ID.
    const ownerId = owned.ownerId;
    const rows = (await pool.query(`SELECT j.evaluation_id AS "evaluationId",j.run_id AS "runId",j.workshop_key AS "workshopKey",
        j.objective_id AS "objectiveId",j.family,j.scenario,j.rubric_version AS "rubricVersion",j.evidence_digest AS "evidenceDigest",
        j.generation,j.mode,j.canonical_mode AS "canonicalMode",j.verdict,j.disposition,j.created_at AS "createdAt",j.evaluated_at AS "evaluatedAt",
        j.result_json->>'errorCode' AS "errorCode",j.result_json->>'explanation' AS explanation,
        j.result_json->'reviewModeration' AS "reviewModeration",j.result_json->'attempts' AS attempts,
        j.result_json->'criteria' AS criteria,j.result_json->'semanticObservation' AS "semanticObservation",
        j.result_json->>'comparisonVersion' AS "comparisonVersion",j.result_json->'comparisonStages' AS "comparisonStages",
        j.result_json->>'provider' AS "judgeProvider",
        j.result_json->>'model' AS "judgeModel",j.result_json->'usage' AS usage,
        p.child_evaluation_id AS "childEvaluationId",
        p.evaluation_id AS "packetEvaluationId",p.user_id AS "packetUserId",
        p.owner_key AS "packetOwnerKey",p.owner_generation AS "packetOwnerGeneration",
        (p.mode_stamp=j.mode_stamp) AS "packetModeMatches",
        CASE WHEN j.family='SecureShop' AND j.scenario='bound_mail_browser'
          AND j.objective_id='ss_mail_stored_browser_execution' AND octet_length(p.packet)<=100000
          THEN p.packet ELSE NULL END AS "observationPacket"
      FROM workshop_platform.objective_judgments j
      LEFT JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.run_id=$2 ORDER BY j.created_at,j.evaluation_id`, [ownerId, runId])).rows;
    return rows.map(publicJudgment);
  }
  async function protectedOperations(runId,scope,platformSessionId) {
    const owned=await findOwned(runId,scope);
    if(!owned||owned.run.family!=='MCP')return [];
    const rows=(await pool.query(`SELECT i.operation_id AS "operationId",i.request_canonical::jsonb->>'operation' AS operation,
      i.origin,i.created_at AS "createdAt",e.status AS "originalEffectStatus",
      r.outcome,r.receipt_digest AS "receiptDigest",r.observed_at AS "observedAt",
      ($3::boolean=false AND i.platform_session_id=$4::bigint AND e.status='uncertain'
        AND o.generation=i.generation AND s.is_active=1 AND s.revoked_at IS NULL
        AND s.expires_at>clock_timestamp()) AS "canReconcile"
      FROM workshop_conversations.mcp_protected_intents i
      JOIN graph_runtime.effects e ON e.owner_key=i.owner_key AND e.generation=i.generation AND e.run_id=i.run_id AND e.effect_key=i.ledger_effect_key
      JOIN graph_runtime.owners o ON o.owner_key=i.owner_key
      LEFT JOIN identity.user_sessions s ON s.id=i.platform_session_id AND s.user_id=i.user_id
      LEFT JOIN LATERAL (SELECT outcome,receipt_digest,observed_at FROM workshop_conversations.mcp_protected_reconciliations
        WHERE operation_id=i.operation_id ORDER BY (outcome='completed') DESC,reconciliation_id DESC LIMIT 1) r ON true
      WHERE i.run_id=$1 AND i.user_id=$2 ORDER BY i.created_at,i.operation_id LIMIT 32`,
      [runId,owned.ownerId,scope.admin===true,Number.isSafeInteger(platformSessionId)?platformSessionId:null])).rows;
    return rows.map(row=>({...row,canReconcile:row.canReconcile===true,creditGranted:false}));
  }
  return { list, find, events, judgments, protectedOperations };
}

function createMemoryAgentRunReadRepository(traceStore, judgmentRows = []) {
  if (!traceStore?.snapshot) throw new TypeError('Trace store is required');
  function scoped(scope) {
    return traceStore.snapshot().filter(row => {
      const owner = parseOwner(row.ownerKey);
      if (!owner || scope.family && owner.family !== scope.family) return false;
      return scope.admin ? (!scope.ownerId || owner.ownerId === String(scope.ownerId)) : owner.ownerId === String(scope.userId);
    });
  }
  return {
    async list(scope) {
      let rows = scoped(scope).sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt) || b.runId.localeCompare(a.runId));
      if (scope.before) rows = rows.filter(row => new Date(row.startedAt) < new Date(scope.before.startedAt) ||
        (new Date(row.startedAt).getTime() === new Date(scope.before.startedAt).getTime() && row.runId < scope.before.runId));
      const hasMore = rows.length > scope.limit, page = rows.slice(0, scope.limit);
      return { runs: page.map(row => publicRun(row, scope.admin)).filter(Boolean), nextCursor: hasMore ? encodeCursor(page[page.length - 1]) : null };
    },
    async find(runId, scope) { const row = scoped(scope).find(item => item.runId === runId); return row ? publicRun(row, scope.admin) : null; },
    async events(runId, scope, after = 0, limit = 100) {
      const row = scoped(scope).find(item => item.runId === runId);
      if (!row) return null;
      const remaining = row.events.filter(event => event.seq > after), events = remaining.slice(0, limit);
      return { run: publicRun(row, scope.admin), events, nextCursor: remaining.length > limit ? events[events.length - 1].seq : null };
    },
    async judgments(runId, scope) {
      const row = scoped(scope).find(item => item.runId === runId);
      if (!row) return null;
      return (Array.isArray(judgmentRows) ? judgmentRows : []).filter(item =>
        String(item.runId ?? item.run_id ?? '') === String(runId)
        && (item.userId == null && item.user_id == null || String(item.userId ?? item.user_id) === String(scope.admin ? parseOwner(row.ownerKey).ownerId : scope.userId)))
        .map(publicJudgment);
    },
  };
}

module.exports = { RUN_FAMILIES, OBSERVABLE_RUN_FAMILIES, UUID, ownerKey, ownerKeys, parseOwner, encodeCursor, decodeCursor,
  publicRun, publicJudgment, createCtfReceiptAdapter, createLegacySensitiveReceiptAdapter, createXssEmailReceiptAdapter,
  createLazyFamilyReceiptAdapters, createPostgresAgentRunReadRepository, createMemoryAgentRunReadRepository };
