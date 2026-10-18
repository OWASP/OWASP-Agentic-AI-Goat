'use strict';
const { createObjectiveJudge, boundedJson } = require('../agent-runtime/objectiveJudge');
const { hasObjectiveObservation, literalComparisonQuery } = require('./sqlNoSqlObjectiveEvidence');
const { getObjectiveRubric } = require('../config/objectiveRubrics');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

// Presentation hashes describe trusted graph bytes, not independent model or
// effect proof. Keep those existing facts and canonical execution fences below.
function gradingPresentation(result, execution, workshopKey, observationIndex) {
  if (result.presentation === undefined) return { answer: result.response || '', context: {} };
  const p = result.presentation;
  const valid = condition => { if (!condition) throw Object.assign(new TypeError('Invalid workshop presentation evidence'), { code: 'WORKSHOP_PRESENTATION_INVALID' }); };
  const sha = value => createHash('sha256').update(value).digest('hex');
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  valid(p && p.version === 'workshop-result-presentation-v1'
    && p.family === (workshopKey === 'sql_injection_workshop' ? 'ARIA' : 'NOVA') && p.runId === execution.runId);
  valid(typeof result.response === 'string' && p.responseSha256 === sha(result.response));
  const n = p.narrative;
  valid(n && typeof n.text === 'string' && ['model', 'fixture', 'unavailable'].includes(n.source)
    && [null, 'MODEL_OUTPUT_LIMIT', 'MODEL_RESPONSE_UNAVAILABLE', 'MODEL_RESPONSE_ERROR'].includes(n.errorCode)
    && n.sha256 === sha(n.text) && (n.source !== 'unavailable' || n.text === ''));
  valid(Array.isArray(result.toolObservations) && Array.isArray(p.blocks)
    && p.blocks.length === result.toolObservations.length && p.blocks.length <= 4
    && Number.isSafeInteger(observationIndex) && observationIndex >= 0 && observationIndex < p.blocks.length);
  valid(p.blocks.every((b, i) => b && b.index === i && result.toolObservations[i]?.index === i));
  const b = p.blocks[observationIndex], observed = result.toolObservations[observationIndex];
  valid(observed.toolUsed === result.toolUsed && isDeepStrictEqual(observed.toolResult, result.toolResult)
    && isDeepStrictEqual(observed.invocation, result.toolInvocation));
  valid(b.tool === observed.toolUsed && typeof b.effectKey === 'string' && b.effectKey.length > 0
    && b.effectKey === observed.effectKey && b.resultSha256 === sha(JSON.stringify(observed.toolResult)) && hash(b.displaySha256));
  return { answer: n.source === 'model' ? n.text : '', context: { presentation: {
    version: p.version, narrativeSource: n.source, narrativeErrorCode: n.errorCode,
    narrativeSha256: n.sha256, responseSha256: p.responseSha256,
    observationIndex, tool: b.tool, effectKey: b.effectKey, resultSha256: b.resultSha256, displaySha256: b.displaySha256,
  } } };
}

function projectWorkshopToolResult(workshopKey, result) {
  if (workshopKey !== 'nosql_injection_workshop' || !Array.isArray(result)) return result;
  const omitted = new Set();
  const rows = result.map(row => Object.fromEntries(Object.entries(row).filter(([key]) => {
    if (['abstract', 'bio', 'cited_by', 'url'].includes(key)) { omitted.add(key); return false; }
    return true;
  })));
  return { rowCount: result.length, omittedFields: [...omitted].sort(), rows };
}

function createWorkshopObjectiveGrader({ workshopKey, syncObjectiveComplete, objectiveLabels, challengeKey,
  completionService, evidenceRepository, readLiteralBaseline, judge = createObjectiveJudge(), postgres = process.env.PLATFORM_DATABASE_ENGINE === 'postgres' }) {
  const service = () => completionService || require('./objectiveCompletionService').getObjectiveCompletionService();
  const history = new Map();
  const scenario = workshopKey === 'sql_injection_workshop' ? 'product_search' : 'paper_search_simulation';
  const evidenceStore = () => {
    if (!evidenceRepository) evidenceRepository = require('../database/postgres/objectiveEvidenceRepository')
      .createObjectiveEvidenceRepository(require('./postgresPlatformStores').getPostgresPlatformStores().pool);
    return evidenceRepository;
  };
  return {
    async begin(userId, execution) {
      await execution.check();
      return postgres ? service().beginAttempt({ userId, workshopKey, execution }) : { generation: execution.generation };
    },
    async observe({ userId, result, execution, attempt, observationIndex=0 }) {
      if (!result.toolUsed) return;
      await execution.check();
      gradingPresentation(result, execution, workshopKey, observationIndex);
      const evidence = { tool: result.toolUsed, invocation: result.toolInvocation || null, result: result.toolResult ?? null };
      if (postgres) {
        await evidenceStore().append({ userId, workshopKey, scenario, generation: attempt.generation,
          runId: execution.runId, evidenceID: `tool_${execution.runId.replaceAll('-', '_')}_${observationIndex}`, evidence });
      } else {
        const key = JSON.stringify([String(userId), attempt.generation]);
        let saved;
        try { saved = JSON.parse(boundedJson(evidence, 16000)); } catch { saved = null; }
        const next = [...(history.get(key) || []), { evidence: saved, omitted: saved === null }].slice(-20);
        history.delete(key); history.set(key, next);
        while (history.size > 500) history.delete(history.keys().next().value);
      }
      await execution.check();
    },
    async evaluate({ userId, objectiveId, message, result, mode, execution, attempt, observationIndex=0 }) {
      const presentation = gradingPresentation(result, execution, workshopKey, observationIndex);
      const rubric = getObjectiveRubric(workshopKey, objectiveId, mode);
      if (!rubric) return { completed: false, judgment: { objectiveId, verdict: 'inconclusive', explanation: 'No applicable objective rubric is available.' } };
      const expectedTool = workshopKey === 'sql_injection_workshop' ? 'search_products' : 'search_papers';
      const retainedHistoryRows = objectiveId === 'sqli_3' ? (postgres
        ? await evidenceStore().list({ userId, workshopKey, scenario, generation: attempt.generation })
        : history.get(JSON.stringify([String(userId), attempt?.generation])) || []) : [];
      // Only trusted graph-selected observations qualify. Retain historical
      // scripted evidence in storage, but never use it to establish a model's
      // multi-turn column-boundary discovery.
      const historyRows = retainedHistoryRows.filter(row => !row.omitted
        && row.evidence?.tool === expectedTool && row.evidence?.invocation?.decisionSource === 'model');
      const facts = { tool_executed: result.toolUsed === expectedTool,
        model_decision_observed: result.toolInvocation?.decisionSource === 'model'
          && result.toolInvocation?.tool === expectedTool,
        objective_signal_detected: hasObjectiveObservation({objectiveId,result,history:historyRows,userId}),
        vulnerable_mode: ['vuln', 'vulnerable'].includes(mode) };
      const evidence = [
        { id: 'request', source: 'student_input', content: message },
        { id: 'tool', source: 'tool_result', content: { tool: result.toolUsed || null,
          invocation: result.toolInvocation || null, result: projectWorkshopToolResult(workshopKey, result.toolResult ?? null) } },
        { id: 'answer', source: 'assistant_response', content: presentation.answer },
        { id: 'context', source: 'server_observation', content: { authenticatedOwnerId: String(userId), mode,
          normalPaperAccessLevels: workshopKey === 'nosql_injection_workshop' ? ['public'] : null,
          decisionSource: result.toolInvocation?.decisionSource === 'model' ? 'model' : 'non_model',
          executionSource: workshopKey === 'nosql_injection_workshop' ? 'postgres_backed_operator_simulation' : 'database_query',
          ...presentation.context } },
      ];
      const literalQuery = literalComparisonQuery(objectiveId, result);
      if (literalQuery !== null && (postgres || readLiteralBaseline)) {
        await execution.check();
        const baseline = readLiteralBaseline ? await readLiteralBaseline({objectiveId,query:literalQuery})
          : workshopKey === 'sql_injection_workshop'
            ? await require('../database/postgres/sqlWorkshopDb').searchProducts(literalQuery,null,'fixed')
            : await require('../database/postgres/nosqlWorkshopDb').searchPapers(literalQuery,null,null,'fixed');
        await execution.check();
        evidence.push({id:'literal_comparison',source:'server_observation',content:{
          literalQuery,mode:'fixed',returnedRowCount:baseline.length,
          returnedRecordIds:baseline.map(row=>row.paper_id||row.product_id||row.id),
          observedAttackRowCount:Array.isArray(result.toolResult)?result.toolResult.length:0,
        }});
      }
      if (workshopKey === 'nosql_injection_workshop') {
        const rows = Array.isArray(result.toolResult) ? result.toolResult : [];
        evidence.push({ id: 'operator_observation', source: 'server_observation', content: {
          executedQuery: result.toolInvocation?.params?.query || '',
          returnedRowCount: rows.length,
          paperRecordCount: rows.filter(row => row.paper_id).length,
          authorRecordCount: rows.filter(row => row.author_id).length,
          returnedAuthorEmails: rows.filter(row => row.author_id && row.email)
            .map(row => ({ authorId: row.author_id, email: row.email })),
          restrictedRecords: rows.filter(row => row.access_level === 'restricted')
            .map(row => ({ paperId: row.paper_id, accessLevel: row.access_level })),
          returnedYears: [...new Set(rows.map(row => row.year).filter(year => year != null))],
        } });
      }
      if (objectiveId === 'sqli_6') {
        const marker = String(result.toolInvocation?.params?.searchTerm || '')
          .match(/UNION\s+SELECT[\s\S]*?'([^']{3,})'/i)?.[1] || null;
        const matches = Array.isArray(result.toolResult) && marker
          ? result.toolResult.flatMap((row, rowIndex) => Object.entries(row)
            .filter(([, value]) => value === marker).map(([field, value]) => ({ rowIndex, field, value }))) : [];
        evidence.push({ id: 'marker_matches', source: 'server_observation', content: {
          submittedUnionTextLiteral: marker, matches,
        } });
      }
      if (objectiveId === 'sqli_3') {
        const rows = historyRows;
        evidence.push({ id: 'order_probes', source: 'server_observation', content: rows.map((row, index) => {
          if (row.omitted) return { attempt: index, omitted: true };
          const observed = row.evidence;
          return { attempt: index, tool: observed.tool, params: observed.invocation?.params || {},
            error: observed.result?.error || null,
            returnedRows: Array.isArray(observed.result) ? observed.result.length : null };
        }) });
      }
      if (postgres) return service().evaluate({ userId, workshopKey, rubric, evidence, facts, execution, attempt });
      // Staged legacy qualification only. Final release removes this branch along
      // with SQLite; durable receipts are supplied by the PostgreSQL path above.
      const judgment = await judge({ rubric, evidence, facts, execution });
      await execution.check();
      if (judgment.verdict !== 'pass') return { completed: false, judgment };
      if (!facts.model_decision_observed) return { completed: false, judgment: { ...judgment, verdict: 'fail', explanation: 'A genuine model-selected tool observation is required; no completion was awarded.' } };
      await syncObjectiveComplete(userId, workshopKey, objectiveId, objectiveLabels[objectiveId], challengeKey);
      await execution.check();
      return { completed: true, judgment };
    },
  };
}
module.exports = { createWorkshopObjectiveGrader, projectWorkshopToolResult };
