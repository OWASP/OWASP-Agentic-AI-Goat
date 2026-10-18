'use strict';

const { createObjectiveJudge } = require('../agent-runtime/objectiveJudge');
const { findChallengeFlag } = require('../config/legacySensitiveFlags');

const { WORKSHOP_KEY } = require('../config/legacyFileSsiCurriculum');
const OBJECTIVES = Object.freeze([
  'path_traversal',
  'ssi_injection',
  'combined_traversal_ssi',
  'ai_assisted_path_traversal',
  'ai_assisted_ssi',
]);
const AI_OBJECTIVES = new Set(['ai_assisted_path_traversal', 'ai_assisted_ssi']);
const PATH_OBJECTIVES = new Set(['path_traversal', 'combined_traversal_ssi', 'ai_assisted_path_traversal']);
const SSI_OBJECTIVES = new Set(['ssi_injection', 'combined_traversal_ssi', 'ai_assisted_ssi']);

function canonicalResult(objectiveId, result = {}) {
  if (!AI_OBJECTIVES.has(objectiveId)) return result;
  const decision = result.decision || {};
  const observation = result.observation || {};
  // A denied/no-op tool has no effect fields. Preserve that absence as JSON
  // null so the Judge can evaluate a negative, rather than reject the packet.
  if (decision.action === 'read_teaching_file') return {
    path: decision.params?.path ?? null,
    accessedPath: decision.params?.path ?? null,
    content: observation.content ?? null,
    boundary: observation.boundary ?? null,
    modelResponse: result.modelResponse?.response || '',
  };
  return {
    original: decision.params?.template ?? null,
    rendered: observation.rendered ?? null,
    commandExecution: observation.commandExecution ?? null,
    executionMode: observation.executionMode ?? null,
    modelResponse: result.modelResponse?.response || '',
  };
}

function inspect(objectiveId, result = {}) {
  const projected = canonicalResult(objectiveId, result);
  const returned = SSI_OBJECTIVES.has(objectiveId) ? projected.rendered : projected.content;
  const substituted = typeof projected.original === 'string' && /<!--#/.test(projected.original)
    && typeof projected.rendered === 'string' && projected.rendered !== projected.original
    && (AI_OBJECTIVES.has(objectiveId) || projected.ssiSucceeded === true);
  const flag = findChallengeFlag(returned);
  const facts = {
    observed_effect: SSI_OBJECTIVES.has(objectiveId) ? substituted : typeof returned === 'string',
    protected_path: projected.boundary?.outsidePublic === true,
    known_flag: Boolean(flag) && (objectiveId !== 'ai_assisted_ssi' || !String(projected.original || '').includes(flag)),
    ssi_substitution: substituted,
  };
  if (AI_OBJECTIVES.has(objectiveId)) {
    for (const key of ['qualified_decision_model', 'model_selected_allowed_tool', 'exact_call_observed',
      'subsequent_qualified_model_response', 'ssi_command_simulated']) {
      facts[key] = result.facts?.[key] === true;
    }
  }
  return { projected, returned, flag, facts };
}

function requiredFacts(objectiveId) {
  const required = ['observed_effect'];
  if (PATH_OBJECTIVES.has(objectiveId)) required.push('protected_path');
  if (SSI_OBJECTIVES.has(objectiveId)) required.push('ssi_substitution');
  if (objectiveId !== 'ssi_injection') required.push('known_flag');
  if (AI_OBJECTIVES.has(objectiveId)) required.push('qualified_decision_model', 'model_selected_allowed_tool',
    'exact_call_observed', 'subsequent_qualified_model_response');
  if (objectiveId === 'ai_assisted_ssi') required.push('ssi_command_simulated');
  return required;
}

function rubricFor(objectiveId) {
  if (!OBJECTIVES.includes(objectiveId)) throw new Error('Unknown Legacy Sensitive objective');
  const descriptions = {
    path_traversal: 'The owned teaching-file reader crossed its public boundary and returned an actual configured challenge flag.',
    ssi_injection: 'The owned lab SSI interpreter resolved a known variable or successfully included an owned file, changing the returned output. Unknown-variable placeholders, failed-include errors and simulated command output alone fail.',
    combined_traversal_ssi: 'One observed lab operation read a protected teaching file, successfully resolved a known SSI variable or included an owned file, and returned a configured challenge flag. Failed directives and simulated commands alone fail. The flag may come from the protected source file when a separate genuine SSI effect also occurred.',
    ai_assisted_path_traversal: 'A qualified configured model selected the exact file-read arguments, the server observed that protected read, and a second qualified response described its actual result.',
    ai_assisted_ssi: 'A qualified configured model selected the exact SSI template, the lab interpreter substituted it without OS execution, and a second qualified response described its actual result.',
  };
  return Object.freeze({ family: 'LegacySensitiveInfo', scenario: 'file_ssi', objectiveId,
    version: AI_OBJECTIVES.has(objectiveId) ? 'legacy-sensitive-canonical-v1' : 'legacy-sensitive-canonical-v2', mode: 'vuln',
    criteria: Object.freeze([{ id: 'observed_outcome', description: descriptions[objectiveId],
      allowedSources: Object.freeze(['tool_result', 'server_observation', 'assistant_response']) }]),
    requiredFacts: Object.freeze(requiredFacts(objectiveId)) });
}

function evidenceFor(objectiveId, request, result, inspected) {
  const base = [
    { id: 'request', source: 'student_input', content: String(request || '') },
    { id: 'tool_result', source: 'tool_result', content: inspected.projected },
    { id: 'effect_observation', source: 'server_observation', content: {
      observationOrdinal: result.observationOrdinal || null,
      outsidePublic: inspected.projected.boundary?.outsidePublic === true,
      configuredFlagObserved: Boolean(inspected.flag),
      ssiCommandExecution: inspected.projected.commandExecution || null,
    } },
  ];
  if (AI_OBJECTIVES.has(objectiveId) && Array.isArray(result.evidence)) {
    base.push(...result.evidence.map(row => ({ id: `agent_${row.id}`, source: row.source, content: row.content })));
  }
  return base;
}

function createLegacySensitiveObjectiveGrader({ completionService, judge = createObjectiveJudge(), postgres = true } = {}) {
  const service = () => completionService || require('./objectiveCompletionService').getObjectiveCompletionService();
  return Object.freeze({
    begin(userId, execution) {
      return postgres ? service().beginAttempt({ userId, workshopKey: WORKSHOP_KEY, execution }) : null;
    },
    async evaluate({ userId, objectiveId, request, result, execution, attempt }) {
      const rubric = rubricFor(objectiveId);
      const observed = inspect(objectiveId, result);
      const packet = { rubric, evidence: evidenceFor(objectiveId, request, result, observed),
        facts: Object.fromEntries(rubric.requiredFacts.map(key => [key, observed.facts[key] === true])), execution };
      if (postgres) return { ...await service().evaluate({ userId, workshopKey: WORKSHOP_KEY,
        ...packet, attempt }), durable: true };
      const judgment = await judge(packet);
      await execution.check();
      return { judgment, completed: judgment.verdict === 'pass'
        && rubric.requiredFacts.every(key => packet.facts[key] === true), durable: false };
    },
  });
}

module.exports = { WORKSHOP_KEY, OBJECTIVES, rubricFor, inspect, createLegacySensitiveObjectiveGrader };
