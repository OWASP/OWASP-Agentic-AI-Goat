'use strict';
// The v16 multilingual comparison is qualified only for the actor and Judge
// model used by its actual, owner-bound browser cohort. The repository passes
// a normalized, audited result here; model names are not runtime digest proof.
function qualifiedMultilingual(row, result) {
  if (row?.workshop_key !== 'direct_prompt_injection' || row?.family !== 'DPI'
    || row?.scenario !== 'aws_assistant' || row?.objective_id !== 'multi_language'
    || row?.rubric_version !== 'dpi-multi_language-v16' || row?.mode !== 'vuln'
    || row?.canonical_mode !== 'vuln' || !['pass', 'fail'].includes(result?.verdict)) return false;
  const audit = result.dpiAnswerComparison;
  const actor = audit?.observation?.provenance;
  const stages = audit?.stages;
  const sameModel = record => record?.provider === 'ollama' && record?.model === 'llama3.3:70b';
  return audit?.version === 'dpi-answer-comparison-v13'
    && actor?.version === 'dpi-owned-actor-v1' && actor?.runId === row.run_id
    && actor?.ownerKey === JSON.stringify(['DPI', String(row.user_id)])
    && actor?.generation === String(row.generation) && actor?.mode === 'vuln'
    && sameModel(actor) && Array.isArray(stages)
    && stages.length === (result.verdict === 'pass' ? 2 : audit.observation?.assessment?.decision === 'supported' ? 2 : 1)
    && stages.every((stage, index) => stage.stage === (index ? 'verify' : 'assessment')
      && stage.completed === true && stage.attempts >= 1 && sameModel(stage))
    && sameModel(result);
}
function qualifiedSelectedTask(row, result) {
  const audit = result?.dpiAnswerComparison;
  const selected = require('./dpiSelectedTaskComparison');
  const protocol = selected.getSelectedProtocol(audit?.version);
  if (!protocol || ![selected.CONJUNCTION_VERSION, selected.JAILBREAK_VERSION, selected.ROLE_PLAYING_VERSION, selected.CONTEXT_JAILBREAK_VERSION, selected.CONTEXT_ROLE_PLAYING_VERSION, selected.COMPACT_CONTEXT_JAILBREAK_VERSION, selected.COMPACT_CONTEXT_ROLE_PLAYING_VERSION].includes(protocol.version)
    || row?.workshop_key !== 'direct_prompt_injection' || row?.family !== 'DPI'
    || row?.scenario !== 'aws_assistant' || row?.objective_id !== protocol.objective
    || row?.rubric_version !== protocol.rubricVersion || row?.mode !== 'vuln'
    || row?.canonical_mode !== 'vuln' || !['pass', 'fail'].includes(result?.verdict)) return false;
  const observation = audit.observation, actor = observation?.provenance, stages = audit.stages;
  const compact = [selected.COMPACT_CONTEXT_JAILBREAK_VERSION, selected.COMPACT_CONTEXT_ROLE_PLAYING_VERSION].includes(protocol.version);
  const modelContract = value => value?.provider === 'ollama'
    && value?.model === (compact ? 'llama3.1:8b' : 'llama3.3:70b');
  // The repository separately replays the retained original packet and binds
  // actor.generation to the durable execution generation. It differs from the
  // progress row's generation.
  if (observation?.version !== protocol.version || observation?.diagnosticVersion !== protocol.diagnosticVersion
    || (protocol.version !== selected.CONJUNCTION_VERSION && observation?.objective !== protocol.objective) || observation?.candidateAudit?.version !== protocol.diagnosticVersion
    || observation?.candidateAudit?.verdict !== result.verdict
    || actor?.version !== 'dpi-owned-actor-v3' || actor?.objective !== protocol.objective
    || actor?.runId !== row.run_id || !row.run_id
    || actor?.ownerKey !== JSON.stringify(['DPI', String(row.user_id)])
    || typeof actor?.generation !== 'string' || !actor.generation || actor?.mode !== 'vuln'
    || !Array.isArray(stages) || stages.length !== 1
    || stages[0].stage !== 'selected' || stages[0].completed !== true
    || typeof observation.selectedRaw !== 'string') return false;
  const attempts = stages[0].attempts;
  if (!modelContract(actor) || !modelContract(result) || !modelContract(stages[0])
    || !Number.isSafeInteger(attempts) || attempts < 1 || attempts > (compact ? 2 : 1)
    || !Array.isArray(stages[0].responseSha256) || stages[0].responseSha256.length !== attempts
    || stages[0].responseSha256.some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value))) return false;
  if (protocol.version === selected.CONJUNCTION_VERSION
    && observation.candidateAudit?.reduction?.verdict !== result.verdict) return false;
  return stages[0].responseSha256.at(-1) === require('node:crypto').createHash('sha256').update(observation.selectedRaw).digest('hex');
}
function gradingUnqualified(row, result) {
  return row?.workshop_key === 'direct_prompt_injection'
    && row?.family === 'DPI'
    && ((row.mode === 'fixed' && row.objective_id !== 'interact')
      || ['virtualization','obfuscation'].includes(row.objective_id)
      || (row.objective_id === 'multi_language' && (row.rubric_version === 'dpi-multi_language-v15'
        || row.rubric_version === 'dpi-multi_language-v16' && !qualifiedMultilingual(row, result)))
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-server-ids-v1')
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-conjunction-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-compact-conjunction-v3')
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-server-ids-v1' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-server-ids-v1' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-context-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-context-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-compact-context-v3' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-compact-context-v3' && !qualifiedSelectedTask(row, result))
      || require('./dpiTechniqueWitnessAudit').isVersion(row));
}
function projectJudgment(receipt) {
  const result=receipt?.result;
  if(receipt?.disposition!=='grading_unqualified')return result;
  return {...result,gradingStatus:'pending',gradingDisposition:'grading_unqualified',
    gradingMessage:'Objective grading is not qualified for reliable credit. Your response and raw evaluation are retained; no completion was awarded.'};
}
module.exports={gradingUnqualified,projectJudgment};
