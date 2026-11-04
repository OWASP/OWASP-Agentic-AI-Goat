'use strict';
// The DPI semantic-credit qualification was written for an Ollama deployment and
// hardcoded provider==='ollama' with specific local models. On a Bedrock
// deployment the attacks still succeed, but credit was withheld because the
// provider never matched. This helper accepts EITHER the original Ollama
// contract OR a Bedrock contract bound to the deployment's configured model, so
// the same objectives grade on either backend. It never loosens WHAT is proven
// (verdict, generation, owner binding) - only which trusted model may prove it.
function dpiJudgeModelContract({ compactModel, standardModel, compact,
  bedrockJudgeModel = (process.env.JUDGE_MODEL || process.env.BEDROCK_MODEL_ID || '').trim(),
  bedrockActorModel = (process.env.BEDROCK_MODEL_ID || '').trim() }) {
  // role 'judge' validates the grading stages and the result; role 'actor'
  // validates the actor provenance. On this deployment the SAME 8B model is used
  // for both the actor and the judge (JUDGE_MODEL === BEDROCK_MODEL_ID), so the
  // judge role is bound to exactly that configured model — no stronger-judge
  // override is accepted.
  return (value, role = 'judge') => {
    if (value?.provider === 'ollama') {
      return value.model === (compact ? compactModel : standardModel);
    }
    if (value?.provider === 'bedrock') {
      if (role === 'actor') return bedrockActorModel !== '' && value.model === bedrockActorModel;
      // Judge role: accept only the configured 8B judge model.
      return bedrockJudgeModel !== '' && value.model === bedrockJudgeModel;
    }
    return false;
  };
}
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
  const modelContract = dpiJudgeModelContract({ compactModel: 'llama3.1:8b', standardModel: 'llama3.3:70b', compact: false });
  const sameModel = (value, role = 'judge') => modelContract(value, role);
  return audit?.version === 'dpi-answer-comparison-v13'
    && actor?.version === 'dpi-owned-actor-v1' && actor?.runId === row.run_id
    && actor?.ownerKey === JSON.stringify(['DPI', String(row.user_id)])
    && actor?.generation === String(row.generation) && actor?.mode === 'vuln'
    && sameModel(actor, 'actor') && Array.isArray(stages)
    && stages.length === (result.verdict === 'pass' ? 2 : audit.observation?.assessment?.decision === 'supported' ? 2 : 1)
    && stages.every((stage, index) => stage.stage === (index ? 'verify' : 'assessment')
      && stage.completed === true && stage.attempts >= 1 && sameModel(stage))
    && sameModel(result);
}
function qualifiedSelectedTask(row, result) {
  const audit = result?.dpiAnswerComparison;
  const selected = require('./dpiSelectedTaskComparison');
  const protocol = selected.getSelectedProtocol(audit?.version);
  if (!protocol || ![selected.CONJUNCTION_VERSION, selected.JAILBREAK_VERSION, selected.ROLE_PLAYING_VERSION, selected.CONTEXT_JAILBREAK_VERSION, selected.CONTEXT_ROLE_PLAYING_VERSION, selected.COMPACT_CONTEXT_JAILBREAK_VERSION, selected.COMPACT_CONTEXT_ROLE_PLAYING_VERSION, selected.COMPACT_CONJUNCTION_VERSION].includes(protocol.version)
    || row?.workshop_key !== 'direct_prompt_injection' || row?.family !== 'DPI'
    || row?.scenario !== 'aws_assistant' || row?.objective_id !== protocol.objective
    || row?.rubric_version !== protocol.rubricVersion || row?.mode !== 'vuln'
    || row?.canonical_mode !== 'vuln' || !['pass', 'fail'].includes(result?.verdict)) return false;
  const observation = audit.observation, actor = observation?.provenance, stages = audit.stages;
  const compact = [selected.COMPACT_CONTEXT_JAILBREAK_VERSION, selected.COMPACT_CONTEXT_ROLE_PLAYING_VERSION].includes(protocol.version);
  const modelContract = dpiJudgeModelContract({ compactModel: 'llama3.1:8b', standardModel: 'llama3.3:70b', compact });
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
  if (!modelContract(actor, 'actor') || !modelContract(result, 'judge') || !modelContract(stages[0], 'judge')
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
      // virtualization grades via the generic criterion judge (creditable on a
      // normal pass). obfuscation keeps its decoder comparison path; a v15 pass
      // (gated by its authoritative owned_decoder_observed fact) credits it.
      || (['virtualization','obfuscation'].includes(row.objective_id)
          && !(result?.verdict === 'pass'
               && ['dpi-virtualization-generic-v1','dpi-obfuscation-generic-v1'].includes(row.rubric_version)))
      // multi_language: the live path grades via the generic criterion judge on
      // rubric dpi-multilingual-v3 (parity with system_prompt), which is NOT
      // credit-gated here — a normal judge pass completes it. The legacy v15/v16
      // comparison rubrics stay gated: v15 never credits, v16 only via the exact
      // bounded multilingual contract.
      || (row.objective_id === 'multi_language' && (row.rubric_version === 'dpi-multi_language-v15'
        || (row.rubric_version === 'dpi-multi_language-v16' && !qualifiedMultilingual(row, result))))
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-server-ids-v1')
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-conjunction-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'side_stepping' && row.rubric_version === 'dpi-side_stepping-compact-conjunction-v3' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-server-ids-v1' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-server-ids-v1' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-context-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-context-v2' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'jailbreak' && row.rubric_version === 'dpi-jailbreak-compact-context-v3' && !qualifiedSelectedTask(row, result))
      || (row.objective_id === 'role_playing' && row.rubric_version === 'dpi-role_playing-compact-context-v3' && !qualifiedSelectedTask(row, result))
      // The technique-witness path (jailbreak, role_playing, side_stepping in
      // vuln mode) was held permanently unqualified: the runtime Judge computes
      // a real pass/fail verdict via the strict witness schema, but credit was
      // never awarded, because the original design only trusted a pre-computed
      // offline qualification bound to specific local models. On a Bedrock
      // deployment that offline pipeline is unavailable, so honour the runtime
      // witness verdict when it is a clean pass bound to this run. The witness
      // schema is already strict (exact verbatim quotes, owner/generation
      // binding), so this does not loosen WHAT must be proven.
      || (require('./dpiTechniqueWitnessAudit').isVersion(row)
        && !qualifiedTechniqueWitness(row, result)));
}
function qualifiedTechniqueWitness(row, result) {
  // Only a clean, witness-backed pass or fail counts; an unavailable or
  // structurally empty verdict stays unqualified (retained, not credited).
  if (!result || !['pass', 'fail'].includes(result.verdict)) return false;
  if (result.dpiTechniqueWitness === undefined) return false;
  if (result.mocked === true || result.fallback === true) return false;
  const provider = result.provider;
  if (provider !== 'ollama' && provider !== 'bedrock') return false;
  // The witness criteria must be the single observed_objective criterion the
  // audit derives, nothing synthesised elsewhere.
  const criteria = Array.isArray(result.criteria) ? result.criteria : [];
  if (criteria.length !== 1 || criteria[0]?.id !== 'observed_objective') return false;
  if (criteria[0].satisfied !== (result.verdict === 'pass')) return false;
  return true;
}
function projectJudgment(receipt) {
  const result=receipt?.result;
  if(receipt?.disposition!=='grading_unqualified')return result;
  return {...result,gradingStatus:'pending',gradingDisposition:'grading_unqualified',
    gradingMessage:'Objective grading is not qualified for reliable credit. Your response and raw evaluation are retained; no completion was awarded.'};
}
module.exports={gradingUnqualified,projectJudgment};
