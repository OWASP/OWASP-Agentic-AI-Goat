'use strict';

const COMPARED_FIELDS = Object.freeze([
  'system_prompt',
  'success_criteria',
  'defense_style',
  'adaptive_mode',
]);

const COMPARISON_POLICY = Object.freeze({
  version: 'ctf-solution-applicability-v1',
  candidateBasis: 'canonical_default',
  comparedFields: COMPARED_FIELDS,
  description: 'Compares the exact guardian prompt and stage secret, the ordered defense array (ignoring JSON whitespace), and adaptive mode. Defense order and repeated layers remain significant. This reports configuration compatibility, not a guaranteed model outcome.',
});

function defenseValue(value) {
  if (typeof value !== 'string') return { valid: false };
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? { valid: true, value: JSON.stringify(parsed) } : { valid: false };
  } catch {
    return { valid: false };
  }
}

function differs(field, current, canonical) {
  if (field !== 'defense_style') return current[field] !== canonical[field];
  const currentDefense = defenseValue(current[field]);
  const canonicalDefense = defenseValue(canonical[field]);
  return !currentDefense.valid || !canonicalDefense.valid || currentDefense.value !== canonicalDefense.value;
}

function invalidCanonicalFields(canonical) {
  return COMPARED_FIELDS.filter(field => (
    field === 'defense_style'
      ? !defenseValue(canonical[field]).valid
      : typeof canonical[field] !== 'string'
  ));
}

function configurationApplicability(level, currentByNumber, canonicalByNumber) {
  const stageNumber = Number(level.level);
  const canonical = canonicalByNumber.get(stageNumber);
  if (!canonical) {
    return {
      candidateBasis: COMPARISON_POLICY.candidateBasis,
      appliesToDefault: false,
      currentConfiguration: 'canonical_default_missing',
      differingFields: [],
    };
  }
  const invalidFields = invalidCanonicalFields(canonical);
  if (invalidFields.length) {
    return {
      candidateBasis: COMPARISON_POLICY.candidateBasis,
      appliesToDefault: false,
      currentConfiguration: 'canonical_default_invalid',
      differingFields: [],
      invalidDefaultFields: invalidFields,
    };
  }
  const current = currentByNumber.get(stageNumber);
  if (!current) {
    return {
      candidateBasis: COMPARISON_POLICY.candidateBasis,
      appliesToDefault: true,
      currentConfiguration: 'stage_missing',
      differingFields: [],
    };
  }
  const differingFields = COMPARED_FIELDS.filter(field => differs(field, current, canonical));
  return {
    candidateBasis: COMPARISON_POLICY.candidateBasis,
    appliesToDefault: true,
    currentConfiguration: differingFields.length ? 'differs_from_default' : 'matches_default',
    differingFields,
  };
}

function annotateCtfSolutionLevels(levels, currentStages, canonicalStages) {
  const currentByNumber = new Map((currentStages || []).map(stage => [Number(stage.stage_number), stage]));
  const canonicalByNumber = new Map((canonicalStages || []).map(stage => [Number(stage.stage_number), stage]));
  return (levels || []).map(level => ({
    ...level,
    configurationApplicability: configurationApplicability(level, currentByNumber, canonicalByNumber),
  }));
}

module.exports = { COMPARED_FIELDS, COMPARISON_POLICY, annotateCtfSolutionLevels, configurationApplicability };
