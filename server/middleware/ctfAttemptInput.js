'use strict';

// defense_style is stored and edited as JSON text. Keep the runtime's ordered,
// repeatable layer semantics while preventing new silent no-ops at admin writes.
const CTF_DEFENSE_NAMES = new Set([
  'input_blocklist',
  'persona_guard',
  'polyglot_decoder',
  'transformation_guard',
  'instruction_leak_guard',
  'output_regex_strip',
  'output_fuzzy_strip',
  'meta_llm_judge',
  'meta_structured_artifact_reviewer_v1',
  'meta_rotation_handoff_reviewer_v1',
]);

function ctfStageDefenseInput(req, res, next) {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Stage configuration must be an object' });
  }
  if (!Object.hasOwn(req.body, 'defense_style')) return next();
  if (typeof req.body.defense_style !== 'string') {
    return res.status(400).json({ error: 'Defense style must be JSON text containing an array' });
  }
  let layers;
  try {
    layers = JSON.parse(req.body.defense_style);
  } catch {
    return res.status(400).json({ error: 'Defense style must be valid JSON' });
  }
  if (!Array.isArray(layers)) {
    return res.status(400).json({ error: 'Defense style must contain a JSON array' });
  }
  if (layers.some(layer => typeof layer !== 'string' || !CTF_DEFENSE_NAMES.has(layer))) {
    return res.status(400).json({ error: 'Defense style contains an unknown defense name' });
  }
  next();
}

// Validate the transport shape, not the attack language. Preserve the exact
// learner payload for classification, hashing, guardian input and evidence.
function ctfStageIdInput(stageParameter, label = 'stage') {
  return (req, res, next) => {
    const stage = req.params[stageParameter];
    if (typeof stage !== 'string' || !/^[1-9][0-9]*$/.test(stage)
        || !Number.isSafeInteger(Number(stage)) || Number(stage) > 2147483647) {
      return res.status(400).json({ error: `Invalid ${label} ID` });
    }
    next();
  };
}

function ctfAttemptInput(stageParameter) {
  const validateStage = ctfStageIdInput(stageParameter);
  return (req, res, next) => validateStage(req, res, () => {
    if (!req.body || typeof req.body.payload !== 'string' || !req.body.payload.trim()) {
      return res.status(400).json({ error: 'Payload must be a non-empty string' });
    }
    next();
  });
}

function ctfStageSecretInput({ partial = false } = {}) {
  return (req, res, next) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Stage configuration must be an object' });
    }
    if (!partial || Object.hasOwn(req.body, 'success_criteria')) {
      // The current visible-secret scorer removes non-ASCII letters/digits.
      // Reject an unrepresentable secret instead of silently saving an unwinnable stage.
      if (typeof req.body.success_criteria !== 'string' || !/[a-z0-9]/.test(req.body.success_criteria.toLowerCase())) {
        return res.status(400).json({ error: 'Stage secret must contain at least one ASCII letter or digit' });
      }
    }
    return ctfStageDefenseInput(req, res, next);
  };
}

module.exports = { CTF_DEFENSE_NAMES, ctfAttemptInput, ctfStageIdInput, ctfStageSecretInput, ctfStageDefenseInput };
