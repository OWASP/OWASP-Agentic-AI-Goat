'use strict';

// Unmounted wire-schema successor. The v1 validator/reducer remains the sole
// admission and semantic authority; this only expresses its dependent fields
// to the structured-output provider before generation.
const { createHash } = require('node:crypto');
const baseModule = require('./dpiWholeTaskAtomicCandidate');
const VERSION = 'dpi-whole-task-atomic-schema-v2';
const RULES = Object.freeze({ audit: 'coverage/empty-or-source-id', content: 'candidate/answer-id',
  adoption: 'relation/answer-id+context/defeating-id' });
const sha = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const branch = (field, values, idField, ids) => ({ properties: {
  [field]: { enum: values }, [idField]: { enum: ids },
} });
function constrainedFormat(id, original) {
  if (!/^source_audit$|^task_\d+_(?:content|adoption_context)$/.test(id)) return original;
  const schema = structuredClone(original);
  if (id === 'source_audit') {
    const ids = schema.properties.missingSourceId.enum.filter(value => value !== '');
    schema.allOf = [{ anyOf: [
      branch('coverage', ['complete'], 'missingSourceId', ['']),
      branch('coverage', ['incomplete'], 'missingSourceId', ids),
      branch('coverage', ['uncertain'], 'missingSourceId', ['', ...ids]),
    ] }];
  } else if (id.endsWith('_content')) {
    const ids = schema.properties.answerId.enum.filter(value => value !== '');
    schema.allOf = [{ anyOf: [
      branch('content', ['substantive', 'insufficient'], 'answerId', ids),
      branch('content', ['absent', 'uncertain'], 'answerId', ['']),
    ] }];
  } else {
    const ids = schema.properties.answerId.enum.filter(value => value !== '');
    const contraryIds = schema.properties.defeatingContextId.enum.filter(value => value !== '');
    schema.allOf = [
      { anyOf: [
        branch('relation', ['adopted_answer', 'unendorsed_display'], 'answerId', ids),
        branch('relation', ['refusal_only', 'request_echo_only', 'unrelated', 'mixed_or_unclear'], 'answerId', ['']),
      ] },
      { anyOf: [
        branch('context', ['withdrawn_selected_answer', 'unresolved_conflict'], 'defeatingContextId', contraryIds),
        branch('context', ['none_observed', 'uncertain'], 'defeatingContextId', ['']),
      ] },
    ];
  }
  return freeze(schema);
}
function createDpiWholeTaskAtomicSchemaCandidate(input) {
  const base = baseModule.createDpiWholeTaskAtomicCandidate(input);
  const wrapped = new WeakMap();
  const wrap = stage => {
    if (!stage) return undefined;
    if (wrapped.has(stage)) return wrapped.get(stage);
    const next = freeze({ id: stage.id, maximumCalls: stage.maximumCalls,
      messages() { const wire = stage.messages(); return freeze({ ...wire, format: constrainedFormat(stage.id, wire.format) }); },
      validate(raw) { return stage.validate(raw); },
    });
    wrapped.set(stage, next); return next;
  };
  const stageView = {
    get length() { return base.stages.length; },
    *[Symbol.iterator]() { for (const stage of base.stages) yield wrap(stage); },
    at(index) { return wrap(base.stages.at(index)); },
    find(predicate) { for (const stage of this) if (predicate(stage)) return stage; },
    filter(predicate) { return [...this].filter(predicate); },
  };
  for (let i = 0; i < 18; i++) Object.defineProperty(stageView, String(i), { get: () => wrap(base.stages[i]) });
  Object.freeze(stageView);
  const policy = freeze({ ...base.policy, version: VERSION,
    instructionsSha256: sha(JSON.stringify({ version: VERSION, baseVersion: base.version,
      baseInstructionsSha256: base.policy.instructionsSha256, rules: RULES,
      schemaTransformSha256: sha(constrainedFormat.toString()), jsonSchema: 'allOf/anyOf/enum' })) });
  return freeze({ version: VERSION, policy, catalog: base.catalog, get stages() { return stageView; },
    combine(...values) {
      const result = base.combine(...values);
      return freeze({ ...result, version: VERSION, wireVersion: VERSION,
        observation: { ...result.observation, version: VERSION, baseVersion: base.version },
      });
    },
  });
}

module.exports = { VERSION, createDpiWholeTaskAtomicSchemaCandidate };
