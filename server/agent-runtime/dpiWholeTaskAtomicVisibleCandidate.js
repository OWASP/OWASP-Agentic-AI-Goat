'use strict';

// Unmounted structured-output wire repair. The effective closed schema is
// visible to the model and contains the same values accepted by v2/v1.
const { createHash } = require('node:crypto');
const schemaModule = require('./dpiWholeTaskAtomicSchemaCandidate');
const VERSION = 'dpi-whole-task-atomic-visible-v3';
const sha = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };

function flatFormat(format) {
  if (!format.allOf) return format;
  // v2 constraints are independent anyOf groups of property enum subsets.
  // Produce the exact Cartesian intersection as complete object alternatives.
  let branches = [structuredClone(format.properties)];
  for (const group of format.allOf) {
    if (!Array.isArray(group.anyOf) || !group.anyOf.length) throw Error('Invalid atomic schema group');
    const next = [];
    for (const properties of branches) for (const option of group.anyOf) {
      const combined = structuredClone(properties);
      for (const [key, restriction] of Object.entries(option.properties || {})) {
        const current = combined[key];
        if (!current?.enum || !restriction?.enum) throw Error('Invalid atomic schema restriction');
        const allowed = current.enum.filter(value => restriction.enum.includes(value));
        if (!allowed.length) throw Error('Empty atomic schema branch');
        combined[key] = { ...current, enum: allowed };
      }
      next.push(combined);
    }
    branches = next;
  }
  return freeze({ anyOf: branches.map(properties => ({ type: 'object', properties,
    required: [...format.required], additionalProperties: false })) });
}

function createDpiWholeTaskAtomicVisibleCandidate(input) {
  const base = schemaModule.createDpiWholeTaskAtomicSchemaCandidate(input);
  const wrapped = new WeakMap();
  const wrap = stage => {
    if (!stage) return undefined;
    if (wrapped.has(stage)) return wrapped.get(stage);
    const next = freeze({ id: stage.id, maximumCalls: stage.maximumCalls,
      messages() {
        const original = stage.messages();
        const format = flatFormat(original.format);
        const messages = [...original.messages];
        messages[0] = { ...messages[0], content: `${messages[0].content}\nOUTPUT_JSON_SCHEMA:${JSON.stringify(format)}` };
        return freeze({ format, messages });
      },
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
      baseInstructionsSha256: base.policy.instructionsSha256,
      transformSha256: sha(flatFormat.toString()), promptSuffix: 'OUTPUT_JSON_SCHEMA:JSON.stringify(effectiveFormat)' })) });
  return freeze({ version: VERSION, policy, catalog: base.catalog, get stages() { return stageView; },
    combine(...values) {
      const result = base.combine(...values);
      return freeze({ ...result, version: VERSION, wireVersion: VERSION,
        observation: { ...result.observation, version: VERSION, baseVersion: base.version },
      });
    },
  });
}

module.exports = { VERSION, createDpiWholeTaskAtomicVisibleCandidate };
