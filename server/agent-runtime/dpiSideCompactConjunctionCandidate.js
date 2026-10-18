'use strict';

// Unmounted current-8B successor to the side-stepping conjunction candidate.
// It preserves v8 admission and reduction while compacting repeated locator
// schemas and allowing one repair only for a reducer-detected contradiction.
const { createHash } = require('node:crypto');
const { createDpiSideConjunctionCandidate } = require('./dpiSideConjunctionCandidate');
const direct = require('./dpiDirectWitnessCandidate');
const {
  CONTRADICTION_CODE,
  CONTRADICTION_REPAIR_POLICY,
} = require('./dpiSelectedCompactContextCandidate');
const { RESPONSE_CONSISTENCY_POLICY } = require('./dpiSelectedResponseConsistencyPolicy');

const VERSION = 'dpi-side-compact-conjunction-v9';
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw Error('Invalid DPI side compact-conjunction candidate'); };

function locatorField(value) {
  const ids = value?.type === 'string' && Array.isArray(value.enum) ? value.enum : null;
  if (!ids?.length || !ids.every(id => typeof id === 'string')) return null;
  if (ids.every(id => id.startsWith('source_'))) return 'source';
  if (ids.every(id => id.startsWith('response_'))) return 'response';
  return null;
}

function compactSideFormat(format) {
  const original = structuredClone(format);
  if (original?.$schema !== 'http://json-schema.org/draft-07/schema#' || original.definitions !== undefined) fail();
  const found = { source: [], response: [] };
  const collect = value => {
    const field = locatorField(value);
    if (field) found[field].push(value);
    if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') Object.values(value).forEach(collect);
  };
  collect(original);
  const definitions = {};
  for (const [field, values] of Object.entries(found)) {
    if (values.length < 2 || !values.every(value => JSON.stringify(value) === JSON.stringify(values[0]))) fail();
    definitions[field + 'Id'] = structuredClone(values[0]);
  }
  const replace = value => {
    const field = locatorField(value);
    if (field) return { $ref: '#/definitions/' + field + 'Id' };
    if (Array.isArray(value)) return value.map(replace);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item)]));
    return value;
  };
  const compact = replace(original);
  compact.definitions = definitions;
  return compact;
}

function compactWire(wire, contradictionRepair = false) {
  const format = compactSideFormat(wire?.format);
  const system = wire?.messages?.[0];
  if (!system || typeof system.content !== 'string' || !Array.isArray(wire.messages) || wire.messages.length !== 2) fail();
  const parts = system.content.split(direct.DELIMITER);
  if (parts.length !== 2) fail();
  return freeze({
    format,
    messages: [
      { ...system, content: parts[0] + RESPONSE_CONSISTENCY_POLICY
        + (contradictionRepair ? CONTRADICTION_REPAIR_POLICY : '') + direct.DELIMITER + JSON.stringify(format) },
      structuredClone(wire.messages[1]),
    ],
  });
}

function createDpiSideCompactConjunctionCandidate(input) {
  if (input?.objective !== 'side_stepping') fail();
  const base = createDpiSideConjunctionCandidate(input);
  if (base.stages.length !== 1 || base.stages[0].id !== 'assessment' || base.stages[0].maximumCalls !== 1) fail();
  const initialWire = compactWire(base.stages[0].messages());
  const schemaSha256 = sha(JSON.stringify(initialWire.format));
  const instructionsSha256 = sha(JSON.stringify({
    version: VERSION,
    baseVersion: base.version,
    baseInstructionsSha256: base.policy.instructionsSha256,
    schemaSha256,
    compaction: 'draft-07-shared-source-response-locator-v1',
    responseConsistencyPolicy: RESPONSE_CONSISTENCY_POLICY,
    contradictionGuard: 'existing-reducer-contradictions-one-repair-v1',
    contradictionRepairPolicy: CONTRADICTION_REPAIR_POLICY,
  }));
  let admittedValue;
  return freeze({
    version: VERSION,
    catalogDigest: base.catalogDigest,
    catalog: base.catalog,
    policy: freeze({ ...base.policy, version: VERSION, baseSemanticsVersion: base.version,
      maximumCalls: 2, schemaSha256, instructionsSha256 }),
    stages: freeze([freeze({
      id: 'assessment',
      maximumCalls: 2,
      retryWhen(error) { return error?.code === CONTRADICTION_CODE; },
      repairMessage(error) { return error?.code === CONTRADICTION_CODE
        ? CONTRADICTION_CODE : base.stages[0].repairMessage(error); },
      messages(error) {
        return compactWire(base.stages[0].messages(), error === CONTRADICTION_CODE);
      },
      validate(raw) {
        admittedValue = undefined;
        const candidate = base.stages[0].validate(raw);
        const reduced = base.combine(candidate);
        if (reduced.decisions?.some(decision => decision.contradictions?.length)) {
          throw Object.assign(new Error('Side-stepping observation labels are internally contradictory'), { code: CONTRADICTION_CODE });
        }
        admittedValue = candidate;
        return admittedValue;
      },
    })]),
    combine(value) {
      if (!admittedValue || value !== admittedValue) fail();
      const reduced = base.combine(value);
      return freeze({ ...reduced, version: VERSION, wireVersion: VERSION, baseSemanticsVersion: base.version });
    },
  });
}

module.exports = { VERSION, compactSideFormat, createDpiSideCompactConjunctionCandidate };
