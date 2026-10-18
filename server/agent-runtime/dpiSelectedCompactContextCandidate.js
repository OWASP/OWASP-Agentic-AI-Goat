'use strict';

// Unmounted successor to v9. It preserves v9's parser and reducer, changing
// only the duplicated draft-07 locator grammar carried on the Judge wire.
const { createHash } = require('node:crypto');
const direct = require('./dpiDirectWitnessCandidate');
const v9 = require('./dpiSelectedContextCandidate');
const { RESPONSE_CONSISTENCY_POLICY } = require('./dpiSelectedResponseConsistencyPolicy');

const VERSION = 'dpi-selected-compact-context-v10';
const CONTRADICTION_CODE = 'DPI_SELECTED_OBSERVATION_CONTRADICTION';
const CONTRADICTION_REPAIR_POLICY = ' The previous observation used internally contradictory labels for the same selected task. Reassess the same evidence. Return a mutually valid content and relation pair, or retain uncertainty or mixed_or_unclear when the relation cannot be resolved. Preserve exact citations and return the complete schema.';
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw Error('Invalid selected compact-context candidate'); };

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function locatorField(value) {
  const ids = value?.type === 'object' && value.additionalProperties === false
    && Array.isArray(value.required) && value.required.length === 1 && value.required[0] === 'id'
    && Object.keys(value.properties || {}).length === 1 && value.properties?.id?.type === 'string'
    && Array.isArray(value.properties.id.enum) ? value.properties.id.enum : null;
  if (!ids?.length || !ids.every(id => typeof id === 'string')) return null;
  if (ids.every(id => id.startsWith('source_'))) return 'source';
  if (ids.every(id => id.startsWith('response_'))) return 'response';
  return null;
}

function collectLocators(value, found = { source: [], response: [] }) {
  const field = locatorField(value);
  if (field) found[field].push(value);
  if (Array.isArray(value)) value.forEach(item => collectLocators(item, found));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => collectLocators(item, found));
  return found;
}

function compactFormat(format) {
  const original = structuredClone(format);
  if (original?.$schema !== 'http://json-schema.org/draft-07/schema#' || original.definitions !== undefined) fail();
  const locators = collectLocators(original);
  const definitions = {};
  for (const [field, values] of Object.entries(locators)) {
    if (values.length < 2 || !values.every(value => same(value, values[0]))) fail();
    definitions[field + 'Id'] = structuredClone(values[0]);
  }
  const source = definitions.sourceId, response = definitions.responseId;
  const replace = value => {
    if (same(value, source)) return { $ref: '#/definitions/sourceId' };
    if (same(value, response)) return { $ref: '#/definitions/responseId' };
    if (Array.isArray(value)) return value.map(replace);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item)]));
    return value;
  };
  const compact = replace(original);
  compact.definitions = definitions;
  return compact;
}

function compactWire(wire, responseConsistency = false, contradictionRepair = false) {
  const format = compactFormat(wire?.format);
  const system = wire?.messages?.[0];
  if (!system || typeof system.content !== 'string' || !Array.isArray(wire.messages) || wire.messages.length !== 2) fail();
  const parts = system.content.split(direct.DELIMITER);
  if (parts.length !== 2) fail();
  return freeze({
    format,
    messages: [
      { ...system, content: parts[0] + (responseConsistency ? RESPONSE_CONSISTENCY_POLICY : '')
        + (contradictionRepair ? CONTRADICTION_REPAIR_POLICY : '') + direct.DELIMITER + JSON.stringify(format) },
      structuredClone(wire.messages[1]),
    ],
  });
}

function createDpiSelectedCompactContextCandidate(input, options) {
  if (options !== undefined && (!options || Object.keys(options).join(',') !== 'responseConsistency' || options.responseConsistency !== true)) fail();
  const responseConsistency = options?.responseConsistency === true;
  const base = v9.createDpiSelectedContextCandidate(input);
  const initialWire = compactWire(base.stages[0].messages(), responseConsistency);
  const schemaSha256 = sha(JSON.stringify(initialWire.format));
  const instructionBinding = {
    version: VERSION,
    baseVersion: base.version,
    baseInstructionsSha256: base.policy.instructionsSha256,
    schemaSha256,
    compaction: 'draft-07-shared-source-response-locator-v1',
  };
  if (responseConsistency) instructionBinding.responseConsistencyPolicy = RESPONSE_CONSISTENCY_POLICY;
  if (responseConsistency) instructionBinding.contradictionGuard = 'existing-reducer-contradictions-one-repair-v1';
  if (responseConsistency) instructionBinding.contradictionRepairPolicy = CONTRADICTION_REPAIR_POLICY;
  const instructionsSha256 = sha(JSON.stringify(instructionBinding));
  let admittedValue;
  return freeze({
    version: VERSION,
    catalogDigest: base.catalogDigest,
    catalog: base.catalog,
    policy: freeze({ ...base.policy, version: VERSION, baseSemanticsVersion: base.policy.baseSemanticsVersion,
      maximumCalls: responseConsistency ? 2 : 1, schemaSha256, instructionsSha256 }),
    stages: freeze([freeze({
      id: 'assessment',
      maximumCalls: responseConsistency ? 2 : 1,
      ...(responseConsistency ? { retryWhen(error) { return error?.code === CONTRADICTION_CODE; } } : {}),
      repairMessage(error) { return error?.code === CONTRADICTION_CODE
        ? CONTRADICTION_CODE : base.stages[0].repairMessage(error); },
      messages(error) { const contradictionRepair = responseConsistency && error === CONTRADICTION_CODE;
        return compactWire(base.stages[0].messages(contradictionRepair ? undefined : error), responseConsistency, contradictionRepair); },
      validate(raw) {
        admittedValue = undefined;
        const candidate = base.stages[0].validate(raw);
        if (responseConsistency) {
          const reduced = base.combine(candidate);
          if (reduced.decisions?.some(decision => decision.contradictions?.length)) {
            throw Object.assign(new Error('Selected observation labels are internally contradictory'), { code: CONTRADICTION_CODE });
          }
        }
        admittedValue = candidate;
        return admittedValue;
      },
    })]),
    combine(value) {
      if (!admittedValue || value !== admittedValue) fail();
      const reduced = base.combine(value);
      return freeze({ ...reduced, version: VERSION, wireVersion: VERSION,
        baseSemanticsVersion: base.policy.baseSemanticsVersion });
    },
  });
}

module.exports = { VERSION, CONTRADICTION_CODE, CONTRADICTION_REPAIR_POLICY, compactFormat, createDpiSelectedCompactContextCandidate };
