'use strict';

// Unmounted successor to v13. It adds a general consistency instruction only;
// source policy selection, schema, raw admission, and reduction remain v13.
const { createHash } = require('node:crypto');
const direct = require('./dpiDirectWitnessCandidate');
const v13 = require('./dpiSelectedObjectiveTechniqueCandidate');
const { RESPONSE_CONSISTENCY_POLICY } = require('./dpiSelectedResponseConsistencyPolicy');

const VERSION = 'dpi-selected-response-consistency-v14';
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw Error('Invalid selected response-consistency candidate'); };

function responseConsistencyWire(wire) {
  const system = wire?.messages?.[0];
  if (!wire?.format || !system || typeof system.content !== 'string' || !Array.isArray(wire.messages) || wire.messages.length !== 2) fail();
  const parts = system.content.split(direct.DELIMITER);
  if (parts.length !== 2) fail();
  return freeze({
    format: wire.format,
    messages: [
      { ...system, content: parts[0] + RESPONSE_CONSISTENCY_POLICY + direct.DELIMITER + JSON.stringify(wire.format) },
      structuredClone(wire.messages[1]),
    ],
  });
}

function createDpiSelectedResponseConsistencyCandidate(input) {
  const base = v13.createDpiSelectedObjectiveTechniqueCandidate(input);
  const initialWire = responseConsistencyWire(base.stages[0].messages());
  const schemaSha256 = sha(JSON.stringify(initialWire.format));
  const instructionsSha256 = sha(JSON.stringify({
    version: VERSION,
    objective: input.objective,
    baseVersion: base.version,
    baseInstructionsSha256: base.policy.instructionsSha256,
    schemaSha256,
    responseConsistencyPolicy: RESPONSE_CONSISTENCY_POLICY,
  }));
  let admittedValue;
  return freeze({
    version: VERSION,
    catalogDigest: base.catalogDigest,
    catalog: base.catalog,
    policy: freeze({ ...base.policy, version: VERSION, baseSemanticsVersion: base.policy.baseSemanticsVersion,
      maximumCalls: 1, schemaSha256, instructionsSha256 }),
    stages: freeze([freeze({
      id: 'assessment',
      maximumCalls: 1,
      repairMessage: base.stages[0].repairMessage,
      messages(error) { return responseConsistencyWire(base.stages[0].messages(error)); },
      validate(raw) {
        admittedValue = undefined;
        admittedValue = base.stages[0].validate(raw);
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

module.exports = { VERSION, RESPONSE_CONSISTENCY_POLICY, createDpiSelectedResponseConsistencyCandidate };
