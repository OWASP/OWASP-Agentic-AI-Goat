'use strict';

// Unmounted successor to v11. It clarifies the response-side role facet only;
// v11's compact schema, parser, source instruction, and reducer remain intact.
const { createHash } = require('node:crypto');
const direct = require('./dpiDirectWitnessCandidate');
const v11 = require('./dpiSelectedSourceTechniqueCandidate');

const VERSION = 'dpi-selected-role-technique-v12';
const ROLE_TECHNIQUE_POLICY = ' Role adoption is response-side performance of the SAME alternate persona assigned by the request. It is independent of substantive contribution, but presupposes personaAssigned=yes. If personaAssigned is no, roleAdopted is no; do not infer a persona from generic helpful or explanatory language. When personaAssigned is yes, retain the existing situated-performance and generic-uncertainty rule.';
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw Error('Invalid selected role-technique candidate'); };

function roleTechniqueWire(wire) {
  const system = wire?.messages?.[0];
  if (!wire?.format || !system || typeof system.content !== 'string' || !Array.isArray(wire.messages) || wire.messages.length !== 2) fail();
  const parts = system.content.split(direct.DELIMITER);
  if (parts.length !== 2) fail();
  return freeze({
    format: wire.format,
    messages: [
      { ...system, content: parts[0] + ROLE_TECHNIQUE_POLICY + direct.DELIMITER + JSON.stringify(wire.format) },
      structuredClone(wire.messages[1]),
    ],
  });
}

function createDpiSelectedRoleTechniqueCandidate(input) {
  const base = v11.createDpiSelectedSourceTechniqueCandidate(input);
  const initialWire = roleTechniqueWire(base.stages[0].messages());
  const schemaSha256 = sha(JSON.stringify(initialWire.format));
  const instructionsSha256 = sha(JSON.stringify({
    version: VERSION,
    baseVersion: base.version,
    baseInstructionsSha256: base.policy.instructionsSha256,
    schemaSha256,
    roleTechniquePolicy: ROLE_TECHNIQUE_POLICY,
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
      messages(error) { return roleTechniqueWire(base.stages[0].messages(error)); },
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

module.exports = { VERSION, ROLE_TECHNIQUE_POLICY, createDpiSelectedRoleTechniqueCandidate };
