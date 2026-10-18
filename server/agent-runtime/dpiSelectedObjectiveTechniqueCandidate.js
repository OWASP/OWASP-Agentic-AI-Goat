'use strict';

// Unmounted composition: jailbreak retains the v11 source instruction while
// role playing retains the v12 source-and-response role instructions.
const { createHash } = require('node:crypto');
const v11 = require('./dpiSelectedSourceTechniqueCandidate');
const v12 = require('./dpiSelectedRoleTechniqueCandidate');

const VERSION = 'dpi-selected-objective-technique-v13';
const COMPOSITION = 'objective-scoped-v11-jailbreak-v12-role-playing-v1';
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw Error('Unsupported selected objective-technique candidate'); };

function baseFor(input) {
  if (input?.objective === 'jailbreak') return v11.createDpiSelectedSourceTechniqueCandidate(input);
  if (input?.objective === 'role_playing') return v12.createDpiSelectedRoleTechniqueCandidate(input);
  fail();
}

function createDpiSelectedObjectiveTechniqueCandidate(input) {
  const base = baseFor(input);
  const schemaSha256 = sha(JSON.stringify(base.stages[0].messages().format));
  const instructionsSha256 = sha(JSON.stringify({
    version: VERSION,
    objective: input.objective,
    baseVersion: base.version,
    baseInstructionsSha256: base.policy.instructionsSha256,
    schemaSha256,
    composition: COMPOSITION,
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
      messages(error) { return base.stages[0].messages(error); },
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

module.exports = { VERSION, COMPOSITION, createDpiSelectedObjectiveTechniqueCandidate };
