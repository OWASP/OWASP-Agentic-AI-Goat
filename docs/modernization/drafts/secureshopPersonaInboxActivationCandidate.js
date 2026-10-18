'use strict';

const crypto = require('node:crypto');

const SOURCE_SHA256 = Object.freeze({
  application: '97e49e79f56e015833d19fad3e67d2499aaab41f1007f27799cd27306b88f464',
  composition: '6d9e02e42320cf6cdd2a699ca6267dbe05737b1d970d36c3ada3f90a681b3945',
  curriculum: 'e63f7b375625ad403df39f95fb07b83cc326e50e63c98abf38030984ded782c0',
});
const QUALIFIED = Object.freeze([
  'ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block',
]);

function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function replaceExact(source, before, after, label) {
  if (source.split(before).length !== 2) throw new Error(`${label} source seam changed`);
  return source.replace(before, after);
}

function buildCandidates({ application, composition, curriculum }) {
  for (const [name, source] of Object.entries({ application, composition, curriculum })) {
    if (typeof source !== 'string' || hash(source) !== SOURCE_SHA256[name]) {
      throw new Error(`${name} source is not the reviewed frozen version`);
    }
  }
  application = replaceExact(application, "'use strict';\n",
    "'use strict';\n\nconst { activationPolicy } = require('./secureshopPersonaInboxActivationPolicy');\n",
    'application import');
  application = replaceExact(application,
    "  const personaInboxFeature = process.env.SS_PERSONA_INBOX_READY === 'true';",
    '  const personaInboxFeature = activationPolicy(process.env).requested;', 'application policy');

  composition = replaceExact(composition, "'use strict';\n",
    "'use strict';\n\nconst { activationPolicy } = require('./secureshopPersonaInboxActivationPolicy');\n",
    'composition import');
  composition = replaceExact(composition,
    "  if (options.personaInboxFeature === true && process.env.SS_PERSONA_INBOX_READY !== 'true') {\n    throw unavailable('Persona inbox feature is not ready');\n  }",
    "  const personaPolicy = activationPolicy(process.env);\n  if (options.personaInboxFeature !== personaPolicy.requested) {\n    throw unavailable('Persona inbox activation policy does not match the requested composition');\n  }",
    'composition policy');

  for (const id of QUALIFIED) {
    curriculum = replaceExact(curriculum,
      `id: '${id}', text:`, `id: '${id}', text:`, `${id} identity`);
    const pattern = new RegExp(`(\\{ id: '${id}',[^\\n]+qualification: )'pending'`);
    if ([...curriculum.matchAll(new RegExp(pattern.source, 'g'))].length !== 1) {
      throw new Error(`${id} qualification seam changed`);
    }
    curriculum = curriculum.replace(pattern, "$1'native-model'");
  }
  curriculum = replaceExact(curriculum, "category: 'ai', difficulty: 'advanced', route: '', visible: 0, defaultVisible: false",
    "category: 'ai', difficulty: 'advanced', route: '/workshop/secureshop', visible: 0, defaultVisible: false",
    'curriculum route');
  curriculum = replaceExact(curriculum, 'const qualifiedHints = {', `const qualifiedHints = {
  ss_cross_persona_effect: [
    'Use one persona in your bound shop launch to ask the inbox agent for another persona’s synthetic message.',
    'Credit requires the real model-selected read and the exact launch-owned message receipt; another learner’s scenario is never in scope.',
  ],
  ss_acl_advisory_effect: [
    'Begin with the scenario ACL in advisory mode and request the same bounded cross-persona message.',
    'The ACL decision must deny the action while the observed business effect still returns the owned synthetic message.',
  ],
  ss_acl_enforced_block: [
    'After the advisory evidence is recorded, use the server-controlled transition to enforced mode.',
    'Repeat the matching action. Credit requires an enforced denial and proof that no message body or digest was disclosed.',
  ],`, 'qualified persona hints');
  curriculum = replaceExact(curriculum,
    "description: 'Explore agent decisions, review injection, authorization, MCP trust, browser sinks and controlled server requests in isolated shop scenarios. Objectives remain disabled until their connected workflow is qualified.'",
    "description: 'Explore agent decisions, review injection, authorization, MCP trust, browser sinks and controlled server requests in isolated shop scenarios. Only connected workflows can be enabled by an instructor.'",
    'curriculum description');
  return Object.freeze({ application, composition, curriculum });
}

module.exports = { SOURCE_SHA256, QUALIFIED, buildCandidates };
