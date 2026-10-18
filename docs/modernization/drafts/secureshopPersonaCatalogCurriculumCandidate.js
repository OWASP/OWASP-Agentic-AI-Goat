'use strict';

const crypto = require('node:crypto');

const SOURCE_SHA256 = 'dc734657b79719631ce10250de35014052e9e20749050e82b43d10cadc96f96c';
const BEFORE = `action: objective.id === 'ss_loop_observation'
      ? 'Ask the moderator to process the current pending product reviews.'
      : 'Use the Product review form, then start a later moderator turn for the same bound launch.',
    explanation: 'Use the owner-bound application flow. The server grades persisted provenance, real model observations, and completed effects.',`;
const AFTER = `action: objective.id === 'ss_loop_observation'
      ? 'Ask the moderator to process the current pending product reviews.'
      : ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
        ? 'Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.'
        : 'Use the Product review form, then start a later moderator turn for the same bound launch.',
    explanation: ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
      ? 'The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure.'
      : 'Use the owner-bound application flow. The server grades persisted provenance, real model observations, and completed effects.',`;

function buildCandidate(source) {
  if (typeof source !== 'string'
      || crypto.createHash('sha256').update(source).digest('hex') !== SOURCE_SHA256) {
    throw new Error('activated SecureShop curriculum candidate is not the reviewed frozen version');
  }
  if (source.split(BEFORE).length !== 2) throw new Error('SecureShop solution example seam changed');
  return source.replace(BEFORE, AFTER);
}

module.exports = { SOURCE_SHA256, buildCandidate };
