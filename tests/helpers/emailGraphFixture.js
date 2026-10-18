'use strict';
// Controlled test seam only. These records do not establish native storage,
// delivery, model provenance, or mounted objective completion.
const { createHash } = require('node:crypto');
const artifactId = '33333333-3333-4333-8333-333333333333';
const ownerKey = JSON.stringify(['IndirectEmail', 'fixture']);
const digest = value => createHash('sha256').update(value).digest('hex');
const artifact = body => ({ artifactId, ingestionKind: 'manual_entry', modelBody: body,
  bodySha256: digest(body), modelBodySha256: digest(body), modelBodyTruncated: false });
const receipt = node => ({ version: 1, status: 'completed', runId: artifactId,
  ownerKey, generation: '2', effectKey: `${artifactId}:${node}` });
const execution = overrides => ({ runId: artifactId, ownerKey, durableGeneration: '2',
  check: async () => {}, effectWithReceipt: async (node, operation) => ({
    value: await operation(), receipt: receipt(node),
  }), ...overrides });
const observation = (profile, body) => ({ id: `${profile}_observation`, source: 'server_observation',
  content: { profile, ...artifact(body), receipt: receipt(`email_read_${profile}_${artifactId}`) } });
module.exports = { artifactId, artifact, execution, observation };
