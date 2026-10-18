'use strict';

const { createHash } = require('node:crypto');
const { validateTaskPolicySnapshot } = require('./secureshopPromptPolicyTaskSnapshot');

const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
const invalid = () => { throw Object.assign(new Error('Policy retrieval snapshot unavailable'), { code: 'POLICY_RETRIEVAL_SNAPSHOT_INVALID' }); };

// This is a pure projection. Authority, cross-store copying and publication are
// deliberately owned by the composition/repository that calls it.
function buildPolicyRetrievalSnapshot(raw) {
  const snapshot = validateTaskPolicySnapshot(structuredClone(raw));
  if (snapshot.role !== 'customer' || snapshot.recipient !== 'summarizer') invalid();
  const documents = snapshot.policies.map((policy, index) => {
    const identity = Object.freeze({ version: 1, policyVersion: snapshot.policyVersion,
      policySnapshotSha256: snapshot.sha256, name: policy.name, renderedSha256: policy.renderedSha256 });
    return Object.freeze({ sourceKind: 'policy', sourceId: index + 1, chunkIndex: 0,
      name: policy.name, targets: policy.targets, text: policy.rendered,
      sourceSha256: sha256(JSON.stringify(identity)) });
  });
  const content = Object.freeze({ version: 1, policyVersion: snapshot.policyVersion,
    policySnapshotSha256: snapshot.sha256, role: 'customer', recipient: 'summarizer',
    documents: Object.freeze(documents) });
  return Object.freeze({ ...content, sha256: sha256(JSON.stringify(content)) });
}

function validatePolicyRetrievalSnapshot(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || JSON.stringify(Object.keys(raw).sort()) !== JSON.stringify(['documents','policySnapshotSha256','policyVersion','recipient','role','sha256','version'].sort())) invalid();
  const policies = raw.documents?.map(document => ({ name: document.name, rendered: document.text,
    renderedSha256: sha256(document.text), targets: document.targets }));
  if (!Array.isArray(policies)) invalid();
  const rebuiltTask = { version: 2, policyContractVersion: 2, policyVersion: raw.policyVersion, role: raw.role,
    recipient: raw.recipient, policies, text: policies.map(row => `[Policy ${JSON.stringify(row.name)}]\n${row.rendered}\n[/Policy]`).join('\n\n') };
  rebuiltTask.sha256 = sha256(JSON.stringify(rebuiltTask));
  if (rebuiltTask.sha256 !== raw.policySnapshotSha256) invalid();
  const rebuilt = buildPolicyRetrievalSnapshot(rebuiltTask);
  if (JSON.stringify(raw) !== JSON.stringify(rebuilt)) invalid();
  return rebuilt;
}

module.exports = { buildPolicyRetrievalSnapshot, validatePolicyRetrievalSnapshot };
