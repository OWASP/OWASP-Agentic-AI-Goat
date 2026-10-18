'use strict';

const { createHash } = require('node:crypto');
const { normalizeRenderRequest, normalizePolicyTargets } = require('./secureshopPromptPolicyContract');
const { RECIPIENTS } = require('./secureshopPromptPolicyTaskSnapshot');
const VERSION = 2;
const KEYS = Object.freeze(['contractVersion', 'operationId', 'name', 'markdown', 'targets']);
const TASK_TARGETS = Object.freeze([...new Set(['customer', 'merchant', 'admin', ...Object.keys(RECIPIENTS)])].sort());
const invalid = message => { throw new TypeError(`Invalid task policy mutation${message ? `: ${message}` : ''}`); };
function exact(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('object required');
  const actual = Object.keys(value).sort(), wanted = [...KEYS].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid('unexpected fields');
}
function normalizeTaskMutationRequest(raw) {
  exact(raw);
  if (raw.contractVersion !== VERSION) invalid('contract version');
  if (!Array.isArray(raw.targets) || raw.targets.length === 0 || raw.targets.some(target => typeof target !== 'string' || !TASK_TARGETS.includes(target))) invalid('targets');
  if (new Set(raw.targets).size !== raw.targets.length) invalid('duplicate targets');
  const targets = Object.freeze([...raw.targets].sort());
  const rendererTargets = [...new Set(targets.flatMap(target => RECIPIENTS[target] || target))];
  const render = normalizeRenderRequest({ operationId: raw.operationId, name: raw.name, markdown: raw.markdown, targets: normalizePolicyTargets(rendererTargets) });
  return Object.freeze({ contractVersion: VERSION, ...render, targets });
}
function renderRequest(raw) {
  const request = normalizeTaskMutationRequest(raw);
  return Object.freeze({ operationId: request.operationId, name: request.name, markdown: request.markdown,
    targets: normalizePolicyTargets([...new Set(request.targets.flatMap(target => RECIPIENTS[target] || target))]) });
}
function taskMutationDigest(raw) {
  const request = normalizeTaskMutationRequest(raw);
  return createHash('sha256').update(JSON.stringify({ version: VERSION, request }), 'utf8').digest('hex');
}
module.exports = { VERSION, KEYS, normalizeTaskMutationRequest, renderRequest, taskMutationDigest };
