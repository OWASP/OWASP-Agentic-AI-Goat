import { shopStorage, flushShopStorage, SHOP_PROMPT_POLICY_KEY } from '../../utils/shopStorage.mjs';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const VERSION = /^[1-9]\d{0,18}$/;
const ROLE_TARGETS = Object.freeze(['customer', 'merchant', 'admin']);
const V2_COMMON = ['version', 'kind', 'operationId', 'requestSha256', 'executionSha256', 'rendered', 'renderedSha256'];
const V2_ISOLATED = [...V2_COMMON, 'isolation', 'exitCode', 'timedOut', 'truncated', 'drained', 'effectWitness'];
const WITNESS = ['version', 'workerAttested', 'commandEffectObserved', 'effectSha256', 'compilerSha256', 'workerSha256'];
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const TASK_RECIPIENTS = Object.freeze({ summarizer: 'customer', 'review-moderator': 'merchant', listing: 'merchant' });
const wellFormed = text => typeof text === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text);
export const isPolicyVersion = value => typeof value === 'string' && VERSION.test(value) && BigInt(value) <= 9223372036854775807n;
export const isPolicyName = value => wellFormed(value) && !!value && new TextEncoder().encode(value).length <= 80 && !/[\u0000-\u001f\u007f/\\]/u.test(value);

export async function policyDigest(text) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
export async function policyRequestDigest({ operationId, name, markdown, injected_into }) {
  if (typeof operationId !== 'string' || !UUID.test(operationId)) throw new Error('Invalid policy operation identity');
  if (!isPolicyName(name)) throw new Error('Policy name must be valid text of at most 80 bytes');
  if (!wellFormed(markdown) || markdown.includes('\0') || new TextEncoder().encode(markdown).length > 16384) throw new Error('Policy source must be valid text of at most 16 KiB');
  if (!Array.isArray(injected_into) || !injected_into.length || new Set(injected_into).size !== injected_into.length
    || injected_into.some(role => !ROLE_TARGETS.includes(role))) throw new Error('Select at least one supported supervisor');
  for (let index = 0; index < injected_into.length; index += 1) if (!Object.hasOwn(injected_into, index)) throw new Error('Select valid supported supervisors');
  return policyDigest(JSON.stringify({ version: 1, operationId, name, markdown, targets: [...injected_into].sort() }));
}
export async function policyMutationDigests(input, supportedTaskTargets = []) {
  if (!Array.isArray(supportedTaskTargets) || new Set(supportedTaskTargets).size !== supportedTaskTargets.length
      || supportedTaskTargets.some(target => !Object.hasOwn(TASK_RECIPIENTS, target))) {
    throw new Error('Supported task policy targets are invalid');
  }
  const targets = input?.injected_into;
  const allowed = new Set([...ROLE_TARGETS, ...supportedTaskTargets]);
  if (!Array.isArray(targets) || !targets.length || new Set(targets).size !== targets.length
      || targets.some(target => !allowed.has(target))) throw new Error('Select at least one supported policy target');
  for (let index = 0; index < targets.length; index += 1) if (!Object.hasOwn(targets, index)) throw new Error('Select valid supported policy targets');
  const hasTaskTarget = targets.some(target => Object.hasOwn(TASK_RECIPIENTS, target));
  const rendererTargets = [...new Set(targets.map(target => TASK_RECIPIENTS[target] || target))];
  const requestSha256 = await policyRequestDigest({ ...input, injected_into: rendererTargets });
  if (!hasTaskTarget) return { requestSha256 };
  const normalized = {
    contractVersion: 2,
    operationId: input.operationId,
    name: input.name,
    markdown: input.markdown,
    targets: [...targets].sort(),
  };
  return {
    requestSha256,
    policyRequestSha256: await policyDigest(JSON.stringify({ version: 2, request: normalized })),
  };
}
function validate(value) {
  const keys = Object.keys(value || {}).sort().join(',');
  if (!value || ![
    'action,expectedVersion,name,operationId,requestSha256,scopeKey',
    'action,expectedVersion,name,operationId,outcome,requestSha256,scopeKey',
    'action,expectedVersion,name,operationId,policyRequestSha256,requestSha256,scopeKey',
    'action,expectedVersion,name,operationId,outcome,policyRequestSha256,requestSha256,scopeKey',
  ].includes(keys)
    || (Object.hasOwn(value, 'outcome') && value.outcome !== 'revision_conflict')
    || typeof value.scopeKey !== 'string' || !HASH.test(value.scopeKey)
    || typeof value.operationId !== 'string' || !UUID.test(value.operationId) || !isPolicyVersion(value.expectedVersion)
    || !['save', 'create', 'preview', 'delete'].includes(value.action)
    || !isPolicyName(value.name)
    || (value.action === 'delete' ? value.requestSha256 !== null || Object.hasOwn(value, 'policyRequestSha256') : !HASH.test(value.requestSha256))
    || (Object.hasOwn(value, 'policyRequestSha256') && !HASH.test(value.policyRequestSha256))) {
    throw new Error('Saved policy operation is invalid');
  }
  return value;
}
function readAllPolicyStates() {
  const raw = shopStorage.getItem(SHOP_PROMPT_POLICY_KEY);
  if (!raw) return [];
  if (new TextEncoder().encode(raw).length > 8192) throw new Error('Saved policy operation is invalid');
  const value = JSON.parse(raw);
  if (value?.version === undefined) {
    const pending = validate(value);
    return [{ scopeKey: pending.scopeKey, pending, history: [] }];
  }
  const rows = value.version === 2 ? value.scopes : [value];
  if (value.version === 2 && (Object.keys(value).sort().join(',') !== 'scopes,version' || !Array.isArray(rows))) throw new Error('Saved policy history is invalid');
  for (const row of rows) {
    const keys = Object.keys(row).sort().join(',');
    if ((value.version === 2 ? keys !== 'history,pending,scopeKey' : keys !== 'history,pending,scopeKey,version' || row.version !== 1)
      || typeof row.scopeKey !== 'string' || !HASH.test(row.scopeKey) || (row.pending !== null && typeof row.pending !== 'object') || !Array.isArray(row.history) || row.history.length > 8) throw new Error('Saved policy history is invalid');
    const entries = [...row.history, ...(row.pending ? [row.pending] : [])].map(validate);
    if (entries.some(entry => entry.scopeKey !== row.scopeKey) || new Set(entries.map(entry => entry.operationId)).size !== entries.length) throw new Error('Saved policy history is invalid');
  }
  if (new Set(rows.map(row => row.scopeKey)).size !== rows.length) throw new Error('Saved policy history is invalid');
  return rows.map(({ scopeKey, pending, history }) => ({ scopeKey, pending, history }));
}
export function readPolicyState(scopeKey) {
  const row = readAllPolicyStates().find(row => row.scopeKey === scopeKey);
  return row ? { pending: row.pending, history: row.history } : { pending: null, history: [] };
}
export function readSavedPolicyPending() {
  return readAllPolicyStates().flatMap(row => row.pending ? [{ ...row.pending }] : []);
}
export const readPolicyPending = scopeKey => readPolicyState(scopeKey).pending;
const sameOperation = (left, right) => left && right
  && Object.keys(left).sort().join(',') === Object.keys(right).sort().join(',')
  && Object.keys(right).every(key => left[key] === right[key]);
export function assertPolicyPendingCurrent(operation) {
  validate(operation);
  if (!sameOperation(readPolicyPending(operation.scopeKey), operation)) {
    throw new Error('Saved policy operation changed');
  }
  return true;
}
async function store(scopeKey, state) {
  const scopes = readAllPolicyStates().filter(row => row.scopeKey !== scopeKey);
  if (state.pending || state.history.length) scopes.push({ scopeKey, ...state });
  if (!scopes.length) {
    shopStorage.removeItem(SHOP_PROMPT_POLICY_KEY);
  } else {
    const value = JSON.stringify({ version: 2, scopes });
    if (new TextEncoder().encode(value).length > 8192) throw new Error('Saved policy history exceeds limit');
    shopStorage.setItem(SHOP_PROMPT_POLICY_KEY, value);
  }
  await flushShopStorage();
}
export async function savePolicyPending(value) {
  validate(value);
  const state = readPolicyState(value.scopeKey);
  if (state.pending && state.pending.operationId !== value.operationId) throw new Error('Another policy operation awaits verification');
  await store(value.scopeKey, { ...state, pending: value });
}

export async function markPolicyRevisionConflict(operation) {
  validate(operation);
  const state = readPolicyState(operation.scopeKey);
  const keys = Object.keys(operation).sort();
  if (!state.pending || Object.keys(state.pending).sort().join(',') !== keys.join(',')
      || keys.some(key => state.pending[key] !== operation[key])) throw new Error('Saved policy operation changed');
  const pending = { ...state.pending, outcome: 'revision_conflict' };
  await store(operation.scopeKey, { ...state, pending });
  return pending;
}
export async function clearPolicyPending(operation) {
  const state = readPolicyState(operation.scopeKey);
  const isPending = sameOperation(state.pending, operation)
    || (state.pending?.outcome === 'revision_conflict'
      && sameOperation(state.pending, { ...operation, outcome: 'revision_conflict' }));
  const isHistorical = state.history.some(row => sameOperation(row, operation));
  if (!isPending && !isHistorical) throw new Error('Saved policy operation changed');
  const next = { pending: isPending ? null : state.pending,
    history: state.history.filter(row => !sameOperation(row, operation)) };
  await store(operation.scopeKey, next);
}
export async function acknowledgePolicyPending(operation) {
  const state = readPolicyState(operation.scopeKey);
  if (state.pending?.outcome === 'revision_conflict') throw new Error('Known conflict must not enter unknown history');
  if (!sameOperation(state.pending, operation)) throw new Error('Saved policy operation changed');
  if (state.history.length >= 8) throw new Error('Eight unknown operations are retained. Verify an earlier operation before dismissing another.');
  await store(operation.scopeKey, { pending: null, history: [...state.history, state.pending] });
}
export async function assertPolicyReceipt(receipt, operation) {
  validate(operation);
  const next = operation.action === 'preview' ? operation.expectedVersion : String(BigInt(operation.expectedVersion) + 1n);
  const expectsPolicyDigest = Object.hasOwn(operation, 'policyRequestSha256');
  const outerKeys = ['version', 'operationId', 'requestSha256', operation.action === 'delete' ? 'deleted' : 'renderResult',
    ...(expectsPolicyDigest ? ['policyRequestSha256'] : []),
    ...(Object.hasOwn(receipt || {}, 'replayed') ? ['replayed'] : [])];
  if (!exactKeys(receipt, outerKeys) || (Object.hasOwn(receipt, 'replayed') && receipt.replayed !== true)
      || receipt.operationId !== operation.operationId || receipt.version !== next || !HASH.test(receipt.requestSha256)
      || Object.hasOwn(receipt, 'policyRequestSha256') !== expectsPolicyDigest
      || (expectsPolicyDigest && receipt.policyRequestSha256 !== operation.policyRequestSha256)) throw new Error('Policy receipt could not be verified');
  if (operation.action === 'delete') {
    if (receipt.deleted !== true) throw new Error('Policy deletion could not be verified');
    return receipt;
  }
  const render = receipt.renderResult;
  if (receipt.requestSha256 !== operation.requestSha256 || !render
    || render.operationId !== operation.operationId || render.requestSha256 !== operation.requestSha256
    || !wellFormed(render.rendered) || render.rendered.includes('\0')
    || new TextEncoder().encode(render.rendered).length > 65536 || !HASH.test(render.renderedSha256)
    || await policyDigest(render.rendered) !== render.renderedSha256) throw new Error('Policy render receipt could not be verified');
  if (render.version === 1) {
    if (!exactKeys(render, ['version', 'operationId', 'requestSha256', 'isolation', 'rendered', 'renderedSha256',
      'exitCode', 'timedOut', 'truncated', 'drained']) || render.isolation !== 'bwrap-policy-template-v1'
      || render.exitCode !== 0 || render.timedOut !== false || render.truncated !== false || render.drained !== true)
      throw new Error('Policy render receipt could not be verified');
  } else if (render.version === 2) {
    const isolated = render.kind === 'isolated_template';
    if (!['literal', 'isolated_template'].includes(render.kind)
      || !exactKeys(render, isolated ? V2_ISOLATED : V2_COMMON) || !HASH.test(render.executionSha256))
      throw new Error('Policy render receipt could not be verified');
    if (isolated) {
      const witness = render.effectWitness;
      if (render.isolation !== 'bwrap-policy-template-v1' || render.exitCode !== 0 || render.timedOut !== false
        || render.truncated !== false || render.drained !== true || !exactKeys(witness, WITNESS)
        || witness.version !== 1 || witness.workerAttested !== true
        || typeof witness.commandEffectObserved !== 'boolean'
        || (witness.commandEffectObserved ? !HASH.test(witness.effectSha256) : witness.effectSha256 !== null)
        || !HASH.test(witness.compilerSha256) || !HASH.test(witness.workerSha256))
        throw new Error('Policy render receipt could not be verified');
    }
  } else throw new Error('Policy render receipt could not be verified');
  return receipt;
}

// These references belong only to the current launch's scoped shop storage.
// A foreign scope is an older/different persona session, not another launch.
export function readForgettablePolicyReferences(currentScopeKey) {
  if (!HASH.test(currentScopeKey)) throw new Error('Current policy scope is invalid');
  return readAllPolicyStates().flatMap(row => [
    ...row.history.map(operation => ({ kind: 'history', operation: { ...operation } })),
    ...(row.pending && row.scopeKey !== currentScopeKey
      ? [{ kind: 'pending', operation: { ...row.pending } }] : []),
  ]);
}
export async function forgetPolicyReference(reference, currentScopeKey) {
  if (!HASH.test(currentScopeKey) || !reference || !['history', 'pending'].includes(reference.kind)) throw new Error('Policy reference is invalid');
  const operation = validate(reference.operation);
  if (reference.kind === 'pending' && operation.scopeKey === currentScopeKey) throw new Error('Dismiss the current pending operation first');
  const state = readPolicyState(operation.scopeKey);
  const stored = reference.kind === 'pending' ? state.pending : state.history.find(row => row.operationId === operation.operationId);
  const keys = Object.keys(operation).sort();
  if (!stored || Object.keys(stored).sort().join(',') !== keys.join(',') || keys.some(key => stored[key] !== operation[key])) throw new Error('Saved policy reference changed');
  await store(operation.scopeKey, reference.kind === 'pending'
    ? { ...state, pending: null }
    : { ...state, history: state.history.filter(row => row.operationId !== operation.operationId) });
}
