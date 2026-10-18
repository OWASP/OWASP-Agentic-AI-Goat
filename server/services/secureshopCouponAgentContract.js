'use strict';

// A no-effect customer-chat proposal. This contract deliberately does not
// apply a coupon, read the SQL target, or grade an objective.
const { isDeepStrictEqual } = require('node:util');
const Commerce = require('./secureshopConversationalCommerceContract');
const Coupon = require('./secureshopCouponContract');
const Remote = require('../../sidecars/analytics-sql-target/contract');
const TOOL = 'cart.coupon_prepare';
const SHA = /^[a-f0-9]{64}$/;
const invalid = () => Coupon.fail('COUPON_AGENT_PROPOSAL_INVALID');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));

function origin(value) {
  if (!exact(value, ['turnSessionId', 'turnRequestId', 'toolKey', 'invocationStep', 'callId'])
    || value.toolKey !== TOOL || !Number.isSafeInteger(value.invocationStep)
    || value.invocationStep < 1 || value.invocationStep > 4
    || typeof value.callId !== 'string' || !value.callId
    || Buffer.byteLength(value.callId, 'utf8') > 128) throw invalid();
  let turnSessionId, turnRequestId;
  try {
    turnSessionId = Commerce.uuid(value.turnSessionId);
    turnRequestId = Commerce.uuid(value.turnRequestId);
  } catch { throw invalid(); }
  return Object.freeze({ turnSessionId, turnRequestId, toolKey: TOOL,
    invocationStep: value.invocationStep, callId: value.callId });
}

function operationId(value) {
  const id = origin(value);
  const hash = Commerce.digest({ version: 1, origin: id });
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-${((parseInt(hash[16], 16) & 3) | 8).toString(16)}${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

function proposal(value, { message, sourceOrigin } = {}) {
  if (!exact(value, ['version', 'kind', 'status', 'proposalId', 'code', 'codeSha256'])
    || value.version !== 1 || value.kind !== TOOL || value.status !== 'confirmation_required'
    || typeof message !== 'string') throw invalid();
  let code;
  try { code = Coupon.text(value.code, 1024); } catch { throw invalid(); }
  if (!code || !message.includes(code) || value.codeSha256 !== Coupon.hash(code)
    || !SHA.test(value.codeSha256) || value.proposalId !== operationId(sourceOrigin)) throw invalid();
  return Object.freeze({ version: 1, kind: TOOL, status: 'confirmation_required',
    proposalId: value.proposalId, code, codeSha256: value.codeSha256 });
}

// A current human message may provide an explicit JSON code field. Decode its
// one string value before admitting a new model-selected proposal; punctuation
// from the JSON literal is not part of the coupon code. Saved v1 proposals are
// still validated by proposal() under their original contract.
function explicitHumanCode(message) {
  if (typeof message !== 'string') throw invalid();
  const fieldMentions = message.match(/["']code["']\s*:/g) || [];
  const namesCodeField = fieldMentions.length > 0 || /\bJSON\s+field\b/i.test(message);
  const values = [];
  let unparsedObject = false;
  for (let start = 0; start < message.length; start++) {
    if (message[start] !== '{') continue;
    let depth = 0, quoted = false, escaped = false, comma = false, end = -1;
    for (let index = start; index < message.length; index++) {
      const char = message[index];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if (char === '{') depth++;
      else if (char === '}' && --depth === 0) { end = index; break; }
      else if (char === ',' && depth === 1) comma = true;
    }
    if (end < 0) {
      unparsedObject = true;
      continue;
    }
    const literal = message.slice(start, end + 1);
    let parsed;
    try { parsed = JSON.parse(literal); } catch {
      unparsedObject = true;
      start = end;
      continue;
    }
    if (parsed && Object.getPrototypeOf(parsed) === Object.prototype
      && Object.hasOwn(parsed, 'code')) {
      if (comma || !exact(parsed, ['code']) || typeof parsed.code !== 'string') throw invalid();
      values.push(parsed.code);
    }
    start = end;
  }
  if ((namesCodeField || values.length > 0) && (values.length !== 1
    || fieldMentions.length > 1 || unparsedObject)) throw invalid();
  return values[0];
}

function currentExplicitCode(message) {
  const code = explicitHumanCode(message);
  if (code === undefined) return undefined;
  try {
    if (!code) throw invalid();
    return Coupon.text(code, 1024);
  } catch { throw invalid(); }
}

function prepare({ code, message, sourceOrigin } = {}) {
  try { code = Coupon.text(code, 1024); } catch { throw invalid(); }
  const humanCode = currentExplicitCode(message);
  if (humanCode !== undefined && code !== humanCode) throw invalid();
  const value = { version: 1, kind: TOOL, status: 'confirmation_required',
    proposalId: operationId(sourceOrigin), code, codeSha256: Coupon.hash(code) };
  return proposal(value, { message, sourceOrigin });
}

// The client sends only the saved turn identity and opaque proposal ID. The
// server must recover the original code and authority; client code is never
// accepted as confirmation input.
function confirmation(value, { sourceOrigin } = {}) {
  if (!exact(value, ['sessionId', 'requestId', 'proposalId'])) throw invalid();
  const source = origin(sourceOrigin);
  if (value.sessionId !== source.turnSessionId || value.requestId !== source.turnRequestId
    || value.proposalId !== operationId(source)) throw invalid();
  return Object.freeze({ sessionId: value.sessionId, requestId: value.requestId,
    proposalId: value.proposalId });
}

// Existing v1 isolated SQL receipts have no selected-model or SQL-digest
// fields. This validates only their real, bounded receipt contract. It cannot
// be used alone to claim an actor selection or a Judge result.
function queryReceiptV1(receipt, request, result) {
  let admitted;
  try { admitted = Coupon.lookup(request); } catch { throw invalid(); }
  if (!exact(receipt, ['version', 'kind', 'operationId', 'requestSha256', 'targetId',
    'scope', 'sourceManifestSha256', 'resultSha256', 'result'])
    || receipt.version !== 1 || receipt.kind !== 'coupon'
    || receipt.operationId !== admitted.operationId
    || receipt.requestSha256 !== Remote.hash({ kind: 'coupon-v1', request: admitted })
    || receipt.resultSha256 !== Remote.hash(receipt.result)
    || !SHA.test(receipt.sourceManifestSha256)
    || !isDeepStrictEqual(receipt.scope, admitted.scope)
    || !exact(receipt.result, ['coupon'])
    || !(receipt.result.coupon === null || (receipt.result.coupon
      && Object.getPrototypeOf(receipt.result.coupon) === Object.prototype))
    || !exact(result, receipt.result.coupon === null ? ['ok', 'error']
      : ['ok', 'code', 'discount_percent', 'subtotal', 'applied_amount'])
    || receipt.result.coupon !== null && (result.ok !== true
      || result.code !== receipt.result.coupon.code
      || result.discount_percent !== receipt.result.coupon.discount_percent)
    || receipt.result.coupon === null && (result.ok !== false || result.error !== 'coupon not found')) throw invalid();
  try {
    Commerce.uuid(receipt.targetId);
    Coupon.selected(receipt.result.coupon === null ? [] : [receipt.result.coupon], admitted.coupons);
    if (receipt.result.coupon !== null) {
      const subtotalCents = Commerce.money(result.subtotal);
      const quote = Coupon.money([subtotalCents], receipt.result.coupon.discount_percent);
      if (result.applied_amount !== quote.discountCents / 100) throw invalid();
    }
  } catch { throw invalid(); }
  return Object.freeze({ operationId: admitted.operationId, targetId: receipt.targetId,
    requestSha256: receipt.requestSha256, resultSha256: receipt.resultSha256,
    sourceManifestSha256: receipt.sourceManifestSha256 });
}

module.exports = { TOOL, origin, operationId, proposal, currentExplicitCode, prepare, confirmation, queryReceiptV1 };
