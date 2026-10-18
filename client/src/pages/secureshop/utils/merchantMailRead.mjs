import { sameRolePolicyMode } from './rolePolicyProposal.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const bytes = value => encoder.encode(value).byteLength;
const bounded = (value, max, allowEmpty = false) => typeof value === 'string'
  && (allowEmpty || value.length > 0) && bytes(value) <= max;
const positive = value => Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
const fail = () => { throw new Error('Saved merchant mail read invalid'); };

function recipient(value) {
  return exact(value, ['id', 'username', 'email', 'role']) && positive(value.id)
    && bounded(value.username, 256) && bounded(value.email, 512)
    && ['customer', 'merchant', 'admin'].includes(value.role);
}

function mailMode(value) {
  return exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    && value.version === 1 && value.featureId === 'mail'
    && value.policyVersion === 'owned-mail-recipient-header-and-html-v1'
    && ['vuln', 'fixed'].includes(value.effectiveMode)
    && exact(value.scope, ['kind', 'id'])
    && value.scope.kind === 'launch_feature' && value.scope.id === 'mail';
}

function header(value) {
  return exact(value, ['id', 'threadId', 'from', 'to', 'subject', 'createdAt', 'sha256'])
    && positive(value.id) && positive(value.threadId)
    && bounded(value.from, 512) && bounded(value.to, 512)
    && bounded(value.subject, 512)
    && typeof value.createdAt === 'string' && Number.isFinite(Date.parse(value.createdAt))
    && SHA.test(value.sha256);
}

function packet(value) {
  if (!value || value.version !== 1 || !mailMode(value.mailModeCapability)) fail();
  if (value.kind === 'recipients') {
    if (!exact(value, ['version', 'kind', 'recipients', 'hasMore', 'mailModeCapability'])
      || !Array.isArray(value.recipients) || value.recipients.length > 5
      || value.recipients.some(row => !recipient(row))
      || new Set(value.recipients.map(row => row.id)).size !== value.recipients.length
      || typeof value.hasMore !== 'boolean'
      || (value.hasMore && value.recipients.length !== 5)) fail();
    return value;
  }
  const base = ['version', 'kind', 'readOperationId', 'mailModeCapability',
    'receiptSha256', 'recipient'];
  if (typeof value.readOperationId !== 'string' || !UUID.test(value.readOperationId)
    || !SHA.test(value.receiptSha256) || !recipient(value.recipient)) fail();
  if (value.kind === 'list') {
    if (!exact(value, [...base, 'offset', 'total', 'hasMore', 'headers'])
      || !Number.isSafeInteger(value.offset) || value.offset < 0 || value.offset > 1020
      || value.offset % 5 !== 0 || !Number.isSafeInteger(value.total)
      || value.total < 0 || value.total > 1024
      || !Array.isArray(value.headers) || value.headers.length > 5
      || value.headers.some(row => !header(row))
      || new Set(value.headers.map(row => row.id)).size !== value.headers.length
      || typeof value.hasMore !== 'boolean'
      || value.hasMore !== (value.offset + value.headers.length < value.total)) fail();
    return value;
  }
  if (value.kind === 'detail') {
    if (!exact(value, [...base, 'messageId', 'messageSha256', 'status', 'message'])
      || !positive(value.messageId) || !SHA.test(value.messageSha256)
      || !['complete', 'oversized'].includes(value.status)) fail();
    if (value.message === null && value.status === 'oversized') return value;
    const message = value.message;
    if (!message || !exact(message, ['id', 'threadId', 'from', 'to', 'subject',
      'createdAt', 'sha256', 'bodyMarkdown', 'bodyHtml', 'headersRaw', 'sourceBytes', 'oversized'])
      || !header({ id: message.id, threadId: message.threadId, from: message.from,
        to: message.to, subject: message.subject, createdAt: message.createdAt,
        sha256: message.sha256 })
      || message.id !== value.messageId || message.sha256 !== value.messageSha256
      || !Number.isSafeInteger(message.sourceBytes) || message.sourceBytes < 0
      || message.sourceBytes > 100352
      || message.oversized !== (value.status === 'oversized')) fail();
    if (message.oversized) {
      if (message.sourceBytes <= 16384 || message.bodyMarkdown !== null
        || message.bodyHtml !== null || message.headersRaw !== null) fail();
    } else if (!bounded(message.bodyMarkdown, 32768, true)
      || !bounded(message.bodyHtml, 65536, true)
      || !bounded(message.headersRaw, 2048, true)
      || bytes(message.bodyMarkdown) + bytes(message.bodyHtml)
        + bytes(message.headersRaw) !== message.sourceBytes
      || message.sourceBytes > 16384) fail();
    return value;
  }
  fail();
}

export function decodeMerchantMailRead(value, outerMode, stopReason) {
  if (value == null) return null;
  if (stopReason !== 'end_turn'
    || !exact(value, ['version', 'choiceId', 'modeCapability', 'result'])
    || value.version !== 1
    || (value.choiceId !== null && (typeof value.choiceId !== 'string'
      || !UUID.test(value.choiceId) || value.choiceId !== value.choiceId.toLowerCase()))
    || !sameRolePolicyMode(value.modeCapability, outerMode)
    || outerMode?.featureId !== 'merchant_assistant'
    || outerMode.policyVersion !== 'owned-merchant-read-and-confirmation-v1') fail();
  const result = packet(value.result);
  if (result.kind === 'recipients' && value.choiceId !== null) fail();
  if (result.kind === 'detail' && value.choiceId === null) fail();
  return Object.freeze({ ...value, result: Object.freeze(result) });
}
