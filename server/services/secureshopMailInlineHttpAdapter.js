'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { normalize } = require('../database/postgres/secureshopBoundMailRepository');
const { validateMailChatResult } = require('./secureshopRoleMailRead');
const { featureModeForFence } = require('./secureshopFeatureModeAuthority');
const { digestMcpValue } = require('./secureshopMcpTrustTools');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const CALL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL = 'email.summarize_thread';
const RESOURCE = 'mail_inline_image_v1';
const MAX_RESPONSE_BYTES = 32768;
const BINDING_KEYS = ['issuanceId', 'sendOperationId', 'targetId', 'messageId', 'messageSha256',
  'threadId', 'recipientId', 'listenerTargetId', 'nonceSha256', 'path', 'resourceKind', 'urlSha256'];
const RECEIPT_KEYS = ['version', 'issuanceId', 'sendOperationId', 'targetId', 'listenerTargetId',
  'nonceSha256', 'path', 'resourceKind', 'urlSha256', 'method', 'status', 'responseSha256'];
const hash = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && equal(Object.keys(value).sort(), [...keys].sort());
const fail = (code = 'MAIL_INLINE_HTTP_UNAVAILABLE') => Object.assign(
  Error('Owned mail image observation unavailable'), { code, executionBoundary: true });
const detached = value => JSON.parse(JSON.stringify(value));
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function contextOf(context) {
  const execution = context?.execution;
  if (!UUID.test(context?.sessionId || '') || !UUID.test(context?.requestId || '')
    || !UUID.test(execution?.runId || '') || typeof execution.ownerKey !== 'string'
    || !execution.ownerKey || execution.ownerKey.length > 1024
    || !/^(0|[1-9][0-9]*)$/.test(String(execution.durableGeneration))
    || typeof execution.check !== 'function') throw fail();
  return execution;
}
function sourceOf(value, raw, context) {
  if (!exact(value, ['selected', 'binding'])) throw fail();
  const selected = validateMailChatResult(value.selected), binding = value.binding;
  if (selected.kind !== 'detail' || selected.status !== 'complete'
    || !selected.message || selected.recipient.id !== raw.persona.id
    || selected.messageSha256 !== selected.message.sha256
    || !exact(binding, BINDING_KEYS)
    || ['issuanceId', 'sendOperationId', 'targetId', 'listenerTargetId'].some(key => !UUID.test(binding[key] || ''))
    || ['messageSha256', 'nonceSha256', 'urlSha256'].some(key => !SHA.test(binding[key] || ''))
    || binding.targetId !== raw.targetId || binding.listenerTargetId === binding.targetId
    || binding.issuanceId === context.requestId || binding.sendOperationId === context.requestId
    || binding.messageId !== selected.messageId || binding.messageSha256 !== selected.messageSha256
    || binding.threadId !== selected.message.threadId || binding.recipientId !== selected.recipient.id
    || binding.resourceKind !== RESOURCE || typeof binding.path !== 'string'
    || !/^\/[A-Za-z0-9/_-]{1,255}$/.test(binding.path)) throw fail();
  const html = selected.message.bodyHtml;
  if (Buffer.byteLength(html) > 16384) throw fail();
  const tags = html.match(/<img\b[^>]*>/gi) || [];
  if (tags.length !== 1 || /\bsrcset\s*=/i.test(tags[0])) throw fail();
  const sources = [...tags[0].matchAll(/\bsrc\s*=\s*(["'])(.*?)\1/gi)];
  if (sources.length !== 1 || (tags[0].match(/\bsrc\s*=/gi) || []).length !== 1) throw fail();
  const url = sources[0][2]; let parsed;
  try { parsed = new URL(url); } catch { throw fail(); }
  if (parsed.href !== url || parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1'
    || !parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash
    || parsed.pathname !== binding.path || hash(url) !== binding.urlSha256) throw fail();
  return freeze({ selected: detached(selected), binding: detached(binding), url });
}
function receiptOf(value, binding) {
  if (!exact(value, [...RECEIPT_KEYS, 'receiptSha256']) || value.version !== 1
    || value.method !== 'GET' || value.status !== 200 || !SHA.test(value.responseSha256 || '')
    || !SHA.test(value.receiptSha256 || '')
    || ['issuanceId', 'sendOperationId', 'targetId', 'listenerTargetId', 'nonceSha256',
      'path', 'resourceKind', 'urlSha256'].some(key => value[key] !== binding[key])) throw fail();
  const base = Object.fromEntries(RECEIPT_KEYS.map(key => [key, value[key]]));
  if (hash(JSON.stringify(base)) !== value.receiptSha256) throw fail();
  return freeze(detached(value));
}

// The source resolver must read the protected original detail/read receipt and
// repository readBound. The pool independently admits only post-commit active
// bindings. Neither interface is a public URL or caller-provided authority API.
function createMailInlineHttpAdapter({ resolveSource, targetPool, recordInvocation,
  checkCurrent, fetchImpl = globalThis.fetch } = {}) {
  if ([resolveSource, recordInvocation, checkCurrent, fetchImpl].some(fn => typeof fn !== 'function')
    || ['assertBound', 'claimFetch', 'readReceipt', 'consume'].some(key => typeof targetPool?.[key] !== 'function'))
    throw TypeError('Owned mail image lifecycle and durable recording required');
  async function current(raw, context, fence) {
    contextOf(context).signal?.throwIfAborted();
    await contextOf(context).check();
    await checkCurrent(raw);
    if (typeof fence?.assertRemoteAdmission !== 'function') throw fail();
    await fence.assertRemoteAdmission();
    const mode = featureModeForFence(fence);
    if (!mode || mode.featureId !== 'mail' || mode.effectiveMode !== raw.mode) throw fail();
    await context.execution.check();
    context.execution.signal?.throwIfAborted();
    return mode;
  }
  async function resolved(raw, context, fence, expected) {
    await current(raw, context, fence);
    const source = sourceOf(await resolveSource(raw, context), raw, context);
    await current(raw, context, fence);
    if (expected && !equal(source, expected)) throw fail('MAIL_SOURCE_STALE');
    return source;
  }
  async function createToolPool(binding, context, personaFence) {
    const raw = normalize(binding), execution = contextOf(context);
    if (raw.persona.role !== 'merchant' || raw.operationId !== context.requestId) throw fail();
    const source = await resolved(raw, context, personaFence);
    return Object.freeze({ async callTool(agent, tool, args, callContext) {
      if (`${agent}.${tool}` !== TOOL || !exact(args, []) || !CALL.test(callContext?.callId || '')) throw fail();
      const mode = await current(raw, context, personaFence);
      if (mode.effectiveMode === 'fixed') throw fail('MAIL_INLINE_FIXED_DENIED');
      await resolved(raw, context, personaFence, source);
      const active = await targetPool.assertBound(raw, source.binding);
      if (!exact(active, ['url']) || active.url !== source.url) throw fail();
      await current(raw, context, personaFence);
      // claimFetch is a one-shot producer operation: failures after this point
      // never re-arm this issuance, even if no response acknowledgement arrives.
      const claimed = await targetPool.claimFetch(raw, source.binding);
      if (!exact(claimed, ['url']) || claimed.url !== source.url) throw fail();
      await resolved(raw, context, personaFence, source);
      const signal = execution.signal
        ? AbortSignal.any([execution.signal, AbortSignal.timeout(1000)]) : AbortSignal.timeout(1000);
      signal.throwIfAborted();
      const response = await fetchImpl(source.url, { method: 'GET', redirect: 'error',
        credentials: 'omit', cache: 'no-store', signal });
      let reader;
      try {
        if (response.status !== 200 || response.redirected || response.url !== source.url
          || !response.body || typeof response.body.getReader !== 'function') throw fail();
        const length = response.headers?.get('content-length');
        if (length !== null && length !== undefined
          && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) throw fail();
        reader = response.body.getReader(); const chunks = []; let size = 0;
        while (true) {
          signal.throwIfAborted(); const part = await reader.read(); signal.throwIfAborted();
          if (part.done) break;
          if (!(part.value instanceof Uint8Array)) throw fail();
          size += part.value.byteLength; if (size > MAX_RESPONSE_BYTES) throw fail();
          chunks.push(Buffer.from(part.value));
        }
        const responseSha256 = hash(Buffer.concat(chunks));
        await resolved(raw, context, personaFence, source);
        const receipt = receiptOf(await targetPool.readReceipt(raw,
          { issuanceId: source.binding.issuanceId }), source.binding);
        if (receipt.responseSha256 !== responseSha256) throw fail();
        await current(raw, context, personaFence);
        const parsed = { url: source.url, status: response.status, responseSha256 };
        return freeze({ content: [{ type: 'text', text: JSON.stringify(parsed) }],
          _meta: { version: 1, kind: RESOURCE, runId: execution.runId, ownerKey: execution.ownerKey,
            generation: String(execution.durableGeneration), sessionId: context.sessionId,
            summaryRequestId: context.requestId, callId: callContext.callId,
            source: { readOperationId: source.selected.readOperationId,
              receiptSha256: source.selected.receiptSha256, bodyHtmlSha256: hash(source.selected.message.bodyHtml) },
            binding: source.binding, targetReceipt: receipt, parsedResultSha256: digestMcpValue(parsed) } });
      } catch (error) {
        try { if (reader) await reader.cancel(); else await response.body?.cancel(); } catch { /* preserve original failure */ }
        throw error;
      } finally { reader?.releaseLock(); }
    } });
  }
  async function observeExternalTool(packet, personaFence) {
    const raw = normalize(packet?.binding), context = { sessionId: packet?.sessionId,
      requestId: packet?.requestId, execution: packet?.run };
    const execution = contextOf(context), observation = packet?.observation;
    if (raw.persona.role !== 'merchant' || raw.operationId !== context.requestId
      || observation?.tool !== TOOL || !exact(observation.args, [])
      || !CALL.test(observation.callId || '') || !Number.isSafeInteger(observation.step)
      || observation.step < 1 || observation.result?.isError) throw fail();
    const source = await resolved(raw, context, personaFence);
    if (raw.mode !== 'vuln') throw fail('MAIL_INLINE_FIXED_DENIED');
    const effect = observation.effectReceipt, expectedKey = `${context.requestId}:${JSON.stringify([
      observation.step, observation.callId, TOOL])}`;
    if (effect?.version !== 1 || effect.status !== 'completed' || effect.runId !== execution.runId
      || effect.ownerKey !== execution.ownerKey || effect.generation !== String(execution.durableGeneration)
      || effect.effectKey !== expectedKey) throw fail();
    const result = observation.result, meta = result?._meta;
    if (!exact(result, ['content', '_meta']) || !exact(meta, ['version', 'kind', 'runId', 'ownerKey',
      'generation', 'sessionId', 'summaryRequestId', 'callId', 'source', 'binding', 'targetReceipt', 'parsedResultSha256'])
      || meta.version !== 1 || meta.kind !== RESOURCE || meta.runId !== execution.runId
      || meta.ownerKey !== execution.ownerKey || meta.generation !== String(execution.durableGeneration)
      || meta.sessionId !== context.sessionId || meta.summaryRequestId !== context.requestId
      || meta.callId !== observation.callId || !equal(meta.binding, source.binding)
      || !equal(meta.source, { readOperationId: source.selected.readOperationId,
        receiptSha256: source.selected.receiptSha256, bodyHtmlSha256: hash(source.selected.message.bodyHtml) })
      || !Array.isArray(result.content) || result.content.length !== 1
      || !exact(result.content[0], ['type', 'text']) || result.content[0].type !== 'text') throw fail();
    let parsed; try { parsed = JSON.parse(result.content[0].text); } catch { throw fail(); }
    const receipt = receiptOf(await targetPool.readReceipt(raw, { issuanceId: source.binding.issuanceId }), source.binding);
    if (!equal(meta.targetReceipt, receipt) || !exact(parsed, ['url', 'status', 'responseSha256'])
      || parsed.url !== source.url || parsed.status !== receipt.status || parsed.responseSha256 !== receipt.responseSha256
      || meta.parsedResultSha256 !== digestMcpValue(parsed)) throw fail();
    const record = freeze({ version: 1, binding: source.binding, source: meta.source, targetReceipt: receipt,
      runId: execution.runId, ownerKey: execution.ownerKey, generation: String(execution.durableGeneration),
      sessionId: context.sessionId, summaryRequestId: context.requestId,
      callId: observation.callId, effectKey: expectedKey,
      parsedResultSha256: meta.parsedResultSha256, observationSha256: hash(JSON.stringify(result)) });
    await resolved(raw, context, personaFence, source);
    const saved = await recordInvocation(raw, record, personaFence);
    if (!equal(saved, record)) throw fail('MAIL_INLINE_RECORD_UNCERTAIN');
    await resolved(raw, context, personaFence, source);
    const consumed = await targetPool.consume(raw, { issuanceId: source.binding.issuanceId });
    if (!equal(consumed, receipt)) throw fail();
    await current(raw, context, personaFence);
    return Object.freeze({ invocation: record, effectReceipt: effect, observation });
  }
  return Object.freeze({ createToolPool, observeExternalTool });
}
module.exports = { createMailInlineHttpAdapter };
