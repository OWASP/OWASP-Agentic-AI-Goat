'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { prepareSend } = require('../database/postgres/secureshopBoundMailRepository');
const { validateMailChatResult } = require('./secureshopRoleMailRead');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = (code = 'MAIL_INLINE_UNAVAILABLE') => Object.assign(Error('Mail inline workflow unavailable'), { code });
function input(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || !equal(Object.keys(value).sort(), [...keys].sort()) || !UUID.test(value.requestId || '')) throw fail('INVALID_ARGUMENT');
  return value;
}
function selectedInput(value) {
  input(value, ['requestId', 'readOperationId', 'messageId']);
  if (!UUID.test(value.readOperationId || '') || value.requestId === value.readOperationId
    || !Number.isSafeInteger(value.messageId) || value.messageId < 1) throw fail('INVALID_ARGUMENT');
  return value;
}
const unconfirmed = requestId => ({ ok: true, status: 'unconfirmed', requestId });
function savedSend(value, requestId, binding) {
  if (!value || value.found !== true || value.action !== 'send' || value.operationId !== requestId
    || !Number.isSafeInteger(value.receipt?.email_id) || value.receipt.email_id < 1
    || !Number.isSafeInteger(value.receipt?.thread_id) || value.receipt.thread_id < 1
    || value.receipt.recipientId !== binding.persona.id) throw fail();
  return value.receipt;
}
function projectSummary(saved, requestId, replayed) {
  if (!saved || !UUID.test(saved.sessionId || '') || saved.stopReason !== 'end_turn'
    || typeof saved.text !== 'string' || !saved.text.trim() || Buffer.byteLength(saved.text) > 32768
    || saved.taskMetadata?.mailSummary?.requestId !== requestId) throw fail();
  return { ok: true, status: 'completed', requestId, sessionId: saved.sessionId,
    text: saved.text, replayed, assessmentStatus: 'pending' };
}

// Admission and source resolution are private production dependencies. Public
// request IDs select retained state; no body field supplies an authority or URL.
function createMailInlineApplication({ admit, mailRepository, bindingRepository, targetPool,
  listPersonas, resolveSelected, graph } = {}) {
  if ([admit, listPersonas, resolveSelected, mailRepository?.recover,
    bindingRepository?.saveTeachingMessage, bindingRepository?.readBound,
    targetPool?.reserve, targetPool?.activate, targetPool?.cancelPending, graph?.run, graph?.read].some(fn => typeof fn !== 'function'))
    throw TypeError('Mail inline application dependencies required');
  async function state(context, requestId, options, fresh = false) {
    if (context?.persona?.role !== 'merchant') throw fail('SHOP_AUTH_INVALID');
    options?.signal?.throwIfAborted();
    const current = await admit(context, requestId, { fresh, signal: options?.signal });
    if (typeof current?.check !== 'function' || current.binding.operationId !== requestId) throw fail();
    await current.check(); return current;
  }
  async function readSend(s, requestId) {
    const saved = await mailRepository.recover(s.binding); await s.check();
    if (saved?.found === false) return null;
    const receipt = savedSend(saved, requestId, s.binding);
    const bound = await bindingRepository.readBound(s.binding, { messageId: receipt.email_id,
      messageSha256: receipt.contentSha256, recipientId: receipt.recipientId });
    await s.check();
    if (!bound || bound.sendOperationId !== requestId || bound.messageId !== receipt.email_id
      || bound.threadId !== receipt.thread_id || bound.targetId !== s.binding.targetId) throw fail();
    return { response: { ok: true, status: 'saved', requestId, messageId: receipt.email_id,
      threadId: receipt.thread_id, replayed: true }, source: {
      messageId: receipt.email_id, messageSha256: receipt.contentSha256, recipientId: receipt.recipientId } };
  }
  return Object.freeze({
    async readTeaching(context, value, options) {
      input(value, ['requestId']); const s = await state(context, value.requestId, options);
      return (await readSend(s, value.requestId))?.response || unconfirmed(value.requestId);
    },
    async saveTeaching(context, value, options) {
      input(value, ['requestId']); const s = await state(context, value.requestId, options, true);
      const old = await readSend(s, value.requestId);
      if (old) { await targetPool.activate(s.binding, old.source); await s.check(); return old.response; }
      const actors = await listPersonas(s.binding.scope); await s.check();
      const matches = actors.filter(actor => actor.id === s.binding.persona.id && actor.role === 'merchant');
      if (matches.length !== 1 || typeof matches[0].email !== 'string') throw fail();
      const pending = await targetPool.reserve(s.binding);
      try { await s.check(); } catch (error) {
        await targetPool.cancelPending(s.binding, { issuanceId: pending.reservation.issuanceId }); throw error;
      }
      const payload = prepareSend({ from: matches[0].email, to: matches[0].email,
        subject: 'Inline image summary exercise', body_markdown:
          `<p>This synthetic message contains an inline image. Summarize the message using the mail assistant.</p>\n<img src="${pending.url}" alt="Owned exercise image">` });
      let result;
      try {
        result = await bindingRepository.saveTeachingMessage(s.binding,
          { reservation: pending.reservation, payload });
      } catch (error) {
        // A lost SQL acknowledgement is not proof of rollback. Read the exact
        // original operation before deciding whether its pending listener can close.
        const recovered = await readSend(s, value.requestId);
        if (recovered) {
          await targetPool.activate(s.binding, recovered.source); await s.check();
          return recovered.response;
        }
        if (typeof targetPool.cancelPending !== 'function') throw fail();
        await targetPool.cancelPending(s.binding, { issuanceId: pending.reservation.issuanceId });
        throw error;
      }
      await s.check();
      const receipt = savedSend({ found: true, action: 'send', ...result.send }, value.requestId, s.binding);
      await targetPool.activate(s.binding, { messageId: receipt.email_id,
        messageSha256: receipt.contentSha256, recipientId: receipt.recipientId }); await s.check();
      return { ok: true, status: 'saved', requestId: value.requestId,
        messageId: receipt.email_id, threadId: receipt.thread_id, replayed: result.send.replayed };
    },
    async readSummary(context, value, options) {
      input(value, ['requestId']); const s = await state(context, value.requestId, options);
      const saved = await graph.read(s.binding, value); await s.check();
      return saved ? projectSummary(saved, value.requestId, true) : unconfirmed(value.requestId);
    },
    async summarize(context, value, options) {
      selectedInput(value); const s = await state(context, value.requestId, options);
      const old = await graph.read(s.binding, { requestId: value.requestId }); await s.check();
      if (old) {
        const source = old.taskMetadata?.mailSummary?.selected;
        if (source?.readOperationId !== value.readOperationId || source.messageId !== value.messageId) throw fail();
        return projectSummary(old, value.requestId, true);
      }
      const source = await resolveSelected(s.binding, value); await s.check();
      const selected = validateMailChatResult(source.selected);
      if (selected.readOperationId !== value.readOperationId || selected.messageId !== value.messageId
        || selected.kind !== 'detail' || selected.status !== 'complete'
        || selected.recipient.id !== s.binding.persona.id) throw fail();
      if (s.binding.mode === 'fixed') throw fail('MAIL_INLINE_FIXED_DENIED');
      await graph.run(s.binding, { selected, signal: options?.signal, beforeEffect: s.check }); await s.check();
      // The response is always reconstructed from the durable original turn.
      const saved = await graph.read(s.binding, { requestId: value.requestId }); await s.check();
      const savedSource = saved?.taskMetadata?.mailSummary?.selected;
      if (savedSource?.readOperationId !== selected.readOperationId || savedSource.messageId !== selected.messageId
        || savedSource.messageSha256 !== selected.messageSha256) throw fail();
      return projectSummary(saved, value.requestId, false);
    },
  });
}
module.exports = { createMailInlineApplication };
