'use strict';
const C = require('./secureshopExternalMailContract');

function project(row,{getRecovery=false}={}) {
  const preview = C.validateExternalMailPreview(row.preview);
  if (row.operation_id !== preview.operationId || !C.SHA.test(row.scope_key)
      || row.request_sha256 !== C.externalMailRequestSha256(preview,row.scope_key)
      || !['prepared','cancelled','dispatching','smtp_accepted','rejected_before_dispatch','unknown'].includes(row.state)
      || !Number.isFinite(Date.parse(row.expires_at))) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
  const smtp = row.smtp;
  if ((row.state === 'smtp_accepted') !== (smtp !== null)
      || (smtp !== null && (!C.exact(smtp,['smtpAccepted','deliveryConfirmed','messageId','acceptedRecipient'])
      || smtp.smtpAccepted !== true || smtp.deliveryConfirmed !== false
      || smtp.acceptedRecipient !== preview.recipient || typeof smtp.messageId !== 'string'
      || !smtp.messageId || smtp.messageId.length > 998 || /[\r\n]/.test(smtp.messageId))))
    throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
  if (getRecovery && row.derivedExpired === true && row.state !== 'prepared')
    throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
  return Object.freeze({version:1,operationId:preview.operationId,scopeKey:row.scope_key,
    requestSha256:row.request_sha256,state:getRecovery && row.derivedExpired===true ? 'expired' : row.state,
    preview:Object.freeze({sender:preview.sender,recipient:preview.recipient,subject:preview.subject,text:preview.text}),
    expiresAt:new Date(row.expires_at).toISOString(),smtp});
}
function createExternalMailApplication({ repository, authority, transport, sender }) {
  if (['assertReady','read','prepare','claim','cancel','settle'].some(k=>typeof repository?.[k]!=='function')
      || ['capture','assertCurrent','withDispatch'].some(k=>typeof authority?.[k]!=='function')
      || typeof transport?.isAvailable !== 'function' || typeof transport?.send !== 'function')
    throw TypeError('External mail dependencies required');
  const available = () => transport.isAvailable();
  async function requireReady() {
    if (!available()) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
    await repository.assertReady();
  }
  return Object.freeze({
    async readiness(context) {
      if (!available()) return Object.freeze({version:1,available:false,reason:'not_configured'});
      await requireReady();
      const a = await authority.capture(context);
      return Object.freeze({version:1,available:true,scopeKey:a.scopeKey,sender:C.normalizeExternalSender(sender),
        templateVersion:C.TEMPLATE_VERSION,limits:Object.freeze({ownerPerHour:C.OWNER_LIMIT,senderPerHour:C.SENDER_LIMIT})});
    },
    async read(context,id) {
      if (!C.UUID.test(id)) throw C.error('INVALID_ARGUMENT');
      const a = await authority.capture(context);
      const row = await repository.read(a,id);
      await authority.assertCurrent(a);
      return row ? project(row,{getRecovery:true}) : Object.freeze({version:1,operationId:id,state:'not_found'});
    },
    async prepare(context,body) {
      const input = C.prepareInput(body); await requireReady();
      const a = await authority.capture(context);
      if (input.scopeKey !== a.scopeKey) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
      const preview = C.makeExternalMailPreview({operationId:input.operationId,sender,recipient:input.recipient});
      const row = await repository.prepare(a,preview,C.externalMailRequestSha256(preview,a.scopeKey));
      await authority.assertCurrent(a);
      return project(row);
    },
    async cancel(context,body) {
      const input = C.confirmationInput(body), a = await authority.capture(context);
      const row = await repository.cancel(a,input);
      await authority.assertCurrent(a);
      return project(row);
    },
    async confirm(context,body,{signal}={}) {
      const input = C.confirmationInput(body); await requireReady();
      const a = await authority.capture(context);
      if (signal?.aborted) throw C.error('EXTERNAL_MAIL_UNAVAILABLE');
      const claim = await repository.claim(a,input);
      if (!claim.claimed) return project(claim.row); // Never resend, including unknown/dispatching.
      let enteredTransport = false, state = 'rejected_before_dispatch', smtp = null;
      const controller = new AbortController();
      const deadlineAt = Math.min(Date.now()+C.DISPATCH_MS,a.expiresAt,Date.parse(claim.row.expires_at));
      const abort = () => controller.abort();
      const timer = setTimeout(abort,Math.max(0,deadlineAt-Date.now()));
      signal?.addEventListener('abort',abort,{once:true});
      try {
        if (signal?.aborted) abort();
        // Revalidate the stored exact preview/digest before entering SMTP.
        project(claim.row);
        await authority.withDispatch(a,async held => {
          if (controller.signal.aborted || Date.now() >= held.deadlineAt) throw C.error('EXTERNAL_MAIL_SCOPE_STALE');
          // Claim is durable before this single external effect. No local
          // rollback can prove a remote message was not accepted.
          enteredTransport = true;
          const result = await transport.send(C.validateExternalMailPreview(claim.row.preview),
            {signal:controller.signal,deadlineAt:held.deadlineAt});
          if (!C.exact(result,['smtpAccepted','deliveryConfirmed','messageId','accepted','rejected'])
              || result.smtpAccepted !== true || result.deliveryConfirmed !== false
              || !Array.isArray(result.accepted) || result.accepted.length !== 1
              || result.accepted[0] !== claim.row.preview.recipient
              || !Array.isArray(result.rejected) || result.rejected.length
              || typeof result.messageId !== 'string' || !result.messageId
              || result.messageId.length>998 || /[\r\n]/.test(result.messageId))
            throw C.error('EXTERNAL_MAIL_UNKNOWN');
          smtp = {smtpAccepted:true,deliveryConfirmed:false,messageId:result.messageId,
            acceptedRecipient:result.accepted[0]};
        },{deadlineAt});
        state = 'smtp_accepted';
      } catch {
        state = enteredTransport ? 'unknown' : 'rejected_before_dispatch';
        smtp = null;
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort',abort);
        controller.abort();
      }
      // A failed settlement leaves dispatching, not a retryable draft.
      return project(await repository.settle(input.operationId,state,smtp));
    },
  });
}
module.exports = { createExternalMailApplication, projectExternalMailOperation:project };
