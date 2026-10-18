const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const exact = (value, names) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === names.slice().sort().join(',');
const bounded = (value, max, allowEmpty = false) => typeof value === 'string'
  && (allowEmpty || value.length > 0) && value.isWellFormed() && !value.includes('\0')
  && encoder.encode(value).byteLength <= max;
const positive = value => Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
const invalid = () => { throw new TypeError('Saved merchant mail action is invalid'); };

export function decodeMerchantMailProposal(value) {
  if (value === null || value === undefined) return null;
  if (!exact(value, ['version','kind','action','proposalId','recipient','subject','body_markdown','source'])
    || value.version !== 1 || value.kind !== 'merchant_mail_proposal'
    || !['send','reply'].includes(value.action)
    || typeof value.proposalId !== 'string' || !UUID.test(value.proposalId)) invalid();
  if (value.action === 'send') {
    if (!exact(value.recipient, ['username','email'])
      || !bounded(value.recipient.username, 256) || !bounded(value.recipient.email, 512)
      || !bounded(value.subject, 512) || !bounded(value.body_markdown, 8192, true)
      || value.source !== null) invalid();
  } else if (value.recipient !== null || value.subject !== null || value.body_markdown !== null
    || !exact(value.source, ['from','subject','createdAt'])
    || !bounded(value.source.from, 512) || !bounded(value.source.subject, 512)
    || typeof value.source.createdAt !== 'string'
    || !Number.isFinite(Date.parse(value.source.createdAt))) invalid();
  return value;
}

export function decodeMerchantMailOperation(value, proposalId, action) {
  if (!exact(value, ['version','kind','action','proposalId','status','sendOperationId','emailId',
    'threadId','savedSend','canRetrySameId']) || value.version !== 1
    || value.kind !== 'merchant_mail_operation' || value.action !== action
    || typeof value.proposalId !== 'string' || value.proposalId !== proposalId
    || !UUID.test(value.proposalId)
    || !['saved','saved_unattributed','declined','rejected_before_execution','unconfirmed'].includes(value.status)
    || (value.action === 'send' && ['declined', 'rejected_before_execution'].includes(value.status))
    || typeof value.canRetrySameId !== 'boolean'
    || value.canRetrySameId !== (value.status === 'unconfirmed' && value.action === 'send')) invalid();
  if (value.status === 'saved' || value.status === 'saved_unattributed') {
    if (typeof value.sendOperationId !== 'string' || !UUID.test(value.sendOperationId)
      || (value.action === 'send' && value.sendOperationId !== value.proposalId)
      || !positive(value.emailId) || !positive(value.threadId)
      || !exact(value.savedSend, ['recipientId','to','subject','body_markdown'])
      || !positive(value.savedSend.recipientId) || !bounded(value.savedSend.to, 512)
      || !bounded(value.savedSend.subject, 512)
      || !bounded(value.savedSend.body_markdown, 32768, true)) invalid();
  } else if (value.sendOperationId !== null || value.emailId !== null
    || value.threadId !== null || value.savedSend !== null) invalid();
  return value;
}

export async function merchantMailProposalDigest(proposal) {
  const valid = decodeMerchantMailProposal(proposal);
  if (!valid) invalid();
  const recipient = valid.recipient === null ? null
    : { username: valid.recipient.username, email: valid.recipient.email };
  const source = valid.source === null ? null
    : { from: valid.source.from, subject: valid.source.subject,
      createdAt: valid.source.createdAt };
  const bytes = await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify({
    version: valid.version, kind: valid.kind, action: valid.action, proposalId: valid.proposalId,
    recipient, subject: valid.subject, body_markdown: valid.body_markdown, source,
  })));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function merchantMailExpectedSendOperationId(proposalId, action) {
  if (typeof proposalId !== 'string' || !UUID.test(proposalId)
    || !['send', 'reply'].includes(action)) invalid();
  if (action === 'send') return proposalId;
  const bytes = await crypto.subtle.digest('SHA-256',
    encoder.encode(`bound-mail-v1:${proposalId}:reply`));
  const hash = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

export function merchantMailChatReference(reference) {
  if (!reference || !['send','autoReply'].includes(reference.action)
    || typeof reference.requestId !== 'string' || !UUID.test(reference.requestId)
    || typeof reference.digest !== 'string' || !SHA.test(reference.digest)
    || !exact(reference.chatSource, ['sessionId','requestId'])
    || typeof reference.chatSource.sessionId !== 'string' || !UUID.test(reference.chatSource.sessionId)
    || typeof reference.chatSource.requestId !== 'string' || !UUID.test(reference.chatSource.requestId)) invalid();
  return reference;
}
