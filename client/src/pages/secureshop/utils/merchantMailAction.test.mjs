import { decodeMerchantMailOperation, decodeMerchantMailProposal,
  merchantMailChatReference, merchantMailExpectedSendOperationId,
  merchantMailProposalDigest } from './merchantMailAction.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-5ccc-accc-cccccccccccc';
const send = { version: 1, kind: 'merchant_mail_proposal', action: 'send', proposalId,
  recipient: { username: 'Named customer', email: 'person@example.test' },
  subject: '<img src=x onerror=alert(1)>', body_markdown: '<script>alert(1)</script>', source: null };
const reply = { ...send, action: 'reply', recipient: null, subject: null, body_markdown: null,
  source: { from: 'sender@example.test', subject: 'Question', createdAt: '2026-10-11T20:00:00.000Z' } };
const saved = { version: 1, kind: 'merchant_mail_operation', action: 'send', proposalId,
  status: 'saved', sendOperationId: proposalId, emailId: 7, threadId: 8,
  savedSend: { recipientId: 9, to: send.recipient.email, subject: send.subject,
    body_markdown: send.body_markdown }, canRetrySameId: false };

beforeAll(() => {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: require('node:crypto').webcrypto });
});

test('closed saved send and reply previews preserve exact human-visible content', async () => {
  expect(decodeMerchantMailProposal(send)).toEqual(send);
  expect(decodeMerchantMailProposal(reply)).toEqual(reply);
  expect(decodeMerchantMailOperation(saved, proposalId, 'send')).toEqual(saved);
  expect(decodeMerchantMailOperation({ ...saved, status: 'saved_unattributed' },
    proposalId, 'send').status).toBe('saved_unattributed');
  const digest = await merchantMailProposalDigest(send);
  expect(digest).toMatch(/^[a-f0-9]{64}$/);
  expect(await merchantMailProposalDigest({ body_markdown: send.body_markdown,
    source: null, subject: send.subject,
    recipient: { email: send.recipient.email, username: send.recipient.username },
    proposalId, action: 'send', kind: 'merchant_mail_proposal', version: 1 })).toBe(digest);
  expect(await merchantMailProposalDigest({ ...reply,
    source: { createdAt: reply.source.createdAt, subject: reply.source.subject,
      from: reply.source.from } })).toBe(await merchantMailProposalDigest(reply));
  expect(merchantMailChatReference({ action: 'send', requestId: proposalId, digest,
    chatSource: { sessionId, requestId } }).requestId).toBe(proposalId);
  expect(await merchantMailExpectedSendOperationId(proposalId, 'send')).toBe(proposalId);
  const hash = require('node:crypto').createHash('sha256')
    .update(`bound-mail-v1:${proposalId}:reply`).digest('hex');
  expect(await merchantMailExpectedSendOperationId(proposalId, 'reply'))
    .toBe(`${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`);
});

test('malformed proposals and operations do not become actionable or verified results', () => {
  expect(() => decodeMerchantMailProposal({ ...send, from: 'model-chosen' })).toThrow();
  expect(() => decodeMerchantMailProposal({ ...send, recipient: { ...send.recipient, id: 7 } })).toThrow();
  expect(() => decodeMerchantMailProposal({ ...send, body_markdown: 'x'.repeat(8193) })).toThrow();
  expect(() => decodeMerchantMailProposal({ ...reply, body_markdown: 'approved reply' })).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, proposalId: requestId }, proposalId, 'send')).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, sendOperationId: requestId }, proposalId, 'send')).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, savedSend: { ...saved.savedSend, bcc: 'hidden' } }, proposalId, 'send')).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, status: 'unconfirmed',
    canRetrySameId: true }, proposalId, 'send')).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, action: 'reply' }, proposalId, 'send')).toThrow();
  expect(() => decodeMerchantMailOperation({ ...saved, status: 'saved_unattributed',
    canRetrySameId: true }, proposalId, 'send')).toThrow();
  expect(() => merchantMailChatReference({ action: 'send', requestId: proposalId,
    digest: 'a'.repeat(64), chatSource: { sessionId: [sessionId], requestId } })).toThrow();
});
