import { decodeMerchantMailRead } from './merchantMailRead.mjs';

const outer = { version: 1, featureId: 'merchant_assistant',
  policyVersion: 'owned-merchant-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const mailModeCapability = { version: 1, featureId: 'mail',
  policyVersion: 'owned-mail-recipient-header-and-html-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'mail' } };
const recipient = { id: 7, username: 'Practice merchant',
  email: 'merchant@example.test', role: 'merchant' };
const header = { id: 41, threadId: 4, from: 'buyer@example.test',
  to: 'merchant@example.test', subject: '<img src=x>',
  createdAt: '2026-10-11T12:00:00.000Z', sha256: 'a'.repeat(64) };
const base = { version: 1, readOperationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  mailModeCapability, receiptSha256: 'b'.repeat(64), recipient };
const list = { ...base, kind: 'list', offset: 0, total: 6, hasMore: true,
  headers: [header] };
const wrap = (result, choiceId = null) => ({ version: 1, choiceId,
  modeCapability: outer, result });

test('closed saved mail pages preserve full headers, independent mail mode and truthful pagination', () => {
  const value = decodeMerchantMailRead(wrap(list), outer, 'end_turn');
  expect(value.result.headers[0].subject).toBe('<img src=x>');
  expect(value.result.mailModeCapability.effectiveMode).toBe('fixed');
  expect(value.result.hasMore).toBe(true);
  expect(() => decodeMerchantMailRead(wrap({ ...list, offset: 5 }), outer, 'end_turn')).toThrow();
  expect(() => decodeMerchantMailRead(wrap({ ...list, extra: 1 }), outer, 'end_turn')).toThrow();
  expect(() => decodeMerchantMailRead(wrap(list), outer, 'error')).toThrow();
  expect(() => decodeMerchantMailRead(wrap(list), { ...outer, effectiveMode: 'fixed' }, 'end_turn')).toThrow();
  expect(() => decodeMerchantMailRead(wrap({ version: 1, kind: 'recipients',
    recipients: [recipient], hasMore: true, mailModeCapability }), outer, 'end_turn')).toThrow();
});

test('selected detail renders only exact saved source or an explicit oversized state', () => {
  const choiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const bodyMarkdown = '<script>alert(1)</script>';
  const bodyHtml = '<img src=x onerror=alert(1)>';
  const headersRaw = 'X-Test: raw';
  const sourceBytes = new TextEncoder().encode(bodyMarkdown + bodyHtml + headersRaw).byteLength;
  const detail = { ...base, kind: 'detail', messageId: header.id,
    messageSha256: header.sha256, status: 'complete',
    message: { ...header, bodyMarkdown, bodyHtml, headersRaw, sourceBytes, oversized: false } };
  expect(decodeMerchantMailRead(wrap(detail, choiceId), outer, 'end_turn').result.message.bodyHtml)
    .toBe(bodyHtml);
  expect(() => decodeMerchantMailRead(wrap({ ...detail, message: { ...detail.message,
    sourceBytes: sourceBytes + 1 } }, choiceId), outer, 'end_turn')).toThrow();
  expect(() => decodeMerchantMailRead(wrap(detail), outer, 'end_turn')).toThrow();
  const oversized = { ...detail, status: 'oversized', message: null };
  expect(decodeMerchantMailRead(wrap(oversized, choiceId), outer, 'end_turn').result.message).toBeNull();
  expect(() => decodeMerchantMailRead(wrap({ ...oversized, status: 'complete' }, choiceId),
    outer, 'end_turn')).toThrow();
});
