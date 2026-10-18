import { decodeAdminAuditRead } from './adminAuditRead.mjs';

const mode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const eventId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const event = { store: 'agents', id: `agents:${eventId}`, event_id: eventId,
  ts: '2026-10-11T12:34:56.123456Z', actor: 'Admin', action: 'role_change',
  target: 'Owned customer', params_json: '{"note":"<img src=x onerror=alert(1)>"}',
  outcome: 'completed', source_kind: 'user_administration', source_id: 'saved source',
  ip: null, user_agent: null };
const page = { count: 1, events: [event], hasMore: true, nextCursor: 'opaque_cursor_1' };
const hop = value => ({ tool: 'admin.audit_recent', params: {}, error: null,
  result: { content: [{ type: 'text', text: JSON.stringify(value) }] } });

test('decodes five-or-fewer rows only from exact successful saved admin audit output', () => {
  expect(decodeAdminAuditRead([hop(page)], mode, 'end_turn')).toEqual({
    events: [event], hasMore: true, nextPageAvailable: true,
  });
  expect(decodeAdminAuditRead([hop({ count: 0, events: [], hasMore: false,
    nextCursor: null })], mode, 'end_turn')).toEqual({
    events: [], hasMore: false, nextPageAvailable: false,
  });
});

test('ignores failed hops and denies wrong role mode or nonterminal turns', () => {
  expect(decodeAdminAuditRead([{ ...hop(page), error: { code: 'DENIED' } }], mode, 'end_turn')).toBeNull();
  expect(decodeAdminAuditRead([{ ...hop(page), result: { isError: true } }], mode, 'end_turn')).toBeNull();
  expect(decodeAdminAuditRead([hop(page)], { ...mode, policyVersion: 'invented' }, 'end_turn')).toBeNull();
  expect(decodeAdminAuditRead([hop(page)], { ...mode, featureId: 'merchant_assistant' }, 'end_turn')).toBeNull();
  expect(decodeAdminAuditRead([hop(page)], mode, 'tool_denied')).toBeNull();
});

test('rejects extra fields, contradictory counts, malformed rows and oversized observations', () => {
  for (const invalid of [
    { ...page, unexpected: true },
    { ...page, count: 2 },
    { ...page, events: [{ ...event, target: 123 }] },
    { ...page, events: [{ ...event, id: `review:${eventId}` }] },
    { ...page, events: [{ ...event, extra: 'foreign' }] },
    { ...page, events: [{ ...event, params_json: 'not JSON' }] },
    { ...page, hasMore: false },
  ]) expect(() => decodeAdminAuditRead([hop(invalid)], mode, 'end_turn'))
    .toThrow('Saved admin audit read invalid');
  const tooLarge = { ...page, events: [{ ...event,
    params_json: JSON.stringify({ note: 'x'.repeat(16384) }) }] };
  expect(() => decodeAdminAuditRead([hop(tooLarge)], mode, 'end_turn'))
    .toThrow('Saved admin audit read invalid');
  expect(() => decodeAdminAuditRead([{ ...hop(page), result: { content: [
    { type: 'text', text: JSON.stringify(page) }, { type: 'text', text: '{}' }] } }], mode, 'end_turn'))
    .toThrow('Saved admin audit read invalid');
});
