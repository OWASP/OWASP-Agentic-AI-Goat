import { AUDIT_CSV_CHANNEL, auditCsvForRows, handleAuditCsvExport, requestAuditCsvExport } from './auditCsvExport.mjs';

const nonce = 'a'.repeat(64);
const requestId = 'b'.repeat(32);
const row = overrides => ({ id: 'agents:1', ts: '2026-10-10T00:00:00Z', actor: 'admin', action: 'read',
  target: 'user:1', params_json: '{}', ip: null, user_agent: null, ...overrides });

function host() {
  const link = { click: jest.fn(), remove: jest.fn(), href: '', download: '' };
  const frameWindow = { postMessage: jest.fn() };
  const frame = { isConnected: true, src: `http://localhost/secureshop-frame.html#${nonce}`,
    contentWindow: frameWindow };
  const windowRef = { URL: { createObjectURL: jest.fn(() => 'blob:fixed'), revokeObjectURL: jest.fn() }, Blob };
  const documentRef = { createElement: jest.fn(() => link), body: { appendChild: jest.fn() } };
  const event = { source: frameWindow, origin: 'null', ports: [], data: {
    channel: AUDIT_CSV_CHANNEL, type: 'export', nonce, requestId, rows: [row()],
  } };
  const context = { frame, route: '/secureshop/admin/audit', allowed: true,
    hostWindow: windowRef, documentRef };
  return { event, context, frame, frameWindow, windowRef, documentRef, link };
}

test('fixed-schema CSV escapes quotes and neutralizes spreadsheet formula cells', () => {
  const csv = auditCsvForRows([row({ actor: ' =1+1', target: '"quoted"', params_json: '\uFEFF@SUM(1)' })]);
  expect(csv).toContain('"\' =1+1"');
  expect(csv).toContain('"""quoted"""');
  expect(csv).toContain('"\'\uFEFF@SUM(1)"');
  expect(() => auditCsvForRows([row({ arbitrary: 'x' })])).toThrow('Invalid audit export row');
  expect(() => auditCsvForRows([row({ actor: 'x'.repeat(16 * 1024 * 1024 + 1) })]))
    .toThrow('Audit export exceeds page limit');
});

test('parent exports one bounded current page with a fixed filename and acknowledges it', () => {
  const h = host();
  expect(handleAuditCsvExport(h.event, h.context)).toBe(true);
  expect(h.windowRef.URL.createObjectURL).toHaveBeenCalledTimes(1);
  expect(h.link.download).toBe('secureshop-audit-current-page.csv');
  expect(h.link.click).toHaveBeenCalledTimes(1);
  expect(h.windowRef.URL.revokeObjectURL).toHaveBeenCalledWith('blob:fixed');
  expect(h.frameWindow.postMessage).toHaveBeenCalledWith({ channel: AUDIT_CSV_CHANNEL,
    type: 'result', nonce, requestId, ok: true }, '*');
  expect(handleAuditCsvExport(h.event, h.context)).toBe(true);
  expect(h.link.click).toHaveBeenCalledTimes(1);
});

test('parent ignores foreign, stale and nonadmin messages; rejects malformed rows without download', () => {
  for (const change of [
    h => { h.event.origin = 'http://localhost'; },
    h => { h.event.ports = [{}]; },
    h => { h.event.source = {}; },
    h => { h.frame.isConnected = false; },
    h => { h.event.data.nonce = 'c'.repeat(64); },
    h => { h.context.route = '/secureshop/merchant'; },
    h => { h.context.allowed = false; },
  ]) {
    const h = host(); change(h);
    expect(handleAuditCsvExport(h.event, h.context)).toBe(false);
    expect(h.link.click).not.toHaveBeenCalled();
  }
  const h = host(); h.event.data.rows = [row({ actor: 5 })];
  expect(handleAuditCsvExport(h.event, h.context)).toBe(true);
  expect(h.link.click).not.toHaveBeenCalled();
  expect(h.frameWindow.postMessage).toHaveBeenCalledWith(expect.objectContaining({ ok: false }), '*');
});

test('child resolves only matching parent acknowledgement and rejects an explicit failure', async () => {
  const listeners = new Set();
  const parent = { postMessage: jest.fn() };
  const frameWindow = { parent, location: { hash: `#${nonce}` }, document: { baseURI: 'http://localhost/secureshop-frame.html' },
    crypto: { getRandomValues: array => array.fill(7) },
    addEventListener: (_, listener) => listeners.add(listener),
    removeEventListener: (_, listener) => listeners.delete(listener) };
  const pending = requestAuditCsvExport([row()], frameWindow);
  const sent = parent.postMessage.mock.calls[0][0];
  expect(sent.rows).toEqual([row()]);
  for (const listener of listeners) listener({ source: {}, origin: 'http://localhost', ports: [],
    data: { channel: AUDIT_CSV_CHANNEL, type: 'result', nonce, requestId: sent.requestId, ok: true } });
  expect(listeners.size).toBe(1);
  for (const listener of listeners) listener({ source: parent, origin: 'http://localhost', ports: [],
    data: { channel: AUDIT_CSV_CHANNEL, type: 'result', nonce, requestId: sent.requestId, ok: true } });
  await expect(pending).resolves.toBeUndefined();
  expect(listeners.size).toBe(0);
  const rejected = requestAuditCsvExport([row()], frameWindow);
  const retry = parent.postMessage.mock.calls[1][0];
  for (const listener of listeners) listener({ source: parent, origin: 'http://localhost', ports: [],
    data: { channel: AUDIT_CSV_CHANNEL, type: 'result', nonce, requestId: retry.requestId, ok: false } });
  await expect(rejected).rejects.toThrow('could not be saved');
});
