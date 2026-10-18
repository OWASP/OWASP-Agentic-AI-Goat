export const AUDIT_CSV_CHANNEL = 'dvaia-secureshop-audit-csv-v1';

const HEADERS = Object.freeze(['id', 'ts', 'actor', 'action', 'target', 'params_json', 'ip', 'user_agent']);
const NONCE = /^[a-f0-9]{64}$/;
const REQUEST_ID = /^[a-f0-9]{32}$/;
const MAX_ROWS = 10000;
const MAX_BYTES = 16 * 1024 * 1024;
const usedRequests = new WeakMap();
const bytes = value => new TextEncoder().encode(value).byteLength;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const auditRoute = route => /^\/secureshop\/(?:v2\/)?admin\/audit\/?(?:\?|$)/.test(route);
const csvCell = value => {
  let cell = value ?? '';
  // Spreadsheets can execute formulas after leading whitespace or a BOM.
  if (/^[\u0000-\u0020\uFEFF]*[=+@-]/u.test(cell)) cell = `'${cell}`;
  return `"${cell.replaceAll('"', '""')}"`;
};

export function projectAuditCsvRows(events) {
  if (!Array.isArray(events)) throw new TypeError('Audit page unavailable');
  return events.map(event => Object.fromEntries(HEADERS.map(key => [key, event?.[key] ?? null])));
}

export function auditCsvForRows(rows) {
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > MAX_ROWS) throw new TypeError('Invalid audit export page');
  let size = 0;
  const lines = [HEADERS.join(',')];
  for (const row of rows) {
    if (!exact(row, HEADERS)) throw new TypeError('Invalid audit export row');
    const fields = HEADERS.map(key => {
      const value = row[key];
      if (value !== null && typeof value !== 'string') throw new TypeError('Invalid audit export field');
      const text = value ?? '';
      if (text.length > MAX_BYTES - size) throw new TypeError('Audit export exceeds page limit');
      size += bytes(text);
      if (size > MAX_BYTES) throw new TypeError('Audit export exceeds page limit');
      return csvCell(text);
    });
    lines.push(fields.join(','));
  }
  const csv = lines.join('\r\n');
  if (bytes(csv) > 2 * MAX_BYTES) throw new TypeError('Audit export exceeds page limit');
  return csv;
}

export function requestAuditCsvExport(events, frameWindow = globalThis.window) {
  const nonce = frameWindow.location.hash.slice(1);
  if (frameWindow.parent === frameWindow || !NONCE.test(nonce)) return Promise.reject(new Error('Audit export is unavailable'));
  let rows;
  try { rows = projectAuditCsvRows(events); auditCsvForRows(rows); }
  catch { return Promise.reject(new Error('Audit export is unavailable')); }
  const requestId = [...frameWindow.crypto.getRandomValues(new Uint8Array(16))]
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  const origin = new URL(frameWindow.document.baseURI).origin;
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = error => {
      if (done) return;
      done = true; clearTimeout(timer); frameWindow.removeEventListener('message', receive);
      if (error) reject(error); else resolve();
    };
    const receive = event => {
      const data = event.data;
      if (event.source !== frameWindow.parent || event.origin !== origin || event.ports.length !== 0
        || !exact(data, ['channel', 'type', 'nonce', 'requestId', 'ok'])
        || data.channel !== AUDIT_CSV_CHANNEL || data.type !== 'result' || data.nonce !== nonce
        || data.requestId !== requestId || typeof data.ok !== 'boolean') return;
      finish(data.ok ? null : new Error('Audit export could not be saved'));
    };
    const timer = setTimeout(() => finish(new Error('Audit export was not confirmed')), 10000);
    frameWindow.addEventListener('message', receive);
    try { frameWindow.parent.postMessage({ channel: AUDIT_CSV_CHANNEL, type: 'export', nonce, requestId, rows }, origin); }
    catch { finish(new Error('Audit export is unavailable')); }
  });
}

// The child only supplies a snapshot of the rows it already displays. This is
// a bounded local download, not authority to read a new audit page or access
// parent storage. API authentication remains responsible for the original read.
export function handleAuditCsvExport(event, { frame, route, allowed, hostWindow = globalThis.window,
  documentRef = hostWindow.document } = {}) {
  const data = event?.data;
  if (!frame?.isConnected || event.source !== frame.contentWindow || event.origin !== 'null'
    || event.ports?.length !== 0 || !allowed || !auditRoute(route)
    || !exact(data, ['channel', 'type', 'nonce', 'requestId', 'rows'])
    || data.channel !== AUDIT_CSV_CHANNEL || data.type !== 'export'
    || !NONCE.test(data.nonce) || data.nonce !== new URL(frame.src).hash.slice(1)
    || !REQUEST_ID.test(data.requestId)) return false;
  let recent = usedRequests.get(frame);
  if (!recent) { recent = new Map(); usedRequests.set(frame, recent); }
  if (recent.has(data.requestId) || recent.size >= 32) {
    frame.contentWindow.postMessage({ channel: AUDIT_CSV_CHANNEL, type: 'result', nonce: data.nonce,
      requestId: data.requestId, ok: recent.get(data.requestId) === true }, '*');
    return true;
  }
  let ok = false;
  try {
    const csv = auditCsvForRows(data.rows);
    const url = hostWindow.URL.createObjectURL(new hostWindow.Blob([csv], { type: 'text/csv;charset=utf-8' }));
    try {
      if (!frame.isConnected || event.source !== frame.contentWindow) throw new Error('Frame changed');
      const link = documentRef.createElement('a');
      link.href = url;
      link.download = 'secureshop-audit-current-page.csv';
      documentRef.body.appendChild(link);
      try { link.click(); ok = true; } finally { link.remove(); }
    } finally { hostWindow.URL.revokeObjectURL(url); }
  } catch { /* The child receives one truthful failure acknowledgement. */ }
  recent.set(data.requestId, ok);
  if (frame.isConnected && event.source === frame.contentWindow) {
    frame.contentWindow.postMessage({ channel: AUDIT_CSV_CHANNEL, type: 'result', nonce: data.nonce,
      requestId: data.requestId, ok }, '*');
  }
  return true;
}
