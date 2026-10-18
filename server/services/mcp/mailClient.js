'use strict';

/**
 * Real SMTP client for the MCP lab. send_report / confused-deputy / indirect-
 * injection exfiltration sends a GENUINE email into the Mailpit sink; the UI
 * and tests then read it back through Mailpit's JSON API — proving the data
 * really left the app over SMTP. Returns { ok:false } when Mailpit is
 * unavailable so the caller fails honestly (the exploit does not score) — there
 * is no simulated delivery.
 */

const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const { MAILPIT_SMTP_HOST, MAILPIT_SMTP_PORT, MAILPIT_API_URL, BACKEND_TIMEOUT_MS } = require('./config');
const MAX_EXFIL_MAIL_RECEIPTS = 20;
const OWNED_MESSAGE_ID = /^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@dvaia\.local$/i;
const MAILPIT_DATABASE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const READBACK_VERSION = 'mcp-mailpit-readback.v1';
const READBACK_NEWLINE_POLICY = 'crlf-to-lf-plus-one-terminal-newline.v1';
const trustedMessageReadbacks = new WeakSet();

let transporter = null;
function getTransport() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: MAILPIT_SMTP_HOST,
      port: MAILPIT_SMTP_PORT,
      secure: false,
      tls: { rejectUnauthorized: false },
      connectionTimeout: BACKEND_TIMEOUT_MS,
      greetingTimeout: BACKEND_TIMEOUT_MS,
    });
  }
  return transporter;
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = BACKEND_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...opts, signal: ctrl.signal });
    const reader = response.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 1024 * 1024) {
            ctrl.abort();
            throw new Error('Mail response exceeds limit');
          }
          chunks.push(Buffer.from(value));
        }
      } finally { reader.releaseLock(); }
    }
    const text = Buffer.concat(chunks).toString('utf8');
    return { ok: response.ok, status: response.status, json: async () => JSON.parse(text) };
  } finally { clearTimeout(t); }
}

/**
 * Send a real email. @returns {Promise<{ok:boolean, messageId?:string, error?:string}>}
 */
async function sendReport({ to, from = 'mcp-ops@acme-corp.internal', subject = 'Operations report', body = '' }) {
  try {
    const info = await getTransport().sendMail({ from, to, subject, text: body });
    const messageId = String(info.messageId || '').trim();
    if (!messageId) return { ok: false, error: 'SMTP delivery returned no Message-ID receipt' };
    return { ok: true, messageId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function readiness() {
  try {
    const [smtp, api] = await Promise.all([
      getTransport().verify(),
      fetchWithTimeout(`${MAILPIT_API_URL}/api/v1/info`, {}, BACKEND_TIMEOUT_MS),
    ]);
    return Object.freeze({ ready: smtp === true && api.ok === true, smtp: smtp === true, api: api.ok === true });
  } catch { return Object.freeze({ ready: false, smtp: false, api: false }); }
}

/**
 * Send using a receipt ID already reserved in the durable MCP resource store.
 * This is a private composition adapter: model/tool arguments never select the
 * Message-ID. Runtime wiring remains disabled until the owned-resource schema
 * and reset composition are promoted together.
 */
async function sendOwnedReport({ to, from = 'mcp-ops@acme-corp.internal', subject = 'Operations report', body = '', messageId }) {
  const assigned = normalizeSmtpMessageId(messageId);
  if (!/^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@dvaia\.local$/i.test(assigned)) {
    throw new TypeError('Canonical server-assigned MCP Message-ID is required');
  }
  try {
    const info = await getTransport().sendMail({ from, to, subject, text: body, messageId: assigned });
    const returned = String(info.messageId || '').trim();
    if (!returned) return { ok: false, error: 'SMTP delivery returned no Message-ID receipt' };
    return { ok: true, messageId: returned };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function normalizeSmtpMessageId(value) {
  const raw = String(value || '').trim();
  return raw.startsWith('<') && raw.endsWith('>') ? raw.slice(1, -1).trim() : raw;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonical(value) {
  return JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
}

function readbackInput(value) {
  const fields = ['body', 'messageId', 'subject', 'to'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== fields.join(',')) {
    throw new TypeError('Exact owned mail readback input is required');
  }
  const messageId = normalizeSmtpMessageId(value.messageId);
  if (value.messageId !== messageId || !OWNED_MESSAGE_ID.test(messageId)
      || typeof value.to !== 'string' || !value.to.length || Buffer.byteLength(value.to) > 320
      || typeof value.subject !== 'string' || !value.subject.length || Buffer.byteLength(value.subject) > 512
      || typeof value.body !== 'string' || !value.body.length || Buffer.byteLength(value.body) > 65536) {
    throw new TypeError('Canonical owned mail readback values are required');
  }
  return Object.freeze({ messageId, to: value.to, subject: value.subject, body: value.body });
}

function normalizedText(value) {
  if (typeof value !== 'string' || /\r(?!\n)/.test(value)) return null;
  return value.replace(/\r\n/g, '\n');
}

function compareDecodedText(submitted, observed) {
  const expected = normalizedText(submitted);
  const actual = normalizedText(observed);
  if (expected === null || actual === null) return null;
  if (actual === expected) return Object.freeze({ normalized: actual, transportTerminalNewline: false });
  if (!expected.endsWith('\n') && actual === `${expected}\n`) {
    return Object.freeze({ normalized: actual, transportTerminalNewline: true });
  }
  return null;
}

function isTrustedMessageReadback(value) {
  return Boolean(value && typeof value === 'object' && trustedMessageReadbacks.has(value));
}

/**
 * Verify one complete Mailpit message against the server-owned SMTP receipt and
 * submitted payload. Search is only a locator: duplicates are ambiguous, and
 * the exact database ID, Message-ID, recipient, subject and decoded text are
 * rechecked on the full detail response. Mailpit documents that detail reads
 * mark the message read; this candidate is therefore reserved for server-side
 * evidence collection rather than the existing read-only UI projection.
 *
 * SMTP/MIME may convert CRLF to LF and add one final transport newline. No
 * other text change is accepted. The receipt keeps the digest of the original
 * submitted body separate from the digest of the normalized observed text.
 */
async function verifyMessageReadback(value, { fetcher = fetchWithTimeout } = {}) {
  const expected = readbackInput(value);
  if (typeof fetcher !== 'function') throw new TypeError('Mailpit readback fetcher is required');
  try {
    const search = new URL(`${MAILPIT_API_URL}/api/v1/search`);
    search.searchParams.set('query', `message-id:${expected.messageId}`);
    search.searchParams.set('limit', '2');
    const searchResponse = await fetcher(search.toString(), { redirect: 'error' }, 3000);
    if (!searchResponse.ok) return Object.freeze({ ok: false, status: 'unavailable' });
    const result = await searchResponse.json();
    if (!Number.isSafeInteger(result?.messages_count)) {
      return Object.freeze({ ok: false, status: 'unavailable' });
    }
    if (!Array.isArray(result.messages)) return Object.freeze({ ok: false, status: 'unavailable' });
    if (result.messages_count === 0) return Object.freeze({ ok: false,
      status: result.messages.length === 0 ? 'not_found' : 'unavailable' });
    if (result.messages_count !== 1 || result.messages.length !== 1) {
      return Object.freeze({ ok: false, status: 'ambiguous' });
    }
    const summary = result.messages[0];
    if (!summary || typeof summary.ID !== 'string' || !MAILPIT_DATABASE_ID.test(summary.ID)
        || summary.ID.toLowerCase() === 'latest'
        || normalizeSmtpMessageId(summary.MessageID) !== expected.messageId) {
      return Object.freeze({ ok: false, status: 'mismatch' });
    }
    const detailUrl = `${MAILPIT_API_URL}/api/v1/message/${encodeURIComponent(summary.ID)}`;
    const detailResponse = await fetcher(detailUrl, { redirect: 'error' }, 3000);
    if (!detailResponse.ok) return Object.freeze({ ok: false, status: 'unavailable' });
    const detail = await detailResponse.json();
    const addresses = Array.isArray(detail?.To) ? detail.To : [];
    const comparison = compareDecodedText(expected.body, detail?.Text);
    if (detail?.ID !== summary.ID || normalizeSmtpMessageId(detail?.MessageID) !== expected.messageId
        || addresses.length !== 1 || addresses[0]?.Address !== expected.to
        || detail?.Subject !== expected.subject || !comparison) {
      return Object.freeze({ ok: false, status: 'mismatch' });
    }
    const receiptBody = Object.freeze({ version: READBACK_VERSION, messageId: expected.messageId,
      newlinePolicy: READBACK_NEWLINE_POLICY,
      mailpitIdSha256: sha256(Buffer.from(summary.ID)),
      recipientSha256: sha256(Buffer.from(expected.to)),
      subjectSha256: sha256(Buffer.from(expected.subject)),
      submittedBodySha256: sha256(Buffer.from(expected.body)),
      submittedBodyByteCount: Buffer.byteLength(expected.body),
      submittedPayloadSha256: sha256(Buffer.from(canonical({ body: expected.body, subject: expected.subject }))),
      normalizedObservedTextSha256: sha256(Buffer.from(comparison.normalized)),
      normalizedObservedTextByteCount: Buffer.byteLength(comparison.normalized),
      transportTerminalNewline: comparison.transportTerminalNewline });
    const receipt = Object.freeze({ ...receiptBody,
      receiptSha256: sha256(Buffer.from(canonical(receiptBody))) });
    trustedMessageReadbacks.add(receipt);
    return Object.freeze({ ok: true, status: 'verified', receipt });
  } catch {
    return Object.freeze({ ok: false, status: 'unavailable' });
  }
}

function deliveredSmtpMessageIds(sentReports) {
  const ids = [];
  const seen = new Set();
  // Keep the Captured Data panel's prior 20-message bound, but apply it to
  // server-owned receipts before Mailpit lookup. sentReports is append-ordered,
  // so reverse traversal selects the learner's newest unique deliveries.
  for (let index = (sentReports || []).length - 1; index >= 0 && ids.length < MAX_EXFIL_MAIL_RECEIPTS; index -= 1) {
    const report = sentReports[index];
    if (!report || report.delivered !== true) continue;
    const messageId = normalizeSmtpMessageId(report.messageId);
    if (!messageId || seen.has(messageId)) continue;
    seen.add(messageId);
    ids.push(messageId);
  }
  return ids;
}

function messageSummary(message) {
  return {
    id: message.ID,
    messageId: message.MessageID || null,
    to: (message.To || []).map(x => x.Address).join(', '),
    from: message.From ? message.From.Address : '',
    subject: message.Subject,
    snippet: message.Snippet,
    createdAt: message.Created,
  };
}

/**
 * Read delivered messages back from Mailpit's API (proof of real delivery).
 * @returns {Promise<{ok:boolean, messages:Array}>}
 */
async function listMessages(limit = 50) {
  try {
    const r = await fetchWithTimeout(`${MAILPIT_API_URL}/api/v1/messages?limit=${limit}`, {}, 3000);
    if (!r.ok) return { ok: false, messages: [] };
    const body = await r.json();
    const messages = (body.messages || []).map(messageSummary);
    return { ok: true, messages };
  } catch {
    return { ok: false, messages: [] };
  }
}

/**
 * Retrieve only messages named by server-recorded SMTP Message-ID receipts.
 * Mailpit's `ID` is its own database key and is deliberately not compared to
 * Nodemailer's Message-ID. The search prevents an owned older message from
 * being displaced by newer messages in the shared sink; the exact comparison
 * prevents a broad or malformed search from returning unrelated mail.
 */
async function listMessagesBySmtpIds(messageIds, { fetcher = fetchWithTimeout } = {}) {
  const wanted = [...new Set((messageIds || []).map(normalizeSmtpMessageId).filter(Boolean))];
  if (!wanted.length) {
    try {
      // Preserve truthful availability without listing any shared mailbox row.
      const response = await fetcher(`${MAILPIT_API_URL}/api/v1/info`, {}, 3000);
      return { ok: response.ok, messages: [] };
    } catch {
      return { ok: false, messages: [] };
    }
  }
  const messages = [];
  const seenInternalIds = new Set();
  try {
    for (const smtpId of wanted) {
      const url = new URL(`${MAILPIT_API_URL}/api/v1/search`);
      url.searchParams.set('query', `message-id:${smtpId}`);
      url.searchParams.set('limit', '50');
      const response = await fetcher(url.toString(), {}, 3000);
      if (!response.ok) return { ok: false, messages: [] };
      const body = await response.json();
      for (const candidate of body.messages || []) {
        if (normalizeSmtpMessageId(candidate.MessageID) !== smtpId) continue;
        if (seenInternalIds.has(candidate.ID)) continue;
        seenInternalIds.add(candidate.ID);
        messages.push(messageSummary(candidate));
      }
    }
    return { ok: true, messages };
  } catch {
    return { ok: false, messages: [] };
  }
}

/** Delete only deliveries identified by server-owned SMTP receipts. */
async function deleteMessagesBySmtpIds(messageIds, { fetcher = fetchWithTimeout, timeoutMs = 8000 } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 30000) throw new TypeError('Invalid cleanup deadline');
  const wanted = [...new Set((messageIds || []).map(normalizeSmtpMessageId).filter(Boolean))];
  const deadline = Date.now() + timeoutMs;
  let deleted = 0;
  const boundedFetch = (url, options, requestTimeout) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('Cleanup deadline exceeded');
    return fetcher(url, options, Math.min(requestTimeout, remaining));
  };
  for (let index = 0; index < wanted.length; index++) {
    try {
      const found = await listMessagesBySmtpIds([wanted[index]], { fetcher: boundedFetch });
      if (!found.ok) throw new Error('Cleanup lookup failed');
      const ids = [...new Set(found.messages.map(message => message.id).filter(id => typeof id === 'string' && id))];
      // Empty IDs mean delete everything in Mailpit. Never send them.
      if (ids.length) {
        const response = await boundedFetch(`${MAILPIT_API_URL}/api/v1/messages`, {
          method: 'DELETE', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ IDs: ids }),
        }, 3000);
        if (!response.ok) throw new Error('Cleanup deletion failed');
        deleted += ids.length;
      }
    } catch { return { ok: false, deleted, remainingMessageIds: wanted.slice(index) }; }
  }
  return { ok: true, deleted };
}

module.exports = { readiness, sendReport, sendOwnedReport, listMessages, listMessagesBySmtpIds,
  verifyMessageReadback, isTrustedMessageReadback, deliveredSmtpMessageIds, deleteMessagesBySmtpIds,
  _internals: { fetchWithTimeout, MAX_EXFIL_MAIL_RECEIPTS, normalizeSmtpMessageId, messageSummary,
    READBACK_VERSION, READBACK_NEWLINE_POLICY, MAILPIT_DATABASE_ID,
    readbackInput, normalizedText, compareDecodedText } };
