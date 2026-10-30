'use strict';

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024;
const DEFAULT_MAX_MESSAGE_BYTES = 512 * 1024;
const DEFAULT_MAX_MESSAGES = 50;
const FIXED_SENDER = 'attacker@owasp-ai-goat.invalid';
const OWNER_ADDRESS = /^xss-([1-9][0-9]*)@owasp-ai-goat\.invalid$/;

class XssLocalMailError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'XssLocalMailError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new XssLocalMailError(code, message);
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function boundedString(value, name, maximumBytes, { allowEmpty = true } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)
    || Buffer.byteLength(value, 'utf8') > maximumBytes) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function normalizeMailboxAddress(value) {
  if (typeof value !== 'string') return null;
  return value.trim().toLowerCase();
}

function ownerAddress(value) {
  if (typeof value !== 'string') fail('INVALID_RECIPIENT', 'A single owned XSS inbox is required');
  const match = OWNER_ADDRESS.exec(value);
  if (!match) fail('INVALID_RECIPIENT', 'A single owned XSS inbox is required');
  const ownerId = Number(match[1]);
  if (!Number.isSafeInteger(ownerId) || ownerId <= 0 || String(ownerId) !== match[1]) {
    fail('INVALID_RECIPIENT', 'A single owned XSS inbox is required');
  }
  return { address: value, ownerId: String(ownerId) };
}

function createXssLocalMail({
  smtpHost,
  smtpPort,
  apiUrl,
  nodemailer: mailer = require('nodemailer'),
  fetcher = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES,
  maxMessages = DEFAULT_MAX_MESSAGES,
} = {}) {
  if (typeof smtpHost !== 'string' || !smtpHost || /[\r\n]/.test(smtpHost)) throw new TypeError('Invalid SMTP host');
  boundedInteger(smtpPort, 'SMTP port', 1, 65535);
  boundedInteger(timeoutMs, 'mail deadline', 1, 30000);
  boundedInteger(maxResponseBytes, 'mail response limit', 1, 1024 * 1024);
  boundedInteger(maxMessageBytes, 'mail message limit', 1, 1024 * 1024);
  boundedInteger(maxMessages, 'mail result limit', 1, 100);
  if (!mailer || typeof mailer.createTransport !== 'function') throw new TypeError('Nodemailer transport is required');
  if (typeof fetcher !== 'function') throw new TypeError('Mailpit fetch implementation is required');

  let base;
  try { base = new URL(apiUrl); } catch { throw new TypeError('Invalid Mailpit API URL'); }
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new TypeError('Invalid Mailpit API URL');
  }
  base.pathname = `${base.pathname.replace(/\/+$/, '')}/`;

  let transporter = null;
  let closed = false;

  function requireOpen() {
    if (closed) fail('MAIL_ADAPTER_CLOSED', 'The local mail adapter is closed');
  }

  function canonicalize(recipient) {
    requireOpen();
    return ownerAddress(recipient).address;
  }

  function getTransport() {
    requireOpen();
    if (!transporter) {
      transporter = mailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: false,
        connectionTimeout: timeoutMs,
        greetingTimeout: timeoutMs,
        socketTimeout: timeoutMs,
      });
      if (!transporter || typeof transporter.sendMail !== 'function') {
        transporter = null;
        fail('SMTP_UNAVAILABLE', 'The local SMTP transport is unavailable');
      }
    }
    return transporter;
  }

  async function readBoundedJson(response) {
    if (!response || response.redirected === true || response.ok !== true) {
      fail('MAILPIT_UNAVAILABLE', 'The local mailbox request failed');
    }
    const mediaType = String(response.headers?.get?.('content-type') || '').split(';', 1)[0].trim().toLowerCase();
    if (mediaType !== 'application/json') fail('MAILPIT_INVALID_RESPONSE', 'The local mailbox returned an invalid response');
    const advertised = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(advertised) && advertised > maxResponseBytes) {
      fail('MAILPIT_RESPONSE_TOO_LARGE', 'The local mailbox response exceeded its limit');
    }
    const reader = response.body?.getReader?.();
    if (!reader) fail('MAILPIT_INVALID_RESPONSE', 'The local mailbox returned an invalid response');
    const chunks = [];
    let bytes = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) fail('MAILPIT_INVALID_RESPONSE', 'The local mailbox returned an invalid response');
        bytes += part.value.byteLength;
        if (bytes > maxResponseBytes) fail('MAILPIT_RESPONSE_TOO_LARGE', 'The local mailbox response exceeded its limit');
        chunks.push(Buffer.from(part.value));
      }
    } finally {
      try { reader.releaseLock(); } catch {}
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
      return parsed;
    } catch (error) {
      if (error instanceof XssLocalMailError) throw error;
      fail('MAILPIT_INVALID_RESPONSE', 'The local mailbox returned an invalid response');
    }
  }

  async function requestJson(relativePath) {
    requireOpen();
    const url = new URL(relativePath, base);
    if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) {
      fail('MAILPIT_INVALID_REQUEST', 'The local mailbox request is invalid');
    }
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new XssLocalMailError('MAILPIT_TIMEOUT', 'The local mailbox request timed out'));
      }, timeoutMs);
    });
    try {
      return await Promise.race([
        Promise.resolve().then(() => fetcher(url.toString(), {
          method: 'GET',
          redirect: 'error',
          credentials: 'omit',
          headers: { Accept: 'application/json' },
          signal: controller.signal,
        })).then(readBoundedJson),
        deadline,
      ]);
    } catch (error) {
      if (error instanceof XssLocalMailError) throw error;
      if (controller.signal.aborted) fail('MAILPIT_TIMEOUT', 'The local mailbox request timed out');
      fail('MAILPIT_UNAVAILABLE', 'The local mailbox request failed');
    } finally {
      clearTimeout(timer);
    }
  }

  function exactRecipients(message, expected) {
    if (!Array.isArray(message?.To) || message.To.length !== 1) return false;
    const address = message.To[0]?.Address ?? message.To[0]?.Email;
    return address === expected;
  }

  function summary(message, recipient) {
    if (!message || typeof message !== 'object' || !exactRecipients(message, recipient)) return null;
    const id = boundedString(message.ID, 'Mailpit message ID', 256, { allowEmpty: false });
    const messageId = boundedString(message.MessageID, 'SMTP Message-ID', 998, { allowEmpty: false });
    if (id === messageId) fail('MAILPIT_INVALID_RESPONSE', 'Mailpit message identifiers are ambiguous');
    return {
      id,
      messageId,
      from: boundedString(message.From?.Address ?? message.From?.Email, 'mail sender', 320, { allowEmpty: false }),
      subject: boundedString(message.Subject ?? '', 'mail subject', 4096),
      timestamp: boundedString(message.Created ?? '', 'mail timestamp', 256),
      read: Boolean(message.Read),
    };
  }

  async function sendEmail(recipient, subject, body, ownerKey, options = {}) {
    requireOpen();
    const owned = ownerAddress(recipient);
    if (typeof ownerKey !== 'string' || ownerKey !== owned.ownerId) {
      fail('RECIPIENT_OWNER_MISMATCH', 'The XSS inbox does not belong to this owner');
    }
    boundedString(subject, 'mail subject', 4096);
    boundedString(body, 'mail body', maxMessageBytes);
    if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some(key => key !== 'html')) throw new TypeError('Invalid mail options');
    const html = Object.hasOwn(options, 'html')
      ? boundedString(options.html, 'mail HTML body', maxMessageBytes)
      : undefined;
    let info;
    try {
      info = await getTransport().sendMail({ from: FIXED_SENDER, to: recipient, subject, text: body, ...(html === undefined ? {} : { html }) });
    } catch {
      fail('SMTP_UNAVAILABLE', 'The local SMTP transport failed');
    }
    const messageId = typeof info?.messageId === 'string' ? info.messageId.trim() : '';
    const accepted = Array.isArray(info?.accepted) ? info.accepted.map(normalizeMailboxAddress) : [];
    const rejected = Array.isArray(info?.rejected) ? info.rejected.map(normalizeMailboxAddress) : [];
    if (!messageId || accepted.length !== 1 || accepted[0] !== recipient || rejected.length !== 0) {
      fail('SMTP_ACCEPTANCE_UNVERIFIED', 'SMTP acceptance could not be verified');
    }
    return Object.freeze({ success: true, messageId, sentTo: recipient, sentFrom: FIXED_SENDER,
      subject, accepted: Object.freeze([recipient]), rejected: Object.freeze([]), smtpAccepted: true,
      deliveryConfirmed: false });
  }

  async function fetchEmails(recipient, filterBySender = true) {
    requireOpen();
    canonicalize(recipient);
    const query = new URLSearchParams({ query: `to:"${recipient}"`, limit: String(maxMessages) });
    const payload = await requestJson(`api/v1/search?${query}`);
    if (!Array.isArray(payload.messages) || payload.messages.length > maxMessages) {
      fail('MAILPIT_INVALID_RESPONSE', 'The local mailbox returned an invalid message list');
    }
    const emails = payload.messages.map(message => summary(message, recipient)).filter(Boolean)
      .filter(message => !filterBySender || normalizeMailboxAddress(message.from) === FIXED_SENDER);
    return { success: true, emails };
  }

  async function fetchEmail(recipient, emailId) {
    requireOpen();
    canonicalize(recipient);
    boundedString(emailId, 'Mailpit message ID', 256, { allowEmpty: false });
    const payload = await requestJson(`api/v1/message/${encodeURIComponent(emailId)}`);
    const item = summary(payload, recipient);
    if (!item || item.id !== emailId || normalizeMailboxAddress(item.from) !== FIXED_SENDER) {
      fail('MAILPIT_MESSAGE_MISMATCH', 'The mailbox message does not match this owned inbox');
    }
    const htmlBody = boundedString(payload.HTML ?? '', 'mail HTML body', maxMessageBytes);
    const body = boundedString(payload.Text ?? '', 'mail text body', maxMessageBytes);
    return { success: true, email: { ...item, body, htmlBody } };
  }

  function getStatus() {
    return Object.freeze({ initialized: transporter !== null, targetEmail: FIXED_SENDER, provider: 'mailpit', method: 'SMTP' });
  }

  async function close() {
    if (closed) return;
    closed = true;
    const active = transporter;
    transporter = null;
    if (active && typeof active.close === 'function') await active.close();
  }

  return Object.freeze({ sendEmail, getStatus, canonicalize, fetchEmails, fetchEmail, close });
}

module.exports = { createXssLocalMail, XssLocalMailError };
