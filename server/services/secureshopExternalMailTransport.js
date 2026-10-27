'use strict';

// This adapter is intentionally separate from the Gmail workshop service.  It
// sends only an already-persisted, server-generated external-test preview.
const nodemailer = require('nodemailer');
const {
  DISPATCH_MS,
  normalizeExternalSender,
  validateExternalMailPreview,
} = require('./secureshopExternalMailContract');

const SMTP_HOST = 'smtp.gmail.com';
const SMTP_PORT = 465;

class ExternalMailTransportError extends Error {
  constructor(code, { dispatchStarted = false, uncertain = false } = {}) {
    super('External test mail unavailable');
    this.name = 'ExternalMailTransportError';
    this.code = code;
    this.dispatchStarted = dispatchStarted;
    this.uncertain = uncertain;
  }
}

function fail(code, options) { throw new ExternalMailTransportError(code, options); }

function readExternalMailConfiguration(env = process.env) {
  const enabled = env?.SS_EXTERNAL_MAIL_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, sender: null, appPassword: null });
  const sender = typeof env.SS_EXTERNAL_MAIL_GMAIL_USER === 'string'
    ? env.SS_EXTERNAL_MAIL_GMAIL_USER : '';
  const appPassword = typeof env.SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD === 'string'
    ? env.SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD.replace(/\s/g, '') : '';
  return Object.freeze({ enabled: true, sender, appPassword });
}

function boundedConfig(config) {
  if (!config?.enabled) fail('EXTERNAL_MAIL_UNAVAILABLE');
  let sender;
  try { sender = normalizeExternalSender(config.sender); }
  catch { fail('EXTERNAL_MAIL_UNAVAILABLE'); }
  if (typeof config.appPassword !== 'string' || !/^[A-Za-z]{16}$/.test(config.appPassword)) {
    fail('EXTERNAL_MAIL_UNAVAILABLE');
  }
  return { sender, appPassword: config.appPassword };
}

function timeoutError(dispatchStarted) {
  return new ExternalMailTransportError(dispatchStarted ? 'EXTERNAL_MAIL_UNKNOWN' : 'EXTERNAL_MAIL_TIMEOUT', {
    dispatchStarted, uncertain: dispatchStarted,
  });
}

async function withDeadline(work, { signal, deadlineAt, dispatchStarted }) {
  if (signal?.aborted) throw timeoutError(dispatchStarted());
  const remaining = Math.min(DISPATCH_MS, deadlineAt - Date.now());
  if (!Number.isFinite(remaining) || remaining <= 0) throw timeoutError(dispatchStarted());
  let timer;
  let onAbort;
  try {
    return await Promise.race([
      Promise.resolve().then(() => {
        if (signal?.aborted || Date.now() >= deadlineAt) throw timeoutError(dispatchStarted());
        return work();
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(timeoutError(dispatchStarted())), remaining);
        if (signal) {
          onAbort = () => reject(timeoutError(dispatchStarted()));
          signal.addEventListener('abort', onAbort, { once: true });
        }
      }),
    ]);
  } finally {
    clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener('abort', onAbort);
  }
}

function exactAcceptance(info, recipient) {
  const messageId = typeof info?.messageId === 'string' ? info.messageId.trim() : '';
  if (!Array.isArray(info?.accepted) || !Array.isArray(info?.rejected)
      || info.accepted.length !== 1 || info.rejected.length !== 0
      || typeof info.accepted[0] !== 'string') return null;
  const accepted = info.accepted;
  if (!messageId || messageId.length > 998 || /[\r\n]/.test(messageId)
      || accepted[0] !== recipient) return null;
  return Object.freeze({ smtpAccepted: true, deliveryConfirmed: false, messageId,
    accepted: Object.freeze([recipient]), rejected: Object.freeze([]) });
}

function createExternalMailTransport({ config = readExternalMailConfiguration(), createTransport = nodemailer.createTransport } = {}) {
  if (typeof createTransport !== 'function') throw new TypeError('SMTP transport factory is required');

  function isAvailable() {
    try { boundedConfig(config); return true; } catch { return false; }
  }

  async function send(preview, { signal, deadlineAt = Date.now() + DISPATCH_MS } = {}) {
    const { sender, appPassword } = boundedConfig(config);
    let canonical;
    try { canonical = validateExternalMailPreview(preview); }
    catch { fail('EXTERNAL_MAIL_INVALID_REQUEST'); }
    if (canonical.sender !== sender) fail('EXTERNAL_MAIL_INVALID_REQUEST');
    const startedAt = Date.now();
    const effectiveDeadline = Number.isFinite(deadlineAt)
      ? Math.min(deadlineAt, startedAt + DISPATCH_MS) : NaN;
    if (signal?.aborted || !Number.isFinite(effectiveDeadline) || effectiveDeadline <= startedAt) {
      fail('EXTERNAL_MAIL_TIMEOUT');
    }
    const remaining = effectiveDeadline - startedAt;
    let transport;
    let dispatchStarted = false;
    try {
      transport = createTransport({
        host: SMTP_HOST, port: SMTP_PORT, secure: true, requireTLS: true,
        auth: { user: sender, pass: appPassword },
        tls: { servername: SMTP_HOST, rejectUnauthorized: true },
        connectionTimeout: remaining, greetingTimeout: remaining, socketTimeout: remaining,
      });
      if (!transport || typeof transport.sendMail !== 'function') fail('EXTERNAL_MAIL_UNAVAILABLE');
      const info = await withDeadline(() => {
        dispatchStarted = true;
        return transport.sendMail({ from: sender, to: canonical.recipient,
          subject: canonical.subject, text: canonical.text });
      }, { signal, deadlineAt: effectiveDeadline, dispatchStarted: () => dispatchStarted });
      const accepted = exactAcceptance(info, canonical.recipient);
      if (!accepted) fail('EXTERNAL_MAIL_UNKNOWN', { dispatchStarted: true, uncertain: true });
      return accepted;
    } catch (error) {
      if (error instanceof ExternalMailTransportError) throw error;
      fail(dispatchStarted ? 'EXTERNAL_MAIL_UNKNOWN' : 'EXTERNAL_MAIL_UNAVAILABLE', {
        dispatchStarted, uncertain: dispatchStarted,
      });
    } finally {
      // Invoke close immediately, but never let a provider's hanging close turn
      // one bounded dispatch into an unbounded request.
      try {
        const closing = Promise.resolve(transport?.close?.()).catch(() => {});
        const closeBudget = Math.max(0, effectiveDeadline - Date.now());
        let closeTimer;
        await Promise.race([closing, new Promise(resolve => {
          closeTimer = setTimeout(resolve, closeBudget);
        })]);
        clearTimeout(closeTimer);
      } catch { /* Close must not expose provider details. */ }
    }
  }

  return Object.freeze({ isAvailable, send });
}

module.exports = { SMTP_HOST, SMTP_PORT, ExternalMailTransportError, readExternalMailConfiguration,
  createExternalMailTransport };
