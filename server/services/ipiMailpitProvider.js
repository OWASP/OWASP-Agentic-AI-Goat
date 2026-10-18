'use strict';

const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const gmailInspection = require('./gmailEmailAgentService');

const DEFAULT_DOMAIN = 'dvaia.invalid';
const DEFAULT_SENDER = `indirectpromptinjection@${DEFAULT_DOMAIN}`;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_MESSAGE_BYTES = 512 * 1024;
const MAX_MESSAGES = 50;

function bounded(value, name, max, {empty = true} = {}) {
  if (typeof value !== 'string' || (!empty && value.length === 0) || Buffer.byteLength(value, 'utf8') > max) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function normalize(value) { return typeof value === 'string' ? value.trim().toLowerCase() : ''; }

function createIpiMailpitProvider({
  smtpHost = process.env.MAILPIT_SMTP_HOST || '127.0.0.1',
  smtpPort = Number(process.env.MAILPIT_SMTP_PORT || 1025),
  apiUrl = process.env.MAILPIT_API_URL || 'http://127.0.0.1:8025',
  domain = process.env.IPI_MAIL_DOMAIN || DEFAULT_DOMAIN,
  sender = process.env.IPI_MAIL_FROM || DEFAULT_SENDER,
  hmacSecret = process.env.IPI_MAIL_HMAC_SECRET,
  fetcher = globalThis.fetch,
  mailer = nodemailer,
  timeoutMs = Number(process.env.IPI_MAIL_TIMEOUT_MS || DEFAULT_TIMEOUT_MS),
} = {}) {
  if (!hmacSecret || typeof hmacSecret !== 'string' || hmacSecret.length < 32) throw new Error('IPI_MAIL_HMAC_SECRET must be a private 32-character secret');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new TypeError('Invalid Mailpit timeout');
  if (!/^[a-z0-9.-]+$/.test(domain) || !/^[^@\s]+@[^@\s]+$/.test(sender)) throw new TypeError('Invalid local IPI mail identity');
  if (!Number.isSafeInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535) throw new TypeError('Invalid Mailpit SMTP port');
  if (typeof fetcher !== 'function' || typeof mailer?.createTransport !== 'function') throw new TypeError('Mailpit transport dependencies are required');
  const base = new URL(apiUrl);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) throw new TypeError('Invalid Mailpit API URL');
  const baseOrigin = base.origin;
  base.pathname = `${base.pathname.replace(/\/+$/, '')}/`;
  let transporter = null;
  let closed = false;
  let initialized = false;
  let lifecycleEpoch = 0;
  let initError = null;

  function contextOf(context) {
    const ownerId = Number(context?.ownerId);
    const generation = String(context?.generation ?? '');
    if (!Number.isSafeInteger(ownerId) || ownerId < 1 || !/^\d+$/.test(generation) || Number(generation) < 0 || !Number.isSafeInteger(Number(generation)) || String(Number(generation)) !== generation) throw new TypeError('Invalid IPI mail owner context');
    return { ownerId, generation };
  }
  function addressFor(context) {
    const {ownerId, generation} = contextOf(context);
    const token = crypto.createHmac('sha256', hmacSecret).update(`${ownerId}|${generation}`).digest('base64url').slice(0, 32);
    return `ipi-${token}@${domain}`;
  }
  function assertRecipient(recipient, context) {
    const expected = addressFor(context);
    if (normalize(recipient) !== expected.toLowerCase()) {
      const error = new Error('The local IPI inbox does not belong to this owner or generation');
      error.statusCode = 403;
      error.code = 'IPI_RECIPIENT_OWNER_MISMATCH';
      throw error;
    }
    return expected;
  }
  function validateRecipientDomain(email, context) {
    try { const expected = assertRecipient(email, context); return {valid:true, domain, email:expected}; }
    catch (error) { return {valid:false, error:error.message}; }
  }
  function requireOpen() { if (closed) throw new Error('The local IPI mail provider is closed'); }
  function transport() {
    requireOpen();
    if (!transporter) transporter = mailer.createTransport({host:smtpHost, port:smtpPort, secure:false, connectionTimeout:timeoutMs, greetingTimeout:timeoutMs, socketTimeout:timeoutMs});
    return transporter;
  }
  async function readJson(response, controller) {
    if (!response || response.redirected === true || response.ok !== true) throw new Error('Mailpit request failed');
    const type = String(response.headers?.get?.('content-type') || '').split(';',1)[0].trim().toLowerCase();
    if (type !== 'application/json') throw new Error('Mailpit returned non-JSON data');
    const advertised = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(advertised) && advertised > MAX_RESPONSE_BYTES) throw new Error('Mailpit response too large');
    const reader = response.body?.getReader?.();
    if (!reader) {
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw new Error('Mailpit response too large');
      return JSON.parse(text);
    }
    const chunks = []; let bytes = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) throw new Error('Mailpit returned an invalid body');
        bytes += part.value.byteLength;
        if (bytes > MAX_RESPONSE_BYTES) { try { await reader.cancel(); } catch {} controller?.abort(); throw new Error('Mailpit response too large'); }
        chunks.push(Buffer.from(part.value));
      }
    } finally { try { reader.releaseLock(); } catch {} }
    return JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'));
  }
  async function request(path) {
    requireOpen();
    const url = new URL(path, base);
    if (url.origin !== baseOrigin || !url.pathname.startsWith(base.pathname)) throw new Error('Invalid Mailpit request path');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try { return await readJson(await fetcher(url, {method:'GET', redirect:'error', credentials:'omit', headers:{Accept:'application/json'}, signal:controller.signal}), controller); }
    finally { clearTimeout(timer); }
  }
  function summary(message, recipient) {
    const to = message?.To?.map?.(item => normalize(item?.Address ?? item?.Email)).filter(Boolean) || [];
    if (to.length !== 1 || to[0] !== normalize(recipient)) return null;
    const id = bounded(String(message.ID || ''), 'Mailpit message ID', 256, {empty:false});
    const smtpId = bounded(String(message.MessageID || ''), 'SMTP Message-ID', 998, {empty:false});
    if (id === smtpId) throw new Error('Mailpit and SMTP message identities must differ');
    return {id, messageId:smtpId, from:bounded(String((message.From?.Address ?? message.From?.Email) || ''), 'sender', 320, {empty:false}), subject:bounded(String(message.Subject || ''), 'subject', 4096), timestamp:bounded(String(message.Created || ''), 'timestamp', 256), read:Boolean(message.Read)};
  }
  async function initialize(force = false) {
    requireOpen();
    if (initialized && !force) return true;
    const epoch = lifecycleEpoch;
    try {
      const smtp = transport();
      if (typeof smtp.verify !== 'function') throw new Error('The local SMTP transport cannot verify readiness');
      await smtp.verify();
      await request('api/v1/info');
      if (closed || epoch !== lifecycleEpoch) return false;
      initialized = true;
      initError = null;
      return true;
    } catch (error) {
      initialized = false;
      initError = /too large/i.test(error?.message || '')
        ? 'Local Mailpit response exceeded its configured limit'
        : 'Local Mailpit is unavailable';
      try { transporter?.close?.(); } catch {}
      transporter = null;
      return false;
    }
  }
  async function sendEmail(recipient, subject, body, ownerKey, context) {
    if (!await initialize()) throw Object.assign(new Error(initError), {code:'MAILPIT_UNAVAILABLE', statusCode:503});
    const owned = assertRecipient(recipient, context);
    if (String(ownerKey) !== String(context.ownerId)) throw new Error('The local IPI inbox owner is invalid');
    bounded(subject, 'subject', 4096); bounded(body, 'body', MAX_MESSAGE_BYTES);
    const info = await transport().sendMail({from:sender, to:owned, subject, text:body});
    const messageId = typeof info?.messageId === 'string' ? info.messageId.trim() : '';
    const accepted = Array.isArray(info?.accepted) ? info.accepted.map(normalize) : [];
    const rejected = Array.isArray(info?.rejected) ? info.rejected.map(normalize) : [];
    if (!messageId || accepted.length !== 1 || accepted[0] !== normalize(owned) || rejected.length) throw new Error('SMTP acceptance could not be verified');
    return {success:true, messageId, sentTo:owned, sentFrom:sender, subject, accepted:[owned], rejected:[], smtpAccepted:true, deliveryConfirmed:false};
  }
  async function fetchEmails(context, filterBySender = true) {
    if (!await initialize()) throw Object.assign(new Error(initError), {code:'MAILPIT_UNAVAILABLE', statusCode:503});
    const recipient = addressFor(context);
    const query = new URLSearchParams({query:`to:"${recipient}"`, limit:String(MAX_MESSAGES)});
    const payload = await request(`api/v1/search?${query}`);
    if (!Array.isArray(payload?.messages) || payload.messages.length > MAX_MESSAGES) throw new Error('Mailpit message list is invalid');
    const emails = payload.messages.map(item => summary(item, recipient)).filter(Boolean).filter(item => !filterBySender || normalize(item.from) === normalize(sender))
      .map(item => ({...item, provider:'mailpit', providerMessageId:item.id}));
    return {success:true, emails};
  }
  async function fetchEmail(context, emailId) {
    if (!await initialize()) throw Object.assign(new Error(initError), {code:'MAILPIT_UNAVAILABLE', statusCode:503});
    const recipient = addressFor(context); bounded(emailId, 'Mailpit message ID', 256, {empty:false});
    const payload = await request(`api/v1/message/${encodeURIComponent(emailId)}`);
    const item = summary(payload, recipient);
    if (!item || item.id !== emailId || normalize(item.from) !== normalize(sender)) throw new Error('Mailpit message does not match the current IPI inbox');
    return {success:true, email:{...item, body:bounded(String(payload.Text || ''), 'body', MAX_MESSAGE_BYTES), htmlBody:bounded(String(payload.HTML || ''), 'HTML body', MAX_MESSAGE_BYTES), provider:'mailpit', providerMessageId:item.id}};
  }
  async function close() { if (closed) return; closed = true; lifecycleEpoch += 1; initialized = false; const active = transporter; transporter = null; await active?.close?.(); }
  return Object.freeze({addressFor, validateRecipientDomain, sendEmail, fetchEmails, fetchEmail,
    initialize, reinitialize:()=>initialize(true),
    getStatus:() => ({initialized, targetEmail:sender, provider:'mailpit', method:'SMTP', error:initError}),
    getAllowedDomains:() => [domain], getSupportedDomains:() => [domain], getTargetSender:() => sender,
    detectSuspiciousContent: body => gmailInspection.detectSuspiciousContent(body), close});
}

module.exports = {createIpiMailpitProvider};
