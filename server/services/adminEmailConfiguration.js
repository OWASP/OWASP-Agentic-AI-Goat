'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const dotenv = require('dotenv');

const PROVIDERS = new Set(['gmail', 'mailpit']);
const ENV_KEYS = Object.freeze([
  'IPI_EMAIL_PROVIDER', 'XSS_MAIL_PROVIDER', 'GMAIL_USER', 'GMAIL_APP_PASSWORD', 'IPI_MAIL_HMAC_SECRET',
  'WORKSHOP_MAILPIT_SMTP_HOST', 'WORKSHOP_MAILPIT_SMTP_PORT', 'WORKSHOP_MAILPIT_API_URL',
]);

function configError(message, field) {
  const error = new Error(message);
  error.code = 'INVALID_EMAIL_CONFIGURATION';
  error.statusCode = 400;
  error.field = field;
  return error;
}

function normalizedProvider(value, field) {
  const provider = String(value || '').trim().toLowerCase();
  if (!PROVIDERS.has(provider)) throw configError('Choose Gmail/SharkLasers or Mailpit.', field);
  return provider;
}

function configuredProvider(value, fallback) {
  const provider = String(value || fallback).trim().toLowerCase();
  return PROVIDERS.has(provider) ? provider : fallback;
}

function validateCredential(value, field) {
  if (typeof value !== 'string' || !value.trim()) throw configError(`${field} is required when Gmail is selected.`, field);
  const normalized = value.trim();
  if (normalized.length > 320 || /[\0\r\n]/.test(normalized)) throw configError(`Enter a valid ${field}.`, field);
  return normalized;
}

function serializeEnvValue(value) {
  return /^[A-Za-z0-9._:@/+={}-]*$/.test(value) ? value : JSON.stringify(value);
}

function mailpitInboxUrl(value) {
  // Prefer an explicit public inbox URL (AWS) over the loopback API URL.
  try {
    const url = new URL(String(value || process.env.MAILPIT_PUBLIC_INBOX_URL || 'http://127.0.0.1:8025'));
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return null;
    return `${url.origin}${url.pathname.replace(/\/$/, '')}`;
  } catch { return null; }
}

function updateEnvText(source, updates) {
  const values = new Map(Object.entries(updates));
  const seen = new Set();
  const lines = String(source || '').split(/\r?\n/).map(line => {
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(?:.*)$/);
    if (!match || !values.has(match[1])) return line;
    seen.add(match[1]);
    return `${match[1]}=${serializeEnvValue(values.get(match[1]))}`;
  });
  for (const key of ENV_KEYS) if (values.has(key) && !seen.has(key)) lines.push(`${key}=${serializeEnvValue(values.get(key))}`);
  return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}

async function atomicWritePrivateEnv(envPath, content) {
  const directory = path.dirname(envPath);
  const temporary = path.join(directory, `.${path.basename(envPath)}.mail-config-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
  let handle;
  try {
    handle = await fs.open(temporary, 'wx', 0o600);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
  } finally {
    await handle?.close();
  }
  try {
    await fs.rename(temporary, envPath);
    await fs.chmod(envPath, 0o600);
    const dir = await fs.open(directory, 'r');
    try { await dir.sync(); } finally { await dir.close(); }
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

function applyRuntimeEmailConfiguration(updates) {
  for (const [key, value] of Object.entries(updates)) process.env[key] = value;
  // Each provider switch is explicit and happens only after the private file
  // is durably committed. New workshop operations resolve these fresh adapters.
  require('./gmailEmailAgentService').reconfigureFromEnvironment();
  require('./ipiEmailProvider').refreshIpiEmailProvider();
  require('./xssMailProvider').refreshXssMailProvider();
  require('./xssEmailDispatch').refreshXssEmailDispatch();
}

function createAdminEmailConfiguration({
  envPath = path.resolve(__dirname, '../..', '.env'),
  readProcessEnv = () => process.env,
  applyRuntime = applyRuntimeEmailConfiguration,
} = {}) {
  async function readPrivateEnv() {
    let stat;
    try { stat = await fs.lstat(envPath); } catch (error) {
      if (error.code === 'ENOENT') throw configError('Private application configuration is unavailable. Run setup first.');
      throw error;
    }
    if (!stat.isFile() || stat.isSymbolicLink()) throw configError('Private application configuration is unavailable.');
    if (stat.size > 256 * 1024) throw configError('Private application configuration is too large.');
    return fs.readFile(envPath, 'utf8');
  }

  async function status() {
    const saved = dotenv.parse(await readPrivateEnv());
    const running = readProcessEnv();
    const ipiProvider = configuredProvider(saved.IPI_EMAIL_PROVIDER, 'mailpit');
    const xssProvider = configuredProvider(saved.XSS_MAIL_PROVIDER, 'gmail');
    return Object.freeze({
      ipiProvider,
      xssProvider,
      gmailConfigured: Boolean(String(saved.GMAIL_USER || '').trim() && String(saved.GMAIL_APP_PASSWORD || '').trim()),
      mailpitSigningConfigured: Boolean(String(saved.IPI_MAIL_HMAC_SECRET || '').trim()),
      mailpitInboxUrl: mailpitInboxUrl(saved.WORKSHOP_MAILPIT_API_URL),
      restartRequired: configuredProvider(running.IPI_EMAIL_PROVIDER, 'mailpit') !== ipiProvider
        || configuredProvider(running.XSS_MAIL_PROVIDER, 'gmail') !== xssProvider
        || String(running.GMAIL_USER || '') !== String(saved.GMAIL_USER || '')
        || String(running.GMAIL_APP_PASSWORD || '') !== String(saved.GMAIL_APP_PASSWORD || ''),
    });
  }

  async function save(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw configError('Email configuration is required.');
    const text = await readPrivateEnv();
    const current = dotenv.parse(text);
    const ipiProvider = normalizedProvider(input.ipiProvider, 'ipiProvider');
    const xssProvider = normalizedProvider(input.xssProvider, 'xssProvider');
    const hasUser = Object.prototype.hasOwnProperty.call(input, 'gmailUser');
    const hasPassword = Object.prototype.hasOwnProperty.call(input, 'gmailAppPassword');
    if (hasUser !== hasPassword) throw configError('Enter both Gmail address and App Password, or leave both fields blank.', hasUser ? 'gmailAppPassword' : 'gmailUser');
    const usingGmail = ipiProvider === 'gmail' || xssProvider === 'gmail';
    const gmailUser = hasUser ? validateCredential(input.gmailUser, 'gmailUser') : String(current.GMAIL_USER || '').trim();
    const gmailAppPassword = hasPassword ? validateCredential(input.gmailAppPassword, 'gmailAppPassword') : String(current.GMAIL_APP_PASSWORD || '').trim();
    if (usingGmail && (!gmailUser || !gmailAppPassword)) {
      throw configError('Configure a Gmail address and App Password before selecting Gmail/SharkLasers.', 'gmailUser');
    }
    const updates = { IPI_EMAIL_PROVIDER: ipiProvider, XSS_MAIL_PROVIDER: xssProvider };
    if (hasUser) {
      updates.GMAIL_USER = gmailUser;
      updates.GMAIL_APP_PASSWORD = gmailAppPassword;
    }
    if (ipiProvider === 'mailpit' && String(current.IPI_MAIL_HMAC_SECRET || '').trim().length < 32) {
      updates.IPI_MAIL_HMAC_SECRET = crypto.randomBytes(32).toString('hex');
    }
    if (ipiProvider === 'mailpit' || xssProvider === 'mailpit') {
      updates.WORKSHOP_MAILPIT_SMTP_HOST = String(current.WORKSHOP_MAILPIT_SMTP_HOST || '127.0.0.1').trim();
      updates.WORKSHOP_MAILPIT_SMTP_PORT = String(current.WORKSHOP_MAILPIT_SMTP_PORT || '1025').trim();
      updates.WORKSHOP_MAILPIT_API_URL = String(current.WORKSHOP_MAILPIT_API_URL || 'http://127.0.0.1:8025').trim();
    }
    await atomicWritePrivateEnv(envPath, updateEnvText(text, updates));
    applyRuntime(updates);
    return status();
  }

  return Object.freeze({ status, save });
}

module.exports = { createAdminEmailConfiguration, updateEnvText, serializeEnvValue, mailpitInboxUrl, applyRuntimeEmailConfiguration };
