'use strict';

const LOCAL_SENDER = 'attacker@dvaia.invalid';
const PROVIDERS = new Set(['mailpit', 'gmail']);

function configuredProvider(value) {
  const provider = String(value || 'gmail').trim().toLowerCase();
  if (!PROVIDERS.has(provider)) throw new Error(`Unsupported XSS_MAIL_PROVIDER: ${provider}`);
  return provider;
}

function assertIdentity(userId, userKey) {
  if (!Number.isSafeInteger(userId) || userId <= 0) throw new TypeError('A positive platform user ID is required');
  if (typeof userKey !== 'string' || !userKey.trim() || Buffer.byteLength(userKey, 'utf8') > 256
    || /[\0\r\n]/.test(userKey)) throw new TypeError('A bounded owner key is required');
}

function createXssMailProviderSelector({
  readProvider = () => process.env.XSS_MAIL_PROVIDER,
  createLocal = () => {
    const config = require('./mcp/config');
    return require('./xssLocalMail').createXssLocalMail({
      smtpHost: config.MAILPIT_SMTP_HOST,
      smtpPort: config.MAILPIT_SMTP_PORT,
      apiUrl: config.MAILPIT_API_URL,
      timeoutMs: config.BACKEND_TIMEOUT_MS,
    });
  },
  getGmail = () => require('./gmailEmailAgentService'),
  getExternalMailbox = () => require('./sharkLasersScraper'),
  getEmailStore = () => require('./emailWorkshopStore'),
} = {}) {
  let cached = null;
  let closed = false;
  let closePromise = null;

  function getXssMailProvider() {
    if (closed) throw new Error('XSS mail provider selector is closed');
    const provider = configuredProvider(readProvider());
    if (cached?.provider === provider) return cached;
    if (cached) throw new Error('XSS mail provider cannot change after initialization');
    if (provider === 'mailpit') {
      const adapter = createLocal();
      if (!adapter || typeof adapter.sendEmail !== 'function'
        || typeof adapter.fetchEmails !== 'function' || typeof adapter.fetchEmail !== 'function') {
        throw new TypeError('Invalid local XSS mail adapter');
      }
      cached = Object.freeze({ provider, mode: 'local', transport: adapter, mailbox: adapter });
    } else {
      const transport = getGmail();
      const mailbox = getExternalMailbox();
      if (!transport || typeof transport.sendEmail !== 'function' || typeof transport.getStatus !== 'function'
        || !mailbox || typeof mailbox.fetchEmails !== 'function' || typeof mailbox.fetchEmail !== 'function') {
        throw new TypeError('Invalid external XSS mail adapters');
      }
      cached = Object.freeze({ provider, mode: 'external', transport, mailbox });
    }
    return cached;
  }

  async function resolveXssMailContext(userId, userKey) {
    assertIdentity(userId, userKey);
    const selected = getXssMailProvider();
    if (selected.provider === 'mailpit') {
      return Object.freeze({ email: `xss-${userId}@dvaia.invalid`, mode: 'local', provider: 'mailpit',
        editable: false, sender: LOCAL_SENDER });
    }
    const [email, status] = await Promise.all([
      Promise.resolve(getEmailStore().getConfiguredEmail(userKey)),
      Promise.resolve(selected.transport.getStatus()),
    ]);
    const sender = typeof status?.targetEmail === 'string' ? status.targetEmail.trim().toLowerCase() : '';
    if (!sender || /[\s\r\n]/.test(sender)) throw new Error('Gmail sender configuration is unavailable');
    return Object.freeze({ email: typeof email === 'string' ? email.trim().toLowerCase() : '',
      mode: 'external', provider: 'gmail', editable: true, sender });
  }

  function refreshXssMailProvider() {
    if (closed) throw new Error('XSS mail provider selector is closed');
    const retired = cached;
    cached = null;
    // The shared Gmail service owns its reconfiguration. Only close the
    // disposable local transport when switching away from Mailpit.
    if (retired?.provider === 'mailpit') {
      try {
        const closing = retired.transport?.close?.();
        if (closing && typeof closing.catch === 'function') closing.catch(() => {});
      } catch {}
    }
  }

  function close() {
    if (closePromise) return closePromise;
    closed = true;
    const transport = cached?.transport;
    cached = null;
    closePromise = Promise.resolve().then(() => {
      if (transport && typeof transport.close === 'function') return transport.close();
      return undefined;
    });
    return closePromise;
  }

  return Object.freeze({ getXssMailProvider, resolveXssMailContext, refreshXssMailProvider, close });
}

const singleton = createXssMailProviderSelector();

module.exports = {
  getXssMailProvider: singleton.getXssMailProvider,
  resolveXssMailContext: singleton.resolveXssMailContext,
  refreshXssMailProvider: singleton.refreshXssMailProvider,
  close: singleton.close,
  createXssMailProviderSelector,
  LOCAL_SENDER,
};
