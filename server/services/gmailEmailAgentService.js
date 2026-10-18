/**
 * Gmail Email Agent Service (SMTP Version)
 * Handles email operations for the Email Agent workshop:
 * - Sends attack emails FROM indirectpromptinjection@gmail.com TO user's temp inbox
 * Uses Gmail SMTP with App Password authentication (no OAuth required).
 */

const nodemailer = require('nodemailer');

const TARGET_EMAIL = process.env.GMAIL_USER || 'indirectpromptinjection@gmail.com';

const SUSPICIOUS_KEYWORDS = [
  'IGNORE',
  'SYSTEM:',
  'SYSTEM INSTRUCTION',
  'ACT AS',
  'YOU ARE NOW',
  'HIDDEN INSTRUCTION',
  'OVERRIDE',
  'FORGET PREVIOUS',
  'DISREGARD',
  'NEW ROLE',
  'PRETEND',
  'ROLEPLAY',
  'IGNORE ALL PREVIOUS',
  'IGNORE PREVIOUS INSTRUCTIONS',
  '<!-- HIDDEN',
  '[SYSTEM',
  'WITHOUT RESTRICTIONS',
  'UNRESTRICTED'
];

const ALLOWED_TEMP_DOMAINS = [
  'sharklasers.com',
  'guerrillamail.com',
  'guerrillamail.org',
  'guerrillamail.net',
  'guerrillamail.biz',
  'guerrillamail.de',
  'grr.la',
  'spam4.me',
  'pokemail.net',
  'temp-mail.org',
  '10minutemail.com',
  'tempmail.com'
];

const rateLimitMap = new Map();
const sendRateLimitMap = new Map();
const RATE_LIMIT_MAX = 100;
const SEND_RATE_LIMIT_MAX = 50;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour

class GmailEmailAgentService {
  constructor({ transporter = null, initialized = false, targetEmail = TARGET_EMAIL } = {}) {
    this.transporter = transporter;
    this.initialized = initialized;
    this.targetEmail = targetEmail;
    this.initError = null;
    this.lastInitAttempt = null;
  }

  async initialize(forceRetry = false) {
    // If already initialized, return true
    if (this.initialized) return true;
    
    // Allow retry if forced or if last attempt was more than 30 seconds ago
    const now = Date.now();
    if (!forceRetry && this.lastInitAttempt && (now - this.lastInitAttempt) < 30000) {
      return false;
    }
    this.lastInitAttempt = now;
    
    try {
      const gmailUser = process.env.GMAIL_USER;
      const gmailAppPassword = process.env.GMAIL_APP_PASSWORD;
      
      console.log('[GmailService] Initializing SMTP...');
      console.log('[GmailService] GMAIL_USER configured:', !!gmailUser);
      console.log('[GmailService] GMAIL_APP_PASSWORD configured:', !!gmailAppPassword);
      
      if (!gmailUser) {
        this.initError = 'Gmail SMTP not configured. Set GMAIL_USER environment variable in .env file.';
        console.warn('[GmailService]', this.initError);
        return false;
      }
      
      if (!gmailAppPassword) {
        this.initError = 'Gmail SMTP not configured. Set GMAIL_APP_PASSWORD environment variable (App Password, not regular password). Generate one at https://myaccount.google.com/apppasswords';
        console.warn('[GmailService]', this.initError);
        return false;
      }

      // Try a list of host/port combos in order. Some networks block 587
      // (STARTTLS) but allow 465 (implicit SSL); GMAIL_SMTP_PORT can force one.
      // Falls back automatically so the lab works behind restrictive firewalls.
      const forcedPort = parseInt(process.env.GMAIL_SMTP_PORT, 10);
      const candidates = forcedPort
        ? [{ port: forcedPort, secure: forcedPort === 465 }]
        : [
            { port: 587, secure: false }, // STARTTLS
            { port: 465, secure: true },  // implicit SSL (often open when 587 isn't)
          ];

      let lastErr = null;
      for (const c of candidates) {
        try {
          this.transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: c.port,
            secure: c.secure,
            auth: { user: gmailUser, pass: gmailAppPassword },
            pool: true,
            maxConnections: 50,
            maxMessages: 100,
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 15000,
          });
          console.log(`[GmailService] Verifying SMTP smtp.gmail.com:${c.port} (secure=${c.secure})...`);
          const verifyPromise = this.transporter.verify();
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('SMTP verification timed out after 10 seconds')), 10000));
          await Promise.race([verifyPromise, timeoutPromise]);
          this.initialized = true;
          this.initError = null;
          this.activePort = c.port;
          console.log(`[GmailService] SMTP initialized on port ${c.port} for`, gmailUser);
          return true;
        } catch (e) {
          lastErr = e;
          console.warn(`[GmailService] port ${c.port} failed: ${e.code || e.message}`);
          try { this.transporter?.close(); } catch (_) {}
          this.transporter = null;
        }
      }
      throw lastErr || new Error('SMTP verification failed on all ports');
    } catch (err) {
      console.error('[GmailService] Initialization error:', err.code || 'TIMEOUT', err.message);
      
      // Provide detailed, helpful error messages based on error type
      if (err.message && err.message.includes('timed out')) {
        this.initError = `Gmail SMTP verification timed out — ports 587 and 465 both appear blocked by your network/firewall. Try a different network, a VPN, or set GMAIL_SMTP_PORT if your relay uses another port.`;
      } else if (err.code === 'EAUTH') {
        this.initError = `Gmail authentication failed (EAUTH). The App Password may be invalid or expired. Steps to fix: 1) Go to https://myaccount.google.com/apppasswords 2) Generate a new App Password for "Mail" 3) Update GMAIL_APP_PASSWORD in .env 4) Restart the server`;
      } else if (err.code === 'ESOCKET' || err.code === 'ECONNECTION') {
        this.initError = `Could not connect to Gmail SMTP server (${err.code}). Check your network connection and ensure port 587 is not blocked by firewall.`;
      } else if (err.code === 'ECONNREFUSED') {
        this.initError = `Connection refused to Gmail SMTP server. This may be a network or firewall issue.`;
      } else if (err.code === 'ETIMEDOUT') {
        this.initError = `Connection to Gmail SMTP server timed out. Check your network connection.`;
      } else if (err.responseCode === 535) {
        this.initError = `Gmail rejected the credentials (535). Ensure you're using an App Password, not your regular Gmail password. Generate one at https://myaccount.google.com/apppasswords`;
      } else {
        this.initError = `Gmail SMTP initialization failed: ${err.message} (${err.code || 'unknown error'})`;
      }
      
      console.error('[GmailService]', this.initError);
      return false;
    }
  }
  
  // Force re-initialization (for retry functionality)
  async reinitialize() {
    this.initialized = false;
    this.transporter = null;
    this.initError = null;
    return this.initialize(true);
  }

  checkRateLimit(userKey) {
    const now = Date.now();
    const userLimits = rateLimitMap.get(userKey) || { count: 0, windowStart: now };
    
    if (now - userLimits.windowStart > RATE_LIMIT_WINDOW_MS) {
      userLimits.count = 0;
      userLimits.windowStart = now;
    }
    
    if (userLimits.count >= RATE_LIMIT_MAX) {
      const retryAfter = Math.ceil((userLimits.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000);
      return { allowed: false, retryAfter };
    }
    
    userLimits.count++;
    rateLimitMap.set(userKey, userLimits);
    return { allowed: true };
  }

  checkSendRateLimit(userKey) {
    const now = Date.now();
    const userLimits = sendRateLimitMap.get(userKey) || { count: 0, windowStart: now };
    
    if (now - userLimits.windowStart > RATE_LIMIT_WINDOW_MS) {
      userLimits.count = 0;
      userLimits.windowStart = now;
    }
    
    if (userLimits.count >= SEND_RATE_LIMIT_MAX) {
      const retryAfter = Math.ceil((userLimits.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000);
      return { allowed: false, retryAfter, remaining: 0 };
    }
    
    userLimits.count++;
    sendRateLimitMap.set(userKey, userLimits);
    return { allowed: true, remaining: SEND_RATE_LIMIT_MAX - userLimits.count };
  }

  validateRecipientDomain(email) {
    if (!email || typeof email !== 'string') {
      return { valid: false, error: 'Invalid email address' };
    }
    
    const emailLower = email.toLowerCase().trim();
    const parts = emailLower.split('@');
    if (parts.length !== 2) {
      return { valid: false, error: 'Invalid email format' };
    }
    const [local, domain] = parts;
    // This workshop accepts one bare ASCII temp-inbox address. Reject address
    // lists and display-name/header syntax rather than letting Nodemailer turn
    // one learner field into multiple SMTP recipients.
    if (!local || !domain || local.startsWith('.') || local.endsWith('.') || local.includes('..')
      || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
      || !/^[a-z0-9.-]+$/.test(domain)) {
      return { valid: false, error: 'Invalid email format' };
    }
    if (!ALLOWED_TEMP_DOMAINS.includes(domain)) {
      return { 
        valid: false, 
        error: `Domain "${domain}" is not allowed. Only temporary email services are permitted: ${ALLOWED_TEMP_DOMAINS.slice(0, 3).join(', ')}, etc.`
      };
    }
    
    return { valid: true, domain, email: emailLower };
  }

  buildMailOptions(to, subject, body, options = {}) {
    if (!options || Object.getPrototypeOf(options) !== Object.prototype
      || Object.keys(options).some(key => key !== 'html')) {
      throw new TypeError('Invalid mail rendering options');
    }
    const htmlBody = Object.hasOwn(options, 'html')
      ? options.html
      : `<html><body><pre style="font-family: Arial, sans-serif; white-space: pre-wrap;">${body.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre></body></html>`;
    if (typeof htmlBody !== 'string' || !htmlBody.length) throw new TypeError('Invalid prebuilt HTML body');
    
    return {
      from: this.targetEmail,
      to: to,
      subject: subject,
      text: body,
      html: htmlBody
    };
  }

  async sendEmail(toEmail, subject, body, userKey, options = {}) {
    const domainCheck = this.validateRecipientDomain(toEmail);
    if (!domainCheck.valid) {
      const error = new Error(domainCheck.error);
      error.statusCode = 400;
      throw error;
    }

    const initialized = await this.initialize();
    if (!initialized) {
      throw new Error(this.initError || 'Gmail SMTP service not initialized');
    }

    const rateCheck = this.checkSendRateLimit(userKey);
    if (!rateCheck.allowed) {
      const error = new Error(`Send rate limit exceeded. Please wait ${rateCheck.retryAfter} seconds. Limit: ${SEND_RATE_LIMIT_MAX} emails per hour.`);
      error.retryAfter = rateCheck.retryAfter;
      error.statusCode = 429;
      throw error;
    }

    try {
      const requestedRecipient = domainCheck.email;
      const mailOptions = this.buildMailOptions(requestedRecipient, subject, body, options);
      const info = await this.transporter.sendMail(mailOptions);
      const messageId = typeof info?.messageId === 'string' ? info.messageId.trim() : '';
      const accepted = normalizeEnvelopeRecipients(info?.accepted);
      const rejected = normalizeEnvelopeRecipients(info?.rejected);
      if (!messageId || accepted.length !== 1 || accepted[0] !== requestedRecipient || rejected.length !== 0) {
        const error = new Error('SMTP did not return an exact acceptance receipt for the requested recipient.');
        error.code = 'SMTP_ACCEPTANCE_UNVERIFIED';
        error.statusCode = 502;
        throw error;
      }

      console.log(`[GmailService] SMTP accepted email to ${requestedRecipient}, messageId: ${messageId}`);
      
      return {
        success: true,
        messageId,
        sentTo: requestedRecipient,
        sentFrom: this.targetEmail,
        subject,
        remainingSends: rateCheck.remaining,
        requestedRecipient,
        accepted,
        rejected,
        smtpAccepted: true,
        deliveryConfirmed: false
      };
    } catch (err) {
      console.error('[GmailService] Send error:', err.message);

      if (err.code === 'SMTP_ACCEPTANCE_UNVERIFIED') throw err;
      
      if (err.code === 'EAUTH') {
        const error = new Error('Gmail authentication failed. Check GMAIL_APP_PASSWORD is correct.');
        error.statusCode = 401;
        throw error;
      }
      
      if (err.responseCode === 550 || err.responseCode === 553) {
        const error = new Error('Email rejected by server. The recipient address may be invalid.');
        error.statusCode = 400;
        throw error;
      }
      
      if (err.code === 'EENVELOPE') {
        const error = new Error('Invalid email envelope. Check sender and recipient addresses.');
        error.statusCode = 400;
        throw error;
      }
      
      throw new Error(err.message || 'Failed to send email via SMTP');
    }
  }

  getAllowedDomains() {
    return [...ALLOWED_TEMP_DOMAINS];
  }

  detectSuspiciousContent(body) {
    if (!body) return { containsSuspiciousContent: false, suspiciousKeywords: [] };

    const upperBody = body.toUpperCase();
    const found = [];

    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (upperBody.includes(keyword.toUpperCase())) {
        found.push(keyword);
      }
    }

    return {
      containsSuspiciousContent: found.length > 0,
      suspiciousKeywords: found
    };
  }

  isAvailable() {
    return this.initialized && !this.initError;
  }

  getStatus() {
    return {
      initialized: this.initialized,
      error: this.initError,
      targetEmail: this.targetEmail,
      method: 'SMTP'
    };
  }

  // Close transporter connections (for graceful shutdown)
  async close() {
    if (this.transporter) {
      this.transporter.close();
      this.transporter = null;
      this.initialized = false;
      console.log('[GmailService] SMTP transporter closed');
    }
  }
}

function normalizeEnvelopeRecipients(value) {
  if (!Array.isArray(value)) return [];
  return value.map(recipient => typeof recipient === 'string' ? recipient.trim().toLowerCase() : null)
    .filter(Boolean);
}

module.exports = new GmailEmailAgentService();
module.exports.GmailEmailAgentService = GmailEmailAgentService;
