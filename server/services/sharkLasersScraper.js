/**
 * SharkLasers (GuerrillaMail) Email Fetcher
 * Fetches emails from temporary SharkLasers/GuerrillaMail inboxes using their public API.
 * Used by the Email Agent workshop to retrieve attack emails.
 */

const axios = require('axios');

const GUERRILLAMAIL_API = 'https://www.guerrillamail.com/ajax.php';
const TARGET_SENDER = 'indirectpromptinjection@gmail.com';

const SUPPORTED_DOMAINS = [
  'sharklasers.com',
  'guerrillamail.com',
  'guerrillamail.org',
  'guerrillamail.net',
  'guerrillamail.biz',
  'guerrillamail.de',
  'grr.la',
  'spam4.me',
  'pokemail.net'
];

// GuerrillaMail SID tokens go stale after a while; a session reused past this
// window silently returns an empty inbox (no error), which looks like "mail
// never arrived". Re-init proactively once a session is older than the TTL.
const SESSION_TTL_MS = 5 * 60 * 1000; // 5 min

class SharkLasersScraper {
  constructor() {
    this.sessions = new Map();
  }

  /**
   * Return a valid session for `email`, re-initialising when it is missing or
   * older than SESSION_TTL_MS (stale SIDs silently return an empty inbox).
   * @param {boolean} force - always re-init (used to retry after an empty poll).
   */
  async getFreshSession(email, force = false) {
    email = this.canonicalize(email);
    const existing = this.sessions.get(email);
    const stale = existing && (Date.now() - (existing.createdAt || 0) > SESSION_TTL_MS);
    if (!existing || stale || force) {
      await this.initSession(email);
    }
    return this.sessions.get(email);
  }

  /**
   * Canonicalise a SharkLasers/GuerrillaMail address to its BASE inbox by
   * stripping any "+alias" sub-address from the local part. GuerrillaMail keys
   * inboxes by the base username, and its own UI hands out plus-aliases
   * (e.g. y17gk6+3go9kepz7a638@sharklasers.com) that map to the base inbox
   * (y17gk6@…). Retrieving with the raw alias opens a DIFFERENT session and the
   * attack email is never found — so we always work against the base inbox.
   */
  canonicalize(email) {
    const raw = String(email || '').trim().toLowerCase();
    const at = raw.indexOf('@');
    if (at < 0) return raw;
    const local = raw.slice(0, at).split('+')[0]; // drop +alias
    return `${local}${raw.slice(at)}`;
  }

  getSupportedDomains() {
    return [...SUPPORTED_DOMAINS];
  }

  getTargetSender() {
    return TARGET_SENDER;
  }

  isValidDomain(email) {
    if (!email || typeof email !== 'string') return false;
    const domain = email.toLowerCase().split('@')[1];
    return SUPPORTED_DOMAINS.includes(domain);
  }

  /**
   * Initialize a session with GuerrillaMail for a specific email address
   */
  async initSession(email) {
    if (!this.isValidDomain(email)) {
      throw new Error(`Invalid domain. Supported: ${SUPPORTED_DOMAINS.slice(0, 3).join(', ')}...`);
    }

    email = this.canonicalize(email);
    const emailUsername = email.split('@')[0];
    
    try {
      const response = await axios.post(
        `${GUERRILLAMAIL_API}?f=set_email_user`,
        `email_user=${encodeURIComponent(emailUsername)}`,
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000
        }
      );

      if (response.data && response.data.sid_token) {
        this.sessions.set(email, {
          sidToken: response.data.sid_token,
          emailAddr: response.data.email_addr,
          createdAt: Date.now()
        });
        return {
          success: true,
          emailAddr: response.data.email_addr,
          sidToken: response.data.sid_token
        };
      }

      throw new Error('Failed to initialize GuerrillaMail session');
    } catch (err) {
      console.error('[SharkLasers] Session init error:', err.message);
      throw new Error(`Failed to connect to GuerrillaMail: ${err.message}`);
    }
  }

  /**
   * Fetch emails from the inbox
   */
  async fetchEmails(email, filterBySender = true) {
    // One poll against the current session; returns the raw GuerrillaMail list
    // (null when the SID is stale/invalid, so the caller can re-init and retry).
    const pollOnce = async (session) => {
      const response = await axios.get(
        `${GUERRILLAMAIL_API}?f=get_email_list&offset=0&sid_token=${session.sidToken}`,
        { timeout: 10000 }
      );
      // A stale SID comes back without a usable `list` — signal that to retry.
      if (!response.data || !Array.isArray(response.data.list)) return null;
      return response.data.list;
    };

    try {
      let session = await this.getFreshSession(email);
      let list = await pollOnce(session);
      // Empty or missing list can mean an expired SID rather than an empty inbox.
      // Re-initialise the session ONCE and retry so a stale token can't silently
      // hide a delivered attack email.
      if (!list || list.length === 0) {
        session = await this.getFreshSession(email, true); // force re-init
        const retry = await pollOnce(session);
        if (Array.isArray(retry)) list = retry;
      }
      if (!Array.isArray(list)) list = [];

      let emails = list;
      if (filterBySender) {
        emails = emails.filter(e =>
          e.mail_from && e.mail_from.toLowerCase().includes('indirectpromptinjection')
        );
      }

      return {
        success: true,
        emails: emails.map(e => ({
          id: e.mail_id,
          from: e.mail_from,
          subject: e.mail_subject,
          timestamp: e.mail_timestamp,
          read: e.mail_read === '1'
        }))
      };
    } catch (err) {
      console.error('[SharkLasers] Fetch emails error:', err.message);
      throw new Error(`Failed to fetch emails: ${err.message}`);
    }
  }

  /**
   * Fetch a specific email by ID
   */
  async fetchEmail(email, emailId) {
    // Fetch the body against a given session; returns null when the SID is stale
    // (GuerrillaMail replies without a mail_body), so the caller can retry.
    const fetchOnce = async (session) => {
      const response = await axios.get(
        `${GUERRILLAMAIL_API}?f=fetch_email&email_id=${emailId}&sid_token=${session.sidToken}`,
        { timeout: 10000 }
      );
      if (!response.data || response.data.mail_body == null) return null;
      return response.data;
    };

    try {
      let session = await this.getFreshSession(email);
      let data = await fetchOnce(session);
      if (!data) {
        // Stale SID → re-init once and retry before giving up.
        session = await this.getFreshSession(email, true);
        data = await fetchOnce(session);
      }
      if (!data) {
        throw new Error('Email not found');
      }
      const response = { data };

      const plainText = this.stripHtml(response.data.mail_body || '');

      return {
        success: true,
        email: {
          id: response.data.mail_id,
          from: response.data.mail_from,
          subject: response.data.mail_subject,
          body: plainText,
          htmlBody: response.data.mail_body,
          timestamp: response.data.mail_timestamp
        }
      };
    } catch (err) {
      console.error('[SharkLasers] Fetch email error:', err.message);
      throw new Error(`Failed to fetch email: ${err.message}`);
    }
  }

  /**
   * Fetch the most recent email from the target sender
   */
  async fetchLatestFromSender(email) {
    const result = await this.fetchEmails(email, true);
    
    if (!result.emails || result.emails.length === 0) {
      return {
        success: false,
        error: `No emails found from ${TARGET_SENDER}. The email may take 1-2 minutes to arrive. Please try again.`
      };
    }

    // Get the most recent email
    const latestEmail = result.emails[0];
    return this.fetchEmail(email, latestEmail.id);
  }

  /**
   * Strip HTML tags from email body
   */
  stripHtml(html) {
    if (!html) return '';
    
    let text = html;
    
    // Remove script and style tags completely
    text = text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    text = text.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
    
    // Replace <br> and </p> with newlines
    text = text.replace(/<br\s*\/?>/gi, '\n');
    text = text.replace(/<\/p>/gi, '\n\n');
    text = text.replace(/<\/div>/gi, '\n');
    
    // Remove all other HTML tags
    text = text.replace(/<[^>]+>/g, '');
    
    // Decode HTML entities
    text = text.replace(/&nbsp;/g, ' ');
    text = text.replace(/&amp;/g, '&');
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&apos;/g, "'");
    
    // Clean up extra whitespace
    text = text.replace(/\n\s*\n\s*\n/g, '\n\n');
    text = text.trim();
    
    return text;
  }

  /**
   * Clear session for an email
   */
  clearSession(email) {
    this.sessions.delete(email);
  }
}

module.exports = new SharkLasersScraper();
