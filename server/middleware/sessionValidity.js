'use strict';

// JWT signature validity is necessary but cannot undo persisted revocation.
function isSessionActive(session, now = Date.now()) {
  if (!session || ![true, 1].includes(session.is_active)) return false;
  const raw = session.expires_at;
  // SQLite CURRENT_TIMESTAMP/datetime() values are UTC without a zone suffix.
  const timestamp = typeof raw === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw)
    ? raw.replace(' ', 'T') + 'Z' : raw;
  const expiresAt = new Date(timestamp).getTime();
  return Number.isFinite(expiresAt) && expiresAt > now;
}

module.exports = { isSessionActive };
