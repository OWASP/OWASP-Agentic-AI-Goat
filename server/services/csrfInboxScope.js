'use strict';

// Mailpit is a shared application service. Its per-learner addresses are
// platform ownership boundaries, separate from the intentional email gadget.
function createCsrfInboxScope({ getProvider, resolveContext }) {
  if (typeof getProvider !== 'function' || typeof resolveContext !== 'function') {
    throw new TypeError('Configured mail provider and owner context required');
  }
  return async function canonicalInbox(userId, address) {
    if (!Number.isSafeInteger(userId) || userId < 1) throw new TypeError('Authenticated learner required');
    const selected = getProvider();
    if (!selected?.mailbox?.canonicalize || !['local', 'external'].includes(selected.mode)) {
      throw new Error('Email provider configuration unavailable');
    }
    const canonical = selected.mailbox.canonicalize(address);
    if (selected.mode === 'local') {
      const context = await resolveContext(userId, String(userId));
      if (context?.mode !== 'local' || context?.editable !== false
        || canonical !== selected.mailbox.canonicalize(context.email)) {
        const error = new Error('This workshop inbox does not belong to the signed-in learner');
        error.code = 'CSRF_INBOX_OWNER_MISMATCH';
        error.statusCode = 403;
        throw error;
      }
    }
    return canonical;
  };
}
module.exports = { createCsrfInboxScope };
