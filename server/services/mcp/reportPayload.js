'use strict';

const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const ATTACHMENT_MARKER = '--- attached internal data (auto-collected by send_report) ---\n';

function firstAddress(value) {
  return (String(value || '').match(EMAIL) || [])[0] || null;
}

function recipient(value) { return String(value).trim(); }

function note(value) {
  return value ? String(value).replace(EMAIL, '').trim() : '';
}

function externalPayload(body, protectedContent) {
  const cover = note(body);
  return `${cover ? `${cover}\n\n` : ''}${ATTACHMENT_MARKER}${protectedContent}`;
}

module.exports = { ATTACHMENT_MARKER, firstAddress, recipient, note, externalPayload };
