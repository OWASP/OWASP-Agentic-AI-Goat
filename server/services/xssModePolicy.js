'use strict';

function effectiveXssMode(mode) {
  if (mode === null || mode === undefined || mode === 'vuln') return 'vuln';
  if (mode === 'fixed') return 'fixed';
  throw new TypeError('Unsupported XSS workshop mode');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

// This is the actual content sent to the chat's HTML insertion sink. The
// vulnerable mode deliberately preserves the original teaching payload.
function renderChatHtml(value, mode) {
  return effectiveXssMode(mode) === 'fixed' ? escapeHtml(value) : String(value ?? '');
}

// The builder preview is parsed as a full document, so fixed mode must make
// the entire persisted source inert rather than merely removing known tags.
function renderEmailDocument(value, mode) {
  if (effectiveXssMode(mode) !== 'fixed') return String(value ?? '');
  return `<!doctype html><html><head><meta charset="utf-8"></head><body><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${escapeHtml(value)}</pre></body></html>`;
}

async function assertXssAttemptModeCurrent({ ownerId, workshopKey, attempt, execution, readScope }) {
  if (!attempt || typeof readScope !== 'function') throw new TypeError('Bound XSS mode scope is required');
  if (attempt.userId !== undefined && String(attempt.userId) !== String(ownerId)
      || attempt.workshopKey !== undefined && attempt.workshopKey !== workshopKey) {
    throw Object.assign(new Error('XSS attempt owner or workshop changed'),
      { code: 'XSS_MODE_STALE', statusCode: 409 });
  }
  await execution.check();
  const scope = await readScope(ownerId, workshopKey);
  await execution.check();
  if (scope.generation !== attempt.generation || scope.modeStamp !== attempt.modeStamp
      || effectiveXssMode(scope.mode) !== effectiveXssMode(attempt.mode)) {
    throw Object.assign(new Error('XSS mode or generation changed during the owner run'),
      { code: 'XSS_MODE_STALE', statusCode: 409 });
  }
}

module.exports = { effectiveXssMode, escapeHtml, renderChatHtml, renderEmailDocument,
  assertXssAttemptModeCurrent };
