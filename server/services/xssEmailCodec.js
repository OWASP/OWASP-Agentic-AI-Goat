'use strict';

const { createHash } = require('node:crypto');

const VERSION = 'xss-email.v1';
const MAX_PAYLOAD_BYTES = 65536;
const MAX_HTML_BYTES = 524288;
const HTML_PREFIX = '<html><body><pre style="font-family: Arial, sans-serif; white-space: pre-wrap;">';
const HTML_SUFFIX = '</pre></body></html>';
const MARKER_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

function bytes(value) { return Buffer.byteLength(value, 'utf8'); }
function digest(value) { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function frozen(value) {
  for (const item of Object.values(value)) if (item && typeof item === 'object') frozen(item);
  return Object.freeze(value);
}
function escapeHtmlText(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function decodeHtmlText(value) {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}
function fail(reason) { return frozen({ valid: false, reason, body: null, payload: null }); }

function assertMarker(marker) {
  if (typeof marker !== 'string' || !MARKER_PATTERN.test(marker)) {
    throw new TypeError('marker must be 16-128 URL-safe characters supplied by the server');
  }
}

function bodyParts(marker, payloadDigest, payloadBytes) {
  return {
    prefix: `Dear Customer,\r\n\r\nWe have a special reward waiting for you. Please review the details below:\r\n\r\n`
      + `[OWASP-AI-GOAT-XSS-BEGIN version=${VERSION} marker=${marker} sha256=${payloadDigest} bytes=${payloadBytes}]\r\n`,
    suffix: `\r\n[OWASP-AI-GOAT-XSS-END marker=${marker}]\r\n\r\n`
      + 'If the content is not displaying correctly, please update your browser settings.\r\n\r\n'
      + 'Regards,\r\nSecurity Research Team',
  };
}

function buildXssMail({ marker, payload }) {
  assertMarker(marker);
  if (typeof payload !== 'string' || payload.length === 0) throw new TypeError('payload must be a non-empty string');
  const payloadBytes = bytes(payload);
  if (payloadBytes > MAX_PAYLOAD_BYTES) throw new RangeError(`payload exceeds ${MAX_PAYLOAD_BYTES} UTF-8 bytes`);
  const payloadDigest = digest(payload);
  const parts = bodyParts(marker, payloadDigest, payloadBytes);
  const body = `${parts.prefix}${payload}${parts.suffix}`;
  const subject = `You have been selected — Special Offer Inside [OWASP-AI-GOAT-XSS:${marker}]`;
  const html = `${HTML_PREFIX}${escapeHtmlText(body)}${HTML_SUFFIX}`;
  if (bytes(html) > MAX_HTML_BYTES) throw new RangeError(`encoded mail exceeds ${MAX_HTML_BYTES} UTF-8 bytes`);
  const expected = frozen({
    version: VERSION, marker,
    subjectDigest: digest(subject), subjectBytes: bytes(subject),
    logicalBodyDigest: digest(body), logicalBodyBytes: bytes(body),
    payloadDigest, payloadBytes,
    htmlDigest: digest(html), htmlBytes: bytes(html),
  });
  return frozen({ subject, body, html, ...expected, expected });
}

function validateExpected(expected) {
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) return false;
  try { assertMarker(expected.marker); } catch { return false; }
  if (expected.version !== VERSION) return false;
  for (const key of ['subjectDigest', 'logicalBodyDigest', 'payloadDigest', 'htmlDigest']) {
    if (typeof expected[key] !== 'string' || !/^[a-f0-9]{64}$/.test(expected[key])) return false;
  }
  for (const key of ['subjectBytes', 'logicalBodyBytes', 'payloadBytes', 'htmlBytes']) {
    if (!Number.isSafeInteger(expected[key]) || expected[key] < 1) return false;
  }
  return expected.payloadBytes <= MAX_PAYLOAD_BYTES && expected.htmlBytes <= MAX_HTML_BYTES;
}

function validateRetrievedMail({ htmlBody, subject, expected }) {
  if (!validateExpected(expected)) return fail('invalid_expected_metadata');
  if (typeof htmlBody !== 'string') return fail('missing_html_body');
  if (bytes(htmlBody) !== expected.htmlBytes || digest(htmlBody) !== expected.htmlDigest) {
    return fail('html_digest_mismatch');
  }
  const expectedSubject = `You have been selected — Special Offer Inside [OWASP-AI-GOAT-XSS:${expected.marker}]`;
  if (bytes(expectedSubject) !== expected.subjectBytes || digest(expectedSubject) !== expected.subjectDigest) {
    return fail('subject_metadata_mismatch');
  }
  if (subject !== undefined && subject !== expectedSubject) return fail('subject_mismatch');
  if (!htmlBody.startsWith(HTML_PREFIX) || !htmlBody.endsWith(HTML_SUFFIX)) return fail('wrapper_mismatch');
  const encodedBody = htmlBody.slice(HTML_PREFIX.length, -HTML_SUFFIX.length);
  const body = decodeHtmlText(encodedBody);
  if (`${HTML_PREFIX}${escapeHtmlText(body)}${HTML_SUFFIX}` !== htmlBody) return fail('noncanonical_html_encoding');
  if (bytes(body) !== expected.logicalBodyBytes || digest(body) !== expected.logicalBodyDigest) {
    return fail('logical_body_digest_mismatch');
  }
  const parts = bodyParts(expected.marker, expected.payloadDigest, expected.payloadBytes);
  if (!body.startsWith(parts.prefix) || !body.endsWith(parts.suffix)) return fail('dispatch_wrapper_mismatch');
  const payload = body.slice(parts.prefix.length, -parts.suffix.length);
  if (bytes(payload) !== expected.payloadBytes || digest(payload) !== expected.payloadDigest) {
    return fail('payload_digest_mismatch');
  }
  const evidence = frozen({ version: VERSION, marker: expected.marker,
    subjectDigest: expected.subjectDigest, logicalBodyDigest: expected.logicalBodyDigest,
    payloadDigest: expected.payloadDigest, htmlDigest: expected.htmlDigest,
    logicalBodyBytes: expected.logicalBodyBytes, payloadBytes: expected.payloadBytes, htmlBytes: expected.htmlBytes });
  return frozen({ valid: true, reason: null, body, payload, subject: expectedSubject, evidence });
}

module.exports = {
  buildXssMail, validateRetrievedMail, VERSION, MAX_PAYLOAD_BYTES, MAX_HTML_BYTES,
};
