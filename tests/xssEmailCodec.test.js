'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildXssMail, validateRetrievedMail, MAX_PAYLOAD_BYTES } = require('../server/services/xssEmailCodec');

const marker = 'owned_ServerMarker_0123456789';
const payload = '<img src=x onerror="globalThis.capture(`雪 &lt; &#39; \' \\r\\n`)" data-note="a&b">\r\n第二行';

test('XSS mail codec round-trips exact attack bytes through its outbound MIME HTML', () => {
  const mail = buildXssMail({ marker, payload });
  const outbound = require('../server/services/gmailEmailAgentService')
    .buildMailOptions('owned@sharklasers.com', mail.subject, mail.body, { html: mail.html });
  assert.equal(outbound.text, mail.body);
  assert.equal(outbound.html, mail.html);
  assert.match(mail.subject, new RegExp(marker));
  assert.ok(mail.html.includes('&lt;img'));
  assert.ok(mail.html.includes('&amp;lt;'), 'an existing entity is escaped rather than decoded early');
  const result = validateRetrievedMail({ htmlBody: mail.html, subject: mail.subject, expected: mail.expected });
  assert.equal(result.valid, true);
  assert.equal(result.payload, payload);
  assert.equal(result.body, mail.body);
  assert.equal(result.evidence.payloadDigest, mail.payloadDigest);
  assert.equal(Buffer.byteLength(result.payload), mail.payloadBytes);
  assert.equal(Object.isFrozen(mail.expected), true);
});

test('XSS mail codec rejects altered wrapper, marker, body, subject, and payload metadata', () => {
  const mail = buildXssMail({ marker, payload });
  const cases = [
    { htmlBody: ` ${mail.html}`, expected: mail.expected, reason: 'html_digest_mismatch' },
    { htmlBody: mail.html.replace(marker, 'another_ServerMarker_012345'), expected: mail.expected, reason: 'html_digest_mismatch' },
    { htmlBody: mail.html.replace('Dear Customer', 'Dear Attacker'), expected: mail.expected, reason: 'html_digest_mismatch' },
    { htmlBody: mail.html.replace('&lt;img', '&lt;svg'), expected: mail.expected, reason: 'html_digest_mismatch' },
    { htmlBody: mail.html, subject: `${mail.subject}!`, expected: mail.expected, reason: 'subject_mismatch' },
    { htmlBody: mail.html, expected: { ...mail.expected, payloadDigest: '0'.repeat(64) }, reason: 'dispatch_wrapper_mismatch' },
  ];
  for (const fixture of cases) {
    const result = validateRetrievedMail(fixture);
    assert.equal(result.valid, false);
    assert.equal(result.reason, fixture.reason);
    assert.equal(result.payload, null);
  }
});

test('XSS mail codec validates marker and UTF-8 byte bounds without sanitizing payloads', () => {
  assert.throws(() => buildXssMail({ marker: 'learner\r\nBcc:x', payload }), /marker/);
  assert.throws(() => buildXssMail({ marker: 'short', payload }), /marker/);
  assert.throws(() => buildXssMail({ marker, payload: '' }), /non-empty/);
  assert.throws(() => buildXssMail({ marker, payload: '雪'.repeat(Math.ceil(MAX_PAYLOAD_BYTES / 3) + 1) }), /exceeds/);
  const active = '<svg onload="alert(1)"><script>globalThis.x=1</script></svg>';
  const mail = buildXssMail({ marker, payload: active });
  assert.equal(validateRetrievedMail({ htmlBody: mail.html, subject: mail.subject, expected: mail.expected }).payload, active);
});
