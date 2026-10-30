'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const enabled = process.env.XSS_LOCAL_MAIL_TEST_DISPOSABLE === 'yes';

function normalizeMessageId(value) {
  const text = String(value || '').trim();
  return text.startsWith('<') && text.endsWith('>') ? text.slice(1, -1) : text;
}

test('real isolated Mailpit preserves exact XSS mail and separates owner inboxes', { skip: !enabled, timeout: 30000 }, async () => {
  const api = new URL(process.env.XSS_LOCAL_MAIL_API_URL);
  assert.equal(api.hostname, '127.0.0.1');
  assert.ok(api.port && api.port !== '8025');
  assert.equal(process.env.XSS_LOCAL_MAIL_SMTP_HOST, '127.0.0.1');
  assert.ok(process.env.XSS_LOCAL_MAIL_SMTP_PORT && process.env.XSS_LOCAL_MAIL_SMTP_PORT !== '1025');

  const { createXssLocalMail } = require('../server/services/xssLocalMail');
  const codec = require('../server/services/xssEmailCodec');
  const { createXssEmailDispatch, inspectXssMailProof } = require('../server/services/xssEmailDispatch');
  const adapter = createXssLocalMail({
    smtpHost: process.env.XSS_LOCAL_MAIL_SMTP_HOST,
    smtpPort: Number(process.env.XSS_LOCAL_MAIL_SMTP_PORT),
    apiUrl: api.toString(),
    timeoutMs: 3000,
  });
  const owners = ['917001', '917002'];
  // This repository is deliberately an in-memory orchestration fixture. The
  // test qualifies real SMTP and Mailpit retrieval, not durable PostgreSQL.
  const evidenceRows = [];
  const repository = {
    async append(row) {
      const stored = structuredClone(row);
      evidenceRows.push(stored);
      return structuredClone(stored);
    },
    async list(query) {
      return evidenceRows.filter(row => String(row.userId) === String(query.userId)
        && row.workshopKey === query.workshopKey && row.scenario === query.scenario
        && row.generation === query.generation).map(row => structuredClone(row));
    },
  };
  const dispatch = createXssEmailDispatch({ repository, transport: adapter, mailbox: adapter, codec });
  function ownerScope(owner) {
    return {
      userId: owner,
      generation: 4,
      execution: {
        runId: `owned-mail-${owner}`,
        ownerKey: JSON.stringify(['XSS', owner]),
        durableGeneration: 9,
        async check() {},
        async effect(_key, callback) { return callback(); },
      },
    };
  }
  function proofScope(scope, kind) {
    return { kind, userId: scope.userId, generation: scope.generation,
      runId: scope.execution.runId, ownerKey: scope.execution.ownerKey,
      durableGeneration: scope.execution.durableGeneration };
  }
  const sent = [];
  try {
    for (const owner of owners) {
      const payload = `<img src=x onerror="window.__mail_${owner}='& exact ✓'">`;
      const scope = ownerScope(owner);
      const acceptedProof = await dispatch.send(scope, { recipient: `xss-${owner}@owasp-ai-goat.invalid`, payload });
      const accepted = inspectXssMailProof(acceptedProof, proofScope(scope, 'accepted'));
      assert.ok(accepted, 'dispatch acceptance evidence should be opaque and bound to its owner execution');
      assert.equal(accepted.recipient, `xss-${owner}@owasp-ai-goat.invalid`);
      assert.equal(accepted.sender, 'attacker@owasp-ai-goat.invalid');
      const mail = codec.buildXssMail({ marker: accepted.marker, payload });
      sent.push({ owner, scope, payload, mail, accepted, acceptedProof });
    }

    const observed = new Map();
    for (let attempt = 0; attempt < 30 && observed.size < owners.length; attempt += 1) {
      for (const item of sent) {
        if (observed.has(item.owner)) continue;
        const listing = await adapter.fetchEmails(`xss-${item.owner}@owasp-ai-goat.invalid`, false);
        const candidate = listing.emails.find(email => email.subject === item.mail.subject);
        if (candidate) observed.set(item.owner, { listing, candidate });
      }
      if (observed.size < owners.length) await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(observed.size, owners.length, 'each SMTP-accepted message should become visible in its owned inbox');

    for (const item of sent) {
      const { listing, candidate } = observed.get(item.owner);
      const other = sent.find(entry => entry.owner !== item.owner);
      assert.equal(listing.emails.some(email => email.subject === other.mail.subject), false,
        'an exact owner query must not return the other owner message');
      assert.equal(candidate.from, 'attacker@owasp-ai-goat.invalid');
      assert.notEqual(candidate.id, candidate.messageId, 'Mailpit internal ID is not the SMTP Message-ID');
      assert.equal(candidate.messageId, normalizeMessageId(item.accepted.providerMessageId),
        'Mailpit SMTP Message-ID must correspond to Nodemailer acceptance evidence');

      const fetched = await adapter.fetchEmail(`xss-${item.owner}@owasp-ai-goat.invalid`, candidate.id);
      assert.equal(fetched.email.id, candidate.id);
      assert.equal(fetched.email.messageId, candidate.messageId);
      assert.equal(fetched.email.from, 'attacker@owasp-ai-goat.invalid');
      assert.equal(fetched.email.subject, item.mail.subject);
      assert.equal(fetched.email.htmlBody, item.mail.html, 'Mailpit must return the exact codec HTML bytes');
      assert.equal(fetched.email.body, item.mail.body);
      const decoded = codec.validateRetrievedMail({
        htmlBody: fetched.email.htmlBody,
        subject: fetched.email.subject,
        expected: item.mail.expected,
      });
      assert.equal(decoded.valid, true);
      assert.equal(decoded.payload, item.payload);

      const retrieved = await dispatch.retrieve(item.scope, { recipient: `xss-${item.owner}@owasp-ai-goat.invalid` });
      assert.ok(retrieved.email);
      assert.equal(retrieved.email.body, item.mail.body);
      assert.ok(inspectXssMailProof(retrieved.email, proofScope(item.scope, 'retrieved')),
        'retrieval should return a real opaque proof bound to the same owner execution');
    }

    const foreign = await dispatch.retrieve(sent[1].scope, { recipient: `xss-${sent[0].owner}@owasp-ai-goat.invalid` });
    assert.match(foreign.error, /no current accepted dispatch/i);
    assert.equal(inspectXssMailProof(sent[0].acceptedProof, proofScope(sent[1].scope, 'accepted')), null,
      'another owner cannot reuse the first owner opaque acceptance proof');
  } finally {
    await adapter.close();
  }
});
