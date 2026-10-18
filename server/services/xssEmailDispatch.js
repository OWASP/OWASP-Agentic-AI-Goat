'use strict';

const { randomBytes, randomUUID } = require('node:crypto');
const proofs = new WeakMap();
const WORKSHOP = 'xss_workshop';
const SCENARIO = 'xss_email_dispatch';
function freezeRecord(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freezeRecord);
    Object.freeze(value);
  }
  return value;
}

function inspectXssMailProof(value, scope) {
  const proof = value && typeof value === 'object' ? proofs.get(value) : null;
  if (!proof || proof.kind !== scope.kind || proof.userId !== String(scope.userId)
    || proof.generation !== scope.generation || proof.runId !== scope.runId
    || proof.ownerKey !== scope.ownerKey || proof.durableGeneration !== scope.durableGeneration) return null;
  return proof;
}

function createXssEmailDispatch({ repository, transport, mailbox, codec, expectedSender = transport?.getStatus?.().targetEmail }) {
  if (!repository?.append || !repository?.list || !transport?.sendEmail || !mailbox?.fetchEmails
    || !mailbox?.fetchEmail || !codec?.buildXssMail || !codec?.validateRetrievedMail) {
    throw new TypeError('Explicit durable mail evidence, transport, mailbox and codec are required');
  }
  if (typeof expectedSender !== 'string' || !/^[^\s@<>]+@[^\s@<>]+$/.test(expectedSender)) throw new TypeError('Configured SMTP sender required');
  expectedSender = expectedSender.toLowerCase();
  async function check(scope) {
    const { execution, userId, generation } = scope;
    if (!Number.isSafeInteger(Number(userId)) || Number(userId) <= 0
      || !Number.isInteger(generation) || generation < 0 || !execution?.runId
      || execution.ownerKey !== JSON.stringify(['XSS', String(userId)])
      || !Number.isSafeInteger(Number(execution.durableGeneration))
      || typeof execution.check !== 'function' || typeof execution.effect !== 'function') {
      throw new Error('Authenticated durable XSS execution is required');
    }
    await execution.check();
  }
  const repositoryScope = scope => ({ userId: scope.userId, workshopKey: WORKSHOP,
    scenario: SCENARIO, generation: scope.generation, runId: scope.execution.runId });
  async function append(scope, evidenceID, evidence) {
    await check(scope);
    const row = await repository.append({ ...repositoryScope(scope), evidenceID, evidence });
    await check(scope);
    if (!row || row.omitted || !row.evidence) throw new Error('Mail provenance could not be persisted');
    return row;
  }
  function prove(value, kind, scope, evidence) {
    proofs.set(value, freezeRecord({ ...JSON.parse(JSON.stringify(evidence)), kind, userId: String(scope.userId),
      generation: scope.generation, runId: scope.execution.runId, ownerKey: scope.execution.ownerKey,
      durableGeneration: scope.execution.durableGeneration }));
    return Object.freeze(value);
  }
  return {
    async send(scope, { recipient, payload }) {
      await check(scope);
      const canonicalRecipient = mailbox.canonicalize(recipient);
      const dispatchId = randomUUID();
      const marker = randomBytes(32).toString('hex');
      const mail = codec.buildXssMail({ marker, payload });
      const pending = { version: 1, dispatchId, state: 'pending', marker,
        recipient: canonicalRecipient, sender: expectedSender, ownerKey: scope.execution.ownerKey,
        durableGeneration: scope.execution.durableGeneration, dispatchRunId: scope.execution.runId,
        expected: mail.expected, subject: mail.subject };
      await append(scope, `mail_${dispatchId}_pending`, pending);
      // A started effect is never automatically repeated after a timeout or crash.
      // If acceptance cannot be durably recorded, pending means outcome unknown.
      const result = await scope.execution.effect(`email_dispatch_${dispatchId}`, () =>
        transport.sendEmail(canonicalRecipient, mail.subject, mail.body, String(scope.userId), { html: mail.html }));
      await check(scope);
      if (result?.smtpAccepted !== true || typeof result.messageId !== 'string' || !result.messageId.trim()
        || result.sentTo !== canonicalRecipient || String(result.sentFrom || '').toLowerCase() !== expectedSender
        || !Array.isArray(result.accepted) || result.accepted.length !== 1 || result.accepted[0] !== canonicalRecipient
        || !Array.isArray(result.rejected) || result.rejected.length !== 0) {
        throw new Error('SMTP acceptance evidence is missing; delivery is unconfirmed');
      }
      const accepted = { ...pending, state: 'accepted', providerMessageId: result.messageId,
        sender: result.sentFrom, accepted: result.accepted, rejected: result.rejected };
      await append(scope, `mail_${dispatchId}_accepted`, accepted);
      return prove({ success: true, canonicalRecipient, configuredRecipient: canonicalRecipient,
        payload, providerReceipt: result.messageId, smtpAccepted: true }, 'accepted', scope, accepted);
    },
    async retrieve(scope, { recipient }) {
      await check(scope);
      const canonicalRecipient = mailbox.canonicalize(recipient);
      const rows = await repository.list({ ...repositoryScope(scope), limit: 100 });
      await check(scope);
      const dispatches = rows.filter(row => !row.omitted && row.generation === scope.generation
        && row.evidence?.state === 'accepted' && row.evidence.recipient === canonicalRecipient
        && row.evidence.ownerKey === scope.execution.ownerKey
        && row.evidence.durableGeneration === scope.execution.durableGeneration
        && row.runId === row.evidence.dispatchRunId).map(row => row.evidence).reverse();
      if (!dispatches.length) return { error: 'Send a new attack email from this exercise first; no current accepted dispatch is available.' };
      const listing = await mailbox.fetchEmails(canonicalRecipient, false);
      await check(scope);
      if (listing?.success !== true || !Array.isArray(listing.emails)) throw new Error('Inbox query failed');
      for (const dispatch of dispatches) {
        const candidates = listing.emails.filter(email => email.subject === dispatch.subject);
        for (const candidate of candidates.slice(0, 20)) {
          const fetched = await mailbox.fetchEmail(canonicalRecipient, candidate.id);
          await check(scope);
          if (fetched?.success !== true || !fetched.email) continue;
          const email = fetched.email;
          if (String(email.id) !== String(candidate.id) || email.subject !== dispatch.subject
            || String(email.from || '').trim().toLowerCase() !== String(dispatch.sender).trim().toLowerCase()) continue;
          // Mailpit exposes the original SMTP Message-ID separately from its
          // internal inbox ID. Bind it when available; external APIs may omit it.
          const normalizeMessageId = value => String(value || '').trim().replace(/^<(.*)>$/, '$1');
          if (Object.hasOwn(email, 'messageId')
            && normalizeMessageId(email.messageId) !== normalizeMessageId(dispatch.providerMessageId)) continue;
          const decoded = codec.validateRetrievedMail({ htmlBody: email.htmlBody, expected: dispatch.expected });
          if (!decoded.valid) continue;
          const observation = { version: 1, state: 'retrieved', dispatchId: dispatch.dispatchId,
            dispatchRunId: dispatch.dispatchRunId, providerMessageId: dispatch.providerMessageId,
            inboxMessageId: String(email.id), recipient: canonicalRecipient, sender: dispatch.sender,
            expected: dispatch.expected, ...decoded.evidence };
          await append(scope, `read_${randomUUID()}`, observation);
          return { email: prove({ id: email.id, subject: email.subject, sender: email.from, body: decoded.body },
            'retrieved', scope, observation) };
        }
      }
      return { error: 'The inbox has no exact message matching your current exercise dispatch. Delivery may still be pending.' };
    },
  };
}

let configured;
function getXssEmailDispatch() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw new Error('Authenticated email grading requires the PostgreSQL platform');
  if (!configured) configured = createXssEmailDispatch({
    repository: require('../database/postgres/objectiveEvidenceRepository').createObjectiveEvidenceRepository(
      require('./postgresPlatformStores').getPostgresPlatformStores().pool,
      { maxEntries: 100, maxBytes: 16000, retentionSeconds: 2592000 }),
    ...require('./xssMailProvider').getXssMailProvider(),
    codec: require('./xssEmailCodec'),
  });
  return configured;
}

module.exports = { createXssEmailDispatch, getXssEmailDispatch, inspectXssMailProof };
