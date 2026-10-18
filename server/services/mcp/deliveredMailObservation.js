'use strict';

const crypto = require('node:crypto');
const confusedDeputyObservation = require('./confusedDeputyObservation');
const mailClient = require('./mailClient');

const VERSION = 'mcp-delivered-mail-observation.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const trustedObservations = new WeakSet();
const acceptedWitnesses = new WeakMap();
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const plain = value => Boolean(value && Object.getPrototypeOf(value) === Object.prototype);
const exactKeys = (value, fields) => plain(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');

function exactScope(value) {
  return exactKeys(value, ['generation', 'platformOwnerId', 'platformSessionId', 'targetId'])
    && UUID.test(value.targetId || '')
    && Number.isSafeInteger(value.platformOwnerId) && value.platformOwnerId > 0
    && Number.isSafeInteger(value.platformSessionId) && value.platformSessionId > 0
    && Number.isSafeInteger(value.generation) && value.generation >= 0;
}

function acceptedWitness(value, input) {
  if (!confusedDeputyObservation.isTrustedWitness(value)
      || !exactKeys(value, ['delivery', 'effectKeySha256', 'generation', 'platformOwnerId',
        'platformSessionId', 'protectedRead', 'runId', 'targetId', 'version'])
      || value.version !== 'mcp-confused-deputy-observation.v1'
      || value.targetId !== input.scope.targetId || value.platformOwnerId !== input.scope.platformOwnerId
      || value.platformSessionId !== input.scope.platformSessionId || value.generation !== input.scope.generation
      || value.runId !== input.runId || value.effectKeySha256 !== sha(Buffer.from(input.effectKey))
      || !exactKeys(value.protectedRead, ['byteCount', 'sha256', 'source'])
      || value.protectedRead.source !== 'owned_runner_current_tool'
      || value.protectedRead.sha256 !== sha(Buffer.from(input.protectedContent))
      || value.protectedRead.byteCount !== Buffer.byteLength(input.protectedContent)
      || !exactKeys(value.delivery, ['external', 'intentId', 'messageId', 'payloadSha256',
        'recipient', 'status'])
      || value.delivery.status !== 'accepted' || value.delivery.external !== true
      || value.delivery.intentId !== input.intentId.toLowerCase()
      || value.delivery.messageId !== input.messageId || value.delivery.recipient !== input.to
      || value.delivery.payloadSha256 !== sha(Buffer.from(canonical({ body: input.body,
        subject: input.subject })))) return null;
  return value;
}

function readbackReceipt(value, input, accepted) {
  if (!mailClient.isTrustedMessageReadback(value)
      || value.version !== mailClient._internals.READBACK_VERSION
      || value.messageId !== input.messageId
      || value.recipientSha256 !== sha(Buffer.from(input.to))
      || value.subjectSha256 !== sha(Buffer.from(input.subject))
      || value.submittedBodySha256 !== sha(Buffer.from(input.body))
      || value.submittedBodyByteCount !== Buffer.byteLength(input.body)
      || value.submittedPayloadSha256 !== accepted.delivery.payloadSha256
      || !SHA.test(value.receiptSha256 || '')) return null;
  return value;
}

function validInput(input) {
  const fields = ['body', 'effectKey', 'execution', 'intentId', 'messageId', 'protectedContent',
    'runId', 'scope', 'subject', 'to'];
  if (!exactKeys(input, fields) || !exactScope(input.scope) || !UUID.test(input.intentId || '')
      || !UUID.test(input.runId || '') || typeof input.effectKey !== 'string' || !input.effectKey.length
      || Buffer.byteLength(input.effectKey) > 500 || typeof input.messageId !== 'string'
      || !input.messageId.length || Buffer.byteLength(input.messageId) > 320
      || typeof input.to !== 'string' || !input.to.length || Buffer.byteLength(input.to) > 320
      || typeof input.subject !== 'string' || !input.subject.length || Buffer.byteLength(input.subject) > 512
      || typeof input.body !== 'string' || !input.body.length || Buffer.byteLength(input.body) > 65536
      || typeof input.protectedContent !== 'string' || !input.protectedContent.length
      || Buffer.byteLength(input.protectedContent) > 65536) return false;
  const execution = input.execution;
  return Boolean(execution && execution.ownerKey === JSON.stringify(['MCP', String(input.scope.platformOwnerId)])
    && String(execution.durableGeneration) === String(input.scope.generation)
    && execution.runId === input.runId && typeof execution.check === 'function');
}

function createDeliveredMailObservation({ mailResources,
  verifyMessageReadback = mailClient.verifyMessageReadback } = {}) {
  if (!mailResources || typeof mailResources.observeAccepted !== 'function'
      || typeof verifyMessageReadback !== 'function') {
    throw new TypeError('Durable accepted mail and full-message verifier are required');
  }
  return Object.freeze({
    async observe(input) {
      if (!validInput(input)) return null;
      const expected = Object.freeze({ scope: Object.freeze({ ...input.scope }), execution: input.execution,
        intentId: input.intentId, runId: input.runId, effectKey: input.effectKey,
        messageId: input.messageId, to: input.to, subject: input.subject,
        body: input.body, protectedContent: input.protectedContent });
      await expected.execution.check();
      const firstResult = await mailResources.observeAccepted(expected);
      const first = acceptedWitness(firstResult?.confusedDeputyWitness, expected);
      if (!first) return null;
      await expected.execution.check();
      const verified = await verifyMessageReadback({ messageId: expected.messageId, to: expected.to,
        subject: expected.subject, body: expected.body });
      await expected.execution.check();
      const mailbox = verified?.ok === true && verified.status === 'verified'
        ? readbackReceipt(verified.receipt, expected, first) : null;
      if (!mailbox) return null;
      const secondResult = await mailResources.observeAccepted(expected);
      const second = acceptedWitness(secondResult?.confusedDeputyWitness, expected);
      if (!second || canonical(second) !== canonical(first)) return null;
      await expected.execution.check();
      const body = Object.freeze({ version: VERSION, targetId: expected.scope.targetId,
        platformOwnerId: expected.scope.platformOwnerId,
        platformSessionId: expected.scope.platformSessionId, generation: expected.scope.generation,
        runId: expected.runId, effectKeySha256: first.effectKeySha256,
        acceptedWitnessSha256: sha(Buffer.from(canonical(first))),
        readbackReceiptSha256: mailbox.receiptSha256 });
      const observation = Object.freeze({ ...body,
        receiptSha256: sha(Buffer.from(canonical(body))) });
      trustedObservations.add(observation);
      acceptedWitnesses.set(observation, second);
      return observation;
    },
  });
}

function isTrustedObservation(value) {
  return Boolean(value && typeof value === 'object' && trustedObservations.has(value));
}

function acceptedWitnessFor(value) { return acceptedWitnesses.get(value) || null; }

module.exports = { VERSION, createDeliveredMailObservation, isTrustedObservation, acceptedWitnessFor,
  _internals: { canonical, sha, acceptedWitness, readbackReceipt, validInput } };
