'use strict';

// Pure ticket shape/provenance contract. Authority and effects belong to the
// bound graph, repository, and current persona/scene guards, never this module.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const TOOL = 'support.ticket_prepare';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const invalid = () => Object.assign(new TypeError('Ticket contract unavailable'), { code: 'TICKET_CONTRACT_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const hash = value => createHash('sha256').update(value).digest('hex');
function uuid(value) { if (typeof value !== 'string' || !UUID.test(value)) throw invalid(); return value; }
function sha(value) { if (typeof value !== 'string' || !SHA.test(value)) throw invalid(); return value; }
function integer(value) { if (!Number.isSafeInteger(value) || value < 1) throw invalid(); return value; }
function raw(value, maxBytes) {
  if (typeof value !== 'string' || !value.trim() || !value.isWellFormed() || value.includes('\0')
      || Buffer.byteLength(value, 'utf8') > maxBytes) throw invalid();
  return value;
}

// The physical ticket form sends exactly one canonical JSON object. Decoding
// the entire message prevents a model from borrowing JSON delimiter bytes or
// selecting only a substring of the requested ticket text.
function humanRequest(message) {
  if (typeof message !== 'string') throw invalid();
  let value;
  try { value = JSON.parse(message); } catch { throw invalid(); }
  if (!exact(value, ['subject', 'body'])) throw invalid();
  const subject = raw(value.subject, 256), body = raw(value.body, 4096);
  if (message !== JSON.stringify({ subject, body })) throw invalid();
  return Object.freeze({ subject, body });
}

function selected(value, message) {
  if (!exact(value, ['subject', 'body'])) throw invalid();
  const request = humanRequest(message);
  if (value.subject !== request.subject || value.body !== request.body) throw invalid();
  return Object.freeze({ subject: request.subject, body: request.body });
}

function origin(value) {
  if (!exact(value, ['turnSessionId', 'turnRequestId', 'toolKey', 'invocationStep', 'callId'])
      || value.toolKey !== TOOL || !Number.isSafeInteger(value.invocationStep)
      || value.invocationStep < 1 || value.invocationStep > 4
      || typeof value.callId !== 'string' || !value.callId
      || Buffer.byteLength(value.callId, 'utf8') > 128) throw invalid();
  return Object.freeze({ turnSessionId: uuid(value.turnSessionId),
    turnRequestId: uuid(value.turnRequestId), toolKey: TOOL,
    invocationStep: value.invocationStep, callId: value.callId });
}

function operationId(value) {
  const o = origin(value);
  const digest = hash(JSON.stringify(['secureshop-support-ticket-v1', o]));
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-${((parseInt(digest[16], 16) & 3) | 8).toString(16)}${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}

// The turn hash binds the original conversation and message; the binding-row
// digest additionally binds its persona session, authority version, and scene
// grant. This reference is a selector, never an authority token.
function requestRef(value) {
  if (!exact(value, ['requestHash', 'envelopeSha256'])) throw invalid();
  const digest = hash(JSON.stringify(['secureshop-ticket-current-request-v2',
    sha(value.requestHash), sha(value.envelopeSha256)]));
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-5${digest.slice(13, 16)}-${((parseInt(digest[16], 16) & 3) | 8).toString(16)}${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}

function proposal(value, { message, sourceOrigin } = {}) {
  if (!exact(value, ['version', 'kind', 'status', 'proposalId', 'subject', 'body',
    'subjectSha256', 'bodySha256', 'origin']) || value.version !== 1
    || value.kind !== TOOL || value.status !== 'confirmation_required') throw invalid();
  const args = selected({ subject: value.subject, body: value.body }, message);
  const o = origin(sourceOrigin);
  if (!exact(value.origin, ['turnSessionId', 'turnRequestId', 'toolKey', 'invocationStep', 'callId'])
    || !isDeepStrictEqual(value.origin, o)
    || value.proposalId !== operationId(o)
    || value.subjectSha256 !== hash(args.subject) || value.bodySha256 !== hash(args.body)) throw invalid();
  return Object.freeze({ version: 1, kind: TOOL, status: 'confirmation_required',
    proposalId: value.proposalId, subject: args.subject, body: args.body,
    subjectSha256: sha(value.subjectSha256), bodySha256: sha(value.bodySha256), origin: o });
}

function prepare({ subject, body, message, sourceOrigin } = {}) {
  const args = selected({ subject, body }, message);
  const o = origin(sourceOrigin);
  return proposal({ version: 1, kind: TOOL, status: 'confirmation_required',
    proposalId: operationId(o), subject: args.subject, body: args.body,
    subjectSha256: hash(args.subject), bodySha256: hash(args.body), origin: o },
  { message, sourceOrigin: o });
}

function projectProposal(value, options) {
  const p = proposal(value, options);
  return Object.freeze({ version: 1, kind: TOOL, status: 'confirmation_required',
    proposalId: p.proposalId, subject: p.subject, body: p.body,
    subjectSha256: p.subjectSha256, bodySha256: p.bodySha256 });
}

function confirmation(value, { sourceOrigin } = {}) {
  if (!exact(value, ['sessionId', 'requestId', 'proposalId'])) throw invalid();
  const o = origin(sourceOrigin);
  if (value.sessionId !== o.turnSessionId || value.requestId !== o.turnRequestId
      || value.proposalId !== operationId(o)) throw invalid();
  return Object.freeze({ sessionId: uuid(value.sessionId), requestId: uuid(value.requestId),
    proposalId: uuid(value.proposalId) });
}

function execution(value) {
  if (!exact(value, ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'])) throw invalid();
  return Object.freeze({ launchId: uuid(value.launchId), scenarioId: uuid(value.scenarioId),
    generation: integer(value.generation), platformOwnerId: integer(value.platformOwnerId),
    platformSessionId: integer(value.platformSessionId) });
}
function actor(value) {
  if (!exact(value, ['shopUserId', 'personaSessionId', 'authorityVersion'])
      || typeof value.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(value.authorityVersion)) throw invalid();
  return Object.freeze({ shopUserId: integer(value.shopUserId),
    personaSessionId: uuid(value.personaSessionId), authorityVersion: value.authorityVersion });
}
function scene(value) {
  if (!exact(value, ['sceneId', 'sceneGeneration', 'targetId', 'grantId', 'birth'])) throw invalid();
  return Object.freeze({ sceneId: uuid(value.sceneId), sceneGeneration: integer(value.sceneGeneration),
    targetId: uuid(value.targetId), grantId: uuid(value.grantId), birth: execution(value.birth) });
}
function source(value) {
  if (!exact(value, ['execution', 'customer', 'scene', 'turn', 'proposalId'])
    || !exact(value.turn, ['sessionId', 'requestId', 'runId'])) throw invalid();
  const result = { execution: execution(value.execution), customer: actor(value.customer),
    scene: scene(value.scene), turn: Object.freeze({ sessionId: uuid(value.turn.sessionId),
      requestId: uuid(value.turn.requestId), runId: uuid(value.turn.runId) }),
    proposalId: uuid(value.proposalId) };
  return Object.freeze(result);
}
function consumer(value, original) {
  if (!exact(value, ['execution', 'admin', 'scene'])) throw invalid();
  const s = source(original), e = execution(value.execution), a = actor(value.admin), c = scene(value.scene);
  if (e.platformOwnerId !== s.execution.platformOwnerId
    || c.sceneId !== s.scene.sceneId || c.sceneGeneration !== s.scene.sceneGeneration
    || c.targetId !== s.scene.targetId || JSON.stringify(c.birth) !== JSON.stringify(s.scene.birth)
    || a.shopUserId === s.customer.shopUserId) throw invalid();
  return Object.freeze({ execution: e, admin: a, scene: c });
}

// The repository validates receiptSha256 against its own immutable receipt;
// this pure DTO validator cannot derive it from a self-referential result.
function publicResult(value) {
  if (!exact(value, ['version', 'kind', 'ticketId', 'operationId', 'requestId', 'runId',
    'proposalId', 'status', 'subjectSha256', 'bodySha256', 'receiptSha256'])
    || value.version !== 1 || value.kind !== 'support_ticket' || value.status !== 'open'
    || typeof value.ticketId !== 'string' || !/^[1-9]\d*$/.test(value.ticketId)) throw invalid();
  return Object.freeze({ version: 1, kind: 'support_ticket', ticketId: value.ticketId,
    operationId: uuid(value.operationId), requestId: uuid(value.requestId), runId: uuid(value.runId),
    proposalId: uuid(value.proposalId), status: 'open', subjectSha256: sha(value.subjectSha256),
    bodySha256: sha(value.bodySha256), receiptSha256: sha(value.receiptSha256) });
}
function result(value, { source: original, ticketProposal } = {}) {
  const publicValue = publicResult(value);
  const s = source(original);
  if (!exact(ticketProposal, ['version', 'kind', 'status', 'proposalId', 'subject', 'body',
    'subjectSha256', 'bodySha256', 'origin']) || ticketProposal.version !== 1
    || ticketProposal.kind !== TOOL || ticketProposal.status !== 'confirmation_required'
    || ticketProposal.proposalId !== s.proposalId
    || ticketProposal.subjectSha256 !== hash(raw(ticketProposal.subject, 256))
    || ticketProposal.bodySha256 !== hash(raw(ticketProposal.body, 4096))) throw invalid();
  const selectedOrigin = origin(ticketProposal.origin);
  if (selectedOrigin.turnSessionId !== s.turn.sessionId
    || selectedOrigin.turnRequestId !== s.turn.requestId
    || operationId(selectedOrigin) !== s.proposalId) throw invalid();
  if (value.operationId !== s.proposalId || value.requestId !== s.turn.requestId
    || value.runId !== s.turn.runId || value.proposalId !== s.proposalId
    || value.subjectSha256 !== ticketProposal?.subjectSha256
    || value.bodySha256 !== ticketProposal?.bodySha256) throw invalid();
  return publicValue;
}

function publicSaved(value) {
  if (exact(value, ['status']) && value.status === 'unconfirmed') return Object.freeze({ status: 'unconfirmed' });
  if (!exact(value, ['status', 'result']) || value.status !== 'completed') throw invalid();
  return Object.freeze({ status: 'completed', result: publicResult(value.result) });
}
function saved(value, options) {
  const publicValue = publicSaved(value);
  if (publicValue.status === 'completed') result(value.result, options);
  return publicValue;
}

function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,6}Z$/.test(value)
      || !Number.isFinite(Date.parse(value))) throw invalid();
  return value;
}
function summary(value) {
  if (!exact(value, ['ticketId', 'subject', 'status', 'createdAt'])
      || typeof value.ticketId !== 'string' || !/^[1-9]\d*$/.test(value.ticketId)
      || value.status !== 'open') throw invalid();
  return Object.freeze({ ticketId: value.ticketId, subject: raw(value.subject, 256),
    status: 'open', createdAt: timestamp(value.createdAt) });
}
function adminList(value) {
  if (!exact(value, ['version', 'tickets', 'nextCursor']) || value.version !== 1
      || !Array.isArray(value.tickets) || value.tickets.length > 20
      || value.nextCursor !== null && (typeof value.nextCursor !== 'string'
        || !value.nextCursor || Buffer.byteLength(value.nextCursor, 'utf8') > 1024)) throw invalid();
  return Object.freeze({ version: 1, tickets: Object.freeze(value.tickets.map(summary)),
    nextCursor: value.nextCursor });
}
function modeCapability(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || value.version !== 1 || value.featureId !== 'support_tickets'
      || value.policyVersion !== 'owned-ticket-render-v1'
      || !['vuln', 'fixed'].includes(value.effectiveMode)
      || !exact(value.scope, ['kind', 'id']) || value.scope.kind !== 'launch_feature'
      || value.scope.id !== 'support_tickets') throw invalid();
  return Object.freeze({ version: 1, featureId: value.featureId, policyVersion: value.policyVersion,
    effectiveMode: value.effectiveMode, scope: Object.freeze({ kind: 'launch_feature', id: 'support_tickets' }) });
}
function publicAdminDetail(value) {
  if (!exact(value, ['version', 'ticketId', 'operationId', 'proposalId', 'subject', 'body',
    'status', 'createdAt', 'subjectSha256', 'bodySha256', 'receiptSha256', 'modeCapability'])
      || value.version !== 1 || value.status !== 'open'
      || typeof value.ticketId !== 'string' || !/^[1-9]\d*$/.test(value.ticketId)) throw invalid();
  const subject = raw(value.subject, 256), body = raw(value.body, 4096);
  if (value.subjectSha256 !== hash(subject) || value.bodySha256 !== hash(body)) throw invalid();
  return Object.freeze({ version: 1, ticketId: value.ticketId,
    operationId: uuid(value.operationId), proposalId: uuid(value.proposalId),
    subject, body, status: 'open', createdAt: timestamp(value.createdAt),
    subjectSha256: sha(value.subjectSha256), bodySha256: sha(value.bodySha256),
    receiptSha256: sha(value.receiptSha256), modeCapability: modeCapability(value.modeCapability) });
}
function adminDetail(value, { source: original, consumer: current } = {}) {
  const publicValue = publicAdminDetail(value);
  const s = source(original);
  consumer(current, s);
  if (publicValue.operationId !== s.proposalId || publicValue.proposalId !== s.proposalId) throw invalid();
  return publicValue;
}

module.exports = { TOOL, humanRequest, selected, origin, operationId, requestRef, proposal, prepare,
  projectProposal, confirmation, source, consumer, publicResult, result,
  publicSaved, saved, adminList, modeCapability, publicAdminDetail, adminDetail };
