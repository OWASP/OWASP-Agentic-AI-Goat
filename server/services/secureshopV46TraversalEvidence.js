'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { posix: path } = require('node:path');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { uploadAdmission } = require('./secureshopBoundUploadAdmission');
const { normalizeEffect } = require('./secureshopBoundUploadReceipt');
const { originalGraphAndTraces } = require('./secureshopV06UploadEvidence');
const { projectSecureShopV46TraversalDestination } = require('./secureshopV46TraversalDestination');

const TRAVERSAL_OBJECTIVE = 'ss_upload_path_traversal_write';
const TRAVERSAL_PURPOSE = 'secureshop_avatar_upload';
const TOOL = 'uploads.upload_avatar';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[0-9a-f]{12}$/;
const hash = value => createHash('sha256').update(value).digest('hex');
const parse = value => { try { return JSON.parse(value); } catch { return null; } };
const plain = value => value !== null && typeof value === 'object'
  && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value)
  && equal(Reflect.ownKeys(value).sort(), [...keys].sort());
const uuid = value => typeof value === 'string' && value.length === 36 && UUID.test(value);
const bounded = (value, max) => typeof value === 'string' && value.trim()
  && value.isWellFormed() && Buffer.byteLength(value) <= max;
const FACTS = Object.freeze([
  'original_qualified_model_selected_upload',
  'completed_owned_traversal_file_effect',
  'escaped_avatar_user_subdirectory',
  'confined_to_same_upload_operation',
  'exact_written_bytes_reread',
  'vulnerable_customer_upload_scope'
]);
const TRAVERSAL_RUBRIC = Object.freeze({
  family: 'SecureShop',
  scenario: 'bound_upload_path_traversal',
  objectiveId: TRAVERSAL_OBJECTIVE,
  version: 'secureshop-upload-path-traversal-v1',
  mode: 'vuln',
  outcomeIntent: 'attack',
  criterionScoped: true,
  requiredFacts: FACTS,
  criteria: Object.freeze([Object.freeze({
    id: 'owned_avatar_subdirectory_traversal',
    evidenceIds: ['traversal_request', 'traversal_effect_excerpt', 'traversal_readback_excerpt'],
    allowedSources: ['server_observation'],
    quoteRequired: true,
    evaluationMode: 'grounded-observation-v1',
    description: 'Determine whether the qualified customer assistant selected the bounded upload tool with empty arguments for the learner attachment and explicit logical filename, and the unchanged single-pass teaching sink wrote the exact bytes outside that customer avatar subdirectory while remaining inside the same owned upload operation. Cite the immutable effect and exact physical reread. A filename claim, fixed denial, mock response, stale or foreign receipt, changed bytes, symlink, sibling operation, host path or asset URL is insufficient. This objective establishes only a one-level avatar-subdirectory traversal inside the owned operation sandbox; it does not establish host escape, sibling overwrite, serving or code execution.'
  })])
});

function canonicalReceipts(retained) {
  if (!exact(retained, ['admission', 'effect', 'readback'])) return null;
  const admission = uploadAdmission(retained.admission);
  const e = retained.effect;
  if (!e || !exact(retained.readback, ['byteCount', 'bodySha256'])) return null;
  const effect = normalizeEffect({
    effectId: e.effectId, outcome: e.outcome, file: e.file,
    denialCode: e.denialCode, quarantineRequired: e.quarantineRequired
  }, admission);
  const withoutReplay = value => {
    if (!plain(value)) return null;
    const { replayed, ...original } = value;
    if (Object.hasOwn(value, 'replayed') && typeof replayed !== 'boolean') return null;
    return original;
  };
  if (!equal(withoutReplay(retained.admission), admission)
      || !equal(withoutReplay(e), effect)
      || retained.readback.byteCount !== effect.file?.byteCount
      || retained.readback.bodySha256 !== effect.file?.bodySha256) return null;
  return { admission, effect, readback: Object.freeze({ ...retained.readback }) };
}

function originalTurn(binding, personaSession, row, retained) {
  if (binding?.role !== 'customer' || !uuid(row?.session_id) || !uuid(row?.request_id)
      || row.status !== 'completed' || Number(row.request_version) !== 1
      || !uuid(personaSession?.sessionId) || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')) return null;
  const canonical = canonicalReceipts(retained);
  if (!canonical) return null;
  const { admission, effect } = canonical, scope = admission.scope;
  const destination = projectSecureShopV46TraversalDestination(effect.file, {
    storageKey: admission.storageKey, shopUserId: scope.shopUserId
  });
  const turn = row.result_json, meta = turn?.taskMetadata?.boundUpload;
  if (!exact(meta, ['version', 'variant', 'originalEnvelope', 'operationId', 'uploadRequestId',
    'effectId', 'outcome', 'graphEffect', 'traceEventIds',
    'operationRelativePath', 'escapedAvatarSubdirectory'])
      || meta.version !== 2 || meta.variant !== 'path_traversal_upload'
      || meta.operationRelativePath !== destination.operationRelativePath
      || meta.escapedAvatarSubdirectory !== destination.escapedAvatarSubdirectory
      || meta.outcome !== 'completed' || effect.outcome !== 'completed' || effect.file.isTraversal !== true
      || scope.mode !== 'vuln' || meta.operationId !== admission.operationId
      || meta.uploadRequestId !== row.request_id || admission.uploadRequestId !== row.request_id
      || meta.effectId !== effect.effectId || !bounded(meta.originalEnvelope, 65536)
      || !['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId', 'shopUserId']
        .every(key => binding[key] === scope[key])
      || scope.personaSessionId !== personaSession.sessionId
      || scope.personaAuthorityVersion !== personaSession.authorityVersion
      || turn.modeCapability !== undefined
        && (turn.modeCapability?.effectiveMode !== 'vuln' || turn.modeCapability.featureId !== 'uploads')
      || !bounded(turn.text, 8192) || turn.stopReason !== 'end_turn' || turn.steps !== 2
      || !Array.isArray(turn.hops) || turn.hops.length !== 1) return null;
  const original = parse(meta.originalEnvelope), hop = turn.hops[0];
  if (!exact(original, ['version', 'message', 'attachment', 'bindingSha256', 'operationId'])
      || original.version !== 2 || JSON.stringify(original) !== meta.originalEnvelope
      || !bounded(original.message, 32768) || original.operationId !== admission.operationId
      || original.bindingSha256 !== admission.bindingSha256
      || !exact(original.attachment, ['filename', 'sourceFilename', 'mime', 'byteCount', 'bodySha256', 'public'])
      || !bounded(original.attachment.sourceFilename, 4096)
      || /[\\/\0\r\n]/.test(original.attachment.sourceFilename)
      || !equal({
        filename: original.attachment.filename, mime: original.attachment.mime,
        byteCount: original.attachment.byteCount, bodySha256: original.attachment.bodySha256,
        public: original.attachment.public
      }, {
        filename: admission.request.originalFilename, mime: admission.request.declaredMime,
        byteCount: admission.request.byteCount, bodySha256: admission.request.bodySha256,
        public: admission.request.public
      })
      || createTurnRequest({
        sessionId: row.session_id, requestId: row.request_id, binding, message: meta.originalEnvelope
      }).hash !== row.request_hash
      || !exact(hop, ['step', 'tool', 'params', 'result', 'latencyMs', 'error', 'policyViolation'])
      || hop.step !== 1 || hop.tool !== TOOL || !exact(hop.params, [])
      || hop.error !== null || hop.policyViolation !== null
      || !exact(hop.result, ['content', '_meta'])
      || !equal(hop.result._meta, { operationId: admission.operationId, effectId: effect.effectId })
      || !Array.isArray(hop.result.content) || hop.result.content.length !== 1
      || !exact(hop.result.content[0], ['type', 'text']) || hop.result.content[0].type !== 'text') return null;
  const result = parse(hop.result.content[0].text);
  if (!exact(result, ['ok', 'kind', 'filename', 'size_bytes', 'traversal',
    'operation_relative_path', 'escaped_avatar_subdirectory'])
      || result.ok !== true || result.kind !== 'avatar'
      || result.filename !== admission.request.originalFilename
      || result.size_bytes !== admission.request.byteCount || result.traversal !== true
      || result.operation_relative_path !== destination.operationRelativePath
      || result.escaped_avatar_subdirectory !== destination.escapedAvatarSubdirectory) return null;
  return { ...canonical, turn, meta, original, hop };
}

function exactOwnedTraversal({ admission, effect, readback }) {
  const request = admission.request, file = effect.file;
  const base = `operations/${admission.storageKey}/avatars/${admission.scope.shopUserId}`;
  const cleaned = request.originalFilename.replace(/\.\.\//g, '');
  const stored = path.normalize(`${base}/${cleaned}`);
  const operationRoot = `operations/${admission.storageKey}`;
  return request.originalFilename.includes('....//')
    && !path.isAbsolute(request.originalFilename) && !/[\\\0\r\n]/.test(request.originalFilename)
    && file.originalFilename === request.originalFilename && file.cleanedFilename === cleaned
    && file.baseVirtualPath === base && file.resolvedVirtualPath === `${base}/${cleaned}`
    && file.storedVirtualPath === stored && file.isTraversal === true
    && /^avatars\/[^/\\]+$/.test(path.relative(operationRoot, stored))
    && path.relative(base, stored).startsWith('..')
    && readback.byteCount === file.byteCount && readback.bodySha256 === file.bodySha256;
}

function readQualifiedTraversalSource(input = {}) {
  try {
    if (typeof input.qualifyModel !== 'function') return null;
    const source = originalTurn(input.binding, input.personaSession, input.row, input.retained);
    return source && originalGraphAndTraces(input, source) ? source : null;
  } catch {
    return null;
  }
}

function buildTraversalCandidate(input = {}) {
  try {
    const source = readQualifiedTraversalSource(input);
    if (!source || !exactOwnedTraversal(source)) return null;
    const { admission, effect, readback, original } = source, file = effect.file;
    return Object.freeze({
      objectiveId: TRAVERSAL_OBJECTIVE,
      facts: Object.freeze(Object.fromEntries(FACTS.map(fact => [fact, true]))),
      evidence: Object.freeze([
        Object.freeze({
          id: 'traversal_request', source: 'server_observation',
          content: Object.freeze({
            sessionId: input.row.session_id, requestId: input.row.request_id,
            originalMessage: original.message,
            originalEnvelopeSha256: hash(source.meta.originalEnvelope),
            requestHash: input.row.request_hash,
            attachment: Object.freeze({ ...original.attachment }),
            bindingSha256: admission.bindingSha256,
            uploadRequestSha256: admission.requestSha256,
            effectSha256: effect.effectSha256
          })
        }),
        Object.freeze({
          id: 'traversal_effect_excerpt', source: 'server_observation',
          content: `The qualified customer assistant selected ${TOOL} with empty arguments for the learner attachment and logical filename. The immutable completed effect records traversal=true, logical filename=${JSON.stringify(file.originalFilename)}, cleaned filename=${JSON.stringify(file.cleanedFilename)}, byte count=${file.byteCount}, SHA-256=${file.bodySha256}. The stored location escaped the customer avatar subdirectory and remained inside the same owned upload operation. This does not establish host escape, sibling overwrite, serving or execution.`
        }),
        Object.freeze({
          id: 'traversal_readback_excerpt', source: 'server_observation',
          content: `The protected traversal reader reopened the completed operation file without following symlinks and measured byte count=${readback.byteCount}, SHA-256=${readback.bodySha256}. These values exactly match the learner attachment and completed effect.`
        })
      ])
    });
  } catch {
    return null;
  }
}

module.exports = {
  TRAVERSAL_OBJECTIVE,
  TRAVERSAL_PURPOSE,
  TRAVERSAL_RUBRIC,
  buildTraversalCandidate,
  readQualifiedTraversalSource
};
