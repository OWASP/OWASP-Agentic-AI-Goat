'use strict';
const { createHash, randomUUID } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createSecureShopManualExecutionConfig, MANUAL_TOOL } = require('./secureshopManualExecutionConfig');
const { executionScope } = require('./secureshopSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BYTES = 20 * 1024 * 1024;
const FILE_FIELDS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId', 'virtualPath', 'bytes', 'sha256']);
const BINDING_FIELDS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId']);
function failure(code, message) { return Object.assign(new Error(message), { code }); }
function invalid() { return failure('INVALID_ARGUMENT', 'Invalid product manual upload'); }
function modelIdentity(value) {
  const provider = value?.provider; const model = value?.model;
  if (typeof provider !== 'string' || !provider.trim() || typeof model !== 'string' || !model.trim()
      || value.mocked !== false || value.fallback === true
      || [provider, model].some(v => /^(mock|fixture|scripted|fallback|unavailable)$/i.test(v.trim()))) {
    throw failure('PRODUCT_MODEL_UNAVAILABLE', 'A genuine product model response is required');
  }
  return Object.freeze({ provider, model });
}
function snapshot(input) {
  const scope = createLaunchScope(input.scope);
  if (input.persona?.role !== 'merchant' || !Number.isSafeInteger(input.persona.id)
      || input.persona.id < 1 || input.persona.id > 2147483647
      || !Number.isSafeInteger(input.productId) || input.productId < 1 || input.productId > 2147483647
      || !Buffer.isBuffer(input.bytes) || !input.bytes.length || input.bytes.length > MAX_BYTES
      || typeof input.filename !== 'string' || !input.filename.trim()
      || Buffer.byteLength(input.filename) > 255 || /[\x00-\x1f\x7f]/.test(input.filename)
      || typeof input.mime !== 'string' || !input.mime.trim() || Buffer.byteLength(input.mime) > 128
      || /[\x00-\x1f\x7f]/.test(input.mime) || typeof input.isPublic !== 'boolean') throw invalid();
  const signal = input.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw invalid();
  const bytes = Buffer.from(input.bytes);
  const persona = Object.freeze({ id: input.persona.id, role: 'merchant' });
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  // Identical uploads in one launch generation deliberately replay. Byte,
  // metadata, product, persona or generation changes select a new operation.
  const hash = createHash('sha256').update(JSON.stringify(['dvaia-manual-v1', scope,
    persona.id, input.productId, sha256, input.filename, input.mime, input.isPublic])).digest('hex');
  const operationId = `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
  return Object.freeze({ scope, persona, signal, productId: input.productId, bytes, sha256,
    filename: input.filename, mime: input.mime, isPublic: input.isPublic, operationId });
}
function exactArgs(args, productId) {
  if (!args || Object.getPrototypeOf(args) !== Object.prototype
      || Object.keys(args).length !== 1 || args.product_id !== productId) throw invalid();
}
function createSecureShopBoundManualIngestion({ launches, conversationRepository, journal,
  coordinator, provider, catalog, retrieval, writer, extractor, embedder, repository, personaAuthority, toolPolicyRepository, promptPolicyRepository } = {}) {
  const promptPolicyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority);
  if (toolPolicyRepository !== undefined && (typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof personaAuthority?.capture !== 'function')) throw new TypeError('Policy repository and persona authority required');
  for (const [value, method] of [[launches, 'assertCurrent'], [coordinator, 'run'],
    [provider, 'chat'], [provider, 'finalResponse'], [catalog, 'getOwnedMerchantProduct'],
    [retrieval, 'ensureProvisioned'], [writer, 'writeAndReadBack'], [embedder, 'embed'],
    [repository, 'appendManual']]) {
    if (typeof value?.[method] !== 'function') throw new TypeError('Manual ingestion dependencies required');
  }
  if (typeof extractor !== 'function') throw new TypeError('Manual extractor required');
  if (personaAuthority !== undefined && typeof personaAuthority?.capture !== 'function') throw new TypeError('Persona authority required');
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const config = createSecureShopManualExecutionConfig();
  return Object.freeze({ purpose: PURPOSES.productManualIngest,
    async upload(input = {}) {
      const trustedPersonaSession = input.personaSession === undefined ? undefined : Object.freeze({
        sessionId: input.personaSession?.sessionId, authorityVersion: input.personaSession?.authorityVersion });
      const source = snapshot(input);
      const fence = personaAuthority?.capture({scope:source.scope,personaId:source.persona.id,role:source.persona.role,sessionId:trustedPersonaSession?.sessionId,authorityVersion:trustedPersonaSession?.authorityVersion});
      const personaEffect = fence ? require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence) : undefined;
      source.signal?.throwIfAborted();
      const check = async execution => {
        source.signal?.throwIfAborted();
        await execution?.check();
        await launches.assertCurrent(source.scope);
        await personaEffect?.check(source.scope);
        source.signal?.throwIfAborted();
        await execution?.check();
      };
      await check();
      const session = await conversations.create(source.scope, source.persona, PURPOSES.productManualIngest);
      let accepted = null; let finalModel = null; let capturedSource = null;
      const checkedProvider = {
        ...(provider.config ? { config: provider.config } : {}),
        async chat(args) { const value = await provider.chat({ ...args, closedToolCatalog: true }); modelIdentity(value); return value; },
        async finalResponse(args) { const value = await provider.finalResponse(args); finalModel = modelIdentity(value); return value; },
      };
      const runner = createBoundAgentRunner({ turns, conversations, ...promptPolicyOptions, repository: conversationRepository,
        ...(toolPolicyRepository === undefined ? {} : { toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({ repository: toolPolicyRepository, workflow: 'manual', declaredTools: config.manifest.getForRole('merchant') }) }),
        journal, provider: checkedProvider, pool: { async callTool() { throw invalid(); } },
        ...config, ...(fence ? {capturePersonaAuthority:()=>fence,personaLocalToolModes:{[MANUAL_TOOL]:'remote_admission'}} : {}), conversationPurpose: PURPOSES.productManualIngest, executionScope: 'turn',
        limits: { maxSteps: 4, maxParallelTools: 1 }, captureResultTraces: true,
        async createLocalTools(_binding, _context, authority, execution) {
          if (authority !== source) throw invalid();
          return new Map([[MANUAL_TOOL, async args => {
            exactArgs(args, source.productId);
            await check(execution);
            const owned = await catalog.getOwnedMerchantProduct({ scope: source.scope,
              persona: source.persona, productId: source.productId, personaEffect });
            await check(execution);
            const productExecution = executionScope(owned?.binding);
            if (!productExecution || !['launchId', 'scenarioId', 'generation',
              'platformOwnerId', 'platformSessionId'].every(key => productExecution[key] === source.scope[key])) {
              throw failure('BOUND_RETRIEVAL_MISMATCH', 'Manual product execution changed');
            }
            const meta = await retrieval.ensureProvisioned({ scope: source.scope,
              persona: source.persona, signal: execution.signal, personaEffect });
            if (!owned?.binding || !BINDING_FIELDS.every(key => owned.binding[key] === meta[key])) {
              throw failure('BOUND_RETRIEVAL_MISMATCH', 'Manual product target changed');
            }
            await check(execution);
            const file = await writer.writeAndReadBack(source.scope, {
              operationId: source.operationId, productId: source.productId, bytes: source.bytes,
              filename: source.filename, mime: source.mime, signal: execution.signal }, {personaEffect});
            await check(execution);
            const receiptFields = file.receipt;
            if (!receiptFields || Object.keys(receiptFields).length !== FILE_FIELDS.length
                || !FILE_FIELDS.every(key => Object.hasOwn(receiptFields, key))
                || !UUID.test(receiptFields.targetId) || receiptFields.targetId === owned.binding.targetId
                || !['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
                  .every(key => receiptFields[key] === source.scope[key])
                || receiptFields.virtualPath !== `/uploads/product_manuals/${source.productId}/${source.operationId}-manual`
                || receiptFields.bytes !== source.bytes.length
                || !Buffer.isBuffer(file.data) || !file.data.equals(source.bytes)
                || receiptFields.sha256 !== source.sha256) {
              throw failure('INVALID_FILE_RESULT', 'Manual read-back receipt changed');
            }
            const extracted = await extractor({ bytes: file.data, filename: source.filename, mime: source.mime });
            await check(execution);
            if (!extracted || !Array.isArray(extracted.chunks) || !extracted.chunks.length
                || extracted.chunks.length > 129) throw invalid();
            const chunks = [];
            let runtimeFingerprint = null;
            const reconstructed = extracted.chunks.map((chunk, index) => {
              if (!chunk || chunk.chunkIndex !== index || typeof chunk.text !== 'string'
                  || !chunk.text || Buffer.byteLength(chunk.text) > 32768) throw invalid();
              return chunk.text;
            }).join('');
            if (Buffer.byteLength(reconstructed) !== extracted.extractedBytes
                || extracted.extractedBytes > 200000
                || createHash('sha256').update(reconstructed).digest('hex') !== extracted.textSha256) throw invalid();
            for (const chunk of extracted.chunks) {
              const text = chunk.text;
              await check(execution);
              const value = await embedder.embed(text, { signal: execution.signal });
              await check(execution);
              const fingerprint = embedder.getRuntimeFingerprint?.()?.fingerprint;
              if (typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(fingerprint) || (runtimeFingerprint !== null && runtimeFingerprint !== fingerprint)) throw failure('EMBEDDING_FINGERPRINT_UNAVAILABLE', 'Verified manual embedding runtime changed or is unavailable');
              runtimeFingerprint = fingerprint;
              if (value.embeddingModel !== meta.embeddingModel || value.embeddingDimension !== meta.embeddingDimension) {
                throw failure('BOUND_RETRIEVAL_MISMATCH', 'Manual embedding identity changed');
              }
              chunks.push({ text, embedding: value.embedding });
            }
            const appendInput = {
              operationId: source.operationId, productId: source.productId, merchantId: source.persona.id,
              fileReceipt: Object.fromEntries(FILE_FIELDS.map(key => [key, file.receipt[key]])),
              filename: source.filename, mime: source.mime, isPublic: source.isPublic,
              extractor: extracted.extractor, extractionSha256: extracted.textSha256,
              embeddingModel: meta.embeddingModel, embeddingDimension: meta.embeddingDimension, chunks,
              expectedRuntimeFingerprint: runtimeFingerprint,
            };
            const withLineage = typeof repository.appendManualWithLineage === 'function';
            // The same persona effect owns the original append transaction; the
            // additive repository method only returns its private PG projection.
            const selectedRepository = withLineage ? { appendManual: (...args) => repository.appendManualWithLineage(...args) } : repository;
            const appended = personaEffect ? await personaEffect.appendManual(selectedRepository, owned.binding, appendInput)
              : await selectedRepository.appendManual(owned.binding, appendInput);
            const receipt = withLineage ? appended.receipt : appended;
            capturedSource = { target: JSON.parse(JSON.stringify(owned.binding)), receipt,
              lineage: withLineage ? appended.lineage : { eligible: false, reason: 'missing_original' } };
            await check(execution);
            if (receipt.operationId !== source.operationId || !Number.isSafeInteger(receipt.manualSourceId)
                || receipt.manualSourceId < 1 || receipt.documentCount !== chunks.length) throw invalid();
            accepted = Object.freeze({ ok: true, kind: 'product_manual', scope_id: source.productId,
              filename: source.filename, cleaned_filename: source.filename,
              relative_path: file.receipt.virtualPath, mime: source.mime, size_bytes: file.receipt.bytes,
              is_traversal: false, extracted_bytes: extracted.extractedBytes,
              chunk_count: chunks.length, chunk_ids: Object.freeze(chunks.map((_, i) => `manual:${receipt.manualSourceId}:${i}`)),
              extractor: extracted.extractor, extractor_error: null, indexed_corpus: 'manuals',
              operationId: source.operationId, replayed: receipt.replayed === true });
            return { content: [{ type: 'text', text: JSON.stringify(accepted) }] };
          }]]);
        },
        async enterFinalResponseAfterLocalTool({ localToolAuthority, observation }) {
          if (localToolAuthority !== source) throw invalid();
          if (observation.result?.isError === true) return false;
          exactArgs(observation.args, source.productId);
          if (observation.tool !== MANUAL_TOOL || !accepted) throw invalid();
          return true;
        },
        async resultMetadata({ result, execution, binding, sessionId, requestId, traces }) {
          await check();
          if (result.stopReason !== 'end_turn' || !accepted || !finalModel) {
            throw failure('PRODUCT_MODEL_UNAVAILABLE', 'Manual ingestion did not complete');
          }
          const metadata = { productManualIngest: { version: 1, operationId: source.operationId,
            observation: accepted, ...finalModel } };
          const origin = { version: 1, binding, personaSession: trustedPersonaSession,
            source: { sessionId, requestId }, runId: execution.runId,
            traceEventIds: traces.map(row => row.event_id), ...capturedSource };
          metadata.manualRagUploadOrigin = origin;
          if (Buffer.byteLength(JSON.stringify(metadata)) > 65536) {
            origin.lineage = { eligible: false, reason: 'metadata_limit' };
            if (Buffer.byteLength(JSON.stringify(metadata)) > 65536) origin.traceEventIds = [];
            if (Buffer.byteLength(JSON.stringify(metadata)) > 65536) delete metadata.manualRagUploadOrigin;
          }
          return metadata;
        },
      });
      const result = await runner.run({ sessionId: session.id, requestId: randomUUID(),
        scope: source.scope, persona: source.persona, personaSession:trustedPersonaSession, signal: source.signal, localToolAuthority: source,
        message: `Store and index this manual for product ${source.productId}. File metadata: ${JSON.stringify({ filename: source.filename, mime: source.mime, bytes: source.bytes.length, sha256: source.sha256 })}` });
      await check();
      const metadata = result.taskMetadata?.productManualIngest;
      if (result.stopReason !== 'end_turn' || metadata?.operationId !== source.operationId
          || !metadata.observation?.ok || !metadata.provider || !metadata.model) {
        throw failure('PRODUCT_MODEL_UNAVAILABLE', 'Manual ingestion is unavailable');
      }
      return Object.freeze({ ...metadata.observation, provider: metadata.provider, model: metadata.model });
    },
  });
}
module.exports = { createSecureShopBoundManualIngestion };
