'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const MAX_FILENAME_BYTES = 1024;
const MAX_MIME_BYTES = 256;

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'INVALID_FILE_WRITE' });
}

function text(value, name, limit) {
  if (typeof value !== 'string' || value.includes('\0') || Buffer.byteLength(value) > limit) {
    throw invalid(`${name} is invalid`);
  }
  return value;
}

function snapshotInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)) {
    throw invalid('File write input is required');
  }
  const allowed = new Set(['bytes', 'filename', 'mime', 'operationId', 'productId', 'signal']);
  const required = ['bytes', 'filename', 'mime', 'operationId', 'productId'];
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(descriptors);
  if (required.some(key => !Object.prototype.hasOwnProperty.call(descriptors, key))
      || keys.some(key => !allowed.has(key))
      || Object.getOwnPropertySymbols(input).length
      || keys.some(key => !Object.prototype.hasOwnProperty.call(descriptors[key], 'value'))) {
    throw invalid('File write input has invalid fields');
  }
  const operationId = descriptors.operationId.value;
  const productId = descriptors.productId.value;
  const bytes = descriptors.bytes.value;
  if (typeof operationId !== 'string' || !UUID.test(operationId)) throw invalid('operationId must be a UUID');
  if (!Number.isSafeInteger(productId) || productId < 1 || productId > 2147483647) {
    throw invalid('productId must be a positive integer');
  }
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_UPLOAD_BYTES) {
    throw invalid('bytes must be a Buffer no larger than 20 MiB');
  }
  const signal = descriptors.signal?.value;
  if (signal !== undefined && (!signal || typeof signal !== 'object' || typeof signal.aborted !== 'boolean')) {
    throw invalid('signal must be an AbortSignal');
  }
  return Object.freeze({
    operationId: operationId.toLowerCase(),
    productId,
    bytes: Buffer.from(bytes),
    filename: text(descriptors.filename.value, 'filename', MAX_FILENAME_BYTES),
    mime: text(descriptors.mime.value, 'mime', MAX_MIME_BYTES),
    signal,
  });
}

function abort(signal) {
  if (signal?.aborted) {
    throw Object.assign(new Error('File write was aborted'), { name: 'AbortError', code: 'ABORT_ERR' });
  }
}

function mismatch(message, code = 'TARGET_BINDING_MISMATCH') {
  throw Object.assign(new Error(message), { code });
}

function createSecureShopReservedFileWriter({ launches, files } = {}) {
  if (!launches || typeof launches.reserveFilesTarget !== 'function'
      || typeof launches.assertCurrent !== 'function'
      || !files || typeof files.provisionReservedTarget !== 'function'
      || typeof files.writeFile !== 'function' || typeof files.readFile !== 'function') {
    throw new TypeError('Reserved file writer dependencies required');
  }

  return Object.freeze({
    async writeAndReadBack(trustedScope, input, options = {}) {
      const personaEffect = require('./secureshopPersonaProductEffect').assertPersonaProductEffect(options.personaEffect);
      // Capture authority, metadata, and bytes before the first asynchronous boundary.
      const scope = createLaunchScope(trustedScope);
      const value = snapshotInput(input);
      await personaEffect?.check(scope);
      const virtualPath = `/uploads/product_manuals/${value.productId}/${value.operationId}-manual`;
      const expectedSha256 = createHash('sha256').update(value.bytes).digest('hex');
      abort(value.signal);

      const target = Object.freeze({ ...await launches.reserveFilesTarget({
        platformSessionId: scope.platformSessionId,
        platformOwnerId: scope.platformOwnerId,
        launchId: scope.launchId,
        expectedGeneration: scope.generation,
      }) });
      abort(value.signal);
      if (typeof target.targetId !== 'string' || !UUID.test(target.targetId)
          || target.launchId !== scope.launchId || target.scenarioId !== scope.scenarioId
          || target.generation !== scope.generation || target.kind !== 'files') {
        mismatch('File reservation does not match the authorized launch', 'RESERVATION_BINDING_MISMATCH');
      }

      const binding = Object.freeze({
        targetId: target.targetId.toLowerCase(),
        launchId: scope.launchId,
        scenarioId: scope.scenarioId,
        generation: scope.generation,
        ownerId: String(scope.platformOwnerId),
      });
      const current = async () => {
        abort(value.signal);
        await launches.assertCurrent({ ...scope });
        await personaEffect?.check(scope);
        abort(value.signal);
      };
      const boundary = async operation => {
        await current();
        const result = await operation();
        await current();
        return result;
      };

      const provisioned = await boundary(() => files.provisionReservedTarget({ ...binding }));
      if (!provisioned || provisioned.targetId !== binding.targetId
          || provisioned.launchId !== binding.launchId || provisioned.scenarioId !== binding.scenarioId
          || provisioned.generation !== binding.generation || provisioned.ownerId !== binding.ownerId
          || typeof provisioned.capability !== 'string' || !provisioned.capability) {
        mismatch('Isolated file target does not match its reservation');
      }

      const written = await boundary(() => files.writeFile(
        provisioned.capability,
        virtualPath,
        value.bytes,
        { expectedGeneration: binding.generation, createParents: true },
      ));
      if (!written || written.virtualPath !== virtualPath || written.generation !== binding.generation
          || written.bytes !== value.bytes.length || written.sha256 !== expectedSha256) {
        mismatch('Isolated file write result is invalid', 'INVALID_FILE_WRITE_RESULT');
      }

      const read = await boundary(() => files.readFile(
        provisioned.capability,
        virtualPath,
        { expectedGeneration: binding.generation, maxBytes: MAX_UPLOAD_BYTES },
      ));
      if (!read || !Buffer.isBuffer(read.data) || read.virtualPath !== virtualPath
          || read.generation !== binding.generation || read.bytes !== value.bytes.length
          || read.bytes !== read.data.length || read.sha256 !== expectedSha256
          || createHash('sha256').update(read.data).digest('hex') !== expectedSha256
          || !read.data.equals(value.bytes)) {
        mismatch('Isolated file read-back result is invalid', 'INVALID_FILE_READBACK');
      }

      const receipt = Object.freeze({
        targetId: binding.targetId,
        launchId: binding.launchId,
        scenarioId: binding.scenarioId,
        generation: binding.generation,
        platformOwnerId: scope.platformOwnerId,
        platformSessionId: scope.platformSessionId,
        virtualPath,
        bytes: value.bytes.length,
        sha256: expectedSha256,
      });
      return Object.freeze({
        receipt,
        operationId: value.operationId,
        productId: value.productId,
        filename: value.filename,
        mime: value.mime,
        data: Buffer.from(read.data),
      });
    },
  });
}

module.exports = { MAX_UPLOAD_BYTES, createSecureShopReservedFileWriter };
