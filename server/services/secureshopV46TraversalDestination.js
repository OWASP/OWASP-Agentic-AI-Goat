'use strict';

const path = require('node:path');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function unavailable() {
  return Object.assign(new Error('Traversal upload destination unavailable'), {
    code: 'BOUND_UPLOAD_EFFECT_MISMATCH',
    executionBoundary: true
  });
}

function validateSecureShopV46OperationRelativePath(value) {
  if (typeof value !== 'string' || !value.isWellFormed() || Buffer.byteLength(value) > 4096) throw unavailable();
  const match = /^avatars\/([^/\\\0\r\n]+)$/u.exec(value);
  if (!match || ['.', '..'].includes(match[1])) throw unavailable();
  return value;
}

function projectSecureShopV46TraversalDestination(file, { storageKey, shopUserId } = {}) {
  if (!file || file.isTraversal !== true || !UUID.test(storageKey || '')
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1
      || typeof file.cleanedFilename !== 'string' || !/^\.\.\/[^/]+$/u.test(file.cleanedFilename)
      || !file.cleanedFilename.isWellFormed()) throw unavailable();
  const base = `operations/${storageKey}/avatars/${shopUserId}`;
  const resolved = `${base}/${file.cleanedFilename}`;
  const stored = path.posix.normalize(resolved);
  const operationRelativePath = path.posix.relative(`operations/${storageKey}`, stored);
  if (file.baseVirtualPath !== base || file.resolvedVirtualPath !== resolved
      || file.storedVirtualPath !== stored) throw unavailable();
  validateSecureShopV46OperationRelativePath(operationRelativePath);
  return Object.freeze({
    operationRelativePath,
    escapedAvatarSubdirectory: true
  });
}

module.exports = {
  projectSecureShopV46TraversalDestination,
  validateSecureShopV46OperationRelativePath
};
