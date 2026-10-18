'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const {
  createHash
} = require('node:crypto');
const {
  getSecureShopUploadRoot
} = require('./secureshop/assetPaths');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function failure(code) {
  return Object.assign(new Error(code), {
    code,
    executionBoundary: true
  });
}
async function checkedDirectory(directory) {
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.mode & 0o022) throw failure('UPLOAD_STORAGE_UNSAFE');
}
function createSecureShopUploadWriter({
  environment = process.env,
  createTools
} = {}) {
  const root = path.resolve(getSecureShopUploadRoot(environment));
  return Object.freeze({
    async writeAndReadBack({
      operationId,
      storageKey,
      shopUserId,
      bytes,
      filename,
      mime,
      signal
    }) {
      signal?.throwIfAborted();
      if (!UUID.test(operationId || '') || !UUID.test(storageKey || '') || !Number.isSafeInteger(shopUserId) || shopUserId < 1 || !Buffer.isBuffer(bytes) || !bytes.length || bytes.length > 20 * 1024 * 1024 || typeof filename !== 'string' || !filename || filename !== path.basename(filename) || /[\\/\0\r\n]/.test(filename) || typeof mime !== 'string' || !mime || /[\0\r\n]/.test(mime)) throw failure('INVALID_ARGUMENT');
      // Reserve the operation before invoking the unchanged teaching sink. An
      // existing directory is uncertain state, never permission to invoke twice.
      await fs.mkdir(root, {
        recursive: true,
        mode: 0o700
      });
      await checkedDirectory(root);
      if ((await fs.realpath(root)) !== root) throw failure('UPLOAD_STORAGE_UNSAFE');
      const operations = path.join(root, 'operations');
      await fs.mkdir(operations, {
        recursive: true,
        mode: 0o700
      });
      await checkedDirectory(operations);
      const operationRoot = path.join(operations, storageKey);
      try {
        await fs.mkdir(operationRoot, {
          mode: 0o700
        });
      } catch (error) {
        if (error.code === 'EEXIST') throw failure('BOUND_UPLOAD_OUTCOME_UNCERTAIN');
        throw error;
      }
      signal?.throwIfAborted();
      const tools = (createTools || require('../../agent-host/agents/uploads/tools').createUploadTools)({
        uploadRoot: operationRoot
      });
      const result = await tools.upload_avatar({
        user_id: shopUserId,
        file_bytes_base64: bytes.toString('base64'),
        filename,
        mime
      });
      if (result?.ok !== true || result.kind !== 'avatar' || result.scope_id !== shopUserId || result.filename !== filename || result.cleaned_filename !== filename || result.is_traversal !== false || typeof result.written_path !== 'string' || typeof result.relative_path !== 'string') throw failure('UPLOAD_WRITE_FAILED');
      const base = path.join(operationRoot, 'avatars', String(shopUserId));
      const actualPath = path.resolve(result.written_path);
      if (path.dirname(actualPath) !== base || result.relative_path !== `server/uploads/secureshop/avatars/${shopUserId}/${path.basename(actualPath)}`) throw failure('UPLOAD_WRITE_OUTSIDE_OWNED_ROOT');
      const relative = path.relative(root, actualPath).split(path.sep).join('/');
      const receipt = {
        storedVirtualPath: relative,
        responseByteCount: bytes.length,
        responseSha256: createHash('sha256').update(bytes).digest('hex')
      };
      const actual = await require('./secureshopUploadAssetReader').createSecureShopUploadAssetReader({
        environment
      })(receipt);
      if (!actual.equals(bytes)) throw failure('UPLOAD_READBACK_CHANGED');
      signal?.throwIfAborted();
      return Object.freeze({
        cleanedFilename: result.cleaned_filename,
        byteCount: actual.length,
        bodySha256: receipt.responseSha256,
        baseVirtualPath: `operations/${storageKey}/avatars/${shopUserId}`,
        resolvedVirtualPath: `operations/${storageKey}/avatars/${shopUserId}/${filename}`,
        storedVirtualPath: relative,
        isTraversal: false
      });
    }
  });
}
module.exports = {
  createSecureShopUploadWriter
};
