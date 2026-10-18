'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { getSecureShopUploadRoot } = require('./secureshop/assetPaths');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = code => Object.assign(new Error(code), { code, executionBoundary: true });

async function safeDirectory(directory) {
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.mode & 0o022) throw fail('UPLOAD_STORAGE_UNSAFE');
}

async function safeChain(root, target) {
  const relative = path.relative(root, target);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw fail('UPLOAD_WRITE_OUTSIDE_OWNED_ROOT');
  }
  let cursor = root;
  for (const part of relative.split(path.sep).slice(0, -1)) {
    cursor = path.join(cursor, part);
    const stat = await fs.lstat(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw fail('UPLOAD_STORAGE_UNSAFE');
  }
}

function createSecureShopV46TraversalWriter({ environment = process.env, createTools } = {}) {
  const root = path.resolve(getSecureShopUploadRoot(environment));
  return Object.freeze({
    async writeAndReadBack({ operationId, storageKey, shopUserId, bytes, filename, mime, signal }) {
      signal?.throwIfAborted();
      if (!UUID.test(operationId || '') || !UUID.test(storageKey || '')
          || !Number.isSafeInteger(shopUserId) || shopUserId < 1
          || !Buffer.isBuffer(bytes) || !bytes.length || bytes.length > 20 * 1024 * 1024
          || typeof filename !== 'string' || !filename.isWellFormed() || !filename || Buffer.byteLength(filename) > 4096
          || !filename.includes('....//') || path.isAbsolute(filename) || /[\\\0\r\n]/.test(filename)
          || typeof mime !== 'string' || !mime || /[\0\r\n]/.test(mime)) throw fail('INVALID_ARGUMENT');

      const operationRoot = path.join(root, 'operations', storageKey);
      const base = path.join(operationRoot, 'avatars', String(shopUserId));
      const cleaned = filename.replace(/\.\.\//g, '');
      const expectedPath = path.resolve(base, cleaned);
      const expectedRelative = path.relative(operationRoot, expectedPath);
      const avatarRelative = path.relative(base, expectedPath);
      if (!new RegExp(`^avatars\\${path.sep}[^\\${path.sep}]+$`).test(expectedRelative)
          || !new RegExp(`^\\.\\.\\${path.sep}[^\\${path.sep}]+$`).test(avatarRelative)
          || path.isAbsolute(expectedRelative) || path.isAbsolute(avatarRelative)) {
        throw fail('INVALID_ARGUMENT');
      }

      await fs.mkdir(root, { recursive: true, mode: 0o700 });
      await safeDirectory(root);
      if (await fs.realpath(root) !== root) throw fail('UPLOAD_STORAGE_UNSAFE');
      const operations = path.join(root, 'operations');
      await fs.mkdir(operations, { recursive: true, mode: 0o700 });
      await safeDirectory(operations);
      try {
        await fs.mkdir(operationRoot, { mode: 0o700 });
      } catch (error) {
        if (error.code === 'EEXIST') throw fail('BOUND_UPLOAD_OUTCOME_UNCERTAIN');
        throw error;
      }
      await safeChain(operationRoot, expectedPath).catch(error => {
        if (error?.code === 'ENOENT') return;
        throw error;
      });
      try {
        await fs.lstat(expectedPath);
        throw fail('BOUND_UPLOAD_OUTCOME_UNCERTAIN');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }

      signal?.throwIfAborted();
      const tools = (createTools || require('../../agent-host/agents/uploads/tools').createUploadTools)({ uploadRoot: operationRoot });
      const result = await tools.upload_avatar({
        user_id: shopUserId,
        file_bytes_base64: bytes.toString('base64'),
        filename,
        mime
      });
      if (result?.ok !== true || result.kind !== 'avatar' || result.scope_id !== shopUserId
          || result.filename !== filename || result.cleaned_filename !== cleaned || result.is_traversal !== true
          || path.resolve(result.written_path || '') !== expectedPath) throw fail('UPLOAD_WRITE_FAILED');
      await safeChain(operationRoot, expectedPath);
      if (await fs.realpath(path.dirname(expectedPath)) !== path.dirname(expectedPath)) throw fail('UPLOAD_STORAGE_UNSAFE');

      const storedVirtualPath = `operations/${storageKey}/${expectedRelative.split(path.sep).join('/')}`;
      const bodySha256 = createHash('sha256').update(bytes).digest('hex');
      const actual = await require('./secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader({ environment })({
        storedVirtualPath,
        responseByteCount: bytes.length,
        responseSha256: bodySha256
      });
      if (!actual.equals(bytes)) throw fail('UPLOAD_READBACK_CHANGED');
      signal?.throwIfAborted();
      return Object.freeze({
        cleanedFilename: cleaned,
        byteCount: actual.length,
        bodySha256,
        baseVirtualPath: `operations/${storageKey}/avatars/${shopUserId}`,
        resolvedVirtualPath: `operations/${storageKey}/avatars/${shopUserId}/${cleaned}`,
        storedVirtualPath,
        isTraversal: true
      });
    }
  });
}

module.exports = { createSecureShopV46TraversalWriter };
