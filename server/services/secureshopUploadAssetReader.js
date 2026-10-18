'use strict';

const fs = require('node:fs/promises');
const {
  constants
} = require('node:fs');
const path = require('node:path');
const {
  createHash
} = require('node:crypto');
const {
  getSecureShopUploadRoot
} = require('./secureshop/assetPaths');
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
function createSecureShopUploadAssetReader({
  environment = process.env
} = {}) {
  const root = path.resolve(getSecureShopUploadRoot(environment));
  return async receipt => {
    const virtual = receipt?.storedVirtualPath;
    if (typeof virtual !== 'string' || !new RegExp(`^operations/${UUID}/avatars/[1-9][0-9]*/[^/\\\\]+$`).test(virtual) || virtual.split('/').some(p => p === '.' || p === '..') || /[\0\r\n]/.test(virtual) || !Number.isSafeInteger(receipt.responseByteCount) || receipt.responseByteCount < 1 || receipt.responseByteCount > 20 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(receipt.responseSha256 || '')) throw Error('UPLOAD_ASSET_PATH_UNAVAILABLE');
    // Check every component, including ancestors of the configured root. The
    // final descriptor remains no-follow and bounded even if the file changes.
    let cursor = path.parse(root).root;
    for (const component of path.join(root, virtual).slice(cursor.length).split(path.sep)) {
      cursor = path.join(cursor, component);
      const stat = await fs.lstat(cursor);
      if (stat.isSymbolicLink()) throw Error('UPLOAD_ASSET_PATH_UNAVAILABLE');
    }
    const handle = await fs.open(cursor, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size !== receipt.responseByteCount) throw Error('UPLOAD_ASSET_BYTES_CHANGED');
      const bytes = Buffer.alloc(receipt.responseByteCount + 1);
      let offset = 0;
      while (offset < bytes.length) {
        const read = await handle.read(bytes, offset, bytes.length - offset, offset);
        if (!read.bytesRead) break;
        offset += read.bytesRead;
      }
      if (offset !== receipt.responseByteCount || createHash('sha256').update(bytes.subarray(0, offset)).digest('hex') !== receipt.responseSha256) throw Error('UPLOAD_ASSET_BYTES_CHANGED');
      return bytes.subarray(0, offset);
    } finally {
      await handle.close();
    }
  };
}
module.exports = {
  createSecureShopUploadAssetReader
};
