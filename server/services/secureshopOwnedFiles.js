'use strict';
const path = require('node:path');
const { createSecureShopFiles } = require('../../sidecars/sandbox-runner/secureshopFiles');
let retained;
// The application bootstrap validates this private data root. The file primitive
// validates its own root and filesystem components lazily before any effect.
function getSecureShopOwnedFiles(env = process.env) {
  const root = env.OWASP_AI_GOAT_APP_DATA_ROOT;
  if (!root) {
    if (retained) throw new Error('Owned SecureShop files already configured');
    return undefined;
  }
  if (typeof root !== 'string' || !path.isAbsolute(root) || root.includes('\0')) {
    throw new TypeError('Private application data root required');
  }
  const directory = path.join(root, 'secureshop-owned-files');
  if (retained && retained.directory !== directory) throw new Error('Owned SecureShop files already configured');
  retained ||= Object.freeze({ directory, files: createSecureShopFiles({ root: directory,
    maxReadBytes: 20 * 1024 * 1024, maxWriteBytes: 20 * 1024 * 1024 }) });
  return retained.files;
}
module.exports = { getSecureShopOwnedFiles };
