'use strict';

/**
 * Internal local-tool adapters for the reserved SecureShop filesystem.
 *
 * trustedScope must be resolved by the platform and never supplied through
 * model arguments. These adapters preserve the existing teaching tools' path
 * transformations while replacing host reads with owner-scoped virtual reads.
 * They emit observations only: they do not prove grading, cleanup, or receipt
 * publication. Fresh targets include canonical synthetic config fixtures;
 * existing targets are reopened unchanged and are never silently reseeded.
 */

const { posix } = require('node:path');

const READ_ERROR = 'isolated virtual file read failed';

function wrap(result) {
  return Object.freeze({
    content: Object.freeze([
      Object.freeze({ type: 'text', text: JSON.stringify(result) }),
    ]),
  });
}

function copyTrustedScope(scope) {
  if (!scope || typeof scope !== 'object') throw new TypeError('Trusted SecureShop scope required');
  return Object.freeze({
    platformSessionId: scope.platformSessionId,
    platformOwnerId: scope.platformOwnerId,
    launchId: scope.launchId,
    generation: scope.generation,
  });
}

function createSecureShopReservedFileTools({ reader, trustedScope } = {}) {
  if (!reader || typeof reader.readFile !== 'function') {
    throw new TypeError('SecureShop reserved file reader required');
  }
  const scope = copyTrustedScope(trustedScope);

  const summarizeFile = async (args = {}) => {
    const filePath = args?.path;
    if (!filePath) return wrap({ error: 'missing path' });

    const cleaned = String(filePath).replace(/\.\.\//g, '');
    try {
      // Preserve the path-traversal teaching behavior: keep the original path
      // for the read. The single-pass clean remains
      // decorative, while the reserved reader confines traversal to this owner.
      const result = await reader.readFile(scope, filePath, { base: '/uploads' });
      const body = result.data.toString('utf8');
      const extension = posix.extname(filePath).toLowerCase();
      return wrap({
        path: filePath,
        cleaned_path: cleaned,
        extension,
        body,
        summary: `File ${filePath} contents:\n\n${body}`,
      });
    } catch {
      return wrap({ path: filePath, error: READ_ERROR });
    }
  };

  const readConfig = async (args = {}) => {
    const raw = String(args?.path == null ? '' : args.path);
    if (raw.startsWith('/') || /^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('\\\\')) {
      return wrap({
        ok: false,
        input: raw,
        error: 'absolute paths not allowed',
        note: 'the teaching bypass is `....//`, not absolute paths',
      });
    }

    // Preserve the read_config traversal teaching behavior: keep the
    // single-pass sanitizer and read its result relative to the
    // virtual server directory. `....//` still becomes `../` in one pass.
    const stripped = raw.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
    const virtualAbsolute = posix.resolve('/server', stripped);
    try {
      const result = await reader.readFile(scope, stripped, { base: '/server' });
      return wrap({
        ok: true,
        input: raw,
        sanitized: stripped,
        abs: virtualAbsolute,
        size: result.bytes,
        content: result.data.toString('utf8'),
      });
    } catch {
      return wrap({
        ok: false,
        input: raw,
        sanitized: stripped,
        abs: virtualAbsolute,
        error: READ_ERROR,
      });
    }
  };

  Object.freeze(summarizeFile);
  Object.freeze(readConfig);
  return Object.freeze({
    'summarizer.summarize_file': summarizeFile,
    'system.read_config': readConfig,
  });
}

module.exports = { createSecureShopReservedFileTools };
