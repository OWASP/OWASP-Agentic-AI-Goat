'use strict';
// Closed source closure for the local package. A matching digest is integrity
// evidence, not native platform qualification. The installer must still verify
// the resulting immutable image and the exact owned runtime profile.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const PREFIX = 'sidecars/sandbox-runner/owned-pricing-http/';
const FILES = Object.freeze([
  'Dockerfile.local', 'buildAssets.js', 'executor.js', 'http-handler.js',
  'http-listener.js', 'http-profile.apparmor.in', 'input.js',
  'namespace-init.c', 'network-manifest.json', 'process-supervisor.c',
  'profile.js', 'wire.js', 'worker.js',
].map(name => PREFIX + name).concat('sidecars/sandbox-runner/mcpSeccompFilter.c').sort());
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function capturePricingPackage(root) {
  const files = {};
  for (const relative of FILES) {
    const filename = path.join(root, relative);
    const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 || before.size > 1024 * 1024) throw Error('Pricing package source invalid');
      const bytes = fs.readFileSync(fd), after = fs.fstatSync(fd), named = fs.lstatSync(filename);
      if (bytes.length !== before.size || before.ino !== after.ino || before.dev !== after.dev || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || named.isSymbolicLink() || named.ino !== before.ino || named.dev !== before.dev) throw Error('Pricing package source changed');
      files[relative] = sha(bytes);
    } finally { fs.closeSync(fd); }
  }
  const record = Object.freeze({ version: 1, architecture: 'arm64', files: Object.freeze(files) });
  return Object.freeze({ ...record, sha256: sha(JSON.stringify(record)) });
}
module.exports = { PRICING_PACKAGE_FILES: FILES, capturePricingPackage };
