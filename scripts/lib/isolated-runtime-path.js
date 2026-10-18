'use strict';
const fs = require('node:fs');
const path = require('node:path');

function isolatedRuntimePath(directory, inheritedPath = '', executable = process.execPath, platform = process.platform) {
  // Windows retains its existing executable-directory behavior. POSIX gets a
  // Node-only shim so an independently selected npm stays ahead of bundled npm.
  if (platform === 'win32') return [path.dirname(executable), inheritedPath].filter(Boolean).join(path.delimiter);
  const bin = path.join(directory, '.isolated-runtime-bin');
  fs.mkdirSync(bin, { mode: 0o700 });
  fs.symlinkSync(executable, path.join(bin, 'node'));
  return [bin, inheritedPath].filter(Boolean).join(path.delimiter);
}
module.exports = { isolatedRuntimePath };
