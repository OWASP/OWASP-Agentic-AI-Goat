'use strict';

// The owned service Dockerfiles copy only these paths from sandbox-runner.
// Stage those bytes into the owned guest rather than exposing a Windows host
// directory to its Docker daemon.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const SOURCES = Object.freeze({
  http: Object.freeze({
    files: ['Dockerfile', 'mcpSeccompFilter.c', 'mcpSeccompProbe.c', 'package.json',
      'index.js', 'mcpTargets.js', 'mcpProtectedState.js', 'mcpPackageCatalog.js',
      'ownedTargetApi.js', 'entrypoint.sh', 'policy-render/process-supervisor.c',
      'policy-render/policy-init.c', 'policy-render/executor.js',
      'policy-render/http-handler.js', 'policy-render/worker.js',
      'policy-render/secureshopPromptPolicyContract.js'],
    directories: ['protected-operations', 'owned-http', 'policy-render/assets', 'labfs'],
  }),
  shadow: Object.freeze({
    files: ['owned-shadow/Dockerfile', 'mcpSeccompFilter.c', 'mcpSeccompProbe.c',
      'mcpTargets.js', 'mcpProtectedState.js', 'mcpPackageCatalog.js',
      'protected-operations/operationStore.js', 'owned-http/canonical.js',
      'owned-http/network-manifest.json'],
    directories: ['owned-shadow', 'owned-http', 'labfs'],
  }),
});

async function collectOwnedServiceBuildContext({ root, service }) {
  const source = SOURCES[service];
  if (!source || !path.isAbsolute(root || '')) throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
  const base = path.join(root, 'sidecars', 'sandbox-runner');
  const names = new Set(source.files);
  async function visit(relative) {
    const directory = path.join(base, ...relative.split('/'));
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory() && !entry.isSymbolicLink()) await visit(child);
      else if (entry.isFile() && !entry.isSymbolicLink()) names.add(child);
      else throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
    }
  }
  for (const directory of source.directories) await visit(directory);
  if (names.size > 128) throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
  const files = [];
  let total = 0;
  for (const name of [...names].sort()) {
    const file = path.join(base, ...name.split('/'));
    const before = await fs.lstat(file);
    if (!before.isFile() || before.isSymbolicLink() || before.size > 1024 * 1024) throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
    const bytes = await fs.readFile(file);
    const after = await fs.lstat(file);
    if (!after.isFile() || after.isSymbolicLink() || before.ino !== after.ino || before.size !== bytes.length
        || after.size !== bytes.length || before.mtimeMs !== after.mtimeMs) throw new Error('MCP_OWNED_BUILD_CONTEXT_CHANGED');
    total += bytes.length;
    if (total > 16 * 1024 * 1024) throw new Error('MCP_OWNED_BUILD_CONTEXT_INVALID');
    files.push({ path: `sidecars/sandbox-runner/${name}`,
      bytes, sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
  }
  return files;
}

module.exports = { collectOwnedServiceBuildContext, _internals: { sources: SOURCES } };
