'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const CONTROLLED_MCP_ENV = 'sidecars/sandbox-runner/labfs/opt/app/config/.env';
const CONTROLLED_MCP_ENV_SHA256 = 'c90c0fb0c438f25014ca86033d6758c75c7dd1e08b453ce0bdfd179d1b919a7f';

const CONTROLLED_FINFLOW_LOGS = new Set([
  'server/sensitive_files/logs/access.log',
  'server/sensitive_files/logs/error.log',
  'server/sensitive_files/logs/audit.log',
  'server/sensitive_files/logs/llm_requests.log',
]);
const PRIVATE_PLATFORM_FILES = new Set([
  'server/config/secrets.env',
  'server/platform_secrets.json',
]);

function createCopyFilter(source, { readPublicBuild = false } = {}) {
  if (typeof readPublicBuild !== 'boolean') throw new TypeError('Read-public-build mode must be boolean');
  const root = path.resolve(source);
  return filename => {
    const relative = path.relative(root, filename);
    const parts = relative.split(path.sep);
    if (parts.some(part => ['.git', 'node_modules', '.cache', 'coverage'].includes(part))) return false;
    if (relative.split(path.sep).join('/') === CONTROLLED_MCP_ENV) {
      const stat = fs.lstatSync(filename);
      if (!stat.isFile() || stat.isSymbolicLink()
          || fs.realpathSync(filename) !== path.join(fs.realpathSync(root), CONTROLLED_MCP_ENV)
          || createHash('sha256').update(fs.readFileSync(filename)).digest('hex') !== CONTROLLED_MCP_ENV_SHA256) {
        throw new Error('Reviewed synthetic MCP environment fixture changed or is unsafe');
      }
      return true;
    }
    if (PRIVATE_PLATFORM_FILES.has(relative.split(path.sep).join('/'))) return false;
    if (parts.some(part => part === '.env' || part.startsWith('.env.')) && !filename.endsWith('.example')) return false;
    const controlledFinflowLog = CONTROLLED_FINFLOW_LOGS.has(relative.split(path.sep).join('/'));
    if (/\.(?:db|sqlite|sqlite3)(?:-(?:wal|shm|journal))?$/.test(filename) || (filename.endsWith('.log') && !controlledFinflowLog)) return false;
    if (!readPublicBuild && /^client[\\/]build(?:[\\/]|$)/.test(relative)) return false;
    if (/^(?:server[\\/]logs|server[\\/]uploads|server[\\/]database[\\/]vector-indexes)(?:[\\/]|$)/.test(relative)) return false;
    return true;
  };
}

function copyIsolatedSource(source, destination) {
  fs.cpSync(path.resolve(source), path.resolve(destination), {
    recursive: true,
    filter: createCopyFilter(source),
  });
}

module.exports = { CONTROLLED_FINFLOW_LOGS, createCopyFilter, copyIsolatedSource };
