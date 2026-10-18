'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { managedConfigurationPath } = require('../../../server/services/mcp/ownedManagedConfiguration');

const BOOLEAN_KEYS = Object.freeze([
  'SS_BOUND_REVIEWS_ENABLED',
  'SS_PERSONA_INBOX_READY',
  'SS_MCP_TRUST_READY',
  'SS_CONTROLLED_SSRF_READY',
]);
const ROOT_KEYS = Object.freeze(['SS_MCP_TRUST_FIXTURE_ROOT', 'SS_CONTROLLED_SSRF_FIXTURE_ROOT']);
const KEYS = Object.freeze(['SS_ENABLE', ...BOOLEAN_KEYS, ...ROOT_KEYS]);

function invalid(code = 'SECURESHOP_MANAGED_CONFIGURATION_INVALID') {
  return Object.assign(new Error(code), { code });
}
function directory(root, name, home) { return path.join(path.dirname(managedConfigurationPath({ root, home })), name); }
function managedPath(root, home) { return directory(root, 'secureshop-qualified.env', home); }
function expectedRoots(root, home) {
  return Object.freeze({
    SS_MCP_TRUST_FIXTURE_ROOT: directory(root, 'secureshop-mcp-targets', home),
    SS_CONTROLLED_SSRF_FIXTURE_ROOT: directory(root, 'secureshop-ssrf-targets', home),
  });
}
function parse(bytes, { root = path.resolve(__dirname, '../..'), home } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 8192) throw invalid();
  const values = Object.create(null), seen = new Set();
  for (const line of bytes.toString('utf8').split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (!match || !KEYS.includes(match[1]) || seen.has(match[1])) throw invalid();
    seen.add(match[1]); values[match[1]] = match[2];
  }
  if (KEYS.some(key => !seen.has(key)) || values.SS_ENABLE !== 'true') throw invalid();
  const state = values.SS_BOUND_REVIEWS_ENABLED;
  if (!['true', 'false'].includes(state) || BOOLEAN_KEYS.some(key => values[key] !== state)) throw invalid();
  const roots = expectedRoots(root, home);
  if (ROOT_KEYS.some(key => values[key] !== roots[key])) throw invalid();
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, values[key]])));
}
function assertPrivateDirectory(value) {
  const stat = fs.lstatSync(value);
  if (!stat.isDirectory() || stat.isSymbolicLink()
      || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw invalid('SECURESHOP_FIXTURE_ROOT_UNTRUSTED');
}
function load({ root = path.resolve(__dirname, '../..'), home, file = managedPath(root, home) } = {}) {
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (error) { if (error.code === 'ENOENT') return Object.freeze({}); throw error; }
  if (!stat.isFile() || stat.isSymbolicLink()
      || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw invalid('SECURESHOP_MANAGED_CONFIGURATION_UNTRUSTED');
  const values = parse(fs.readFileSync(file), { root, home });
  if (values.SS_BOUND_REVIEWS_ENABLED === 'true') ROOT_KEYS.forEach(key => assertPrivateDirectory(values[key]));
  return values;
}

module.exports = { KEYS, BOOLEAN_KEYS, ROOT_KEYS, managedPath, expectedRoots, parse, load };
