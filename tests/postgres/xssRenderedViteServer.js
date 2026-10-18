'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

function privateDirectory(value, name, { strictMode = false } = {}) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError(`${name} must be absolute`);
  const resolved = path.resolve(value);
  const link = fs.lstatSync(resolved);
  if (!link.isDirectory() || link.isSymbolicLink()) throw new TypeError(`${name} must be a private directory`);
  const real = fs.realpathSync(resolved); const stat = fs.statSync(real);
  if (stat.uid !== process.getuid?.() || (strictMode && (stat.mode & 0o077))) throw new TypeError(`${name} ownership/mode invalid`);
  return real;
}

function parseArgs(argv) {
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]; const value = argv[i + 1];
    if (!key?.startsWith('--') || value === undefined || values[key]) throw new TypeError('Invalid Vite helper arguments');
    values[key] = value;
  }
  const required = ['--workspace', '--port', '--backend-port', '--runtime-root'];
  if (Object.keys(values).length !== required.length || required.some(key => !values[key])) throw new TypeError('Complete Vite helper arguments required');
  const port = Number(values['--port']); const backendPort = Number(values['--backend-port']);
  if (![port, backendPort].every(value => Number.isInteger(value) && value >= 1 && value <= 65535)) throw new TypeError('Vite ports must be valid');
  return { workspace: values['--workspace'], port, backendPort, runtimeRoot: values['--runtime-root'] };
}

async function main({ workspace, port, backendPort, runtimeRoot }) {
  const sourceRoot = privateDirectory(workspace, 'workspace');
  const writableRoot = privateDirectory(runtimeRoot, 'runtimeRoot', { strictMode: true });
  if (writableRoot === sourceRoot || writableRoot.startsWith(`${sourceRoot}${path.sep}`)) throw new TypeError('Vite runtime root must be outside frozen source');
  const clientRoot = path.join(sourceRoot, 'client'); const configFile = path.join(clientRoot, 'vite.config.mjs');
  if (!fs.statSync(configFile).isFile() || fs.realpathSync(configFile) !== configFile) throw new TypeError('Frozen Vite config required');
  const cacheDir = path.join(writableRoot, 'vite-cache'); fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const cacheStat = fs.lstatSync(cacheDir);
  if (!cacheStat.isDirectory() || cacheStat.isSymbolicLink() || cacheStat.uid !== process.getuid?.() || (cacheStat.mode & 0o077)) throw new TypeError('Vite cache ownership/mode invalid');
  const envDir = path.join(writableRoot, 'vite-env');
  try { fs.mkdirSync(envDir, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  if (privateDirectory(envDir, 'Vite env directory', { strictMode: true }) !== envDir
    || fs.readdirSync(envDir).length !== 0) throw new TypeError('Vite env directory must be empty and canonical');
  process.env.DVAIA_VITE_ENV_DIR = envDir;
  process.env.PORT = String(backendPort); process.env.DVAIA_CLIENT_PORT = String(port);
  const viteEntry = path.join(clientRoot, 'node_modules', 'vite', 'dist', 'node', 'index.js');
  if (!fs.statSync(viteEntry).isFile() || fs.realpathSync(viteEntry) !== viteEntry) throw new TypeError('Admitted client Vite entry required');
  const { createServer } = await import(pathToFileURL(viteEntry).href);
  const server = await createServer({ root: clientRoot, configFile, configLoader: 'native', cacheDir, envDir,
    server: { host: '127.0.0.1', port, strictPort: true } });
  const close = async () => { try { await server.close(); } finally { process.exit(0); } };
  process.once('SIGTERM', close); process.once('SIGINT', close); await server.listen();
}

if (require.main === module) main(parseArgs(process.argv.slice(2))).catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
module.exports = { main, parseArgs };
