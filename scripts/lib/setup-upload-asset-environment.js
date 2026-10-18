'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const windowsPrivateState = require('./windows-private-state');

const KEYS = Object.freeze([
  'SS_BOUND_UPLOAD_ASSETS_ENABLED',
  'SS_UPLOAD_ASSET_HOST',
  'SS_UPLOAD_ASSET_PORT',
  'SS_UPLOAD_ASSET_PUBLIC_ORIGIN',
  'SS_UPLOAD_ASSET_CAPABILITY_SECRET',
]);
const RESERVED_PORTS = new Set([
  1025, 3000, 3001, 5432, 8025, 8081, 8082, 8090, 8091, 8092, 8093, 8094,
  8097, 8109, 8110, 8111, 8112, 8113, 8114, 8115, 8116, 8117, 8118, 11434,
]);

function publicError(code, message) {
  return Object.assign(new Error(message), { code });
}

function presentKeys(environment) {
  return KEYS.filter(key => Object.hasOwn(environment, key));
}

function assertCompleteConfiguration(environment, {
  activationPolicy = require('../../server/services/secureshopUploadAssetProduction').activationPolicy,
} = {}) {
  const present = presentKeys(environment);
  if (present.length === 0) return null;
  const enabled = environment.SS_BOUND_UPLOAD_ASSETS_ENABLED;
  if (enabled === 'false' && present.length === 1) {
    return Object.freeze({ SS_BOUND_UPLOAD_ASSETS_ENABLED: 'false' });
  }
  if (present.length !== KEYS.length) {
    throw publicError('UPLOAD_ASSET_CONFIGURATION_PARTIAL',
      'SecureShop upload asset configuration is partial. Preserve or repair the complete private five-key tuple before retrying setup.');
  }
  const secret = environment.SS_UPLOAD_ASSET_CAPABILITY_SECRET;
  if (!['true', 'false'].includes(enabled)
      || !/^[1-9][0-9]{0,4}$/.test(environment.SS_UPLOAD_ASSET_PORT)
      || Number(environment.SS_UPLOAD_ASSET_PORT) > 65535
      || typeof secret !== 'string' || Buffer.byteLength(secret) < 32
      || Buffer.byteLength(secret) > 4096 || /[\r\n\0]/.test(secret)) {
    throw publicError('UPLOAD_ASSET_CONFIGURATION_INVALID',
      'SecureShop upload asset configuration is invalid; the private configuration was not changed.');
  }
  try {
    const activation = activationPolicy({ ...environment, SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true' });
    if (activation?.enabled !== true || activation.assetHost !== environment.SS_UPLOAD_ASSET_HOST
        || activation.port !== Number(environment.SS_UPLOAD_ASSET_PORT)
        || activation.origin !== environment.SS_UPLOAD_ASSET_PUBLIC_ORIGIN) throw Error();
  } catch {
    throw publicError('UPLOAD_ASSET_CONFIGURATION_INVALID',
      'SecureShop upload asset configuration is invalid; the private configuration was not changed.');
  }
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, environment[key]])));
}

function assertPrivateDirectory(directory, platform, privateState) {
  const paths = platform === 'win32' ? path.win32 : path;
  if (typeof directory !== 'string' || !paths.isAbsolute(directory)) throw Error();
  if (platform === 'win32') {
    privateState.inspectPrivateDirectory(directory);
    return;
  }
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) throw Error();
}

function readPosixSecret(filePath) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600
        || stat.nlink !== 1 || stat.size > 8192) throw Error();
    return fs.readFileSync(descriptor);
  } finally { fs.closeSync(descriptor); }
}

function decodeSecret(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192) throw Error();
  const value = JSON.parse(bytes.toString('utf8'));
  if (!value || Object.keys(value).sort().join(',') !== 'secret,version' || value.version !== 1
      || typeof value.secret !== 'string' || !/^[a-f0-9]{96}$/.test(value.secret)
      || !Buffer.from(`${JSON.stringify(value)}\n`).equals(bytes)) throw Error();
  return value.secret;
}

function createPosixSecret(filePath, bytes) {
  const directory = path.dirname(filePath);
  const temporary = path.join(directory, `.upload-asset-capability-${randomBytes(12).toString('hex')}.pending`);
  let descriptor;
  let created = false;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    try { fs.linkSync(temporary, filePath); created = true; }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const parent = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return created;
}

function ensureCapabilitySecret({ directory, platform = process.platform,
  privateState = windowsPrivateState, fileSystem = fs } = {}) {
  try {
    assertPrivateDirectory(directory, platform, privateState);
    const paths = platform === 'win32' ? path.win32 : path;
    const filePath = paths.join(directory, 'secureshop-upload-asset-capability.json');
    let exists = true;
    try { fileSystem.lstatSync(filePath); }
    catch (error) { if (error.code !== 'ENOENT') throw error; exists = false; }
    if (exists) {
      const bytes = platform === 'win32' ? privateState.readPrivateFile(filePath) : readPosixSecret(filePath);
      return Object.freeze({ secret: decodeSecret(bytes), filePath, created: false });
    }
    const value = Object.freeze({ version: 1, secret: randomBytes(48).toString('hex') });
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    if (platform === 'win32') privateState.createPrivateFile(filePath, bytes);
    else createPosixSecret(filePath, bytes);
    const published = platform === 'win32' ? privateState.readPrivateFile(filePath) : readPosixSecret(filePath);
    return Object.freeze({ secret: decodeSecret(published), filePath, created: true });
  } catch {
    throw publicError('UPLOAD_ASSET_PRIVATE_STATE_INVALID',
      'Private SecureShop upload asset configuration is unavailable; no environment values were changed.');
  }
}

async function bindOnce(createServer) {
  const server = createServer();
  return new Promise((resolve, reject) => {
    let finished = false;
    const fail = () => {
      if (finished) return;
      finished = true;
      const error = publicError('UPLOAD_ASSET_LOOPBACK_UNAVAILABLE',
        'The private IPv6 loopback listener is unavailable. Enable the host ::1 loopback interface and retry setup; no host alias was changed.');
      if (server.listening) server.close(() => reject(error));
      else reject(error);
    };
    server.once('error', fail);
    try {
      server.listen({ host: '::1', port: 0, exclusive: true, ipv6Only: true }, () => {
        const address = server.address();
        const selected = address && typeof address === 'object' ? address.port : 0;
        server.close(error => {
          if (finished) return;
          finished = true;
          if (error || !Number.isSafeInteger(selected) || selected < 1 || selected > 65535) {
            return reject(publicError('UPLOAD_ASSET_LOOPBACK_UNAVAILABLE',
              'The private IPv6 loopback listener is unavailable. Enable the host ::1 loopback interface and retry setup; no host alias was changed.'));
          }
          resolve(selected);
        });
      });
    } catch { fail(); }
  });
}

async function selectUploadAssetPort({ createServer = net.createServer } = {}) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const selected = await bindOnce(createServer);
    if (!RESERVED_PORTS.has(selected)) return selected;
  }
  throw publicError('UPLOAD_ASSET_LOOPBACK_UNAVAILABLE',
    'The private IPv6 loopback listener could not select a non-conflicting port; no environment values were changed.');
}

async function prepareUploadAssetEnvironment({ environment = {}, directory, execute = true } = {}, dependencies = {}) {
  const existing = assertCompleteConfiguration(environment, dependencies);
  if (existing) return Object.freeze({ state: existing.SS_BOUND_UPLOAD_ASSETS_ENABLED === 'false' ? 'preserved-disabled' : 'preserved',
    additions: Object.freeze({}), configuration: existing, probed: false });
  if (!execute) return Object.freeze({ state: 'planned', additions: Object.freeze({}), configuration: null, probed: false });
  const port = await selectUploadAssetPort(dependencies);
  const privateSecret = ensureCapabilitySecret({ directory,
    platform: dependencies.platform, privateState: dependencies.privateState, fileSystem: dependencies.fileSystem });
  const additions = Object.freeze({
    SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true',
    SS_UPLOAD_ASSET_HOST: '::1',
    SS_UPLOAD_ASSET_PORT: String(port),
    SS_UPLOAD_ASSET_PUBLIC_ORIGIN: `http://[::1]:${port}`,
    SS_UPLOAD_ASSET_CAPABILITY_SECRET: privateSecret.secret,
  });
  const configuration = assertCompleteConfiguration({ ...environment, ...additions }, dependencies);
  return Object.freeze({ state: 'created', additions, configuration, probed: true,
    secretCreated: privateSecret.created, secretFile: privateSecret.filePath });
}

module.exports = {
  UPLOAD_ASSET_ENVIRONMENT_KEYS: KEYS,
  assertCompleteUploadAssetConfiguration: assertCompleteConfiguration,
  ensureUploadAssetCapabilitySecret: ensureCapabilitySecret,
  prepareUploadAssetEnvironment,
  selectUploadAssetPort,
};
