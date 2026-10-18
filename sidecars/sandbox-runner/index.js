'use strict';

/**
 * MCP Sandbox Runner
 * ------------------
 * A tiny HTTP service that executes REAL shell commands for the MCP Vulnerable
 * Server workshop, inside a disposable, powerless, network-isolated box.
 *
 * The lab filesystem is baked into this image at real absolute paths
 * (/var/secrets, /opt/app/config, /etc/passwd, /home/mcp-admin, ...) so
 * `cat /var/secrets/master_key.txt`, `env`, `grep`, and command chaining all
 * really run against real bytes — the secrets the app scores come out of genuine
 * process output, not a simulated string table.
 *
 * Isolation:
 *   - Preferred: bubblewrap (bwrap) unshares net + pid + mount + uts and
 *     read-only-binds the rootfs, giving each command an empty network
 *     namespace (cannot reach 169.254.169.254, the app, or the internet) while
 *     still executing real coreutils. A small set of lab dirs are bound rw so
 *     the mutation objectives (key rotation, postinstall) can write.
 *   - Fallback (e.g. AWS Fargate, where unprivileged user namespaces are
 *     unavailable): plain exec as a non-root uid with a stripped env, cwd
 *     locked to the per-session workdir, wall-clock timeout and output cap.
 *     Real execution, weaker network containment — mitigated by a powerless
 *     task role and a dedicated, secret-free container.
 *
 * Endpoints:
 *   GET  /health                         → { status, isolation, bwrap, uid }
 *   POST /exec   { sessionId, command }   → { stdout, stderr, exitCode, ... }
 *   POST /reset  { sessionId }            → restores mutable lab files
 */

const http = require('node:http');
const { spawnSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');
const { createOwnedTargetApiFromEnvironment } = require('./ownedTargetApi');
const policyExecutor = require('./policy-render/executor');
const { createPolicyRenderHttpHandler } = require('./policy-render/http-handler');

const PORT = parseInt(process.env.SANDBOX_RUNNER_PORT || '8090', 10);
const HOST = process.env.SANDBOX_RUNNER_HOST || '0.0.0.0';
const EXEC_TIMEOUT_MS = parseInt(process.env.SANDBOX_EXEC_TIMEOUT_MS || '10000', 10);
const MAX_OUTPUT_BYTES = parseInt(process.env.SANDBOX_MAX_OUTPUT_BYTES || '65536', 10);
const SESSION_ROOT = process.env.SANDBOX_SESSION_ROOT || '/sandbox/sessions';
const PRISTINE_ROOT = process.env.SANDBOX_PRISTINE_ROOT || '/opt/lab-pristine';

const POLICY_RENDER_ENABLED = 'SECURESHOP_POLICY_RENDER_ENABLED';
const POLICY_RENDER_MAX_CONCURRENT = 'SECURESHOP_POLICY_RENDER_MAX_CONCURRENT';

function packagedExecutable(filename, lstatSync = fs.lstatSync) {
  try {
    const stat = lstatSync(filename);
    return stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.gid === 0
      && (stat.mode & 0o022) === 0 && (stat.mode & 0o111) !== 0;
  } catch { return false; }
}

function createPolicyRendererFromEnvironment(env = process.env, {
  lstatSync = fs.lstatSync, checkAssets = policyExecutor.checkAssets,
  strictProbe = policyExecutor.strictProbe,
  createExecutor = policyExecutor.createPolicyRenderExecutor,
  createHandler = createPolicyRenderHttpHandler,
} = {}) {
  const enabled = env[POLICY_RENDER_ENABLED] === 'true';
  if (!enabled) return Object.freeze({ enabled: false, available: false, isolation: 'unavailable',
    reason: 'disabled', handler: null, close: async () => {} });
  const maximum = env[POLICY_RENDER_MAX_CONCURRENT] === undefined
    ? 2 : Number(env[POLICY_RENDER_MAX_CONCURRENT]);
  try {
    if (!Number.isInteger(maximum) || maximum < 1 || maximum > 16
        || !packagedExecutable(policyExecutor.DEFAULT_SUPERVISOR, lstatSync)
        || !packagedExecutable(policyExecutor.DEFAULT_INIT, lstatSync)) throw new Error('invalid packaged policy renderer');
    checkAssets();
    if (!strictProbe()) throw new Error('strict namespace unavailable');
    const handler = createHandler({ executor: createExecutor(), maxConcurrent: maximum });
    return Object.freeze({ enabled: true, available: true, isolation: policyExecutor.ISOLATION,
      reason: null, handler, close: () => handler.close() });
  } catch {
    return Object.freeze({ enabled: true, available: false, isolation: 'unavailable',
      reason: 'strict_preflight_failed', handler: null, close: async () => {} });
  }
}

// Directories that must be writable inside the sandbox so mutation objectives
// (admin_rotate_keys, supply-chain postinstall) really change bytes on disk.
const MUTABLE_LAB_DIRS = ['/var/secrets', '/opt/app/config', '/tmp', '/var/tmp'];

const CONFIG_SNAPSHOT_VERSION = 'config-snapshot.v1';
const CONFIG_SNAPSHOT_LIMITS = Object.freeze({
  maxSourceBytes: 64 * 1024,
  maxOutputBytes: (2 * 64 * 1024) + 64,
  maxCredentials: 64,
  maxCredentialNameBytes: 256,
});
const ENV_CREDENTIAL_FIELDS = new Set([
  'API_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'DB_PASSWORD',
  'JWT_SECRET', 'SECRET_TOKEN', 'STRIPE_KEY',
]);
const JSON_CREDENTIAL_FIELDS = new Set([
  'access_key', 'api_key', 'client_secret', 'jwt_secret', 'live_key',
  'password', 'secret_key', 'secret_token', 'token',
]);

function snapshotError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function decodeUtf8(buffer, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw snapshotError('CONFIG_SOURCE_MALFORMED', `${label} is not valid UTF-8`);
  }
}

function credentialValue(value) {
  if (typeof value !== 'string' || value.length === 0 || /[\0\r\n]/.test(value)) return null;
  const trimmed = value.trim();
  if (!trimmed || /^(?:\[?redacted\]?|<redacted>|\*+|x+)$/i.test(trimmed)) return null;
  return value;
}

function parseEnvCredentials(buffer) {
  decodeUtf8(buffer, 'environment source');
  const seen = new Set();
  const credentials = [];
  for (let lineStart = 0; lineStart <= buffer.length;) {
    const newline = buffer.indexOf(0x0a, lineStart);
    const next = newline < 0 ? buffer.length : newline;
    let lineEnd = next;
    if (lineEnd > lineStart && buffer[lineEnd - 1] === 0x0d) lineEnd--;
    let contentStart = lineStart;
    while (contentStart < lineEnd && (buffer[contentStart] === 0x20 || buffer[contentStart] === 0x09)) contentStart++;
    const rawLine = decodeUtf8(buffer.subarray(contentStart, lineEnd), 'environment source line');
    if (!rawLine || rawLine.startsWith('#')) {
      if (newline < 0) break;
      lineStart = newline + 1;
      continue;
    }
    const equals = buffer.indexOf(0x3d, contentStart);
    if (equals < 0 || equals >= lineEnd) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'environment source contains an invalid assignment');
    const left = decodeUtf8(buffer.subarray(contentStart, equals), 'environment source key');
    const match = left.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)$/);
    if (!match) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'environment source contains an invalid assignment');
    const key = match[1];
    if (seen.has(key)) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'environment source contains a duplicate assignment');
    seen.add(key);
    const startByte = equals + 1;
    const endByte = lineEnd;
    let value = decodeUtf8(buffer.subarray(startByte, endByte), 'environment source value');
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else if (value.startsWith('"') || value.startsWith("'") || value.endsWith('"') || value.endsWith("'")) {
      throw snapshotError('CONFIG_SOURCE_MALFORMED', 'environment source contains an unterminated quoted value');
    }
    if (ENV_CREDENTIAL_FIELDS.has(key) && credentialValue(value) !== null) {
      credentials.push({ name: `env.${key}`, startByte, endByte });
    }
    if (newline < 0) break;
    lineStart = newline + 1;
  }
  return credentials;
}

function parseJsonCredentials(buffer) {
  const text = decodeUtf8(buffer, 'credentials source');
  try {
    JSON.parse(text);
  } catch {
    throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source is not valid JSON');
  }
  let offset = 0;
  const credentials = [];
  const skip = () => { while (/\s/.test(text[offset] || '')) offset++; };
  const byteOffset = index => Buffer.byteLength(text.slice(0, index), 'utf8');
  const parseString = () => {
    if (text[offset] !== '"') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains an invalid string');
    const tokenStart = offset++;
    const contentStart = offset;
    while (offset < text.length) {
      if (text[offset] === '\\') { offset += 2; continue; }
      if (text[offset] === '"') {
        const contentEnd = offset;
        offset++;
        return { value: JSON.parse(text.slice(tokenStart, offset)), contentStart, contentEnd };
      }
      offset++;
    }
    throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains an unterminated string');
  };
  const parseValue = (pathParts, field, depth) => {
    skip();
    if (text[offset] === '{') return parseObject(pathParts, depth);
    if (text[offset] === '[') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credential arrays are unsupported');
    if (text[offset] === '"') {
      const token = parseString();
      if (JSON_CREDENTIAL_FIELDS.has(field.toLowerCase()) && credentialValue(token.value) !== null) {
        credentials.push({ name: `json.${pathParts.join('.')}`,
          startByte: byteOffset(token.contentStart), endByte: byteOffset(token.contentEnd) });
      }
      return;
    }
    while (offset < text.length && !/[},]/.test(text[offset])) offset++;
  };
  const parseObject = (pathParts, depth) => {
    if (depth > 12) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source is too deeply nested');
    if (text[offset++] !== '{') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source must be a JSON object');
    const keys = new Set();
    skip();
    if (text[offset] === '}') { offset++; return; }
    while (offset < text.length) {
      skip();
      const keyToken = parseString();
      const key = keyToken.value;
      if (/[^\x20-\x7e]/.test(key)) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credential field name contains control characters');
      if (keys.has(key)) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains a duplicate field');
      keys.add(key);
      skip();
      if (text[offset++] !== ':') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains an invalid field');
      parseValue([...pathParts, key], key, depth + 1);
      skip();
      if (text[offset] === '}') { offset++; return; }
      if (text[offset++] !== ',') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains an invalid object');
    }
    throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains an unterminated object');
  };
  skip();
  if (text[offset] !== '{') throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source must be a JSON object');
  parseObject([], 0);
  skip();
  if (offset !== text.length) throw snapshotError('CONFIG_SOURCE_MALFORMED', 'credentials source contains trailing data');
  return credentials;
}

async function readSnapshotSource(sourcePath, label, maxSourceBytes) {
  let handle;
  try {
    // A learner can replace a lab file with a FIFO. Nonblocking open lets the
    // regular-file check reject it without exhausting the filesystem workers.
    handle = await fs.promises.open(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw snapshotError('CONFIG_SOURCE_INVALID', `${label} must be a regular file`);
    if (before.size === 0n) throw snapshotError('CONFIG_SOURCE_EMPTY', `${label} is empty`);
    if (before.size > BigInt(maxSourceBytes)) throw snapshotError('CONFIG_SOURCE_OVERSIZE', `${label} exceeds the size limit`);
    const chunks = [];
    let bytes = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(16 * 1024, maxSourceBytes + 1 - bytes));
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (read.bytesRead === 0) break;
      bytes += read.bytesRead;
      if (bytes > maxSourceBytes) throw snapshotError('CONFIG_SOURCE_OVERSIZE', `${label} exceeds the size limit`);
      chunks.push(chunk.subarray(0, read.bytesRead));
    }
    const data = Buffer.concat(chunks, bytes);
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
        || BigInt(data.length) !== before.size) {
      throw snapshotError('CONFIG_SOURCE_CHANGED', `${label} changed while it was read`);
    }
    return data;
  } catch (error) {
    if (error?.code?.startsWith?.('CONFIG_')) throw error;
    if (error?.code === 'ELOOP') throw snapshotError('CONFIG_SOURCE_SYMLINK', `${label} must not be a symbolic link`);
    if (error?.code === 'ENOENT') throw snapshotError('CONFIG_SOURCE_MISSING', `${label} is unavailable`);
    throw snapshotError('CONFIG_SOURCE_INVALID', `${label} could not be read`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function createConfigSnapshot({ envPath, credentialsPath, maxSourceBytes = CONFIG_SNAPSHOT_LIMITS.maxSourceBytes } = {}) {
  if (typeof envPath !== 'string' || !path.isAbsolute(envPath)
      || typeof credentialsPath !== 'string' || !path.isAbsolute(credentialsPath)) {
    throw new TypeError('Absolute server-owned config source paths are required');
  }
  if (!Number.isInteger(maxSourceBytes) || maxSourceBytes < 1 || maxSourceBytes > CONFIG_SNAPSHOT_LIMITS.maxSourceBytes) {
    throw new TypeError('Invalid config source size limit');
  }
  const sources = Object.freeze([
    Object.freeze({ id: 'environment', path: envPath }),
    Object.freeze({ id: 'credentials', path: credentialsPath }),
  ]);
  return async function snapshot() {
    // Each source is opened without symlink following and read exactly once.
    // The two-file operation is not a filesystem transaction; this helper only
    // attests the exact bytes returned by this invocation.
    const env = await readSnapshotSource(sources[0].path, 'environment source', maxSourceBytes);
    const credentials = await readSnapshotSource(sources[1].path, 'credentials source', maxSourceBytes);
    const discovered = [
      ...parseEnvCredentials(env).map(item => ({ ...item, source: 'environment' })),
      ...parseJsonCredentials(credentials).map(item => ({ ...item, source: 'credentials' })),
    ];
    if (discovered.length === 0) throw snapshotError('CONFIG_CREDENTIALS_MISSING', 'No supported current credentials were found');
    if (discovered.length > CONFIG_SNAPSHOT_LIMITS.maxCredentials) throw snapshotError('CONFIG_CREDENTIAL_LIMIT', 'Too many credential fields were found');
    if (discovered.some(item => Buffer.byteLength(item.name) > CONFIG_SNAPSHOT_LIMITS.maxCredentialNameBytes)) {
      throw snapshotError('CONFIG_SOURCE_MALFORMED', 'Credential field name exceeds the size limit');
    }

    const chunks = [];
    let outputBytes = 0;
    const append = value => {
      const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
      chunks.push(data); outputBytes += data.length;
    };
    const sourceReceipts = [];
    const sourceStarts = new Map();
    for (const [source, data] of [[sources[0], env], [sources[1], credentials]]) {
      append(`--- ${source.id} ---\n`);
      const startByte = outputBytes;
      sourceStarts.set(source.id, startByte);
      append(data);
      const endByte = outputBytes;
      if (data[data.length - 1] !== 0x0a) append('\n');
      sourceReceipts.push(Object.freeze({ id: source.id, sha256: sha256(data), bytes: data.length,
        range: Object.freeze({ startByte, endByte }) }));
    }
    const credentialReceipts = [];
    for (const item of discovered) {
      const sourceData = item.source === 'environment' ? env : credentials;
      const value = sourceData.subarray(item.startByte, item.endByte);
      const startByte = sourceStarts.get(item.source) + item.startByte;
      const endByte = sourceStarts.get(item.source) + item.endByte;
      credentialReceipts.push(Object.freeze({ name: item.name, source: item.source,
        valueSha256: sha256(value), valueBytes: value.length,
        range: Object.freeze({ startByte, endByte }) }));
    }
    const output = Buffer.concat(chunks);
    if (output.length > CONFIG_SNAPSHOT_LIMITS.maxOutputBytes) throw snapshotError('CONFIG_OUTPUT_OVERSIZE', 'Config snapshot output exceeds the size limit');
    return Object.freeze({
      output: output.toString('utf8'),
      observation: Object.freeze({
        version: CONFIG_SNAPSHOT_VERSION,
        outputSha256: sha256(output),
        outputBytes: output.length,
        sources: Object.freeze(sourceReceipts),
        credentials: Object.freeze(credentialReceipts),
      }),
    });
  };
}

function buildConfigSnapshotProgram(invocationId) {
  if (typeof invocationId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(invocationId)) {
    throw new TypeError('A version 4 invocation UUID is required');
  }
  const definitions = [
    snapshotError, sha256, decodeUtf8, credentialValue, parseEnvCredentials,
    parseJsonCredentials, readSnapshotSource, createConfigSnapshot,
  ].map(fn => fn.toString()).join('\n');
  return [
    "'use strict';",
    "const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');const {TextDecoder}=require('node:util');",
    `const CONFIG_SNAPSHOT_VERSION=${JSON.stringify(CONFIG_SNAPSHOT_VERSION)};`,
    `const CONFIG_SNAPSHOT_LIMITS=Object.freeze(${JSON.stringify(CONFIG_SNAPSHOT_LIMITS)});`,
    `const ENV_CREDENTIAL_FIELDS=new Set(${JSON.stringify([...ENV_CREDENTIAL_FIELDS])});`,
    `const JSON_CREDENTIAL_FIELDS=new Set(${JSON.stringify([...JSON_CREDENTIAL_FIELDS])});`,
    definitions,
    `(async()=>{const snapshot=createConfigSnapshot({envPath:'/opt/app/config/.env',credentialsPath:'/var/secrets/credentials.json'});const result=await snapshot();process.stdout.write(JSON.stringify({ok:true,invocationId:${JSON.stringify(invocationId)},...result}));})().catch(()=>{process.stdout.write(JSON.stringify({ok:false,error:'CONFIG_SNAPSHOT_UNAVAILABLE'}));process.exitCode=70;});`,
  ].join('\n');
}

// Lab process environment — REAL env the exec'd command inherits. `env` genuinely
// prints these; the app scans that output for flags. Kept in sync with the
// values the config files advertise so the lesson is internally consistent.
const LAB_ENV = {
  USER: 'mcp-admin',
  HOME: '/home/mcp-admin',
  HOSTNAME: 'mcp-server-prod-01',
  PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  SHELL: '/bin/bash',
  TERM: 'xterm-256color',
  LANG: 'en_US.UTF-8',
  APP_ENV: 'production',
  MCP_PORT: '3100',
  DB_HOST: '10.0.1.50',
  DB_PORT: '5432',
  DB_USER: 'mcp_service',
  DB_PASSWORD: 'McP#Pr0d!2026',
  DB_NAME: 'acme_production',
  API_KEY: 'sk-mcp-a8f2k9d1e4b7c3f6',
  SECRET_TOKEN: 'st_mcp_7f3c9a1e5b2d8046',
  INTERNAL_SERVICE_URL: 'http://10.0.1.100:8080/api',
  JWT_SECRET: 'mcp_K9#xP2$vL5nQ8wR',
  NODE_ENV: 'production',
  LOG_LEVEL: 'warn',
};

let BWRAP_AVAILABLE = false;
let CODEBOT_STRICT_AVAILABLE = false;
let CODEBOT_STRICT_DIAGNOSTIC = null;

const CODEBOT_ISOLATION = 'bwrap-codebot-v1';
const CODEBOT_MAX_TRANSFORM_BYTES = 64 * 1024;
const CODEBOT_ENV = {
  PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  USER: 'codebot', HOME: '/work', HOSTNAME: 'codebot-lab',
  LANG: 'C.UTF-8', NODE_ENV: 'production',
};
const CODEBOT_ENV_FILE = [
  'DATABASE_URL=postgres://admin:SuperSecret123@db.internal:5432/prod',
  'API_KEY=sk-live-a1b2c3d4e5f6',
  'JWT_SECRET=my-jwt-secret-key-2024',
  'OLLAMA_MODEL=llama3.1:8b',
  'NODE_ENV=production',
  'REDIS_URL=redis://cache.internal:6379',
].join('\n');
const CODEBOT_SSH_KEY = [
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  'b3BlbnNzaC1rZXktdjEAAAAEbm9uZQAAAA==',
  'AAABAAAAB3NzaC1yc2EAAAADAQABAAABgQC7lf4nKx...',
  'Y2VzGHKP4mNVPQlBMo3YpP4BBBBBBBBBBBBB...',
  '-----END OPENSSH PRIVATE KEY-----',
].join('\n');

function detectBwrap() {
  const probe = spawnSync('bwrap', ['--unshare-net', '--ro-bind', '/', '/', '/bin/true'], {
    timeout: 5000,
  });
  BWRAP_AVAILABLE = probe.status === 0;
  const via = BWRAP_AVAILABLE ? 'bwrap (empty netns + ro rootfs)' : 'plain non-root exec (no netns)';
  // eslint-disable-next-line no-console
  console.log(`[sandbox-runner] isolation mode: ${via}; uid=${process.getuid ? process.getuid() : 'n/a'}`);
  const strictArgv = [
    // The service runs as uid 10001 without host capabilities. Enter a user
    // namespace first so bwrap can create its private mount/network namespaces.
    '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-uts', '--unshare-ipc',
    '--die-with-parent', '--new-session', '--clearenv', ...existingRuntimeMounts(),
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work', '--chdir', '/work',
    '--setenv', 'PATH', CODEBOT_ENV.PATH, '/usr/local/bin/node', '-e', 'process.exit(0)',
  ];
  const strictProbe = spawnSync('bwrap', strictArgv, { timeout: 5000, env: { PATH: CODEBOT_ENV.PATH } });
  CODEBOT_STRICT_AVAILABLE = strictProbe.status === 0;
  const boundedStderr = Buffer.isBuffer(strictProbe.stderr)
    ? strictProbe.stderr.toString('utf8').replace(/[\r\n\t]+/g, ' ').slice(0, 512)
    : '';
  CODEBOT_STRICT_DIAGNOSTIC = Object.freeze({
    status: Number.isInteger(strictProbe.status) ? strictProbe.status : null,
    signal: typeof strictProbe.signal === 'string' ? strictProbe.signal : null,
    errorCode: typeof strictProbe.error?.code === 'string' ? strictProbe.error.code : null,
    stderr: boundedStderr,
  });
  console.log(`[sandbox-runner] CodeBot strict isolation: ${CODEBOT_STRICT_AVAILABLE ? CODEBOT_ISOLATION : 'unavailable'}`);
  if (!CODEBOT_STRICT_AVAILABLE) console.log(`[sandbox-runner] CodeBot strict probe: ${JSON.stringify(CODEBOT_STRICT_DIAGNOSTIC)}`);
}

function ensureSessionDir(sessionId) {
  const safe = String(sessionId || 'default').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64) || 'default';
  const dir = path.join(SESSION_ROOT, safe);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function existingRuntimeMounts() {
  // Fresh bwrap root: mount only the runtime needed for node, /bin/sh and
  // coreutils. The runner's /app, /opt and /sandbox trees are never mounted.
  return ['/usr', '/bin', '/lib', '/lib64']
    .filter(p => fs.existsSync(p))
    .flatMap(p => ['--ro-bind', p, p]);
}

function buildCodeBotBwrapArgv(wrapper, transformB64) {
  const argv = [
    '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-uts', '--unshare-ipc',
    '--die-with-parent', '--new-session', '--clearenv',
    ...existingRuntimeMounts(),
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work',
    '--dir', '/app', '--dir', '/app/config', '--dir', '/app/.ssh', '--dir', '/etc',
    '--file', '3', '/app/config/.env', '--file', '4', '/app/.ssh/id_rsa',
    '--file', '5', '/etc/passwd', '--file', '6', '/etc/group', '--chdir', '/work',
    '--hostname', 'codebot-lab',
  ];
  for (const [key, value] of Object.entries(CODEBOT_ENV)) argv.push('--setenv', key, value);
  argv.push('/usr/local/bin/node', '-e', wrapper, transformB64);
  return argv;
}

function codeBotWrapperSource(marker) {
  return [
    "'use strict';",
    "const source=Buffer.from(process.argv[1],'base64').toString('utf8');",
    'const result={};',
    'try {',
    // Deliberate fictional pkg-parse teaching sink. new Function keeps the
    // runner marker and parent-generated fixture canary out of eval scope.
    '  const execute=new Function("require","result","\\"use strict\\"; return eval("+JSON.stringify(source)+");");',
    '  const value=execute(require,result);',
    "  let output=result.transform_output !== undefined ? result.transform_output : value;",
    "  if (Buffer.isBuffer(output)) output=output.toString('utf8');",
    "  else if (output === undefined) output='';",
    "  else if (typeof output !== 'string') output=JSON.stringify(output);",
    `  process.stdout.write('\\n'+${JSON.stringify(marker)}+Buffer.from(JSON.stringify({executed:true,output})).toString('base64'));`,
    '} catch (error) {',
    "  process.stderr.write(String(error && error.stack || error));",
    '  process.exitCode=70;',
    '}',
  ].join('\n');
}

function runCodeBotTransform(sessionId, transform) {
  if (!CODEBOT_STRICT_AVAILABLE) return Promise.resolve({ ok: false, error: 'strict bubblewrap isolation unavailable', isolation: 'unavailable' });
  if (typeof transform !== 'string' || Buffer.byteLength(transform) > CODEBOT_MAX_TRANSFORM_BYTES) {
    return Promise.resolve({ ok: false, error: 'transform must be a string no larger than 65536 bytes', isolation: CODEBOT_ISOLATION });
  }
  const marker = `__CODEBOT_RESULT_${crypto.randomBytes(24).toString('hex')}__`;
  const envCanary = crypto.randomBytes(24).toString('hex');
  const sshCanary = crypto.randomBytes(24).toString('hex');
  const envFixture = `${CODEBOT_ENV_FILE}\nCODEBOT_ENV_PROOF=${envCanary}`;
  const sshFixture = CODEBOT_SSH_KEY.replace('\n-----END OPENSSH PRIVATE KEY-----', `\nCODEBOT_SSH_PROOF=${sshCanary}\n-----END OPENSSH PRIVATE KEY-----`);
  const argv = buildCodeBotBwrapArgv(codeBotWrapperSource(marker), Buffer.from(transform).toString('base64'));
  return new Promise(resolve => {
    // Explicit minimal environment: no runner/service credentials are inherited.
    const child = spawn('bwrap', argv, {
      env: { PATH: CODEBOT_ENV.PATH }, detached: true,
      stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
    });
    const fixtureStreams = [envFixture, sshFixture, 'codebot:x:10001:10001:CodeBot Lab:/work:/bin/bash\n', 'codebot:x:10001:\n'];
    fixtureStreams.forEach((content, index) => {
      child.stdio[index + 3].on('error', () => {});
      child.stdio[index + 3].end(content);
    });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), truncated = false, timedOut = false;
    const started = Date.now();
    const capture = (current, chunk) => {
      if (current.length >= MAX_OUTPUT_BYTES) { truncated = true; return current; }
      const next = Buffer.concat([current, chunk]);
      if (next.length > MAX_OUTPUT_BYTES) { truncated = true; return next.subarray(0, MAX_OUTPUT_BYTES); }
      return next;
    };
    child.stdout.on('data', chunk => { stdout = capture(stdout, chunk); });
    child.stderr.on('data', chunk => { stderr = capture(stderr, chunk); });
    const killTree = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} } };
    const timer = setTimeout(() => { timedOut = true; killTree(); }, EXEC_TIMEOUT_MS);
    child.on('error', error => {
      clearTimeout(timer); killTree();
      resolve({ ok: false, error: error.message, exitCode: 127, isolation: CODEBOT_ISOLATION, executed: false });
    });
    child.on('close', code => {
      clearTimeout(timer); killTree();
      const text = stdout.toString('utf8');
      const at = text.lastIndexOf(marker);
      let envelope = null;
      if (at >= 0) {
        try { envelope = JSON.parse(Buffer.from(text.slice(at + marker.length).trim(), 'base64').toString('utf8')); } catch {}
      }
      const exitCode = timedOut ? 124 : (code == null ? 1 : code);
      resolve({
        ok: exitCode === 0 && envelope?.executed === true,
        executed: exitCode === 0 && envelope?.executed === true,
        transformOutput: envelope?.output || text.slice(0, at >= 0 ? at : undefined).trim(),
        observations: {
          javascriptEvaluated: exitCode === 0 && envelope?.executed === true,
          envFileRead: String(envelope?.output || '').includes(envCanary),
          sshFileRead: String(envelope?.output || '').includes(sshCanary),
        },
        stderr: stderr.toString('utf8'), exitCode, timedOut, truncated,
        durationMs: Date.now() - started, isolation: CODEBOT_ISOLATION,
        ...(exitCode !== 0 ? { error: timedOut ? 'transform timed out' : 'transform failed' } : {}),
      });
    });
  });
}

function resetCodeBotSession(sessionId) {
  // CodeBot uses a new tmpfs /work and pipe-seeded fixtures for every execution,
  // so no learner-controlled bytes persist in the runner filesystem.
  return { ok: true, ephemeral: true, sessionId: strictSessionKeyForResponse(sessionId) };
}

function strictSessionKeyForResponse(sessionId) {
  return crypto.createHash('sha256').update(String(sessionId || '')).digest('hex').slice(0, 16);
}

function buildBwrapArgv(cwd, command) {
  // The security-critical property is an EMPTY network namespace (--unshare-net):
  // the command cannot reach 169.254.169.254, the app, or the internet. We
  // ro-bind the real rootfs (so all coreutils + the seeded lab files are real),
  // then rw-bind only the mutable lab dirs + the per-session workdir. We avoid
  // a fresh proc/pid mount (rejected in some nested/unprivileged runtimes).
  //
  // --dev /dev mounts a FRESH minimal writable devtmpfs (real /dev/null,
  // /dev/zero, /dev/urandom, ...). Without it, /dev arrives only via the
  // top-level --ro-bind / /, which makes /dev/null READ-ONLY → any command
  // using `2>/dev/null`, `>/dev/null`, or output redirects fails with
  // "Permission denied". --dev is orthogonal to --unshare-net, so the empty
  // network namespace (no route to the metadata/app/internet) is unchanged.
  const argv = [
    '--unshare-net', '--unshare-uts', '--unshare-ipc',
    '--die-with-parent',
    '--ro-bind', '/', '/',
    '--dev', '/dev',
  ];
  for (const d of MUTABLE_LAB_DIRS) {
    if (fs.existsSync(d)) argv.push('--bind', d, d);
  }
  argv.push('--bind', cwd, cwd, '--chdir', cwd);
  argv.push('/bin/bash', '-lc', command);
  return argv;
}

function runCommand(sessionId, command) {
  return new Promise((resolve) => {
    const cwd = ensureSessionDir(sessionId);
    const env = { ...LAB_ENV };
    let bin, argv;
    if (BWRAP_AVAILABLE) {
      bin = 'bwrap';
      argv = buildBwrapArgv(cwd, command);
    } else {
      bin = '/bin/bash';
      argv = ['-lc', command];
    }

    const child = spawn(bin, argv, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let truncated = false;
    let killedByTimeout = false;
    const started = Date.now();

    const capture = (buf, chunk) => {
      if (buf.length >= MAX_OUTPUT_BYTES) { truncated = true; return buf; }
      const next = Buffer.concat([buf, chunk]);
      if (next.length > MAX_OUTPUT_BYTES) { truncated = true; return next.subarray(0, MAX_OUTPUT_BYTES); }
      return next;
    };
    child.stdout.on('data', (c) => { stdout = capture(stdout, c); });
    child.stderr.on('data', (c) => { stderr = capture(stderr, c); });

    const timer = setTimeout(() => {
      killedByTimeout = true;
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
    }, EXEC_TIMEOUT_MS);

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        stdout: stdout.toString('utf8'),
        stderr: (stderr.toString('utf8') + `\n[runner] spawn error: ${err.message}`).trim(),
        exitCode: 127, truncated, timedOut: false,
        durationMs: Date.now() - started,
        isolation: BWRAP_AVAILABLE ? 'bwrap-netns' : 'plain',
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        stdout: stdout.toString('utf8'),
        stderr: stderr.toString('utf8'),
        exitCode: killedByTimeout ? 124 : (code == null ? (signal ? 137 : 1) : code),
        truncated,
        timedOut: killedByTimeout,
        durationMs: Date.now() - started,
        isolation: BWRAP_AVAILABLE ? 'bwrap-netns' : 'plain',
      });
    });
  });
}

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

/**
 * Restore the mutable lab files from the pristine snapshot baked at build time,
 * and clear the per-session workdir. Makes the mutation objectives repeatable.
 */
function resetSession(sessionId) {
  const restored = [];
  if (fs.existsSync(PRISTINE_ROOT)) {
    for (const d of MUTABLE_LAB_DIRS) {
      const rel = d.replace(/^\//, '');
      const from = path.join(PRISTINE_ROOT, rel);
      if (fs.existsSync(from) && fs.existsSync(d)) {
        try {
          for (const entry of fs.readdirSync(from)) {
            copyRecursive(path.join(from, entry), path.join(d, entry));
          }
          restored.push(d);
        } catch (e) { /* best effort */ }
      }
    }
  }
  const dir = ensureSessionDir(sessionId);
  try {
    for (const entry of fs.readdirSync(dir)) {
      fs.rmSync(path.join(dir, entry), { recursive: true, force: true });
    }
  } catch { /* ignore */ }
  return { restored, workdir: dir };
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1_000_000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
  });
}

function json(res, code, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(payload);
}

function createConfigSnapshotHandler(snapshot) {
  return async body => {
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'invocationId,sessionId'
      || typeof body.sessionId !== 'string' || !/^mcp_[1-9][0-9]{0,9}$/.test(body.sessionId)
      || Number(body.sessionId.slice(4)) > 2147483647
      || typeof body.invocationId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.invocationId)) {
      return { status: 400, body: { ok: false, error: 'INVALID_CONFIG_INVOCATION' } };
    }
    try {
      const result = await snapshot();
      return { status: 200, body: { ok: true, invocationId: body.invocationId, ...result } };
    } catch {
      return { status: 503, body: { ok: false, error: 'CONFIG_SNAPSHOT_UNAVAILABLE' } };
    }
  };
}
// Paths are part of the lab implementation, never supplied by a learner or a
// request. Reading current buffers proves disclosure, not per-session storage
// isolation: generic MCP mutable-directory separation remains separate work.
const configSnapshotHandler = createConfigSnapshotHandler(createConfigSnapshot({
  envPath: '/opt/app/config/.env', credentialsPath: '/var/secrets/credentials.json',
}));
const ownedTargetApi = createOwnedTargetApiFromEnvironment();
const policyRenderer = createPolicyRendererFromEnvironment();

const server = http.createServer(async (req, res) => {
  try {
    if (req.url === '/secureshop/policy-render') {
      res.setHeader('cache-control', 'no-store');
      if (!policyRenderer.enabled) return json(res, 404, { error: 'not found' });
      if (!policyRenderer.available) return json(res, 503, { error: 'POLICY_RENDER_UNAVAILABLE' });
      return policyRenderer.handler.handle(req, res);
    }
    if (req.url.startsWith('/owned-targets/')) {
      if (!ownedTargetApi) return json(res, 404, { error: 'not found' });
      const authorization = req.headers.authorization;
      const token = typeof authorization === 'string' && authorization.startsWith('Bearer ')
        ? authorization.slice('Bearer '.length) : null;
      const result = await ownedTargetApi.handle({ method: req.method, path: req.url,
        token, body: req.method === 'POST' ? await readBody(req) : undefined });
      res.setHeader('cache-control', 'no-store');
      return json(res, result.status, result.body);
    }
    if (req.method === 'GET' && req.url === '/health') {
      return json(res, 200, {
        status: 'ok',
        isolation: BWRAP_AVAILABLE ? 'bwrap-netns' : 'plain',
        bwrap: BWRAP_AVAILABLE,
        codebotIsolation: CODEBOT_STRICT_AVAILABLE ? CODEBOT_ISOLATION : 'unavailable',
        codebotAvailable: CODEBOT_STRICT_AVAILABLE,
        codebotDiagnostic: CODEBOT_STRICT_AVAILABLE ? null : CODEBOT_STRICT_DIAGNOSTIC,
        policyRenderer: { enabled: policyRenderer.enabled, available: policyRenderer.available,
          isolation: policyRenderer.isolation },
        uid: process.getuid ? process.getuid() : null,
      });
    }
    if (req.method === 'POST' && req.url === '/codebot/transform') {
      const { sessionId, transform } = await readBody(req);
      if (!/^codebot-[a-f0-9]{32}$/.test(String(sessionId || ''))) {
        return json(res, 400, { ok: false, error: 'valid CodeBot session identity is required' });
      }
      const result = await runCodeBotTransform(sessionId, transform);
      return json(res, result.error === 'strict bubblewrap isolation unavailable' ? 503 : 200, result);
    }
    if (req.method === 'POST' && req.url === '/codebot/reset') {
      const { sessionId } = await readBody(req);
      if (!/^codebot-[a-f0-9]{32}$/.test(String(sessionId || ''))) {
        return json(res, 400, { ok: false, error: 'valid CodeBot session identity is required' });
      }
      return json(res, 200, resetCodeBotSession(sessionId));
    }
    if (req.method === 'POST' && req.url === '/config/snapshot') {
      const result = await configSnapshotHandler(await readBody(req));
      res.setHeader('cache-control', 'no-store');
      return json(res, result.status, result.body);
    }
    if (req.method === 'POST' && req.url === '/exec') {
      const { sessionId, command } = await readBody(req);
      if (!command || typeof command !== 'string') {
        return json(res, 400, { error: 'command (string) is required' });
      }
      const result = await runCommand(sessionId || 'default', command);
      return json(res, 200, result);
    }
    if (req.method === 'POST' && req.url === '/reset') {
      const { sessionId } = await readBody(req);
      return json(res, 200, { status: 'reset', ...resetSession(sessionId || 'default') });
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
});

function createSandboxRunnerShutdown({ serverInstance = server, policyRendererInstance = policyRenderer,
  transportDrainMs = 1000 } = {}) {
  if (!Number.isInteger(transportDrainMs) || transportDrainMs < 100 || transportDrainMs > 5000) {
    throw new TypeError('Bounded sandbox transport drain required');
  }
  let pending = null;
  return function shutdown() {
    if (pending) return pending;
    pending = (async () => {
      await policyRendererInstance.close();
      if (!serverInstance.listening) return;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => serverInstance.closeAllConnections?.(), transportDrainMs);
        timer.unref?.();
        serverInstance.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); });
      });
    })();
    return pending;
  };
}

const shutdownSandboxRunner = createSandboxRunnerShutdown();

if (require.main === module) {
  detectBwrap();
  server.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.log(`[sandbox-runner] listening on ${HOST}:${PORT}`);
  });
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
    shutdownSandboxRunner().catch(() => { process.exitCode = 1; });
  });
}

module.exports = {
  runCommand, resetSession, detectBwrap, LAB_ENV,
  runCodeBotTransform, resetCodeBotSession, buildCodeBotBwrapArgv,
  CODEBOT_ISOLATION, createConfigSnapshot, CONFIG_SNAPSHOT_VERSION, CONFIG_SNAPSHOT_LIMITS,
  buildConfigSnapshotProgram, createConfigSnapshotHandler,
  createPolicyRendererFromEnvironment, createSandboxRunnerShutdown,
};
