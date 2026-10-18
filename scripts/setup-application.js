'use strict';
// Fresh application setup. Existing environment files and databases are never reset.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const { createHash, randomBytes } = require('node:crypto');
const { execFile } = require('node:child_process');
const { runSetupCommand } = require('./lib/setup-command');
const { assertSupportedApplicationNodeVersion } = require('./application-node-runtime');
const {
  LocalDockerAuthorityError,
  authorityDigest,
  assertPrivateDirectory,
  assertPrivateStateFile,
  resolveDockerAuthority,
  verifyDockerAuthority,
  executeBoundDocker,
  writeLocalDockerAuthority,
  isLoopbackServiceUrl,
} = require('./local-docker-authority');
const { promisify } = require('node:util');
const { ensureLocalMailpit } = require('./local-mailpit');
const exec = promisify(execFile);
class SetupError extends Error {}
const OLLAMA_SETUP_GENERATE_URL = 'http://127.0.0.1:11434/api/generate';
const OLLAMA_SETUP_INFERENCE_TIMEOUT_MS = 120_000;

function workspaceId(root) { return createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 12); }
function selectOwnedCouponBundle({upgrade,qualifiedSecureShop,boundReviewsEnabled,couponPreference,analyticsPreference,
  ownedCoupons,ownedAnalytics,enableOwnedAnalytics}) {
  const qualified = qualifiedSecureShop || (upgrade && boundReviewsEnabled);
  const defaultCoupons = qualified && couponPreference !== false && analyticsPreference !== false;
  const coupons = ownedCoupons || defaultCoupons;
  return Object.freeze({ownedCoupons:coupons,
    ownedAnalytics:ownedAnalytics || enableOwnedAnalytics || coupons
      || (upgrade && boundReviewsEnabled && analyticsPreference !== null)});
}
async function prepareSetupPrivateDirectory({ homeDirectory, directory, id,
  // Filesystem authority follows the actual host, independently of a selected
  // sidecar platform. Overrides here are only controlled-test providers.
  filesystemPlatform = process.platform, privateState,
} = {}) {
  if (filesystemPlatform !== 'win32') {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    await fs.chmod(directory, 0o700);
    return;
  }
  try {
    const { normalizePrivatePath } = require('./lib/windows-private-state');
    const home = normalizePrivatePath(homeDirectory);
    const privateBase = normalizePrivatePath(path.win32.join(home, '.dvaia'));
    if (!/^[a-f0-9]{12}$/.test(id) || normalizePrivatePath(directory) !== path.win32.join(privateBase, id)) throw Error();
    const native = privateState || require('./lib/windows-private-state');
    // Each call creates only its requested private leaf. Ordinary home parents
    // must already exist and pass native ancestor admission.
    native.ensurePrivateDirectory(privateBase);
    native.ensurePrivateDirectory(directory);
    native.inspectPrivateDirectory(privateBase);
    native.inspectPrivateDirectory(directory);
  } catch {
    throw Object.assign(new SetupError('Private setup directory unavailable'), { code: 'SETUP_PRIVATE_DIRECTORY_INVALID' });
  }
}
async function privateFile(filename, content) {
  await fs.writeFile(filename, content, { flag: 'wx', mode: 0o600 });
}
async function readJson(filename) {
  try { return JSON.parse(await fs.readFile(filename, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function run(command, args, cwd, env = process.env, options = {}) {
  await runSetupCommand(command, args, cwd, env, options, SetupError);
}
const REQUIRED_INSTALLED_COMPONENTS = Object.freeze([
  'langchain',
  '@langchain/core',
  '@langchain/langgraph',
  '@langchain/ollama',
  '@modelcontextprotocol/sdk',
  'pg',
  'express',
  'bcryptjs',
  'express-rate-limit',
  'jsonwebtoken',
  'multer',
  'xml2js',
  'sax',
  'zod',
  'puppeteer',
  '@huggingface/transformers',
]);
const REQUIRED_COMPONENT_ENTRY_POINTS = Object.freeze({
  '@modelcontextprotocol/sdk': '@modelcontextprotocol/sdk/server/index.js',
});
async function verifyInstalledComponents(root) {
  try { root = await fs.realpath(root); }
  catch { throw new SetupError('Application root is unavailable'); }
  let manifest;
  try { manifest = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8')); }
  catch { throw new SetupError('Application package manifest is unavailable or invalid'); }
  let nodeModulesRoot;
  try { nodeModulesRoot = await fs.realpath(path.join(root, 'node_modules')); }
  catch { throw new SetupError('Application dependencies are not installed; rerun setup without --no-install'); }
  const versions = {};
  for (const name of REQUIRED_INSTALLED_COMPONENTS) {
    const declared = manifest.dependencies?.[name];
    if (typeof declared !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(declared)) {
      throw new SetupError(`Required component ${name} must have an exact application version`);
    }
    let installed;
    try { installed = JSON.parse(await fs.readFile(path.join(root, 'node_modules', ...name.split('/'), 'package.json'), 'utf8')); }
    catch { throw new SetupError(`Required component ${name}@${declared} is not installed; rerun setup without --no-install`); }
    if (installed.version !== declared) {
      throw new SetupError(`Required component ${name} is ${installed.version || 'invalid'}, expected ${declared}; rerun setup without --no-install`);
    }
    let entry;
    try { entry = require.resolve(REQUIRED_COMPONENT_ENTRY_POINTS[name] || name, { paths: [root] }); }
    catch { throw new SetupError(`Required component ${name}@${declared} has no loadable application entry point`); }
    const resolvedEntry = await fs.realpath(entry);
    if (resolvedEntry !== nodeModulesRoot && !resolvedEntry.startsWith(`${nodeModulesRoot}${path.sep}`)) {
      throw new SetupError(`Required component ${name}@${declared} did not resolve from this application`);
    }
    versions[name] = declared;
  }
  return Object.freeze(versions);
}
async function requestOllamaGeneration({ model, endpoint = OLLAMA_SETUP_GENERATE_URL,
  timeoutMs = OLLAMA_SETUP_INFERENCE_TIMEOUT_MS } = {}) {
  if (endpoint !== OLLAMA_SETUP_GENERATE_URL) throw new SetupError('Ollama setup inference must use the local loopback endpoint');
  const body = Buffer.from(JSON.stringify({
    model,
    prompt: 'Reply with READY to verify local inference.',
    stream: false,
    options: { temperature: 0, num_predict: 8 },
  }));
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      callback(value);
    };
    const deadline = setTimeout(() => {
      const error = new Error('Ollama inference timed out');
      error.code = 'ETIMEDOUT';
      request?.destroy(error);
      finish(reject, error);
    }, timeoutMs);
    request = http.request(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': body.length },
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 1024 * 1024) {
          const error = new Error('Ollama inference response exceeded the setup limit');
          error.code = 'OLLAMA_INVALID_RESPONSE';
          response.destroy(error);
          finish(reject, error);
        } else chunks.push(chunk);
      });
      response.on('error', error => finish(reject, error));
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(`Ollama inference returned HTTP ${response.statusCode}`);
          error.code = 'OLLAMA_HTTP_ERROR';
          error.statusCode = response.statusCode;
          finish(reject, error);
          return;
        }
        try { finish(resolve, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch {
          const error = new Error('Ollama inference returned invalid JSON');
          error.code = 'OLLAMA_INVALID_RESPONSE';
          finish(reject, error);
        }
      });
    });
    request.on('error', error => finish(reject, error));
    request.end(body);
  });
}
async function ensureOllamaModel({
  model = 'llama3.1:8b', root = path.resolve(__dirname, '..'), env = process.env,
  execute = exec, runCommand = run, requestGeneration = requestOllamaGeneration,
} = {}) {
  if (model !== 'llama3.1:8b') throw new SetupError('Fresh setup requires the qualified llama3.1:8b local model');
  const localEnv = { ...env, OLLAMA_HOST: 'http://127.0.0.1:11434' };
  let alreadyInstalled = true;
  try {
    await execute('ollama', ['show', model], { cwd: root, env: localEnv, maxBuffer: 1024 * 1024, timeout: 15_000 });
  } catch (error) {
    if (error && error.code === 'ENOENT') throw new SetupError('Ollama is required. Install it with the platform installer, then rerun setup.');
    alreadyInstalled = false;
    try {
      await runCommand('ollama', ['pull', model], root, localEnv, { timeoutMs: 60 * 60 * 1000 });
      await execute('ollama', ['show', model], { cwd: root, env: localEnv, maxBuffer: 1024 * 1024, timeout: 15_000 });
    } catch {
      throw new SetupError(`Ollama could not install ${model}. Ensure the local Ollama service is running, then rerun setup.`);
    }
  }
  let generation;
  try {
    generation = await requestGeneration({ model, endpoint: OLLAMA_SETUP_GENERATE_URL,
      timeoutMs: OLLAMA_SETUP_INFERENCE_TIMEOUT_MS });
  } catch (error) {
    if (error?.code === 'ETIMEDOUT' || error?.name === 'AbortError') {
      throw new SetupError(`Ollama inference timed out while verifying ${model} at ${OLLAMA_SETUP_GENERATE_URL}. Ensure Ollama has enough memory to run the local 8B model, then rerun setup.`);
    }
    if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH'].includes(error?.code)) {
      throw new SetupError(`Ollama became unavailable at ${OLLAMA_SETUP_GENERATE_URL}. Restart the local Ollama service, then rerun setup.`);
    }
    throw new SetupError(`Ollama inference failed for ${model} at ${OLLAMA_SETUP_GENERATE_URL}. Check the local Ollama service logs, then rerun setup.`);
  }
  if (!generation || generation.model !== model) {
    throw new SetupError(`Ollama inference returned the wrong model identity; expected ${model}. Verify the local model installation, then rerun setup.`);
  }
  if (generation.done !== true || typeof generation.response !== 'string' || !generation.response.trim()) {
    throw new SetupError(`Ollama inference returned no completed output for ${model}. Check the local model and available memory, then rerun setup.`);
  }
  return Object.freeze({ model, alreadyInstalled, pulled: !alreadyInstalled });
}
async function verifyBrowserRuntime({
  root = path.resolve(__dirname, '..'), executablePath,
  loadPuppeteer = target => require(require.resolve('puppeteer', { paths: [target] })),
} = {}) {
  let configuredExecutablePath;
  if (executablePath !== undefined) {
    if (typeof executablePath !== 'string' || !path.isAbsolute(executablePath) || executablePath.includes('\0')) {
      throw new SetupError('PUPPETEER_EXECUTABLE_PATH must be an absolute executable path');
    }
    try {
      const resolved = await fs.realpath(executablePath);
      const stat = await fs.stat(resolved);
      if (!stat.isFile()) throw new Error('not a regular file');
      await fs.access(resolved, require('node:fs').constants.X_OK);
    } catch {
      throw new SetupError('PUPPETEER_EXECUTABLE_PATH does not identify an executable browser');
    }
    configuredExecutablePath = executablePath;
  }
  let browser;
  try {
    const puppeteer = loadPuppeteer(root);
    if (!puppeteer || typeof puppeteer.launch !== 'function') throw new Error('invalid Puppeteer module');
    const launchOptions = { headless: true, timeout: 30_000 };
    if (configuredExecutablePath) launchOptions.executablePath = configuredExecutablePath;
    browser = await puppeteer.launch(launchOptions);
    if (!browser || typeof browser.close !== 'function') throw new Error('invalid browser handle');
    await browser.close();
    browser = null;
  } catch {
    if (browser) await browser.close().catch(() => {});
    throw new SetupError('Puppeteer could not launch a sandboxed browser. Install a supported browser or set PUPPETEER_EXECUTABLE_PATH, then rerun setup.');
  }
  return Object.freeze({ ready: true, configuredExecutablePath: configuredExecutablePath || null, sandboxDisabled: false });
}
async function ensurePuppeteerBrowserInstalled({
  root = path.resolve(__dirname, '..'), env = process.env, runCommand = run,
  platform = process.platform,
  loadPuppeteer = target => require(require.resolve('puppeteer', { paths: [target] })),
} = {}) {
  if (env.PUPPETEER_EXECUTABLE_PATH) {
    return Object.freeze({ ready: true, downloaded: false, configuredExecutablePath: env.PUPPETEER_EXECUTABLE_PATH });
  }
  const skipped = ['PUPPETEER_SKIP_DOWNLOAD', 'PUPPETEER_SKIP_CHROME_DOWNLOAD']
    .find(name => /^(?:1|true|yes)$/i.test(String(env[name] || '')));
  if (skipped) {
    throw new SetupError(`${skipped} requires an explicit PUPPETEER_EXECUTABLE_PATH during supported setup`);
  }
  const puppeteer = loadPuppeteer(root);
  if (!puppeteer || typeof puppeteer.executablePath !== 'function') {
    throw new SetupError('The installed Puppeteer package does not expose its browser path');
  }
  const executableReady = async filename => {
    if (typeof filename !== 'string' || !path.isAbsolute(filename)) return false;
    try {
      const stat = await fs.stat(filename);
      await fs.access(filename, require('node:fs').constants.X_OK);
      return stat.isFile();
    } catch { return false; }
  };
  let executablePath = await puppeteer.executablePath();
  if (await executableReady(executablePath)) {
    return Object.freeze({ ready: true, downloaded: false, configuredExecutablePath: null });
  }
  const modulesRoot = await fs.realpath(path.join(root, 'node_modules'));
  let cli;
  if (platform === 'win32') {
    // Windows npm's .bin/puppeteer is a shell shim, not the JavaScript CLI.
    // Resolve the installed package's declared bin and admit it within both
    // the package and modules roots before passing it directly to Node.
    const packageRoot = await fs.realpath(path.join(root, 'node_modules', 'puppeteer'));
    const manifest = JSON.parse(await fs.readFile(path.join(packageRoot, 'package.json'), 'utf8'));
    const bin = typeof manifest.bin === 'string' ? manifest.bin : manifest.bin?.puppeteer;
    if (typeof bin !== 'string' || bin.includes('\0') || path.isAbsolute(bin)) throw new SetupError('The installed Puppeteer browser command is invalid');
    cli = await fs.realpath(path.resolve(packageRoot, bin));
    const packageRelative = path.relative(packageRoot, cli);
    if (!packageRelative || packageRelative.startsWith('..') || path.isAbsolute(packageRelative) || !/\.(?:c|m)?js$/i.test(cli) || !(await fs.stat(cli)).isFile()) {
      throw new SetupError('The installed Puppeteer browser command is outside its package');
    }
  } else cli = await fs.realpath(path.join(root, 'node_modules', '.bin', 'puppeteer'));
  const relative = path.relative(modulesRoot, cli);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new SetupError('The installed Puppeteer browser command is outside node_modules');
  }
  await runCommand(process.execPath, ['--use-system-ca', cli, 'browsers', 'install', 'chrome'], root, env,
    { timeoutMs: 600_000 });
  executablePath = await puppeteer.executablePath();
  if (!await executableReady(executablePath)) {
    throw new SetupError('Puppeteer browser installation completed without the required executable');
  }
  return Object.freeze({ ready: true, downloaded: true, configuredExecutablePath: null });
}
function npmRuntimeEnvironment(admittedNpm, env, platform) {
  const base = admittedNpm?.environment || env;
  if (platform !== 'win32' || !admittedNpm) return base;
  // Match default startup: npm does not add Node's directory to lifecycle
  // PATH. Copy and collapse case variants for this command's children only.
  const result = { ...base }, pathKeys = Object.keys(base).filter(key => key.toLowerCase() === 'path');
  const priorPaths = pathKeys.flatMap(key => String(base[key] || '').split(';')).filter(Boolean);
  for (const key of pathKeys) delete result[key];
  result.Path = [path.win32.dirname(admittedNpm.command), ...priorPaths].join(';');
  return result;
}
function setupRendererRoot(root, env, key, directory) {
  const configured = env[key];
  if (configured === undefined || configured === '') return path.join(root, 'client/build', directory);
  if (typeof configured !== 'string' || !path.isAbsolute(configured)) {
    throw new SetupError(`${key} must be an absolute renderer directory`);
  }
  return path.resolve(configured);
}
async function ensureReviewRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadRenderer = require('../server/services/secureshopReviewCardRenderer').loadSecureShopReviewCardRenderer } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:review-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadRenderer({ root: setupRendererRoot(root, env, 'SECURESHOP_REVIEW_RENDERER_ROOT', 'secureshop-review-renderer') });
  const body = 'DVAIA installation renderer verification';
  const markup = await renderer.renderReviewCard({ id: 1, body, rating: 5,
    author_id: 1, product_id: 1, status: 'published', created_at: '2026-01-01T00:00:00Z' });
  if (typeof markup !== 'string' || !markup.includes(body)) {
    throw new SetupError('SecureShop review renderer verification failed');
  }
  return Object.freeze({ ready: true, sourceSha256: renderer.sourceSha256,
    artifactSha256: renderer.artifactSha256 });
}

async function ensureProductDescriptionRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadProductRenderer = require('../server/services/secureshopProductDescriptionRenderer').loadSecureShopProductDescriptionRenderer } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:product-description-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadProductRenderer({ root: setupRendererRoot(root, env, 'SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_ROOT', 'secureshop-product-description-renderer') });
  if (renderer?.componentId !== 'SecureShop.Product.Description'
      || !/^[a-f0-9]{64}$/.test(renderer.sourceSha256)
      || !/^[a-f0-9]{64}$/.test(renderer.artifactSha256)
      || typeof renderer.renderProductDescription !== 'function') {
    throw new SetupError('SecureShop product description renderer verification failed');
  }
  const description = 'DVAIA installation product description verification';
  const markup = await renderer.renderProductDescription({ id: 1, description_html: description });
  if (typeof markup !== 'string' || !markup.includes(description)) {
    throw new SetupError('SecureShop product description renderer verification failed');
  }
  return Object.freeze({ artifactReady: true, componentId: renderer.componentId,
    sourceSha256: renderer.sourceSha256, artifactSha256: renderer.artifactSha256 });
}

async function ensureMailRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadMailRenderer = require('../server/services/secureshopMailBrowserQualification').loadMailClientArtifact } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:mail-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadMailRenderer();
  if (renderer?.component?.id !== 'SecureShop.MailMessageBody'
      || !/^[a-f0-9]{64}$/.test(renderer.component.sourceSha256)
      || !/^[a-f0-9]{64}$/.test(renderer.component.artifactSha256)) {
    throw new SetupError('SecureShop mail renderer verification failed');
  }
  // Artifact admission only; browser execution and objective readiness remain separate.
  return Object.freeze({ artifactReady: true, ...renderer.component });
}

async function ensureTicketRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadTicketRenderer = require('../server/services/secureshopTicketBrowserQualification').loadTicketClientArtifact } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:ticket-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadTicketRenderer();
  if (renderer?.component?.id !== 'SecureShop.AdminTicketBody'
      || !/^[a-f0-9]{64}$/.test(renderer.component.sourceSha256)
      || !/^[a-f0-9]{64}$/.test(renderer.component.artifactSha256)) {
    throw new SetupError('SecureShop ticket renderer verification failed');
  }
  // Artifact admission only; browser execution and objective readiness remain separate.
  return Object.freeze({ artifactReady: true, ...renderer.component });
}

async function ensureSearchEchoRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadSearchEchoRenderer = require('../server/services/secureshopSearchEchoBrowserQualification').loadSearchEchoClientArtifact } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:search-echo-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadSearchEchoRenderer();
  if (renderer?.component?.id !== 'SecureShop.SearchEcho'
      || !/^[a-f0-9]{64}$/.test(renderer.component.sourceSha256)
      || !/^[a-f0-9]{64}$/.test(renderer.component.artifactSha256)) {
    throw new SetupError('SecureShop search-echo renderer verification failed');
  }
  // Artifact admission only; browser execution and objective readiness remain separate.
  return Object.freeze({ artifactReady: true, ...renderer.component });
}

async function ensurePolicyOutputRenderer({ root, env = process.env, runCommand = run, admittedNpm,
  execute = exec, platform = process.platform,
  loadPolicyOutputRenderer = require('../server/services/secureshopPolicyOutputBrowserQualification').loadPolicyOutputClientArtifact } = {}) {
  if (platform === 'win32' && !admittedNpm) admittedNpm = await require('./lib/setup-npm-admission').admitSetupNpm({ environment: env, execute, platform });
  await runCommand(admittedNpm?.command || 'npm', [...(admittedNpm?.prefix || []), 'run', 'build:policy-output-renderer'], path.join(root, 'client'), npmRuntimeEnvironment(admittedNpm, env, platform));
  const renderer = loadPolicyOutputRenderer();
  if (renderer?.component?.id !== 'SecureShop.PolicyFinalResponse'
      || !/^[a-f0-9]{64}$/.test(renderer.component.sourceSha256)
      || !/^[a-f0-9]{64}$/.test(renderer.component.artifactSha256)) {
    throw new SetupError('SecureShop policy-output renderer verification failed');
  }
  // Artifact admission only; browser execution and objective readiness remain separate.
  return Object.freeze({ artifactReady: true, ...renderer.component });
}

async function verifySetupRuntime({
  root = path.resolve(__dirname, '..'), ensureModel = true, env = process.env,
  execute = exec, runCommand = run, loadPuppeteer, embeddingCacheDirectory, requestGeneration,
} = {}) {
  const installed = await verifyInstalledComponents(root);
  const model = ensureModel ? await ensureOllamaModel({ root, env, execute, runCommand, requestGeneration }) : null;
  const browser = await verifyBrowserRuntime({ root, executablePath: env.PUPPETEER_EXECUTABLE_PATH, loadPuppeteer });
  const embedding = ensureModel ? await ensureEmbeddingModel({ root, env, runCommand,
    cacheDirectory: embeddingCacheDirectory || env.XENOVA_CACHE || path.join(root, '.cache', 'embeddings') }) : null;
  return Object.freeze({ installed, model, browser, embedding });
}
async function prepareInstalledRuntime({ root, cacheDirectory, install, admittedNpm,
  env, execute, runCommand, loadPuppeteer, loadRenderer, loadMailRenderer, loadProductRenderer, loadTicketRenderer, loadSearchEchoRenderer, loadPolicyOutputRenderer, ensureModel, requestGeneration,
  platform = process.platform, verifyRuntime = verifySetupRuntime }) {
  if (install) {
    const args = [...admittedNpm.prefix, 'ci', '--strict-peer-deps', '--strict-allow-scripts'];
    const commandEnvironment = npmRuntimeEnvironment(admittedNpm, env, platform);
    await runCommand(admittedNpm.command, args, root, commandEnvironment);
    await runCommand(admittedNpm.command, args, path.join(root, 'client'), commandEnvironment);
    await ensurePuppeteerBrowserInstalled({ root, env, runCommand, loadPuppeteer, platform });
  }
  await ensureReviewRenderer({ root, env, runCommand, loadRenderer, admittedNpm, execute, platform });
  await ensureMailRenderer({ root, env, runCommand, loadMailRenderer, admittedNpm, execute, platform });
  await ensureProductDescriptionRenderer({ root, env, runCommand, loadProductRenderer, admittedNpm, execute, platform });
  await ensureTicketRenderer({ root, env, runCommand, loadTicketRenderer, admittedNpm, execute, platform });
  await ensureSearchEchoRenderer({ root, env, runCommand, loadSearchEchoRenderer, admittedNpm, execute, platform });
  await ensurePolicyOutputRenderer({ root, env, runCommand, loadPolicyOutputRenderer, admittedNpm, execute, platform });
  return verifyRuntime({ root, ensureModel, env, execute, runCommand, loadPuppeteer,
    embeddingCacheDirectory: cacheDirectory, requestGeneration });
}
async function ensureEmbeddingModel({ root = path.resolve(__dirname, '..'), cacheDirectory,
  env = process.env, runCommand = run } = {}) {
  if (typeof cacheDirectory !== 'string' || !path.isAbsolute(cacheDirectory) || cacheDirectory.includes('\0')) {
    throw new SetupError('XENOVA_CACHE must be an absolute embedding cache directory');
  }
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new SetupError('Embedding setup requires TLS verification; remove NODE_TLS_REJECT_UNAUTHORIZED=0');
  let cache;
  try {
    cache = await require('./verify-embedding-runtime').prepareEmbeddingCache(cacheDirectory);
    await runCommand(process.execPath, ['--use-system-ca', path.join(root, 'scripts/verify-embedding-runtime.js'),
      '--cache-dir', cache.directory], root, { ...env, XENOVA_CACHE: cache.directory }, { timeoutMs: 600_000 });
    await cache.check();
  } catch {
    throw new SetupError('The local embedding model could not be verified. Check download access, the model cache and trusted system certificates, then rerun setup.');
  }
  return Object.freeze({ model: 'Xenova/all-MiniLM-L6-v2', cacheDirectory: cache.directory, dimensions: 384, dtype: 'q8' });
}
function ownedRunnerOptions({ platform = process.platform, environment = process.env } = {}) {
  if (platform === 'linux') return Object.freeze({ platform, colimaProfile: undefined });
  if (platform === 'darwin') {
    return Object.freeze({
      platform,
      colimaProfile: environment.DVAIA_MCP_OWNED_COLIMA_PROFILE || 'colima-default',
    });
  }
  return Object.freeze({ platform, colimaProfile: undefined });
}
async function provisionOwnedRunnerForSetup({ root, directory, homeDirectory, platform = process.platform,
  environment = process.env, provisionFromEnvironment, ownedLabSession } = {}) {
  if (['false', '0'].includes(environment.MCP_SIDECARS_AUTOSTART)) return Object.freeze({ available: false, activationEnabled: false, profile: null, managedPath: path.join(directory, 'mcp-owned.env'), code: 'MCP_INSTALL_EXPLICITLY_DISABLED', stage: null });
  const options = ownedRunnerOptions({ platform, environment });
  try {
    const provision = provisionFromEnvironment || require('./install/mcp-owned-provision').provisionFromEnvironment;
    const result = await provision({
      root,
      home: homeDirectory,
      envPath: path.join(root, '.env'),
      managedPath: path.join(directory, 'mcp-owned.env'),
      platform: options.platform,
      colimaProfile: options.colimaProfile,
      activateQualified: true,
      activateObservedAction: true,
      activateIndirectInjection: true,
      activateSupplyChain: true,
      ...(ownedLabSession ? { ownedLabSession } : {}),
    });
    if (result?.ok !== true || result.available === false
      || result.managedPath !== path.join(directory, 'mcp-owned.env')
      || typeof result.profile !== 'string' || !result.profile.trim()
      || typeof result.activationEnabled !== 'boolean') {
      throw Object.assign(new Error('Invalid owned runner provisioning result'), {
        code: 'MCP_INSTALL_INVALID_RESULT', stage: 'owned-readiness',
      });
    }
    return Object.freeze({ available: true, activationEnabled: result.activationEnabled === true,
      profile: result.profile || null, managedPath: result.managedPath, code: null, stage: null });
  } catch (error) {
    return Object.freeze({ available: false, activationEnabled: false, profile: null,
      managedPath: path.join(directory, 'mcp-owned.env'), code: error?.code || 'MCP_INSTALL_FAILED',
      stage: error?.stage || null });
  }
}
function admitOwnedRunnerForSetup(ownedRunner, { required = true } = {}) {
  if (!required) return ownedRunner;
  if (ownedRunner?.available !== true) {
    throw Object.assign(new SetupError(
      'Required owned MCP/CodeBot runner readiness was not confirmed. Existing private setup configuration was preserved; inspect the private managed runner state, then run npm run setup:mcp-owned before starting the application.'),
    { code: 'MCP_INSTALL_REQUIRED_UNAVAILABLE' });
  }
  if (ownedRunner.activationEnabled !== true) {
    throw Object.assign(new SetupError(
      'Required owned MCP/CodeBot runner was prepared but not activated. Existing private setup configuration was preserved; run npm run setup:mcp-owned before starting the application.'),
    { code: 'MCP_INSTALL_REQUIRED_NOT_ACTIVATED' });
  }
  return ownedRunner;
}
async function availablePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(0, '127.0.0.1', resolve); });
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}
function validateLocalPostgresState(state, binding) {
  try { return require('./lib/setup-local-postgres-state').validateLocalPostgresState(state, binding); }
  catch { throw new SetupError('Local PostgreSQL setup state does not match this workspace'); }
}
function assertOwnedPostgresVolume(volume, { id }) {
  if (volume && volume.Labels?.['org.dvaia.workspace'] !== id) {
    throw new SetupError('An unowned PostgreSQL volume already exists; nothing was changed');
  }
}
function assertOwnedPostgresContainer(container, state, { id, name }) {
  if (!container) return;
  if (container.Config?.Labels?.['org.dvaia.workspace'] !== id) {
    throw new SetupError(`Container ${name} already exists without matching setup ownership; nothing was changed`);
  }
  const mount = container.Mounts?.find(item => item.Destination === '/var/lib/postgresql');
  const binding = container.HostConfig?.PortBindings?.['5432/tcp'];
  if (mount?.Type !== 'volume' || mount.Name !== name || !Array.isArray(binding) || binding.length !== 1
    || binding[0]?.HostIp !== '127.0.0.1' || binding[0]?.HostPort !== String(state.port)) {
    throw new SetupError(`Container ${name} does not match the owned PostgreSQL state; nothing was changed`);
  }
}
async function rewriteLocalPostgresState(statePath, originalBytes, state) {
  const pendingPath = `${statePath}.upgrade`;
  let handle;
  try {
    handle = await fs.open(pendingPath, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(state));
    await handle.sync();
  } catch (error) {
    if (error.code === 'EEXIST') throw new SetupError('Local PostgreSQL state upgrade requires review of the existing staging file');
    throw error;
  } finally { await handle?.close(); }
  try {
    if (!(await fs.readFile(statePath)).equals(originalBytes)) throw new SetupError('Local PostgreSQL state changed during authority adoption');
    await fs.rename(pendingPath, statePath);
    await fs.chmod(statePath, 0o600);
  } catch (error) {
    await fs.rm(pendingPath, { force: true });
    throw error;
  }
}
function createLocalPostgresSetup({filesystemPlatform=process.platform,fileSystem=fs,
  privateState=require('./lib/windows-private-state'),privateJournal,
  authorityTools={assertPrivateDirectory,assertPrivateStateFile,resolveDockerAuthority,verifyDockerAuthority,executeBoundDocker,writeLocalDockerAuthority,authorityDigest},
  findAvailablePort=availablePort,
}={}){
 const fs=fileSystem,storagePath=filesystemPlatform==='win32'?path.win32:path;
 if(filesystemPlatform==='win32'&&!privateJournal)privateJournal=require('./lib/windows-provisioning-journal').createWindowsProvisioningJournal({platform:filesystemPlatform,privateState});
 const {assertPrivateDirectory,assertPrivateStateFile,resolveDockerAuthority,verifyDockerAuthority,executeBoundDocker,writeLocalDockerAuthority,authorityDigest}=authorityTools;
 const storageFailure=()=>Object.assign(new SetupError('Local PostgreSQL private state unavailable'),{code:'LOCAL_POSTGRES_PRIVATE_STATE_INVALID'});
 const nativeRead=filePath=>{try{const bytes=privateState.readPrivateFile(filePath);if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw Error();return bytes;}catch{throw storageFailure();}};
 const nativeCreate=(filePath,bytes)=>{try{privateJournal.createJournal({filePath,bytes});}catch{throw storageFailure();}};
 const namedExists=async filePath=>{try{await fs.lstat(filePath);return true;}catch(error){if(error.code==='ENOENT')return false;throw storageFailure();}};
async function localPostgres({ directory, id, execute = exec, existingOnly = false,
  environment = process.env, platform = process.platform, ownedLabSession, ownLabChild,
  uid = typeof process.getuid === 'function' ? process.getuid() : null } = {}) {
  if (ownedLabSession !== undefined) {
    const binding = require('./lib/windows-owned-lab').describeOwnedLab(ownedLabSession);
    if (platform !== 'win32' || binding.workspaceId !== id || typeof ownLabChild !== 'function') {
      throw new SetupError('Owned Windows PostgreSQL requires its matching lab and forwarding owner.');
    }
  }
  const name = `dvaia-postgres-${id}`;
  const statePath = storagePath.join(directory, 'local-postgres.json');
  if(filesystemPlatform==='win32'){try{privateState.inspectPrivateDirectory(directory);}catch{throw storageFailure();}}
  else await assertPrivateDirectory(directory, { uid, platform:filesystemPlatform });
  let originalStateBytes = null;
  if(filesystemPlatform==='win32'){
    if(await namedExists(statePath))originalStateBytes=nativeRead(statePath);
    else if(existingOnly)throw new SetupError('Additive upgrade requires the existing owned PostgreSQL state or PG_ADMIN_DATABASE_URL.');
  }else{
    try {
      await assertPrivateStateFile(statePath, { uid, platform:filesystemPlatform });
      originalStateBytes = await fs.readFile(statePath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (existingOnly) throw new SetupError('Additive upgrade requires the existing owned PostgreSQL state or PG_ADMIN_DATABASE_URL.');
    }
  }
  let state = null;
  if (originalStateBytes) {
    try { state = validateLocalPostgresState(JSON.parse(originalStateBytes), { id, name }); }
    catch (error) {
      if (error instanceof SetupError) throw error;
      throw new SetupError('Local PostgreSQL setup state is invalid JSON');
    }
  }
  const resolved = await resolveDockerAuthority({ directory, workspaceId: id, environment, execute, platform, uid, persist: false, ...(ownedLabSession ? { ownedLabSession } : {}) });
  const authority = resolved.authority;
  const docker = args => executeBoundDocker({ authority, execute, environment, args });
  const inspect = async args => {
    try { return JSON.parse((await docker(args)).stdout)[0]; }
    catch (error) { if (error.code === 1) return null;throw error; }
  };
  const existing = await inspect(['inspect', name]);
  const volume = await inspect(['volume', 'inspect', name]);
  if (existing && !state) throw new SetupError(`Container ${name} already exists without matching setup ownership; nothing was changed`);
  assertOwnedPostgresVolume(volume, { id });
  if (state) assertOwnedPostgresContainer(existing, state, { id, name });

  if (state?.version === 1) {
    if (!volume) {
      throw new SetupError('Legacy local PostgreSQL state has no owned persistent volume; Docker authority was not adopted');
    }
    if (!resolved.persisted) await writeLocalDockerAuthority({ directory, authority });
    state = { ...state, version: 2, dockerAuthorityDigest: authorityDigest(authority) };
    if(filesystemPlatform==='win32'){
      try{privateJournal.updateJournal({filePath:statePath,originalBytes:originalStateBytes,resultBytes:Buffer.from(JSON.stringify(state))});}catch{throw storageFailure();}
    }else await rewriteLocalPostgresState(statePath, originalStateBytes, state);
  } else if (state?.version === 2) {
    if (!resolved.persisted) throw new SetupError('Local PostgreSQL Docker authority state is missing; nothing was changed');
    if (state.dockerAuthorityDigest !== authorityDigest(authority)) {
      throw new SetupError('Local PostgreSQL state is bound to a different Docker authority; nothing was changed');
    }
  } else {
    if (volume) throw new SetupError('An owned PostgreSQL volume exists without private setup state; nothing was changed');
    if (!resolved.persisted) await writeLocalDockerAuthority({ directory, authority });
    state = { version: 2, id, name, port: await findAvailablePort(), password: randomBytes(32).toString('hex'),
      dockerAuthorityDigest: authorityDigest(authority) };
    if(filesystemPlatform==='win32')nativeCreate(statePath,Buffer.from(JSON.stringify(state)));
    else await privateFile(statePath, JSON.stringify(state));
  }

  if (!existing) {
    if (!volume && existingOnly) throw new SetupError('The owned PostgreSQL volume is unavailable; additive upgrade did not create a replacement');
    if (!volume) {
      await verifyDockerAuthority({ authority, execute, environment });
      await docker(['volume', 'create', '--label', `org.dvaia.workspace=${id}`, name]);
    }
    // The env file keeps passwords out of subprocess arguments and logs.
    const envPath = storagePath.join(directory, 'postgres-container.env');
    const expectedPasswordBytes=Buffer.from(`POSTGRES_PASSWORD=${state.password}\n`);
    if(filesystemPlatform==='win32'){
      if(await namedExists(envPath)){
        if(!nativeRead(envPath).equals(expectedPasswordBytes))throw storageFailure();
      }else nativeCreate(envPath,expectedPasswordBytes);
    }else{
      try { await privateFile(envPath, expectedPasswordBytes); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        await assertPrivateStateFile(envPath,{uid,platform:filesystemPlatform});
        if(!(await fs.readFile(envPath)).equals(expectedPasswordBytes))throw storageFailure();
      }
    }
    const dockerEnvPath = ownedLabSession ? await ownedLabSession.stagePrivateEnvironment({
      bytes: expectedPasswordBytes, sha256: createHash('sha256').update(expectedPasswordBytes).digest('hex'),
    }) : envPath;
    await verifyDockerAuthority({ authority, execute, environment });
    await docker(['run', '--detach', '--restart', 'unless-stopped', '--name', name, '--label', `org.dvaia.workspace=${id}`,
      '--env-file', dockerEnvPath, '--publish', `127.0.0.1:${state.port}:5432`,
      '--mount', `type=volume,src=${name},dst=/var/lib/postgresql`, 'postgres:18']);
  } else if (!existing.State.Running) {
    await verifyDockerAuthority({ authority, execute, environment });
    await docker(['start', name]);
  }
  await verifyDockerAuthority({ authority, execute, environment });
  if (ownedLabSession) await ownedLabSession.openLoopbackForwards([{ local: state.port, guest: state.port }], { ownChild: ownLabChild });
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await docker(['exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres']);
      const inspected = JSON.parse((await docker(['inspect', name])).stdout)[0];
      const port = inspected.NetworkSettings.Ports['5432/tcp']?.find(item => item.HostIp === '127.0.0.1')?.HostPort;
      if (port !== String(state.port)) throw new SetupError('PostgreSQL has no matching loopback port mapping');
      return `postgresql://postgres:${state.password}@127.0.0.1:${port}/postgres`;
    } catch (error) {
      if (attempt === 59) throw new SetupError('Local PostgreSQL did not become ready; inspect the named setup container');
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
}
return Object.freeze({localPostgres});
}
const {localPostgres}=createLocalPostgresSetup();
function encodeEnv(config) {
  return Object.entries(config).map(([key, value]) => {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || /[\r\n\0]/.test(String(value))) throw new SetupError('Invalid setup configuration');
    return `${key}=${JSON.stringify(String(value))}`;
  }).join('\n') + '\n';
}
function shouldBindLocalSidecarDocker(environment = process.env) {
  const autostart = environment.MCP_SIDECARS_AUTOSTART;
  if (autostart === '0' || autostart === 'false' || environment.TEAM_ID || environment.ECS_CONTAINER_METADATA_URI_V4) return false;
  const sandboxUrl = environment.SANDBOX_RUNNER_URL || 'http://127.0.0.1:8090';
  return isLoopbackServiceUrl(sandboxUrl);
}
async function setup({
  root = path.resolve(__dirname, '..'), install = true, adminUrl,
  ensureModel = true, execute = exec, runCommand = run, processEnvironment = process.env, loadPuppeteer,
  upgrade = false, repair = false, homeDirectory = os.homedir(), provision, provisionDelivery, initializeApplication, platform = process.platform,
  ownedMcpRegistry = false, enableOwnedMcpRegistry = false, setupOwnedMcpRegistry, ownedPolicyRenderer = false, enableOwnedPolicyRenderer = false, provisionOwnedPolicyRenderer, ownedListingTemplate = false, enableOwnedListingTemplate = false, provisionOwnedListingTemplate, ownedListings = false, enableOwnedListings = false, setupOwnedListings, preflightOwnedListings, ownedSystem = false, ownedPricing = false, setupOwnedPricing, ownedCoupons = false, setupOwnedCoupons, ownedAnalytics = false, enableOwnedAnalytics = false, setupOwnedAnalytics, qualifiedSecureShop = false, prepareQualifiedSystem, preflightQualifiedSystem, setupOwnedSystem, provisionOwnedRunner, provisionOwnedHttp, provisionOwnedShadow, provisionAuditSql, nodeVersion = process.versions.node, requestGeneration, loadRenderer, loadMailRenderer, loadProductRenderer, loadTicketRenderer, loadSearchEchoRenderer, loadPolicyOutputRenderer,
  ensureDockerAuthority = resolveDockerAuthority,
  runDatabasePhase = require('./install/setup-database-phase').runSetupDatabasePhase,
  observeWindowsHost = require('./lib/windows-host-preflight').observeWindowsHostPreflight,
  prepareWindowsLabInstallation, provisionBaseLabServices, setupLocalPostgres, setupLocalMailpit,
  prepareRuntime, admitNpm,
} = {}) {
  assertSupportedApplicationNodeVersion(nodeVersion);
  if (enableOwnedPolicyRenderer && !ownedPolicyRenderer) throw Object.assign(new SetupError('Owned policy renderer enablement requires explicit --owned-policy-renderer consent.'), {code:'POLICY_RENDER_ENABLE_REQUIRES_OWNED'});
  if (enableOwnedListings && !ownedListings) throw Object.assign(new SetupError('Owned Listings enablement requires --owned-listings.'), {code:'LISTINGS_ENABLE_REQUIRES_OWNED'});
  if (enableOwnedListingTemplate && !ownedListingTemplate) throw Object.assign(new SetupError('Owned Listings template enablement requires --owned-listing-template.'), {code:'LISTING_TEMPLATE_ENABLE_REQUIRES_OWNED'});
  if (ownedListingTemplate && platform === 'win32') throw Object.assign(new SetupError('Owned Listings template is qualified only on Linux or macOS ARM64.'), {code:'LISTING_TEMPLATE_PLATFORM_UNQUALIFIED'});
  if (platform === 'win32') require('./lib/windows-host-preflight').assertWindowsHostSupported(observeWindowsHost());
  if (repair && !upgrade) throw new SetupError('Prerequisite repair requires an existing installation; use --repair for the supported additive path.');
  processEnvironment = { ...processEnvironment };
  root = await fs.realpath(root);
  const envPath = path.join(root, '.env');
  const id = workspaceId(root);
  const directory = path.join(homeDirectory, '.dvaia', id);
  const qualifiedState = upgrade
    ? require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory}) : {};
  const analyticsState = await require('../server/services/secureshopAnalyticsManagedConfiguration').readManagedAnalyticsConfiguration({root,homeDirectory});
  const couponState = require('../server/services/secureshopCouponManagedConfiguration').load({root,home:homeDirectory});
  // A complete bound shop includes coupons. Explicit disabled preferences
  // remain authoritative; an existing Analytics installation still upgrades.
  ({ownedCoupons,ownedAnalytics}=selectOwnedCouponBundle({upgrade,qualifiedSecureShop,
    boundReviewsEnabled:qualifiedState.SS_BOUND_REVIEWS_ENABLED === 'true',
    couponPreference:couponState?.config.enabled ?? null,
    analyticsPreference:analyticsState?.config.enabled ?? null,
    ownedCoupons,ownedAnalytics,enableOwnedAnalytics}));
  ownedMcpRegistry = ownedMcpRegistry || enableOwnedMcpRegistry || qualifiedSecureShop;
  if (!ownedAnalytics && analyticsState) {
    throw Object.assign(new SetupError('Existing owned Analytics requires its non-destructive upgrade: npm run setup -- --upgrade --owned-analytics. Existing data and enabled/disabled preference are preserved.'),{code:'ANALYTICS_UPGRADE_FLAG_REQUIRED'});
  }
  const listingsQualification = ownedListings ? await (preflightOwnedListings || require('./install/listings-setup').preflight)({root,environment:processEnvironment}) : null;
  if (ownedSystem) require('./install/secureshop-owned-system-activate').listenerPorts({root,homeDirectory,environment:processEnvironment});
  if(qualifiedSecureShop && !ownedSystem) throw Object.assign(new SetupError('Qualified SecureShop fresh preparation requires explicit --qualified-secureshop --owned-system consent.'),{code:'SYSTEM_COMBINED_OPT_IN_REQUIRED'});
  if(qualifiedSecureShop) await (preflightQualifiedSystem || require('./install/secureshop-qualified-system-setup').preflight)({root,home:homeDirectory,platform,environment:processEnvironment});
  let windowsLab;
  try {
  if (upgrade) {
    const manifestPath = path.join(directory, 'provisioning.json');
    const { provisioningPlan, provisionApplication } = require('../db/postgres/provision-application');
    const { inspectUpgradeState, reconcileConfiguration, appendPrivateEnvironment } = require('./application-upgrade');
    const state = await inspectUpgradeState({ envPath, manifestPath, currentPlan: provisioningPlan() });
    if(ownedSystem && !qualifiedSecureShop) require('./install/secureshop-owned-system-activate').assertPersistentPrerequisites({root,homeDirectory,existingEnvironment:state.parsed});
    if(ownedPricing && !qualifiedSecureShop) require('./install/pricing-setup').assertPrerequisites({...state.parsed,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})});
    if(ownedAnalytics && !qualifiedSecureShop) require('./install/analytics-setup').assertPrerequisites({...state.parsed,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})});
    if (repair) {
      const repairEnvironment = { ...state.parsed, ...processEnvironment };
      const admittedNpm = install || platform === 'win32' ? await (admitNpm || require('./lib/setup-npm-admission').admitSetupNpm)({environment:processEnvironment,execute,platform}) : null;
      await (prepareRuntime || prepareInstalledRuntime)({ root, cacheDirectory: repairEnvironment.XENOVA_CACHE || path.join(directory, 'models'),
        install, admittedNpm, env: repairEnvironment, execute, runCommand, loadPuppeteer,
        loadRenderer, loadMailRenderer, loadProductRenderer, loadTicketRenderer, loadSearchEchoRenderer, loadPolicyOutputRenderer, ensureModel, requestGeneration, platform });
    }
    const appDataEnvironment = { ...state.parsed, ...processEnvironment };
    const appDataRoot = require('./application-data-root').ensureApplicationDataRoot({
      workspace: root, environment: appDataEnvironment, homeDirectory,
    });
    const externalAdminUrl = adminUrl || processEnvironment.PG_ADMIN_DATABASE_URL;
    if (platform === 'win32' && (shouldBindLocalSidecarDocker(appDataEnvironment) || !externalAdminUrl)) {
      windowsLab = await (prepareWindowsLabInstallation || require('./lib/windows-lab-installation').prepareWindowsLabInstallation)({ root, homeDirectory, environment: appDataEnvironment, mode: 'existing' });
    }
    if (externalAdminUrl && shouldBindLocalSidecarDocker(appDataEnvironment)) {
      await ensureDockerAuthority({ directory, workspaceId: id, environment: appDataEnvironment,
        execute, platform, persist: true, ...(windowsLab ? { ownedLabSession: windowsLab.session } : {}) });
    }
    const databaseAdminUrl = externalAdminUrl || await (setupLocalPostgres || localPostgres)({
      directory, id, execute, existingOnly: true, environment: appDataEnvironment, platform,
      ...(windowsLab ? { ownedLabSession: windowsLab.session, ownLabChild: windowsLab.ownLabChild } : {}),
    });
    const phaseResult = await runDatabasePhase({ kind: 'upgrade', context: { root, directory, homeDirectory, envPath, id, platform,
      manifestPath, state, databaseAdminUrl, appDataRoot, appDataEnvironment, processEnvironment,
      ownedMcpRegistry, enableOwnedMcpRegistry, ownedPolicyRenderer, enableOwnedPolicyRenderer, ownedListingTemplate, enableOwnedListingTemplate, ownedSystem, ownedPricing, ownedAnalytics, enableOwnedAnalytics, ownedCoupons, ownedListings, enableOwnedListings, qualifiedSecureShop, listingsQualification } },
      { provision, provisionDelivery, initializeApplication, setupOwnedMcpRegistry, prepareQualifiedSystem, setupOwnedSystem, setupOwnedPricing, setupOwnedAnalytics, setupOwnedCoupons, setupOwnedListings,
        provisionOwnedPolicyRenderer, provisionOwnedListingTemplate, provisionAuditSql, prepareWindowsLabInstallation, provisionBaseLabServices });
    console.log('PostgreSQL setup database phase completed; existing credentials and environment values were preserved.');
    return phaseResult;
  }
  if(ownedSystem && !qualifiedSecureShop) require('./install/secureshop-owned-system-activate').assertPersistentPrerequisites({root,homeDirectory,fresh:true});
  if(ownedPricing && !qualifiedSecureShop) require('./install/pricing-setup').assertPrerequisites(require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory}));
  if(ownedAnalytics && !qualifiedSecureShop) require('./install/analytics-setup').assertPrerequisites({...processEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})},{fresh:true});
  // Do this before installing dependencies, launching Docker, or provisioning roles.
  try { await fs.lstat(envPath); throw new SetupError('An .env already exists. Fresh setup will not overwrite it; use the documented PostgreSQL migration/configuration commands.'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const admittedNpm = install || platform === 'win32' ? await (admitNpm || require('./lib/setup-npm-admission').admitSetupNpm)({environment:processEnvironment,execute,platform}) : null;
  await prepareSetupPrivateDirectory({ homeDirectory, directory, id });
  const appDataEnvironment = { ...processEnvironment };
  const appDataRoot = require('./application-data-root').ensureApplicationDataRoot({
    workspace: root, environment: appDataEnvironment, homeDirectory,
  });
  const runtime = await (prepareRuntime || prepareInstalledRuntime)({ root,
    cacheDirectory: processEnvironment.XENOVA_CACHE || path.join(directory, 'models'),
    install, admittedNpm, env: processEnvironment, execute, runCommand, loadPuppeteer,
    loadRenderer, loadMailRenderer, loadProductRenderer, loadTicketRenderer, loadSearchEchoRenderer, loadPolicyOutputRenderer, ensureModel, requestGeneration, platform });
  const requestedEmailProvider = String(processEnvironment.IPI_EMAIL_PROVIDER || '').trim().toLowerCase();
  if (requestedEmailProvider && !['gmail', 'mailpit'].includes(requestedEmailProvider)) {
    throw new SetupError('IPI_EMAIL_PROVIDER must be gmail or mailpit');
  }
  if (requestedEmailProvider !== 'gmail' && !shouldBindLocalSidecarDocker(processEnvironment)) {
    throw new SetupError('Fresh setup requires the local Docker sidecar authority for the default Mailpit email provider; set IPI_EMAIL_PROVIDER=gmail explicitly to use external Gmail.');
  }
  const externalAdminUrl = adminUrl || processEnvironment.PG_ADMIN_DATABASE_URL;
  if (platform === 'win32' && (shouldBindLocalSidecarDocker(processEnvironment) || !externalAdminUrl)) {
    windowsLab = await (prepareWindowsLabInstallation || require('./lib/windows-lab-installation').prepareWindowsLabInstallation)({ root, homeDirectory, environment: processEnvironment, mode: 'fresh' });
  }
  if (externalAdminUrl && shouldBindLocalSidecarDocker(processEnvironment)) {
    await ensureDockerAuthority({ directory, workspaceId: id, environment: processEnvironment,
      execute, platform, persist: true, ...(windowsLab ? { ownedLabSession: windowsLab.session } : {}) });
  }
  const databaseAdminUrl = externalAdminUrl
    || await (setupLocalPostgres || localPostgres)({ directory, id, execute, environment: processEnvironment, platform,
      ...(windowsLab ? { ownedLabSession: windowsLab.session, ownLabChild: windowsLab.ownLabChild } : {}) });
  let localMailpit = null;
  if (requestedEmailProvider !== 'gmail') {
    localMailpit = await (setupLocalMailpit || ensureLocalMailpit)({ directory, id, execute, environment: processEnvironment, platform,
      ...(windowsLab ? { ownedLabSession: windowsLab.session, ownLabChild: windowsLab.ownLabChild } : {}) });
  }
  const provisionFreshApplication = provision || require('../db/postgres/provision-application').provisionApplication;
  const { configuration: config } = await provisionFreshApplication({ adminUrl: databaseAdminUrl, manifestPath: path.join(directory, 'provisioning.json') });
  const phaseResult = await runDatabasePhase({ kind: 'fresh', context: { root, directory, homeDirectory, envPath, id, platform,
    databaseAdminUrl, config, appDataRoot, processEnvironment, runtime, requestedEmailProvider, localMailpit,
    ownedMcpRegistry, enableOwnedMcpRegistry, ownedPolicyRenderer, enableOwnedPolicyRenderer, ownedListingTemplate, enableOwnedListingTemplate, ownedSystem, ownedPricing, ownedAnalytics, enableOwnedAnalytics, ownedCoupons, ownedListings, enableOwnedListings, qualifiedSecureShop, listingsQualification } },
    { provisionDelivery, setupOwnedMcpRegistry, prepareQualifiedSystem, setupOwnedSystem, setupOwnedPricing, setupOwnedAnalytics, setupOwnedCoupons, setupOwnedListings,
      provisionOwnedRunner, provisionOwnedHttp, provisionOwnedShadow, provisionOwnedPolicyRenderer, provisionOwnedListingTemplate, provisionAuditSql, prepareWindowsLabInstallation, provisionBaseLabServices });
  console.log(`PostgreSQL setup database phase completed. Your administrator login is stored privately at ${path.join(directory, 'administrator.json')}`);
  return phaseResult;
  } finally {
    if (windowsLab) await windowsLab.close();
  }
}
async function prepareOwnedPolicyRendererForSetup({ requested, activate, root, homeDirectory, platform, processEnvironment, provision }) {
  if (!requested) return Object.freeze({ policyRenderer: Object.freeze({requested:false,ready:false,enabled:false}), additions: Object.freeze({}) });
  const result = await (provision || require('./install/secureshop-owned-policy-renderer').provision)({
    root, home: homeDirectory, platform, architecture: process.arch, environment: processEnvironment, activate,
  });
  if (!result || typeof result.ready !== 'boolean' || typeof result.enabled !== 'boolean') {
    throw Object.assign(new SetupError('Owned policy renderer setup did not return a complete readiness decision.'), {code:'POLICY_RENDER_SETUP_INCOMPLETE'});
  }
  let additions = {};
  if (activate) {
    const match = /^http:\/\/127\.0\.0\.1:([0-9]{1,5})$/.exec(result.baseUrl || '');
    const port = match ? Number(match[1]) : 0;
    if (result.ready !== true || result.enabled !== true || port < 1024 || port > 65535) {
      throw Object.assign(new SetupError('Owned policy renderer activation requires confirmed readiness and its exact private loopback origin.'), {code:'POLICY_RENDER_SETUP_INCOMPLETE'});
    }
    additions = {SS_BOUND_PROMPT_POLICIES_ENABLED:'true',SS_POLICY_RENDERER_BASE_URL:result.baseUrl};
  }
  return Object.freeze({
    policyRenderer: Object.freeze({requested:true,ready:result.ready,enabled:result.enabled,
      ...(result.preservedDisabled === true ? {preservedDisabled:true} : {})}),
    additions: Object.freeze(additions),
  });
}
async function prepareOwnedListingTemplateForSetup({ requested, activate, root, homeDirectory, platform, processEnvironment, provision }) {
  if (!requested) return Object.freeze({ requested:false, ready:false, enabled:false });
  const result = await (provision || require('./install/secureshop-owned-listing-template').provision)({
    root, home:homeDirectory, platform, architecture:process.arch, environment:processEnvironment, activate,
  });
  if (!result || typeof result.ready !== 'boolean' || typeof result.enabled !== 'boolean') {
    throw Object.assign(new SetupError('Owned Listings template setup did not return a complete readiness decision.'), {code:'LISTING_TEMPLATE_SETUP_INCOMPLETE'});
  }
  if (activate) {
    const match = /^http:\/\/127\.0\.0\.1:([0-9]{4})$/.exec(result.baseUrl || '');
    const port = match ? Number(match[1]) : 0;
    if (result.ready !== true || result.enabled !== true || port < 8109 || port > 8118
      || !/^[a-f0-9]{64}$/.test(result.containerId || '') || !/^sha256:[a-f0-9]{64}$/.test(result.imageId || '')) {
      throw Object.assign(new SetupError('Owned Listings template activation requires exact retained resource and inert readiness proof.'), {code:'LISTING_TEMPLATE_SETUP_INCOMPLETE'});
    }
  }
  return Object.freeze({ requested:true, ready:result.ready, enabled:result.enabled,
    ...(result.staged === true ? {staged:true} : {}),
    ...(result.preservedDisabled === true ? {preservedDisabled:true} : {}) });
}
// A byte-bound publication ID makes identical retries select the retained
// journal, without granting authority outside the caller's maintenance lease.
function createSetupUpgradeEnvironmentAppender({ root, directory, id }, {
  filesystemPlatform = process.platform,
  append = require('./application-upgrade').appendPrivateEnvironment,
  privateState = require('./lib/windows-private-state'), fileSystem = fs,
} = {}) {
  return Object.freeze({
    async append({ purpose, envPath, pendingPath, originalBytes, encodedAdditions }) {
      let publicationContext;
      if (filesystemPlatform === 'win32') {
        if (!['database-pairs', 'password-reset-key', 'upload-asset-environment'].includes(purpose) || !Buffer.isBuffer(originalBytes) || originalBytes.length > 1024 * 1024 ||
            typeof encodedAdditions !== 'string' || Buffer.byteLength(encodedAdditions) > 1024 * 1024) {
          throw Object.assign(new SetupError('Private upgrade publication unavailable'), { code: 'UPGRADE_PRIVATE_STATE_INVALID' });
        }
        const separator = encodedAdditions && originalBytes.length && originalBytes.at(-1) !== 10 ? '\n' : '';
        const result = Buffer.concat([originalBytes, Buffer.from(separator + encodedAdditions)]);
        if (result.length > 1024 * 1024) throw Object.assign(new SetupError('Private upgrade publication unavailable'), { code: 'UPGRADE_PRIVATE_STATE_INVALID' });
        const digest = createHash('sha256').update(JSON.stringify([
          'dvaia.setup.additive-environment.v1', root, directory, id, purpose,
          createHash('sha256').update(originalBytes).digest('hex'), createHash('sha256').update(result).digest('hex'),
        ])).digest('hex');
        const operationId = `${digest.slice(0,8)}-${digest.slice(8,12)}-4${digest.slice(13,16)}-a${digest.slice(17,20)}-${digest.slice(20,32)}`;
        publicationContext = { root, directory, id, operationId };
      }
      return append({ envPath, pendingPath, originalBytes, encodedAdditions, ...(publicationContext ? { publicationContext } : {}) });
    },
    async readOriginalBytes(envPath) {
      if (filesystemPlatform !== 'win32') return fileSystem.readFile(envPath);
      try {
        const bytes = privateState.readPrivateWorkspaceFile(envPath);
        if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) throw Error();
        return bytes;
      } catch { throw Object.assign(new SetupError('Private upgrade publication unavailable'), { code: 'UPGRADE_PRIVATE_STATE_INVALID' }); }
    },
  });
}
async function executeSetupDatabasePhase(request, maintenanceScope, dependencies = {}) {
  const { root, directory, homeDirectory, envPath, id, platform, manifestPath, state, databaseAdminUrl,
    config, appDataRoot, appDataEnvironment, processEnvironment, runtime, requestedEmailProvider, localMailpit,
    ownedMcpRegistry, enableOwnedMcpRegistry, ownedPolicyRenderer, enableOwnedPolicyRenderer, ownedListingTemplate, enableOwnedListingTemplate, ownedSystem, ownedPricing, ownedAnalytics, enableOwnedAnalytics, ownedCoupons, ownedListings, enableOwnedListings, qualifiedSecureShop, listingsQualification } = request.context;
  const { provision, provisionDelivery, setupOwnedMcpRegistry, prepareQualifiedSystem, setupOwnedSystem, setupOwnedPricing,
    setupOwnedAnalytics, setupOwnedCoupons, setupOwnedListings, provisionOwnedRunner, provisionOwnedHttp,
    provisionOwnedShadow, provisionOwnedPolicyRenderer, provisionOwnedListingTemplate, provisionAuditSql, prepareWindowsLabInstallation, provisionBaseLabServices,
    deferPublication, runCommand = run, initializeApplication = require('../db/postgres/initialize-application').initializeApplication,
    prepareUploadAssetEnvironment = require('./lib/setup-upload-asset-environment').prepareUploadAssetEnvironment } = dependencies;
  if (typeof deferPublication !== 'function') throw new SetupError('Database phase publication owner required');
  const scopeTools = require('./lib/application-maintenance-scope');
  scopeTools.assertApplicationMaintenanceScope(maintenanceScope, process.env);
  let windowsLab;
  try {
  const labEnvironment = request.kind === 'upgrade' ? appDataEnvironment : processEnvironment;
  if (platform === 'win32' && shouldBindLocalSidecarDocker(labEnvironment)) {
    maintenanceScope.assertHeld();
    windowsLab = await (prepareWindowsLabInstallation || require('./lib/windows-lab-installation').prepareWindowsLabInstallation)({ root, homeDirectory, environment: labEnvironment, mode: 'existing' });
    maintenanceScope.assertHeld();
    await (provisionBaseLabServices || require('./install/windows-base-lab-services').provisionWindowsBaseLabServices)({
      session: windowsLab.session, ownLabChild: windowsLab.ownLabChild, root, mode: request.kind === 'fresh' ? 'fresh' : 'start',
    });
    maintenanceScope.assertHeld();
    if (request.kind === 'fresh') {
      await windowsLab.session.openLoopbackForwards([8092, 8093, 8094].map(port => ({ local: port, guest: port })), { ownChild: windowsLab.ownLabChild });
      maintenanceScope.assertHeld();
    }
  }
  const setPhaseEnvironment = environment => {
    scopeTools.assertApplicationMaintenanceScope(maintenanceScope, environment);
    Object.assign(process.env, environment);
  };
  const { reconcileConfiguration } = require('./application-upgrade');
  const environmentAppender = createSetupUpgradeEnvironmentAppender({ root, directory, id });
  const { provisionApplication } = require('../db/postgres/provision-application');
  if (request.kind === 'upgrade') {
    maintenanceScope.assertHeld();
    const uploadAssets = await prepareUploadAssetEnvironment({ environment: state.parsed, directory, execute: true }, { platform });
    maintenanceScope.assertHeld();
    const result = await (provision || provisionApplication)({
      adminUrl: databaseAdminUrl, manifestPath, upgrade: true, env: { ...process.env },
    });
    const reconciled = reconcileConfiguration({
      envBytes: state.envBytes, parsed: state.parsed, plan: result.plan, configuration: result.configuration,
    });
    maintenanceScope.assertHeld();
    const delivery = await require('./install/ctf-delivery-setup').prepareCtfDelivery({
      directory, adminUrl: databaseAdminUrl, environment: { ...process.env }, existing: state.parsed,
      ...(provisionDelivery ? { provision: provisionDelivery } : {}),
    });
    Object.assign(reconciled.additions, delivery.additions);
    const mergedEnvironment = { ...processEnvironment, ...state.parsed, ...reconciled.additions,
      DVAIA_APP_DATA_ROOT: appDataRoot };
    setPhaseEnvironment(mergedEnvironment);
    // Existing stores also need pending forward-only migrations and default-only
    // seeds. Missing URL pairs describe provisioning additions, not schema age.
    if(!scopeTools.hasCompletedProspectiveMaintenanceScope(maintenanceScope)){await initializeApplication({ maintenanceScope });maintenanceScope.assertHeld();await require('./install/ctf-authority-setup').prepareCtfAuthority({ root, directory, environment: mergedEnvironment, maintenanceScope });}
    maintenanceScope.assertHeld();
    const auditSql = state.parsed.SS_ENABLE === 'true' && shouldBindLocalSidecarDocker(processEnvironment)
      ? await (provisionAuditSql || require('./install/audit-sql-target').provisionForSetup)({
        root, homeDirectory, platform, environment: processEnvironment,
        applicationEnvironment: mergedEnvironment,
        ...(windowsLab ? { ownedLabSession: windowsLab.session, ownLabChild: windowsLab.ownLabChild } : {}),
      })
      : { provisioned: false, activationEnabled: false };
    maintenanceScope.assertHeld();
    if (auditSql.activationEnabled === true && state.parsed.SS_ENABLE === 'true'
      && !Object.hasOwn(state.parsed, 'SS_AUDIT_SUMMARY_ENABLED')) {
      reconciled.additions.SS_AUDIT_SUMMARY_ENABLED = 'true';
    }
    const system = qualifiedSecureShop ? await (prepareQualifiedSystem || require('./install/secureshop-qualified-system-setup').prepare)({root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : ownedSystem ? await (setupOwnedSystem || require('./install/secureshop-owned-system-activate').setupOwnedSystem)({enabled:ownedSystem,root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const pricing = ownedPricing ? await (setupOwnedPricing || require('./install/pricing-setup').setupOwnedPricing)({requested:true,root,homeDirectory,platform,maintenanceScope,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const analytics = ownedAnalytics ? await (setupOwnedAnalytics || require('./install/analytics-setup').setupOwnedAnalytics)({requested:true,explicitActivation:enableOwnedAnalytics,root,homeDirectory,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const coupons = ownedCoupons ? await (setupOwnedCoupons || require('./install/coupons-setup').setupOwnedCoupons)({requested:true,root,homeDirectory,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const listings = ownedListings ? await (setupOwnedListings || require('./install/listings-setup').setupOwnedListings)({requested:true,explicitActivation:enableOwnedListings,root,homeDirectory,platform,maintenanceScope,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})},qualification:listingsQualification}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const ownedRegistry = ownedMcpRegistry ? await (setupOwnedMcpRegistry || require('./install/secureshop-owned-mcp-registry-setup').setupOwnedMcpRegistry)({requested:true,explicitActivation:enableOwnedMcpRegistry,upgrade:request.kind==='upgrade',maintenanceScope,root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...mergedEnvironment,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
    maintenanceScope.assertHeld();
    const {policyRenderer,additions:policyRendererEnvironment} = await prepareOwnedPolicyRendererForSetup({requested:ownedPolicyRenderer,activate:enableOwnedPolicyRenderer,root,homeDirectory,platform,processEnvironment,provision:provisionOwnedPolicyRenderer});
    maintenanceScope.assertHeld();
    Object.assign(reconciled.additions,policyRendererEnvironment);
    const listingTemplate = await prepareOwnedListingTemplateForSetup({requested:ownedListingTemplate,activate:enableOwnedListingTemplate,root,homeDirectory,platform,processEnvironment,provision:provisionOwnedListingTemplate});
    maintenanceScope.assertHeld();
    deferPublication(async () => {
    if (Object.keys(reconciled.additions).length) {
      await environmentAppender.append({ purpose: 'database-pairs', envPath, pendingPath: state.pendingPath, originalBytes: state.envBytes,
        encodedAdditions: encodeEnv(reconciled.additions) });
    }
    if (Object.keys(uploadAssets.additions).length) {
      await environmentAppender.append({ purpose: 'upload-asset-environment', envPath, pendingPath: state.pendingPath,
        originalBytes: await environmentAppender.readOriginalBytes(envPath),
        encodedAdditions: encodeEnv(uploadAssets.additions) });
    }
    if (state.parsed.SS_PASSWORD_RESET_KEY_PATH) {
      require('../server/services/secureshopPasswordResetKeys').loadPasswordResetKeys({
        filePath: state.parsed.SS_PASSWORD_RESET_KEY_PATH,
      });
    } else {
      const resetKey = require('./lib/setup-password-reset-key').ensurePasswordResetKey({ directory });
      await environmentAppender.append({ purpose: 'password-reset-key', envPath, pendingPath: state.pendingPath,
        originalBytes: await environmentAppender.readOriginalBytes(envPath),
        encodedAdditions: encodeEnv({ SS_PASSWORD_RESET_KEY_PATH: resetKey.filePath }) });
    }
    });
    console.log(`PostgreSQL application configuration upgraded with ${reconciled.missing.length} additive store(s). Existing credentials and environment values were preserved.`);
    return { envPath, directory, upgradedSchemas: reconciled.missing.map(row => row.schema), auditSql, system, analytics, pricing, listings, coupons, ownedRegistry, policyRenderer, listingTemplate };
  }
  if (request.kind !== 'fresh') throw new SetupError('Unknown database phase');
  const delivery = await require('./install/ctf-delivery-setup').prepareCtfDelivery({
    directory, adminUrl: databaseAdminUrl, environment: processEnvironment,
    ...(provisionDelivery ? { provision: provisionDelivery } : {}),
  });
  const credentialsPath = path.join(directory, 'administrator.json');
  const administrator = require('./lib/setup-administrator-journal').ensureAdministratorJournal({ directory });
  const resetKey = require('./lib/setup-password-reset-key').ensurePasswordResetKey({ directory });
  const applicationEnv = { ...config, ...delivery.configuration,
    SS_PASSWORD_RESET_KEY_PATH: resetKey.filePath,
    ...(processEnvironment.LEGACY_SENSITIVE_FILES_ROOT ? { LEGACY_SENSITIVE_FILES_ROOT: processEnvironment.LEGACY_SENSITIVE_FILES_ROOT } : {}), PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    SS_ENABLE: 'true',
    ...(shouldBindLocalSidecarDocker(processEnvironment) ? { SS_AUDIT_SUMMARY_ENABLED: 'true' } : {}),
    ...(processEnvironment.PG_TLS ? { PG_TLS: processEnvironment.PG_TLS } : {}),
    ...(runtime.browser.configuredExecutablePath ? { PUPPETEER_EXECUTABLE_PATH: runtime.browser.configuredExecutablePath } : {}),
    ...(runtime.embedding ? { XENOVA_CACHE: runtime.embedding.cacheDirectory } : {}),
    AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://localhost:11434',
    IPI_EMAIL_PROVIDER: requestedEmailProvider === 'gmail' ? 'gmail' : 'mailpit',
    IPI_MAIL_DOMAIN: 'dvaia.invalid', IPI_MAIL_FROM: 'indirectpromptinjection@dvaia.invalid',
    MAILPIT_SMTP_HOST: localMailpit?.smtpHost || '127.0.0.1',
    MAILPIT_SMTP_PORT: String(localMailpit?.smtpPort || 1025),
    MAILPIT_API_URL: localMailpit?.apiUrl || 'http://127.0.0.1:8025',
    ...(localMailpit ? { MAILPIT_STATE_PATH: localMailpit.statePath } : {}),
    JUDGE_PROVIDER: 'ollama', JUDGE_MODEL: 'llama3.1:8b', LANGSMITH_TRACING: 'false' };
  const uploadAssets = await prepareUploadAssetEnvironment({
    environment: { ...processEnvironment, ...applicationEnv }, directory, execute: true,
  }, { platform });
  Object.assign(applicationEnv, uploadAssets.configuration);
  if (platform === 'darwin') applicationEnv.DVAIA_MCP_OWNED_COLIMA_PROFILE = ownedRunnerOptions({ platform, environment: processEnvironment }).colimaProfile;
  const {policyRenderer,additions:policyRendererEnvironment} = await prepareOwnedPolicyRendererForSetup({requested:ownedPolicyRenderer,activate:enableOwnedPolicyRenderer,root,homeDirectory,platform,processEnvironment,provision:provisionOwnedPolicyRenderer});
  maintenanceScope.assertHeld();
  Object.assign(applicationEnv,policyRendererEnvironment);
  const listingTemplate = await prepareOwnedListingTemplateForSetup({requested:ownedListingTemplate,activate:enableOwnedListingTemplate,root,homeDirectory,platform,processEnvironment,provision:provisionOwnedListingTemplate});
  maintenanceScope.assertHeld();
  const environmentPublication = require('./lib/setup-environment-publication').prepareFreshEnvironmentPublication({
    root, directory, id, envPath, environment: applicationEnv,
  });
  Object.assign(applicationEnv, environmentPublication.environment);
  setPhaseEnvironment({ ...processEnvironment, ...applicationEnv, DVAIA_APP_DATA_ROOT: appDataRoot });
  await initializeApplication({ maintenanceScope });
  // Missing generated teaching artifacts are an explicit fresh-install step.
  await runCommand(process.execPath, ['server/database/sensitiveInfoFiles.js', '--initialize-missing'], root,
    { ...processEnvironment, ...applicationEnv, DVAIA_APP_DATA_ROOT: appDataRoot });
  maintenanceScope.assertHeld();
  const pool = require('../server/database/postgres').createPool(applicationEnv, 'IDENTITY_MIGRATION_DATABASE_URL');
  try { await require('../db/postgres/bootstrap-admin').bootstrapAdmin({ pool, ...administrator, initialTrainingProfile: true }); }
  finally { await pool.end(); }
  maintenanceScope.assertHeld();
  await require('./install/ctf-authority-setup').prepareCtfAuthority({ root, directory, environment: { ...processEnvironment, ...applicationEnv }, maintenanceScope });
  maintenanceScope.assertHeld();
  const ownedRunner = await provisionOwnedRunnerForSetup({
    root, directory, homeDirectory, platform, environment: processEnvironment,
    provisionFromEnvironment: provisionOwnedRunner,
    ...(windowsLab ? { ownedLabSession: windowsLab.session } : {}),
  });
  admitOwnedRunnerForSetup(ownedRunner, { required: shouldBindLocalSidecarDocker(processEnvironment) });
  maintenanceScope.assertHeld();
  let ownedHttp = { available: false, activationEnabled: false };
  if (shouldBindLocalSidecarDocker(processEnvironment)) {
    try {
      ownedHttp = await (provisionOwnedHttp || require('./install/mcp-owned-http-setup').provisionOwnedHttpForSetup)({
        root, homeDirectory, platform, environment: processEnvironment,
        applicationEnvironment: { ...processEnvironment, ...applicationEnv },
        ...(windowsLab ? { ownedLabSession: windowsLab.session } : {}),
      });
      if (ownedHttp?.available !== true || ownedHttp.activationEnabled !== true) throw new Error('HTTP readiness incomplete');
    } catch (cause) {
      throw Object.assign(new SetupError('Required owned HTTP service is unavailable. Private configuration and data were preserved; fix the reported prerequisite, then run node scripts/install/mcp-owned-http-setup.js before starting the application.'),
        { code: 'MCP_HTTP_SETUP_REQUIRED', cause });
    }
  }
  maintenanceScope.assertHeld();
  let ownedShadow = { available: false, activationEnabled: false };
  if (shouldBindLocalSidecarDocker(processEnvironment)) {
    try {
      ownedShadow = await (provisionOwnedShadow || require('./install/mcp-owned-shadow-setup').provisionOwnedShadowForSetup)({root, homeDirectory, platform, environment: processEnvironment, applicationEnvironment: { ...processEnvironment, ...applicationEnv }, ...(windowsLab ? { ownedLabSession: windowsLab.session } : {}) });
      if (ownedShadow?.available !== true || ownedShadow.activationEnabled !== true) throw new Error('Shadow transport readiness incomplete');
    } catch (cause) {
      throw Object.assign(new SetupError('Owned shadow MCP service setup did not complete. Private configuration and data were preserved; repair the reported prerequisite and run node scripts/install/mcp-owned-shadow-setup.js.'), {code:'MCP_SHADOW_SETUP_REQUIRED',cause});
    }
  }
  maintenanceScope.assertHeld();
  let auditSql = { provisioned: false, activationEnabled: false };
  if (shouldBindLocalSidecarDocker(processEnvironment)) {
    try {
      const prepared = await (provisionAuditSql || require('./install/audit-sql-target').provisionForSetup)({
        root, homeDirectory, platform, environment: processEnvironment, applicationEnvironment: { ...processEnvironment, ...applicationEnv },
        ...(windowsLab ? { ownedLabSession: windowsLab.session, ownLabChild: windowsLab.ownLabChild } : {}),
      });
      auditSql = { ...prepared, provisioned: true, activationEnabled: prepared.activationEnabled === true };
    } catch (cause) {
      throw Object.assign(new SetupError('Owned audit SQL prerequisite provisioning failed. Existing application data and private configuration were preserved; repair the local Docker prerequisite and run node scripts/install/audit-sql-target.js. The audit service remains disabled.'),
        { code: 'AUDIT_SQL_SETUP_REQUIRED', cause });
    }
  }
  maintenanceScope.assertHeld();
  const listings = ownedListings ? await (setupOwnedListings || require('./install/listings-setup').setupOwnedListings)({requested:true,explicitActivation:enableOwnedListings,root,homeDirectory,platform,maintenanceScope,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})},qualification:listingsQualification}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  const system = qualifiedSecureShop ? await (prepareQualifiedSystem || require('./install/secureshop-qualified-system-setup').prepare)({root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : ownedSystem ? await (setupOwnedSystem || require('./install/secureshop-owned-system-activate').setupOwnedSystem)({enabled:ownedSystem,root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  const pricing = ownedPricing ? await (setupOwnedPricing || require('./install/pricing-setup').setupOwnedPricing)({requested:true,root,homeDirectory,platform,maintenanceScope,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  const analytics = ownedAnalytics ? await (setupOwnedAnalytics || require('./install/analytics-setup').setupOwnedAnalytics)({requested:true,explicitActivation:enableOwnedAnalytics,root,homeDirectory,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  const coupons = ownedCoupons ? await (setupOwnedCoupons || require('./install/coupons-setup').setupOwnedCoupons)({requested:true,root,homeDirectory,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  const ownedRegistry = ownedMcpRegistry ? await (setupOwnedMcpRegistry || require('./install/secureshop-owned-mcp-registry-setup').setupOwnedMcpRegistry)({requested:true,explicitActivation:enableOwnedMcpRegistry,upgrade:false,maintenanceScope,root,homeDirectory,platform,environment:processEnvironment,applicationEnvironment:{...processEnvironment,...applicationEnv,...require('../server/services/secureshopQualifiedManagedConfiguration').load({root,home:homeDirectory})}}) : {requested:false,activationEnabled:false};
  maintenanceScope.assertHeld();
  deferPublication(() => environmentPublication.publish());
  console.log(`PostgreSQL application configuration created. Start with ${platform === 'win32' ? 'powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1' : './start_all.sh'}. Existing SQLite data was not imported or changed.`);
  if (localMailpit) console.log(`Owned local Mailpit is ready at ${localMailpit.apiUrl}; its private state is recorded at ${localMailpit.statePath}.`);
  console.log(`Your administrator login is stored privately at ${credentialsPath}`);
  console.log('LangChain and LangGraph are installed application dependencies; llama3.1:8b is available from local Ollama and requires no API credentials.');
  if (runtime.embedding) console.log('Document retrieval embedding model is cached and verified; XENOVA_CACHE records its canonical directory.');
  if (ownedRunner.available) {
    console.log(ownedRunner.activationEnabled
      ? `Owned MCP/CodeBot runner is ready and activated through ${ownedRunner.managedPath}.`
      : `Owned MCP/CodeBot runner is prepared but remains disabled at ${ownedRunner.managedPath}.`);
  } else {
    console.log(`Owned MCP/CodeBot runner readiness was not confirmed (${ownedRunner.code}). Managed configuration: ${ownedRunner.managedPath}.`);
  }
  return { envPath, directory, appDataRoot, runtime, ownedRunner, ownedHttp, ownedShadow, auditSql, system, analytics, pricing, listings, coupons, ownedRegistry, policyRenderer, listingTemplate };
  } finally {
    if (windowsLab) await windowsLab.close();
  }
}

function setupHostPlan({ platform = process.platform,
  observeWindowsHost = require('./lib/windows-host-preflight').observeWindowsHostPreflight } = {}) {
  return platform === 'win32' ? require('./lib/windows-host-preflight').validateWindowsHostPreflight(observeWindowsHost()) : null;
}
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.some(arg => !['--no-install', '--plan', '--upgrade', '--repair', '--owned-system', '--owned-listings', '--enable-owned-listings', '--owned-pricing', '--owned-analytics', '--owned-coupons', '--enable-owned-analytics', '--qualified-secureshop', '--owned-mcp-registry', '--enable-owned-mcp-registry', '--owned-policy-renderer', '--enable-owned-policy-renderer', '--owned-listing-template', '--enable-owned-listing-template'].includes(arg))) {
    console.error('Usage: node scripts/setup-application.js [--no-install] [--plan] [--upgrade|--repair] [--owned-system] [--owned-listings] [--enable-owned-listings] [--owned-pricing] [--owned-analytics] [--owned-coupons] [--enable-owned-analytics] [--qualified-secureshop] [--owned-mcp-registry] [--enable-owned-mcp-registry] [--owned-policy-renderer] [--enable-owned-policy-renderer] [--owned-listing-template] [--enable-owned-listing-template]'); process.exitCode = 1;
  } else if (args.includes('--enable-owned-policy-renderer') && !args.includes('--owned-policy-renderer')) {
    console.error('--enable-owned-policy-renderer requires --owned-policy-renderer.'); process.exitCode = 1;
  } else if (args.includes('--enable-owned-listing-template') && !args.includes('--owned-listing-template')) {
    console.error('--enable-owned-listing-template requires --owned-listing-template.'); process.exitCode = 1;
  } else if (args.includes('--enable-owned-listings') && !args.includes('--owned-listings')) {
    console.error('--enable-owned-listings requires --owned-listings.'); process.exitCode = 1;
  } else if (args.includes('--plan')) {
    try {
    const host = setupHostPlan();
    if (host) console.log(JSON.stringify(host, null, 2));
    if (host && !host.hostSupported) process.exitCode = 1;
    else {
    if(args.includes('--owned-mcp-registry') || args.includes('--enable-owned-mcp-registry') || args.includes('--qualified-secureshop')) console.log('Owned MCP registry: automatically build or verify the pinned 17-file image and private loopback service after bound SecureShop prerequisites. ARM64 qualified only; Linux AMD64 remains unqualified. Preserve existing disabled preferences unless --enable-owned-mcp-registry is explicit. Plan performs no build, provisioning or activation.');
    if(args.includes('--owned-policy-renderer')) console.log('Owned strict policy renderer: verify or provision the private loopback renderer while preserving its disabled preference. Activation requires explicit --enable-owned-policy-renderer and confirmed readiness. Plan performs no build, provisioning or activation.');
    if(args.includes('--owned-listing-template')) console.log('Owned Listings template: separate ARM64 Linux/macOS package, private loopback port 8109–8118 and disabled-by-default staged container. Activation requires --enable-owned-listing-template and exact inert readiness. It does not enable Listings. Plan performs no build, provisioning or activation.');
    if(args.includes('--enable-owned-analytics')) console.log('Explicit Analytics enablement also provisions/verifies its existing owned resources and enables the private feature only after readiness; use to recover staged setup or deliberately re-enable it.');
    if(args.includes('--owned-coupons')) console.log('Owned coupon opt-in: automatically prepares owned Analytics, applies additive review migrations, verifies runtime/schema, and records private activation. Existing disabled preferences are preserved. Requires bound SecureShop. Plan makes no changes.');
    if(args.includes('--owned-analytics')) console.log('Owned Analytics: provision a separate private PostgreSQL cluster and enable only after cluster and application request-schema readiness. Requires enabled bound SecureShop; preserves existing disabled preferences. Plan makes no changes.');
    if(args.includes('--qualified-secureshop')) console.log('Explicit combined opt-in prepares six bound SecureShop panels (reviews, manuals, products, inbox, MCP trust, controlled SSRF) and private System listeners. Requires existing enforced profile/ARM64; candidate readiness precedes activation. Plan makes no changes.');
    if(args.includes('--owned-pricing')) console.log('Owned Pricing opt-in: requires bound SecureShop; ARM64 daemon/package only, immutable workspace AppArmor profile, private loopback listener and readiness before activation. AMD64 remains unqualified. Plan performs no changes.');
    console.log('Local audit SQL prerequisite: fresh provisioning uses loopback port 8097; retained private configurations keep their saved port and disabled preference. Eligible SecureShop setup enables audit summary only when its private setting is absent and owned audit readiness succeeds. Plan makes no changes.');
    if(args.includes('--owned-listings')) console.log(args.includes('--enable-owned-listings')?'Owned Listings explicit activation (ARM64 qualified only): provision or verify the exact retained manager, schema, cleanup bindings and private authority, then atomically enable and require application restart. Plan performs no provisioning or activation.':'Owned Listings preparation (ARM64 qualified only): verify package and daemon authority, then stage one shared manager and private journal disabled. Plan performs no provisioning or activation.');
    if(args.includes('--owned-system')) console.log('Opt-in owned System (ARM64 only; other host architectures fail before build): verify existing Docker authority and installed AppArmor profile; provision three private loopback listeners and activate only after readiness. Plan performs no provisioning or activation; .env is unchanged by System integration.');
    if(args.includes('--repair')) console.log('Existing-install repair: verify the private environment and provisioning manifest, install locked application/client dependencies, install a missing Puppeteer browser, rebuild/verify renderers, verify LangChain/LangGraph, local llama3.1:8b generation and the embedding cache, then run the supported additive database phase. Preserve administrator credentials, environment values and learner data. Plan makes no changes.');
    console.log(args.includes('--upgrade') || args.includes('--repair')
      ? `Additive upgrade: require the existing private environment and provisioning manifest; bind local PostgreSQL and ordinary MCP sidecars to a verified local Docker daemon unless externally managed; preserve all credentials and settings; provision appended PostgreSQL stores and apply pending migrations/default-only seeds to every configured store; atomically append their configuration; validate the configured private password-reset recovery key or provision it once and append its path when absent. ${args.includes('--repair') ? 'Repair additionally prepares local dependencies, browser and model before this database phase.' : 'No packages, model, browser, administrator, AWS assets or existing data are changed.'}`
      : 'Fresh setup: preserve existing .env; install locked application/client dependencies including LangChain and LangGraph; verify or pull llama3.1:8b from the platform-installed Ollama service; download/cache and verify the document embedding model with trusted TLS; verify a sandboxed browser; bind local PostgreSQL and ordinary MCP sidecars to a verified local Docker daemon; provision and readiness-check the pinned loopback Mailpit API/SMTP service unless IPI_EMAIL_PROVIDER=gmail is explicit; use explicit PG_ADMIN_DATABASE_URL or a dedicated local Docker PostgreSQL18; provision16 isolated databases; initialize schemas/seeds; create private .env; install and activate the separately bound owned MCP/CodeBot runner and owned HTTP service only after strict schema and local readiness passes (Linux locally; macOS uses DVAIA_MCP_OWNED_COLIMA_PROFILE or colima-default). No AWS assets or existing data are changed.');
    }
    } catch { console.error('Windows host preflight unavailable; setup plan made no changes.'); process.exitCode = 1; }
  } else setup({ ownedMcpRegistry:args.includes('--owned-mcp-registry'), enableOwnedMcpRegistry:args.includes('--enable-owned-mcp-registry'), ownedPolicyRenderer:args.includes('--owned-policy-renderer'), enableOwnedPolicyRenderer:args.includes('--enable-owned-policy-renderer'), ownedListingTemplate:args.includes('--owned-listing-template'), enableOwnedListingTemplate:args.includes('--enable-owned-listing-template'), install: !args.includes('--no-install'), upgrade: args.includes('--upgrade') || args.includes('--repair'), repair: args.includes('--repair'), ownedListings:args.includes('--owned-listings'), enableOwnedListings:args.includes('--enable-owned-listings'), ownedSystem:args.includes('--owned-system'), ownedPricing:args.includes('--owned-pricing'), ownedAnalytics:args.includes('--owned-analytics'), ownedCoupons:args.includes('--owned-coupons'), enableOwnedAnalytics:args.includes('--enable-owned-analytics'), qualifiedSecureShop:args.includes('--qualified-secureshop') }).catch(error => {
    // Subprocess errors can contain environment/SQL secrets; print only our public errors.
    const code = /^[A-Z0-9_]+$/.test(String(error.code || '')) ? ` (${error.code})` : '';
    console.error(error.code === 'MAILPIT_LEGACY_STATE_UNSUPPORTED'
      ? require('./local-mailpit').LEGACY_STATE_MESSAGE
      : error.code === 'UPGRADE_ENV_RECOVERY_REQUIRED'
      ? 'Additive upgrade stopped because .env.upgrade already exists. Inspect that private file and the current .env, then remove only the stale staging file before retrying.'
      : (error instanceof SetupError || error instanceof LocalDockerAuthorityError || error.code === 'UNSUPPORTED_NODE_RUNTIME' || error.code === 'SETUP_NPM_UNAVAILABLE' || ['WINDOWS_HOST_UNSUPPORTED','WINDOWS_HOST_PREFLIGHT_UNAVAILABLE'].includes(error.code)) ? error.message
        : `Setup failed${code}. Existing data was not reset; check the private setup state and PostgreSQL availability.`);
    if (Array.isArray(error.causes)) console.error('Setup database phase diagnostics:', error.causes.filter(value => /^[A-Z0-9_]{1,80}$/.test(value)).join(', '), /^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(error.migration || '') ? error.migration : '');
    process.exitCode = 1;
  });
}
// Explicit candidate seam only; ordinary setup remains unchanged until release.
const { provisionOwnedHttpCandidateForSetup } = require('./install/mcp-owned-http-activate');
module.exports = { setupHostPlan, createLocalPostgresSetup, createSetupUpgradeEnvironmentAppender, executeSetupDatabasePhase, provisionOwnedHttpCandidateForSetup, setup, selectOwnedCouponBundle, localPostgres, workspaceId, encodeEnv, privateFile, prepareSetupPrivateDirectory, prepareInstalledRuntime, verifyInstalledComponents, ensureOllamaModel, ensureEmbeddingModel, ensureReviewRenderer, ensureMailRenderer, ensureProductDescriptionRenderer, ensureTicketRenderer, ensureSearchEchoRenderer, ensurePolicyOutputRenderer,
  ensurePuppeteerBrowserInstalled, requestOllamaGeneration, OLLAMA_SETUP_GENERATE_URL, OLLAMA_SETUP_INFERENCE_TIMEOUT_MS,
  verifyBrowserRuntime, verifySetupRuntime, ownedRunnerOptions, provisionOwnedRunnerForSetup, shouldBindLocalSidecarDocker,
  admitOwnedRunnerForSetup, REQUIRED_INSTALLED_COMPONENTS };
