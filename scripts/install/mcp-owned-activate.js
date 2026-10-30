'use strict';
// Readiness-only activation of an already provisioned local installation.
const fs = require('node:fs/promises');
const path = require('node:path');
const dotenv = require('dotenv');
const { managedConfigurationPath, parseManagedConfiguration } = require('../../server/services/mcp/ownedManagedConfiguration');
const { prepareOwnedManagedConfiguration } = require('./mcp-owned-local');
const { assertRequestedCapabilities } = require('./mcp-owned-provision');
const FLAGS = Object.freeze({ '--observed-action': 'activateObservedAction', '--indirect-injection': 'activateIndirectInjection', '--supply-chain': 'activateSupplyChain' });
function fail(code) { throw Object.assign(new Error(code), { code }); }
async function readPrivate(file) {
  if (!path.isAbsolute(file)) fail('MCP_ACTIVATE_PRIVATE_FILE');
  const st = await fs.lstat(file);
  if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1 || (st.mode & 0o077) || st.uid !== process.getuid()) fail('MCP_ACTIVATE_PRIVATE_FILE');
  return fs.readFile(file);
}
function parseArgs(args, root = path.resolve(__dirname, '../..')) {
  const options = { envPath: path.join(root, '.env'), managedPath: managedConfigurationPath({ root }) };
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]; if (seen.has(arg)) fail('MCP_ACTIVATE_ARGUMENTS'); seen.add(arg);
    if (FLAGS[arg]) options[FLAGS[arg]] = true;
    else if (arg === '--env' || arg === '--managed') { const value = args[++i]; if (!value || !path.isAbsolute(value)) fail('MCP_ACTIVATE_ARGUMENTS'); options[arg === '--env' ? 'envPath' : 'managedPath'] = value; }
    else fail('MCP_ACTIVATE_ARGUMENTS');
  }
  if (!Object.values(FLAGS).some(k => options[k] === true)) fail('MCP_ACTIVATE_ARGUMENTS');
  return options;
}
async function probeExisting(env) {
  if (env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') fail('MCP_ACTIVATE_POSTGRES_REQUIRED');
  const pg = require('../../server/database/postgres');
  const pools = []; let smtp;
  try {
    pools.push(pg.createPool(env, 'IDENTITY_DATABASE_URL'));
    pools.push(pg.createPool(env, 'MCP_WORKSHOP_DATABASE_URL'));
    const targets = require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({ baseURL: env.MCP_OWNED_TARGET_URL, token: env.MCP_OWNED_TARGET_TOKEN });
    const resources = await require('../../server/services/mcp/ownedResourceComposition').createMcpOwnedResourceReadiness({ resourcePool: pools[1], targets })();
    const conversationsReady = await require('../../server/services/mcp/ownedResourceProduction').conversationReadiness(pools[0]);
    const codeBot = await require('../../server/services/supplyChain/codeBotProduction').readRunnerReadiness({ env });
    const port = Number(env.MAILPIT_SMTP_PORT || 1025);
    const url = new URL(env.MAILPIT_API_URL || 'http://127.0.0.1:8025');
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) fail('MCP_ACTIVATE_MAIL_CONFIGURATION');
    smtp = require('nodemailer').createTransport({ host: env.MAILPIT_SMTP_HOST || '127.0.0.1', port, secure: false, tls: { rejectUnauthorized: false }, connectionTimeout: 4000, greetingTimeout: 4000, socketTimeout: 4000 });
    const verified = await smtp.verify();
    const api = await require('../../server/services/mcp/mailClient')._internals.fetchWithTimeout(`${url.href.replace(/\/$/, '')}/api/v1/info`, {}, 4000);
    return { resources, codeBot, conversationsReady, mailReady: verified === true && api.ok === true };
  } finally {
    const closed = await Promise.allSettled([Promise.resolve().then(() => smtp?.close()), ...pools.map(pool => Promise.resolve().then(() => pool.end()))]);
    if (closed.some(x => x.status !== 'fulfilled')) fail('MCP_ACTIVATE_CLEANUP_FAILED');
  }
}
async function activateExisting({ envPath, managedPath, activateObservedAction = false, activateIndirectInjection = false, activateSupplyChain = false, probe = probeExisting } = {}) {
  const requested = { activateObservedAction, activateIndirectInjection, activateSupplyChain };
  if (Object.values(requested).some(v => typeof v !== 'boolean') || !Object.values(requested).some(Boolean)) fail('MCP_ACTIVATE_ARGUMENTS');
  const originalEnv = await readPrivate(envPath), originalManaged = await readPrivate(managedPath);
  const existing = parseManagedConfiguration(originalManaged);
  const privateEnv = dotenv.parse(originalEnv);
  require('../../server/services/platformSigningConfiguration').assertPlatformSigningConfiguration(privateEnv);
  // This command adds lesson gates only; base runner and CodeBot must already be active.
  if (existing.MCP_OWNED_RESOURCES_ENABLED !== 'true' || existing.CODEBOT_OWNED_EXECUTION_ENABLED !== 'true') fail('MCP_ACTIVATE_BASE_REQUIRED');
  const observed = activateObservedAction || existing.MCP_OBSERVED_ACTION_ENABLED === 'true';
  if ((activateIndirectInjection || activateSupplyChain) && !observed) fail('MCP_ACTIVATE_OBSERVED_REQUIRED');
  const effective = { activateObservedAction: observed, activateIndirectInjection: activateIndirectInjection || existing.MCP_INDIRECT_INJECTION_ENABLED === 'true', activateSupplyChain: activateSupplyChain || existing.MCP_SUPPLY_CHAIN_ENABLED === 'true' };
  const checked = await probe({ ...privateEnv, ...existing });
  const r = checked?.resources;
  if (r?.ready !== true || r.repositoryReady !== true || r.runnerReady !== true || r.runnerIsolation !== 'bwrap-seccomp-v1' || r.supervisorProfile !== 'owasp-ai-goat-mcp-sandbox (enforce)' || checked.codeBot?.ready !== true || checked.codeBot.isolation !== 'bwrap-codebot-v1' || checked.conversationsReady !== true || checked.mailReady !== true) fail('MCP_ACTIVATE_READINESS_FAILED');
  assertRequestedCapabilities(r, effective);
  if (!(await readPrivate(envPath)).equals(originalEnv) || !(await readPrivate(managedPath)).equals(originalManaged)) fail('MCP_ACTIVATE_CONFIGURATION_CHANGED');
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true, ...effective, randomToken: () => fail('MCP_ACTIVATE_TOKEN_REQUIRED') });
  const after = parseManagedConfiguration(await readPrivate(managedPath));
  const expected = { ...existing };
  if (activateObservedAction) expected.MCP_OBSERVED_ACTION_ENABLED = 'true';
  if (activateIndirectInjection) expected.MCP_INDIRECT_INJECTION_ENABLED = 'true';
  if (activateSupplyChain) expected.MCP_SUPPLY_CHAIN_ENABLED = 'true';
  if (JSON.stringify(after) !== JSON.stringify(expected) || !(await readPrivate(envPath)).equals(originalEnv)) fail('MCP_ACTIVATE_CONFIGURATION_CHANGED');
  return Object.freeze({ ok: true, changed: !(await readPrivate(managedPath)).equals(originalManaged), requested: Object.keys(requested).filter(k => requested[k]), readinessVerified: true, runtimeReloadRequired: true, runtimeActivated: false, genuineQualification: false });
}
function activationFailure(error) {
  const messages = {
    MCP_INSTALL_CAPABILITY_UNAVAILABLE: 'The existing runner lacks a requested lesson capability. Upgrade the owned runner with preservation checks before retrying activation.',
    MCP_ACTIVATE_ARGUMENTS: 'Explicit supported lesson flags and absolute configuration paths are required.',
    MCP_ACTIVATE_PRIVATE_FILE: 'Existing owner-private regular configuration files are required.',
    MCP_ACTIVATE_BASE_REQUIRED: 'The existing owned runner and CodeBot base configuration must already be enabled.',
    MCP_ACTIVATE_OBSERVED_REQUIRED: 'Indirect injection and supply chain require existing or explicitly requested observed-action activation.',
    MCP_ACTIVATE_READINESS_FAILED: 'Existing runner, database, CodeBot or mail readiness did not pass. No activation was performed.',
    MCP_ACTIVATE_CONFIGURATION_CHANGED: 'Configuration changed during activation checks. Review the private configuration before retrying.',
    MCP_ACTIVATE_CLEANUP_FAILED: 'Readiness resources did not retire successfully. No activation was performed.',
  };
  const code = Object.hasOwn(messages, error?.code) ? error.code : 'MCP_ACTIVATE_FAILED';
  return { ok: false, code, message: messages[code] || 'Existing installation activation failed; configuration and readiness require review.' };
}
if (require.main === module) {
  Promise.resolve().then(() => activateExisting(parseArgs(process.argv.slice(2)))).then(result => process.stdout.write(JSON.stringify(result) + '\n')).catch(error => { process.stderr.write(JSON.stringify(activationFailure(error)) + '\n'); process.exitCode = 1; });
}
module.exports = { activateExisting, parseArgs, probeExisting, activationFailure };
