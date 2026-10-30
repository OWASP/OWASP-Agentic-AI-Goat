'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const dotenv = require('dotenv');
const { prepareOwnedEnvironment, prepareOwnedManagedConfiguration, managedConfigurationPath,
  localProfilePlan, MANAGED } = require('../scripts/install/mcp-owned-local');
const { loadOwnedManagedConfiguration } = require('../server/services/mcp/ownedManagedConfiguration');
const { provisionOwnedLocal, provisionFromEnvironment } = require('../scripts/install/mcp-owned-provision');

async function installedProfileDigest() {
  const template = await fs.readFile(path.join(__dirname, '../sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'), 'utf8');
  return require('node:crypto').createHash('sha256').update(template.replaceAll('@@SUPERVISOR_PROFILE@@', 'owasp-ai-goat-mcp-sandbox')).digest('hex');
}

async function environment(t, body = `JWT_SECRET=${'s'.repeat(48)}\nCUSTOM_SETTING=preserved\n`) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-owned-install-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const envPath = path.join(directory, '.env'); await fs.writeFile(envPath, body, { mode: 0o600 }); return envPath;
}

test('private activation configuration preserves signing key and existing target token exactly', async t => {
  const token = 'T'.repeat(64); const jwt = 'j'.repeat(48);
  const envPath = await environment(t, `JWT_SECRET=${jwt}\nMCP_OWNED_TARGET_TOKEN=${token}\n`);
  const result = await prepareOwnedEnvironment({ envPath, randomToken: () => { throw new Error('must not rotate'); } });
  assert.equal(result.tokenPreserved, true); const parsed = dotenv.parse(await fs.readFile(envPath));
  assert.equal(parsed.JWT_SECRET, jwt); assert.equal(parsed.MCP_OWNED_TARGET_TOKEN, token);
  for (const [key, value] of Object.entries(MANAGED)) assert.equal(parsed[key], value);
  assert.equal((await fs.stat(envPath)).mode & 0o077, 0);
});

test('missing target token is generated once while owned application activation stays off', async t => {
  const envPath = await environment(t); let calls = 0;
  await prepareOwnedEnvironment({ envPath, randomToken: () => { calls++; return 'N'.repeat(64); } });
  await prepareOwnedEnvironment({ envPath, randomToken: () => { calls++; return 'X'.repeat(64); } });
  const parsed = dotenv.parse(await fs.readFile(envPath));
  assert.equal(calls, 1); assert.equal(parsed.MCP_OWNED_TARGET_TOKEN, 'N'.repeat(64));
  assert.equal(parsed.MCP_OWNED_RESOURCES_ENABLED, 'false'); assert.equal(parsed.CUSTOM_SETTING, 'preserved');
  assert.equal(parsed.CODEBOT_OWNED_EXECUTION_ENABLED, 'false');
  assert.equal(parsed.CODEBOT_SANDBOX_RUNNER_URL, 'http://127.0.0.1:8092');
});

test('managed configuration preserves the private environment and activates only by explicit transition', async t => {
  const envPath = await environment(t); const before = await fs.readFile(envPath);
  const managedPath = path.join(path.dirname(envPath), 'private', 'mcp-owned.env'); let tokens = 0;
  const prepared = await prepareOwnedManagedConfiguration({ envPath, managedPath,
    randomToken: () => { tokens++; return 'M'.repeat(64); } });
  assert.equal(tokens, 1); assert.equal(prepared.activationEnabled, false);
  assert.deepEqual(await fs.readFile(envPath), before);
  assert.equal((await fs.stat(managedPath)).mode & 0o077, 0);
  assert.deepEqual(loadOwnedManagedConfiguration({ file: managedPath }), prepared.values);
  const activated = await prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateQualified: true, randomToken: () => { throw new Error('must preserve token'); } });
  assert.equal(activated.activationEnabled, true);
  assert.equal(activated.values.MCP_OWNED_TARGET_TOKEN, 'M'.repeat(64));
  assert.equal(activated.values.MCP_OWNED_RESOURCES_ENABLED, 'true');
  assert.equal(activated.values.MCP_OBSERVED_ACTION_ENABLED, 'false');
  assert.equal(activated.values.CODEBOT_OWNED_EXECUTION_ENABLED, 'true');
  assert.deepEqual(await fs.readFile(envPath), before);
});

test('observed-action activation is independent, explicit, and backwards compatible with five-objective config', async t => {
  const envPath = await environment(t); const managedPath = path.join(path.dirname(envPath), 'managed', 'mcp-owned.env');
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    randomToken: () => 'O'.repeat(64) });
  const current = await fs.readFile(managedPath, 'utf8');
  const legacyFive = current.split('\n').filter(line => !line.startsWith('MCP_OBSERVED_ACTION_ENABLED=')).join('\n');
  await fs.writeFile(managedPath, legacyFive, { mode: 0o600 });
  assert.equal(loadOwnedManagedConfiguration({ file: managedPath }).MCP_OBSERVED_ACTION_ENABLED, 'false');
  await assert.rejects(prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateObservedAction: true }), { code: 'MCP_INSTALL_ENV_INVALID' });
  const activated = await prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateQualified: true, activateObservedAction: true });
  assert.equal(activated.values.MCP_OBSERVED_ACTION_ENABLED, 'true');
  const preserved = await prepareOwnedManagedConfiguration({ envPath, managedPath });
  assert.equal(preserved.values.MCP_OBSERVED_ACTION_ENABLED, 'true');
  const disabled = await prepareOwnedManagedConfiguration({ envPath, managedPath, forceDisabled: true });
  assert.equal(disabled.values.MCP_OWNED_RESOURCES_ENABLED, 'false');
  assert.equal(disabled.values.MCP_OBSERVED_ACTION_ENABLED, 'false');
});

test('indirect-injection activation is default-off and requires qualified observed action', async t => {
  const envPath = await environment(t); const managedPath = path.join(path.dirname(envPath), 'managed', 'mcp-owned.env');
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    randomToken: () => 'I'.repeat(64) });
  assert.equal(loadOwnedManagedConfiguration({ file: managedPath }).MCP_INDIRECT_INJECTION_ENABLED, 'false');
  await assert.rejects(prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateQualified: true, activateIndirectInjection: true }), { code: 'MCP_INSTALL_ENV_INVALID' });
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    activateObservedAction: true, activateIndirectInjection: true });
  const enabled = loadOwnedManagedConfiguration({ file: managedPath });
  assert.equal(enabled.MCP_OBSERVED_ACTION_ENABLED, 'true');
  assert.equal(enabled.MCP_INDIRECT_INJECTION_ENABLED, 'true');
  const disabled = await prepareOwnedManagedConfiguration({ envPath, managedPath, forceDisabled: true });
  assert.equal(disabled.values.MCP_INDIRECT_INJECTION_ENABLED, 'false');
});

test('managed activation overrides explicit private false feature flags without rewriting private env', async t => {
  const envPath = await environment(t, `JWT_SECRET=${'s'.repeat(48)}\nMCP_OBSERVED_ACTION_ENABLED=false\nMCP_INDIRECT_INJECTION_ENABLED=false\nMCP_SUPPLY_CHAIN_ENABLED=false\n`);
  const before = await fs.readFile(envPath);
  const managedPath = path.join(path.dirname(envPath), 'managed', 'mcp-owned.env');
  const result = await prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateQualified: true, activateObservedAction: true, activateIndirectInjection: true });
  assert.equal(result.values.MCP_OBSERVED_ACTION_ENABLED, 'true');
  assert.equal(result.values.MCP_INDIRECT_INJECTION_ENABLED, 'true');
  assert.deepEqual(await fs.readFile(envPath), before);
});

test('managed startup configuration is workspace scoped and rejects untrusted or unknown input', async t => {
  const envPath = await environment(t); const home = path.dirname(envPath); const root = '/owned/workspace';
  const first = managedConfigurationPath({ root, home });
  assert.notEqual(first, managedConfigurationPath({ root: '/other/workspace', home }));
  await prepareOwnedManagedConfiguration({ envPath, managedPath: first, randomToken: () => 'N'.repeat(64) });
  await fs.appendFile(first, 'UNRELATED=value\n');
  assert.throws(() => loadOwnedManagedConfiguration({ file: first }), { code: 'MCP_MANAGED_CONFIGURATION_INVALID' });
  await fs.writeFile(first, 'x', { mode: 0o644 }); await fs.chmod(first, 0o644);
  assert.throws(() => loadOwnedManagedConfiguration({ file: first }), { code: 'MCP_MANAGED_CONFIGURATION_UNTRUSTED' });
});

test('failed qualified readiness leaves managed activation disabled', async t => {
  const envPath = await environment(t); const before = await fs.readFile(envPath);
  const managedPath = path.join(path.dirname(envPath), 'managed', 'mcp-owned.env');
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    randomToken: () => 'Q'.repeat(64) });
  assert.equal(loadOwnedManagedConfiguration({ file: managedPath }).MCP_OWNED_RESOURCES_ENABLED, 'true');
  await assert.rejects(provisionFromEnvironment({ envPath, managedPath, activateQualified: true,
    provision: async ({ readiness, codeBotReadiness }) => {
      assert.equal((await readiness()).ready, true);
      assert.equal((await codeBotReadiness()).ready, false);
      throw Object.assign(new Error('not ready'), { code: 'MCP_INSTALL_READINESS_FAILED' });
    },
    targetClientFactory: () => ({ readiness: async () => ({ ready: true }) }),
    codeBotReadiness: async () => ({ ready: false }) }), { code: 'MCP_INSTALL_READINESS_FAILED' });
  const managed = loadOwnedManagedConfiguration({ file: managedPath });
  assert.equal(managed.MCP_OWNED_RESOURCES_ENABLED, 'false');
  assert.equal(managed.CODEBOT_OWNED_EXECUTION_ENABLED, 'false');
  assert.deepEqual(await fs.readFile(envPath), before);
});

test('invalid signing state, conflicting managed values, duplicates and pending recovery fail before mutation', async t => {
  const cases = [
    [`CUSTOM_SETTING=x\n`, 'INVALID_CONFIGURATION'],
    [`JWT_SECRET=${'s'.repeat(48)}\nMCP_OWNED_TARGET_PORT=9999\n`, 'MCP_INSTALL_ENV_CONFLICT'],
    [`JWT_SECRET=${'s'.repeat(48)}\nMCP_OWNED_TARGET_PORT=8092\nMCP_OWNED_TARGET_PORT=8092\n`, 'MCP_INSTALL_ENV_CONFLICT'],
  ];
  for (const [body, code] of cases) {
    const envPath = await environment(t, body); const before = await fs.readFile(envPath);
    await assert.rejects(prepareOwnedEnvironment({ envPath }), { code }); assert.deepEqual(await fs.readFile(envPath), before);
  }
  const envPath = await environment(t); await fs.writeFile(`${envPath}.mcp-owned`, 'recovery', { mode: 0o600 });
  await assert.rejects(prepareOwnedEnvironment({ envPath }), { code: 'MCP_INSTALL_RECOVERY_REQUIRED' });
});

test('local profile plans are exact for Linux and an explicitly named Colima VM only', () => {
  const linux = localProfilePlan({ platform: 'linux', root: '/app' });
  assert.equal(linux.destination, '/etc/apparmor.d/owasp-ai-goat-mcp-sandbox'); assert.equal(linux.profile, 'owasp-ai-goat-mcp-sandbox');
  assert.equal(linux.dockerHost, 'unix:///var/run/docker.sock');
  const mac = localProfilePlan({ platform: 'darwin', root: '/app', home: '/home/test', colimaProfile: 'colima-owasp-ai-goat-local' });
  assert.equal(mac.sshConfig, '/home/test/.colima/_lima/colima-owasp-ai-goat-local/ssh.config');
  assert.equal(mac.sshHost, 'lima-colima-owasp-ai-goat-local');
  assert.equal(mac.dockerHost, 'unix:///home/test/.colima/owasp-ai-goat-local/docker.sock');
  assert.throws(() => localProfilePlan({ platform: 'darwin', colimaProfile: 'default' }), { code: 'MCP_INSTALL_COLIMA_PROFILE_REQUIRED' });
  assert.throws(() => localProfilePlan({ platform: 'win32' }), { code: 'MCP_INSTALL_PLATFORM_UNSUPPORTED' });
});

test('compose keeps the strict owned runner opt-in, persistent and separate from legacy sidecars', async () => {
  const compose = await fs.readFile(path.join(__dirname, '../docker-compose.yml'), 'utf8');
  assert.match(compose, /mcp-owned-sandbox:\n\s+profiles: \["mcp-owned"\]/);
  assert.match(compose, /apparmor:\$\{MCP_OWNED_TARGET_APPARMOR_PROFILE:-owasp-ai-goat-mcp-sandbox\}/);
  assert.match(compose, /MCP_OWNED_TARGETS_ENABLED: "true"/); assert.match(compose, /mcp-owned-targets:\/sandbox\/owned-targets/);
  assert.doesNotMatch(compose.slice(compose.indexOf('mcp-owned-sandbox:'), compose.indexOf('mailpit:')), /privileged:|cap_add:|network_mode:\s*host/);
});

test('Linux provisioning parses and loads the exact profile before starting owned services', async () => {
  const calls = [];
  const run = async (file, args, options) => {
    calls.push([file, [...args], options]);
    if (file === 'sudo' && args[1] === 'sha256sum') {
      const profile = calls.find(([name, value]) => name === 'sudo'
        && value[1] === 'apparmor_parser' && value[2] === '--skip-kernel-load')[1][3];
      const bytes = await fs.readFile(profile);
      return { exitCode: 0, stdout: `${require('node:crypto').createHash('sha256').update(bytes).digest('hex')}  ${args.at(-1)}\n` };
    }
    if (file === 'sudo' && args[1] === 'stat') return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    if (file === 'sudo' && args[1] === 'cat') return { exitCode: 0, stdout: 'owasp-ai-goat-mcp-sandbox (enforce)\n' };
    return { exitCode: 0, stdout: '' };
  };
  const result = await provisionOwnedLocal({ platform: 'linux', root: path.join(__dirname, '..'), run,
    readiness: async () => ({ ready: true, runnerReady: true, repositoryReady: true,
      runnerIsolation: 'bwrap-seccomp-v1', supervisorProfile: 'owasp-ai-goat-mcp-sandbox (enforce)' }) });
  assert.equal(result.activationEnabled, false); assert.match(result.profileSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(calls.map(([file, args]) => [file, args.slice(0, 3).join(' ')]), [
    ['sudo', '--non-interactive true'], ['sudo', '--non-interactive apparmor_parser --skip-kernel-load'],
    ['sudo', '--non-interactive test -e'], ['sudo', '--non-interactive stat -c'],
    ['sudo', '--non-interactive sha256sum /etc/apparmor.d/owasp-ai-goat-mcp-sandbox'],
    ['sudo', '--non-interactive stat -c'], ['sudo', '--non-interactive sha256sum /etc/apparmor.d/owasp-ai-goat-mcp-sandbox'],
    ['sudo', '--non-interactive apparmor_parser -r'],
    ['sudo', '--non-interactive cat /sys/kernel/security/apparmor/profiles'],
    ['docker', '--host unix:///var/run/docker.sock compose'], ['docker', '--host unix:///var/run/docker.sock compose'],
  ]);
  const dockerCalls = calls.filter(([file]) => file === 'docker');
  assert.ok(dockerCalls[0][1].includes('--no-recreate'));
  assert.deepEqual(dockerCalls[0][1].slice(-2), ['--wait', 'mailpit']);
  assert.equal(dockerCalls[1][2].timeoutMs, 10 * 60_000);
  assert.deepEqual(dockerCalls[1][1].slice(-2), ['--wait', 'mcp-owned-sandbox']);
});

test('a conflicting stable profile stops before load, Compose, or readiness', async () => {
  const calls = []; let readiness = 0;
  const run = async (file, args) => {
    calls.push([file, [...args]]);
    if (file === 'sudo' && args[1] === 'sha256sum') return { exitCode: 0, stdout: `${'0'.repeat(64)}  ${args.at(-1)}\n` };
    if (file === 'sudo' && args[1] === 'stat') return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    return { exitCode: 0, stdout: '' };
  };
  await assert.rejects(provisionOwnedLocal({ platform: 'linux', root: path.join(__dirname, '..'), run,
    readiness: async () => { readiness++; } }), { code: 'MCP_INSTALL_PROFILE_CONFLICT' });
  assert.equal(readiness, 0); assert.equal(calls.some(([file, args]) => file === 'sudo'
    && args[1] === 'apparmor_parser' && args[2] === '-r'), false);
  assert.equal(calls.some(([file]) => file === 'docker'), false);
});

test('provisioning rejects an ambient Docker daemon or context that differs from the selected authority', async () => {
  for (const commandEnv of [
    { DOCKER_HOST: 'unix:///tmp/wrong.sock' },
    { DOCKER_CONTEXT: 'desktop-linux' },
  ]) {
    let commands = 0; let probes = 0;
    await assert.rejects(provisionOwnedLocal({ platform: 'linux', root: path.join(__dirname, '..'), commandEnv,
      run: async () => { commands++; return { exitCode: 0, stdout: '' }; },
      readiness: async () => { probes++; return { ready: true }; } }),
    { code: 'MCP_INSTALL_DOCKER_AUTHORITY_CONFLICT', stage: 'docker-authority' });
    assert.equal(commands, 0); assert.equal(probes, 0);
  }
});

test('owned services never imply activation when live readiness is incomplete', async () => {
  const profileSha256 = await installedProfileDigest();
  const run = async (file, args) => {
    if (file === 'sudo' && args[1] === 'sha256sum') return { exitCode: 0, stdout: `${profileSha256}  ${args.at(-1)}\n` };
    if (file === 'sudo' && args[1] === 'test') return { exitCode: 1, stdout: '' };
    if (file === 'sudo' && args[1] === 'cat') return { exitCode: 0, stdout: 'owasp-ai-goat-mcp-sandbox (enforce)\n' };
    if (file === 'sudo' && args[1] === 'stat') return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    return { exitCode: 0, stdout: '' };
  };
  await assert.rejects(provisionOwnedLocal({ platform: 'linux', root: path.join(__dirname, '..'), run,
    readiness: async () => ({ ready: false, runnerReady: false, repositoryReady: true,
      runnerIsolation: null, supervisorProfile: null }) }),
  { code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness' });
});

test('owned service provisioning rejects a runner without strict CodeBot isolation', async () => {
  const profileSha256 = await installedProfileDigest();
  const run = async (file, args) => {
    if (file === 'sudo' && args[1] === 'sha256sum') return { exitCode: 0, stdout: `${profileSha256}  ${args.at(-1)}\n` };
    if (file === 'sudo' && args[1] === 'test') return { exitCode: 1, stdout: '' };
    if (file === 'sudo' && args[1] === 'cat') return { exitCode: 0, stdout: 'owasp-ai-goat-mcp-sandbox (enforce)\n' };
    if (file === 'sudo' && args[1] === 'stat') return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    return { exitCode: 0, stdout: '' };
  };
  await assert.rejects(provisionOwnedLocal({ platform: 'linux', root: path.join(__dirname, '..'), run,
    readiness: async () => ({ ready: true, runnerReady: true, runnerIsolation: 'bwrap-seccomp-v1',
      supervisorProfile: 'owasp-ai-goat-mcp-sandbox (enforce)' }),
    codeBotReadiness: async () => ({ ready: false, runnerReady: false, isolation: 'unavailable' }) }),
  { code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness' });
});

test('managed Colima provisioning uses only its explicit SSH authority and cleans its owned transfer directory', async () => {
  const calls = [];
  const run = async (file, args) => {
    calls.push([file, [...args]]);
    const command = args.at(-1);
    if (file === 'ssh' && /^test -e \/tmp\/owasp-ai-goat-mcp-owned-/.test(command)) return { exitCode: 1, stdout: '' };
    if (file === 'ssh' && command === 'sudo sha256sum /etc/apparmor.d/owasp-ai-goat-mcp-sandbox') {
      const profile = calls.find(([name]) => name === 'scp')[1][2];
      const bytes = await fs.readFile(profile);
      return { exitCode: 0, stdout: `${require('node:crypto').createHash('sha256').update(bytes).digest('hex')}  /etc/apparmor.d/owasp-ai-goat-mcp-sandbox\n` };
    }
    if (file === 'ssh' && command === 'sudo cat /sys/kernel/security/apparmor/profiles') {
      return { exitCode: 0, stdout: 'owasp-ai-goat-mcp-sandbox (enforce)\n' };
    }
    if (file === 'ssh' && command === 'sudo stat -c %u:%g:%a:%F /etc/apparmor.d/owasp-ai-goat-mcp-sandbox') {
      return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    }
    return { exitCode: 0, stdout: '' };
  };
  await provisionOwnedLocal({ platform: 'darwin', root: path.join(__dirname, '..'), home: '/home/test',
    colimaProfile: 'colima-owasp-ai-goat-local', nonce: '123456abcdef', run,
    readiness: async () => ({ ready: true, runnerReady: true, repositoryReady: true,
      runnerIsolation: 'bwrap-seccomp-v1', supervisorProfile: 'owasp-ai-goat-mcp-sandbox (enforce)' }) });
  const sshCalls = calls.filter(([file]) => file === 'ssh');
  assert.ok(sshCalls.every(([, args]) => args[0] === '-F'
    && args[1] === '/home/test/.colima/_lima/colima-owasp-ai-goat-local/ssh.config'
    && args[2] === 'lima-colima-owasp-ai-goat-local'));
  assert.match(sshCalls.at(-1)[1].at(-1), /^rm -rf \/tmp\/owasp-ai-goat-mcp-owned-[a-f0-9]{12}-123456abcdef$/);
  const docker = calls.find(([file]) => file === 'docker');
  assert.deepEqual(docker[1].slice(0, 3), ['--host', 'unix:///home/test/.colima/owasp-ai-goat-local/docker.sock', 'compose']);
});

test('an uncertain Colima directory creation is retained as explicit cleanup debt', async () => {
  const calls = [];
  const run = async (file, args) => {
    calls.push([file, [...args]]); const command = args.at(-1);
    if (file === 'ssh' && /^test -e \/tmp\/owasp-ai-goat-mcp-owned-/.test(command)) return { exitCode: 1, stdout: '' };
    if (file === 'ssh' && /^mkdir -m 0700 /.test(command)) throw Object.assign(new Error('timeout'), { code: 'TIMEOUT' });
    return { exitCode: 0, stdout: '' };
  };
  let caught;
  try {
    await provisionOwnedLocal({ platform: 'darwin', root: path.join(__dirname, '..'), home: '/home/test',
      colimaProfile: 'colima-owasp-ai-goat-local', nonce: '123456abcdef', run, readiness: async () => ({ ready: true }) });
  } catch (error) { caught = error; }
  assert.equal(caught.code, 'MCP_INSTALL_PROFILE_RECOVERY_REQUIRED');
  assert.equal(caught.stage, 'remote-create');
  assert.equal(caught.cleanupDebt.ownership, 'creation_unconfirmed');
  assert.equal(calls.some(([file, args]) => file === 'ssh' && /^rm -rf /.test(args.at(-1))), false);
});

test('operational entrypoint uses managed endpoint and token, preserves private env, and gates activation on readiness', async t => {
  const envPath = await environment(t); const before = await fs.readFile(envPath);
  const managedPath = path.join(path.dirname(envPath), 'managed', 'mcp-owned.env'); let configured;
  const run = async (file, args) => {
    if (file === 'sudo' && args[1] === 'sha256sum') {
      const profile = args.at(-1);
      const source = await fs.readFile(path.join(__dirname, '../sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'), 'utf8');
      const rendered = source.replaceAll('@@SUPERVISOR_PROFILE@@', 'owasp-ai-goat-mcp-sandbox');
      return { exitCode: 0, stdout: `${require('node:crypto').createHash('sha256').update(rendered).digest('hex')}  ${profile}\n` };
    }
    if (file === 'sudo' && args[1] === 'cat') return { exitCode: 0, stdout: 'owasp-ai-goat-mcp-sandbox (enforce)\n' };
    if (file === 'sudo' && args[1] === 'stat') return { exitCode: 0, stdout: '0:0:600:regular file\n' };
    return { exitCode: 0, stdout: '' };
  };
  const result = await provisionFromEnvironment({ envPath, managedPath, activateQualified: true,
    platform: 'linux', root: path.join(__dirname, '..'), run,
    codeBotReadiness: async () => ({ ready: true, runnerReady: true, isolation: 'bwrap-codebot-v1' }),
    targetClientFactory(value) {
      configured = value;
      return { async readiness() { return { ready: true, runnerReady: true, isolation: 'bwrap-seccomp-v1',
        supervisorProfile: 'owasp-ai-goat-mcp-sandbox (enforce)' }; } };
    } });
  const parsed = loadOwnedManagedConfiguration({ file: managedPath });
  assert.equal(configured.baseURL, 'http://127.0.0.1:8092');
  assert.equal(configured.token, parsed.MCP_OWNED_TARGET_TOKEN);
  assert.equal(parsed.MCP_OWNED_RESOURCES_ENABLED, 'true'); assert.equal(result.activationEnabled, true);
  assert.equal(parsed.CODEBOT_OWNED_EXECUTION_ENABLED, 'true');
  assert.deepEqual(await fs.readFile(envPath), before);
  assert.equal(result.codeBotIsolation, 'bwrap-codebot-v1');
});

test('protected recovery mode requires exact inspected immutable image/profile and capability before private activation',async t=>{
 const envPath=await environment(t),managedPath=path.join(path.dirname(envPath),'protected.env');
 const template=await fs.readFile(path.join(__dirname,'../sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'),'utf8');
 const profileSha256=require('node:crypto').createHash('sha256').update(template.replaceAll('@@SUPERVISOR_PROFILE@@','owasp-ai-goat-mcp-sandbox')).digest('hex');
 const image='sha256:'+'a'.repeat(64);let actualImage=image;
 const run=async(file,args)=>{
  if(file==='sudo'&&args[1]==='sha256sum')return{exitCode:0,stdout:`${profileSha256}  ${args.at(-1)}\n`};
  if(file==='sudo'&&args[1]==='test')return{exitCode:1,stdout:''};
  if(file==='sudo'&&args[1]==='cat')return{exitCode:0,stdout:'owasp-ai-goat-mcp-sandbox (enforce)\n'};
  if(file==='sudo'&&args[1]==='stat')return{exitCode:0,stdout:'0:0:600:regular file\n'};
  if(file==='docker'&&args.includes('ps'))return{exitCode:0,stdout:'b'.repeat(64)+'\n'};
  if(file==='docker'&&args.includes('inspect'))return{exitCode:0,stdout:JSON.stringify({Image:actualImage,AppArmorProfile:'owasp-ai-goat-mcp-sandbox'})};
  return{exitCode:0,stdout:''};
 };
 const options={envPath,managedPath,activateQualified:true,activateProtectedRecovery:true,protectedRecoveryRelease:{image,profileSha256},platform:'linux',root:path.join(__dirname,'..'),run,codeBotReadiness:async()=>({ready:true,isolation:'bwrap-codebot-v1'}),targetClientFactory:()=>({readiness:async()=>({ready:true,runnerReady:true,isolation:'bwrap-seccomp-v1',supervisorProfile:'owasp-ai-goat-mcp-sandbox (enforce)',protectedJournalCapability:'mcp-owned-protected-operation-journal.v1',protectedReadbackCapability:'mcp-owned-protected-readback.v1'})})};
 await provisionFromEnvironment(options);assert.equal(loadOwnedManagedConfiguration({file:managedPath}).MCP_PROTECTED_RECOVERY_ENABLED,'true');
 await provisionFromEnvironment(options);assert.equal(loadOwnedManagedConfiguration({file:managedPath}).MCP_PROTECTED_RECOVERY_ENABLED,'true');
 actualImage='sha256:'+'c'.repeat(64);await assert.rejects(provisionFromEnvironment(options),{code:'MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED'});assert.equal(loadOwnedManagedConfiguration({file:managedPath}).MCP_PROTECTED_RECOVERY_ENABLED,'false');
});

test('requested lesson capabilities admit exact readiness and deny each missing capability before activation', async t => {
 const envPath=await environment(t),before=await fs.readFile(envPath),managedPath=path.join(path.dirname(envPath),'capabilities.env');
 const q=require('../server/services/mcp/ownedQualification');
 const receipt={ready:true,runnerReady:true,isolation:'bwrap-seccomp-v1',supervisorProfile:'owasp-ai-goat-mcp-sandbox (enforce)',protectedStateCapability:q.PROTECTED_STATE_CAPABILITY,observedActionCapability:q.OBSERVED_ACTION_CAPABILITY,ticketReadCapability:q.TICKET_READ_CAPABILITY,packageInstallCapability:q.PACKAGE_INSTALL_CAPABILITY};
 const options={envPath,managedPath,activateQualified:true,activateObservedAction:true,activateIndirectInjection:true,activateSupplyChain:true,provision:async({readiness})=>{await readiness();return {ok:true};}};
 for(const key of ['protectedStateCapability','observedActionCapability','ticketReadCapability','packageInstallCapability']) {
  for(const replacement of [undefined,'wrong-capability']) {
   await assert.rejects(provisionFromEnvironment({...options,targetClientFactory:()=>({readiness:async()=>({...receipt,[key]:replacement})})}),{code:'MCP_INSTALL_CAPABILITY_UNAVAILABLE'});
   const state=loadOwnedManagedConfiguration({file:managedPath});
   for(const flag of ['MCP_OWNED_RESOURCES_ENABLED','MCP_OBSERVED_ACTION_ENABLED','MCP_INDIRECT_INJECTION_ENABLED','MCP_SUPPLY_CHAIN_ENABLED'])assert.equal(state[flag],'false');
  }
 }
 await assert.rejects(provisionFromEnvironment({...options,provision:async()=>({ok:true}),targetClientFactory:()=>({readiness:async()=>receipt})}),{code:'MCP_INSTALL_CAPABILITY_UNAVAILABLE'});
 const token=loadOwnedManagedConfiguration({file:managedPath}).MCP_OWNED_TARGET_TOKEN;
 await provisionFromEnvironment({...options,targetClientFactory:()=>({readiness:async()=>receipt})});
 const state=loadOwnedManagedConfiguration({file:managedPath});
 for(const flag of ['MCP_OWNED_RESOURCES_ENABLED','MCP_OBSERVED_ACTION_ENABLED','MCP_INDIRECT_INJECTION_ENABLED','MCP_SUPPLY_CHAIN_ENABLED'])assert.equal(state[flag],'true');
 assert.equal(state.MCP_OWNED_TARGET_TOKEN,token);assert.deepEqual(await fs.readFile(envPath),before);
});
