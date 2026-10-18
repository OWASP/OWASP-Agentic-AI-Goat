'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const {
  defaultUpgrade,
  defaultRetainedOwnershipInitialization,
  prepareDisposableEnvironment,
} = require('./release-inputs/populated16-rehearsal.cjs');

const guard = path.join(__dirname, 'release-inputs', 'populated16-network-guard.cjs');
const upgradeChild = path.join(__dirname, 'release-inputs', 'populated16-upgrade-child.cjs');
const retainedInitializerChild = path.join(__dirname, 'release-inputs', 'populated16-retained-ownership-initialize-child.cjs');

function runGuardProbe(environment) {
  const source = `'use strict';
const net=require('node:net');
const allowed=Number(process.env.ALLOWED_PORT),blocked=Number(process.env.BLOCKED_PORT);
let socket;
try {
  assertDenied(()=>net.connect({host:'127.0.0.1',port:blocked}),'REHEARSAL_NETWORK_DENIED');
  assertDenied(()=>net.connect({path:'/tmp/populated16-forbidden.sock'}),'REHEARSAL_NETWORK_DENIED');
} catch(error) { console.error(error.message); process.exit(2); }
Promise.resolve(fetch('http://127.0.0.1:'+blocked+'/')).then(
  ()=>{throw Error('fetch unexpectedly allowed');},
  error=>{if(error.message!=='REHEARSAL_PROVIDER_DENIED')throw error;},
).then(()=>new Promise((resolve,reject)=>{
  socket=net.connect({host:'127.0.0.1',port:allowed},resolve);
  socket.once('error',reject);
})).then(()=>{socket.end();process.stdout.write('guard-passed');},error=>{
  console.error(error.message);process.exitCode=3;
});
function assertDenied(work,code){try{work();throw Error('socket unexpectedly allowed');}catch(error){if(error.message!==code)throw error;}}
`;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source], {
      env: { ...environment, NODE_OPTIONS: `--require ${guard}` },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', value => stdout.push(value));
    child.stderr.on('data', value => stderr.push(value));
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(Error('guard probe timeout'));
    }, 5000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() });
    });
  });
}

test('rehearsal guard allows only its exact owned PostgreSQL endpoint', { timeout: 10000 }, async t => {
  const server = net.createServer(socket => socket.end());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const allowed = server.address().port;
  const blocked = allowed === 65535 ? allowed - 1 : allowed + 1;
  const result = await runGuardProbe({
    PG_ADMIN_DATABASE_URL: `postgresql://postgres@127.0.0.1:${allowed}/postgres`,
    ALLOWED_PORT: String(allowed),
    BLOCKED_PORT: String(blocked),
  });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, 'guard-passed');
});

test('default upgrade selects the real upgrade child path with the guard preloaded', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'populated16-upgrade-')));
  const installation = path.join(root, 'installation');
  const home = path.join(root, 'home');
  fs.mkdirSync(installation, { mode: 0o700 });
  fs.mkdirSync(home, { mode: 0o700 });
  const launches = [];
  const controls = {
    createOwnedChildren() {
      return {
        launch(command, args, options) {
          launches.push({ command, args, options });
          return { marker: 'controlled-child' };
        },
        async cleanup() {},
      };
    },
    async waitForChild(child) {
      assert.deepEqual(child, { marker: 'controlled-child' });
      return 0;
    },
  };
  try {
    await defaultUpgrade({
      installation,
      home,
      admin: 'postgresql://postgres@127.0.0.1:55432/postgres',
      environment: {},
    }, { controls });
    assert.equal(launches.length, 1);
    assert.equal(launches[0].command, process.execPath);
    assert.equal(launches[0].args[0], upgradeChild);
    assert.equal(path.dirname(launches[0].args[1]), installation);
    assert.equal(launches[0].options.cwd, installation);
    assert.equal(launches[0].options.env.PG_ADMIN_DATABASE_URL,
      'postgresql://postgres@127.0.0.1:55432/postgres');
    assert.equal(launches[0].options.env.NODE_OPTIONS, `--require ${guard}`);
    assert.equal(fs.existsSync(guard), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('retained ownership uses a fresh guarded canonical initializer child for every pass', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'populated16-retained-init-')));
  const installation = path.join(root, 'installation'), home = path.join(root, 'home');
  fs.mkdirSync(installation, { mode: 0o700 }); fs.mkdirSync(home, { mode: 0o700 });
  const launches = [], controls = { createOwnedChildren() { return { launch(command,args,options) { launches.push({command,args,options}); return { marker: `child-${launches.length}` }; }, async cleanup() {} }; }, async waitForChild() { return 0; } };
  try {
    await defaultRetainedOwnershipInitialization({ installation, home, admin: 'postgresql://postgres@127.0.0.1:55432/postgres', environment: { IDENTITY_DATABASE_URL: 'postgresql://runtime@127.0.0.1:55432/identity' } }, { controls });
    assert.equal(launches.length, 1); assert.equal(launches[0].command, process.execPath); assert.equal(launches[0].args[0], retainedInitializerChild);
    assert.equal(path.dirname(launches[0].args[1]), installation); assert.equal(launches[0].options.cwd, installation);
    assert.equal(launches[0].options.env.HOME, home); assert.equal(launches[0].options.env.PG_ADMIN_DATABASE_URL, 'postgresql://postgres@127.0.0.1:55432/postgres'); assert.equal(launches[0].options.env.NODE_OPTIONS, `--require ${guard}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('disposable CTF delivery is provisioned before target environment publication', async () => {
  const oldDelivery = 'postgresql://dvaia_ctf_delivery:installed-secret@installed.invalid/dvaia_ctf';
  const newDelivery = 'postgresql://dvaia_ctf_delivery:disposable-secret@127.0.0.1:55432/dvaia_ctf';
  const calls = [];
  const environment = await prepareDisposableEnvironment({
    sourceConfiguration: {
      CTF_DELIVERY_DATABASE_URL: oldDelivery,
      PG_TLS: 'disable',
      SS_ENABLE: 'true',
    },
    provision: { configuration: { IDENTITY_DATABASE_URL: 'postgresql://runtime@127.0.0.1:55432/identity' } },
    directory: '/owned/private',
    admin: 'postgresql://postgres@127.0.0.1:55432/postgres',
    installation: '/owned/installation',
    home: '/owned/home',
    mappings: { PG_TLS: 'disable' },
  }, async options => {
    calls.push(options);
    return { configuration: { CTF_DELIVERY_DATABASE_URL: newDelivery }, additions: {
      CTF_DELIVERY_DATABASE_URL: newDelivery,
    } };
  });

  assert.deepEqual(calls, [{
    directory: '/owned/private',
    adminUrl: 'postgresql://postgres@127.0.0.1:55432/postgres',
    environment: { PG_TLS: 'disable' },
    existing: {},
  }]);
  assert.equal(environment.CTF_DELIVERY_DATABASE_URL, newDelivery);
  assert.notEqual(environment.CTF_DELIVERY_DATABASE_URL, oldDelivery);
  assert.equal(environment.IDENTITY_DATABASE_URL,
    'postgresql://runtime@127.0.0.1:55432/identity');
});
