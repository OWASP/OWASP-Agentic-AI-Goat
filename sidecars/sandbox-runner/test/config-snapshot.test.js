'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createConfigSnapshot, CONFIG_SNAPSHOT_VERSION, CONFIG_SNAPSHOT_LIMITS,
  buildConfigSnapshotProgram } = require('../index');

const digest = value => crypto.createHash('sha256').update(value).digest('hex');

async function fixture(t, env, credentials, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-config-snapshot-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const envPath = path.join(root, '.env');
  const credentialsPath = path.join(root, 'credentials.json');
  await fs.writeFile(envPath, env);
  await fs.writeFile(credentialsPath, credentials);
  return { root, envPath, credentialsPath,
    snapshot: createConfigSnapshot({ envPath, credentialsPath, ...options }) };
}

function assertRanges(result) {
  const output = Buffer.from(result.output, 'utf8');
  assert.equal(result.observation.outputBytes, output.length);
  assert.equal(result.observation.outputSha256, digest(output));
  for (const credential of result.observation.credentials) {
    const source = result.observation.sources.find(item => item.id === credential.source);
    assert.ok(source);
    assert.ok(credential.range.startByte >= source.range.startByte);
    assert.ok(credential.range.endByte <= source.range.endByte);
    const value = output.subarray(credential.range.startByte, credential.range.endByte);
    assert.equal(value.length, credential.valueBytes);
    assert.equal(digest(value), credential.valueSha256);
  }
}

test('snapshot returns exact source bytes and byte-addressed current credential evidence', async t => {
  const env = Buffer.from('APP_ENV=production\nDB_PASSWORD=rotatable-db-value\nJWT_SECRET=jwt-value\n', 'utf8');
  const credentials = Buffer.from(JSON.stringify({ aws: { access_key: 'current-access', secret_key: 'current-secret' }, database: { password: 'json-db-value' } }, null, 2));
  const f = await fixture(t, env, credentials);
  const result = await f.snapshot();

  assert.equal(result.observation.version, CONFIG_SNAPSHOT_VERSION);
  assert.deepEqual(result.observation.sources.map(source => source.id), ['environment', 'credentials']);
  for (const [source, expected] of [[result.observation.sources[0], env], [result.observation.sources[1], credentials]]) {
    const actual = Buffer.from(result.output, 'utf8').subarray(source.range.startByte, source.range.endByte);
    assert.deepEqual(actual, expected);
    assert.equal(source.sha256, digest(expected));
    assert.equal(source.bytes, expected.length);
  }
  assert.deepEqual(result.observation.credentials.map(item => item.name), [
    'env.DB_PASSWORD', 'env.JWT_SECRET', 'json.aws.access_key',
    'json.aws.secret_key', 'json.database.password',
  ]);
  assertRanges(result);
  assert.equal(JSON.stringify(result.observation).includes('rotatable-db-value'), false,
    'observation contains digests and ranges, not a second plaintext credential copy');
});

test('rotation produces a new observation over the values current for that invocation', async t => {
  const f = await fixture(t, 'DB_PASSWORD=first-db\n', '{"database":{"password":"first-json"}}\n');
  const first = await f.snapshot();
  await fs.writeFile(f.envPath, 'DB_PASSWORD=second-db\n');
  await fs.writeFile(f.credentialsPath, '{"database":{"password":"second-json"}}\n');
  const second = await f.snapshot();

  assert.match(first.output, /first-db/);
  assert.doesNotMatch(second.output, /first-db|first-json/);
  assert.match(second.output, /second-db/);
  assert.notEqual(first.observation.outputSha256, second.observation.outputSha256);
  assertRanges(first);
  assertRanges(second);
});

test('credential ranges use UTF-8 byte offsets rather than JavaScript character offsets', async t => {
  const f = await fixture(t, 'APP_ENV=prod\nAPI_KEY=clé-秘密\n', '{"stripe":{"live_key":"κλειδί"}}\n');
  const result = await f.snapshot();
  assertRanges(result);
  const output = Buffer.from(result.output, 'utf8');
  assert.deepEqual(result.observation.credentials.map(item =>
    output.subarray(item.range.startByte, item.range.endByte).toString('utf8')), ['clé-秘密', 'κλειδί']);
});

test('JSON escape spelling is attested inside the original source without synthesized plaintext', async t => {
  const rawJson = '{"service":{"secret_key":"escaped\\u79d8\\\"value"}}\n';
  const f = await fixture(t, 'DB_PASSWORD=clé-秘密\n', rawJson);
  const result = await f.snapshot();
  assertRanges(result);
  const output = Buffer.from(result.output, 'utf8');
  const jsonCredential = result.observation.credentials.find(item => item.source === 'credentials');
  assert.equal(output.subarray(jsonCredential.range.startByte, jsonCredential.range.endByte).toString('utf8'), 'escaped\\u79d8\\\"value');
  assert.doesNotMatch(result.output, /escaped秘"value/,
    'decoded JSON value is not appended as a second synthesized disclosure');
});

test('missing, empty, malformed, unsupported and oversized sources fail honestly', async t => {
  const cases = [
    { env: '', json: '{}', code: 'CONFIG_SOURCE_EMPTY' },
    { env: 'not-an-assignment\n', json: '{"password":"value"}', code: 'CONFIG_SOURCE_MALFORMED' },
    { env: 'DB_PASSWORD=value\n', json: '{bad', code: 'CONFIG_SOURCE_MALFORMED' },
    { env: 'APP_ENV=production\n', json: '{"profile":{"name":"operator"}}', code: 'CONFIG_CREDENTIALS_MISSING' },
    { env: 'DB_PASSWORD=[REDACTED]\n', json: '{"password":"***"}', code: 'CONFIG_CREDENTIALS_MISSING' },
    { env: 'DB_PASSWORD=value-that-is-too-large\n', json: '{"password":"value"}', maxSourceBytes: 16, code: 'CONFIG_SOURCE_OVERSIZE' },
  ];
  for (const item of cases) {
    const f = await fixture(t, item.env, item.json, { maxSourceBytes: item.maxSourceBytes });
    await assert.rejects(f.snapshot(), error => error.code === item.code);
  }

  const missing = await fixture(t, 'DB_PASSWORD=value\n', '{"password":"value"}');
  await fs.rm(missing.credentialsPath);
  await assert.rejects(missing.snapshot(), error => error.code === 'CONFIG_SOURCE_MISSING');
});

test('a named pipe is rejected without waiting for a writer', {skip:process.platform==='win32'}, async t => {
  const {execFileSync}=require('node:child_process');
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-config-fifo-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const envPath=path.join(root,'.env'),credentialsPath=path.join(root,'credentials.json');
  execFileSync('mkfifo',[envPath]);
  await fs.writeFile(credentialsPath,JSON.stringify({password:'owned-fixture'}));
  const program=`const {createConfigSnapshot}=require(process.argv[1]);createConfigSnapshot({envPath:process.argv[2],credentialsPath:process.argv[3]})().then(()=>process.exit(2),error=>process.exit(error.code==='CONFIG_SOURCE_INVALID'?0:3));`;
  // A subprocess deadline makes a regression fail without leaving the parent
  // test process stuck in a pending filesystem worker.
  execFileSync(process.execPath,['-e',program,path.resolve(__dirname,'../index.js'),envPath,credentialsPath],{timeout:3000});
});

test('directories and symbolic links cannot become config evidence sources', async t => {
  const f = await fixture(t, 'DB_PASSWORD=value\n', '{"password":"value"}');
  const directorySnapshot = createConfigSnapshot({ envPath: f.root, credentialsPath: f.credentialsPath });
  await assert.rejects(directorySnapshot(), error => error.code === 'CONFIG_SOURCE_INVALID');

  const link = path.join(f.root, 'linked.env');
  await fs.symlink(f.envPath, link);
  const linkedSnapshot = createConfigSnapshot({ envPath: link, credentialsPath: f.credentialsPath });
  await assert.rejects(linkedSnapshot(), error => error.code === 'CONFIG_SOURCE_SYMLINK');
});

test('factory accepts only bounded absolute server-selected paths', () => {
  assert.throws(() => createConfigSnapshot({ envPath: '.env', credentialsPath: '/credentials.json' }), /Absolute server-owned/);
  assert.throws(() => createConfigSnapshot({ envPath: '/.env', credentialsPath: '/credentials.json', maxSourceBytes: 0 }), /size limit/);
});

test('standalone compatibility program fixes source paths and emits no native failure detail', () => {
  const invocationId = '81000000-0000-4000-8000-000000000001';
  const program = buildConfigSnapshotProgram(invocationId);
  assert.match(program, /\/opt\/app\/config\/\.env/);
  assert.match(program, /\/var\/secrets\/credentials\.json/);
  assert.match(program, /CONFIG_SNAPSHOT_UNAVAILABLE/);
  assert.match(program, new RegExp(invocationId));
  assert.doesNotMatch(program, /process\.argv|envPath:\s*process|credentialsPath:\s*process/);
  assert.deepEqual(CONFIG_SNAPSHOT_LIMITS, {
    maxSourceBytes: 65536, maxOutputBytes: 131136, maxCredentials: 64, maxCredentialNameBytes: 256,
  });
  assert.throws(() => buildConfigSnapshotProgram('caller-chosen-command'), /version 4 invocation UUID/);
});
