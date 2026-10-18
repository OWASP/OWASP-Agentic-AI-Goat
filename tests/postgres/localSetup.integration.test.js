'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');
const { localPostgres } = require('../../scripts/setup-application');
const {
  POSTGRES_IMAGE,
  createDockerAdapters,
  inspectOptional,
  inspectPinnedPostgresImage,
  createOwnedDirectory,
  removeOwnedDirectory,
  cleanupOwnedFixture,
  createRecoveryJournal,
  updateRecoveryJournal,
} = require('./localSetupNativeFixture');

const socket = process.env.PG_LOCAL_DOCKER_TEST_SOCKET;
const evidencePath = process.env.PG_LOCAL_DOCKER_TEST_EVIDENCE;
const workspace = path.resolve(__dirname, '../..');

async function sourceHashes() {
  const files = [
    __filename,
    require.resolve('./localSetupNativeFixture'),
    require.resolve('../../scripts/setup-application'),
    require.resolve('../../scripts/local-docker-authority'),
  ];
  return Object.fromEntries(await Promise.all(files.map(async filename => [
    path.relative(workspace, filename),
    createHash('sha256').update(await fs.readFile(filename)).digest('hex'),
  ])));
}

function parseFormattedString(stdout, description) {
  let value;
  try { value = JSON.parse(String(stdout).trim()); } catch {}
  assert.equal(typeof value, 'string', `${description} must be a JSON string`);
  assert.ok(value, `${description} must not be empty`);
  return value;
}

function assertOwnedPostgresResources({ container, volume, id, name, port, imageId }) {
  assert.equal(container?.Config?.Labels?.['org.dvaia.workspace'], id);
  assert.equal(volume?.Labels?.['org.dvaia.workspace'], id);
  assert.equal(container.Image, imageId, 'Container must use the preflight image identity');
  assert.ok(container.Mounts?.some(item => item.Type === 'volume' && item.Name === name
    && item.Destination === '/var/lib/postgresql'));
  assert.deepEqual(container.HostConfig?.PortBindings?.['5432/tcp'], [
    { HostIp: '127.0.0.1', HostPort: String(port) },
  ]);
}

test('owned local PostgreSQL binding survives restart and legacy authority adoption', {
  skip: process.env.PG_TEST_DISPOSABLE !== 'yes' || !socket,
  timeout: 180000,
}, async t => {
  const id = randomBytes(6).toString('hex');
  const nonce = randomBytes(16).toString('hex');
  const name = `dvaia-postgres-${id}`;
  const directory = await createOwnedDirectory({ id, nonce });
  let client = null;
  let admitted = false;
  let expectedImage = null;
  let daemonId = null;
  let cleanupEvidence = null;
  let journal = null;
  let journalCreated = false;
  const expectedSourceHashes = await sourceHashes();

  const { applicationExecute, ownedDocker } = createDockerAdapters({
    socket,
    environment: process.env,
    beforeApplicationRun: async ({ args, ownedDocker: runOwnedDocker }) => {
      assert.equal(args.at(-1), POSTGRES_IMAGE, 'Application must use the preflight PostgreSQL image tag');
      assert.equal(args.some(value => value === '--pull' || value.startsWith('--pull=')), false,
        'Native qualification never enables image pulling');
      const currentImage = await inspectPinnedPostgresImage(runOwnedDocker);
      assert.equal(currentImage.id, expectedImage.id, 'PostgreSQL image tag changed after preflight');
    },
  });
  const applicationEnvironment = { ...process.env, DOCKER_HOST: socket,
    DOCKER_TLS_VERIFY: '1', DOCKER_CERT_PATH: '/fixture/must-not-reach-docker' };
  delete applicationEnvironment.DOCKER_CONTEXT;

  try {
    journal = { version: 1, status: 'preflight', id, name, directory,
      canonicalDirectory: await fs.realpath(directory), nonce, sourceHashes: expectedSourceHashes,
      expectedImage: null, daemonId: null, containerId: null, phases: [], cleanup: null };
    await createRecoveryJournal({ evidencePath, workspace, state: journal });
    journalCreated = true;
    expectedImage = await inspectPinnedPostgresImage(ownedDocker);
    daemonId = parseFormattedString((await ownedDocker(['info', '--format', '{{json .ID}}'])).stdout,
      'Docker daemon identity');
    assert.equal(await inspectOptional(ownedDocker, 'container', name), null, 'Random fixture container must start absent');
    assert.equal(await inspectOptional(ownedDocker, 'volume', name), null, 'Random fixture volume must start absent');
    journal = { ...journal, status: 'ready', expectedImage, daemonId,
      phases: [...journal.phases, { name: 'preflight', complete: true, exactResourcesAbsent: true }] };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });
    admitted = true;

    journal = { ...journal, status: 'fresh-running', phases: [...journal.phases, { name: 'fresh', complete: false }] };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });
    const freshUrl = await localPostgres({ directory, id, execute: applicationExecute,
      environment: applicationEnvironment });
    const freshState = JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8'));
    const freshAuthority = JSON.parse(await fs.readFile(path.join(directory, 'local-docker.json'), 'utf8'));
    assert.equal(freshState.version, 2);
    assert.match(freshState.dockerAuthorityDigest, /^[a-f0-9]{64}$/);
    assert.equal(freshAuthority.workspaceId, id);
    assert.equal(freshAuthority.host, socket);
    assert.equal(freshAuthority.daemonId, daemonId);
    assert.equal((await fs.stat(path.join(directory, 'local-postgres.json'))).mode & 0o777, 0o600);
    assert.equal((await fs.stat(path.join(directory, 'local-docker.json'))).mode & 0o777, 0o600);
    const freshContainer = await inspectOptional(ownedDocker, 'container', name);
    assertOwnedPostgresResources({
      container: freshContainer, volume: await inspectOptional(ownedDocker, 'volume', name),
      id, name, port: freshState.port, imageId: expectedImage.id,
    });
    journal = { ...journal, status: 'fresh-complete', containerId: freshContainer.Id,
      phases: journal.phases.map(phase => phase.name === 'fresh' ? { ...phase, complete: true } : phase) };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });

    client = new (require('pg').Client)({ connectionString: freshUrl });
    await client.connect();
    assert.match((await client.query('SHOW server_version')).rows[0].server_version, /^18\./);
    await client.query('CREATE TABLE dvaia_native_binding_sentinel (id text PRIMARY KEY)');
    await client.query('INSERT INTO dvaia_native_binding_sentinel(id) VALUES ($1)', [nonce]);
    await client.end(); client = null;

    journal = { ...journal, status: 'restart-running', phases: [...journal.phases, { name: 'restart', complete: false }] };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });
    await ownedDocker(['stop', name]);
    const restartedUrl = await localPostgres({ directory, id, execute: applicationExecute,
      environment: applicationEnvironment });
    assert.equal(new URL(restartedUrl).port, new URL(freshUrl).port);
    assert.equal(new URL(restartedUrl).password, new URL(freshUrl).password);
    client = new (require('pg').Client)({ connectionString: restartedUrl });
    await client.connect();
    assert.deepEqual((await client.query('SELECT id FROM dvaia_native_binding_sentinel')).rows, [{ id: nonce }]);
    await client.end(); client = null;
    journal = { ...journal, status: 'restart-complete',
      phases: journal.phases.map(phase => phase.name === 'restart' ? { ...phase, complete: true } : phase) };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });

    journal = { ...journal, status: 'legacy-running', phases: [...journal.phases, { name: 'legacy-adoption', complete: false }] };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });
    await ownedDocker(['stop', name]);
    const retained = JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8'));
    const legacy = { version: 1, id: retained.id, name: retained.name,
      port: retained.port, password: retained.password };
    const legacyPending = path.join(directory, 'local-postgres.fixture-legacy');
    await fs.writeFile(legacyPending, JSON.stringify(legacy), { flag: 'wx', mode: 0o600 });
    await fs.rename(legacyPending, path.join(directory, 'local-postgres.json'));
    await fs.rm(path.join(directory, 'local-docker.json'));

    const adoptedUrl = await localPostgres({ directory, id, execute: applicationExecute,
      environment: applicationEnvironment, existingOnly: true });
    assert.equal(new URL(adoptedUrl).port, new URL(freshUrl).port);
    assert.equal(new URL(adoptedUrl).password, new URL(freshUrl).password);
    const adoptedState = JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8'));
    const adoptedAuthority = JSON.parse(await fs.readFile(path.join(directory, 'local-docker.json'), 'utf8'));
    assert.equal(adoptedState.version, 2);
    assert.match(adoptedState.dockerAuthorityDigest, /^[a-f0-9]{64}$/);
    assert.equal(adoptedAuthority.host, socket);
    assert.equal(adoptedAuthority.daemonId, daemonId);
    assertOwnedPostgresResources({
      container: await inspectOptional(ownedDocker, 'container', name),
      volume: await inspectOptional(ownedDocker, 'volume', name),
      id, name, port: adoptedState.port, imageId: expectedImage.id,
    });
    client = new (require('pg').Client)({ connectionString: adoptedUrl });
    await client.connect();
    assert.deepEqual((await client.query('SELECT id FROM dvaia_native_binding_sentinel')).rows, [{ id: nonce }]);
    journal = { ...journal, status: 'legacy-complete',
      phases: journal.phases.map(phase => phase.name === 'legacy-adoption' ? { ...phase, complete: true } : phase) };
    await updateRecoveryJournal({ evidencePath, workspace, state: journal });
  } finally {
    let finalFailure = null;
    let cleanupSucceeded = false;
    const qualificationComplete = journal?.phases?.some(phase => phase.name === 'legacy-adoption' && phase.complete === true) === true;
    try { await client?.end(); } catch (error) { finalFailure = error; }
    if (journalCreated) {
      journal = { ...journal, status: 'cleanup-running', cleanup: { complete: false } };
      try { await updateRecoveryJournal({ evidencePath, workspace, state: journal }); }
      catch (error) { finalFailure ||= error; }
    }
    try {
      if (admitted) cleanupEvidence = await cleanupOwnedFixture({ ownedDocker, id, name, directory, nonce });
      else {
        await removeOwnedDirectory({ directory, id, nonce });
        cleanupEvidence = { containerRemoved: false, volumeRemoved: false,
          containerAbsent: true, volumeAbsent: true, directoryRemoved: true };
      }
      assert.deepEqual(await sourceHashes(), expectedSourceHashes, 'Native fixture source changed during qualification');
      cleanupSucceeded = true;
    } catch (error) { finalFailure ||= error; }
    if (journalCreated) {
      journal = { ...journal,
        status: cleanupSucceeded ? (qualificationComplete ? 'complete' : 'failed-cleaned') : 'cleanup-failed',
        cleanup: cleanupSucceeded ? { complete: true, ...cleanupEvidence } : { complete: false },
        ...(cleanupSucceeded ? { sourceHashesAfter: expectedSourceHashes } : {}) };
      try { await updateRecoveryJournal({ evidencePath, workspace, state: journal }); }
      catch (error) { finalFailure ||= error; }
    }
    t.diagnostic(JSON.stringify({ id, name, directory, daemonId, imageId: expectedImage?.id || null,
      repoDigests: expectedImage?.repoDigests || [], admitted, cleanup: cleanupEvidence }));
    if (finalFailure) throw finalFailure;
  }
});
