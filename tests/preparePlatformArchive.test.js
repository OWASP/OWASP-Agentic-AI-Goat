'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { COLUMNS: platform } = require('../db/postgres/map-platform-snapshot');
const { COLUMNS: identity } = require('../db/postgres/map-identity-archive');
const { preparePlatformArchive } = require('../db/postgres/prepare-platform-archive');
const { planPlatformArchive, argumentsFor } = require('../db/postgres/plan-platform-archive');

test('archive preparation exposes private inputs separately and blocks unmapped source apply', async () => {
  const archive = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-prepare-archive-'));
  const write = async (file, bytes) => {
    await fs.writeFile(path.join(archive, file), bytes);
    return { bytes: Buffer.byteLength(bytes), sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  };
  try {
    const tables = [];
    for (const [name, columns] of Object.entries({ ...platform, ...identity })) {
      const file = `${name}.jsonl`;
      tables.push({ name, columns: columns.split(' '), rows: 0, file, ...await write(file, '') });
    }
    tables.push({ name: 'custom_state', columns: ['payload'], rows: 1, file: 'custom.jsonl',
      ...await write('custom.jsonl', JSON.stringify([{ type: 'text', value: 'private archived payload' }]) + '\n') });
    const schemaFile = 'schema.json';
    const schema = await write(schemaFile, JSON.stringify(tables.map(table => ({ type: 'table', name: table.name }))));
    await write('manifest.json', JSON.stringify({ version: 1, format: 'dvaia-sqlite-archive-v1', complete: true,
      files: [{ name: 'users_auth.db', sourceSha256: 'b'.repeat(64), schemaFile, schema, tables }] }));
    const result = await preparePlatformArchive({ archive, identityMap: {} });
    assert.equal(result.report.readyToApply, false);
    assert.equal(result.report.requiresReview, true);
    assert.deepEqual(result.report.unmappedPopulatedTables, [{ source: 'users_auth.db', table: 'custom_state', rows: 1, disposition: 'unmapped' }]);
    assert.equal(result.inputs.platform.tables.custom_state[0].payload, 'private archived payload');
    assert.equal(JSON.stringify(result.report).includes('private archived payload'), false);
    assert.equal(result.inputs.platform.archiveDigest, result.inputs.solutions.archiveDigest);
    assert.equal(result.inputs.additionalSolutions.archiveDigest, result.report.archiveDigest);
    assert.equal(result.inputs.platform.review, undefined);
    const reviewed = await preparePlatformArchive({ archive, identityMap: {},
      identityReview: { archiveDigest: result.report.archiveDigest, normalizations: [] } });
    assert.equal(reviewed.report.identity.normalizationReviewComplete, true);
    assert.equal(reviewed.report.readyToApply, false);
    assert.deepEqual(reviewed.inputs.identity, result.inputs.identity);
    await assert.rejects(preparePlatformArchive({ archive, identityMap: {},
      identityReview: { archiveDigest: 'f'.repeat(64), normalizations: [] } }), { code: 'STALE_IDENTITY_NORMALIZATION_REVIEW' });
    await assert.rejects(preparePlatformArchive({ archive, identityMap: { 7: 71 } }), { code: 'ARCHIVE_IDENTITY_MAPPING_TARGET_MISSING' });
    const mapFile = path.join(archive, 'identity-map.json'), output = path.join(archive, 'private-plan.json');
    await fs.writeFile(mapFile, '{}');
    const planned = await planPlatformArchive({ archive, identityMapFile: mapFile, output });
    assert.equal(planned.readyToApply, false);
    assert.equal((await fs.stat(output)).mode & 0o777, 0o600);
    assert.equal((await fs.readFile(output, 'utf8')).includes('private archived payload'), false);
    await assert.rejects(planPlatformArchive({ archive, identityMapFile: mapFile, output }), { code: 'EEXIST' });
    const stdout = require('node:child_process').execFileSync(process.execPath,
      [path.join(__dirname, '../db/postgres/plan-platform-archive.js'), '--archive', archive, '--identity-map', mapFile], { encoding: 'utf8' });
    assert.equal(JSON.parse(stdout).readyToApply, false);
    assert.equal(stdout.includes('private archived payload'), false);
    assert.equal(stdout.includes('"inputs"'), false);
    const auxiliaryColumns = require('../db/postgres/map-identity-auxiliary').COLUMNS;
    const manifest = JSON.parse(await fs.readFile(path.join(archive, 'manifest.json'), 'utf8'));
    const appendAuxiliary = async (name, columns) => {
      const file = `${name}.jsonl`;
      manifest.files[0].tables.push({ name, columns: columns.split(' '), rows: 0, file, ...await write(file, '') });
      manifest.files[0].schema = await write(schemaFile, JSON.stringify(manifest.files[0].tables.map(table => ({ type:'table', name:table.name }))));
      await write('manifest.json', JSON.stringify(manifest));
    };
    const auxiliaryEntries = Object.entries(auxiliaryColumns);
    await appendAuxiliary(...auxiliaryEntries[0]);
    await assert.rejects(preparePlatformArchive({ archive, identityMap:{} }), {code:'INCOMPLETE_AUXILIARY_ARCHIVE_SCOPE'});
    for (const entry of auxiliaryEntries.slice(1)) await appendAuxiliary(...entry);
    const withAuxiliary = await preparePlatformArchive({ archive, identityMap:{} });
    assert.deepEqual(withAuxiliary.inputs.identityAuxiliary.identityUserIds, []);
    assert.equal(withAuxiliary.inputs.identityAuxiliary.archiveDigest, withAuxiliary.report.archiveDigest);
    for (const table of Object.keys(auxiliaryColumns)) assert.equal(withAuxiliary.report.coverage.find(row=>row.table===table).disposition,'mapped');
    assert.equal(withAuxiliary.report.readyToApply,false);

  } finally { await fs.rm(archive, { recursive: true, force: true }); }
});

test('offline archive plan rejects mutation switches, duplicate arguments and invalid timezone choices', () => {
  assert.deepEqual(argumentsFor(['--archive', '/archive', '--identity-map', '/map']), { archive: '/archive', identityMapFile: '/map' });
  for (const tail of [['--apply'], ['--archive', '/other'], ['--naive-timestamps', 'local'], ['--output']]) {
    assert.throws(() => argumentsFor(['--archive', '/archive', '--identity-map', '/map', ...tail]), /INVALID_PLAN_ARGUMENTS/);
  }
});

test('plan parser rejects inherited object-property flags',()=>{
 for(const flag of ['constructor','__proto__']) assert.throws(()=>argumentsFor(['--archive','a','--identity-map','i',flag,'x']),/INVALID_PLAN_ARGUMENTS/);
});
