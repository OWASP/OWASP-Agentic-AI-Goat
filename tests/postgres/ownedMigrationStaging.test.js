'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createOwnedMigrationStaging } = require('./helpers/ownedMigrationStaging');
async function temp(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-migration-data-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return name => path.join(root, name);
}
test('existing candidate or predecessor prevents staging and cleanup preserves all bytes', async t => {
  const file = await temp(t), staging = createOwnedMigrationStaging();
  await fs.writeFile(file('existing'), 'canonical');
  await assert.rejects(staging.assertAbsent([file('absent'), file('existing')]), /already exists/);
  await staging.cleanup();
  assert.equal(await fs.readFile(file('existing'), 'utf8'), 'canonical');
  await assert.rejects(fs.stat(file('absent')), { code: 'ENOENT' });
});
test('exclusive-create collision after preflight retains concurrent bytes and removes only own prior file', async t => {
  const file = await temp(t), staging = createOwnedMigrationStaging();
  await staging.assertAbsent([file('own'), file('raced')]);
  await staging.write(file('own'), Buffer.from('owned'));
  await fs.writeFile(file('raced'), 'other');
  await assert.rejects(staging.write(file('raced'), Buffer.from('ours')), { code: 'EEXIST' });
  await staging.cleanup();
  await assert.rejects(fs.stat(file('own')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(file('raced'), 'utf8'), 'other');
});
test('replaced inode and modified owned bytes are retained while independent owned file is retired', async t => {
  const file = await temp(t), staging = createOwnedMigrationStaging();
  for (const name of ['replaced', 'modified', 'owned']) await staging.write(file(name), Buffer.from('original'));
  await fs.rename(file('replaced'), file('original-inode'));
  await fs.writeFile(file('replaced'), 'original');
  await fs.writeFile(file('modified'), 'changed');
  await assert.rejects(staging.cleanup(), AggregateError);
  assert.equal(await fs.readFile(file('replaced'), 'utf8'), 'original');
  assert.equal(await fs.readFile(file('modified'), 'utf8'), 'changed');
  await assert.rejects(fs.stat(file('owned')), { code: 'ENOENT' });
});
