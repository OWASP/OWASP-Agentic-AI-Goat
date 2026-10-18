'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopModeService } = require('../server/services/workshopModeService');
const { createWorkshopModeRepository } = require('../server/database/postgres/workshopRevisionRepository');

function readFixture(savedMode) {
  const queries = [];
  const pool = { async query(sql, args) {
    queries.push({ sql, args });
    assert.match(sql, /^SELECT /, 'reading mode must not create a mode row or revision');
    if (sql.includes('LIMIT 0')) return { rows: [] };
    if (sql.includes('FROM workshop_platform.exercises')) return { rows: [{ workshop_key: 'csrf_workshop' }] };
    assert.deepEqual(args, [41, 'csrf_workshop']);
    return { rows: savedMode === undefined ? [] : [{ mode: savedMode }] };
  } };
  return { queries, service: createWorkshopModeService(createWorkshopModeRepository(pool)) };
}

test('CSRF no-row mode remains canonical null across reads without creating state', async () => {
  const { service, queries } = readFixture();
  for (let i = 0; i < 2; i++) {
    assert.equal(await service.getMode({ userId: 41, workshopKey: 'csrf_workshop' }), null);
  }
  assert.equal(queries.filter(q => q.sql.includes('LIMIT 0')).length, 1);
  assert.equal(queries.filter(q => q.sql.includes('SELECT mode')).length, 2);
});

test('explicit persisted CSRF modes are not replaced by the historical null default', async () => {
  for (const mode of ['vuln', 'fixed']) {
    const { service } = readFixture(mode);
    assert.equal(await service.getMode({ userId: 41, workshopKey: 'csrf_workshop' }), mode);
  }
});

test('null is a compatibility default, not a public mode mutation', async () => {
  const { service, queries } = readFixture();
  await assert.rejects(service.setMode({ userId: 41, workshopKey: 'csrf_workshop', mode: null }), /Invalid mode/);
  assert.equal(queries.length, 0);
});
