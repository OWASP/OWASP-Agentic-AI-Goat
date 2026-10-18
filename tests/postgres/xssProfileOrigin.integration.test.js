'use strict';

const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request)) {
    throw new Error(`Working/SQLite database import forbidden: ${request}`);
  }
  return originalLoad.call(this, request, parent, isMain);
};

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const { createXssWorkshopDb } = require('../../server/database/postgres/xssWorkshopDb');
const { createXssProfileOriginRepository } = require('../../server/database/postgres/xssProfileOriginRepository');
const { inspectXssProfileOrigin } = require('../../server/services/xssProfileOriginValidation');

const runtimeUrl = process.env.PG_XSS_PROFILE_ORIGIN_RUNTIME_URL;
const migrationUrl = process.env.PG_XSS_PROFILE_ORIGIN_MIGRATION_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && runtimeUrl && migrationUrl;

function assertOwnedUrl(value) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/dvaia_test_xss_profile_origin');
}
function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
function modelInput(userId, field, value, overrides = {}) {
  const runId = overrides.runId || randomUUID();
  return {
    userKey: String(userId), platformUserId: userId, field, value,
    learnerMessage: overrides.learnerMessage || `Generate a new event-handler value and save it to my ${field}.`,
    workshopGeneration: overrides.workshopGeneration ?? 3,
    execution: {
      runId, ownerKey: JSON.stringify(['XSS', String(userId)]), durableGeneration: 5,
      check: overrides.check || (async () => {}), ...(overrides.execution || {}),
    },
    decision: {
      modelSucceeded: true, decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b',
      rawDecisionResponse: JSON.stringify({ action: 'updateProfile', field, value }),
      ...(overrides.decision || {}),
    },
    observationIndex: overrides.observationIndex ?? 0,
  };
}
function storedLlmExecution(execution, userId, childGeneration, overrides = {}) {
  const runId = overrides.runId || execution.runId;
  const ownerKey = JSON.stringify(['XSS', String(userId)]);
  return {
    ...execution, runId, ownerKey,
    scopeBinding:Object.freeze({ runId, ownerId:userId, ownerKey, scopeKey:'stored_llm',
      parentGeneration:String(execution.durableGeneration), childGeneration:String(childGeneration) }),
  };
}
function storedUserExecution(userId, childGeneration, check = async () => {}) {
  const runId = randomUUID();
  const ownerKey = JSON.stringify(['XSS', String(userId)]);
  return {
    runId, ownerKey, durableGeneration:'5', check,
    scopeBinding:Object.freeze({runId, ownerId:userId, ownerKey, scopeKey:'stored_user',
      parentGeneration:'5', childGeneration:String(childGeneration)}),
  };
}

test('native profile origin is atomic, current-value bound and invalidated by every manual write and reset',
  { skip: !enabled }, async () => {
    assertOwnedUrl(runtimeUrl); assertOwnedUrl(migrationUrl);
    const pool = createPool(process.env, 'PG_XSS_PROFILE_ORIGIN_RUNTIME_URL');
    const migration = createPool(process.env, 'PG_XSS_PROFILE_ORIGIN_MIGRATION_URL');
    try {
      const legacy = createXssWorkshopDb(pool);
      await legacy.initializeXssWorkshopDb(migration);
      const ledger = (await migration.query(`SELECT name,checksum,applied_at
        FROM dvaia_migrations.ledger ORDER BY name`)).rows;
      assert.equal(ledger.at(-1)?.name, '0015_owner_deletion_write_fence.sql');
      await legacy.initializeXssWorkshopDb(migration);
      assert.deepEqual((await migration.query(`SELECT name,checksum,applied_at
        FROM dvaia_migrations.ledger ORDER BY name`)).rows, ledger,
      'fresh current XSS migration tail replays as a no-op');
      const repository = createXssProfileOriginRepository(pool);

      const payload = '<img src=x onerror="globalThis.✓=\'雪\'">';
      const write = modelInput(17, 'bio', payload);
      const receipt = await repository.writeModelField(write);
      assert.deepEqual(Object.keys(receipt).sort(), ['decisionSource','durableGeneration','field','model','observationIndex',
        'ownerKey','platformUserId','provider','rawDecisionSha256','revision','runId','userKey','valueSha256','version',
        'workshopGeneration','writtenAt'].sort());
      assert.equal(receipt.valueSha256, digest(payload));
      const current = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' });
      assert.equal(current.value, payload);
      assert.equal(current.origin.runId, write.execution.runId);
      assert.deepEqual(current.origin, receipt);
      assert.equal(inspectXssProfileOrigin({ snapshot: current, userKey: '17', platformUserId: 17,
        field: 'bio', workshopGeneration: 3, execution: write.execution, requireWriterRun: true }).valid, true);
      assert.deepEqual(Object.keys(await legacy.getProfile('17')).sort(), ['bio','name','website'],
        'public profile DTO does not expose revision or origin metadata');

      const sameBytes = await repository.writeManualField({ userKey: '17', platformUserId: 17, field: 'bio', value: payload });
      assert.equal(BigInt(sameBytes.revision), BigInt(receipt.revision) + 1n);
      const manuallyRewritten = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' });
      assert.equal(manuallyRewritten.origin, null,
        'an identical-byte manual rewrite invalidates model origin');
      assert.equal(inspectXssProfileOrigin({ snapshot: manuallyRewritten, userKey: '17', platformUserId: 17,
        field: 'bio', workshopGeneration: 3, execution: write.execution }).reason, 'origin_missing');

      const regenerated = await repository.writeModelField(modelInput(17, 'bio', payload));
      const copiedSame = await repository.writeModelField(modelInput(17, 'bio', payload,
        { learnerMessage: `Save this exact value as my bio: ${payload}` }));
      assert.equal(copiedSame.written, true, 'the intentionally unsafe model-selected write still executes');
      assert.equal(copiedSame.qualifyingOrigin, false);
      assert.equal(copiedSame.copiedFromLearner, true);
      assert.equal(BigInt(copiedSame.revision), BigInt(regenerated.revision) + 1n);
      const copiedSameSnapshot = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' });
      assert.equal(copiedSameSnapshot.value, payload);
      assert.equal(copiedSameSnapshot.origin, null, 'same-byte learner copy clears the prior authentic origin');
      assert.equal(inspectXssProfileOrigin({ snapshot: copiedSameSnapshot, userKey: '17', platformUserId: 17,
        field: 'bio', workshopGeneration: 3, execution: write.execution }).valid, false);

      const generatedAgain = await repository.writeModelField(modelInput(17, 'bio', '<svg onload="generated()">'));
      assert.equal((await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' })).origin.runId,
        generatedAgain.runId);
      const learnerValue = '<img src=x onerror="learner()">';
      const copiedNew = await repository.writeModelField(modelInput(17, 'bio', learnerValue,
        { learnerMessage: `Please persist exactly ${learnerValue} without changing it.` }));
      assert.equal(copiedNew.qualifyingOrigin, false);
      const copiedNewSnapshot = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' });
      assert.equal(copiedNewSnapshot.value, learnerValue, 'new learner bytes remain stored as the teaching sink');
      assert.equal(copiedNewSnapshot.valueSha256, digest(learnerValue));
      assert.equal(copiedNewSnapshot.origin, null);

      const second = await repository.writeModelField(modelInput(17, 'website', 'javascript:alert(17)', { observationIndex: 2 }));
      await repository.resetProfile({ userKey: '17', platformUserId: 17 });
      const reset = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'website' });
      assert.equal(reset.value, 'https://example.com');
      assert.equal(reset.origin, null);
      assert.equal(BigInt(reset.revision), BigInt(second.revision) + 1n);

      const beforeRejected = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'name' });
      await assert.rejects(repository.writeModelField(modelInput(17, 'name', 'foreign', { execution: {
        ownerKey: '["XSS","18"]',
      } })), { code: 'OWNER_MISMATCH' });
      await assert.rejects(repository.writeModelField(modelInput(17, 'name', 'scripted', { decision: {
        modelSucceeded: true, decisionSource: 'model', provider: 'fixture-model', model: 'fixture',
      } })), { code: 'MODEL_PROVENANCE_REQUIRED' });
      let checks = 0;
      await assert.rejects(repository.writeModelField(modelInput(17, 'name', 'stale', { check: async () => {
        checks += 1;
        if (checks === 2) throw Object.assign(new Error('reset won'), { code: 'STALE_GENERATION' });
      } })), { code: 'STALE_GENERATION' });
      assert.deepEqual(await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'name' }), beforeRejected,
        'a failed final current-execution check rolls back the profile and origin write');

      await repository.writeModelField(modelInput(18, 'name', 'owner eighteen'));
      assert.equal((await repository.readCurrent({ userKey: '18', platformUserId: 18, field: 'name' })).value,
        'owner eighteen');
      await assert.rejects(repository.readCurrent({ userKey: '18', platformUserId: 17, field: 'name' }),
        { code: 'OWNER_MISMATCH' });

      const preciseInput = modelInput(29, 'bio', '<b>precision fixture</b>', {
        execution: { durableGeneration: '9007199254740993' },
      });
      const preciseReceipt = await repository.writeModelField(preciseInput);
      const preciseSnapshot = await repository.readCurrent({ userKey: '29', platformUserId: 29, field: 'bio' });
      assert.equal(preciseReceipt.durableGeneration, '9007199254740993');
      assert.equal(preciseSnapshot.origin.durableGeneration, '9007199254740993');
      const inspection = { snapshot: preciseSnapshot, userKey: '29', platformUserId: 29,
        field: 'bio', workshopGeneration: 3, execution: preciseInput.execution };
      assert.equal(inspectXssProfileOrigin(inspection).valid, true);
      assert.equal(inspectXssProfileOrigin({ ...inspection,
        execution: { ...preciseInput.execution, durableGeneration: '9007199254740992' } }).valid, false);
      await assert.rejects(repository.writeModelField(modelInput(29, 'bio', 'must not overwrite', {
        execution: { durableGeneration: '9223372036854775808' },
      })), { code: 'BAD_REQUEST' });
      assert.deepEqual(await repository.readCurrent({ userKey: '29', platformUserId: 29, field: 'bio' }), preciseSnapshot);

      const scopedInput = modelInput(30, 'bio', '<i>child-bound model value</i>');
      scopedInput.execution = storedLlmExecution(scopedInput.execution, 30, '9007199254740993');
      const scopedReceipt = await repository.writeModelField(scopedInput);
      assert.equal(scopedReceipt.version, 'xss-profile-origin-v2');
      assert.equal(scopedReceipt.scopeKey, 'stored_llm');
      assert.equal(scopedReceipt.childGeneration, '9007199254740993');
      const scopedSnapshot = await repository.readCurrent({ userKey:'30', platformUserId:30, field:'bio' });
      assert.deepEqual(scopedSnapshot.origin, scopedReceipt);
      assert.equal(inspectXssProfileOrigin({ snapshot:scopedSnapshot, userKey:'30', platformUserId:30,
        field:'bio', workshopGeneration:3, execution:scopedInput.execution, requireWriterRun:true }).valid, true);
      const laterExecution = storedLlmExecution(scopedInput.execution, 30, '9007199254740993', {
        runId:randomUUID(),
      });
      assert.equal(inspectXssProfileOrigin({ snapshot:scopedSnapshot, userKey:'30', platformUserId:30,
        field:'bio', workshopGeneration:3, execution:laterExecution }).valid, true,
      'a later run in the same child generation may read the current v2 origin');
      const resetGeneration = storedLlmExecution(laterExecution, 30, '9007199254740994');
      assert.equal(inspectXssProfileOrigin({ snapshot:scopedSnapshot, userKey:'30', platformUserId:30,
        field:'bio', workshopGeneration:3, execution:resetGeneration }).valid, false,
      'a scoped reset child-generation advance invalidates the old v2 origin');
      assert.equal(inspectXssProfileOrigin({ snapshot:scopedSnapshot, userKey:'30', platformUserId:30,
        field:'bio', workshopGeneration:3,
        execution:{ ...laterExecution, scopeBinding:undefined } }).valid, false,
      'v2 origin cannot qualify an unscoped execution');
      const legacyScopedExecution = storedLlmExecution(preciseInput.execution, 29, '0');
      assert.equal(inspectXssProfileOrigin({ snapshot:preciseSnapshot, userKey:'29', platformUserId:29,
        field:'bio', workshopGeneration:3, execution:legacyScopedExecution }).valid, false,
      'legacy v1 origin cannot qualify a scoped execution');
      await assert.rejects(migration.query(`UPDATE xss.profile_model_origins SET child_generation=NULL
        WHERE user_key='30' AND field='bio'`), { code:'23514' });
      await assert.rejects(migration.query(`UPDATE xss.profile_model_origins SET scope_key=NULL
        WHERE user_key='30' AND field='bio'`), { code:'23514' });
      assert.deepEqual(await repository.readCurrent({ userKey:'30', platformUserId:30, field:'bio' }), scopedSnapshot,
        'all-or-none child binding constraint rolls back an invalid partial update');

      const guardedModel = await repository.writeModelField(modelInput(31, 'bio', '<b>guarded origin</b>'));
      const beforeGuardedManual = await repository.readCurrent({userKey:'31', platformUserId:31, field:'bio'});
      assert.equal(beforeGuardedManual.origin.runId, guardedModel.runId);
      let manualChecks = 0;
      const staleManualExecution = storedUserExecution(31, '4', async () => {
        manualChecks += 1;
        if (manualChecks === 2) {
          throw Object.assign(new Error('stored-user child reset won'),
            {name:'AbortError', code:'XSS_SCOPE_STALE'});
        }
      });
      await assert.rejects(repository.writeScopedManualField({userKey:'31', platformUserId:31,
        field:'bio', value:'<img src=x onerror="late()">', execution:staleManualExecution}),
      {code:'XSS_SCOPE_STALE'});
      assert.equal(manualChecks, 2);
      assert.deepEqual(await repository.readCurrent({userKey:'31', platformUserId:31, field:'bio'}),
        beforeGuardedManual,
      'a stale final stored-user child check rolls back both the physical profile write and origin deletion');

      const committedManual = await repository.writeScopedManualField({userKey:'31', platformUserId:31,
        field:'bio', value:'<img src=x onerror="current()">', execution:storedUserExecution(31, '5')});
      assert.equal(committedManual.origin, null);
      const afterGuardedManual = await repository.readCurrent({userKey:'31', platformUserId:31, field:'bio'});
      assert.equal(afterGuardedManual.value, '<img src=x onerror="current()">');
      assert.equal(afterGuardedManual.origin, null,
        'a current stored-user write commits the teaching sink and invalidates prior model provenance');

      const concurrent = [];
      for (let index = 0; index < 12; index += 1) {
        if (index % 2) concurrent.push(repository.writeManualField({ userKey: '23', platformUserId: 23, field: 'bio', value: `manual-${index}` })
          .then(result => ({ kind: 'manual', result, value: `manual-${index}` })));
        else concurrent.push(repository.writeModelField(modelInput(23, 'bio', `model-${index}`, { observationIndex: index }))
          .then(result => ({ kind: 'model', result, value: `model-${index}` })));
      }
      const results = await Promise.all(concurrent);
      assert.equal(new Set(results.map(item => item.result.revision)).size, results.length,
        'concurrent writes receive one distinct serialized revision each');
      const winner = results.reduce((latest, item) => BigInt(item.result.revision) > BigInt(latest.result.revision) ? item : latest);
      const final = await repository.readCurrent({ userKey: '23', platformUserId: 23, field: 'bio' });
      assert.equal(final.revision, winner.result.revision);
      assert.equal(final.value, winner.value);
      assert.equal(final.valueSha256, digest(winner.value));
      if (winner.kind === 'model') assert.equal(final.origin.runId, winner.result.runId);
      else assert.equal(final.origin, null);

      assert.equal((await migration.query(`SELECT count(*)::int n FROM xss.profile_model_origins o
        JOIN xss.profiles p USING(user_key) WHERE o.revision<>CASE o.field
          WHEN 'name' THEN p.name_revision WHEN 'bio' THEN p.bio_revision ELSE p.website_revision END`)).rows[0].n, 0);
    } finally {
      await Promise.all([pool.end(), migration.end()]);
    }
  });
