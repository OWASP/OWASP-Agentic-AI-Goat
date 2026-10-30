'use strict';

const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const WORKSHOP_KEY = 'sensitive_info_disclosure';
const OBJECTIVE = 'traversal_secrets';

async function request(base, token, objectiveId) {
  const response = await fetch(`${base}/api/workshop/sensitive-info/chat`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`,
      'content-type': 'application/json' },
    body: JSON.stringify({ userMessage: 'ordinary fixture request', objectiveId }), signal:AbortSignal.timeout(10000),
  });
  return { status: response.status, body: await response.json() };
}

async function qualify({identityRuntime,identityMigration,ports,onStage=()=>{}}){
    assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
    for(const [pool,role] of [[identityRuntime,'runtime'],[identityMigration,'migration']]){const row=(await pool.query('SELECT current_user role,current_database() database')).rows[0];assert.equal(row.role,'dvaia_identity_'+role);assert.match(row.database,/^owasp_ai_goat_test_finflow_admission_[a-f0-9]{12}_identity$/);}
    let server,serverPort;
    const originalLoad = Module._load;
    const routePath = path.resolve(__dirname, '../../server/routes/sensitiveInfoWorkshop.js');
    assert.equal(require.cache[routePath],undefined,'Fresh owned route module required');
    let actorCalls = 0;
    let creditWrites = 0;
    class StubActor {
      async runUserExclusive(owner, work) {
        return work({}, { ownerId: owner, ownerKey: JSON.stringify(['FinFlow', owner]),
          durableGeneration: '0', runId: randomUUID(), check: async () => {} });
      }
      async processMessage(_message, _history, _mode, objectiveId) {
        actorCalls++;
        return { success: true, response: 'explicit no-model actor stub', toolCalls: [],
          judgments: [], completedObjectiveIds: [], durableGrading: true,
          run: { decision_source: 'stub', provider: null, model: null }, objectiveId };
      }
      async resetUserExclusive(_owner, work) { return work(); }
    }
    const storeStub = {
      engine: 'postgres',
      async completeObjective() { creditWrites++; throw new Error('stub actor cannot earn credit'); },
      async logToolCall() { throw new Error('stub actor cannot execute tools'); },
    };
    try {
      onStage('identity-initialize');
      const identityApi = require('../../server/database/postgres/identityRepository');
      await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
      await require('../../server/database/postgres/workshopPlatformSeed')
        .seedWorkshopPlatform(identityMigration);
      const identityAdapter = require('../../server/services/postgresIdentityAdapter')
        .getPostgresIdentityAdapter();
      const passwordHash = await require('bcryptjs').hash(randomUUID(), 4);
      const owner = await identityAdapter.repository.createUser({
        username: `finflow-admission-${randomUUID().slice(0, 8)}`,
        email: `finflow-admission-${randomUUID()}@fixture.invalid`, passwordHash,
      });
      const session = await identityAdapter.createSession(
        await identityAdapter.repository.findCredentialById(owner.id),
        { get: () => null, ip: '127.0.0.1' });
      const config = require('../../server/database/postgres/workshopConfigRepository')
        .createWorkshopConfigRepository(identityRuntime);
      await config.setExerciseVisibility(WORKSHOP_KEY, true, owner.id);
      await config.setObjectiveVisibility(WORKSHOP_KEY, OBJECTIVE, true, owner.id);

      Module._load = function admissionStub(requested, parent, isMain) {
        if (parent?.filename === routePath && requested === '../services/sensitiveInfoWorkshopAgent') {
          return { SensitiveInfoWorkshopAgent: StubActor, OBJECTIVES: [],
            createSensitiveInfoWorkshopStateStore: () => ({ resetUser() {} }) };
        }
        if (parent?.filename === routePath && requested === '../database/sensitiveInfoWorkshopDb') {
          return storeStub;
        }
        if (parent?.filename === routePath && requested === '../utils/progressSync') {
          return { syncObjectiveComplete: async () => { creditWrites++; },
            syncWorkshopStarted: async () => {}, checkAndMarkWorkshopComplete: async () => false,
            resetWorkshopProgress: async () => {} };
        }
        return originalLoad.call(this, requested, parent, isMain);
      };
      delete require.cache[routePath];
      const express = require('express');
      const app = express();
      app.use(express.json());
      app.use('/api/workshop/sensitive-info', require(routePath));
      server = await new Promise(resolve => {
        const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
      });
      const base = `http://127.0.0.1:${server.address().port}`;

      serverPort=server.address().port;ports.add(serverPort);onStage('enabled');
      let outcome = await request(base, session.token, OBJECTIVE);
      assert.equal(outcome.status, 200, JSON.stringify(outcome.body));
      assert.equal(outcome.body.run.decision_source, 'stub');
      assert.equal(actorCalls, 1);

      onStage('disabled');await config.setObjectiveVisibility(WORKSHOP_KEY, OBJECTIVE, false, owner.id);
      outcome = await request(base, session.token, OBJECTIVE);
      assert.equal(outcome.status, 409);
      assert.equal(outcome.body.code, 'OBJECTIVE_DISABLED');
      assert.equal(actorCalls, 1);

      await config.setObjectiveVisibility(WORKSHOP_KEY, OBJECTIVE, true, owner.id);
      onStage('hidden');await config.setExerciseVisibility(WORKSHOP_KEY, false, owner.id);
      for (const selected of [OBJECTIVE, undefined]) {
        outcome = await request(base, session.token, selected);
        assert.equal(outcome.status, 403);
        assert.equal(outcome.body.code, 'EXERCISE_UNAVAILABLE');
      }
      assert.equal(actorCalls, 1);

      onStage('reenabled');await config.setExerciseVisibility(WORKSHOP_KEY, true, owner.id);
      outcome = await request(base, session.token, undefined);
      assert.equal(outcome.status, 200, JSON.stringify(outcome.body));
      assert.equal(actorCalls, 2);

      onStage('storage-unavailable');await identityMigration.query('ALTER TABLE workshop_platform.objectives RENAME TO objectives_admission_probe');
      try {
        outcome = await request(base, session.token, OBJECTIVE);
        assert.equal(outcome.status, 503);
        assert.equal(outcome.body.code, 'EXERCISE_AVAILABILITY_UNAVAILABLE');
        assert.doesNotMatch(JSON.stringify(outcome.body), /objectives_admission_probe|relation|postgres/i);
      } finally {
        await identityMigration.query('ALTER TABLE workshop_platform.objectives_admission_probe RENAME TO objectives');
      }
      onStage('no-credit-readback');assert.equal(actorCalls, 2);
      assert.equal(creditWrites, 0);
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count
        FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`,
      [owner.id, WORKSHOP_KEY])).rows[0].count, 0);
      assert.equal((await identityRuntime.query(`SELECT count(*)::integer AS count
        FROM workshop_platform.objective_judgments WHERE user_id=$1 AND workshop_key=$2`,
      [owner.id, WORKSHOP_KEY])).rows[0].count, 0);
      return {scope:'controlled actor/store; real authenticated live catalog; no model proof',actorCalls,creditWrites,enabled:200,disabled:409,hiddenSelected:403,hiddenGeneral:403,reenabled:200,storageUnavailable:503,canonicalCompletions:0,canonicalJudgments:0};
    } finally {
      Module._load = originalLoad;
      delete require.cache[routePath];
      if (server) await new Promise((resolve, reject) =>{server.close(error => error ? reject(error) : resolve());server.closeAllConnections?.();});
      if(serverPort)ports.delete(serverPort);
    }
}
module.exports={qualify,request,WORKSHOP_KEY,OBJECTIVE};
