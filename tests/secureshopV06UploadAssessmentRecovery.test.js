'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict');
const {
  randomUUID,
  createHash
} = require('node:crypto');
const {
  createSecureShopAssessmentSubjects,
  subjectState
} = require('../server/services/secureshopAssessmentSubject');
const {
  createSecureShopAssessmentStore
} = require('../server/database/postgres/secureshopAssessmentStore');
const {
  createObjectiveCompletionService
} = require('../server/services/objectiveCompletionService');
const {
  prepareJudgeInput,
  JUDGE_VERSION
} = require('../server/agent-runtime/objectiveJudge');
async function fixture({
  role = 'customer'
} = {}) {
  const tenantId = randomUUID(),
    principalId = randomUUID(),
    actor = 1000000001;
  const scope = {
    launchId: randomUUID(),
    scenarioId: randomUUID(),
    generation: 1,
    platformOwnerId: 501,
    platformSessionId: 502
  };
  const input = {
    scope,
    personaId: actor,
    role,
    sessionId: randomUUID(),
    authorityVersion: '1'
  };
  const current = {
      mode: 'vuln',
      generation: 0,
      revision: '1'
    },
    catalog = {
      catalog_active: true,
      effective_enabled: true,
      qualification: 'native-model'
    };
  const judgments = new Map(),
    links = new Map(),
    invocations = [],
    writes = [];
  const query = async (sql, p = []) => {
    const answer = rows => ({
      rows,
      rowCount: rows.length
    });
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.includes('pg_advisory_xact_lock')) return answer([]);
    if (sql.includes('SELECT realm')) return answer([{
      realm: 'shop',
      shop_tenant_id: tenantId
    }]);
    if (sql.includes('SELECT e.tenant_id')) return answer([{
      tenant_id: tenantId,
      principal_id: principalId,
      shop_user_id: actor,
      membership_version: '1'
    }]);
    if (sql.includes('SELECT s.id')) return answer([{
      id: scope.platformSessionId
    }]);
    if (sql.includes('SELECT l.launch_id')) return answer([{
      launch_id: scope.launchId
    }]);
    if (sql.includes('lock_assessment_mode')) return answer([{
      ...current
    }]);
    if (sql.includes('SELECT o.*')) return answer([{
      ...catalog
    }]);
    if (sql.startsWith('SELECT j.*,m.mode')) return answer([...judgments.values()].filter(row => !p[2] || row.evaluation_id === p[2]));
    if (sql.startsWith('SELECT * FROM secureshop_auth.assessment_judgments')) return answer(judgments.has(p[2]) ? [structuredClone(judgments.get(p[2]))] : []);
    if (sql.startsWith('SELECT 1 FROM secureshop_auth.assessment_retries r')) return answer(invocations.filter(i => links.get(i.parent_id) === p[2] && i.run_id === p[3] && JSON.stringify(i.execution_json) === p[4]).map(() => ({})));
    if (sql.startsWith('SELECT 1 FROM secureshop_auth.assessment_retries')) return answer([...links.values()].includes(p[2]) ? [{}] : []);
    if (sql.startsWith('SELECT child_id')) return answer(links.has(p[2]) ? [{
      child_id: links.get(p[2])
    }] : []);
    if (sql.startsWith('SELECT attempt,run_id')) return answer(invocations.filter(i => i.parent_id === p[2]));
    if (sql.startsWith('INSERT INTO secureshop_auth.assessment_judgments')) {
      const row = {
        ...structuredClone(judgments.get(p[2])),
        evaluation_id: p[3],
        execution_json: JSON.parse(p[4]),
        verdict: null,
        disposition: null,
        result_json: null,
        result_digest: null,
        judge_observations: null,
        judge_result_json: null,
        result_serialized: null,
        evaluated_at: null
      };
      judgments.set(row.evaluation_id, row);
      writes.push('child');
      return answer([structuredClone(row)]);
    }
    if (sql.startsWith('INSERT INTO secureshop_auth.assessment_retries')) {
      links.set(p[2], p[3]);
      writes.push('link');
      return answer([]);
    }
    if (sql.startsWith('INSERT INTO secureshop_auth.assessment_retry_invocations')) {
      invocations.push({
        parent_id: p[2],
        attempt: p[3],
        run_id: p[4],
        execution_json: JSON.parse(p[5])
      });
      writes.push('invocation');
      return answer([]);
    }
    if (sql.startsWith('UPDATE secureshop_auth.assessment_judgments')) {
      const row = judgments.get(p[2]);
      Object.assign(row, {
        verdict: p[3],
        disposition: p[4],
        result_json: JSON.parse(p[5]),
        result_digest: p[6],
        judge_observations: JSON.parse(p[7]),
        judge_result_json: p[8],
        result_serialized: p[9],
        evaluated_at: new Date()
      });
      writes.push('verdict');
      return answer([structuredClone(row)]);
    }
    throw Error(`Unexpected controlled recovery query: ${sql.slice(0, 90)}`);
  };
  const pool = {
    query,
    connect: async () => ({
      query,
      release() {}
    })
  };
  const fence = {
    assertRemoteAdmission: async () => {},
    withCrossStoreEffect: fn => fn()
  };
  const subjects = createSecureShopAssessmentSubjects({
    identityPool: pool,
    launches: {
      assertCurrent: async () => {}
    },
    personaAuthority: {
      capture: () => fence
    }
  });
  async function store(overrides = {}) {
    const execution = {
      runId: randomUUID(),
      ownerKey: JSON.stringify(['shop-test', 'owned-conversation']),
      durableGeneration: '0',
      check: async () => {},
      ...overrides
    };
    const subject = await subjects.capture(input, execution);
    return {
      ...createSecureShopAssessmentStore({
        pool,
        subject
      }),
      execution,
      binding: subjectState(subject).binding
    };
  }
  const original = await store();
  const rubric = {
    family: 'SecureShop',
    scenario: 'agent_loop',
    objectiveId: 'ss_loop_observation',
    version: 'test-v1',
    mode: 'vuln',
    requiredFacts: ['effect'],
    criteria: [{
      id: 'effect',
      description: 'Observed owned effect',
      allowedSources: ['server_observation']
    }]
  };
  const prepared = prepareJudgeInput({
    rubric,
    evidence: [{
      id: 'effect',
      source: 'server_observation',
      content: 'Immutable prior effect'
    }],
    facts: {
      effect: true
    }
  });
  assert.equal(prepared.evidenceError, undefined);
  const parent = {
    tenant_id: tenantId,
    principal_id: principalId,
    evaluation_id: randomUUID(),
    shop_user_id: actor,
    execution_json: original.binding,
    objective_id: rubric.objectiveId,
    family: rubric.family,
    scenario: rubric.scenario,
    rubric_version: rubric.version,
    evidence_digest: prepared.evidenceDigest,
    run_id: original.execution.runId,
    generation: 0,
    mode: 'vuln',
    mode_stamp: createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1', tenantId, principalId, 0, '1', 'vuln'])).digest('hex'),
    packet: prepared.packet,
    judge_version: JUDGE_VERSION,
    owner_key: original.binding.ownerKey,
    owner_generation: '0',
    verdict: 'unavailable',
    disposition: 'not_pass',
    result_json: {
      errorCode: 'JUDGE_TIMEOUT'
    },
    result_digest: 'a'.repeat(64),
    created_at: new Date(),
    evaluated_at: new Date()
  };
  judgments.set(parent.evaluation_id, parent);
  const begin = s => s.receipts.beginRetry({
    userId: scope.platformOwnerId,
    evaluationId: parent.evaluation_id,
    judgeVersion: JUDGE_VERSION,
    ownerGeneration: s.execution.durableGeneration
  });
  return {
    store,
    begin,
    parent,
    current,
    catalog,
    judgments,
    links,
    invocations,
    writes,
    scope,
    input,
    pool,
    tenantId,
    principalId,
    actor,
    fence
  };
}
async function recoveryContext(f, {
  role = 'customer'
} = {}) {
  const retryRuns = [];
  const {
    createSecureShopStandaloneAuthService
  } = require('../server/services/secureshopStandaloneAuth');
  const row = {
    principalId: f.principalId,
    ownerId: 90,
    sessionId: 91,
    shopUserId: f.actor,
    username: 'customer',
    email: 'customer@shop.test',
    role,
    credentialVersion: '1',
    authorityVersion: '1',
    expiresAt: new Date(Date.now() + 60000).toISOString()
  };
  const repository = Object.fromEntries(['registerWithSession', 'findCredential', 'recordFailedLogin', 'createSession', 'rotateSession', 'revokeSession', 'readCredentialForSession', 'changePassword', 'revokeAll'].map(name => [name, async () => {}]));
  repository.readCurrentSession = async () => row;
  repository.readOrCreateDefaultExecutionSession = async () => ({
    ...row,
    principalOwnerId: 90,
    ownerId: f.scope.platformOwnerId,
    authSessionId: 91,
    sessionId: f.scope.platformSessionId,
    tenantId: f.tenantId,
    membershipVersion: '1'
  });
  const authService = createSecureShopStandaloneAuthService({
    repository
  });
  return {
    base: await authService.authenticate('a'.repeat(43)),
    deps: {
      identityPool: f.pool,
      authService,
      bootstrap: async () => ({
        bearer: 'private',
        persona: {
          token: 'private'
        }
      }),
      launches: {
        resolveCapability: async () => f.scope,
        assertCurrent: async () => {}
      },
      personaAuth: {
        authenticateBoundToken: async () => ({
          user: {
            id: f.actor,
            role
          },
          sessionId: f.input.sessionId,
          authorityVersion: '1'
        })
      },
      personaAuthority: {
        capture: () => f.fence
      },
      coordinatorFactory: () => ({
        run: async (_owner, _options, work) => {
          const runId = randomUUID();
          retryRuns.push(runId);
          return work({
            runId,
            ownerKey: f.parent.owner_key,
            durableGeneration: '0',
            check: async () => {}
          });
        }
      })
    },
    retryRuns
  };
}
for(const variant of ['V06','V07']) test(`${variant} retained upload retry binds exact original packet and customer before Judge`, async t => {
  const E=require('../server/services/secureshopV07UploadEvidence');
  const evidence = variant==='V07'?{UPLOAD_RUBRIC:E.RUBRIC,UPLOAD_OBJECTIVE:E.OBJECTIVE}:require('../server/services/secureshopV06UploadEvidence');
  const createRecovery = require('../server/services/secureshopAssessmentRecovery').createSecureShopAssessmentRecovery;
  async function setup(role = 'customer') {
    const f = await fixture({
      role
    });
    // This controlled packet tests recovery routing; source validity is covered by the V06 evidence tests.
    const rubric = evidence.UPLOAD_RUBRIC;
    const packet = prepareJudgeInput({
      rubric,
      evidence: variant==='V07'?[{id:'preview_decision',source:'server_observation',content:'The original customer model selected the saved preview tool.'},{id:'preview_execution',source:'server_observation',content:'The unchanged file fully decoded and executed, creating the observed isolated canary.'}]:[{
        id: 'upload_request',
        source: 'server_observation',
        content: 'Original customer request'
      }, {
        id: 'upload_effect_excerpt',
        source: 'server_observation',
        content: 'Completed owned protected read'
      }, {
        id: 'upload_serve_excerpt',
        source: 'server_observation',
        content: 'Finished unsafe-inline delivery of identical bytes'
      }],
      facts: Object.fromEntries(rubric.requiredFacts.map(id => [id, true]))
    });
    assert.equal(packet.evidenceError, undefined);
    Object.assign(f.parent, {
      objective_id: evidence.UPLOAD_OBJECTIVE,
      family: evidence.UPLOAD_RUBRIC.family,
      scenario: evidence.UPLOAD_RUBRIC.scenario,
      rubric_version: evidence.UPLOAD_RUBRIC.version,
      packet: packet.packet,
      evidence_digest: packet.evidenceDigest,
      qualification: 'native-model',
      live_mode: 'vuln',
      live_generation: 0,
      live_revision: '1',
      live_owner_generation: '0',
      catalog_active: true,
      enabled: true,
      is_child: false,
      retry_count: 0
    });
    const {
      base,
      deps,
      retryRuns
    } = await recoveryContext(f, {
      role
    });
    let stale = false;
    const calls = {
      reads: 0,
      checks: 0,
      judge: 0
    };
    const service = createRecovery({
      ...deps,
      [variant==='V07'?'polyglotUploadAssessment':'uploadAssessment']: {
        async assertRetainedPacket(input) {
          calls.reads++;
          assert.deepEqual(input.packet, JSON.parse(packet.packet));
          assert.deepEqual(input.scope, f.scope);
          assert.deepEqual(input.persona, {
            id: f.actor,
            role: 'customer'
          });
          assert.deepEqual(input.personaSession, {
            sessionId: f.input.sessionId,
            authorityVersion: '1'
          });
          return {
            async assertCurrent() {
              calls.checks++;
              if (stale) throw Object.assign(Error('Original upload retired'), {
                code: 'SECURESHOP_FEATURE_MODE_STALE'
              });
            }
          };
        }
      },
      judge: async input => {
        calls.judge++;
        assert.equal(prepareJudgeInput(input).packet, packet.packet);
        assert.equal(input.execution.runId, f.parent.run_id);
        return {
          family: evidence.UPLOAD_RUBRIC.family,
          scenario: evidence.UPLOAD_RUBRIC.scenario,
          objectiveId: evidence.UPLOAD_OBJECTIVE,
          rubricVersion: evidence.UPLOAD_RUBRIC.version,
          mode: 'vuln',
          evidenceDigest: packet.evidenceDigest,
          runId: input.execution.runId,
          judgeVersion: JUDGE_VERSION,
          verdict: 'unavailable',
          errorCode: 'JUDGE_TIMEOUT',
          criteria: [],
          provider: null,
          model: null,
          explanation: 'Controlled V06 retry; no genuine credit'
        };
      }
    });
    return {
      f,
      base,
      service,
      calls,
      packet,
      retryRuns,
      retire: () => {
        stale = true;
      }
    };
  }
  await t.test('original receipt retries Judge with no new upload or serve or actor effect', async () => {
    const {
      f,
      base,
      service,
      calls,
      packet,
      retryRuns
    } = await setup();
    assert.equal((await service.list(base)).judgments[0].canRetry, true);
    const result = await service.retry(base, {
      evaluationId: f.parent.evaluation_id
    });
    assert.equal(result.verdict, 'unavailable');
    assert.equal(result.completed, false);
    assert.equal(calls.judge, 1);
    assert.ok(calls.reads >= 2);
    assert.ok(calls.checks >= 3);
    const child = f.judgments.get(result.childEvaluationId);
    assert.equal(child.packet, packet.packet);
    assert.equal(child.run_id, f.parent.run_id);
    assert.equal(f.links.size, 1);
    assert.equal(f.invocations.length, 1);
    assert.equal(retryRuns.length, 1);
    assert.notEqual(retryRuns[0], f.parent.run_id);
    assert.equal(f.invocations[0].run_id, retryRuns[0]);
    assert.equal(child.owner_key, f.parent.owner_key);
  });
  await t.test('retired original scope rejects before retry or Judge', async () => {
    const {
      f,
      base,
      service,
      calls,
      retire
    } = await setup();
    retire();
    assert.equal((await service.list(base)).judgments[0].canRetry, false);
    await assert.rejects(service.retry(base, {
      evaluationId: f.parent.evaluation_id
    }), {
      code: 'SECURESHOP_FEATURE_MODE_STALE'
    });
    assert.equal(calls.judge, 0);
    assert.equal(f.links.size, 0);
    assert.equal(f.invocations.length, 0);
    assert.deepEqual(f.writes, []);
  });
  await t.test('pending catalog blocks retry before canonical writes', async () => {
    const {
      f,
      base,
      service,
      calls
    } = await setup();
    f.parent.qualification = 'pending';
    f.catalog.qualification = 'pending';
    assert.equal((await service.list(base)).judgments[0].canRetry, false);
    await assert.rejects(service.retry(base, {
      evaluationId: f.parent.evaluation_id
    }));
    assert.equal(calls.judge, 0);
    assert.equal(f.links.size, 0);
    assert.deepEqual(f.writes, []);
  });
  for (const [name, mutate, role] of [['malformed packet', f => {
    f.parent.packet = '{';
  }], ['modified packet', f => {
    const p = JSON.parse(f.parent.packet);
    p.evidence.at(-1).content += ' changed';
    f.parent.packet = JSON.stringify(p);
  }], ['outer digest', f => {
    f.parent.evidence_digest = 'b'.repeat(64);
  }], ['outer rubric', f => {
    f.parent.rubric_version = 'unknown-v01-version';
  }], ['outer scenario', f => {
    f.parent.scenario = 'different-scenario';
  }], ['non-customer', () => {}, 'merchant']]) await t.test(name, async () => {
    const {
      f,
      base,
      service,
      calls
    } = await setup(role);
    mutate(f);
    assert.equal((await service.list(base)).judgments[0].canRetry, false);
    await assert.rejects(service.retry(base, {
      evaluationId: f.parent.evaluation_id
    }), {
      code: 'SECURESHOP_FEATURE_MODE_STALE'
    });
    assert.deepEqual(calls, {
      reads: 0,
      checks: 0,
      judge: 0
    });
    assert.equal(f.links.size, 0);
    assert.equal(f.invocations.length, 0);
    assert.deepEqual(f.writes, []);
  });
});
