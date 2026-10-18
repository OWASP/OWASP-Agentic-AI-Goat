'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
const {
  createPostgresWorkshopResetAdapters,
  createPostgresWorkshopResetService,
  listPostgresStudentIds,
  withPostgresStudentResetAdmission,
  createLazyStudentResetAdmission,
} = require('../server/services/postgresWorkshopResetService');
const { RagVectorStore } = require('../server/services/ragVectorStore');

test('production reset adapter registry covers the complete workshop catalog', () => {
  const adapters = createPostgresWorkshopResetAdapters(() => {
    throw new Error('adapter modules must remain lazy during reset preflight');
  });
  const service = createPostgresWorkshopResetService({
    adapters,
    progress: { resetWorkshopProgress: async () => {} },
    listUserIds: async () => [],
  });

  for (const workshopKey of Object.keys(WORKSHOP_OBJECTIVES)) {
    assert.doesNotThrow(() => service.assertSupported(workshopKey), workshopKey);
  }
});

test('DPI and IPI adapters use their mounted coordinators before canonical reset', async () => {
  const events = [];
  const load = (request) => {
    if (request === '../routes/promptInjectionWorkshop') return {
      resetOwner: async (owner, work) => { events.push(['dpi-lease', owner]); await work(); },
    };
    if (request === '../routes/ragInjection') return {
      resetOwner: async (owner, work) => { events.push(['rag-lease', owner]); await work(); },
      clearOwnerState: async (owner) => { events.push(['rag-clear', owner]); },
    };
    if (request === '../routes/emailAgent') return {
      resetOwner: async (owner, work) => { events.push(['email-lease', owner]); await work(); },
    };
    if (request === './emailArtifactStore') return {
      assertReady: async () => { events.push(['email-ready']); },
      retireOwner: async scope => { events.push(['email-retire', scope]); return 2; },
    };
    throw new Error(`Unexpected load: ${request}`);
  };
  const service = createPostgresWorkshopResetService({
    adapters: createPostgresWorkshopResetAdapters(load),
    progress: {
      resetWorkshopProgress: async (owner, workshopKey) => events.push(['canonical', owner, workshopKey]),
    },
  });

  await service.resetStudent({ userId: 7, workshopKey: 'direct_prompt_injection' });
  await service.resetStudent({ userId: 7, workshopKey: 'indirect_prompt_injection' });

  assert.deepEqual(events, [
    ['dpi-lease', '7'],
    ['canonical', 7, 'direct_prompt_injection'],
    ['email-ready'],
    ['rag-lease', '7'],
    ['rag-clear', '7'],
    ['email-lease', '7'],
    ['email-retire', { ownerId:7, ownerKey:JSON.stringify(['IndirectEmail', '7']) }],
    ['canonical', 7, 'indirect_prompt_injection'],
  ]);
});

test('administrative XSS reset uses the durable parent composition with the admitted lifecycle guard', async () => {
  const events = [];
  const lifecycle = Object.freeze({ ownerId:7, check:async()=>{} });
  const operationId = '12d1738e-48a6-4f09-8fa6-24c34069c50a';
  const composition = {
    async assertReady() { events.push('parent-ready'); },
    async reset(input) {
      events.push(['parent-reset', input]);
      return { operationId:input.operationId, ownerId:input.ownerId, status:'completed' };
    },
  };
  const identityPool = { name:'identity-pool' };
  const load = request => {
    if (request === './xssParentResetComposition') {
      return { getXssParentResetComposition:async()=>composition };
    }
    if (request === '../routes/xssWorkshop') {
      return { resetOwner:async(owner, work) => { events.push(['legacy-lease', owner]); return work(); } };
    }
    if (request === './postgresIdentityAdapter') {
      return { getPostgresIdentityAdapter:()=>({pool:identityPool}) };
    }
    if (request === '../database/postgres/xssParentResetJournalRepository') {
      return { createXssParentResetJournalRepository:pool => {
        assert.equal(pool, identityPool);
        return { assertMutationAdmitted:async owner => events.push(['student-admitted',owner]) };
      } };
    }
    if (request === './xssMutationAdmission') {
      return { configuredXssProfileResetPendingCheck:async(owner, guard) => {
        assert.equal(guard, lifecycle);
        events.push(['profile-reset-admitted', owner]);
      } };
    }
    if (request === '../database/postgres/xssWorkshopDb') {
      return {
        resetProgress:async owner => events.push(['legacy-progress', owner]),
        resetProfile:async owner => events.push(['legacy-profile', owner]),
      };
    }
    throw new Error(`Unexpected load: ${request}`);
  };
  const service = createPostgresWorkshopResetService({
    adapters:createPostgresWorkshopResetAdapters(load),
    progress:{resetWorkshopProgress:async(owner,key)=>events.push(['canonical',owner,key])},
    withStudentResetAdmission:async(owner, work) => {
      assert.equal(owner, 7);
      events.push('admit');
      return work(lifecycle);
    },
  });

  await service.resetStudent({userId:7, workshopKey:'xss_workshop'});
  assert.deepEqual(events.splice(0), [
    'admit', ['student-admitted',7], ['profile-reset-admitted',7],
    ['legacy-lease','7'], ['legacy-progress','7'], ['legacy-profile','7'],
    ['canonical',7,'xss_workshop'],
  ]);

  assert.deepEqual(await service.resetAdministrativeStudent({
    userId:7, workshopKey:'xss_workshop', operationId,
  }), {operationId, ownerId:7, status:'completed'});
  assert.deepEqual(events, [
    'parent-ready', 'admit',
    ['parent-reset', {ownerId:7, operationId, lifecycle}],
  ]);
});

test('pending XSS parent reset rejects student reset before coordinator, store, or canonical mutation', async () => {
  const events=[];
  const pending=Object.assign(new Error('XSS parent reset is active'), {
    code:'XSS_PARENT_RESET_UNAVAILABLE',
  });
  const load=request=>{
    if(request==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool:{}})};
    if(request==='../database/postgres/xssParentResetJournalRepository')return{
      createXssParentResetJournalRepository:()=>({assertMutationAdmitted:async()=>{events.push('parent-check');throw pending;}}),
    };
    throw new Error(`Mutation must not reach ${request}`);
  };
  const service=createPostgresWorkshopResetService({
    adapters:createPostgresWorkshopResetAdapters(load),
    progress:{resetWorkshopProgress:async()=>events.push('canonical')},
    withStudentResetAdmission:async(owner,work)=>{
      events.push(['admit',owner]);
      return work({ownerId:owner,check:async()=>events.push('lifecycle-check')});
    },
  });

  await assert.rejects(service.resetStudent({userId:7,workshopKey:'xss_workshop'}),error=>{
    assert.equal(error,pending);
    assert.equal(error.code,'XSS_PARENT_RESET_UNAVAILABLE');
    assert.equal(error.statusCode,503);
    return true;
  });
  assert.deepEqual(events,[['admit',7],'lifecycle-check','parent-check']);
});

test('pending XSS profile reset rejects ordinary reset before coordinator, store, or canonical mutation', async () => {
  const events=[];
  const pending=Object.assign(new Error('XSS profile reset is active'), {
    code:'XSS_PROFILE_RESET_PENDING', statusCode:503,
  });
  const lifecycle={ownerId:7,check:async()=>events.push('lifecycle-check')};
  const load=request=>{
    if(request==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool:{}})};
    if(request==='../database/postgres/xssParentResetJournalRepository')return{
      createXssParentResetJournalRepository:()=>({assertMutationAdmitted:async owner=>events.push(['parent-check',owner])}),
    };
    if(request==='./xssMutationAdmission')return{
      configuredXssProfileResetPendingCheck:async(owner,guard)=>{
        assert.equal(owner,7);
        assert.equal(guard,lifecycle);
        events.push(['profile-reset-check',owner]);
        throw pending;
      },
    };
    throw new Error(`Mutation must not reach ${request}`);
  };
  const service=createPostgresWorkshopResetService({
    adapters:createPostgresWorkshopResetAdapters(load),
    progress:{resetWorkshopProgress:async()=>events.push('canonical')},
    withStudentResetAdmission:async(owner,work)=>{
      events.push(['admit',owner]);
      return work(lifecycle);
    },
  });

  await assert.rejects(service.resetStudent({userId:7,workshopKey:'xss_workshop'}),error=>{
    assert.equal(error,pending);
    assert.equal(error.code,'XSS_PROFILE_RESET_PENDING');
    assert.equal(error.statusCode,503);
    return true;
  });
  assert.deepEqual(events,[['admit',7],'lifecycle-check',['parent-check',7],['profile-reset-check',7]]);
});

test('administrative fallback and bulk reset use one admission without selecting the specialized student path', async () => {
  const events=[];
  const adapter={
    reset:async(owner,work)=>{events.push(['fallback-reset',owner]);return work();},
    clear:async owner=>events.push(['fallback-clear',owner]),
  };
  const service=createPostgresWorkshopResetService({
    adapters:{sql_injection_workshop:adapter},
    progress:{resetWorkshopProgress:async(owner,key)=>events.push(['canonical',owner,key])},
    listUserIds:async()=>[7,8],
    withStudentResetAdmission:async(owner,work)=>{events.push(['admit',owner]);return work({ownerId:owner});},
  });

  await service.resetAdministrativeStudent({userId:7,workshopKey:'sql_injection_workshop'});
  assert.deepEqual(events.splice(0), [
    ['admit',7], ['fallback-reset','7'], ['fallback-clear','7'],
    ['canonical',7,'sql_injection_workshop'],
  ]);
  await service.resetWorkshop({workshopKey:'sql_injection_workshop'});
  assert.deepEqual(events, [
    ['admit',7], ['fallback-reset','7'], ['fallback-clear','7'], ['canonical',7,'sql_injection_workshop'],
    ['admit',8], ['fallback-reset','8'], ['fallback-clear','8'], ['canonical',8,'sql_injection_workshop'],
  ]);
});

test('IPI durable reset failure never clears canonical progress or falls back to a generic reset', async () => {
  const events = [];
  const failure = Object.assign(new Error('artifact retirement failed'), { code:'EMAIL_ARTIFACT_STORAGE_NOT_READY' });
  const load = request => {
    if (request === '../routes/ragInjection') return {
      resetOwner: async (owner, work) => { events.push(['rag-lease', owner]); return work(); },
      clearOwnerState: async owner => events.push(['rag-clear', owner]),
    };
    if (request === '../routes/emailAgent') return {
      resetOwner: async (owner, work) => { events.push(['email-lease', owner]); return work(); },
    };
    if (request === './emailArtifactStore') return {
      assertReady: async () => events.push(['email-ready']),
      retireOwner: async () => { events.push(['email-retire']); throw failure; },
    };
    throw new Error(`Unexpected load: ${request}`);
  };
  const service = createPostgresWorkshopResetService({
    adapters:createPostgresWorkshopResetAdapters(load),
    progress:{ resetWorkshopProgress:async () => events.push(['canonical']) },
  });
  await assert.rejects(service.resetStudent({ userId:7,
    workshopKey:'indirect_prompt_injection' }), error => error === failure);
  assert.deepEqual(events, [
    ['email-ready'], ['rag-lease', '7'], ['rag-clear', '7'],
    ['email-lease', '7'], ['email-retire'],
  ]);
});

test('RAG owner reset clears every session without touching sibling owners', () => {
  const store = new RagVectorStore();
  store.sessions.set('1::old', [{ text: 'old' }]);
  store.sessions.set('1::current', [{ text: 'current' }]);
  store.sessions.set('11::sibling', [{ text: 'sibling' }]);
  store.sessionMetadata.set('1::old', { filename: 'old.txt' });
  store.sessionMetadata.set('1::current', { filename: 'current.txt' });
  store.sessionMetadata.set('11::sibling', { filename: 'sibling.txt' });
  store.lastSessionByUser.set('1', { sessionId: 'current' });
  store.lastSessionByUser.set('11', { sessionId: 'sibling' });

  assert.equal(store.clearUserSessions('1'), 2);
  assert.equal(store.getActiveSessionsCount('1'), 0);
  assert.equal(store.getActiveSessionsCount('11'), 1);
  assert.equal(store.lastSessionByUser.has('1'), false);
  assert.equal(store.lastSessionByUser.has('11'), true);
  assert.equal(store.sessionMetadata.has('1::old'), false);
  assert.equal(store.sessionMetadata.has('11::sibling'), true);
});

test('admin MCP reset waits for owned retirement before mutating store or canonical progress', async () => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  const calls = [];
  const adapters = createPostgresWorkshopResetAdapters(request => {
    if (request === '../routes/mcpWorkshop') return {
      resetOwner: async (owner, work) => { calls.push(['retire-start', owner]); await pending; calls.push(['retired', owner]); return work({ check: async () => {} }); },
    };
    if (request === '../database/postgres/mcpWorkshopDb') return { resetUser: async owner => calls.push(['store', owner]) };
    if (request.includes('sandbox')) throw Error('legacy MCP sandbox cleanup must not be loaded');
    throw Error(`Unexpected load ${request}`);
  });
  const service = createPostgresWorkshopResetService({ adapters,
    progress: { resetWorkshopProgress: async (_owner, key) => calls.push(['canonical', key]) } });
  const reset = service.resetStudent({ userId: 7, workshopKey: 'mcp_workshop' });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, [['retire-start', '7']]);
  finish({ ok: true });
  await reset;
  assert.deepEqual(calls, [['retire-start', '7'], ['retired', '7'], ['store', '7'],
    ['canonical', 'mcp_workshop']]);
});

test('admin MCP reset rejection prevents store and canonical mutation', async () => {
  const failure = Object.assign(new Error('owned retirement unavailable'), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE', statusCode: 503 });
  const calls = [];
  const adapters = createPostgresWorkshopResetAdapters(request => {
    if (request === '../routes/mcpWorkshop') return { resetOwner: async () => { calls.push('retire'); throw failure; } };
    if (request === '../database/postgres/mcpWorkshopDb') return { resetUser: async () => calls.push('store') };
    if (request.includes('sandbox')) throw Error('legacy MCP sandbox cleanup must not be loaded');
    throw Error(`Unexpected load: ${request}`);
  });
  const service = createPostgresWorkshopResetService({ adapters,
    progress: { resetWorkshopProgress: async () => calls.push('canonical') } });
  await assert.rejects(service.resetStudent({ userId: 7, workshopKey: 'mcp_workshop' }), error => error === failure);
  assert.deepEqual(calls, ['retire']);
});

test('admin MCP reset rejects a missing owner lease before any progress mutation', async () => {
  const calls = [];
  const adapters = createPostgresWorkshopResetAdapters(request => {
    if (request === '../routes/mcpWorkshop') return { resetOwner: async (_owner, work) => work() };
    if (request === '../database/postgres/mcpWorkshopDb') return { resetUser: async () => calls.push('store') };
    throw Error(`Unexpected load: ${request}`);
  });
  const service = createPostgresWorkshopResetService({ adapters,
    progress: { resetWorkshopProgress: async () => calls.push('canonical') } });
  await assert.rejects(service.resetStudent({ userId: 7, workshopKey: 'mcp_workshop' }),
    { code: 'RESET_AUTHORITY_UNAVAILABLE', statusCode: 503 });
  assert.deepEqual(calls, []);
});

test('admin MCP reset rechecks its owner lease between store and canonical changes', async () => {
  for (const loseAt of ['before-store', 'after-store', 'after-canonical', 'never']) {
    const calls = [];
    let current = loseAt !== 'before-store';
    const failure = Object.assign(Error('reset lease lost'), { name: 'AbortError' });
    const adapters = createPostgresWorkshopResetAdapters(request => {
      if (request === '../routes/mcpWorkshop') return { resetOwner: async (_owner, work) => work({
        check: async () => { if (!current) throw failure; },
      }) };
      if (request === '../database/postgres/mcpWorkshopDb') return { resetUser: async () => {
        calls.push('store'); if (loseAt === 'after-store') current = false;
      } };
      throw Error(`Unexpected load: ${request}`);
    });
    const service = createPostgresWorkshopResetService({ adapters, progress: {
      resetWorkshopProgress: async () => {
        calls.push('canonical'); if (loseAt === 'after-canonical') current = false;
      },
    } });
    const reset = service.resetStudent({ userId: 7, workshopKey: 'mcp_workshop' });
    if (loseAt === 'never') await reset;
    else await assert.rejects(reset, error => error.code === 'RESET_PARTIAL_FAILURE' && error.cause === failure);
    assert.deepEqual(calls, loseAt === 'before-store' ? []
      : loseAt === 'after-store' ? ['store'] : ['store', 'canonical']);
  }
});

test('SecureShop uses specialized owner reset and never invokes generic unscoped progress clear', async () => {
  const events=[];
  const specialized={assertReady:async()=>events.push('ready'),resetOwner:async owner=>{
    events.push(['owner-reset',owner]);return{completed:true};}};
  const adapters=createPostgresWorkshopResetAdapters(request=>{
    if(request==='./secureshopOwnerResetService')return{getSecureShopOwnerResetService:()=>specialized};
    throw Error(`Unexpected load ${request}`);
  });
  const service=createPostgresWorkshopResetService({adapters,progress:{resetWorkshopProgress:async()=>{
    throw Error('generic progress clear is unsafe');}}});
  assert.deepEqual(await service.resetStudent({userId:7,workshopKey:'secureshop_agent_security'}),{completed:true});
  assert.deepEqual(events,['ready',['owner-reset',7]]);
});

test('FinFlow admin reset requires and delegates once to the durable aggregate without generic clears', async () => {
  const events = [];
  const operationId = '12d1738e-48a6-4f09-8fa6-24c34069c50a';
  const aggregate = {
    reset: async (owner, options) => {
      events.push(['aggregate', owner, options]);
      return { operationId, ownerId: owner, status: 'completed' };
    },
  };
  const adapters = createPostgresWorkshopResetAdapters(request => {
    events.push(['load', request]);
    if (request === './sensitiveInfoResetComposition') return {
      getSensitiveInfoResetComposition: async () => ({ reset: aggregate }),
    };
    throw new Error(`Generic FinFlow reset dependency must not load: ${request}`);
  });
  const service = createPostgresWorkshopResetService({
    adapters,
    progress: { resetWorkshopProgress: async () => { throw new Error('canonical clear duplicated'); } },
  });

  assert.deepEqual(await service.resetStudent({ userId: 7,
    workshopKey: 'sensitive_info_disclosure', operationId }), {
    operationId, ownerId: 7, status: 'completed',
  });
  assert.deepEqual(events, [
    ['load', './sensitiveInfoResetComposition'],
    ['load', './sensitiveInfoResetComposition'],
    ['aggregate', 7, { operationId }],
  ]);
});

test('FinFlow aggregate readiness and reset failures fail closed without generic fallback', async () => {
  let genericClears = 0;
  const progress = { resetWorkshopProgress: async () => { genericClears += 1; } };
  const unavailable = createPostgresWorkshopResetService({
    adapters: createPostgresWorkshopResetAdapters(request => {
      if (request === './sensitiveInfoResetComposition') return {
        getSensitiveInfoResetComposition: async () => null,
      };
      throw new Error(`Unexpected generic fallback: ${request}`);
    }),
    progress,
  });
  await assert.rejects(unavailable.resetStudent({ userId: 7,
    workshopKey: 'sensitive_info_disclosure' }), {
    code: 'RESET_STORAGE_NOT_READY', statusCode: 503,
  });

  const resetFailure = Object.assign(new Error('retirement failed'), { code: 'RESET_RECEIPT_MISMATCH' });
  const failing = createPostgresWorkshopResetService({
    adapters: createPostgresWorkshopResetAdapters(request => {
      if (request === './sensitiveInfoResetComposition') return {
        getSensitiveInfoResetComposition: async () => ({ reset: {
          reset: async () => { throw resetFailure; },
        } }),
      };
      throw new Error(`Unexpected generic fallback: ${request}`);
    }),
    progress,
  });
  await assert.rejects(failing.resetStudent({ userId: 7,
    workshopKey: 'sensitive_info_disclosure' }), error => error === resetFailure);
  assert.equal(genericClears, 0);
});

test('production bulk inventory selects canonical students without an admitted deletion', async () => {
  let query;
  const ids = await listPostgresStudentIds({
    async query(sql) {
      query = sql.replace(/\s+/g, ' ').trim();
      return { rows: [{ id: 4 }, { id: '9' }] };
    },
  });
  assert.deepEqual(ids, [4, 9]);
  assert.match(query, /FROM identity\.users users WHERE users\.role='student' AND users\.admin_level=0 AND NOT EXISTS/);
  assert.match(query, /identity\.student_deletion_jobs deletion WHERE deletion\.subject_user_id=users\.id/);
  assert.doesNotMatch(query, /role='admin'|role='super_admin'/);
});

test('student reset admission holds the lifecycle advisory lock across nested reset work', async () => {
  const events = [];
  const client = {
    async query(sql, values) {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      events.push(['query', normalized, values]);
      if (normalized.includes('pg_advisory_unlock')) return { rows: [{ unlocked: true }], rowCount: 1 };
      if (normalized.includes('FROM identity.users')) return { rows: [{ id: 7 }], rowCount: 1 };
      if (normalized.includes('FROM identity.student_deletion_jobs')) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 0 };
    },
    release() { events.push(['release']); },
  };
  const result = await withPostgresStudentResetAdmission({
    async connect() { events.push(['connect']); return client; },
  }, 7, async () => { events.push(['reset']); return 'done'; });
  assert.equal(result, 'done');
  assert.deepEqual(events.map(event => event[0]), [
    'connect', 'query', 'query', 'query', 'reset', 'query', 'release',
  ]);
  assert.match(events[1][1], /pg_advisory_lock/);
  assert.match(events[2][1], /identity\.users/);
  assert.doesNotMatch(events[2][1], /FOR UPDATE/);
  assert.match(events[3][1], /identity\.student_deletion_jobs/);
  assert.match(events[5][1], /pg_advisory_unlock/);
});

test('production lifecycle pool is reserved lazily once and a failed reservation remains retryable', async () => {
  const pool = { purpose: 'lease' };
  let creations = 0;
  const admissions = [];
  const admission = createLazyStudentResetAdmission({
    createLifecyclePool() {
      creations += 1;
      if (creations === 1) throw Object.assign(new Error('startup budget still occupied'), {
        code: 'POOL_BUDGET_EXHAUSTED',
      });
      return pool;
    },
    async admit(selectedPool, studentId, work) {
      admissions.push([selectedPool, studentId]);
      return work();
    },
  });
  assert.equal(creations, 0, 'route/service construction must not reserve lease capacity');
  assert.throws(() => admission(7, async () => 'unreachable'), { code: 'POOL_BUDGET_EXHAUSTED' });
  assert.equal(creations, 1);assert.deepEqual(admissions, []);
  assert.equal(await admission(7, async () => 'first'), 'first');
  assert.equal(await admission(8, async () => 'second'), 'second');
  assert.equal(creations, 2, 'successful lease pool is reused');
  assert.deepEqual(admissions, [[pool, 7], [pool, 8]]);
});

test('student reset admission rejects a deletion job before reset mutation', async () => {
  const events = [];
  const client = {
    async query(sql) {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      events.push(normalized);
      if (normalized.includes('pg_advisory_unlock')) return { rows: [{ unlocked: true }], rowCount: 1 };
      if (normalized.includes('FROM identity.users')) return { rows: [{ id: 7 }], rowCount: 1 };
      if (normalized.includes('FROM identity.student_deletion_jobs')) return { rows: [{ '?column?': 1 }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    release() { events.push('release'); },
  };
  let mutated = false;
  await assert.rejects(withPostgresStudentResetAdmission({ connect: async () => client }, 7,
    async () => { mutated = true; }), { code:'STUDENT_DELETION_ADMITTED', statusCode:409 });
  assert.equal(mutated, false);
  assert.ok(events.some(event => typeof event === 'string' && event.includes('pg_advisory_unlock')));
  assert.equal(events.at(-1), 'release');
});

test('student reset admission forwards the exact active lifecycle guard and retires it after work', async () => {
  let guard;
  const client = {
    async query(sql) {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      if (normalized.includes('pg_advisory_unlock')) {
        return { rows: [{ unlocked: true }], rowCount: 1 };
      }
      if (normalized.includes('FROM pg_catalog.pg_locks')) {
        return { rows: [{ held: true }], rowCount: 1 };
      }
      if (normalized.includes('FROM identity.users')) {
        return { rows: [{ id: 7 }], rowCount: 1 };
      }
      if (normalized.includes('FROM identity.student_deletion_jobs')) {
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    },
    release() {},
  };

  const result = await withPostgresStudentResetAdmission({ connect: async () => client }, 7,
    async lifecycleGuard => {
      guard = lifecycleGuard;
      assert.equal(lifecycleGuard.ownerId, 7);
      await lifecycleGuard.check();
      return 'done';
    });

  assert.equal(result, 'done');
  assert.equal(guard.ownerId, 7);
  await assert.rejects(guard.check(), { code: 'STUDENT_LIFECYCLE_LOCK_LOST' });
});

test('bounded lifecycle clients queue concurrent resets without reserving the control pool', async () => {
  const waiters = [];
  let leased = 0;
  const pool = {
    connect() {
      if (leased < 4) return Promise.resolve(client());
      return new Promise(resolve => waiters.push(resolve));
    },
  };
  function client() {
    leased += 1;
    return {
      async query(sql) {
        if (sql.includes('pg_advisory_unlock')) return { rows:[{ unlocked:true }], rowCount:1 };
        if (sql.includes('FROM identity.users')) return { rows:[{ id:7 }], rowCount:1 };
        return { rows:[], rowCount:0 };
      },
      release() {
        leased -= 1;
        const next = waiters.shift();
        if (next) next(client());
      },
    };
  }
  let active = 0;
  let maximum = 0;
  const results = await Promise.all(Array.from({ length:8 }, (_, index) =>
    withPostgresStudentResetAdmission(pool, index + 1, async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      await new Promise(resolve => setImmediate(resolve));
      active -= 1;
      return index;
    })));
  assert.deepEqual(results, [0,1,2,3,4,5,6,7]);
  assert.equal(maximum, 4);
  assert.equal(leased, 0);
});

test('lost lifecycle lock connection cannot report reset success', async () => {
  class Client extends EventEmitter {
    async query(sql) {
      if (sql.includes('pg_advisory_unlock')) throw new Error('connection lost');
      if (sql.includes('FROM identity.users')) return { rows:[{ id:7 }], rowCount:1 };
      return { rows:[], rowCount:0 };
    }
    release(error) { this.releaseError = error; }
  }
  const client = new Client();
  await assert.rejects(withPostgresStudentResetAdmission({ connect:async()=>client }, 7, async () => {
    client.emit('error', new Error('socket closed'));
  }), { code:'STUDENT_LIFECYCLE_LOCK_LOST' });
  assert.ok(client.releaseError instanceof Error);
});

test('resetAll completes every readiness preflight before its first mutation', async()=>{
  const events=[];
  const adapters=Object.fromEntries(Object.keys(WORKSHOP_OBJECTIVES).map(key=>[key,{
    preflight:async()=>events.push(['ready',key]),
    preflightAdministrative:async()=>events.push(['admin-ready',key]),
    reset:async(_owner,work)=>work(),clear:async()=>events.push(['clear',key]),
  }]));
  adapters.secureshop_agent_security={preflight:async()=>events.push(['ready','secureshop_agent_security']),
    preflightAdministrative:async()=>events.push(['admin-ready','secureshop_agent_security']),
    resetOwner:async()=>events.push(['clear','secureshop_agent_security'])};
  const service=createPostgresWorkshopResetService({adapters,progress:{resetWorkshopProgress:async()=>{}},
    listUserIds:async()=>[7]});
  await service.resetAll();
  const firstClear=events.findIndex(([kind])=>kind==='clear');
  assert.deepEqual(new Set(events.slice(0,firstClear).filter(([kind])=>kind==='ready').map(([,key])=>key)),
    new Set(Object.keys(WORKSHOP_OBJECTIVES)));
  assert.deepEqual(new Set(events.slice(0,firstClear).filter(([kind])=>kind==='admin-ready').map(([,key])=>key)),
    new Set(Object.keys(WORKSHOP_OBJECTIVES)));
});
test('durable CSRF reset completes victim flush and canonical progress inside original journal authority',async()=>{
 const events=[],actorRequest={user:{id:1}},execution={ownerKey:'owned'},operationId='original';
 const adapters=createPostgresWorkshopResetAdapters(name=>{
  if(name==='../routes/csrfWorkshop')return{resetOwner:async(_,work)=>work(execution),clearRagOwnerState:async()=>{throw Error('RAM fallback');},durableRagComposition:()=>({resolveRequest:async req=>{assert.equal(req,actorRequest);return{reset:async(ex,options)=>{assert.equal(ex,execution);assert.equal(options.targetOwnerId,17);assert.equal(options.operationId,operationId);events.push('begin');await options.afterErase();events.push('finish');}};}})};
  if(name==='../database/postgres/csrfWorkshopDb')return{resetUser:async()=>events.push('store')};
  if(name==='./csrfVictimSandbox')return{getOrCreateSandbox:()=>({ready:async()=>{},reset:()=>events.push('victim'),flush:async()=>events.push('flush')})};
  throw Error('Unexpected dependency');
 });
 await adapters.csrf_workshop.resetOwner(17,{actorRequest,operationId,resetCanonical:async()=>events.push('progress')});assert.deepEqual(events,['begin','store','victim','flush','progress','finish']);
});

test('bulk replay capability calls route composition accessors and rejects unconfigured routes',()=>{
 let configured=null;
 const {createPostgresWorkshopResetAdapters}=require('../server/services/postgresWorkshopResetService');
 const adapters=createPostgresWorkshopResetAdapters(name=>{
  if(['../routes/ragInjection','../routes/csrfWorkshop'].includes(name))return{durableRagComposition:()=>configured};
  throw new Error('Unexpected load '+name);
 });
 assert.equal(adapters.csrf_workshop.bulkResetReplaySafe(),false);
 assert.equal(adapters.indirect_prompt_injection.bulkResetReplaySafe(),false);
 configured={resolveRequest:async()=>{}};
 assert.equal(adapters.csrf_workshop.bulkResetReplaySafe(),true);
 assert.equal(adapters.indirect_prompt_injection.bulkResetReplaySafe(),true);
});
