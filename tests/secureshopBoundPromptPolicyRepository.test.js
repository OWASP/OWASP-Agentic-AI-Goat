'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  {
    randomUUID,
    createHash
  } = require('node:crypto');
const {
  createBoundPromptPolicyRepository: create
} = require('../server/database/postgres/secureshopBoundPromptPolicyRepository');
const contract = require('../server/services/secureshopPromptPolicyContract');
const {createFeatureModeAuthority}=require('../server/services/secureshopFeatureModeAuthority');
const {createBoundPromptPolicyService}=require('../server/services/secureshopBoundPromptPolicyService');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
function modeFixture(initial='fixed') {
  let mode=initial, epoch=0, calls=0;
  const modeAuthority=createFeatureModeAuthority({progress:{async getEvaluationScope(){return {mode,generation:epoch,modeStamp:String(epoch)};}},launches:{async assertCurrent(){}}});
  const f=fixture({modeAuthority});
  const renderer={async render(request,{executionMode}){
    calls++; assert.equal(executionMode,'vuln');
    return {...f.rendered(request),version:2,kind:'isolated_template',
      executionSha256:contract.renderExecutionDigest({version:2,mode:'vuln',request}),
      effectWitness:{version:1,workerAttested:true,commandEffectObserved:false,effectSha256:null,
        compilerSha256:contract.COMPILER_SHA256,workerSha256:contract.WORKER_SHA256}};
  },async checkReadiness(){throw Error('Fixed policy must not probe renderer');}};
  return {...f,modeAuthority,renderer,get calls(){return calls;},setMode(value){mode=value;epoch++;},
    service:createBoundPromptPolicyService({repository:f.repository,renderer,modeAuthority})};
}

test('RoleChoices Policy repository and service share the mode authority; missing token is denied', async()=>{
  const fixtureSource=readFileSync(join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
  const compositionSource=readFileSync(join(__dirname,'../server/services/secureshopBoundReviewComposition.js'),'utf8');
  assert.match(fixtureSource,/createBoundPromptPolicyRepository\(\{ pool: agents,\s*personaAuthority: grading\.personaAuthority, audit: reset\.audit\.agents, modeAuthority,/);
  assert.match(compositionSource,/createBoundPromptPolicyService\(\{repository:promptPolicyRepository,renderer:promptPolicyRenderer,modeAuthority\}\)/);
  const f=modeFixture('fixed'), input=f.input();
  assert.equal((await f.service.render(input)).state,'completed');
  const token=await f.modeAuthority.capture(f.context.scope,'policy');
  await assert.rejects(f.repository.beginRender({...f.input(),execution:token.snapshot}),
    {code:'SECURESHOP_FEATURE_MODE_STALE'});
});

test('fixed policy publishes literal task source and permits delete without renderer; private read validates exact original revision',async()=>{
  const f=modeFixture(), x=f.input();
  x.request={...x.request,contractVersion:2,targets:['listing'],markdown:'{{ synthetic_template }}'};
  const result=await f.service.render(x);
  assert.equal(result.receipt.version,'2'); assert.equal(result.receipt.renderResult.kind,'literal');
  assert.equal(result.receipt.renderResult.rendered,x.request.markdown); assert.equal(f.calls,0);
  assert.deepEqual(await f.service.readiness(x),{ready:true});
  const start=f.queries.length;
  const evidence=await f.service.readAssessmentPublication({...f.context,operationId:x.request.operationId});
  assert.equal(evidence.action,'upsert'); assert.equal(evidence.execution.mode,'fixed');
  assert.deepEqual(evidence.request,x.request); assert.deepEqual(evidence.receipt,result.receipt);
  assert.equal(evidence.revision.version,'2'); assert.equal(evidence.revision.payload.markdown,x.request.markdown);
  assert.ok(f.queries.slice(start).every(sql=>sql.startsWith('SET ')||sql.startsWith('SELECT ')));
  const removed=await f.service.remove({...f.context,operationId:randomUUID(),name:x.request.name,expectedVersion:'2'});
  assert.equal(removed.deleted,true); assert.equal(removed.version,'3'); assert.equal(f.calls,0);
  assert.deepEqual(await f.service.readAssessmentPublication({...f.context,operationId:x.request.operationId}),evidence);
  assert.equal((await f.service.readAssessmentPublication({...f.context,operationId:removed.operationId})).action,'delete');
});

test('completed vulnerable v2 and historical v1 replay after fixed toggle without another render or publication',async()=>{
  for(const historical of [false,true]){
    const f=modeFixture('vuln'), x=f.input(); let first;
    if(historical){
      // An old composed service admitted a v1 operation before mode authority existed.
      const legacy=create({pool:{query(){}},personaAuthority:f.authority,audit:{async append(){}}});
      await legacy.beginRender(x); first={receipt:await legacy.publish({...x,renderResult:f.rendered(x.request)})};
    }else first=await f.service.render(x);
    const count=f.calls, revisions=f.revisions.length; f.setMode('fixed');
    const replay=await f.service.render(x);
    assert.deepEqual(replay.receipt,{...first.receipt,replayed:true});
    assert.equal(f.calls,count); assert.equal(f.revisions.length,revisions);
    const evidence=await f.service.readAssessmentPublication({...f.context,operationId:x.request.operationId});
    assert.equal(evidence.execution?.mode??null,historical?null:'vuln');
  }
});

test('policy mode switch before publication and forged capability cannot publish; completed uncertainty recovers exactly',async()=>{
  const f=modeFixture('vuln'), x=f.input(), original=f.renderer.render;
  f.renderer.render=async(...args)=>{const value=await original(...args);f.setMode('fixed');return value;};
  await assert.rejects(f.service.render(x),{code:'ANALYTICS_MODE_STALE'});
  assert.equal(f.revisions.length,0); assert.equal((await f.repository.operation({...f.context,operationId:x.request.operationId})).state,'pending');
  const token=await f.modeAuthority.capture(f.context.scope,'policy');
  await assert.rejects(f.repository.beginRender({...f.input(),execution:token.snapshot},{modeToken:{...token}}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
  const next=f.input(), publish=f.repository.publish;
  const service=createBoundPromptPolicyService({modeAuthority:f.modeAuthority,renderer:f.renderer,repository:{...f.repository,
    async publish(...args){const receipt=await publish(...args);f.setMode('vuln');return receipt;}}});
  await assert.rejects(service.render(next),{code:'POLICY_OUTCOME_UNCERTAIN'});
  const receipt=await f.repository.operation({...f.context,operationId:next.request.operationId});
  assert.equal(receipt.renderResult.kind,'literal'); assert.equal(f.revisions.length,1);
});

test('private publication evidence rejects forged result/revision and foreign session; preview remains no publication',async()=>{
  const f=modeFixture(), x=f.input({action:'preview'});
  await f.service.render(x);
  assert.equal((await f.service.readAssessmentPublication({...f.context,operationId:x.request.operationId})).revision,null);
  await assert.rejects(f.service.readAssessmentPublication({...f.context,personaSession:{...f.context.personaSession,sessionId:randomUUID()},operationId:x.request.operationId}),{code:'OPERATION_CONFLICT'});
  const up=f.input();await f.service.render(up);
  f.revisions[0].values[8]=JSON.stringify({...JSON.parse(f.revisions[0].values[8]),rendered:'forged'});
  await assert.rejects(f.service.readAssessmentPublication({...f.context,operationId:up.request.operationId}),{code:'POLICY_INTEGRITY_UNAVAILABLE'});
  f.revoke();await assert.rejects(f.service.readAssessmentPublication({...f.context,operationId:x.request.operationId}),{code:'SHOP_AUTH_INVALID'});
});
function fixture(options = {}) {
  const context = {
      scope: {
        launchId: randomUUID(),
        scenarioId: randomUUID(),
        generation: 1,
        platformOwnerId: 1,
        platformSessionId: 2
      },
      persona: {
        id: 3,
        role: 'admin'
      },
      personaSession: {
        sessionId: randomUUID(),
        authorityVersion: '1'
      }
    },
    heads = new Map(),
    operations = new Map(),
    policies = new Map(),
    snapshots = new Map(),
    revisions = [],
    audits = [],
    queries = [];
  let revoke = false,
    drop = false;
  const scope = v => JSON.stringify(v.slice(0, 5)),
    key = (v, id = v[5]) => scope(v) + id;
  const client = {
    query: async (sql, v = []) => {
      queries.push(sql);
      let rows = [];
      if (sql.startsWith('SET ')) return {
        rows
      };
      if (sql.startsWith('INSERT INTO secureshop_agents.bound_prompt_policy_heads')) {
        if (!heads.has(scope(v))) heads.set(scope(v), '1');
      } else if (sql.startsWith('SELECT policy_version')) rows = [{
        version: heads.get(scope(v))
      }];else if (sql.startsWith('SELECT count')) {
        const table = sql.includes('_snapshots') ? snapshots : operations;
        rows = [{
          n: [...table.keys()].filter(k => k.startsWith(scope(v))).length
        }];
      } else if (sql.startsWith('SELECT * FROM') && sql.includes('_operations')) rows = operations.has(key(v)) ? [operations.get(key(v))] : [];else if (sql.startsWith('INSERT INTO') && sql.includes('_operations')) operations.set(key(v), {
        operation_id: v[5],
        persona_id: v[6],
        persona_session_id: v[7],
        authority_version: v[8],
        action: v[9],
        expected_version: v[10],
        mutation_sha256: Buffer.from(v[11], 'hex'),
        request_sha256: v[13] ? Buffer.from(v[13], 'hex') : null,
        payload_json: JSON.parse(v[12]),
        result_json: null
      });else if (sql.startsWith('UPDATE') && sql.includes('_operations')) Object.assign(operations.get(key(v)), {
        result_json: JSON.parse(v[6]),
        result_sha256: Buffer.from(v[7], 'hex')
      });else if (sql.startsWith('SELECT name') && sql.includes('_revisions')) rows=revisions.filter(r=>scope(r.values)===scope(v)&&r.values[5]===v[5]).map(r=>({name:r.values[6],version:r.values[7],action:r.action,payload_json:JSON.parse(r.values[8]),digest:r.values[9]}));else if (sql.startsWith('SELECT name')) rows = [...policies.entries()].filter(([k]) => k.startsWith(scope(v))).map(([, r]) => r);else if (sql.startsWith('INSERT INTO') && sql.includes('_revisions')) revisions.push({
        action: sql.includes("'delete'") ? 'delete' : 'upsert',
        values: v
      });else if (sql.startsWith('INSERT INTO') && sql.includes('_current')) policies.set(key(v), {
        name: v[5],
        policy_version: v[6],
        payload_json: JSON.parse(v[7]),
        digest: v[8]
      });else if (sql.startsWith('UPDATE') && sql.includes('_heads')) heads.set(scope(v), v[5]);else if (sql.startsWith('DELETE') && sql.includes('_current')) policies.delete(key(v));else if (sql.startsWith('SELECT *') && sql.includes('_snapshots')) rows = snapshots.has(key(v)) ? [snapshots.get(key(v))] : [];else if (sql.startsWith('INSERT INTO') && sql.includes('_snapshots')) snapshots.set(key(v), {
        persona_id: v[6],
        persona_session_id: v[7],
        authority_version: v[8],
        persona_role: v[9],
        policy_version: v[10],
        payload_json: JSON.parse(v[11]),
        payload_sha256: Buffer.from(v[12], 'hex')
      });else throw Error('Unexpected SQL ' + sql);
      return {
        rows
      };
    }
  };
  const authority = {
    capture: async input => {
      const assertCurrent = async () => {
        if (revoke) throw Object.assign(Error('revoked'), {
          code: 'SHOP_AUTH_INVALID'
        });
      };
      await assertCurrent();
      return {
        binding: {
          ...input.scope,
          personaId: input.personaId,
          role: input.role,
          sessionId: input.sessionId,
          authorityVersion: input.authorityVersion
        },
        assertRemoteAdmission: assertCurrent,
        withPersonaEffect: async work => {
          await assertCurrent();
          const result = await work(client);
          if (drop) throw Error('Lost commit response');
          return result;
        }
      };
    }
  };
  const repository = create({
    pool: {
      query() {
        throw Error('No pool query during fenced work');
      }
    },
    personaAuthority: authority,
    ...(options.modeAuthority?{modeAuthority:options.modeAuthority}:{}),
    audit: {
      append: async (c, event) => {
        assert.equal(c, client);
        audits.push(event);
      }
    },
    checkRunBinding: async (c, x) => {
      assert.equal(c, client);
      assert.ok(x.runId);return Object.hasOwn(options, 'runBinding') ? options.runBinding : true;
    }
  });
  const input = (extra = {}) => ({
    ...structuredClone(context),
    action: 'upsert',
    expectedVersion: '1',
    request: {
      operationId: randomUUID(),
      name: 'owned-policy',
      markdown: 'Synthetic policy',
      targets: ['admin']
    },
    ...extra
  });
  const rendered = request => ({
    version: 1,
    operationId: request.operationId,
    requestSha256: contract.requestDigest(request),
    isolation: contract.ISOLATION,
    rendered: request.markdown,
    renderedSha256: createHash('sha256').update(request.markdown).digest('hex'),
    exitCode: 0,
    timedOut: false,
    truncated: false,
    drained: true
  });
  return {
    repository,
    authority,
    context,
    input,
    rendered,
    heads,
    operations,
    policies,
    snapshots,
    revisions,
    audits,
    queries,
    revoke() {
      revoke = true;
    },
    drop() {
      drop = true;
    },
    undrop() {
      drop = false;
    }
  };
}
test('durable reservation prevents duplicate render; preview completion does not advance head', async () => {
  const f = fixture(),
    x = f.input({
      action: 'preview'
    });
  assert.equal((await f.repository.beginRender(x)).state, 'admitted');
  assert.equal((await f.repository.beginRender(x)).state, 'pending');
  await assert.rejects(f.repository.beginRender({
    ...x,
    expectedVersion: '2'
  }), {
    code: 'OPERATION_CONFLICT'
  });
  const done = await f.repository.publish({
    ...x,
    renderResult: f.rendered(x.request)
  });
  assert.equal(done.version, '1');
  assert.equal(f.policies.size, 0);
  assert.equal((await f.repository.beginRender(x)).state, 'completed');
  assert.equal((await f.repository.publish({
    ...x,
    renderResult: f.rendered(x.request)
  })).replayed, true);
  assert.equal(f.audits.length, 1);
});
test('upsert freezes run policy text; later update and tombstone preserve prior snapshot/replay', async () => {
  const f = fixture(),
    x = f.input();
  await f.repository.beginRender(x);
  await f.repository.publish({
    ...x,
    renderResult: f.rendered(x.request)
  });
  const run = {
      ...f.context,
      runId: randomUUID()
    },
    first = await f.repository.admitRunSnapshot(run);
  assert.equal(first.policyVersion, '2');
  assert.match(first.text, /Synthetic policy/);
  const next = f.input({
    expectedVersion: '2',
    request: {
      ...x.request,
      operationId: randomUUID(),
      markdown: 'Changed'
    }
  });
  await f.repository.beginRender(next);
  await f.repository.publish({
    ...next,
    renderResult: f.rendered(next.request)
  });
  assert.deepEqual(await f.repository.admitRunSnapshot(run), first);
  const del = {
    ...f.context,
    operationId: randomUUID(),
    name: x.request.name,
    expectedVersion: '3'
  };
  assert.equal((await f.repository.remove(del)).version, '4');
  assert.equal((await f.repository.remove(del)).replayed, true);
  assert.equal(f.policies.size, 0);
  assert.equal(f.revisions.at(-1).action, 'delete');
  assert.deepEqual(await f.repository.admitRunSnapshot(run), first);
});
test('malformed render and changed replay output cannot mutate accepted policy', async () => {
  const f = fixture(),
    x = f.input();
  await assert.rejects(f.repository.publish({
    ...x,
    renderResult: f.rendered(x.request)
  }), {
    code: 'POLICY_RENDER_NOT_ADMITTED'
  });
  await f.repository.beginRender(x);
  await assert.rejects(f.repository.publish({
    ...x,
    renderResult: {
      ...f.rendered(x.request),
      drained: false
    }
  }));
  assert.equal(f.policies.size, 0);
  await f.repository.publish({
    ...x,
    renderResult: f.rendered(x.request)
  });
  const r = f.rendered(x.request);
  r.rendered = 'Different';
  r.renderedSha256 = createHash('sha256').update(r.rendered).digest('hex');
  await assert.rejects(f.repository.publish({
    ...x,
    renderResult: r
  }), {
    code: 'OPERATION_CONFLICT'
  });
});
test('original admin recovery rejects another session; revoked authority and absent run checker fail closed', async () => {
  const f = fixture(),
    x = f.input();
  await f.repository.beginRender(x);
  await assert.rejects(f.repository.operation({
    ...f.context,
    operationId: x.request.operationId,
    personaSession: {
      ...f.context.personaSession,
      sessionId: randomUUID()
    }
  }), {
    code: 'OPERATION_CONFLICT'
  });
  f.revoke();
  await assert.rejects(f.repository.beginRender(f.input()), {
    code: 'SHOP_AUTH_INVALID'
  });
  const noRun = create({
    pool: {
      query() {}
    },
    personaAuthority: f.authority,
    audit: {
      append() {}
    }
  });
  await assert.rejects(noRun.admitRunSnapshot({
    ...f.context,
    runId: randomUUID()
  }), {
    code: 'POLICY_RUN_AUTHORITY_UNAVAILABLE'
  });
});
test('lost reservation acknowledgement stays pending; response loss never grants a second render', async () => {
  const f = fixture(),
    x = f.input();
  f.drop();
  await assert.rejects(f.repository.beginRender(x), {
    code: 'POLICY_OUTCOME_UNCERTAIN'
  });
  f.undrop();
  assert.equal((await f.repository.beginRender(x)).state, 'pending');
  assert.equal(f.operations.size, 1);
  assert.equal(f.audits.length, 0);
});
test('inputs snapshot before authority await and sibling policies remain isolated', async () => {
  const f = fixture(),
    x = f.input(),
    original = f.authority.capture;
  let release;
  const barrier = new Promise(r => release = r);
  f.authority.capture = async value => {
    await barrier;
    return original(value);
  };
  const pending = f.repository.beginRender(x);
  x.request.markdown = 'Caller mutation';
  release();
  await pending;
  const admitted = [...f.operations.values()][0];
  assert.equal(admitted.payload_json.markdown, 'Synthetic policy');
  const sibling = {
    ...f.context,
    scope: {
      ...f.context.scope,
      launchId: randomUUID(),
      platformOwnerId: 99
    }
  };
  assert.deepEqual((await f.repository.list(sibling)).policies, []);
  assert.equal(f.operations.size, 1);
});
test('another publish wins CAS: losing pending operation never rerenders or overwrites', async () => {
  const f=fixture(),a=f.input(),b=f.input({request:{operationId:randomUUID(),name:'other',markdown:'other',targets:['admin']}});
  await f.repository.beginRender(a);await f.repository.beginRender(b);
  const receipt=await f.repository.publish({...b,renderResult:f.rendered(b.request)});
  assert.equal(receipt.version,'2');assert.equal(receipt.renderResult.version,1);
  await assert.rejects(f.repository.publish({...a,renderResult:f.rendered(a.request)}),{code:'REVISION_CONFLICT'});
  assert.equal((await f.repository.beginRender(a)).state,'pending');assert.equal(f.policies.size,1);
});
test('assembled prompt limit includes policy delimiters before publication', async () => {
  const f=fixture();
  const big=x=>({...f.rendered(x.request),rendered:'x'.repeat(65536),renderedSha256:createHash('sha256').update('x'.repeat(65536)).digest('hex')});
  const a=f.input();await f.repository.beginRender(a);await f.repository.publish({...a,renderResult:big(a)});
  const b=f.input({expectedVersion:'2',request:{operationId:randomUUID(),name:'second',markdown:'x',targets:['admin']}});await f.repository.beginRender(b);
  await assert.rejects(f.repository.publish({...b,renderResult:big(b)}));assert.equal(f.policies.size,1);assert.equal(f.audits.length,1);
});
test('operation admission quota bounds unresolved render reservations',async()=>{
 const f=fixture();for(let i=0;i<512;i++)await f.repository.beginRender(f.input());
 await assert.rejects(f.repository.beginRender(f.input()),{code:'POLICY_QUOTA_EXCEEDED'});assert.equal(f.operations.size,512);
});
test('retirement SQL redacts payloads while retaining immutable digests; owner cleanup scoped',()=>{
 const sql=require('node:fs').readFileSync('docs/modernization/drafts/secureshop-bound-prompt-policies/0027_bound_prompt_policies.candidate.sql','utf8');
 assert.match(sql,/SET payload_json=NULL,result_json=NULL/);assert.doesNotMatch(sql,/SET result_sha256=NULL/);
 assert.match(sql,/SET payload_json=NULL WHERE platform_launch_id=l AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id/);
 assert.match(sql,/DELETE FROM secureshop_agents.bound_prompt_policy_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id/);
 assert.equal((sql.match(/EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert\(\)/g)||[]).length,5);
});

for (const value of [false, undefined, null, {}]) {
  test(`run binding requires explicit true (${String(value)}) before any snapshot write`, async () => {
    const f = fixture({ runBinding: value });
    await assert.rejects(f.repository.admitRunSnapshot({ ...f.context, runId: randomUUID() }), { code: 'POLICY_RUN_AUTHORITY_UNAVAILABLE' });
    assert.equal(f.snapshots.size, 0);
  });
}

test('definitive stale begin and delete reject before operation/publication changes',async()=>{
 const f=fixture(),first=f.input();await f.repository.beginRender(first);await f.repository.publish({...first,renderResult:f.rendered(first.request)});
 const before={operations:f.operations.size,policies:f.policies.size,audits:f.audits.length};
 await assert.rejects(f.repository.beginRender(f.input()),{code:'REVISION_CONFLICT'});
 await assert.rejects(f.repository.remove({...f.context,operationId:randomUUID(),name:first.request.name,expectedVersion:'1'}),{code:'REVISION_CONFLICT'});
 assert.deepEqual({operations:f.operations.size,policies:f.policies.size,audits:f.audits.length},before);
});

test('v2 task targets retain OR semantics, immutable recipient replay and unchanged v1 role behavior', async () => {
  const f = fixture();
  const task = require('../server/services/secureshopPromptPolicyTaskMutation');
  const input = f.input(); input.request = { ...input.request, contractVersion: 2, targets: ['summarizer', 'review-moderator'] };
  const admitted = await f.repository.beginRender(input);
  const renderResult = f.rendered(task.renderRequest(input.request));
  assert.equal(admitted.requestSha256, renderResult.requestSha256);
  const receipt = await f.repository.publish({ ...input, renderResult });
  assert.equal(receipt.policyRequestSha256, task.taskMutationDigest(input.request));
  assert.equal((await f.repository.publish({ ...input, renderResult })).replayed, true);
  await assert.rejects(f.repository.beginRender({ ...input, request: { ...input.request, targets: ['customer'] } }), { code: 'OPERATION_CONFLICT' });
  const context = { ...f.context, persona: { id: 9, role: 'customer' }, runId: randomUUID(), policyContractVersion: 2, recipient: 'summarizer' };
  const selected = await f.repository.admitRunSnapshot(context); assert.equal(selected.policies.length, 1);
  assert.deepEqual(selected.policies[0].targets, ['review-moderator', 'summarizer']);
  await assert.rejects(f.repository.admitRunSnapshot({ ...context, recipient: null }), { code: 'OPERATION_CONFLICT' });
  assert.equal((await f.repository.admitRunSnapshot({ ...context, runId: randomUUID(), recipient: null })).policies.length, 0);
  const legacy = { ...context, runId: randomUUID() }; delete legacy.recipient; delete legacy.policyContractVersion;
  assert.equal((await f.repository.admitRunSnapshot(legacy)).policies.length, 0);
  const merchant = { ...context, persona: { id: 10, role: 'merchant' }, runId: randomUUID(), recipient: 'review-moderator' };
  assert.equal((await f.repository.admitRunSnapshot(merchant)).policies.length, 1);
});
