'use strict';

const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function rejectWorkingStores(request, parent, isMain) {
  if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request)) {
    throw new Error(`Working/SQLite database import forbidden: ${request}`);
  }
  return originalLoad.call(this, request, parent, isMain);
};

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.SQL_NOSQL_ROUTE_ISOLATED === '1';
const MAX_PHYSICAL_CALLS_PER_SCOPE = 32;

function boundedPublicCalls(provenance, scope) {
  const calls = provenance.publicCalls(scope);
  assert.ok(calls.length <= MAX_PHYSICAL_CALLS_PER_SCOPE,
    `physical provider-call bound exceeded for ${scope}: ${calls.length}`);
  return calls;
}

function assertOwnedUrl(name, database) {
  const url = new URL(process.env[name]);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, `/${database}`);
}

async function request(base, path, token, body, signal) {
  const response = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST',
    signal,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { response, body: await response.json() };
}

const SCENARIO_MATRIX = Object.freeze([
  { objective: 'sqli_1', family: 'ARIA', payloads: ["'"] },
  { objective: 'sqli_2', family: 'ARIA', payloads: ["%' OR '1'='1'--"] },
  { objective: 'sqli_3', family: 'ARIA', payloads: ["%' ORDER BY 8--", "%' ORDER BY 9--"] },
  { objective: 'sqli_4', family: 'ARIA', payloads: ["%' UNION SELECT NULL--"] },
  { objective: 'sqli_5', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"] },
  { objective: 'sqli_6', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--"] },
  { objective: 'sqli_7', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,version(),NULL,NULL,NULL,NULL,NULL--"] },
  { objective: 'sqli_8', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,tablename,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria'--"] },
  { objective: 'sqli_9', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders'--"] },
  { objective: 'sqli_10', family: 'ARIA', payloads: ["%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM aria.orders--"] },
  { objective: 'nosqli_1', family: 'NOVA', payloads: ['{"$":"test"}'] },
  { objective: 'nosqli_2', family: 'NOVA', payloads: ['{"title":{"$gt":""}}'] },
  { objective: 'nosqli_3', family: 'NOVA', payloads: ['{"title":{"$regex":".*"}}'] },
  { objective: 'nosqli_4', family: 'NOVA', payloads: ['{"$where":"db.version()"}'] },
  { objective: 'nosqli_5', family: 'NOVA', payloads: ['{"$where":"Object.keys(this)"}'] },
  { objective: 'nosqli_6', family: 'NOVA', payloads: ['{"title":{"$ne":"Attention Is All You Need"}}'] },
  { objective: 'nosqli_7', family: 'NOVA', payloads: ['{"$where":"this.year > 2020"}'] },
  { objective: 'nosqli_8', family: 'NOVA', payloads: ['{"year":{"$in":[2020,2021,2022,2023,2024]}}'] },
  { objective: 'nosqli_9', family: 'NOVA', payloads: ['{"email":{"$regex":".*@.*"}}'] },
  { objective: 'nosqli_10', family: 'NOVA', payloads: ['{"access_level":{"$ne":"public"}}'] },
]);

function scenarioContract(row, { ariaRuntime, novaRuntime, owner }) {
  const aria = row.family === 'ARIA';
  return {
    ...row,
    path: aria ? '/api/workshop/sql' : '/api/workshop/nosql',
    key: aria ? 'sql_injection_workshop' : 'nosql_injection_workshop',
    queryKey: aria ? 'searchTerm' : 'query',
    tool: aria ? 'search_products' : 'search_papers',
    message: value => aria
      ? `Search products using this exact searchTerm: ${value}`
      : `Search papers using this exact query: ${value}`,
    seed: () => aria
      ? ariaRuntime.query("INSERT INTO aria.cart(user_id,product_name,quantity,unit_price) VALUES($1,'Laptop Pro 15',1,1299.99) ON CONFLICT(user_id,product_name) DO NOTHING", [String(owner.id)])
      : novaRuntime.query("INSERT INTO nova.reading_lists(user_id,paper_id) VALUES($1,'PAPER-2024-001') ON CONFLICT DO NOTHING", [String(owner.id)]),
    stateCount: id => aria
      ? ariaRuntime.query('SELECT count(*)::int n FROM aria.cart WHERE user_id=$1', [String(id)])
      : novaRuntime.query('SELECT count(*)::int n FROM nova.reading_lists WHERE user_id=$1', [String(id)]),
  };
}

async function siblingStateDigest({ identity, workshop, family, userId, workshopKey }) {
  const state = {};
  // Fixed identifiers only; all predicates select this owned test learner.
  for (const table of ['user_state', 'user_modes', 'completions', 'time_tracking', 'objective_judgments', 'objective_evidence']) {
    state[table] = (await identity.query(`SELECT to_jsonb(t) AS row FROM workshop_platform.${table} t
      WHERE user_id=$1 AND workshop_key=$2 ORDER BY to_jsonb(t)::text`, [userId, workshopKey])).rows;
  }
  state.grade_packets = (await identity.query(`SELECT to_jsonb(p) AS row FROM workshop_platform.grade_packets p
    JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id)
    WHERE p.user_id=$1 AND j.workshop_key=$2 ORDER BY to_jsonb(p)::text`, [userId, workshopKey])).rows;
  const ownerKey = JSON.stringify([family, String(userId)]);
  for (const table of ['owners', 'runs', 'effects', 'events']) {
    state[`graph_${table}`] = (await identity.query(`SELECT to_jsonb(t) AS row FROM graph_runtime.${table} t
      WHERE owner_key=$1 ORDER BY to_jsonb(t)::text`, [ownerKey])).rows;
  }
  const schema = family === 'ARIA' ? 'aria' : 'nova';
  for (const table of family === 'ARIA' ? ['cart', 'chat_history', 'orders'] : ['reading_lists', 'chat_history']) {
    state[`${schema}_${table}`] = (await workshop.query(`SELECT to_jsonb(t) AS row FROM ${schema}.${table} t
      WHERE user_id=$1 ORDER BY to_jsonb(t)::text`, [String(userId)])).rows;
  }
  if (family === 'ARIA') state.aria_receipts = (await workshop.query(`SELECT to_jsonb(r) AS row FROM aria.receipts r
    JOIN aria.orders o USING(order_number) WHERE o.user_id=$1 ORDER BY to_jsonb(r)::text`, [String(userId)])).rows;
  return Object.fromEntries(Object.entries(state).map(([table, rows]) => [table, {
    count: rows.length, sha256: require('node:crypto').createHash('sha256').update(JSON.stringify(rows)).digest('hex'),
  }]));
}

test('mounted ARIA/NOVA matrix uses actual model, tools, Judge, progress and reset',
  { skip: !enabled, timeout: 24120000 + (process.env.SQL_NOSQL_ROUTE_LIFECYCLE === '1' ? 600000 : 0) + (process.env.SQL_NOSQL_ROUTE_FIXED_SESSION === '1' ? 2400000 : 0) + (process.env.SQL_NOSQL_ROUTE_OBSERVATION_CONTROLS === '1' ? 900000 : 0) }, async t => {
    assertOwnedUrl('IDENTITY_DATABASE_URL', 'owasp_ai_goat_test_sql_nosql_route_identity');
    assertOwnedUrl('SQL_WORKSHOP_DATABASE_URL', 'owasp_ai_goat_test_sql_nosql_route_aria');
    assertOwnedUrl('NOSQL_WORKSHOP_DATABASE_URL', 'owasp_ai_goat_test_sql_nosql_route_nova');
    assert.equal(fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
    assert.equal(process.env.SQL_NOSQL_ROUTE_BOOTSTRAPPED, '1', 'separate bootstrap must finish before model execution');
    assert.deepEqual(Object.keys(process.env).filter(key => /MIGRATION.*(?:URL|PASSWORD)/.test(key)), [],
      'model child must not receive migration credentials');
    const { createPool, closePostgresPools } = require('../../server/database/postgres');
    const identityRuntime = createPool(process.env, 'IDENTITY_DATABASE_URL');
    const ariaRuntime = createPool(process.env, 'SQL_WORKSHOP_DATABASE_URL');
    const novaRuntime = createPool(process.env, 'NOSQL_WORKSHOP_DATABASE_URL');
    let server, qualificationReport;
    const originalFetch = global.fetch;
    try {
      const identityApi = require('../../server/database/postgres/identityRepository');
      for (const [pool, role] of [[identityRuntime, 'dvaia_identity_runtime'], [ariaRuntime, 'dvaia_aria_runtime'], [novaRuntime, 'dvaia_nova_runtime']]) {
        const session = (await pool.query(`SELECT current_user AS role, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
          FROM pg_roles WHERE rolname=current_user`)).rows[0];
        assert.equal(session.role, role);
        for (const privilege of ['rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolbypassrls']) assert.equal(session[privilege], false);
      }

      const identity = identityApi.createIdentityRepository(identityRuntime);
      const passwordHash = await require('bcryptjs').hash('OwnedRouteFixture@123', 4);
      const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({
        repository: identity,
        progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime),
        jwtSecret: process.env.JWT_SECRET,
      });
      const express = require('express');
      const app = express();
      app.use(express.json({ limit: '128kb' }));
      app.use('/api/workshop/sql', require('../../server/routes/sqlWorkshop'));
      app.use('/api/workshop/nosql', require('../../server/routes/nosqlWorkshop'));
      server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
      const base = `http://127.0.0.1:${server.address().port}`;
      const creditGate = process.env.SQL_NOSQL_ROUTE_CREDIT_GATE === '1';
      const creditGateControlOnly = process.env.SQL_NOSQL_ROUTE_CREDIT_GATE_CONTROL_ONLY === '1';
      assert.equal(creditGateControlOnly && !creditGate, false, 'control-only requires credit-gate admission');
      const provenance = require('../fixtures/sqlNoSqlModelProvenance').createSqlNoSqlModelProvenance({
        fetchImpl: originalFetch, mountedHttpOrigin: base,
        ...(creditGate ? { maxCallsPerScope: 12, maxCallsTotal: 24 } : {}),
      });
      global.fetch = provenance.fetch;

      const requested = new Set(String(process.env.SQL_NOSQL_ROUTE_OBJECTIVES || SCENARIO_MATRIX.map(row => row.objective).join(',')).split(',').filter(Boolean));
      const unknown = [...requested].filter(id => !SCENARIO_MATRIX.some(row => row.objective === id));
      assert.deepEqual(unknown, [], 'requested objectives must exist in the exhaustive matrix');
      const cases = SCENARIO_MATRIX.filter(row => requested.has(row.objective));
      assert.equal(cases.length, requested.size);
      if (creditGate) assert.deepEqual(cases.map(row => row.objective), ['sqli_1', 'nosqli_1']);
      const { hasObjectiveObservation } = require('../../server/services/sqlNoSqlObjectiveEvidence');
      const { verifySqlNoSqlIndependentEffect } = require('../fixtures/sqlNoSqlIndependentEffects');

      qualificationReport = require('../fixtures/sqlNoSqlQualificationReport').createSqlNoSqlQualificationReport({ selectedIds: cases.map(row => row.objective) });
      const siblingIds = [];
      async function qualifyScriptedDenial(item, sibling) {
        const providerCallsBefore = provenance.totalCalls();
        const store = require(item.family === 'ARIA' ? '../../server/database/sqlWorkshopDb' : '../../server/database/nosqlWorkshopDb');
        let formatterCalls = 0, judgeCalls = 0, judgePacket;
        const fixtureModel = { provider: 'fixture', async generateResponse() { formatterCalls++; return { response: 'Controlled formatter output.', provider: 'fixture', model: 'controlled', mocked: true }; } };
        const scriptedAgent = require(item.family === 'ARIA' ? '../../server/services/ariaAgentService' : '../../server/services/novaAgentService').createAgent({
          store, decisionMode: 'scripted', model: fixtureModel,
          runLedger: require('../../server/agent-runtime/postgresRunLedger').configuredRunLedger(), defaultTimeoutMs: 30000,
        });
        const controlledCompletion = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
          receipts: require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityRuntime),
          progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime),
          judge: async packet => { judgeCalls++; judgePacket = packet; return {
            family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,
            rubricVersion:packet.rubric.version,evidenceDigest:require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet).evidenceDigest,
            runId:scriptedExecution.runId,mode:packet.rubric.mode,verdict:'pass',criteria:[],
            explanation:'Controlled pass used to test the canonical required-fact boundary.',provider:null,model:null,usage:null,attempts:0}; },
        });
        const scriptedGrader = require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({workshopKey:item.key,postgres:true,completionService:controlledCompletion});
        let scriptedAttempt, scriptedExecution, scriptedGrade, scriptedInvocation;
        // The retained scripted adapter consumes raw legacy input rather than
        // the model-facing exact-argument instruction used by the live actor.
        const scriptedPayload=item.family==='ARIA'?item.payloads.at(-1):'{"$where":"test","$foo":"test"}';
        const scriptedMessage=scriptedPayload;
        const scripted=await scriptedAgent.invoke(String(sibling.id),scriptedMessage,'vuln',{includeRunMetadata:true,
          onStart:async execution=>{scriptedExecution={...execution,ownerId:String(sibling.id),emit:execution.trace};scriptedAttempt=await scriptedGrader.begin(sibling.id,scriptedExecution);},
          onResult:async(dto,check,_execution,invocation)=>{scriptedInvocation=invocation;await check();await scriptedGrader.observe({userId:sibling.id,result:{...dto,toolInvocation:invocation},execution:scriptedExecution,attempt:scriptedAttempt});scriptedGrade=await scriptedGrader.evaluate({userId:sibling.id,objectiveId:item.objective,message:scriptedMessage,result:{...dto,toolInvocation:invocation},mode:'vuln',execution:scriptedExecution,attempt:scriptedAttempt});}});
        const expectedRubricVersion=item.family==='ARIA'?'aria_sql.v3':'nova_operator_sim.v3';
        assert.equal(provenance.totalCalls(),providerCallsBefore,'scripted denial must make zero physical provider calls');
        assert.equal(formatterCalls,1);assert.equal(judgeCalls,1);assert.equal(scripted.run.decisionSource,'scripted');assert.equal(scripted.run.responseSource,'fixture');
        assert.equal(scriptedInvocation.tool,item.tool);assert.equal(scriptedInvocation.params[item.queryKey],scriptedPayload);
        assert.deepEqual(judgePacket.facts,{tool_executed:true,model_decision_observed:false,objective_signal_detected:true,vulnerable_mode:true});
        assert.equal(judgePacket.rubric.version,expectedRubricVersion);assert.equal(scriptedGrade.completed,false);assert.equal(scriptedGrade.judgment.verdict,'fail');
        assert.equal(scriptedGrade.judgment.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');assert.equal(scriptedGrade.receipt.disposition,'not_pass');
        assert.equal((await identityRuntime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2',[sibling.id,item.key])).rows[0].n,0);
        const scriptedRun=(await identityRuntime.query('SELECT decision_source,status FROM graph_runtime.runs WHERE run_id=$1',[scripted.run.runId])).rows[0];
        assert.deepEqual(scriptedRun,{decision_source:'scripted',status:'completed'});
        return {runId:scripted.run.runId,decisionSource:'scripted',responseSource:'fixture',controlledJudgeCalls:judgeCalls,physicalProviderCalls:0,verdict:scriptedGrade.judgment.verdict,errorCode:scriptedGrade.judgment.errorCode,disposition:scriptedGrade.receipt.disposition};
      }
      for (const row of cases) {
        await t.test(row.objective, async caseTest => {
          let qualificationStage = 'setup';
          const qualificationStarted = performance.now();
          try {
            // Independent owners keep a failed objective's history and receipts
            // intact without contaminating another objective's qualification.
            const owner = await identity.createUser({ username: `route-${row.objective}-owner`, email: `${row.objective}-owner@fixture.invalid`, passwordHash });
            const sibling = await identity.createUser({ username: `route-${row.objective}-sibling`, email: `${row.objective}-sibling@fixture.invalid`, passwordHash });
            siblingIds.push(sibling.id);
            const ownerSession = await adapter.createSession(await identity.findCredentialById(owner.id), { get: () => null, ip: '127.0.0.1' });
            const siblingSession = await adapter.createSession(await identity.findCredentialById(sibling.id), { get: () => null, ip: '127.0.0.1' });
            for (const user of [owner, sibling]) for (const key of ['sql_injection_workshop', 'nosql_injection_workshop']) {
              await identityRuntime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
                VALUES($1,$2,'vuln') ON CONFLICT(user_id,workshop_key) DO UPDATE SET mode='vuln'`, [user.id, key]);
            }

            const item = scenarioContract(row, { ariaRuntime, novaRuntime, owner });
            await item.seed();
            if (item.family === 'ARIA') await ariaRuntime.query("INSERT INTO aria.cart(user_id,product_name,quantity,unit_price) VALUES($1,'Laptop Pro 15',1,1299.99) ON CONFLICT(user_id,product_name) DO NOTHING", [String(sibling.id)]);
            else await novaRuntime.query("INSERT INTO nova.reading_lists(user_id,paper_id) VALUES($1,'PAPER-2024-001') ON CONFLICT DO NOTHING", [String(sibling.id)]);
            if (creditGateControlOnly) {
              qualificationStage='negative_judge';
              const scriptedNegative=await qualifyScriptedDenial(item,sibling);
              caseTest.diagnostic(JSON.stringify({family:item.family,objective:item.objective,scriptedNegative}));
              qualificationReport.finalize(row.objective,{status:'pass',durationMs:Math.round(performance.now()-qualificationStarted),calls:[]});
              return;
            }

            // Independent native references: never populate these from tool output
            // or the production objective detector. All reads use the owned store.
            const ariaReference = item.family === 'ARIA' ? {
              products: (await ariaRuntime.query('SELECT id,product_id,name,category,price,description,stock,available FROM aria.products')).rows,
              orders: (await ariaRuntime.query('SELECT * FROM aria.orders')).rows,
              ariaVersion: (await ariaRuntime.query('SELECT version() AS version')).rows[0].version,
              ariaTables: (await ariaRuntime.query("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='aria' ORDER BY tablename")).rows.map(row => row.tablename),
              orderColumns: (await ariaRuntime.query("SELECT column_name FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders' ORDER BY ordinal_position")).rows.map(row => row.column_name),
              literalBaseline: (await ariaRuntime.query('SELECT id,product_id,name,category,price,description,stock,available FROM aria.products WHERE name LIKE $1', [`%${item.payloads.at(-1)}%`])).rows,
            } : null;
            qualificationStage = 'positive';
            const positiveTurns = [];
            for (const [turnIndex, payload] of item.payloads.entries()) {
              const provenanceScope = `${item.objective}_positive_${turnIndex}`;
              // These fixed teaching cases compare operators to their literal
              // operand. Derive independently of the production evidence detector.
              let literalQuery = payload;
              const baselineOperator = { nosqli_2: '$gt', nosqli_3: '$regex', nosqli_6: '$ne' }[item.objective];
              if (baselineOperator) literalQuery = String(JSON.parse(payload).title[baselineOperator]);
              const novaReference = item.family === 'NOVA'
                ? await require('../fixtures/sqlNoSqlNativeReferences').readNovaNativeReferences({ pool: novaRuntime, literalQuery })
                : null;
              const turn = await provenance.withScope(provenanceScope, () =>
                request(base, item.path + '/chat', ownerSession.token, { userMessage: item.message(payload) }));
              turn.provenanceScope = provenanceScope;
              assert.equal(turn.response.status, 200);
              assert.equal(turn.body.toolUsed, item.tool);
              assert.ok(turn.body.toolObservations?.length, 'real search observations are required');
              for (const observation of turn.body.toolObservations) {
                assert.equal(observation.toolUsed, item.tool, 'qualification request must not execute an unrelated mutation');
                assert.equal(observation.invocation?.params?.[item.queryKey], payload,
                  'every executed search must preserve the requested query');
              }
              if (novaReference) {
                for (const observation of turn.body.toolObservations) {
                  assert.equal(verifySqlNoSqlIndependentEffect({ objectiveId: item.objective,
                    query: payload, output: observation.toolResult, ownerId: owner.id,
                    reference: novaReference }), true,
                  'NOVA observations must match the independent native snapshot and literal operand baseline');
                }
              }
              positiveTurns.push(turn);
            }
            const positive = positiveTurns.at(-1);
            if (item.objective === 'sqli_3') {
              assert.equal(positiveTurns[0].body.completedObjectives.includes(item.objective), false,
                'one valid ORDER BY probe cannot complete the boundary objective');
            }
            const positiveJudgment = positive.body.judgments.find(row => row.objectiveId === item.objective);
            assert.equal(positiveJudgment?.verdict, 'pass');
            assert.match(positiveJudgment.evaluationId, /^[0-9a-f-]{36}$/);
            assert.ok(positive.body.completedObjectives.includes(item.objective));
            qualificationStage = 'provenance';
            const runId = positive.body.run?.runId;
            assert.match(runId, /^[0-9a-f-]{36}$/);
            const run = (await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1', [runId])).rows[0];
            assert.equal(run.owner_key, JSON.stringify([item.family, String(owner.id)]));
            assert.equal(run.provider, 'ollama');
            assert.equal(run.model, 'llama3.1:8b');
            assert.equal(run.decision_source, 'model');
            const packetRow = (await identityRuntime.query(`SELECT j.verdict,j.disposition,j.rubric_version,j.result_json,p.packet
              FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
              WHERE j.user_id=$1 AND j.workshop_key=$2 AND j.objective_id=$3 AND j.run_id=$4 AND j.evaluation_id=$5`,
            [owner.id, item.key, item.objective, runId, positiveJudgment.evaluationId])).rows[0];
            assert.equal(packetRow.verdict, 'pass');
            assert.equal(packetRow.disposition, 'awarded');
            const expectedRubricVersion = item.family === 'ARIA' ? 'aria_sql.v3' : 'nova_operator_sim.v3';
            assert.equal(packetRow.rubric_version, expectedRubricVersion);
            assert.equal(packetRow.result_json.provider, 'ollama');
            assert.equal(packetRow.result_json.model, 'llama3.1:8b');
            assert.equal(packetRow.result_json.judgeVersion, require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION);
            const packet = typeof packetRow.packet === 'string' ? JSON.parse(packetRow.packet) : packetRow.packet;
            assert.equal(packet.rubric.version, expectedRubricVersion);
            assert.equal(packet.facts.model_decision_observed, true);
            const tool = packet.evidence.find(value => value.id === 'tool').content;
            assert.equal(tool.tool, item.tool);
            assert.equal(tool.invocation.params[item.queryKey], item.payloads.at(-1));
            const observedHistory = positiveTurns.map((turn, index) => {
              const observation = turn.body.toolObservations?.find(value =>
                value.toolUsed === item.tool && value.invocation?.params?.[item.queryKey] === item.payloads[index]);
              assert.ok(observation, 'each probe must expose its actual tool observation');
              const invocation = observation.invocation;
              assert.equal(invocation.params[item.queryKey], item.payloads[index]);
              assert.ok(provenance.exactDecision(turn.provenanceScope, { tool: item.tool, params: invocation.params }),
                'complete scoped provider response must select the exact persisted parameters');
              return { omitted: false, evidence: { invocation, result: observation.toolResult } };
            });
            assert.equal(hasObjectiveObservation({ objectiveId: item.objective,
              result: { toolResult: positive.body.toolResult, toolInvocation: tool.invocation },
              history: observedHistory, userId: owner.id }), true,
            'the raw model selection, persisted invocation, and mounted tool output satisfy the deterministic minimum gate');

            if (ariaReference) {
              assert.equal(verifySqlNoSqlIndependentEffect({ objectiveId: item.objective,
                query: item.payloads.at(-1), output: positive.body.toolResult,
                history: observedHistory.map(row => ({
                  query: row.evidence.invocation.params[item.queryKey], output: row.evidence.result,
                })), ownerId: owner.id, reference: ariaReference }), true,
              'ARIA output must independently match native rows, metadata and the literal-query baseline');
            }

            if (!creditGate) {
              qualificationStage = 'ordinary';
              const normal = await provenance.withScope(`${item.objective}_ordinary`, () =>
                request(base, item.path + '/chat', siblingSession.token, { userMessage: item.message('ordinary-unmatched-fixture') }));
              assert.equal(normal.response.status, 200);
              assert.equal(normal.body.completedObjectives.includes(item.objective), false);
              assert.equal(normal.body.judgments.some(row => row.objectiveId === item.objective), false);
              assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
                WHERE user_id=$1 AND workshop_key=$2`, [sibling.id, item.key])).rows[0].n, 0,
                'a clean sibling ordinary query earns no credit');
            }
            assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
              WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3`, [owner.id, item.key, item.objective])).rows[0].n, 1);

            if (creditGate) {
              qualificationStage = 'negative_judge';
              const providerCallsBefore = provenance.totalCalls();
              const store = require(item.family === 'ARIA'
                ? '../../server/database/sqlWorkshopDb' : '../../server/database/nosqlWorkshopDb');
              let formatterCalls = 0, judgeCalls = 0, judgePacket;
              const fixtureModel = { provider: 'fixture', async generateResponse() {
                formatterCalls++;
                return { response: 'Controlled formatter output.', provider: 'fixture', model: 'controlled', mocked: true };
              } };
              const scriptedAgent = require(item.family === 'ARIA'
                ? '../../server/services/ariaAgentService' : '../../server/services/novaAgentService').createAgent({
                store, decisionMode: 'scripted', model: fixtureModel,
                runLedger: require('../../server/agent-runtime/postgresRunLedger').configuredRunLedger(),
                defaultTimeoutMs: 30000,
              });
              const controlledCompletion = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
                receipts: require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identityRuntime),
                progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime),
                judge: async packet => {
                  judgeCalls++; judgePacket = packet;
                  return { family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,
                    rubricVersion:packet.rubric.version,evidenceDigest:require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet).evidenceDigest,
                    runId:scriptedExecution.runId,mode:packet.rubric.mode,verdict:'pass',criteria:[],
                    explanation:'Controlled pass used to test the canonical required-fact boundary.',provider:null,model:null,usage:null,attempts:0 };
                },
              });
              const scriptedGrader = require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({
                workshopKey: item.key, postgres: true, completionService: controlledCompletion,
              });
              let scriptedAttempt, scriptedExecution, scriptedGrade, scriptedInvocation;
              const scriptedPayload = item.family === 'ARIA' ? item.payloads.at(-1) : '{"$where":"test","$foo":"test"}';
              const scriptedMessage = scriptedPayload;
              const scripted = await scriptedAgent.invoke(String(sibling.id), scriptedMessage, 'vuln', {
                includeRunMetadata: true,
                onStart: async execution => {
                  scriptedExecution = { ...execution, ownerId: String(sibling.id), emit: execution.trace };
                  scriptedAttempt = await scriptedGrader.begin(sibling.id, scriptedExecution);
                },
                onResult: async (dto, check, _execution, invocation) => {
                  scriptedInvocation = invocation;
                  await check();
                  await scriptedGrader.observe({ userId: sibling.id,
                    result: { ...dto, toolInvocation: invocation }, execution: scriptedExecution, attempt: scriptedAttempt });
                  scriptedGrade = await scriptedGrader.evaluate({ userId: sibling.id, objectiveId: item.objective,
                    message: scriptedMessage, result: { ...dto, toolInvocation: invocation }, mode: 'vuln',
                    execution: scriptedExecution, attempt: scriptedAttempt });
                },
              });
              assert.equal(provenance.totalCalls(), providerCallsBefore, 'scripted denial must make zero physical provider calls');
              assert.equal(formatterCalls, 1); assert.equal(judgeCalls, 1);
              assert.equal(scripted.run.decisionSource, 'scripted'); assert.equal(scripted.run.responseSource, 'fixture');
              assert.equal(scriptedInvocation.tool, item.tool);
              assert.equal(scriptedInvocation.params[item.queryKey], scriptedPayload);
              assert.deepEqual(judgePacket.facts, { tool_executed: true, model_decision_observed: false,
                objective_signal_detected: true, vulnerable_mode: true });
              assert.equal(judgePacket.rubric.version, expectedRubricVersion);
              assert.equal(scriptedGrade.completed, false);
              assert.equal(scriptedGrade.judgment.verdict, 'fail');
              assert.equal(scriptedGrade.judgment.errorCode, 'REQUIRED_FACTS_NOT_SATISFIED');
              assert.equal(scriptedGrade.judgment.provider, null); assert.equal(scriptedGrade.judgment.model, null);
              assert.equal(scriptedGrade.receipt.disposition, 'not_pass');
              assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
                WHERE user_id=$1 AND workshop_key=$2`, [sibling.id, item.key])).rows[0].n, 0);
              const scriptedRun = (await identityRuntime.query('SELECT decision_source,status FROM graph_runtime.runs WHERE run_id=$1',
                [scripted.run.runId])).rows[0];
              assert.deepEqual(scriptedRun, { decision_source: 'scripted', status: 'completed' });
              const positiveCalls = positiveTurns.flatMap(turn => boundedPublicCalls(provenance, turn.provenanceScope));
              caseTest.diagnostic(JSON.stringify({ family: item.family, objective: item.objective, runId,
                actor: { provider: run.provider, model: run.model, decisionSource: run.decision_source },
                judge: { provider: packetRow.result_json.provider, model: packetRow.result_json.model,
                  version: packetRow.result_json.judgeVersion }, modelCalls: positiveCalls,
                scriptedNegative: { runId: scripted.run.runId, decisionSource: 'scripted', responseSource: 'fixture',
                  controlledJudgeCalls: judgeCalls, physicalProviderCalls: 0, verdict: scriptedGrade.judgment.verdict,
                  errorCode: scriptedGrade.judgment.errorCode, disposition: scriptedGrade.receipt.disposition } }));
              qualificationReport.finalize(row.objective, { status: 'pass',
                durationMs: Math.round(performance.now() - qualificationStarted), calls: positiveCalls });
              return;
            }

            // Ordinary route admission intentionally nominates no objective. This
            // separate real-agent run explicitly evaluates the same benign tool
            // result, proving the objective's Judge negative rather than no call.
            qualificationStage = 'negative_judge';
            const negativeAgent = require(item.family === 'ARIA'
              ? '../../server/services/ariaAgentService' : '../../server/services/novaAgentService');
            const negativeGrader = require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({
              workshopKey: item.key, postgres: true,
            });
            let negativeAttempt, negativeExecution, negativeGrade, negativeInvocation;
            const negativeScope = `${item.objective}_judge_negative`;
            const negativeMessage = item.message('ordinary-unmatched-fixture');
            await provenance.withScope(negativeScope, () => negativeAgent.invoke(String(sibling.id), negativeMessage, 'vuln', {
              onStart: async execution => {
                negativeExecution = { ...execution, ownerId: String(sibling.id), emit: execution.trace };
                negativeAttempt = await negativeGrader.begin(sibling.id, negativeExecution);
              },
              onResult: async (dto, check, _execution, invocation) => {
                assert.equal(dto.toolUsed, item.tool);
                assert.equal(invocation?.params?.[item.queryKey], 'ordinary-unmatched-fixture');
                negativeInvocation = invocation;
                await check();
                await negativeGrader.observe({ userId: sibling.id,
                  result: { ...dto, toolInvocation: invocation }, execution: negativeExecution,
                  attempt: negativeAttempt });
                negativeGrade = await negativeGrader.evaluate({ userId: sibling.id, objectiveId: item.objective,
                  message: negativeMessage, result: { ...dto, toolInvocation: invocation }, mode: 'vuln',
                  execution: negativeExecution, attempt: negativeAttempt });
              },
            }));
            assert.ok(provenance.exactDecision(negativeScope, { tool: item.tool, params: negativeInvocation.params }));
            assert.equal(negativeGrade.judgment.verdict, 'fail');
            assert.equal(negativeGrade.judgment.provider, 'ollama');
            assert.equal(negativeGrade.judgment.model, 'llama3.1:8b');
            assert.equal(negativeGrade.completed, false);
            assert.equal(negativeGrade.receipt.disposition, 'not_pass');
            assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
              WHERE user_id=$1 AND workshop_key=$2`, [sibling.id, item.key])).rows[0].n, 0);

            const captureSibling = () => siblingStateDigest({ identity: identityRuntime,
              workshop: item.family === 'ARIA' ? ariaRuntime : novaRuntime, family: item.family,
              userId: sibling.id, workshopKey: item.key });
            const siblingBeforeReset = await captureSibling();
            assert.ok(siblingBeforeReset.graph_runs.count > 0 && siblingBeforeReset.graph_effects.count > 0
              && siblingBeforeReset.objective_judgments.count > 0 && siblingBeforeReset.grade_packets.count > 0,
              'reset comparison requires populated actual sibling evidence');
            qualificationStage = 'reset';
            const generationBefore = BigInt(await require('../../server/database/postgres/workshopProgressRepository')
              .createWorkshopProgressRepository(identityRuntime).getGeneration(owner.id, item.key));
            const reset = await request(base, item.path + '/reset', ownerSession.token, {});
            assert.equal(reset.response.status, 200);
            assert.equal(reset.body.success, true);
            const generationAfter = BigInt(await require('../../server/database/postgres/workshopProgressRepository')
              .createWorkshopProgressRepository(identityRuntime).getGeneration(owner.id, item.key));
            assert.equal(generationAfter, generationBefore + 1n);
            assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
              WHERE user_id=$1 AND workshop_key=$2`, [owner.id, item.key])).rows[0].n, 0);
            assert.equal((await item.stateCount(owner.id)).rows[0].n, 0);
            assert.equal((await item.stateCount(sibling.id)).rows[0].n, 1);
            const afterReset = await provenance.withScope(`${item.objective}_after_reset`, () =>
              request(base, item.path + '/chat', ownerSession.token, { userMessage: item.message('ordinary-unmatched-fixture') }));
            assert.equal(afterReset.response.status, 200);
            assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
              WHERE user_id=$1 AND workshop_key=$2`, [owner.id, item.key])).rows[0].n, 0,
              'pre-reset evidence cannot award from an unrelated post-reset turn');
            assert.deepEqual(await captureSibling(), siblingBeforeReset,
              'owner reset and post-reset chat must preserve every sibling row and immutable receipt');
            caseTest.diagnostic(JSON.stringify({ family: item.family, objective: item.objective, runId,
              actor: { provider: run.provider, model: run.model, decisionSource: run.decision_source },
              judge: { provider: packetRow.result_json.provider, model: packetRow.result_json.model,
                version: packetRow.result_json.judgeVersion }, modelCalls: positiveTurns.flatMap(turn => boundedPublicCalls(provenance, turn.provenanceScope)),
              negativeJudge: { verdict: negativeGrade.judgment.verdict, evaluationId: negativeGrade.judgment.evaluationId,
                modelCalls: boundedPublicCalls(provenance, negativeScope) },
              resetGeneration: String(generationAfter) }));
            qualificationReport.finalize(row.objective, { status: 'pass',
              durationMs: Math.round(performance.now() - qualificationStarted),
              calls: [...positiveTurns.flatMap(turn => boundedPublicCalls(provenance, turn.provenanceScope)),
                ...boundedPublicCalls(provenance, negativeScope)] });
          } catch (error) {
            const failureCode = error?.name === 'AssertionError' ? 'ASSERTION_FAILED'
              : error?.name === 'AbortError' ? 'CANCELLED'
              : error?.code === 'ETIMEDOUT' ? 'TIMEOUT' : 'EXECUTION_FAILED';
            qualificationReport.finalize(row.objective, { status: 'fail', failureStage: qualificationStage,
              failureCode, durationMs: Math.round(performance.now() - qualificationStarted) });
            throw error;
          }
        });
      }
      if (process.env.SQL_NOSQL_ROUTE_OBSERVATION_CONTROLS === '1') {
        const { SEQUENCES, qualifyObservationSequence, assertObservationProvenance } = require('../fixtures/sqlNoSqlObservationSequence');
        for (const control of SEQUENCES.filter(value => cases.some(row => row.family === value.family))) {
          await t.test(control.name, { timeout: 300000 }, async () => {
            const owner = await identity.createUser({ username: `control-${control.name}`, email: `${control.name}@fixture.invalid`, passwordHash });
            const key = control.family === 'ARIA' ? 'sql_injection_workshop' : 'nosql_injection_workshop';
            const grader = require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({workshopKey:key,postgres:true});
            const agent = require(control.family === 'ARIA' ? '../../server/services/ariaAgentService' : '../../server/services/novaAgentService');
            const priorReceipts = [], evaluationIds = [], toolReceiptKeys = [];
            const reference=control.family==='NOVA' ? await require('../fixtures/sqlNoSqlNativeReferences').readNovaNativeReferences({pool:novaRuntime,literalQuery:control.queries[0]}) : {};
            const sequence = await provenance.withScope(control.name, () => qualifyObservationSequence({agent,grader,ownerId:owner.id,item:control,
              modes:require('../../server/services/workshopModeService'),
              signal:AbortSignal.timeout(290000),inspect:async({index,dto,invocation,execution,grade})=>{
                assert.equal(verifySqlNoSqlIndependentEffect({objectiveId:control.objective,query:control.queries[index],output:dto.toolResult,ownerId:owner.id,reference}),control.completed[index], 'independent effect outcome');
                const evaluationId=grade.judgment.evaluationId;assert.ok(!evaluationIds.includes(evaluationId));evaluationIds.push(evaluationId);
                const rows=(await identityRuntime.query(`SELECT row_to_json(j)::text AS exact,j.run_id,j.generation,j.verdict,j.disposition
                  FROM workshop_platform.objective_judgments j WHERE user_id=$1 AND evaluation_id=$2`,[owner.id,evaluationId])).rows;
                assert.equal(rows.length,1);assert.equal(rows[0].run_id,execution.runId);assert.equal(String(rows[0].generation),String(execution.generation));
                const {effectKey}=require('../../server/agent-runtime/workshopGraph');
                const effect=execution.runId+':'+effectKey(index,dto.toolUsed,invocation.params);
                const receipt=(await identityRuntime.query(`SELECT effect_key,owner_key,generation,status FROM graph_runtime.effects WHERE run_id=$1 AND effect_key=$2`,[execution.runId,effect])).rows[0];
                assert.ok(receipt);assert.equal(receipt.owner_key,JSON.stringify([control.family,String(owner.id)]));assert.equal(String(receipt.generation),String(execution.generation));
                if(control.completed[index])assert.equal(receipt.status,'completed');toolReceiptKeys.push(effect);
                for(const prior of priorReceipts){const persisted=(await identityRuntime.query('SELECT row_to_json(j)::text AS exact FROM workshop_platform.objective_judgments j WHERE user_id=$1 AND evaluation_id=$2',[owner.id,prior.id])).rows[0];assert.equal(persisted.exact,prior.exact);}
                priorReceipts.push({id:evaluationId,exact:rows[0].exact});
                const credit=(await identityRuntime.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 AND objective_id=$3',[owner.id,key,control.objective])).rows[0].n;
                assert.equal(credit,control.completed[index]?1:0);
              }}));
            assert.ok(provenance.getPrivateCalls(control.name).length>0);
            assert.ok(provenance.getPrivateCalls(control.name).every(call=>call.qualified));
            assertObservationProvenance({ provenance, scope: control.name, item: control, results: sequence.results });
            assert.equal(new Set(toolReceiptKeys).size,control.queries.length);
            t.diagnostic(JSON.stringify({scope:'direct_agent_grader_observation_sequence',case:control.name,passed:true,judgments:evaluationIds.length,toolReceipts:toolReceiptKeys.length,calls:boundedPublicCalls(provenance, control.name)}));
          });
        }
      }

      if (process.env.SQL_NOSQL_ROUTE_LIFECYCLE === '1') {
        for (const family of [...new Set(cases.map(row => row.family))]) {
          await t.test(`${family}_reset_before_judge`, { timeout: 300000 }, async lifecycleTest => {
            const earnedObjectiveId = family === 'ARIA' ? 'sqli_1' : 'nosqli_1';
            // Cancellation needs a successfully completed tool effect. Native
            // SQL syntax errors retain uncertain effects, so use UNION here.
            const objectiveId = family === 'ARIA' ? 'sqli_5' : 'nosqli_3';
            const earnedPayload = SCENARIO_MATRIX.find(row => row.objective === earnedObjectiveId).payloads[0];
            const scenario = SCENARIO_MATRIX.find(row => row.objective === objectiveId);
            const cancellationOwner = await identity.createUser({ username: `lifecycle-${family}-owner`,
              email: `lifecycle-${family}-owner@fixture.invalid`, passwordHash });
            const earnedSibling = await identity.createUser({ username: `lifecycle-${family}-sibling`,
              email: `lifecycle-${family}-sibling@fixture.invalid`, passwordHash });
            const item = scenarioContract(scenario, { ariaRuntime, novaRuntime, owner: cancellationOwner });
            const createSession = async user => adapter.createSession(await identity.findCredentialById(user.id),
              { get: () => null, ip: '127.0.0.1' });
            const cancellationSession = await createSession(cancellationOwner);
            const earnedSession = await createSession(earnedSibling);
            for (const user of [cancellationOwner, earnedSibling]) {
              await identityRuntime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
                VALUES($1,$2,'vuln') ON CONFLICT(user_id,workshop_key) DO UPDATE SET mode='vuln'`, [user.id, item.key]);
            }
            const payload = item.payloads[0];
            const message = item.message(payload);
            const siblingScope = `lifecycle_${family}_earned_sibling`;
            const earned = await provenance.withScope(siblingScope, () =>
              request(base, item.path + '/chat', earnedSession.token, { userMessage: item.message(earnedPayload) }));
            assert.equal(earned.response.status, 200);
            const earnedJudgment = earned.body.judgments.find(row => row.objectiveId === earnedObjectiveId);
            assert.equal(earnedJudgment?.verdict, 'pass');
            assert.ok(earned.body.completedObjectives.includes(earnedObjectiveId));
            const earnedReceipt = (await identityRuntime.query(`SELECT j.*,r.provider AS actor_provider,r.model AS actor_model,
              r.decision_source FROM workshop_platform.objective_judgments j JOIN graph_runtime.runs r ON r.run_id=j.run_id
              WHERE j.user_id=$1 AND j.evaluation_id=$2 AND j.workshop_key=$3 AND j.objective_id=$4`,
            [earnedSibling.id, earnedJudgment.evaluationId, item.key, earnedObjectiveId])).rows[0];
            assert.equal(earnedReceipt.disposition, 'awarded');
            assert.equal(earnedReceipt.actor_provider, 'ollama'); assert.equal(earnedReceipt.actor_model, 'llama3.1:8b');
            assert.equal(earnedReceipt.decision_source, 'model');
            assert.equal(earnedReceipt.result_json.provider, 'ollama'); assert.equal(earnedReceipt.result_json.model, 'llama3.1:8b');
            const earnedInvocation = earned.body.toolObservations?.find(row => row.toolUsed === item.tool)?.invocation;
            assert.equal(earnedInvocation?.params?.[item.queryKey], earnedPayload);
            assert.ok(provenance.exactDecision(siblingScope, { tool: item.tool, params: earnedInvocation.params }));
            const siblingCompletions = async () => Number((await identityRuntime.query(`SELECT count(*) AS n
              FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2`, [earnedSibling.id, item.key])).rows[0].n);
            assert.equal(await siblingCompletions(), 1);
            const siblingSnapshot = () => siblingStateDigest({ identity: identityRuntime,
              workshop: family === 'ARIA' ? ariaRuntime : novaRuntime, family, userId: earnedSibling.id, workshopKey: item.key });
            const siblingBefore = await siblingSnapshot();
            const grader = require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({
              workshopKey: item.key, postgres: true,
            });
            const agent = require(family === 'ARIA' ? '../../server/services/ariaAgentService' : '../../server/services/novaAgentService');
            const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
            const generationBefore = BigInt(await progress.getGeneration(cancellationOwner.id, item.key));
            let gradingExecution, attempt, receiptSnapshot;
            const scope = `lifecycle_${family}_cancelled`;
            const captured = await provenance.withScope(scope, () =>
              require('../fixtures/sqlNoSqlResetQualification').qualifySqlNoSqlResetBeforeJudge({
                agent, owner: cancellationOwner.id, message, deadlineMs: 180000,
                onStart: async execution => {
                  gradingExecution = { ...execution, ownerId: String(cancellationOwner.id), emit: execution.trace };
                  attempt = await grader.begin(cancellationOwner.id, gradingExecution);
                },
                reset: async ({ execution, invocation, dto, signal }) => {
                  assert.equal(invocation.tool, item.tool); assert.equal(invocation.params[item.queryKey], payload);
                  assert.ok(dto.toolObservations?.length);
                  for (const observation of dto.toolObservations) {
                    assert.equal(observation.toolUsed, item.tool); assert.equal(observation.invocation?.params?.[item.queryKey], payload);
                  }
                  const receipts = (await identityRuntime.query(`SELECT row_to_json(e)::text AS value,e.effect_key,e.status
                    FROM graph_runtime.effects e WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3
                    ORDER BY e.effect_key`, [execution.runId, execution.ownerKey, execution.durableGeneration])).rows;
                  const { effectKey } = require('../../server/agent-runtime/workshopGraph');
                  for (const observation of dto.toolObservations) {
                    const key = `${execution.runId}:${effectKey(observation.index, observation.toolUsed, observation.invocation.params)}`;
                    assert.ok(receipts.some(row => row.effect_key === key && row.status === 'completed'), 'actual tool effect must be durable before reset');
                  }
                  receiptSnapshot = receipts.filter(row => row.effect_key.startsWith(`${execution.runId}:tool:`)).map(row => row.value);
                  assert.ok(receiptSnapshot.length > 0);
                  return request(base, item.path + '/reset', cancellationSession.token, {}, signal);
                },
                grade: ({ dto, invocation }) => grader.evaluate({ userId: cancellationOwner.id, objectiveId,
                  message, result: { ...dto, toolInvocation: invocation }, mode: 'vuln', execution: gradingExecution, attempt }),
              }));
            assert.equal(captured.resetResult.response.status, 200); assert.equal(captured.resetResult.body.success, true);
            assert.equal(captured.gradeCalls, 0); assert.equal(captured.cancelled, true); assert.equal(captured.actorError?.name, 'AbortError');
            assert.equal(captured.invocation.tool, item.tool); assert.equal(captured.invocation.params[item.queryKey], payload);
            assert.ok(provenance.exactDecision(scope, { tool: item.tool, params: captured.invocation.params }));
            const run = (await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1', [captured.runId])).rows[0];
            assert.equal(run.status, 'cancelled'); assert.equal(run.owner_key, captured.execution.ownerKey);
            assert.equal(String(run.generation), String(captured.execution.durableGeneration));
            const ownerGeneration = (await identityRuntime.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',
              [captured.execution.ownerKey])).rows[0].generation;
            assert.equal(BigInt(ownerGeneration), BigInt(captured.execution.durableGeneration) + 1n);
            assert.equal(run.provider, 'ollama'); assert.equal(run.model, 'llama3.1:8b'); assert.equal(run.decision_source, 'model');
            const retained = (await identityRuntime.query(`SELECT row_to_json(e)::text AS value FROM graph_runtime.effects e
              WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key LIKE $4 ORDER BY e.effect_key`,
            [captured.runId, captured.execution.ownerKey, captured.execution.durableGeneration, `${captured.runId}:tool:%`])).rows.map(row => row.value);
            assert.deepEqual(retained, receiptSnapshot, 'reset must retain exact completed tool receipts');
            assert.equal(BigInt(await progress.getGeneration(cancellationOwner.id, item.key)), generationBefore + 1n);
            for (const table of ['objective_judgments', 'completions']) {
              assert.equal(Number((await identityRuntime.query(`SELECT count(*) AS n FROM workshop_platform.${table}
                WHERE user_id=$1 AND workshop_key=$2`, [cancellationOwner.id, item.key])).rows[0].n), 0);
            }
            assert.deepEqual(await siblingSnapshot(), siblingBefore); assert.equal(await siblingCompletions(), 1);
            lifecycleTest.diagnostic(JSON.stringify({ lifecycle: 'reset_before_judge', family, runId: captured.runId,
              cancelled: captured.cancelled, gradeCalls: captured.gradeCalls, retainedToolEffects: retained.length,
              earnedSiblingPreserved: true, modelCalls: boundedPublicCalls(provenance, scope) }));
          });
        }
      }
      if (process.env.SQL_NOSQL_ROUTE_FIXED_SESSION === '1') {
        for (const family of [...new Set(cases.map(row => row.family))]) {
          await t.test(`${family}_fixed_mode_and_long_session`, { timeout: 1200000 }, async boundaryTest => {
            const result = await require('../fixtures/sqlNoSqlFixedSessionQualification').qualifyFixedSession({
              family, identity, adapter, passwordHash, identityRuntime,
              workshop: family === 'ARIA' ? ariaRuntime : novaRuntime,
              base, request, provenance, siblingStateDigest,
            });
            boundaryTest.diagnostic(JSON.stringify({ fixedSession: result }));
          });
        }
      }
      assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
        WHERE user_id=ANY($1::integer[]) AND workshop_key IN ('sql_injection_workshop','nosql_injection_workshop')`, [siblingIds])).rows[0].n, 0);
    } finally {
      if (qualificationReport) t.diagnostic(JSON.stringify({ objectiveReport: qualificationReport.snapshot() }));
      global.fetch = originalFetch;
      Module._load = originalLoad;
      if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      await Promise.allSettled([identityRuntime.end(), ariaRuntime.end(), novaRuntime.end()]);
      await closePostgresPools();
    }
  });
