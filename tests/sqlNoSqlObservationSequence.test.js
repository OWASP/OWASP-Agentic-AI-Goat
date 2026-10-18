'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {SEQUENCES,qualifyObservationSequence}=require('./fixtures/sqlNoSqlObservationSequence');
function fixture({wrongQuery=false,early=false}={}){
 const execution={runId:'owned-run',trace:()=>{}},attempt={owned:true};let evaluations=0;
 const item=SEQUENCES[1];
 return {modes:{setMode:async()=>{},getMode:async()=>'vuln'},item,ownerId:1,inspect:async({index,attempt:got})=>{assert.equal(got,attempt);assert.equal(index,evaluations-1);},
 agent:{invoke:async(_id,_message,_mode,options)=>{await options.onStart(execution);const toolObservations=item.queries.slice(0,early?1:2).map(query=>({toolUsed:'search_papers',toolResult:{realFixture:true},invocation:{params:{query:wrongQuery?'fabricated':query}}}));await options.onResult({toolObservations},async()=>{},execution);}},
 grader:{begin:async()=>attempt,observe:async()=>{},evaluate:async()=>{const completed=evaluations++===1;return {completed,judgment:{verdict:completed?'pass':'fail',provider:'ollama',model:'llama3.1:8b'}};}}};
}
test('one execution/attempt grades failed then successful actual callback observations',async()=>{const result=await qualifyObservationSequence(fixture());assert.equal(result.results.length,2);});
test('incomplete or substituted tool sequence cannot qualify',async()=>{await assert.rejects(qualifyObservationSequence(fixture({wrongQuery:true})));await assert.rejects(qualifyObservationSequence(fixture({early:true})));});
test('run mismatch rejects before grading and extra effects cannot qualify', async () => {
  const wrong = fixture();
  wrong.agent.invoke = async (_id, _message, _mode, options) => {
    await options.onStart({ runId: 'expected' });
    await options.onResult({ toolObservations: [{ toolUsed: 'search_papers', invocation: { params: { query: wrong.item.queries[0] } } }] }, async () => {}, { runId: 'foreign' });
  };
  await assert.rejects(qualifyObservationSequence(wrong));
  const extra = fixture();
  extra.agent.invoke = async (_id, _message, _mode, options) => {
    const execution = { runId: 'owned' };await options.onStart(execution);
    const observations = [...extra.item.queries, extra.item.queries[1]].map(query => ({ toolUsed: 'search_papers', invocation: { params: { query } } }));
    await options.onResult({ toolObservations: observations }, async () => {}, execution);
  };
  await assert.rejects(qualifyObservationSequence(extra), /unexpected extra effect/);
});
test('failure after first negative preserves observed no-credit receipt and rejects the sequence', async () => {
  const value = fixture();let first;
  value.inspect = async result => { first = result.grade;throw Error('controlled persistence boundary failure'); };
  await assert.rejects(qualifyObservationSequence(value), /controlled persistence/);
  assert.equal(first.completed, false);assert.equal(first.judgment.verdict, 'fail');
});
test('each observation receives a distinct evidence index within the same run', async () => {
  const value = fixture(), indexes = [], evidenceKeys = new Set();
  value.grader.observe = async ({ execution, observationIndex }) => {
    indexes.push(observationIndex);
    const key = `${execution.runId}:${observationIndex}`;
    assert.equal(evidenceKeys.has(key), false, 'observation evidence keys must not collide');
    evidenceKeys.add(key);
  };
  await qualifyObservationSequence(value);
  assert.deepEqual(indexes, [0, 1]);
  assert.equal(evidenceKeys.size, 2);
});

test('canonical service persists fixed-default control owner mode before actor admission', async () => {
  const { createWorkshopModeService } = require('../server/services/workshopModeService');
  for (const item of SEQUENCES) {
    const value = fixture(), rows = new Map(), events = [];
    value.item = item;
    value.modes = createWorkshopModeService({
      initialize: async () => {},
      getMode: async ({ userId, workshopKey, defaultMode }) => rows.get(`${userId}:${workshopKey}`) || defaultMode,
      setMode: async ({ userId, workshopKey, mode }) => { events.push('persist');rows.set(`${userId}:${workshopKey}`, mode); },
    });
    const workshopKey = item.family === 'ARIA' ? 'sql_injection_workshop' : 'nosql_injection_workshop';
    assert.equal(await value.modes.getMode({ userId: value.ownerId, workshopKey }), 'fixed');
    value.agent.invoke = async (id, _message, mode) => {
      events.push('invoke');
      assert.equal(await value.modes.getMode({ userId: id, workshopKey }), mode);
      throw Error('controlled stop after admission check');
    };
    await assert.rejects(qualifyObservationSequence(value), /controlled stop/);
    assert.deepEqual(events, ['persist', 'invoke']);
    assert.equal(rows.size, 1);
  }
});
test('failed or ineffective mode persistence prevents any actor or grader call', async () => {
  for (const fails of [true, false]) {
    const value = fixture();let calls = 0;
    value.modes = { setMode: async () => { if (fails) throw Error('controlled write failure'); }, getMode: async () => 'fixed' };
    value.agent.invoke = value.grader.begin = async () => { calls++; };
    await assert.rejects(qualifyObservationSequence(value), fails ? /controlled write failure/ : /canonical mode/);
    assert.equal(calls, 0);
  }
});

test('native parent timeout reserves all three optional observation controls', () => {
  const source = require('node:fs').readFileSync(require('node:path').join(__dirname, 'postgres/sqlNoSqlRoute.integration.test.js'), 'utf8');
  const expression = source.match(/skip: !enabled, timeout: (.*?) \}, async t =>/)[1];
  const timeout = env => require('node:vm').runInNewContext(expression, { process: { env } });
  for (const extras of [{}, { SQL_NOSQL_ROUTE_LIFECYCLE: '1', SQL_NOSQL_ROUTE_FIXED_SESSION: '1' }]) {
    assert.equal(timeout({ ...extras, SQL_NOSQL_ROUTE_OBSERVATION_CONTROLS: '1' }) - timeout(extras), 900000);
    assert.equal(timeout({ ...extras, SQL_NOSQL_ROUTE_OBSERVATION_CONTROLS: '0' }), timeout(extras));
  }
});
test('nullable optional filters preserve complete invocation provenance; non-null filters reject before grading', async () => {
  const { assertObservationProvenance } = require('./fixtures/sqlNoSqlObservationSequence');
  for (const family of ['ARIA', 'NOVA']) {
    const item = SEQUENCES.find(row => row.family === family);
    const optional = family === 'ARIA' ? { maxPrice: null } : { topic: null, year: null };
    const tool = family === 'ARIA' ? 'search_products' : 'search_papers';
    const queryKey = family === 'ARIA' ? 'searchTerm' : 'query';
    for (const filter of [null, ...Object.keys(optional)]) {
      const value = fixture();value.item = item;let graded = 0;
      value.inspect = async () => {};
      value.grader.evaluate = async () => {
        const completed = item.completed[graded++];
        return { completed, judgment: { verdict: completed ? 'pass' : 'fail', provider: 'ollama', model: 'llama3.1:8b' } };
      };
      value.agent.invoke = async (_id, _message, _mode, options) => {
        const execution = { runId: 'owned' };await options.onStart(execution);
        const toolObservations = item.queries.map(query => ({ toolUsed: tool, toolResult: {}, invocation: {
          params: { [queryKey]: query, ...optional, ...(filter ? { [filter]: filter === 'topic' ? 'filtered' : 2024 } : {}) },
        } }));
        await options.onResult({ toolObservations }, async () => {}, execution);
      };
      if (filter) {
        await assert.rejects(qualifyObservationSequence(value), /unexpected non-null/);
        assert.equal(graded, 0);
      } else {
        const result = await qualifyObservationSequence(value);let compared = 0;
        const provenance = { exactDecision: (scope, decision) => {
          assert.equal(scope, 'owned-scope');assert.equal(decision.tool, tool);
          assert.strictEqual(decision.params, result.results[compared++].invocation.params);
          for (const key of Object.keys(optional)) assert.equal(Object.hasOwn(decision.params, key), true);
          return true;
        } };
        assertObservationProvenance({ provenance, scope: 'owned-scope', item, results: result.results });
        assert.equal(compared, item.queries.length);
        assert.throws(() => assertObservationProvenance({ provenance: { exactDecision: () => false }, scope: 'owned-scope', item, results: result.results }), /complete observed/);
      }
    }
  }
});
test('ordered user request preserves each separately JSON-encoded literal without selecting model output', async () => {
  for (const item of SEQUENCES) {
    const value = fixture();value.item = item;
    value.agent.invoke = async (_owner, message, mode) => {
      const noun = item.family === 'ARIA' ? 'products' : 'papers';
      const key = item.family === 'ARIA' ? 'searchTerm' : 'query';
      const pattern = new RegExp(`(?:First|Then) search ${noun} with ${key} ("(?:[^"\\\\]|\\\\.)*")\\.`, 'g');
      const literals = [...message.matchAll(pattern)].map(match => JSON.parse(match[1]));
      assert.deepEqual(literals.map(text => Buffer.from(text)), item.queries.map(text => Buffer.from(text)));
      assert.ok(message.startsWith('First search '));
      assert.equal(message.includes('Then search '), item.queries.length === 2);
      assert.match(message, /even if the first returns an error or no results/);
      assert.ok(message.includes(item.family === 'ARIA' ? 'Leave maxPrice unset' : 'Leave topic and year unset'));
      assert.equal(mode, 'vuln');
      throw Error('controlled stop after request inspection');
    };
    await assert.rejects(qualifyObservationSequence(value), /controlled stop after request inspection/);
  }
});
