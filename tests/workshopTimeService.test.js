'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),path=require('node:path');
const {createWorkshopProgressRepository}=require('../server/database/postgres/workshopProgressRepository');
function fixture(){
 let rows=[{id:1,user_id:1,workshop_key:'direct_prompt_injection',last_heartbeat:new Date(1000000),duration_seconds:0}],revisions=0,saved,fail=false;const calls=[];
 const query=async(sql,args=[])=>{calls.push({sql,args});if(sql==='BEGIN'){saved={rows:structuredClone(rows),revisions};return{rows:[]};}if(sql==='ROLLBACK'){rows=saved.rows;revisions=saved.revisions;return{rows:[]};}if(sql==='COMMIT')return{rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:args[0]==='direct_prompt_injection'?[{workshop_key:args[0]}]:[]};
  if(sql.startsWith('INSERT INTO workshop_platform.user_state'))return{rows:[]};if(sql.startsWith('SELECT * FROM workshop_platform.user_state'))return{rows:[{generation:4}]};
  if(sql.startsWith('SELECT clock_timestamp'))return{rows:[{now:new Date(1030000)}]};
  if(sql.startsWith('SELECT * FROM workshop_platform.time_tracking'))return{rows:rows.filter(r=>r.user_id===args[0]&&r.workshop_key===args[1]).slice(-1)};
  if(sql.startsWith('UPDATE workshop_platform.time_tracking')){const r=rows.find(r=>r.id===args[2]);r.last_heartbeat=new Date(args[0]);r.duration_seconds+=args[1];return{rows:[]};}
  if(sql.startsWith('INSERT INTO workshop_platform.time_tracking')){rows.push({id:rows.length+1,user_id:args[0],workshop_key:args[1],last_heartbeat:new Date(args[2]),duration_seconds:0});return{rows:[]};}
  if(sql.startsWith('INSERT INTO workshop_platform.revisions')){if(fail)throw Error('Controlled revision failure');revisions++;return{rows:[{revision:revisions}]};}assert.fail('Unexpected query: '+sql);
 };
 return{service:createWorkshopProgressRepository({query,connect:async()=>({query,release(){}})}),calls,rows:()=>rows,revisions:()=>revisions,fail(){fail=true;}};
}
test('duplicate sequential heartbeat counts one interval using owner/workshop row admission',async()=>{
 const f=fixture();assert.deepEqual(await f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',now:1030}),{added:30,newSession:false});assert.deepEqual(await f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',now:1030}),{added:0,newSession:false});assert.equal(f.rows()[0].duration_seconds,30);assert.equal(f.revisions(),1);
 assert.match(f.calls.find(c=>c.sql.startsWith('SELECT * FROM workshop_platform.user_state')).sql,/FOR UPDATE/);assert.deepEqual(f.calls.find(c=>c.sql.startsWith('SELECT * FROM workshop_platform.time_tracking')).args,[1,'direct_prompt_injection']);
});
test('stale clocks never regress time and exact 120-second gap creates a new session',async()=>{
 const f=fixture();assert.deepEqual(await f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',now:990}),{added:0,newSession:false});assert.deepEqual(await f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',now:1120}),{added:0,newSession:true});assert.equal(f.rows().length,2);assert.equal(f.rows()[0].duration_seconds,0);
});
test('absent clock reads PostgreSQL time and another owner receives a distinct zero-duration session',async()=>{
 const f=fixture();assert.equal((await f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection'})).added,30);assert(f.calls.some(c=>c.sql==='SELECT clock_timestamp() AS now'));await f.service.recordHeartbeat({userId:2,workshopKey:'direct_prompt_injection',now:1030});assert.equal(f.rows()[0].duration_seconds,30);assert.equal(f.rows()[1].user_id,2);assert.equal(f.rows()[1].duration_seconds,0);
});
test('unknown workshop, invalid owner and stale generation reject without time writes',async()=>{
 const f=fixture();await assert.rejects(f.service.recordHeartbeat({userId:null,workshopKey:'direct_prompt_injection'}),{code:'AUTH_REQUIRED'});await assert.rejects(f.service.recordHeartbeat({userId:1,workshopKey:'unknown'}),{code:'NOT_FOUND'});await assert.rejects(f.service.recordHeartbeat({userId:1,workshopKey:'prototype'}),{code:'BAD_REQUEST'});await assert.rejects(f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',expectedGeneration:3}),{code:'STALE_GENERATION'});assert(!f.calls.some(c=>/^(INSERT INTO|UPDATE) workshop_platform.time_tracking/.test(c.sql)));
});
test('revision failure rolls back controlled elapsed-time mutation without acknowledging success',async()=>{
 const f=fixture();f.fail();await assert.rejects(f.service.recordHeartbeat({userId:1,workshopKey:'direct_prompt_injection',now:1030}),/Controlled revision failure/);assert.equal(f.rows()[0].duration_seconds,0);assert.equal(f.rows()[0].last_heartbeat.getTime(),1000000);assert(f.calls.some(c=>c.sql==='ROLLBACK'));assert(!f.calls.some(c=>c.sql==='COMMIT'));
});
test('heartbeat HTTP handler uses verified self identity and maps validation errors', async () => {
  const handlerPath = path.resolve(__dirname, '../server/routes/workshopTimeHandlers.js');
  const databaseLoads = [];
  const originalLoad = Module._load;
  Module._load = function guardDatabaseLoads(request, parent, isMain) {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (resolved.includes(`${path.sep}server${path.sep}database${path.sep}`)) {
      databaseLoads.push(resolved);
      throw new Error(`focused heartbeat handler loaded a database module: ${resolved}`);
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  let createWorkshopTimeHandlers;
  try {
    delete require.cache[handlerPath];
    ({ createWorkshopTimeHandlers } = require(handlerPath));
  } finally {
    Module._load = originalLoad;
    delete require.cache[handlerPath];
  }
  assert.deepEqual(databaseLoads, []);
  const writes = [];
  const handlers = createWorkshopTimeHandlers({
    timeService: {
      recordHeartbeat: async (input) => {
        writes.push(input);
        if (input.workshopKey === 'ghost') {
          throw Object.assign(new Error('Unknown workshop key'), { statusCode: 400, field: 'workshopKey' });
        }
        return { added: 12, newSession: false };
      },
    },
    now: () => 1030,
  });
  const invoke = (req) => new Promise((resolve, reject) => {
    let status = 200;
    const res = {
      status(code) { status = code; return res; },
      json(body) { resolve({ status, body }); },
    };
    Promise.resolve(handlers.recordHeartbeat(req, res)).catch(reject);
  });

  assert.equal((await invoke({ body: { workshopKey: 'direct_prompt_injection' } })).status, 401);
  assert.equal((await invoke({ user: { id: 1 }, body: { workshopKey: 'ghost' } })).status, 400);
  const accepted = await invoke({ user: { id: 1 }, body: { workshopKey: 'direct_prompt_injection' } });
  assert.deepEqual(accepted, { status: 200, body: { success: true, added: 12, newSession: false } });
  assert.deepEqual(writes, [
    { userId: 1, workshopKey: 'ghost', now: 1030 },
    { userId: 1, workshopKey: 'direct_prompt_injection', now: 1030 },
  ]);
});

test('deprecated arbitrary-user progress route is gone for every caller', async () => {
  const { retireArbitraryProgressMutation: handler } = require('../server/routes/workshopProgressIntegrityHandlers');
  const response = await new Promise((resolve, reject) => {
    let status = 200;
    const res = { status(code) { status = code; return res; }, json(body) { resolve({ status, body }); } };
    Promise.resolve(handler({ user: { id: 1 }, params: { userId: '1', challengeId: 'xss_workshop' }, body: {} }, res)).catch(reject);
  });
  assert.equal(response.status, 410);
  assert.equal(response.body.code, 'ARBITRARY_PROGRESS_MUTATION_RETIRED');
});
