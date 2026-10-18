'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopModeRepository,createWorkshopRevisionStore}=require('../server/database/postgres/workshopRevisionRepository');
function fixture(){
 let modes=new Map(),revisions=new Map(),saved,failRevision=false;const calls=[];
 const query=async(sql,args=[])=>{calls.push({sql,args});
  if(sql==='BEGIN'){saved={modes:new Map(modes),revisions:new Map(revisions)};return{rows:[]};}if(sql==='ROLLBACK'){modes=saved.modes;revisions=saved.revisions;return{rows:[]};}if(sql==='COMMIT'||sql.startsWith('SELECT 1'))return{rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:[{workshop_key:args[0],catalog_active:true}]};
  if(sql.startsWith('INSERT INTO workshop_platform.user_state'))return{rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.user_state'))return{rows:[{generation:0}]};
  if(sql.startsWith('SELECT mode')){const mode=modes.get(args[0]+':'+args[1]);return{rows:mode?[{mode}]:[]};}
  if(sql.startsWith('INSERT INTO workshop_platform.user_modes')){modes.set(args[0]+':'+args[1],args[2]);return{rows:[]};}
  if(sql.startsWith('INSERT INTO workshop_platform.revisions')){if(failRevision)throw Error('Controlled revision failure');const k=args.join(':');const n=(revisions.get(k)||0)+1;revisions.set(k,n);return{rows:[{revision:n}]};}
  if(sql.startsWith('SELECT scope_type'))return{rows:[...revisions].filter(([k])=>k.split(':')[1]===args[0]).map(([k,revision])=>{const[scope_type,scope_key,category]=k.split(':');return{scope_type,scope_key,category,revision};})};
  assert.fail('Unexpected query: '+sql);
 };
 const pool={query,connect:async()=>({query,release(){}})};return{modes:createWorkshopModeRepository(pool),revisions:createWorkshopRevisionStore(pool),calls,failRevision(){failRevision=true;}};
}
test('PostgreSQL mode readiness is idempotent; canonical defaults and stored modes isolate owner and workshop',async()=>{
 const f=fixture();await f.modes.initialize();await f.modes.initialize();assert(f.calls.every(c=>c.sql==='SELECT 1 FROM workshop_platform.user_modes LIMIT 0'));
 await f.modes.setMode({userId:11,workshopKey:'sql_injection_workshop',mode:'vuln'});await f.modes.setMode({userId:11,workshopKey:'nosql_injection_workshop',mode:'fixed'});
 assert.equal(await f.modes.getMode({userId:11,workshopKey:'sql_injection_workshop'}),'vuln');assert.equal(await f.modes.getMode({userId:22,workshopKey:'sql_injection_workshop'}),'fixed');assert.equal(await f.modes.getMode({userId:22,workshopKey:'sensitive_info_disclosure'}),'vulnerable');
 assert.equal(await f.modes.getMode({userId:11,workshopKey:'nosql_injection_workshop'}),'fixed');
});
test('changed mode writes its private revision in one transaction; unchanged state never bumps',async()=>{
 const f=fixture(),input={userId:11,workshopKey:'sql_injection_workshop',mode:'vuln'};
 assert.deepEqual(await f.modes.setMode(input),{mode:'vuln',changed:true});assert.deepEqual(await f.modes.setMode(input),{mode:'vuln',changed:false});
 assert.equal((await f.revisions.getSnapshot({userId:11})).user.workshop_mode,1);assert.equal((await f.revisions.getSnapshot({userId:22})).user.workshop_mode,undefined);
 const firstCommit=f.calls.findIndex(c=>c.sql==='COMMIT'),write=f.calls.findIndex(c=>c.sql.startsWith('INSERT INTO workshop_platform.user_modes')),revision=f.calls.findIndex(c=>c.sql.startsWith('INSERT INTO workshop_platform.revisions'));assert(write>0&&revision>write&&firstCommit>revision);
 assert.equal(f.calls.filter(c=>c.sql.startsWith('INSERT INTO workshop_platform.revisions')).length,1);
});
test('revision failure rolls back the controlled mode transaction and rejects instead of reporting changed success',async()=>{
 const f=fixture();f.failRevision();await assert.rejects(f.modes.setMode({userId:11,workshopKey:'sql_injection_workshop',mode:'vuln'}),/Controlled revision failure/);
 assert(f.calls.some(c=>c.sql==='ROLLBACK'));assert(!f.calls.some(c=>c.sql==='COMMIT'));assert.equal(await f.modes.getMode({userId:11,workshopKey:'sql_injection_workshop'}),'fixed');assert.deepEqual(Object.keys((await f.revisions.getSnapshot({userId:11})).user),[]);
});
test('workshop-specific enum and owner validation reject invalid mode writes without mode/revision effects',async()=>{
 const f=fixture();await assert.rejects(f.modes.setMode({userId:11,workshopKey:'sql_injection_workshop',mode:'vulnerable'}),{code:'BAD_REQUEST'});await assert.rejects(f.modes.setMode({userId:-1,workshopKey:'sql_injection_workshop',mode:'vuln'}),{code:'AUTH_REQUIRED'});
 assert(!f.calls.some(c=>/INSERT INTO workshop_platform\.(user_modes|revisions)/.test(c.sql)));
});
