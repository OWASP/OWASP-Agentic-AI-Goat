'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopRevisionStore}=require('../server/database/postgres/workshopRevisionRepository');
function fixture(){
 const calls=[],rows=[];let fail;
 const pool={async query(sql,args=[]){calls.push({sql,args});if(fail)throw fail;
  if(sql.startsWith('SELECT 1'))return{rows:[]};
  if(sql.startsWith('INSERT INTO')){let row=rows.find(r=>r.scope_type===args[0]&&r.scope_key===args[1]&&r.category===args[2]);if(row)row.revision++;else rows.push(row={scope_type:args[0],scope_key:args[1],category:args[2],revision:1});return{rows:[{revision:row.revision}]};}
  if(sql.startsWith('SELECT scope_type'))return{rows:rows.filter(r=>r.scope_type==='global'||r.scope_type==='user'&&r.scope_key===args[0]||r.scope_type==='workshop'&&(args[1]||args[2].includes(r.scope_key)))};
  if(sql.startsWith('SELECT md5('))return{rows:[{digest:'opaque-admin-progress'}]};
  assert.fail('Unexpected query: '+sql);
 }};
 return{store:createWorkshopRevisionStore(pool),calls,rows,fail(error){fail=error;}};
}
test('PostgreSQL initialization checks existing migrated storage without runtime DDL and surfaces failures',async()=>{
 const f=fixture();await f.store.initialize();await f.store.initialize();assert.equal(f.calls.length,2);assert(f.calls.every(c=>c.sql==='SELECT 1 FROM workshop_platform.revisions LIMIT 0'));
 f.fail(Error('Controlled storage unavailable'));await assert.rejects(f.store.initialize(),/Controlled storage unavailable/);
});
test('sequential revision bumps expose increasing revisions through parameterized PostgreSQL UPSERT',async()=>{
 const f=fixture();for(let n=1;n<=12;n++)assert.equal(await f.store.bump({scopeType:'global',scopeKey:'*',category:'admin_visibility'}),n);
 assert.match(f.calls[0].sql,/ON CONFLICT\(scope_type,scope_key,category\) DO UPDATE SET revision=workshop_platform.revisions.revision\+1/);
 assert.deepEqual(f.calls[0].args,['global','*','admin_visibility']);assert.equal((await f.store.getSnapshot({workshopKeys:[]})).global.admin_visibility,12);
});
test('owner and requested workshop scopes stay separate while wildcard reads include every workshop',async()=>{
 const f=fixture();for(const [scopeType,scopeKey,category]of[['global','*','server_restart'],['workshop','mcp_workshop','config'],['workshop','sql_injection_workshop','config'],['user','101','progress'],['user','202','progress']])await f.store.bump({scopeType,scopeKey,category});
 let s=await f.store.getSnapshot({userId:101,workshopKeys:['mcp_workshop','mcp_workshop']});assert.deepEqual(JSON.parse(JSON.stringify(s)),{global:{server_restart:1},workshops:{mcp_workshop:{config:1}},user:{progress:1}});assert.deepEqual(f.calls.at(-1).args,['101',false,['mcp_workshop']]);
 s=await f.store.getSnapshot({userId:303,workshopKeys:['*']});assert.deepEqual(Object.keys(s.workshops).sort(),['mcp_workshop','sql_injection_workshop']);assert.deepEqual(Object.keys(s.user),[]);assert.deepEqual(f.calls.at(-1).args,['303',true,[]]);
 assert.match(f.calls.at(-1).sql,/scope_type='user' AND scope_key=\$1/);
});
test('invalid scopes/categories/owner/workshop keys fail before querying',async()=>{
 const f=fixture();for(const change of [{scopeType:'account',scopeKey:'101',category:'progress'},{scopeType:'global',scopeKey:'wrong',category:'progress'},{scopeType:'user',scopeKey:'*',category:'progress'},{scopeType:'workshop',scopeKey:'__proto__',category:'progress'},{scopeType:'user',scopeKey:'101',category:'constructor'},{scopeType:'user',scopeKey:'101',category:'bad category'}])await assert.rejects(f.store.bump(change));
 await assert.rejects(f.store.getSnapshot({userId:-1}),{code:'AUTH_REQUIRED'});await assert.rejects(f.store.getSnapshot({workshopKeys:['prototype']}),{code:'BAD_REQUEST'});assert.deepEqual(f.calls,[]);
});
test('database-controlled prototype keys retain null dictionaries and ordinary JSON response shape',async()=>{
 const f=fixture();f.rows.push({scope_type:'workshop',scope_key:'__proto__',category:'constructor',revision:7},{scope_type:'global',scope_key:'*',category:'__proto__',revision:2},{scope_type:'user',scope_key:'101',category:'prototype',revision:3});
 const s=await f.store.getSnapshot({userId:101,workshopKeys:['*']});for(const dictionary of[s.global,s.workshops,s.user,s.workshops.__proto__])assert.equal(Object.getPrototypeOf(dictionary),null);
 assert.equal({}.constructor,Object);assert.deepEqual(JSON.parse(JSON.stringify(s)),JSON.parse('{"global":{"__proto__":2},"workshops":{"__proto__":{"constructor":7}},"user":{"prototype":3}}'));
});
test('admin progress digest is opt-in and scans ordered owner revisions and student lifecycle',async()=>{
 const f=fixture();
 await f.store.bump({scopeType:'user',scopeKey:'101',category:'workshop_progress'});
 const student=await f.store.getSnapshot({userId:101,workshopKeys:['*']});
 assert.equal(student.adminProgress,undefined);
 assert.equal(f.calls.filter(c=>c.sql.startsWith('SELECT md5(')).length,0);
 const admin=await f.store.getSnapshot({userId:5,workshopKeys:['*'],includeAdminProgress:true});
 assert.equal(admin.adminProgress,'opaque-admin-progress');
 const sql=f.calls.at(-1).sql;
 assert.match(sql,/r.scope_type='user' AND r.category IN \('workshop_progress','workshop_time'\)/);
 assert.match(sql,/ORDER BY r.scope_key,r.category/);
 assert.match(sql,/FROM identity.users u WHERE u.role IN \('student','user'\)/);
 assert.match(sql,/ORDER BY u.id/);
 assert.doesNotMatch(sql,/SELECT \*/);
});
