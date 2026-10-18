'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createTraceBuffer}=require('../server/services/secureshop/traceBuffer');
test('trace retry preserves event identities and concurrent flush never drains an unwritten batch',async()=>{
 let fail=true,release;const delivered=[];const pause=new Promise(r=>release=r);
 const buffer=createTraceBuffer(async rows=>{if(fail){fail=false;throw Error('offline');}await pause;delivered.push(...rows);});
 const first=buffer.record({session_id:'fixture',step:1});await assert.rejects(buffer.flush(),/offline/);assert.equal(buffer.pending,1);
 const flush=buffer.flush();assert.equal(buffer.flush(),flush);buffer.record({session_id:'fixture',step:2});release();await flush;
 assert.equal(delivered.length,2);assert.equal(delivered[0].event_id,first.event_id);assert.equal(buffer.pending,0);
});
test('trace queue bounds fail explicitly rather than silently dropping pending events',()=>{
 const buffer=createTraceBuffer(async()=>{},{maxPending:1});buffer.record({step:1});assert.throws(()=>buffer.record({step:2}),/queue full/);assert.equal(buffer.pending,1);
});

test('PostgreSQL-selected runtime imports never load SQLite or open a pool',async()=>{
 const {execFile}=require('node:child_process'),{promisify}=require('node:util');
 const script=`process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.WORKSHOP_DATABASE_ENGINE='postgres';const M=require('node:module'),load=M._load;M._load=function(name,p,m){if(['sqlite3','better-sqlite3'].includes(name))throw Error('forbidden SQLite');return load.call(this,name,p,m);};for(const name of ['sessionStore','trace','toolAcl','toolManifest','supervisors/policyLoader'])require('./server/services/secureshop/'+name);require('./agent-host/shared/trace');require('./agent-host/agents/audit/tools');require('./agent-host/agents/mcp-registry/tools');const db=require('./agent-host/shared/db');for(const name of ['getSecureshopDb','getAgentsDb']){let error;try{db[name]();}catch(cause){error=cause;}if(!error||error.message!==db.PG_ONLY_MESSAGE)throw Error('sync store unexpectedly available');}`;
 await promisify(execFile)(process.execPath,['--require','./scripts/lib/isolated-database-access-guard.cjs','-e',script],
  {cwd:require('node:path').join(__dirname,'..')});
});
