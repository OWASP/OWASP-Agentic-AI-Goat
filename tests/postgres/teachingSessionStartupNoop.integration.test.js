'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process'),{createHash}=require('node:crypto');
test('current sixteen-store canonical initializer preserves every seeded row and ledger on second run',{skip:process.env.TEACHING_STARTUP_NOOP!=='1',timeout:120000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const {requiredStoreManifest}=require('../../db/postgres/initialize-application');
 for(const store of requiredStoreManifest)for(const key of [store.runtimeVariable,store.migrationVariable]){const url=new URL(process.env[key]);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,'/owasp_ai_goat_test_full_backend_'+store.schema);}
 const initialize=()=>{const result=spawnSync(process.execPath,['db/postgres/initialize-application.js'],{cwd:process.cwd(),env:process.env,encoding:'utf8',timeout:60000});assert.equal(result.status,0,result.stderr);};
 const snapshot=async()=>{const {Pool}=require('pg'),result={};for(const store of requiredStoreManifest){const pool=new Pool({connectionString:process.env[store.migrationVariable],max:1});try{const tables=(await pool.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY schemaname,tablename")).rows;for(const table of tables){const quote=value=>'"'+value.replaceAll('"','""')+'"';const rows=(await pool.query(`SELECT to_jsonb(t)::text AS row FROM ${quote(table.schemaname)}.${quote(table.tablename)} t ORDER BY to_jsonb(t)::text`)).rows;result[store.schema+'.'+table.schemaname+'.'+table.tablename]={rows:rows.length,sha256:createHash('sha256').update(JSON.stringify(rows)).digest('hex')};}}finally{await pool.end();}}return result;};
 initialize();const before=await snapshot();initialize();const after=await snapshot();assert.deepEqual(after,before);
 fs.writeFileSync(path.join(path.dirname(process.env.OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT),'initializer-noop.json'),JSON.stringify({passed:true,stores:requiredStoreManifest.length,tables:Object.keys(before).length,snapshots:before},null,2),{mode:0o600});
});
