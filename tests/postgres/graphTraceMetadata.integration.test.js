'use strict';
const test=require('node:test'),assert=require('node:assert/strict');const{Pool}=require('pg');
test('native graph metadata accepts bounded judge fields and rejects unknown/raw fields',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_GRAPH_TEST_RUNTIME_URL},async()=>{
 const pool=new Pool({connectionString:process.env.PG_GRAPH_TEST_RUNTIME_URL}),migration=new Pool({connectionString:process.env.PG_GRAPH_TEST_MIGRATION_URL});
 try{await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(pool,migration);const id=require('node:crypto').randomUUID(),owner=JSON.stringify(['trace-test',id]);await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[owner]);await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')",[id,owner]);
 const insert=metadata=>pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,1,'judge_validate','decision',$3)",[id,owner,JSON.stringify(metadata)]);
 for(const data of [{unknown:true},{judgeVersion:{raw:'bad'}},{judgeVersion:'x'.repeat(161)}])await assert.rejects(insert(data),{code:'23514'});
 await insert({tool:'search_products',judgeVersion:'grounded-v8',judgePolicyDigest:'a'.repeat(64),contextTokens:8192,verdict:'pass'});
 }finally{await pool.end();await migration.end();}
});
