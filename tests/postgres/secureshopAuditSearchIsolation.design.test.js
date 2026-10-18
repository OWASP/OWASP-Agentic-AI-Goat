'use strict';
// Design qualification only: synthetic PostgreSQL target, no app-store routing.
const test=require('node:test'),assert=require('node:assert/strict');const {Pool}=require('pg');
test('owned SQLi target preserves UNION and timing while denying sibling and host reads',{skip:process.env.PG_AUDIT_SEARCH_DESIGN!=='yes'},async t=>{
 const url=new URL(process.env.PG_AUDIT_SEARCH_URL);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/dvaia_test_audit_search_[a-f0-9]+$/);assert.equal(url.username,'search_learner');
 const pool=new Pool({connectionString:url.href,max:1});t.after(()=>pool.end());
 const sql=username=>`SELECT id,actor,action,target,params_json,ts FROM owned_a.audit_events WHERE actor LIKE '%${username}%' OR target LIKE '%${username}%' ORDER BY ts DESC LIMIT 200`;
 const query=async text=>{const c=await pool.connect();try{await c.query('BEGIN READ ONLY');await c.query("SET LOCAL statement_timeout='300ms'");return(await c.query({text,values:[],queryMode:'extended'})).rows;}finally{await c.query('ROLLBACK');c.release();}};
 assert.equal((await query(sql('ordinary'))).length,1);
 const injection="' UNION SELECT id,secret,'synthetic-secret','owned', '{}'::jsonb,now() FROM owned_a.teaching_secrets --";
 const rows=await query(sql(injection));assert.ok(rows.some(row=>row.actor==='OWNED_SYNTHETIC_CANARY_A'));
 await assert.rejects(query(sql("' UNION SELECT id,secret,'sibling','owned','{}'::jsonb,now() FROM owned_b.teaching_secrets --")),/permission denied/);
 await assert.rejects(query("SELECT pg_read_file('/etc/passwd')"),/permission denied/);
 await assert.rejects(query('SET ROLE search_sibling'),/permission denied/);
 await assert.rejects(query('DELETE FROM owned_a.audit_events'),/read-only|permission denied/);
 await assert.rejects(query('SELECT 1; SELECT 2'),/multiple commands/);
 const timing=await query("SELECT pg_sleep(0.05), 'actual-postgres-timing' AS marker");assert.equal(timing[0].marker,'actual-postgres-timing');
 await assert.rejects(query('SELECT pg_sleep(3)'),/statement timeout/);
 // A username fence inside the same injectable WHERE is not isolation.
 const bypass=await query("SELECT id FROM owned_a.audit_events WHERE actor='ordinary' AND target LIKE '%' OR true --%'");assert.equal(bypass.length,2);
 console.log('OWNED_AUDIT_SEARCH_DESIGN_NATIVE_UNION_TIMING_AND_ISOLATION_PASSED');
});
