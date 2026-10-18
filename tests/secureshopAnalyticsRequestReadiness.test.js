'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{types}=require('pg');
const {assertAnalyticsRequestReadiness}=require('../server/database/postgres/secureshopAnalyticsRequestReadiness');
test('constraint metadata projects catalog names as text arrays understood by pg',async()=>{
 const sentinel=Error('constraint projection captured');let observed;
 const fields=[['launch_id','uuid'],['scenario_id','uuid'],['generation','bigint'],['platform_owner_id','integer'],['platform_session_id','bigint'],['persona_id','integer'],['role','text'],['request_id','uuid'],['persona_session_id','uuid'],['authority_version','bigint'],['session_id','text'],['question_sha256','text'],['question','text'],['created_at','timestamp with time zone'],['redacted_at','timestamp with time zone']];
 const pool={async query(sql,args){
  if(sql.includes('current_user AS role'))return {rows:[{role:'dvaia_secureshop_agents_runtime'}]};
  if(sql.includes('has_table_privilege'))return {rows:[{allowed:['SELECT','INSERT'].includes(args[1])}]};
  if(sql.includes('FROM pg_attribute'))return {rows:fields.map(([attname,type])=>({attname,type,writable:false,attnotnull:!['question','redacted_at'].includes(attname)}))};
  observed=sql;throw sentinel;
 }};
 await assert.rejects(assertAnalyticsRequestReadiness(pool),error=>error===sentinel);
 assert.match(observed,/ARRAY\(SELECT attname::text FROM unnest\(conkey\)/);
 assert.equal(types.getTypeParser(1003)('{session_id,request_id}'),'{session_id,request_id}');
 assert.deepEqual(types.getTypeParser(1009)('{session_id,request_id}'),['session_id','request_id']);
});
