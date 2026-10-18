'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAnalyticsModeRepository}=require('../server/database/postgres/secureshopAnalyticsModeRepository');
test('effect-time scope is one read-only statement and changes with the canonical revision',async()=>{
 let revision='2',exists=true;const queries=[];
 const repo=createAnalyticsModeRepository({connect(){throw Error('must not acquire owner transaction');},async query(sql,args){queries.push(sql);assert.deepEqual(args,[7,'secureshop_agent_security']);return {rows:exists?[{generation:0,mode:'fixed',stamp:'same',revision}]:[]};}});
 const first=await repo.getEvaluationScopeAtEffect(7,'secureshop_agent_security');revision='4';
 const second=await repo.getEvaluationScopeAtEffect(7,'secureshop_agent_security');assert.notEqual(first.modeStamp,second.modeStamp);assert.equal(first.mode,'fixed');
 assert.equal(queries.length,2);assert.ok(queries.every(sql=>!/(FOR UPDATE|INSERT|BEGIN|advisory)/i.test(sql)));exists=false;
 await assert.rejects(repo.getEvaluationScopeAtEffect(7,'secureshop_agent_security'),/unavailable/);
});
test('same-client canonical mode stamp changes on monotonic revision even when timestamp and mode repeat',async()=>{let revision='1',released=0;const queries=[];const client={async query(sql){queries.push(sql);if(sql.includes('FROM workshop_platform.exercises'))return {rows:[{workshop_key:'secureshop_agent_security'}]};if(sql.includes('FROM workshop_platform.user_state'))return {rows:[{generation:0}]};if(sql.includes('FROM workshop_platform.user_modes'))return {rows:[{mode:'fixed',stamp:'same timestamp'}]};if(sql.includes('FROM workshop_platform.revisions'))return {rows:[{revision}]};return {rows:[]};},release(){released++;}};const repo=createAnalyticsModeRepository({connect:async()=>client});const a=await repo.getEvaluationScope(1,'secureshop_agent_security');revision='3';const b=await repo.getEvaluationScope(1,'secureshop_agent_security');assert.equal(a.mode,b.mode);assert.notEqual(a.modeStamp,b.modeStamp);assert.equal(a.generation,0);assert.equal(released,2);assert.equal(queries.filter(q=>q.includes('FOR UPDATE')).length,2);await assert.rejects(repo.getEvaluationScope(1,'other'));});
