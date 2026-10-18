'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertUserAdministrationReadiness}=require('../server/database/postgres/secureshopBoundUserAdministrationRepository');
function pool(change){const calls=[];return{calls,async query(sql,args){calls.push({sql,args});if(args){const rows=args[0].map((table,i)=>({ordinal:i+1,allowed:i<12}));change?.(rows);return{rows};}return{rows:[{allowed:true,runtime_role:'dvaia_secureshop_agents_runtime'}]};}};}
test('minimum effective grants pass without mutation and every missing required grant fails',async()=>{
 const good=pool();assert.deepEqual(await assertUserAdministrationReadiness(good),{ready:true});
 assert.equal(good.calls.length,2);assert.ok(good.calls.every(c=>c.sql.trim().startsWith('SELECT')));
 assert.ok(good.calls[0].args[1].every(p=>!p.includes(',')));
 for(let i=0;i<12;i++)await assert.rejects(assertUserAdministrationReadiness(pool(rows=>{rows[i].allowed=false;})),{code:'USER_ADMINISTRATION_NOT_READY'});
});
test('broad immutable receipt grants, incomplete results and missing function execution fail closed',async()=>{
 for(let i=12;i<20;i++)await assert.rejects(assertUserAdministrationReadiness(pool(rows=>{rows[i].allowed=true;})),{code:'USER_ADMINISTRATION_NOT_READY'});
 await assert.rejects(assertUserAdministrationReadiness(pool(rows=>rows.pop())),{code:'USER_ADMINISTRATION_NOT_READY'});
 const p=pool(),query=p.query;p.query=async(sql,args)=>args?query(sql,args):{rows:[{allowed:false}]};
 await assert.rejects(assertUserAdministrationReadiness(p),{code:'USER_ADMINISTRATION_NOT_READY'});
});

test('migration or foreign role cannot certify runtime readiness',async()=>{const p=pool(),query=p.query;p.query=async(sql,args)=>args?query(sql,args):{rows:[{allowed:true,runtime_role:'dvaia_secureshop_agents_migration'}]};await assert.rejects(assertUserAdministrationReadiness(p),{code:'USER_ADMINISTRATION_NOT_READY'});});
