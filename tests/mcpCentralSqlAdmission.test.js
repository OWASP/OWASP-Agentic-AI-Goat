'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {KEYS,admitCentralSql}=require('./helpers/mcpCentralSqlAdmission');
const roles=['identity_runtime','identity_migration','mcp_runtime','mcp_migration'];
function good(){return Object.fromEntries(KEYS.map((k,i)=>[k,`postgresql://dvaia_${roles[i]}:private@127.0.0.1:54321/owasp_ai_goat_test_central_ack_0123456789ab_${i<2?'identity':'mcp'}`]));}
test('closed four URL admission precedes driver loading and snapshots input',()=>{const e=good();let n=0;const r=admitCentralSql(e,()=>{n++;return {Pool:'controlled'};});e[KEYS[0]]='changed';assert.equal(n,1);assert.notEqual(r.environment[KEYS[0]],'changed');assert.ok(Object.isFrozen(r.environment));});
test('every malformed URL rejects before any driver or resource callback',()=>{
 const mutations=[v=>undefined,v=>'',v=>v.replace('postgresql:','https:'),v=>v.replace('127.0.0.1','localhost'),v=>v.replace(':54321',''),v=>v.replace(':54321',':0'),v=>v.replace(':54321',':65536'),v=>v+'?sslmode=disable',v=>v+'?',v=>v+'#x',v=>v.replace('0123456789ab','abcdef012345'),v=>v.replace('dvaia_identity_runtime','wrong'),v=>v.replace('_identity','_mcp')];
 for(const mutate of mutations){const e=good();e[KEYS[0]]=mutate(e[KEYS[0]]);let calls=0;assert.throws(()=>admitCentralSql(e,()=>{calls++;throw Error('resource entry');}));assert.equal(calls,0);}
 for(const key of KEYS){const e=good();delete e[key];let calls=0;assert.throws(()=>admitCentralSql(e,()=>calls++));assert.equal(calls,0);}
 const e=good();[e[KEYS[0]],e[KEYS[2]]]=[e[KEYS[2]],e[KEYS[0]]];assert.throws(()=>admitCentralSql(e,()=>assert.fail('resource entry')));
});
