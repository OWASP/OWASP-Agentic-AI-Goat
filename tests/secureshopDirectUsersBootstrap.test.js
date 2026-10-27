'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm');
const fixture=require('node:fs').readFileSync(require('node:path').join(process.cwd(),'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
const body=fixture.slice(fixture.indexOf('async function qualifyDirectAdminUsersPanel('),fixture.indexOf('async function qualifyAdminUserChat('));
const helper=vm.runInNewContext('('+body.trim()+')',{assert,AbortController});
async function exercise(mode){
 const calls=[],context={genuine:'service-issued-context'},stop=Error('PHYSICAL_BOUNDARY');
 const membership={tenant_id:'tenant',role:'merchant',is_active:true};
 const auth={async register(){calls.push('register');return{user:{id:1000000005}};},async login(){calls.push('login');return{context,token:'fixture-token'};},async establishTenantContext(c){assert.equal(c,context);calls.push('execution');},async authenticate(){calls.push('authenticate');return{};}};
 const bootstrap=async c=>{assert.equal(c,context);calls.push('bootstrap');if(mode==='deny')throw Error('AUTH_DENIED');return{persona:{user:{id:mode==='wrong'?99:1000000005}}};};
 const identity={async query(){return{rows:[membership]};}};
 const frame={async click(){calls.push('physical');throw stop;}};
 let error;try{await helper({page:{},frame,suffix:'test',auth,bootstrap,identity,requestLog:[],getDispatches:()=>0,sibling:{user:{id:2}},admin:{user:{id:3}},status:{}});}catch(e){error=e;}
 return{calls,error,stop};
}
test('actual helper authenticates and bootstraps exact registered context before physical panel',async()=>{const r=await exercise();assert.equal(r.error,r.stop);assert.deepEqual(r.calls,['register','login','execution','bootstrap','authenticate','physical']);});
test('bootstrap denial cannot reach physical panel',async()=>{const r=await exercise('deny');assert.match(r.error.message,/AUTH_DENIED/);assert.ok(!r.calls.includes('physical'));});
test('wrong bootstrapped identity denies before physical panel',async()=>{const r=await exercise('wrong');assert.equal(r.error.code,'ERR_ASSERTION');assert.ok(!r.calls.includes('physical'));});
test('original physical target and isolation assertions remain',()=>{assert.ok(body.includes('assert.deepEqual(filtered.users.map(row => row.id), [targetId])'));assert.ok(body.includes('status.directPanelCancelNoEffect = true'));assert.ok(body.includes('status.directPanelBanConfirmed = true'));assert.ok(fixture.includes('auth, bootstrap, composition, pools, requestLog,'));});
