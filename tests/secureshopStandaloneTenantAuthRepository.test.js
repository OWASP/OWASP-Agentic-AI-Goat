'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopStandaloneAuthRepository:create}=require('../server/database/postgres/secureshopStandaloneAuthRepository');
const principal={principalId:'11111111-1111-4111-8111-111111111111',ownerId:1,shopUserId:10,username:'person',email:'person@example.test',role:'customer',credentialVersion:'1',authorityVersion:'1',isActive:true};
const expiresAt='2099-01-01T00:00:00.000Z';
function fixture({role='merchant',allowed=true}={}){
 const calls=[];let inserted;
 const query=async(sql,args)=>{calls.push([sql,args]);
  if(sql.includes('SELECT m.role FROM'))return{rows:allowed?[{role}]:[]};
  if(sql.includes('count(*)'))return{rows:[{count:0}]};
  if(sql.startsWith('INSERT INTO secureshop_auth.sessions')){inserted=args;return{rows:[{sessionId:20,expiresAt}]};}
  if(sql.startsWith('UPDATE secureshop_auth.sessions'))return{rows:[{expiresAt}],rowCount:1};
  if(sql.includes('FROM secureshop_auth.sessions s'))return{rows:allowed?[{...principal,role,sessionId:9,renewedFromSessionId:9,expiresAt}]:[]};
  if(sql.includes('FROM secureshop_auth.principals p'))return{rows:[principal]};
  return{rows:[],rowCount:1};
 };
 return{calls,get inserted(){return inserted;},repo:create({pool:{query,connect:async()=>({query,release(){}})},executionTenantSlug:'other'})};
}
test('fresh credential login captures current tenant and returns member role, not immutable principal role',async()=>{
 const f=fixture();const result=await f.repo.createSession({...principal,tokenHash:'a'.repeat(64),expiresAt});assert.equal(result.role,'merchant');assert.equal(f.inserted[5],null);assert.equal(principal.role,'customer');
 const member=f.calls.find(([sql])=>sql.includes('SELECT m.role FROM'));assert.deepEqual(member[1],[principal.principalId,20,'other']);assert.match(member[0],/v.membership_version=m.membership_version/);
});
test('inactive or absent configured membership rolls back fresh login',async()=>{
 const f=fixture({allowed:false});await assert.rejects(f.repo.createSession({...principal,tokenHash:'a'.repeat(64),expiresAt}),{code:'SHOP_AUTH_INVALID'});assert.ok(f.calls.some(([s])=>s==='ROLLBACK'));assert.ok(!f.calls.some(([s])=>s==='COMMIT'));
});
test('renewal preserves source session lineage rather than acquiring fresh membership snapshots',async()=>{
 const f=fixture();const result=await f.repo.rotateSession({tokenHash:'a'.repeat(64),newTokenHash:'b'.repeat(64),expiresAt});assert.equal(result.role,'merchant');assert.equal(f.inserted[5],9);
 const admission=f.calls.find(([sql])=>sql.includes('renewedFromSessionId'));assert.match(admission[0],/v.membership_version=m.membership_version/);assert.deepEqual(admission[1],['a'.repeat(64),'other']);
});
test('stale configured membership cannot renew even with valid global credential versions',async()=>{
 const f=fixture({allowed:false});assert.equal(await f.repo.rotateSession({tokenHash:'a'.repeat(64),newTokenHash:'b'.repeat(64),expiresAt}),null);assert.equal(f.inserted,undefined);assert.ok(!f.calls.some(([s])=>s.startsWith('UPDATE')));
});
test('session and password reads bind exact configured tenant snapshot and project tenant role',async()=>{
 for(const method of ['readCurrentSession','readCredentialForSession']){const f=fixture({role:'admin'});const result=await f.repo[method]('a'.repeat(64));assert.equal(result.role,'admin');const [sql,args]=f.calls[0];assert.match(sql,/m.role/);assert.match(sql,/session_membership_snapshots/);assert.match(sql,/t.slug=\$2 AND t.is_active AND m.is_active/);assert.equal(args[1],'other');}
});
test('password mutation cannot bypass stale tenant cookie',async()=>{
 const f=fixture({allowed:false});await assert.rejects(f.repo.changePassword({tokenHash:'a'.repeat(64),credentialVersion:'1',passwordHash:'unused'}),{code:'SHOP_AUTH_INVALID'});assert.ok(!f.calls.some(([s])=>s.startsWith('UPDATE')));const entry=f.calls.find(([s])=>s.includes('SELECT p.principal_id'));assert.equal(entry[1][2],'other');assert.match(entry[0],/session_membership_snapshots/);
});
