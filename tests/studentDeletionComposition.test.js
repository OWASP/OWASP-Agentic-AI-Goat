'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {STUDENT_DELETION_STEPS,createStudentDeletionComposition}=require('../server/services/studentDeletionComposition');

test('composition freezes the full ordered deletion protocol and wires the exact repository into SecureShop cleanup',()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused');}};let seen;
 const composition=createStudentDeletionComposition({identityPool:pool,xssPool:pool,finflowPool:pool,
  retireFinflowTraversalOwner:async()=>true, cleanupFinflowBackups:async()=>{throw Error('unused');},
  createSecureShopCleanup:repository=>{seen=repository;return async()=>({completed:true});},
  load:name=>{
   if(name==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({pool})};
   if(name==='../agent-runtime/postgresRunLedger')return{configuredRunLedger:()=>({})};
   if(name==='./studentDeletionRunDrain')return{createStudentDeletionRunDrain:()=>async()=>({completed:true})};
   return {};
  }});
 assert.equal(composition.repository,seen);assert.equal(composition.application.deleteStudent instanceof Function,true);
 assert.deepEqual(composition.steps,STUDENT_DELETION_STEPS);assert.equal(Object.isFrozen(composition.steps),true);
 assert.equal(STUDENT_DELETION_STEPS[0],'revoke_runs');assert.equal(STUDENT_DELETION_STEPS.at(-1),'identity');
 for(const step of STUDENT_DELETION_STEPS)assert.equal(typeof composition.adapters[step],'function',step);
});

test('composition fails closed without dedicated store pools or the retained SecureShop cleanup',()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{}};
 assert.throws(()=>createStudentDeletionComposition({identityPool:pool,xssPool:pool,finflowPool:pool}),/SecureShop/);
 assert.throws(()=>createStudentDeletionComposition({identityPool:pool,xssPool:pool,finflowPool:pool,createSecureShopCleanup:()=>null}),/SecureShop/);
 assert.throws(()=>createStudentDeletionComposition({identityPool:pool,xssPool:null,finflowPool:pool,createSecureShopCleanup:()=>async()=>({completed:true})}),/pools/);
});

for (const missing of ['retireFinflowTraversalOwner','cleanupFinflowBackups']) {
 test(`composition rejects missing ${missing} before exposing deletion`,()=>{
  const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused');}};
  const options={identityPool:pool,xssPool:pool,finflowPool:pool,
   createSecureShopCleanup:()=>async()=>({completed:true}),
   retireFinflowTraversalOwner:async()=>true,cleanupFinflowBackups:async()=>{throw Error('unused');}};
  delete options[missing];
  assert.throws(()=>createStudentDeletionComposition(options),/FinFlow .* deletion cleanup required/);
 });
}

test('explicit CTF authority selection reaches the ordered adapter without changing the durable step protocol',async()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused');}};
 let received;
 const options={identityPool:pool,xssPool:pool,finflowPool:pool,
  createSecureShopCleanup:()=>async()=>({completed:true}),retireFinflowTraversalOwner:async()=>true,cleanupFinflowBackups:async()=>{},
  load:()=>{throw Error('Legacy CTF load forbidden');},
  ctfRuntime:{deleteStudent:async scope=>{received=scope;return{completed:true,operationId:'00000000-0000-0000-0000-000000000001'};}}};
 const scope={subjectId:7,jobId:'owned-job',leaseToken:'owned-lease',check:async()=>{}};
 const composition=createStudentDeletionComposition(options);
 assert.deepEqual(await composition.adapters.ctf(scope),{completed:true});assert.deepEqual(received,scope);
 assert.equal(composition.steps,STUDENT_DELETION_STEPS);
 for(const ctfRuntime of [undefined,null,{}])assert.throws(()=>createStudentDeletionComposition({...options,ctfRuntime}),/CTF authority deletion runtime required/);
});
