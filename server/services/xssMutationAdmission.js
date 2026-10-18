'use strict';
const {withStudentLifecycleLock}=require('../database/postgres/studentLifecycleLock');
const {OwnerWorkflowHttpError}=require('../agent-runtime/ownerWorkflowHttpError');

// Authenticated PostgreSQL mutations only. Anonymous teaching paths deliberately
// do not enter this factory; callers must resolve identity before selecting it.
function createXssMutationAdmission({pool,journal,lifecycle=withStudentLifecycleLock}={}){
 if(typeof pool?.connect!=='function'||typeof journal?.assertMutationAdmitted!=='function'
  ||typeof lifecycle!=='function')throw new TypeError('XSS mutation admission dependencies required');
 return async function admit(value,work){
  const ownerId=typeof value==='number'?value:
   typeof value==='string'&&/^[1-9][0-9]*$/.test(value)?Number(value):NaN;
  if(!Number.isSafeInteger(ownerId)||ownerId<1||ownerId>2147483647||typeof work!=='function')
   throw new TypeError('Authenticated XSS mutation owner required');
  let entered=false;
  try{return await lifecycle(pool,ownerId,async(_client,lifecycleGuard)=>{
   entered=true;
   let active=true;
   const guard=Object.freeze({ownerId,check:async()=>{
    if(!active)throw new Error('XSS mutation admission has ended');
    await lifecycleGuard.check();await journal.assertMutationAdmitted(ownerId);await lifecycleGuard.check();
    if(!active)throw new Error('XSS mutation admission has ended');
   }});
   try{await guard.check();const result=await work(guard);await guard.check();return result;}
   finally{active=false;}
  });}catch(error){
   // Before callback entry no XSS coordinator, journal or mutation work ran.
   // Once acquired, a timeout may follow partial work and is not a safe retry signal.
   if(!entered&&error?.code==='55P03')throw new OwnerWorkflowHttpError(503,
    'Another workshop request is still running. Wait for it to finish, then try again.',2);
   throw error;
  }
 };
}
function createLazyXssMutationAdmission({createLifecyclePool,createJournal}={}){
 if(typeof createLifecyclePool!=='function'||typeof createJournal!=='function')
  throw new TypeError('XSS admission factories required');
 let admission;
 return (owner,work)=>{
  if(!admission){
   // Resolve the journal before allocating a pool, so a failed dependency does
   // not leak a pool reservation. Assignment is synchronous for concurrent use.
   const journal=createJournal();
   if(typeof journal?.assertMutationAdmitted!=='function')throw new TypeError('XSS admission journal required');
   const pool=createLifecyclePool();
   admission=createXssMutationAdmission({pool,journal});
  }
  return admission(owner,work);
 };
}
function createXssProfileResetPendingCheck({journal}={}){
 if(typeof journal?.readNonterminalForOwner!=='function')
  throw new TypeError('XSS profile reset journal required');
 return async function assertNoPendingProfileReset(value,guard){
  const ownerId=typeof value==='number'?value:
   typeof value==='string'&&/^[1-9][0-9]*$/.test(value)?Number(value):NaN;
  if(!Number.isSafeInteger(ownerId)||ownerId<1||ownerId>2147483647
   ||guard?.ownerId!==ownerId||typeof guard?.check!=='function')
   throw new TypeError('Held XSS lifecycle authority required');
  await guard.check();
  const pending=await journal.readNonterminalForOwner(ownerId);
  await guard.check();
  if(pending)throw Object.assign(new Error('Finish or recover the pending profile reset before resetting progress'),{
   code:'XSS_PROFILE_RESET_PENDING',statusCode:503,
  });
  return true;
 };
}
function createLazyXssProfileResetPendingCheck({createJournal}={}){
 if(typeof createJournal!=='function')throw new TypeError('XSS profile reset journal factory required');
 let check;
 return (owner,guard)=>{
  check ||= createXssProfileResetPendingCheck({journal:createJournal()});
  return check(owner,guard);
 };
}
const configuredAdmission=createLazyXssMutationAdmission({
 createLifecyclePool:()=>require('../database/postgres').createPool(process.env,'IDENTITY_DATABASE_URL',{purpose:'lease'}),
 createJournal:()=>require('../database/postgres/xssParentResetJournalRepository').createXssParentResetJournalRepository(
  require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool),
});
const configuredProfileResetPendingCheck=createLazyXssProfileResetPendingCheck({
 createJournal:()=>require('../database/postgres/xssProfileResetJournalRepository').createXssProfileResetJournalRepository(
  require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool),
});
module.exports={createXssMutationAdmission,createLazyXssMutationAdmission,
 createXssProfileResetPendingCheck,createLazyXssProfileResetPendingCheck,
 configuredXssMutationAdmission:configuredAdmission,
 configuredXssProfileResetPendingCheck:configuredProfileResetPendingCheck};
