'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {performance}=require('node:perf_hooks');
const driver=require('./postgres/ownedMcpOriginalCohortDriver');
const ROOT=path.resolve(__dirname,'..');
const options={root:ROOT,runId:'a'.repeat(32),expectedPlanSha256:'b'.repeat(64),outerDeadline:performance.now()+60000,env:{}};
function window(){const entered=performance.now(),started=entered-80,deadline=started+1200000;
 return{configuration:{controlled:true},deadline,signal:new AbortController().signal,
  cohortWindow:{version:1,clock:'producer-performance-now-ms',startedAtMs:started,callbackEnteredAtMs:entered,
   deadlineMs:deadline,budgetMs:1200000,remainingMs:deadline-entered,admissionIncluded:true,renewable:false}};}
function output(value){return{artifact:path.join(ROOT,'tasks/tmp/v23-build-'+options.runId),
 receipt:{version:1,runId:options.runId,planSha256:options.expectedPlanSha256,controlled:false,buildCompleted:true,
  cleanupVerified:true,qualificationComplete:false,error:null,cleanupErrors:[],interruptions:[],consumerJournal:{sealed:true}},
 result:{value,controlled:false,cleanupVerified:true,qualificationComplete:false}};}
function fixture(events,{error,finalizationError}={}){return async(_env,scope)=>{
 assert.throws(()=>driver.assertScope(scope),{code:'ORIGINAL_COHORT_SCOPE_REQUIRED'});
 const state=driver._internals.controlledScope(scope),result={passed:false};
 assert(Object.isFrozen(state));assert.throws(()=>{state.controlled=false;});
 assert.throws(()=>driver.assertScope(scope),{code:'ORIGINAL_COHORT_SCOPE_REQUIRED'});
 assert(state.cohortWindow.remainingMs<1200000);events.push('cohort');
 state.retain({result,async finalize({proof,error:failed}){events.push('finalize');
  result.passed=!!proof&&!failed;if(finalizationError)throw finalizationError;
  const bytes=require('./postgres/secureshopV23Original.integration.test').candidateBytes(result);
  return{version:1,file:'v23-original-result.json',sha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),
   bytes:Buffer.byteLength(bytes),unsealed:true,requiresOwnerTerminal:true};}});
 if(error)throw error;return result;
};}
test('reviewed driver still rejects malformed or unowned options before producer effects',async()=>{
 await assert.rejects(driver.runOriginalCohort(),{code:'ERR_ASSERTION'});
 for(const changed of [{...options,root:'/foreign'}, {...options,runId:'bad'},
  {...options,expectedPlanSha256:'bad'}, {...options,extra:true}])
  await assert.rejects(driver.runOriginalCohort(changed),{code:'ERR_ASSERTION'});
 await assert.rejects(driver.runOriginalCohort({...options,outerDeadline:performance.now()-1}),{code:'ORIGINAL_COHORT_OUTER_DEADLINE'});
 assert.throws(()=>driver.assertScope({}),{code:'ORIGINAL_COHORT_SCOPE_REQUIRED'});
});
test('real producer API rejects an unreviewed plan before build allocation or cohort',async()=>{
 let entered=false;await assert.rejects(driver._internals.runControlled(options,
  require('./postgres/ownedMcpOriginalBuildAdapter').withOriginalRegistryService,
  async()=>{entered=true;}),{code:'ORIGINAL_BUILD_PLAN_CHANGED'});assert.equal(entered,false);
});
test('cohort success is provisional until real producer-shaped cleanup and same outcome join',async()=>{
 const events=[];const result=await driver._internals.runControlled(options,async o=>{
  assert.deepEqual(Object.keys(o).sort(),['consumer','expectedPlanSha256','outerDeadline','root','runId']);
  const value=await o.consumer(window());assert.equal(value.passed,false);events.push('retired');return output(value);
 },fixture(events));
 assert.deepEqual(events,['cohort','retired','finalize']);assert.equal(result.passed,true);
});
test('cleanup, source binding, journal debt and substituted value reject final success',async()=>{
 for(const mutate of [o=>o.receipt.cleanupVerified=false,o=>o.receipt.cleanupErrors.push('unjoined'),
  o=>o.receipt.consumerJournal.sealed=false,o=>o.receipt.controlled=true,o=>o.result.controlled=true,
  o=>o.receipt.runId='c'.repeat(32),o=>o.receipt.planSha256='d'.repeat(64),
  o=>o.receipt.interruptions.push('SIGTERM'),o=>o.result.cleanupVerified=false,
  o=>o.artifact='/tmp/foreign',o=>o.result.value={passed:true}]){
  const events=[];let value;
  await assert.rejects(driver._internals.runControlled(options,async o=>{
   value=await o.consumer(window());const r=output(value);mutate(r);return r;
  },fixture(events)));
  assert.equal(value.passed,false);assert.deepEqual(events,['cohort','finalize']);
 }
});
test('original cohort error survives producer cleanup and failed final publication',async()=>{
 const first=Error('original semantic mismatch'),late=Error('publication failed'),events=[];
 await assert.rejects(driver._internals.runControlled(options,async o=>{
  try{return output(await o.consumer(window()));}finally{events.push('retired');}
 },fixture(events,{error:first,finalizationError:late})),e=>e===first&&e.finalizationError===late);
 assert.deepEqual(events,['cohort','retired','finalize']);
});
test('pending cohort after producer timeout remains explicit debt, never finalizes or claims cleanup',async()=>{
 let release,finished;const held=new Promise(resolve=>release=resolve),events=[];
 await assert.rejects(driver._internals.runControlled(options,async o=>{
  finished=o.consumer(window());finished.catch(()=>{});await Promise.resolve();throw Error('producer timeout');
 },async(env,scope)=>{const value=await fixture(events)(env,scope);await held;return value;}),
 e=>e.code==='ORIGINAL_COHORT_UNJOINED'&&e.retirementUnproven===true);
 release();await finished;assert.deepEqual(events,['cohort']);
});
test('scope revoked after callback, duplicate callback and expired or renewed windows reject',async()=>{
 let captured;
 await driver._internals.runControlled(options,async o=>output(await o.consumer(window())),async(env,scope)=>{
  captured=scope;return fixture([])(env,scope);});
 assert.throws(()=>driver._internals.controlledScope(captured));assert.throws(()=>driver.assertScope(captured));
 await assert.rejects(driver._internals.runControlled(options,async o=>{
  const value=await o.consumer(window());await o.consumer(window());return output(value);
 },fixture([])));
 for(const mutate of [w=>w.cohortWindow.renewable=true,w=>w.deadline+=100,
  w=>w.cohortWindow.remainingMs=1200000,w=>w.cohortWindow.clock='epoch-ms',
  w=>w.signal=AbortSignal.abort(Error('cancelled'))]){
  let entered=false;await assert.rejects(driver._internals.runControlled(options,async o=>{
   const w=window();mutate(w);return output(await o.consumer(w));
  },async()=>{entered=true;}));assert.equal(entered,false);
 }
});
test('publication uses outer remaining deadline and retains held IO debt without late success promotion',async t=>{
 const fs=require('node:fs/promises'),os=require('node:os');
 const {publishPrivateFinal}=require('./postgres/secureshopV23Original.integration.test');
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'v23-publication-'));t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const file=path.join(directory,'v23-original-result.json');await fs.writeFile(file,'{"passed":false}',{mode:0o600});
 const identity=await fs.lstat(file);let release,finished,started;
 const began=new Promise(resolve=>started=resolve);
 const bounded=driver._internals.settlePublication(async({publication})=>{
  let count=0;const proxy={...publication,io:fn=>publication.io(()=>{
   if(++count===4){started();return new Promise(resolve=>{release=()=>resolve(fn());});}return fn();})};
  finished=publishPrivateFinal(file,identity,{passed:true},proxy);await finished;
 },{},performance.now()+80);
 await began;await assert.rejects(bounded,e=>e.code==='ORIGINAL_COHORT_PUBLICATION_DEADLINE'&&e.publicationDebt.pendingOperations===1&&e.publicationDebt.lateWritesNotCancelled);
 assert.equal(await fs.readFile(file,'utf8'),'{"passed":false}');release();await assert.rejects(finished,/PUBLICATION_DEADLINE/);
 assert.equal(await fs.readFile(file,'utf8'),'{"passed":false}');
 assert.deepEqual(await fs.readdir(directory),['v23-original-result.json']);
});
test('expired outer owner admits neither producer nor new publication work',async()=>{
 let effects=0;await assert.rejects(driver._internals.runControlled({...options,outerDeadline:performance.now()-1},
  async()=>{effects++;},fixture([])),{code:'ORIGINAL_COHORT_OUTER_DEADLINE'});
 await assert.rejects(driver._internals.settlePublication(async()=>{effects++;},{},performance.now()-1),{code:'ORIGINAL_COHORT_PUBLICATION_DEADLINE'});
 assert.equal(effects,0);
});
test('owner terminal requires exact candidate bytes, never a mismatched publication receipt',async()=>{
 await assert.rejects(driver._internals.runControlled(options,async o=>output(await o.consumer(window())),async(_env,scope)=>{
  const result={passed:false};driver._internals.controlledScope(scope).retain({result,async finalize(){result.passed=true;
   return{version:1,file:'v23-original-result.json',sha256:'0'.repeat(64),bytes:1,unsealed:true,requiresOwnerTerminal:true};}});return result;
 }));
});
test('failed terminal requires the exact private producer error, bounded publication and one-use binding; semantic failure remains failure',async()=>{
 const fs=require('node:fs/promises'),crypto=require('node:crypto');
 const filename=path.join(ROOT,'tests/postgres/ownedMcpOriginalCohortDriver.js');
 const source=await fs.readFile(filename,'utf8'),localRequire=require('node:module').createRequire(filename);
 for(const scenario of ['retired','forged','wrong-callback','bad-publication','publication-failure','late-publication','pending-io','unjoined-io','semantic-promotion']){
  const original=Object.assign(Error('semantic assertion unchanged'),{code:'ERR_ASSERTION'});
  const ownerError=new AggregateError([original],'Original private build failed; retained journal is authoritative');
  const bindings=new WeakMap();
  const proof=Object.freeze({version:1,runId:options.runId,planSha256:options.expectedPlanSha256,
   artifact:path.join(ROOT,'tasks/tmp/v23-build-'+options.runId),cleanupVerified:true,consumerCleanupVerified:true,sharedStatePreserved:true,
   producerReceipt:{file:'result.json',sha256:'c'.repeat(64),bytes:123},sourceSha256:'d'.repeat(64)});
  if(scenario!=='forged')bindings.set(ownerError,scenario==='wrong-callback'?Error('copy'):original);
  else Object.assign(ownerError,{retirement:proof,cleanupVerified:true});
  const module={exports:{}};
  // Controlled isolated dependency only; no authority is installed in the
  // ordinary module, and no native fixture or transport is executed.
  new Function('require','module','exports','__dirname',source+'\nmodule.exports.testCompose=(o,p,f)=>compose(o,p,f,false);')(
   id=>id==='./ownedMcpOriginalBuildAdapter'?{claimFailedRetirement:async(error,callback)=>{
    if(bindings.get(error)!==callback)throw Object.assign(Error('missing private provenance'),{code:'ORIGINAL_BUILD_FAILED_RETIREMENT_REQUIRED'});
    bindings.delete(error);return proof;
   }}:localRequire(id),module,module.exports,path.dirname(filename));
  const evaluated=module.exports,result={passed:false,errors:['ERR_ASSERTION'],gates:{hostStopped:true}};
  let release,completed,finalizeCalls=0;
  const deadline=performance.now()+(scenario==='late-publication'||scenario==='pending-io'?30:10000);
  const opts={...options,outerDeadline:deadline};
  const action=evaluated.testCompose(opts,async o=>{
   try{await o.consumer(window());}catch(error){assert.equal(error,original);throw ownerError;}
  },async(_env,scope)=>{
   evaluated.assertScope(scope).retain({result,async finalize({proof:success,error,publication}){
    finalizeCalls++;assert.equal(success,null);assert.equal(error,ownerError);
    if(scenario==='semantic-promotion')result.passed=true;
    if(scenario==='publication-failure')throw Error('publication failed');
    if(scenario==='unjoined-io')completed=publication.io(()=>new Promise(resolve=>{release=resolve;}));
    if(scenario==='late-publication'||scenario==='pending-io'){
     completed=publication.io(()=>new Promise(resolve=>{release=resolve;}));await completed;publication.check();
    }
    const bytes=require('./postgres/secureshopV23Original.integration.test').candidateBytes(result);
    return{version:1,file:'v23-original-result.json',sha256:scenario==='bad-publication'?'0'.repeat(64):crypto.createHash('sha256').update(bytes).digest('hex'),
     bytes:Buffer.byteLength(bytes),unsealed:true,requiresOwnerTerminal:true};
   }});throw original;
  });
  await assert.rejects(action,error=>error===ownerError);
  assert.equal(result.passed,scenario==='semantic-promotion');assert.deepEqual(result.errors,['ERR_ASSERTION']);assert.equal(finalizeCalls,1);
  assert.throws(()=>driver.claimFailedTerminal(ownerError,opts),{code:'ORIGINAL_COHORT_FAILED_TERMINAL_REQUIRED'});
  if(scenario==='retired'){
   for(const changed of [{...opts,runId:'0'.repeat(32)},{...opts,expectedPlanSha256:'0'.repeat(64)},{...opts,outerDeadline:deadline+1}])
    assert.throws(()=>evaluated.claimFailedTerminal(ownerError,changed));
   assert.throws(()=>evaluated.claimFailedTerminal(Object.assign(Error('copy'),ownerError),opts));
   const terminal=evaluated.claimFailedTerminal(ownerError,opts);
   assert.equal(terminal.kind,'original-v23-failed-owner-terminal');assert.equal(terminal.passed,false);
   assert.deepEqual(terminal.cohort,result);assert.deepEqual(terminal.retirement,proof);
   assert.equal(terminal.canonicalCredit,false);assert.equal(terminal.qualificationComplete,false);
   assert.throws(()=>evaluated.claimFailedTerminal(ownerError,opts));
  }else assert.throws(()=>evaluated.claimFailedTerminal(ownerError,opts));
  if(release){assert(ownerError.finalizationError.publicationDebt.pendingOperations===1);release();await completed;
   await new Promise(resolve=>setImmediate(resolve));assert.throws(()=>evaluated.claimFailedTerminal(ownerError,opts));}
 }
});
