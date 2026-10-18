'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createObjectiveGradingCore,createDeferredObjectiveGrading,resolveObjectiveGradingDependencies}=require('../server/services/objectiveGradingCore');
function fixture(personaBindings){
 const calls=[],identityPool={query(){throw Error('Unexpected probe');},connect(){throw Error('Unexpected connect');}},progress={getGeneration:async()=>0};
 const receipts={listRecoverable:async input=>{calls.push(['list',input]);return['scoped'];}},completion={retry:async()=>{}};
 const judge=async()=>{},coordinatorFactory=()=>{};
 const constructors={createObjectiveJudgmentRepository(...args){calls.push(['repository',...args]);return receipts;},
  createObjectiveCompletionService(options){calls.push(['completion',options]);return completion;},
  createObjectiveRegradeService(options){calls.push(['regradeFactory',options]);return async input=>{calls.push(['retry',input]);return{replayed:true};};}};
 return{calls,receipts,completion,progress,identityPool,constructors,options:{identityPool,progress,judge,coordinatorFactory,...(personaBindings===undefined?{}:{personaBindings})}};
}
test('one repository and same adapter are shared by assessment dependencies list and retry',async()=>{
 const adapter={capture(){throw Error('Recovery must never capture');}},f=fixture(adapter),core=createObjectiveGradingCore(f.options,f.constructors);
 assert.equal(f.calls.filter(row=>row[0]==='repository').length,1);
 assert.equal(f.calls[0][1],f.identityPool);assert.deepEqual(Object.keys(f.calls[0][2]),['personaBindings']);assert.equal(f.calls[0][2].personaBindings,adapter);
 assert.equal(core.assessmentDependencies.personaBindings,adapter);assert.equal(core.assessmentDependencies.receipts,f.receipts);assert.equal(core.assessmentDependencies.progress,f.progress);
 assert.equal(f.calls[1][1].receipts,f.receipts);assert.equal(f.calls[2][1].receipts,f.receipts);assert.equal(f.calls[2][1].completion,f.completion);
 assert.equal(Object.hasOwn(f.calls[1][1],'capturePersonaEvaluation'),false);assert.equal(f.calls[1][1].judge,f.options.judge);
 assert.equal(f.calls[2][1].coordinatorFactory,f.options.coordinatorFactory);
 assert.deepEqual(await core.listJudgments(42),['scoped']);assert.deepEqual(f.calls.at(-1)[1],{userId:42,judgeVersion:require('../server/agent-runtime/objectiveJudge').JUDGE_VERSION});
 const input={userId:42,evaluationId:'evaluation'};assert.deepEqual(await core.regrade(input),{replayed:true});assert.equal(f.calls.at(-1)[1],input);
 assert.equal(Object.isFrozen(core),true);assert.equal(Object.isFrozen(core.assessmentDependencies),true);
});
test('candidate-off composition omits optional adapter without querying or importing candidate',()=>{
 const before=new Set(Object.keys(require.cache)),f=fixture();const core=createObjectiveGradingCore(f.options,f.constructors);
 assert.equal(f.calls[0].length,2);assert.equal(Object.hasOwn(core.assessmentDependencies,'personaBindings'),false);
 assert.deepEqual(Object.keys(require.cache).filter(name=>!before.has(name)&&name.includes('/drafts/')),[]);
});
test('deferred facade fails closed before install and then forwards captured handlers',async()=>{
 const f=fixture(),facade=createDeferredObjectiveGrading(),{listJudgments,regrade}=facade;
 await assert.rejects(listJudgments(4),{code:'GRADE_STORE_NOT_READY'});await assert.rejects(regrade({userId:4}),{code:'GRADE_STORE_NOT_READY'});assert.equal(f.calls.length,0);
 assert.throws(()=>facade.install({listJudgments:()=>[],regrade:()=>{}}),TypeError);
 const core=createObjectiveGradingCore(f.options,f.constructors);facade.install(core);
 assert.deepEqual(await listJudgments(4),['scoped']);assert.deepEqual(await regrade({userId:4}),{replayed:true});
 assert.throws(()=>facade.install(core),{code:'GRADING_CORE_ALREADY_INSTALLED'});
 const another=fixture();assert.throws(()=>facade.install(createObjectiveGradingCore(another.options,another.constructors)),{code:'GRADING_CORE_ALREADY_INSTALLED'});
 assert.equal(await facade.listJudgments(5).then(rows=>rows[0]),'scoped');
});
test('invalid optional configuration never constructs a default fallback',()=>{
 const f=fixture();for(const personaBindings of [null,{},false])assert.throws(()=>createObjectiveGradingCore({...f.options,personaBindings},f.constructors),TypeError);
 assert.equal(f.calls.length,0);
});
test('failed core construction leaves facade unavailable for deliberate later installation',async()=>{
 const f=fixture(),facade=createDeferredObjectiveGrading();
 assert.throws(()=>createObjectiveGradingCore(f.options,{...f.constructors,createObjectiveJudgmentRepository(){throw Error('Schema readiness failed');}}),/Schema readiness failed/);
 await assert.rejects(facade.listJudgments(1),{code:'GRADE_STORE_NOT_READY'});
 facade.install(createObjectiveGradingCore(f.options,f.constructors));assert.deepEqual(await facade.listJudgments(1),['scoped']);
});

test('real default factories construct without store probes or candidate imports',()=>{
 const before=new Set(Object.keys(require.cache));let queries=0;
 const pool={query(){queries++;throw Error('Unexpected query');},connect(){queries++;throw Error('Unexpected connection');}};
 const core=createObjectiveGradingCore({identityPool:pool,progress:{getGeneration:async()=>0},judge:async()=>{throw Error('No inference during construction');}});
 assert.equal(typeof core.receipts.beginEvaluation,'function');assert.equal(typeof core.completion.retry,'function');assert.equal(typeof core.regrade,'function');assert.equal(queries,0);
 assert.deepEqual(Object.keys(require.cache).filter(name=>!before.has(name)&&name.includes('/drafts/')),[]);
});

test('branded resolver returns the exact assessment dependencies only for the owning identity pool',()=>{
 const adapter={capture(){}},f=fixture(adapter),core=createObjectiveGradingCore(f.options,f.constructors);
 assert.equal(resolveObjectiveGradingDependencies(core,{identityPool:f.identityPool}),core.assessmentDependencies);
 assert.equal(resolveObjectiveGradingDependencies(core,{identityPool:f.identityPool,personaBindings:adapter}),core.assessmentDependencies);
 assert.throws(()=>resolveObjectiveGradingDependencies({...core},{identityPool:f.identityPool}),/Matching objective grading core/);
 assert.throws(()=>resolveObjectiveGradingDependencies(core,{identityPool:{...f.identityPool}}),/Matching objective grading core/);
});

test('branded resolver rejects explicit partial persona adapter mismatches without changing defaults',()=>{
 const adapter={capture(){}},bound=fixture(adapter),boundCore=createObjectiveGradingCore(bound.options,bound.constructors);
 assert.throws(()=>resolveObjectiveGradingDependencies(boundCore,{identityPool:bound.identityPool,personaBindings:undefined}),/persona adapter mismatch/);
 assert.throws(()=>resolveObjectiveGradingDependencies(boundCore,{identityPool:bound.identityPool,personaBindings:{capture(){}}}),/persona adapter mismatch/);
 const plain=fixture(),plainCore=createObjectiveGradingCore(plain.options,plain.constructors);
 assert.equal(resolveObjectiveGradingDependencies(plainCore,{identityPool:plain.identityPool}),plainCore.assessmentDependencies);
 assert.equal(resolveObjectiveGradingDependencies(plainCore,{identityPool:plain.identityPool,personaBindings:undefined}),plainCore.assessmentDependencies);
 assert.throws(()=>resolveObjectiveGradingDependencies(plainCore,{identityPool:plain.identityPool,personaBindings:adapter}),/persona adapter mismatch/);
 assert.equal(Object.hasOwn(plainCore.assessmentDependencies,'personaBindings'),false);
});
