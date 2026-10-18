'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
function fullApp(env={}){
 const writes=[],production={createListingsProduction:options=>options};
 const sandbox={process:{env:{PG_TEST_DISPOSABLE:'yes',LISTINGS_EVIDENCE_ROOT:'/synthetic',...env}},require(name){
  if(name==='node:fs')return{writeFileSync:(_file,text)=>writes.push(JSON.parse(text))};
  if(name==='node:path')return path;if(name==='node:assert/strict')return assert;
  if(name==='../../server/services/secureshopListingsProduction')return production;
  throw Error('Effectful import denied: '+name);
 }};
 vm.runInNewContext(fs.readFileSync(require.resolve('./fixtures/secureshopListingsFullAppProvider.cjs'),'utf8'),sandbox);
 return{options:production.createListingsProduction({}),writes};
}
test('historical mocked transport retains exact identity, sequence, cap and forbidden Judge',async()=>{
 const {options,writes}=fullApp({LISTINGS_FULL_APP_COHORT:'historical-mocked'}),p=options.provider;
 assert.deepEqual(JSON.parse(JSON.stringify(p.config)),{provider:'controlled',model:'full-app-fixture',mocked:true});
 const a=await p.chat(),b=await p.chat(),c=await p.chat(),final=await p.finalResponse();
 assert.equal(a.tool_uses[0].name,'listing.fetch_parse');assert.equal(b.tool_uses[0].name,'listing.publish');
 assert.equal(c.text,'<h2>Controlled Listings lamp</h2><p>Saved through the real workshop bridge.</p>');
 for(const value of [a,b,c,final]){assert.equal(value.mocked,true);assert.equal(value.provider,'controlled');assert.equal(value.fallback,false);}
 assert.equal(final.text,'Controlled supplier import complete.');await assert.rejects(p.chat());
 await assert.rejects(options.assessmentDependencies.judge(),/Judge forbidden/);
 assert.equal(options.assessmentDependencies.qualifyModel,undefined);assert.equal(writes.at(-1).actualModelCalls,0);
});
test('default model-shaped transport stays compatible and incompatible selectors fail before composition',async()=>{
 const {options}=fullApp();assert.equal(options.provider.config.mocked,false);assert.equal(options.provider.config.provider,'controlled-full-app');
 assert.equal((await options.provider.chat()).tool_uses[0].name,'listing.fetch_parse');
 await assert.rejects(options.assessmentDependencies.judge(),/Judge forbidden/);
 assert.throws(()=>fullApp({LISTINGS_FULL_APP_COHORT:'unknown'}),/Unknown/);
 assert.throws(()=>fullApp({LISTINGS_FULL_APP_COHORT:'historical-mocked',LISTINGS_FULL_APP_RETRY:'1'}),/cannot use grading retry/);
});
function grading(){
 const module={exports:{}},calls={guard:0};
 vm.runInNewContext(fs.readFileSync(require.resolve('./fixtures/secureshopListingsGenuineGrading'),'utf8'),{module,require(name){
  if(name==='node:assert/strict')return assert;
  if(name==='node:path')return path;
  if(name==='node:crypto')return{randomUUID:()=>{throw Error('not executing workflow');}};
  if(name==='node:fs'||name==='node:child_process'||name==='./secureshopListingsJudgeCalibration')return{};
  if(name==='../../server/services/secureshopListingsJudgeGuard')return{createListingsJudgeGuard:()=>async()=>{calls.guard++;return{verdict:'fail',errorCode:'LISTINGS_EVIDENCE_INCONSISTENT'};}};
  throw Error('Effectful import denied: '+name);
 }});return{...module.exports,calls};
}
test('explicit actual calibration invokes Judge on unchanged packet; default remains guarded',async()=>{
 const {selectCalibrationJudge,calls}=grading();const seen=[],packet={facts:{invalid:true},evidence:[]};
 const judge=async value=>{seen.push(value);return{verdict:'fail',provider:'controlled-test'};};
 const direct=selectCalibrationJudge({calibrationMode:'actual-judge',judge});assert.strictEqual(direct,judge);
 await direct(packet);assert.strictEqual(seen[0],packet);assert.equal(calls.guard,0);
 const guarded=selectCalibrationJudge({judge});assert.equal((await guarded(packet)).errorCode,'LISTINGS_EVIDENCE_INCONSISTENT');assert.equal(seen.length,1);assert.equal(calls.guard,1);
 assert.throws(()=>selectCalibrationJudge({calibrationMode:'other',judge}),/Unknown/);
 assert.throws(()=>selectCalibrationJudge({calibrationMode:'actual-judge',onlyBrowser:true,judge}),/four-objective/);
});

test('exercise wiring preserves direct historical calibration and reports its mode separately',async()=>{
 async function run(calibrationMode){
  const module={exports:{}},calls=[],writes=[],packet={rubric:{objectiveId:'fixture'},facts:{inconsistent:true},evidence:[]};
  const records=Array.from({length:4},(_,i)=>({objectiveId:String(i),evidenceDigest:'digest'+i}));
  const judge=async value=>{calls.push(value);return{verdict:'fail'};};
  const signal={throwIfAborted(){}};
  vm.runInNewContext(fs.readFileSync(require.resolve('./fixtures/secureshopListingsGenuineGrading'),'utf8'),{
   module,AbortSignal:{timeout:()=>signal},require(name){
    if(name==='node:assert/strict')return assert;if(name==='node:path')return path;
    if(name==='node:fs')return{writeFileSync:(_p,text)=>writes.push(JSON.parse(text)),mkdirSync(){},realpathSync:x=>x};
    if(name==='node:crypto')return{randomUUID:()=> 'controlled-uuid'};
    if(name==='node:child_process')return{spawn:()=>{throw Error('No process launch');}};
    if(name==='node:os')return{homedir:()=>'/synthetic'};
    if(name==='./secureshopListingsJudgeCalibration')return{captureCanonicalListingsPackets:()=>({receipts:{},snapshot:()=>records}),calibrationCases:()=>[{kind:'derived-negative-not-an-execution',packet}]};
    if(name==='./secureshopListingsActualProvider')return{createActualListingsProvider:async options=>{assert.equal(options.maxCalls,12);assert.equal(options.maxHttpCalls,28);return{provider:{},evidence:{calls:[],httpCalls:[]},close(){}};}};
    if(name==='./secureshopListingsActualJudge')return{createActualListingsJudge:options=>{assert.equal(options.maxCalls,16);return{judge,calls};}};
    if(name==='./fullBackendBootControls')return{createOwnedChildren:()=>({cleanup:async()=>{}})};
    if(name==='./fullBackendAssessmentBrowser')return{launchOwnedAssessmentBrowser:async()=>({endpoint:'synthetic',close:async()=>{}})};
    if(name==='../../server/services/xssBrowserQualification')return{createXssBrowserQualification:()=>({close:async()=>{}})};
    if(name==='../../server/services/secureshopListingsJudgeGuard')return{createListingsJudgeGuard:()=>async()=>({verdict:'fail',errorCode:'LISTINGS_EVIDENCE_INCONSISTENT'})};
    throw Error('Effectful import denied: '+name);
   }});
  const prepared=await module.exports.prepareGenuineGrading({root:'/synthetic',receipts:{},...(calibrationMode?{calibrationMode}:{})});
  try{
   const result=await prepared.exercise({post:async action=>action==='rewrite-save'?{ok:true}:{state:'completed'},identity:{query:async()=>({rows:[{},{},{},{}]})},scope:{platformOwnerId:1}});
   assert.equal(result.status,'passed');assert.equal(result.negativeResults.length,1);assert.equal(writes.at(-1).calibrationMode,result.calibrationMode);
   return{result,calls,packet};
  }finally{await prepared.close();}
 }
 const guarded=await run();assert.equal(guarded.result.calibrationMode,'guarded-pipeline');assert.equal(guarded.result.actualJudgeCalls,0);
 const historical=await run('actual-judge');assert.equal(historical.result.calibrationMode,'actual-judge');assert.equal(historical.result.actualJudgeCalls,1);
 assert.strictEqual(historical.calls[0].facts,historical.packet.facts);assert.strictEqual(historical.calls[0].evidence,historical.packet.evidence);
});
