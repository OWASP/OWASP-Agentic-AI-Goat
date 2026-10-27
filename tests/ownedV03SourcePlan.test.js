'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03SourcePlan'),'utf8');
const merge=new Function('fail',source.slice(source.indexOf('function mergeSources('),source.indexOf('async function captureProducerSources('))+';return mergeSources;')(
 code=>Object.assign(Error(code),{code}));
test('producer source union rejects conflicting bytes rather than overwriting',()=>{
 const pins={};merge(pins,{'a.js':'a'.repeat(64)});merge(pins,{'a.js':'a'.repeat(64),'b.py':'b'.repeat(64)});
 assert.equal(Object.keys(pins).length,2);
 assert.throws(()=>merge(pins,{'a.js':'c'.repeat(64)}),{code:'V03_PLAN_SOURCE_CONFLICT'});
 assert.equal(pins['a.js'],'a'.repeat(64));
});
test('source union denies outside paths and malformed digests',()=>{
 for(const value of [{'../a':'a'.repeat(64)},{'/a':'a'.repeat(64)},{'a//b':'a'.repeat(64)},{a:'bad'}])
  assert.throws(()=>merge({},value),{code:'V03_PLAN_SOURCE_PIN'});
});
test('source planner cannot accept caller runners or foreign root',async()=>{
 await assert.rejects(require('./postgres/ownedV03SourcePlan').captureProducerSources('/foreign','a'.repeat(32)),{code:'V03_SOURCE_PLAN_BINDING'});
});
test('actual planner joins both fixed producer maps and verifies the complete result',async()=>{
 const path=require('node:path'),crypto=require('node:crypto'),root=path.resolve(__dirname,'..');
 const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex'),digest=sha('source'),calls=[];
 const modules={
  './ownedSystemDiagnosticBuildAdapter':{diagnosticBuildPlan:async(r,id)=>{
   assert.equal(r,root);assert.equal(id,sha('a'.repeat(32)+':v03-diagnostic').slice(0,32));calls.push('diagnostic');
   return {helperHashes:{'helper.js':digest},metadata:{buildSources:{'diagnostic/Dockerfile':digest}}};},planDigest:()=> 'b'.repeat(64)},
  './ownedMcpOriginalBuildAdapter':{originalBuildPlan:async(r,id,options)=>{
   assert.equal(r,root);assert.equal(id,sha('a'.repeat(32)+':v03-listings').slice(0,32));
   assert.deepEqual(options,{target:'listings-package',listingsMode:'v03-manager'});calls.push('listings');
   return {helperHashes:{'helper.js':digest},buildSources:{'listings/Dockerfile':digest}};},planDigest:()=> 'c'.repeat(64)},
  './ownedV03SourceInventory':{capture:()=>['parent.js']},
  './ownedV03MainAdmission':{_internals:{sourceBytes:async()=>Buffer.from('source')},verifySources:async(r,pins)=>{
   assert.equal(r,root);assert.ok(pins['diagnostic/Dockerfile']);assert.ok(pins['listings/Dockerfile']);assert.ok(pins['parent.js']);calls.push('verify');}}
 };
 const capture=new Function('require','ROOT','path','sha','fail',source.slice(source.indexOf('function mergeSources('),source.indexOf('module.exports='))+';return captureProducerSources;')(
  name=>{assert.ok(Object.hasOwn(modules,name));return modules[name];},root,path,sha,code=>Object.assign(Error(code),{code}));
 const result=await capture(root,'a'.repeat(32));assert.deepEqual(calls,['diagnostic','listings','verify']);
 assert.equal(result.executionApproved,false);assert.equal(result.qualificationComplete,false);assert.ok(Object.isFrozen(result.sourcePins));
});
