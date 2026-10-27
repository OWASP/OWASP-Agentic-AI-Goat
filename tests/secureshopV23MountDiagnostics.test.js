'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const source=require('node:fs').readFileSync(path.join(__dirname,'postgres/secureshopV23PublicRendered.integration.test.js'),'utf8');
const helper=source.slice(source.indexOf('function publicFailureDiagnostic('),source.indexOf('async function runPublicNative('));
const diagnostic=new Function('require',helper+';return publicFailureDiagnostic;')(require);
const body=source.slice(source.indexOf("  stage='mount-bound';"),source.indexOf("  stage='host';",source.indexOf("  stage='mount-bound';")));
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const run=new AsyncFunction('require','fs','path','assert','diagnostic',`let stage,server;const mounted={standaloneAuth:{},publicCatalog:{}},auth={},bootstrap=()=>{},protectedReset={},env={SECURESHOP_V23_PUBLIC_RENDERED_BUILD:'/controlled-build'};
 try{${body};return {stage,completed:true};}catch(error){return {stage,diagnostic:diagnostic(stage,error)};}`);
function dependencies(failAt){
 const seen=[];function step(name){seen.push(name);if(name===failAt)throw Object.assign(new TypeError('PRIVATE_DO_NOT_EMIT'),{code:'RESET_STORAGE_NOT_READY'});}
 const server={address:()=>({port:12345})};
 const app={use(){},get(){},listen(_port,_host,ready){step('mount-listen');queueMicrotask(ready);return server;}};
 const express=()=>{step('mount-express');return app;};express.json=()=>()=>{};express.static=()=>{step('mount-static');return()=>{};};
 const factory=(stage,name,result)=>({[name](){step(stage);return result;}});
 const modules={
  '../../server/services/secureshopBoundApplication':factory('mount-bound','createSecureShopBoundApplication',{gateway(){},standaloneReadiness:{ready:true}}),
  '../../server/routes/secureshopStandaloneAuth':factory('mount-auth','createSecureShopStandaloneAuthRouter',()=>{}),
  '../../server/middleware/secureshopBoundDispatch':factory('mount-dispatch','createSecureShopBoundDispatch',()=>{}),
  '../../server/routes/secureshop/publicCatalog':factory('mount-public','createSecureShopPublicCatalogRouter',()=>{}),express};
 return {seen,require:name=>{assert(Object.hasOwn(modules,name));return modules[name];},fs:{async realpath(value){step('mount-build');return value;}}};
}
for(const stage of ['mount-bound','mount-express','mount-listen','mount-auth','mount-dispatch','mount-public','mount-build','mount-static'])test('actual mount statement retains '+stage,async()=>{
 const d=dependencies(stage),r=await run(d.require,d.fs,path,assert,diagnostic);
 assert.equal(r.diagnostic,`V23_PUBLIC_FAILURE:${stage}:TypeError:RESET_STORAGE_NOT_READY`);assert.equal(d.seen.at(-1),stage);
 assert(!JSON.stringify(r).includes('PRIVATE'));
});
test('success preserves existing mount operation order',async()=>{
 const d=dependencies(null),r=await run(d.require,d.fs,path,assert,diagnostic);assert.equal(r.completed,true);
 assert.deepEqual(d.seen,['mount-bound','mount-express','mount-listen','mount-auth','mount-dispatch','mount-public','mount-build','mount-static']);
});
test('unknowns/accessors/proxies never disclose error data',()=>{
 const e=Object.assign(Error('secret'),{code:'secret-code',name:'secret-name'});
 assert.equal(diagnostic('secret-stage',e),'V23_PUBLIC_FAILURE:unknown:unknown:unknown');
 const getter={get name(){throw Error('read forbidden')},get code(){throw Error('read forbidden')}};
 assert.equal(diagnostic('mount-build',getter),'V23_PUBLIC_FAILURE:mount-build:unknown:unknown');
 const proxy=new Proxy({}, {getOwnPropertyDescriptor(){throw Error('trap forbidden')}});
 assert.equal(diagnostic('mount-build',proxy),'V23_PUBLIC_FAILURE:mount-build:unknown:unknown');
 assert.equal(diagnostic('mount-build',Object.assign(Error('secret'),{code:'ENOENT'})),'V23_PUBLIC_FAILURE:mount-build:Error:ENOENT');
});
