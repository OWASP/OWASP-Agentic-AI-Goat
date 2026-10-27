'use strict';
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs'),filePath=require('node:path'),test=require('node:test');

async function main(){
 const source=fs.readFileSync(filePath.join(__dirname,'postgres/secureshopV23PublicRendered.integration.test.js'),'utf8');
 new vm.Script(source,{filename:'secureshopV23PublicRendered.integration.test.js'});
 const begin=source.indexOf('function boundedFramePath(');
 const end=source.indexOf('async function selectPublicMode(',begin);
 assert(begin>=0&&end>begin);
 const context=vm.createContext({assert,URL});
 vm.runInContext(source.slice(begin,end)+`\nglobalThis.extracted={boundedFramePath,boundedPageErrorClass,publicAdminFrame};`,context);
 const {boundedFramePath:path,boundedPageErrorClass:kind,publicAdminFrame:frame}=context.extracted;
 const origin='http://127.0.0.1:23456';
 assert.equal(path(origin+'/api/secureshop/v2/auth/whoami?token=secret',origin),'/api/secureshop/v2/auth/whoami');
 assert.equal(path(origin+'/api/secureshop/agents/admin/assistant/operations/private-id',origin),'other');
 assert.equal(path('http://foreign.invalid/secret',origin),null);
 assert.equal(path('not-a-url',origin),null);
 assert.equal(vm.runInContext(`extracted.boundedPageErrorClass(new ReferenceError('SECRET'))`,context),'ReferenceError');
 assert.equal(vm.runInContext(`extracted.boundedPageErrorClass(new Error('SECRET'))`,context),'Error');
 assert.equal(kind(null),'unknown');
 const stages=[];let disposed=0;
 const page={async waitForSelector(selector){assert.match(selector,/iframe/);return{
  async contentFrame(){return{detached:false,async waitForSelector(inner){assert.match(inner,/admin-role-composer-slot/);return {};}}},
  async dispose(){disposed++;}};}};
 assert(await frame(page,value=>stages.push(value)));
 assert.deepEqual(stages,['turn-frame-element','turn-frame-attach','turn-frame-composer']);
 assert.equal(disposed,1);
 const failed=[];
 await assert.rejects(frame({async waitForSelector(){throw Error('SECRET');}},value=>failed.push(value)));
 assert.deepEqual(failed,['turn-frame-element']);
 const attach=[];
 await assert.rejects(frame({async waitForSelector(){return{async contentFrame(){return null;},async dispose(){}};}},
  value=>attach.push(value)));
 assert.deepEqual(attach,['turn-frame-element','turn-frame-attach']);
 const composer=[];
 await assert.rejects(frame({async waitForSelector(){return{async contentFrame(){return{detached:false,
  async waitForSelector(){throw Error('SECRET');}};},async dispose(){}};}},value=>composer.push(value)));
 assert.deepEqual(composer,['turn-frame-element','turn-frame-attach','turn-frame-composer']);
 const observer=source.indexOf("page.on('response',response=>recordFrame");
 const navigation=source.indexOf('const login=await page.goto(');
 assert(observer>=0&&navigation>observer);
 assert.match(source,/currentFrameDiagnostic\.signals\.length>=24/);
 assert.match(source,/currentFrameDiagnostic\.pageErrors\.length<4/);
 assert.match(source,/if\(frameDiagnostic\)result\.frameDiagnostic=frameDiagnostic/);
 assert.match(source,/let stage='initial';\n let frameDiagnostic=null;/);
 const catchBlock=source.match(/ \}catch\(error\)\{primary=error;result\.errors\.push\(publicFailureDiagnostic\(stage,error\)\);\n  if\(frameDiagnostic\)result\.frameDiagnostic=frameDiagnostic;\}/)?.[0];
 assert(catchBlock);
 const declaration="let stage='initial';\n let frameDiagnostic=null;";
 const wrapper=new Function('failure','initialize','publicFailureDiagnostic',
  `const result={errors:[]};let primary;${declaration}\ntry{if(initialize)frameDiagnostic={version:1,stage:'turn-frame-element',signals:[],pageErrors:[]};throw failure;${catchBlock}\nreturn {primary,result};`);
 const original=new Error('PRIVATE_MESSAGE');
 const early=wrapper(original,false,()=> 'V23_PUBLIC_FAILURE:initial:Error:unknown');
 assert.equal(early.primary,original);assert.deepEqual(early.result.errors,['V23_PUBLIC_FAILURE:initial:Error:unknown']);
 assert.equal(Object.hasOwn(early.result,'frameDiagnostic'),false);
 const framed=wrapper(original,true,()=> 'V23_PUBLIC_FAILURE:turn-frame-element:Error:unknown');
 assert.equal(framed.primary,original);assert.equal(framed.result.frameDiagnostic.stage,'turn-frame-element');
 assert.deepEqual(framed.result.errors,['V23_PUBLIC_FAILURE:turn-frame-element:Error:unknown']);
 assert.match(source,/const currentFrameDiagnostic=\{version:1,stage:'turn-login',signals:\[\],pageErrors:\[\]\}/);
 assert(!source.includes('frameDiagnostic.signals.push('));
 assert(!source.includes('error.message)frameDiagnostic'));

}
test('V23 bounded turn-frame diagnostics preserve privacy and primary failure',main);
