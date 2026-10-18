'use strict';
// Fixture-only CDP transport: keep the production executor/browser and its
// synthetic origin proxy; avoid adding ephemeral WebSocket ports to the guard.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const evidenceRoot=fs.realpathSync(process.env.CSRF_FULL_INDEX_ROOT);
const limit=process.env.CSRF_MANAGED_BROWSER_LIMIT==='2'?2:1;
assert.ok([undefined,'1','2'].includes(process.env.CSRF_MANAGED_BROWSER_LIMIT),'Invalid owned browser limit');
const sequence=require('./csrfManagedBrowserSequence').createSequence(limit);
if(limit===2)fs.writeFileSync(path.join(evidenceRoot,'csrf-managed-sequence.json'),JSON.stringify({version:1,limit:2}),{mode:0o600});
const puppeteer=require('puppeteer'),launch=puppeteer.launch.bind(puppeteer);;
const launchOwned=async options=>{
 const lease=sequence.reserve();
 const root=limit===2?path.join(evidenceRoot,'csrf-managed-'+lease.index):evidenceRoot;
 if(limit===2)fs.mkdirSync(root,{mode:0o700});
 const profile=path.join(root,'csrf-managed-profile');fs.mkdirSync(profile,{mode:0o700});
 let browser,child,identity,phase='launch',closed=false;
 const cleanup=async()=>{if(closed)return;closed=true;if(browser)await originalClose();if(child&&child.exitCode===null&&child.signalCode===null)await Promise.race([new Promise(r=>child.once('exit',r)),new Promise((_,reject)=>setTimeout(()=>reject(Error('Managed browser close deadline')),3000))]);if(child)assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});if(identity)await require('./csrfManagedBrowserOwnership').assertGroupDrained(identity);fs.rmSync(profile,{recursive:true,force:true});fs.writeFileSync(path.join(root,'csrf-managed-cleanup.json'),JSON.stringify({pid:child?.pid||null,pgid:identity?.pgid||null,absent:true,groupAbsent:!!identity,profileAbsent:!fs.existsSync(profile)}),{mode:0o600});lease.release();};
 let originalClose;
 try{
  const cp=require('node:child_process'),spawn=cp.spawn;let captured;
  cp.spawn=function(executable,args,spawnOptions){
   const result=spawn.call(this,executable,args,spawnOptions);
   if(executable===process.env.PUPPETEER_EXECUTABLE_PATH&&args?.includes('--user-data-dir='+profile)){
    child=result;captured=new Promise((resolve,reject)=>{result.once('spawn',()=>{try{identity=require('./csrfManagedBrowserOwnership').captureManagedIdentity({child:result,profile,root,executable});fs.writeFileSync(path.join(root,'csrf-managed-launch.json'),JSON.stringify(identity),{mode:0o600});resolve(identity);}catch(error){reject(error);}});result.once('error',reject);});captured.catch(()=>{});
   }
   return result;
  };
  try{browser=await launch({...options,pipe:true,userDataDir:profile});originalClose=browser.close.bind(browser);phase='ownership';assert.ok(captured,'Exact browser spawn observed');identity=await captured;assert.equal(child,browser.process());}
  finally{cp.spawn=spawn;}
  fs.writeFileSync(path.join(root,'csrf-managed-process.json'),JSON.stringify({...identity,profile,pipe:true}),{mode:0o600});
  browser.close=cleanup;return browser;
 }catch(error){
  // Closed structured diagnostics: no arbitrary error text, URL, args or env.
  fs.writeFileSync(path.join(root,'csrf-managed-error.json'),JSON.stringify({phase,name:['Error','TypeError','AssertionError','TimeoutError'].includes(error.name)?error.name:'OtherError',code:typeof error.code==='string'&&/^[A-Z0-9_]{1,60}$/.test(error.code)?error.code:null,...(Number.isSafeInteger(error.actual)?{actual:error.actual}:{}),...(Number.isSafeInteger(error.expected)?{expected:error.expected}:{})}),{mode:0o600});
  await cleanup();throw error;
 }

};

// Puppeteer is an ESM namespace under Node 26: its export descriptors may look
// writable but assignment is forbidden. Return a narrow fixture facade instead.
const Module=require('node:module'),originalLoad=Module._load;
const facade=Object.freeze({...puppeteer,launch:launchOwned});
const diagnosticApi=require('./csrfWorkflowDiagnostic');
let postReceiptSequence=0;
const observeFinal=process.env.CSRF_CAPTURE_POST_RECEIPTS==='1'?packet=>{if(++postReceiptSequence>4)throw Error('POST receipt bound exceeded');fs.writeFileSync(path.join(evidenceRoot,'csrf-post-owned-receipt-'+postReceiptSequence+'.json'),JSON.stringify({binding:packet.binding,receipt:packet.receipt,activity:packet.activity},null,2),{mode:0o600});}:undefined;
const diagnostic=diagnosticApi.createDiagnostic({root:evidenceRoot,source:process.cwd()});
const workflowPath=path.join(process.cwd(),'server/services/csrfBrowserWorkflow.js');
Module._load=function(name,...args){if(name==='puppeteer')return facade;const result=originalLoad.call(this,name,...args);if(Module._resolveFilename(name,args[0])===workflowPath)return {...result,createCsrfBrowserWorkflow:diagnosticApi.instrumentWorkflowFactory(result.createCsrfBrowserWorkflow,diagnostic,observeFinal)};return result;};
