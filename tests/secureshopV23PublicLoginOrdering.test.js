'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {pathToFileURL}=require('node:url');
const root=path.resolve(__dirname,'..');
const revised=fs.readFileSync(path.join(root,'tests/postgres/secureshopV23PublicRendered.integration.test.js'),'utf8');
const loginSource=fs.readFileSync(path.join(root,'client/src/pages/secureshop/pages/Login.jsx'),'utf8');
const actual=loginSource.match(/const loggedInUser = await login\(username, password\);\s*navigate\(destination\(loggedInUser\), \{ replace: true \}\);/);
assert(actual,'actual login continuation must retain source shape');
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const continueLogin=new AsyncFunction('login','navigate','destination','username','password',actual[0]);
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};};
async function setup(next){
 const {safeLoginDestination}=await import(pathToFileURL(path.join(root,'client/src/pages/secureshop/utils/loginDestination.mjs')).href);
 const response=deferred(),login=deferred();let pathname='/secureshop/login';const events=[];
 const continuation=continueLogin(()=>login.promise,url=>{pathname=url;events.push('ui-navigation');},user=>safeLoginDestination(next,user),'owned','not-retained');
 return{response,login,continuation,events,get pathname(){return pathname},goto(url){pathname=url;events.push('fixture-navigation');}};
}
test('actual login continuation can navigate after bootstrap response and overwrite manual target',async()=>{
 const state=await setup('/secureshop/home');
 state.response.resolve({persona:{user:{role:'admin'}}});await state.response.promise;
 state.goto('/secureshop/admin/mcp');
 state.login.resolve({role:'admin'});await state.continuation;
 assert.equal(state.pathname,'/secureshop/admin');
 assert.deepEqual(state.events,['fixture-navigation','ui-navigation']);
});
test('explicit admitted next destination plus UI completion avoids competing navigation',async()=>{
 const state=await setup('/secureshop/admin/mcp');
 state.response.resolve({persona:{user:{role:'admin'}}});await state.response.promise;
 let ready=false;
 const wait=state.continuation.then(()=>{assert.equal(state.pathname,'/secureshop/admin/mcp');ready=true;});
 await Promise.resolve();assert.equal(ready,false);
 state.login.resolve({role:'admin'});await wait;
 assert.deepEqual(state.events,['ui-navigation']);
 assert.match(revised,/login\?next=%2Fsecureshop%2Fadmin%2Fmcp/);
 assert.match(revised,/waitForFunction\(\(\)=>window.location.pathname==='\/secureshop\/admin\/mcp',\s*\{timeout:30000\}\)/);
 assert.doesNotMatch(revised,/const mountedPage=await page.goto/);
 assert.match(revised,/const frame=await publicAdminFrame\(page\)/);
});
test('setup substeps use only fixed enums and privacy-safe existing diagnostic',()=>{
 const helper=revised.slice(revised.indexOf('function publicFailureDiagnostic('),revised.indexOf('async function runPublicNative('));
 const diagnostic=new Function('require',helper+';return publicFailureDiagnostic;')(require);
 for(const stage of ['turn-navigation','turn-capability','turn-authentication','turn-mode','turn-journal']){
  assert(revised.includes("stage='"+stage+"';"));
  assert.equal(diagnostic(stage,new Error('private-path-or-secret')),`V23_PUBLIC_FAILURE:${stage}:Error:unknown`);
 }
 assert.equal(diagnostic('private-stage',new Error('secret')),'V23_PUBLIC_FAILURE:unknown:Error:unknown');
});
