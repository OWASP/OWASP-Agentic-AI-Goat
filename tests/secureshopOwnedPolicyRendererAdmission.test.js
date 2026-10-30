'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {rendererAdmissionPath}=require('./fixtures/secureshopOwnedPolicyRendererAdmission');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const owner=require('./postgres/ownedSystemOriginalBrowserOwner')._internals;
const {createRequire}=require('node:module');
function borrowed({mutate=()=>{},directoryFault=null,fetchImpl=null}={}){
 const root=owner.ROOT,runId='a'.repeat(32),directory=root+'/tasks/qualification/system-original-owner-'+runId;
 const options={root,runId,producer:{root,runId},signal:new AbortController().signal,node:owner.NODE,nodeSha256:'a'.repeat(64),
  pythonSha256:'b'.repeat(64),browser:owner.BROWSER,browserSha256:'c'.repeat(64),pgNonce:'d'.repeat(12),pgPort:15432,
  policyVersion:'configuration-readability-relative-v3'};
 const endpoints={system:{client:{},port:18090,baseURL:'http://127.0.0.1:18090',token:'t'.repeat(43)},
  policy:{client:{},port:18091,baseURL:'http://127.0.0.1:18091'},signal:new AbortController().signal,deadline:performance.now()+900000};
 const env={...owner.childEnvironment(options,endpoints)};mutate(env);
 const requests=[],effects=[];
 const health=()=>new Response(JSON.stringify({policyRenderer:{enabled:true,available:true,
  isolation:require('../server/services/secureshopPromptPolicyContract').ISOLATION}}));
 const fakeFetch=(url,init)=>{requests.push({url,init});return fetchImpl?fetchImpl(url,init,health):Promise.resolve(health());};
 const filename=path.join(__dirname,'fixtures/secureshopOwnedPolicyRendererAdmission.js'),local=createRequire(filename),module={exports:{}};
 const io={realpath:async p=>directoryFault==='realpath'&&p===directory?'/foreign':p,lstat:async()=>({
  isDirectory:()=>directoryFault!=='file',isSymbolicLink:()=>directoryFault==='symlink',uid:directoryFault==='uid'?999:501,
  mode:directoryFault==='mode'?0o755:0o700})};
 vm.runInNewContext('(function(require,module,exports){'+fs.readFileSync(filename,'utf8')+'\n})',{
  Buffer,URL,AbortController,AbortSignal,globalThis:{fetch:fakeFetch},process:{cwd:()=>root,getuid:()=>501,env},
  setTimeout:(fn,ms)=>setTimeout(fn,ms===5000?5:ms),clearTimeout
 })(id=>id==='node:fs/promises'?io:id==='node:child_process'?{execFile(){effects.push('process');throw Error('forbidden process');}}:local(id),module,module.exports);
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const start=source.indexOf('async function capturePolicyInstructionRenderer('),end=source.indexOf('function assertPolicyInstructionRepositoryEvidencePath(',start);
 assert(start>=0&&end>start);
 const admit=new vm.Script(source.slice(start,end)+'\ncapturePolicyInstructionRenderer').runInNewContext({
  process:{env},require:id=>{assert.equal(id,'../fixtures/secureshopOwnedPolicyRendererAdmission');return module.exports;}});
 return {admit:()=>admit(root,env),env,requests,effects,health};
}
test('actual owner environment and original fixture helper borrow canonical renderer without Docker or managed records',async()=>{
 const f=borrowed(),renderer=await f.admit();
 assert.equal(renderer.identity.target,'original-v24-policy');assert.equal(renderer.identity.ownership,'paired-producer');
 assert.deepEqual(f.effects,[]);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'http://127.0.0.1:18091/health');
 assert.equal(f.requests[0].init.headers,undefined);assert.equal(f.requests[0].init.redirect,'error');
 await renderer.check();const close=await renderer.close();assert.equal(close.localRetired,true);assert.equal(close.remoteRetired,false);assert.equal(close.builderReleaseAllowed,false);
 const count=f.requests.length;await assert.rejects(async()=>renderer.check());assert.equal(f.requests.length,count);
 assert.equal(await renderer.close(),close);assert.deepEqual(f.effects,[]);
});
test('borrowed renderer sends the original execution envelope and validates the actual response contract',async()=>{
 const contract=require('../server/services/secureshopPromptPolicyContract');
 const request={operationId:'123e4567-e89b-42d3-a456-426614174000',name:'returns',markdown:'Hello {{ store_name }}',targets:['customer']};
 const completed=contract.createLiteralRenderResult(request);let malformed=false;
 const f=borrowed({fetchImpl:async(url,init,health)=>{
  if(url.endsWith('/health'))return health();
  assert.equal(url,'http://127.0.0.1:18091/secureshop/policy-render');assert.equal(init.method,'POST');
  assert.deepEqual(JSON.parse(init.body),{version:2,mode:'fixed',request});assert.equal(init.redirect,'error');
  return new Response(JSON.stringify(malformed?{...completed,drained:false}:completed));
 }}),renderer=await f.admit();
 assert.deepEqual(await renderer.runtime.render(request,{executionMode:'fixed'}),completed);
 malformed=true;await assert.rejects(renderer.runtime.render(request,{executionMode:'fixed'}),{code:'POLICY_RENDER_UNAVAILABLE'});
 await renderer.close();const count=f.requests.length;
 await assert.rejects(async()=>renderer.runtime.render(request,{executionMode:'fixed'}));assert.equal(f.requests.length,count);
 assert.deepEqual(f.effects,[]);
});
test('borrowed V24 rejects old records, other selectors/runs, endpoint swaps and unsafe paths before network',async()=>{
 const mutations=[e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE='0',e=>e.NODE_ENV='production',e=>e.PG_TEST_DISPOSABLE='no',
  e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_RENDERER_TRANSPORT='legacy',e=>e.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE='/other',
  e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID='b'.repeat(32),e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY='/tmp',
  e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_ADMISSION='/old/record',
  ...['http://remote:8090','http://127.0.0.1:18090','http://127.0.0.1:18091/','http://user@127.0.0.1:18091',
   'http://127.0.0.1:99999','http://127.0.0.1:1000','http://127.0.0.1:18091?secret=x'].map(value=>e=>e.SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_URL=value)];
 for(const mutate of mutations){const f=borrowed({mutate});await assert.rejects(f.admit());assert.equal(f.requests.length,0);assert.deepEqual(f.effects,[]);}
 for(const directoryFault of ['file','symlink','uid','mode','realpath']){const f=borrowed({directoryFault});await assert.rejects(f.admit());assert.equal(f.requests.length,0);}
});
test('real borrowed protocol rejects bad health; unjoined local work preserves debt and never claims remote retirement',async()=>{
 const bad=borrowed({fetchImpl:async()=>new Response('{}')});await assert.rejects(bad.admit(),{code:'POLICY_RENDER_UNAVAILABLE'});assert.equal(bad.requests.length,1);
 let release,calls=0;const wait=new Promise(resolve=>{release=resolve;});
 const f=borrowed({fetchImpl:async(_url,_init,health)=>++calls===1?health():wait});
 const renderer=await f.admit(),pending=renderer.check();void pending.catch(()=>{});
 await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(renderer.close(),error=>error.code==='POLICY_BORROWED_UNJOINED'&&error.retirementUnproven);
 release(f.health());await assert.rejects(pending);await assert.rejects(renderer.close(),{code:'POLICY_BORROWED_UNJOINED'});assert.deepEqual(f.effects,[]);
});
test('original V24 renderer admits only exact repository run path with its owned child environment',()=>{
 const root='/owned/repository',runId='a'.repeat(32),filename=root+'/tasks/qualification/system-renderer-'+runId+'/admission.json';
 const env={SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE:'1',PG_TEST_DISPOSABLE:'yes',NODE_ENV:'test',
  OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:root,SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID:runId,
  SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY:root+'/tasks/qualification/system-original-owner-'+runId};
 assert.doesNotThrow(()=>rendererAdmissionPath(root,filename,env));
 for(const key of Object.keys(env))assert.throws(()=>rendererAdmissionPath(root,filename,{...env,[key]:'wrong'}));
 for(const value of [filename+'/..',filename.replace(runId,'b'.repeat(32)),root+'/admission.json'])
  assert.throws(()=>rendererAdmissionPath(root,value,env));
 assert.doesNotThrow(()=>rendererAdmissionPath(root,'/external/admission.json',{}));
});
