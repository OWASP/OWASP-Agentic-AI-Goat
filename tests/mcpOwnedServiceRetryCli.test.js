'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {readRetryEnvironment}=require('../scripts/install/mcp-owned-service-retry-environment');
const {runOwnedHttpRetryCli}=require('../scripts/install/mcp-owned-http-setup');
const {runOwnedShadowRetryCli}=require('../scripts/install/mcp-owned-shadow-setup');
const { _internals: runnerInstall }=require('../scripts/install/mcp-owned-provision');

test('Windows retry reads only the admitted workspace-private .env and names missing or untrusted state',async()=>{
 const file='C:\\workspace\\.env';let reads=0;
 const base={root:'C:\\workspace',platform:'win32',service:'HTTP',environment:{BASE:'retained'},
  fileSystem:{lstat:async value=>{assert.equal(value,file);return{isFile:()=>true,isSymbolicLink:()=>false};}},
  privateState:{readPrivateWorkspaceFile:value=>{assert.equal(value,file);reads++;return Buffer.from('ADDED=private\n');}}};
 assert.deepEqual(await readRetryEnvironment(base),{BASE:'retained',ADDED:'private'});
 assert.equal(reads,1);
 await assert.rejects(readRetryEnvironment({...base,fileSystem:{lstat:async()=>{throw Object.assign(Error('missing'),{code:'ENOENT'});}}}),
  {code:'MCP_HTTP_SETUP_ENV_REQUIRED'});
 await assert.rejects(readRetryEnvironment({...base,privateState:{readPrivateWorkspaceFile:()=>{throw Error('denied');}}}),
  {code:'MCP_HTTP_SETUP_ENV_UNTRUSTED'});
 await assert.rejects(readRetryEnvironment({...base,service:'SHADOW',privateState:{readPrivateWorkspaceFile:()=>Buffer.alloc(1024*1024+1)}}),
  {code:'MCP_SHADOW_SETUP_ENV_UNTRUSTED'});
});

for(const [name,runRetry,port] of [['HTTP',runOwnedHttpRetryCli,8093],['shadow',runOwnedShadowRetryCli,8094]]){
 test(`${name} Windows retry opens CLI and service forwards before setup and drains on success or failure`,async()=>{
  for(const fail of [false,true]){
   const events=[];const session={openLoopbackForwards:async(ports,{ownChild})=>{
    assert.deepEqual(ports,[{local:8092,guest:8092},{local:port,guest:port}]);assert.equal(ownChild,'owned-child');events.push('forward');return{};}};
   const args={root:'C:\\workspace',homeDirectory:'C:\\home',platform:'win32',
    readEnvironment:async()=>({PRIVATE:'loaded'}),
    prepareWindowsLabInstallation:async options=>{assert.equal(options.mode,'existing');assert.equal(options.environment.PRIVATE,'loaded');events.push('prepare');
     return{session,ownLabChild:'owned-child',close:async()=>events.push('close')};},
    provisionForSetup:async options=>{assert.equal(options.ownedLabSession,session);events.push('provision');if(fail)throw Error('controlled');return{ok:true};}};
   if(fail)await assert.rejects(runRetry(args),/controlled/);
   else assert.deepEqual(await runRetry(args),{ok:true});
   assert.deepEqual(events,['prepare','forward','provision','close']);
  }
  let closed=false;
  await assert.rejects(runRetry({root:'C:\\workspace',platform:'win32',
   readEnvironment:async()=>({}),
   prepareWindowsLabInstallation:async()=>({session:{openLoopbackForwards:async()=>({failurePromise:Promise.reject(Error('forward gone'))})},
    ownLabChild:()=>{},close:async()=>{closed=true;}}),
   provisionForSetup:async()=>{await Promise.resolve();return{ok:true};}}),/forward gone/);
  assert.equal(closed,true);
 });
}

test('Windows runner bridge preserves the admitted Compose build timeout in opaque Docker calls',async()=>{
 const calls=[],sha='a'.repeat(64),bindingSha256='b'.repeat(64);
 const plan={profile:'owasp-ai-goat-mcp-sandbox',destination:'/etc/apparmor.d/owasp-ai-goat-mcp-sandbox',
  sessionBinding:{workspaceId:'c'.repeat(12),bindingSha256}};
 const session={
  installAndVerifyProfile:async()=>({name:plan.profile,sha256:sha,destination:plan.destination,bindingSha256}),
  stageReviewedBundle:async()=>'/guest/bundle',stagePrivateEnvironment:async()=>'/guest/env',
  executeDocker:async(args,options)=>{calls.push({args,options});return'';},
 };
 const bridge=await runnerInstall.windowsInstall({plan,rendered:'profile',renderedSha256:sha,session,
  root:'C:\\workspace',commandEnv:{MCP_OWNED_TARGET_TOKEN:'t'.repeat(64)},bundleCollector:async()=>[]});
 await bridge('docker',['--host',null,'compose','--profile','mcp-owned','up','--build','--wait','mcp-owned-sandbox'],{timeoutMs:600000});
 await bridge('docker',['--host',null,'inspect','container'],{timeoutMs:30000});
 assert.equal(calls[0].options.timeoutMs,600000);
 assert.equal(calls[1].options.timeoutMs,30000);
 assert.deepEqual(calls[0].args.slice(0,6),['compose','--project-name','owasp-ai-goat-'+plan.sessionBinding.workspaceId,'--env-file','/guest/env','--profile']);
 assert.equal(calls.every(call=>call.options.bundlePath==='/guest/bundle'),true);
});
