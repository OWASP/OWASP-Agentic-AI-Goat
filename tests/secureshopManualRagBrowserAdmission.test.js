'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const ROOT=path.resolve(__dirname,'..');
function helper(overrides={}){
 const filename=path.join(__dirname,'postgres/secureshopManualRagRendered.integration.test.js');
 const real=require('node:module').createRequire(filename),module={exports:{}};
 vm.compileFunction(fs.readFileSync(filename,'utf8'),['require','module','process','__dirname'],{filename})(name=>{
  if(name==='node:test')return()=>{};
  if(name==='pg')return{Pool:class{constructor(){throw Error('Native allocation forbidden');}}};
  return Object.hasOwn(overrides,name)?overrides[name]:real(name);
 },module,{env:{},cwd:()=>ROOT,getuid:()=>process.getuid()},path.dirname(filename));
 return module.exports;
}
test('V26 opt-in admits exact Fixed-only and diagnostic scopes with private profiles and loopback origins',()=>{
 let mode=0o700,uid=process.getuid(),symlink=false,canonical=true;
 const reads=[],f=helper({'node:fs':{lstatSync:p=>{reads.push(p);return{
  isDirectory:()=>true,isSymbolicLink:()=>symlink,mode,uid};},
  realpathSync:p=>canonical?p:'/foreign'}});
 assert.deepEqual(f.manualRagBrowserArgs({},{}),[]);
 const run=path.join(ROOT,'tasks/qualification/run-controlled'),tmp=path.join(run,'runtime/tmp');
 const options={profile:path.join(tmp,'owasp-ai-goat-manual-rag-browser-controlled'),origin:'http://127.0.0.1:12345'};
 const env={SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX:'1',SECURESHOP_MANUAL_RAG_BROWSER_NATIVE:'1',
  NODE_ENV:'test',PG_TEST_DISPOSABLE:'yes',LIVE_OLLAMA_TEST:'1',OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:ROOT,
  OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE:run,TMPDIR:tmp,
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:'/controlled/python'};
 const args=f.manualRagBrowserArgs(env,options);
 assert.deepEqual(reads,[run,path.join(run,'runtime'),tmp,options.profile]);
 assert.ok(args.includes('--no-sandbox')&&args.includes('--proxy-server=http://blocked.invalid:9'));
 assert.ok(args.includes('--disable-background-networking'));
 assert.ok(args.some(v=>v.startsWith('--host-resolver-rules=MAP * ~NOTFOUND')));
 assert.ok(!args.some(v=>/disable-web-security|ignore-certificate/.test(v)));
 const fixed={...env,SECURESHOP_MANUAL_RAG_FIXED_ONLY:'1'};
 assert.deepEqual(f.manualRagBrowserArgs(fixed,options),args);
 for(const key of ['SECURESHOP_MANUAL_RAG_PAIRED','SECURESHOP_MANUAL_UPLOAD_Q05',
  'SECURESHOP_MANUAL_RAG_PAYLOAD_VARIANT','SECURESHOP_MANUAL_RAG_VARIANT_ATTEMPT'])
  for(const value of ['1','0',''])
   assert.throws(()=>f.manualRagBrowserArgs({...fixed,[key]:value},options));
 for(const patch of [{SECURESHOP_MANUAL_RAG_TEST_NO_SANDBOX:'true'},
  {SECURESHOP_MANUAL_RAG_BROWSER_NATIVE:'0'},{SECURESHOP_MANUAL_RAG_FIXED_ONLY:'true'},
  {SECURESHOP_MANUAL_RAG_FIXED_ONLY:'0'},
  {SECURESHOP_PRODUCT_SUMMARY_TEST_NO_SANDBOX:'1'},{NODE_ENV:'production'},
  {PG_TEST_DISPOSABLE:'no'},{LIVE_OLLAMA_TEST:'0'},{OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:'/foreign'},
  {OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE:tmp},{TMPDIR:run},{SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:'/foreign'}])
  for(const selected of [env,fixed])
   assert.throws(()=>f.manualRagBrowserArgs({...selected,...patch},options));
 for(const origin of ['http://example.com:12345','https://127.0.0.1:12345','http://127.0.0.1:12345/path'])
  for(const selected of [env,fixed])
   assert.throws(()=>f.manualRagBrowserArgs(selected,{...options,origin}));
 const bothDenied=changed=>{for(const selected of [env,fixed])
  assert.throws(()=>f.manualRagBrowserArgs(selected,changed));};
 bothDenied({...options,profile:path.join(tmp,'owasp-ai-goat-similar-browser-other')});
 mode=0o755;bothDenied(options);
 mode=0o700;uid++;bothDenied(options);
 uid=process.getuid();symlink=true;bothDenied(options);
 symlink=false;canonical=false;bothDenied(options);
});
test('V26 browser exception does not change diagnostic caps, no-credit scope or Fixed-only Judge exclusion',()=>{
 const f=helper();
 assert.deepEqual([f.cohortContract(false).actorCap,f.cohortContract(false).judgeCap],[14,4]);
 assert.deepEqual([f.cohortContract(true).actorCap,f.cohortContract(true).judgeCap],[10,0]);
 assert.equal(f.cohortContract(true).flags.length,15);
 assert.equal(f.cohortContract(true).similarRuns,1);
 for(const flag of ['fixedOnly','zeroJudge','noCredit','getOnlyRecovery','resetDenied','siblingPreserved'])
  assert.ok(f.cohortContract(true).flags.includes(flag));
 assert.match(f.cohortContract(true).scope,/zero Judge and no V26 assessment or credit/);
 assert.ok(f.cohortContract(false).flags.includes('noCredit'));
 assert.match(f.SCOPE,/diagnostic only/);
});
test('V26 summary remount requires exact saved GET and forbids summary/model replay while allowing session recovery',()=>{
 const f=helper(),result={sessionId:'owned-session',requestId:'owned-request',summary:'Original summary'};
 const original={method:'POST',pathname:'/products/9/summary',status:200,error:null,
  body:{sessionId:result.sessionId,requestId:result.requestId},response:JSON.stringify(result)};
 const requests=[original],before=f.summaryRecoverySnapshot(requests,9,6,0);
 const saved={method:'GET',pathname:before.savedPath,status:200,error:null,
  response:JSON.stringify({status:'completed',result})};
 requests.push({method:'POST',pathname:'/products/9/summary/session',status:200},saved);
 assert.deepEqual(f.assertSummaryRecovery(requests,before,6,0),result);
 for(const mutate of [
  rows=>rows.pop(),
  rows=>{rows[2].pathname=rows[2].pathname.replace('owned-request','foreign');},
  rows=>{rows[2].response=JSON.stringify({status:'completed',result:{...result,summary:'Changed'}});},
  rows=>{rows[2].status=503;},
  rows=>rows.push({...original})
 ]){const rows=structuredClone(requests);mutate(rows);assert.throws(()=>f.assertSummaryRecovery(rows,before,6,0));}
 assert.throws(()=>f.assertSummaryRecovery(requests,before,7,0));
 assert.throws(()=>f.assertSummaryRecovery(requests,before,6,1));
 assert.throws(()=>f.summaryRecoverySnapshot([],9,0,0));
 assert.equal(f.captureManualRagPath('/products/9/summary/sessions/a/requests/b'),true);
 assert.equal(f.captureManualRagPath('/products/9/summary/session'),true);
 assert.equal(f.captureManualRagPath('/products/9/summary-other'),false);
});
