'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {admitCsrfMainProfile,ensureOwnedRuntimeDirectory}=require('./fixtures/csrfMainProfile');
const {qualificationModel}=require('./fixtures/csrfFullIndexTransport');
const {assertActualCalls}=require('./fixtures/csrfIndirectChainEvidence');
test('historical CSRF profile keeps its exact 8B model and closed 70B requires the indirect chain',()=>{
 assert.deepEqual(qualificationModel(),{model:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'});
 assert.deepEqual(qualificationModel(true),{model:'llama3.3:70b',digest:'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'});
 assert.throws(()=>qualificationModel('yes'),/Closed CSRF model/);
 assert.deepEqual(admitCsrfMainProfile({mode:'actual-indirect-chain',env:{},evidenceRoot:'/tmp/evidence'}),{selected70b:false});
 assert.throws(()=>admitCsrfMainProfile({mode:'actual-indirect-chain',env:{CSRF_FULL_INDEX_70B:'true'},evidenceRoot:'/tmp/evidence'}),/Closed CSRF 70B/);
});
test('selected CSRF profile binds external runtime and browser, and rejects other modes or source overlap',()=>{
 const base=fs.mkdtempSync(path.join(os.tmpdir(),'csrf-profile-'));
 try{
  const source=fs.realpathSync(path.join(__dirname,'..')),runtime=path.join(base,'runtime'),evidence=path.join(base,'evidence'),browser=path.join(base,'browser');
  for(const dir of[runtime,evidence])fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(browser,'fixture browser');
  const env={CSRF_FULL_INDEX_70B:'yes',CSRF_FULL_INDEX_SOURCE_ROOT:source,CSRF_FULL_INDEX_RUNTIME_ROOT:runtime,CSRF_FULL_INDEX_BROWSER_EXECUTABLE:browser,CSRF_FULL_INDEX_BROWSER_SHA256:'a'.repeat(64)};
  assert.deepEqual(admitCsrfMainProfile({mode:'actual-indirect-chain',env,evidenceRoot:evidence}),{selected70b:true,source:fs.realpathSync(source),runtimeRoot:fs.realpathSync(runtime),browserPath:fs.realpathSync(browser),browserSha256:'a'.repeat(64)});
  assert.throws(()=>admitCsrfMainProfile({mode:'actual-get-chain',env,evidenceRoot:evidence}),/only for the fixed indirect chain/);
  assert.throws(()=>admitCsrfMainProfile({mode:'actual-indirect-chain',env:{...env,CSRF_FULL_INDEX_RUNTIME_ROOT:source},evidenceRoot:evidence}),/outside main source/);
  const copied=path.join(base,'copied');fs.mkdirSync(copied);
  assert.throws(()=>admitCsrfMainProfile({mode:'actual-indirect-chain',env:{...env,CSRF_FULL_INDEX_SOURCE_ROOT:copied},evidenceRoot:evidence}),/Exact current main checkout/);
  fs.symlinkSync(path.join(base,'missing'),path.join(runtime,'.env'));
  assert.throws(()=>admitCsrfMainProfile({mode:'actual-indirect-chain',env,evidenceRoot:evidence}),/must not load private environment/);
  fs.rmSync(path.join(runtime,'.env'));
  assert.throws(()=>admitCsrfMainProfile({mode:'actual-indirect-chain',env:{...env,CSRF_FULL_INDEX_BROWSER_SHA256:'missing'},evidenceRoot:evidence}));
 }finally{fs.rmSync(base,{recursive:true,force:true});}
});
test('selected native path runs backend from external cwd with an absolute main source and fixed call cap',()=>{
 const native=fs.readFileSync(path.join(__dirname,'postgres/csrfFullIndex.native.js'),'utf8');
 assert.match(native,/launchCwd=profile\.selected70b\?runtimeRoot:source/);
 assert.match(native,/cwd:launchCwd,env/);
 assert.match(native,/path\.join\(source,'server\/index\.js'\)/);
 assert.match(native,/DVAIA_ISOLATED_TEST_WORKSPACE=source/);
 assert.match(native,/profile\.selected70b\?'--require='\+path\.join\(source,'tests\/fixtures\/dpiPostgresOnlyGuard\.cjs'\)/);
 assert.match(native,/selected70b:profile\.selected70b/);
 assert.match(native,/maxHttpCalls:\(chain\|\|postChain\|\|indirect\)\?18:8/);
 const transport=fs.readFileSync(path.join(__dirname,'fixtures/csrfFullIndexTransport.js'),'utf8');
 assert.match(transport,/Actual CSRF model60s deadline/);
});
test('selected-model actor wire rejects mixed or incomplete terminal provenance',()=>{
 const {createHash}=require('node:crypto'),sha=value=>createHash('sha256').update(value).digest('hex');
 const model=qualificationModel(true).model;
 const request=JSON.stringify({model,stream:false,messages:[{role:'system',content:"VaultLink's AI knowledge-base"}]});
 const response=JSON.stringify({model,message:{content:'bounded output'},done:true});
 const call={request,response,requestSha256:sha(request),responseSha256:sha(response),status:200,responseComplete:true,responseCaptureTruncated:false};
 assert.equal(assertActualCalls([call],model).text,'bounded output');
 assert.throws(()=>assertActualCalls([call],'llama3.1:8b'));
 assert.throws(()=>assertActualCalls([{...call,responseComplete:false}],model));
});
test('selected main-only preload denies legacy learner database imports before opening a store',()=>{
 const {spawnSync}=require('node:child_process'),source=fs.realpathSync(path.join(__dirname,'..'));
 const guard=path.join(source,'tests/fixtures/dpiPostgresOnlyGuard.cjs');
 const env={PATH:process.env.PATH,DVAIA_ISOLATED_TEST_WORKSPACE:source,NODE_OPTIONS:'--require='+guard};
 const denied=spawnSync(process.execPath,['-e',"require('./server/database/authDb')"],{cwd:source,env,encoding:'utf8',timeout:5000});
 assert.notEqual(denied.status,0);assert.match(denied.stderr,/Legacy SQLite module denied in disposable DPI PostgreSQL qualification/);
 const allowed=spawnSync(process.execPath,['-e',"require('pg').Pool;"],{cwd:source,env,encoding:'utf8',timeout:5000});
 assert.equal(allowed.status,0,allowed.stderr);
});
test('selected native bootstrap accepts the already-owned logs directory and rejects links or loose modes',()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'csrf-owned-runtime-')));
 try{
  fs.chmodSync(root,0o700);const logs=path.join(root,'logs'),appdata=path.join(root,'app-data');
  fs.mkdirSync(logs,{mode:0o700});ensureOwnedRuntimeDirectory(logs,root);ensureOwnedRuntimeDirectory(appdata,root);
  assert.equal(fs.statSync(appdata).mode&0o777,0o700);
  fs.chmodSync(logs,0o755);assert.throws(()=>ensureOwnedRuntimeDirectory(logs,root),/Owned private runtime directory/);
  fs.rmdirSync(logs);fs.symlinkSync(appdata,logs);assert.throws(()=>ensureOwnedRuntimeDirectory(logs,root),/Owned private runtime directory/);
  assert.throws(()=>ensureOwnedRuntimeDirectory(path.join(root,'nested','logs'),root),/direct owned runtime/);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('selected full-app boot binds CTF delivery to its disposable CTF store and activates before server startup',()=>{
 const native=fs.readFileSync(path.join(__dirname,'postgres/csrfFullIndex.native.js'),'utf8');
 const delivery=native.indexOf("const delivery=new URL(process.env.CTF_DELIVERY_DATABASE_URL)");
 const activate=native.indexOf('createCtfDeliveryActivationOperator');
 const verify=native.indexOf('createCtfDeliveryActivation({identityPool:identity,ctfPool:ctfRuntime}).verify');
 const backend=native.indexOf("backend=owned.launch(process.execPath");
 assert.ok(0<delivery&&delivery<activate&&activate<verify&&verify<backend);
 assert.match(native,/assert\.equal\(delivery\.host,ctf\.host\)/);
 assert.match(native,/assert\.equal\(delivery\.pathname,ctf\.pathname\)/);
 assert.match(native,/assert\.equal\(decodeURIComponent\(delivery\.username\),'dvaia_ctf_delivery'\)/);
 assert.match(native,/assert\.equal\(activated\.trafficStarted,false\)/);
});
