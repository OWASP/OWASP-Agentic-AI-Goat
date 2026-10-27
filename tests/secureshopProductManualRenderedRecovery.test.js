'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {randomUUID}=require('node:crypto');
const {spawnSync}=require('node:child_process');
const fs=require('node:fs/promises');
const path=require('node:path');
const R=require('./fixtures/secureshopProductManualRenderedRecovery');
const id='123e4567-e89b-41d3-a456-426614174000',key='a'.repeat(64);
const endpoint='http://127.0.0.1:8081'+R.POST;
const rows=()=>[
  {method:'GET',path:R.GET,status:200,state:'not_found',operationId:id,recoveryScopeKey:key,receipt:false},
  {method:'POST',path:R.POST,status:200,state:'indexed',operationId:id,recoveryScopeKey:key,receipt:true},
  {method:'GET',path:R.GET,status:200,state:'indexed',operationId:id,recoveryScopeKey:key,receipt:true},
];
test('new selector imports the actual rendered fixture but cannot run without disposable native admission',()=>{
  const root=path.resolve(__dirname,'..');
  const env={...process.env,SECURESHOP_PRODUCT_MANUAL_RECOVERY_BROWSER_NATIVE:'1',
    PG_TEST_DISPOSABLE:'no',LIVE_OLLAMA_TEST:'0'};
  delete env.NODE_TEST_CONTEXT;
  const run=spawnSync(process.execPath,['--test','--test-reporter=tap',
    'tests/postgres/secureshopStandaloneListingsRendered.integration.test.js'],
    {cwd:root,env,encoding:'utf8',timeout:10000,maxBuffer:65536});
  assert.equal(run.status,0,run.stderr);
  assert.match(run.stdout,/Q05 physical merchant manual commit loss/);
  assert.match(run.stdout,/# SKIP/);
  assert.match(run.stdout,/fail 0/);
});
test('repo-private exact evidence admission rejects prior files, loose modes and symlinks',async()=>{
  const root=path.resolve(__dirname,'..');
  const owned=await fs.mkdtemp(path.join(root,'tasks/qualification/run-manual-recovery-'));
  const receipt=path.join(owned,'merchant-product-manual-recovery-v1.json');
  const alias=path.join(root,'tasks/qualification',`run-manual-link-${randomUUID()}`);
  try{
    await fs.chmod(owned,0o700);
    assert.equal(await R.assertPrivateReceiptPath(root,receipt),owned);
    await assert.rejects(R.assertPrivateReceiptPath(root,path.join(owned,'other.json')));
    await fs.chmod(owned,0o755);
    await assert.rejects(R.assertPrivateReceiptPath(root,receipt));
    await fs.chmod(owned,0o700);
    await fs.writeFile(receipt,'reserved',{flag:'wx',mode:0o600});
    await assert.rejects(R.assertPrivateReceiptPath(root,receipt));
    await assert.rejects(R.publishPrivateReceipt(receipt,{passed:true}),error=>error?.code==='EEXIST');
    assert.equal(await fs.readFile(receipt,'utf8'),'reserved',
      'the raced prior receipt must remain byte-identical');
    await fs.unlink(receipt);
    await R.publishPrivateReceipt(receipt,{passed:false});
    assert.deepEqual(JSON.parse(await fs.readFile(receipt,'utf8')),{passed:false});
    assert.equal((await fs.stat(receipt)).mode&0o077,0);
    await fs.symlink(owned,alias);
    await assert.rejects(R.assertPrivateReceiptPath(root,
      path.join(alias,'merchant-product-manual-recovery-v1.json')));
  }finally{await fs.rm(alias,{force:true});await fs.rm(owned,{recursive:true});}
});
test('exact preflight, one committed POST and GET-only recovery remain distinct from legacy replay',()=>{
  assert.equal(R.assertBrowserRecoverySequence(rows(),{operationId:id,recoveryScopeKey:key}),true);
  for(const mutate of [r=>r.push({...r[1]}),r=>r[2].method='POST',r=>r[2].state='not_found',
    r=>r[1].operationId='223e4567-e89b-41d3-a456-426614174000',r=>r[0].receipt=true,
    r=>r[2].recoveryScopeKey='b'.repeat(64)]){
    const altered=structuredClone(rows());mutate(altered);
    assert.throws(()=>R.assertBrowserRecoverySequence(altered,{operationId:id,recoveryScopeKey:key}));
  }
});
test('physical response loss follows the real 200 and an awaited durable check',async()=>{
  const cdp=new EventEmitter(),sent=[];cdp.send=async(op,args)=>{
    sent.push(op);
    if(op==='Fetch.getResponseBody')return{body:JSON.stringify({ok:true,kind:'product_manual',operationId:id}),base64Encoded:false};
    if(op==='Fetch.failRequest')queueMicrotask(()=>cdp.emit('Network.loadingFailed',{requestId:'network-owned'}));
  };cdp.detach=async()=>{sent.push('detach');};
  const page={createCDPSession:async()=>cdp};let durable=false;
  const fault=await R.dropCommittedManualUpload(page,endpoint,async reply=>{
    assert.equal(reply.operationId,id);durable=true;
  });
  cdp.emit('Fetch.requestPaused',{requestId:'owned',networkId:'network-owned',
    request:{url:endpoint,method:'POST'},responseStatusCode:200});
  const captured=await fault.wait();await fault.close();
  assert.equal(durable,true);assert.equal(captured.operationId,id);assert.equal(captured.status,200);
  assert.equal(captured.responseBytes>0,true);assert.match(captured.responseSha256,/^[0-9a-f]{64}$/);
  assert.deepEqual(sent,['Network.enable','Fetch.enable','Fetch.getResponseBody','Fetch.failRequest',
    'Fetch.disable','Network.disable','detach']);
});
test('uncommitted or non-200 response cannot be reported as physical loss',async()=>{
  for(const status of [200,202,503]){
    const cdp=new EventEmitter(),sent=[];cdp.send=async(op)=>{
      sent.push(op);if(op==='Fetch.getResponseBody')return{body:JSON.stringify({ok:true,kind:'product_manual',operationId:id}),base64Encoded:false};
    };cdp.detach=async()=>{};
    const fault=await R.dropCommittedManualUpload({createCDPSession:async()=>cdp},endpoint,
      async()=>{if(status===200)throw Error('No durable ingest');});
    cdp.emit('Fetch.requestPaused',{requestId:'owned',networkId:'network-owned',
      request:{url:endpoint,method:'POST'},responseStatusCode:status});
    await assert.rejects(fault.wait());await assert.rejects(fault.close());
    assert.ok(sent.includes('Fetch.failRequest'));
  }
});
test('a finished browser response cannot masquerade as lost ACK',async()=>{
  const cdp=new EventEmitter();cdp.send=async op=>{
    if(op==='Fetch.getResponseBody')return{body:JSON.stringify({ok:true,kind:'product_manual',operationId:id}),base64Encoded:false};
    if(op==='Fetch.failRequest')queueMicrotask(()=>cdp.emit('Network.loadingFinished',{requestId:'network-owned'}));
  };cdp.detach=async()=>{};
  const fault=await R.dropCommittedManualUpload({createCDPSession:async()=>cdp},endpoint,async()=>{});
  cdp.emit('Fetch.requestPaused',{requestId:'owned',networkId:'network-owned',
    request:{url:endpoint,method:'POST'},responseStatusCode:200});
  await assert.rejects(fault.wait(),/false !== true|Expected values to be strictly equal/);
  await fault.close();
});
test('a second physical owner upload is rejected rather than quietly continued',async()=>{
  const cdp=new EventEmitter(),sent=[];cdp.send=async op=>{
    sent.push(op);
    if(op==='Fetch.getResponseBody')return{body:JSON.stringify({ok:true,kind:'product_manual',operationId:id}),base64Encoded:false};
    if(op==='Fetch.failRequest')queueMicrotask(()=>cdp.emit('Network.loadingFailed',{requestId:'network-owned'}));
  };cdp.detach=async()=>{};
  const fault=await R.dropCommittedManualUpload({createCDPSession:async()=>cdp},endpoint,async()=>{});
  cdp.emit('Fetch.requestPaused',{requestId:'first',networkId:'network-owned',
    request:{url:endpoint,method:'POST'},responseStatusCode:200});
  await fault.wait();
  cdp.emit('Fetch.requestPaused',{requestId:'second',networkId:'network-second',
    request:{url:endpoint,method:'POST'},responseStatusCode:200});
  await assert.rejects(fault.close(),/second physical manual upload/);
  assert.equal(sent.filter(op=>op==='Fetch.continueRequest').length,0);
});
