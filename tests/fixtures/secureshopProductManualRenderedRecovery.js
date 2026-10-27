'use strict';
// Q05 browser-only recovery evidence. No upload, browser, or network work on import.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const fs=require('node:fs/promises');
const path=require('node:path');
const PROFILE='merchant-product-manual-recovery-v1';
const POST='/api/secureshop/uploads';
const GET='/api/secureshop/uploads/product-manual/receipt';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const hash=value=>createHash('sha256').update(value).digest('hex');

async function assertPrivateReceiptPath(root,receiptPath){
  assert.ok(path.isAbsolute(root)&&path.isAbsolute(receiptPath));
  assert.equal(await fs.realpath(root),root,'only the canonical repository is admitted');
  const relative=path.relative(root,receiptPath).split(path.sep);
  assert.equal(relative.length,4);
  assert.deepEqual(relative.slice(0,2),['tasks','qualification']);
  assert.match(relative[2],/^run-[A-Za-z0-9_-]{8,64}$/);
  assert.equal(relative[3],'merchant-product-manual-recovery-v1.json');
  const parent=path.dirname(receiptPath),info=await fs.lstat(parent);
  assert.ok(info.isDirectory()&&!info.isSymbolicLink());
  assert.equal(await fs.realpath(parent),parent);
  assert.equal(info.mode&0o077,0);
  assert.equal(info.uid,process.getuid());
  await assert.rejects(fs.lstat(receiptPath),error=>error?.code==='ENOENT');
  return parent;
}

async function publishPrivateReceipt(receiptPath,value){
  assert.ok(path.isAbsolute(receiptPath));
  const handle=await fs.open(receiptPath,'wx',0o600);
  try{
    await handle.writeFile(JSON.stringify(value,null,2));
    await handle.sync();
  }finally{await handle.close();}
}

function assertBrowserRecoverySequence(rows,{operationId,recoveryScopeKey}){
  assert.match(operationId,UUID);assert.match(recoveryScopeKey,SHA);
  assert.ok(Array.isArray(rows));
  assert.deepEqual(rows.map(row=>[row.method,row.path]),[['GET',GET],['POST',POST],['GET',GET]],
    'The rendered recovery must have one physical upload POST between two receipt GETs');
  assert.deepEqual(rows.map(row=>row.status),[200,200,200]);
  assert.deepEqual(rows.map(row=>row.state),['not_found','indexed','indexed']);
  assert.ok(rows.every(row=>row.operationId===operationId&&row.recoveryScopeKey===recoveryScopeKey));
  assert.equal(rows[0].receipt,false);assert.equal(rows[2].receipt,true);
  assert.equal(rows.filter(row=>row.method==='POST').length,1);
  return true;
}

// CDP cuts delivery only after a real HTTP 200 response and an independent
// durable commit check. It never substitutes a success, retries, or reads file
// bytes from the user's multipart request.
async function dropCommittedManualUpload(page,endpoint,verifyCommitted){
  assert.equal(typeof verifyCommitted,'function');
  const url=new URL(endpoint);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,POST);
  const cdp=await page.createCDPSession();const pending=new Set();let captured=null,failure=null,closed=false;
  let networkId=null,networkFailed=false,networkFinished=false,networkWake;
  const browserFailure=new Promise(resolve=>{networkWake=resolve;});
  let wake;const observed=new Promise(resolve=>{wake=resolve;});
  const onLoadingFailed=event=>{
    if(networkId&&event.requestId===networkId){networkFailed=true;networkWake();}
  };
  const onLoadingFinished=event=>{
    if(networkId&&event.requestId===networkId){networkFinished=true;networkWake();}
  };
  const onPaused=event=>{
    const task=(async()=>{
      if(!captured&&event.request.url===endpoint&&event.request.method==='POST'){
        assert.equal(event.responseStatusCode,200,'Only a genuine completed HTTP 200 may be dropped');
        assert.ok(typeof event.networkId==='string'&&event.networkId,
          'The browser network request must have a CDP identity');
        networkId=event.networkId;
        const raw=await cdp.send('Fetch.getResponseBody',{requestId:event.requestId});
        const bytes=Buffer.from(raw.body,raw.base64Encoded?'base64':'utf8');
        assert.ok(bytes.length>0&&bytes.length<=65536,'Bounded original upload response required');
        const reply=JSON.parse(bytes.toString('utf8'));
        assert.equal(reply.ok,true);assert.equal(reply.kind,'product_manual');assert.match(reply.operationId,UUID);
        // The callback must SELECT the real committed ingest/receipt before
        // browser response delivery is intentionally severed.
        await verifyCommitted(reply);
        captured=Object.freeze({operationId:reply.operationId,responseSha256:hash(bytes),
          responseBytes:bytes.length,status:event.responseStatusCode});
        await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'Failed'});
        wake();
      }else if(event.request.url===endpoint&&event.request.method==='POST'){
        failure=Error('A second physical manual upload POST is forbidden');wake();
        await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'Aborted'});
      }else await cdp.send('Fetch.continueRequest',{requestId:event.requestId});
    })().catch(async error=>{failure=error;wake();
      await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'Aborted'}).catch(()=>{});
    });
    pending.add(task);void task.finally(()=>pending.delete(task));
  };
  cdp.on('Fetch.requestPaused',onPaused);
  cdp.on('Network.loadingFailed',onLoadingFailed);
  cdp.on('Network.loadingFinished',onLoadingFinished);
  try{
    await cdp.send('Network.enable');
    await cdp.send('Fetch.enable',{patterns:[{urlPattern:endpoint,requestStage:'Response'}]});
  }catch(error){cdp.off('Fetch.requestPaused',onPaused);
    cdp.off('Network.loadingFailed',onLoadingFailed);cdp.off('Network.loadingFinished',onLoadingFinished);
    await cdp.detach().catch(()=>{});throw error;}
  return Object.freeze({
    async wait(timeoutMs=30000){
      assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=120000);
      let timer;try{await Promise.race([observed,new Promise((_,reject)=>{timer=setTimeout(()=>
        reject(Error('Committed manual response was not observed')),timeoutMs);})]);}
      finally{clearTimeout(timer);}
      if(failure)throw failure;assert.ok(captured);
      let failureTimer;try{await Promise.race([browserFailure,new Promise((_,reject)=>{
        failureTimer=setTimeout(()=>reject(Error('Browser request loss was not observed')),5000);
      })]);}finally{clearTimeout(failureTimer);}
      if(failure)throw failure;
      assert.equal(networkFailed,true);assert.equal(networkFinished,false);
      return captured;
    },
    async close(){
      if(closed)return;closed=true;
      await Promise.all([...pending]);
      await cdp.send('Fetch.disable');await cdp.send('Network.disable');
      cdp.off('Fetch.requestPaused',onPaused);
      cdp.off('Network.loadingFailed',onLoadingFailed);cdp.off('Network.loadingFinished',onLoadingFinished);
      await cdp.detach();
      if(failure)throw failure;
    },
  });
}
module.exports={PROFILE,POST,GET,assertPrivateReceiptPath,publishPrivateReceipt,assertBrowserRecoverySequence,
  dropCommittedManualUpload};
