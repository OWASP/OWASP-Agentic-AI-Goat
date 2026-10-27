'use strict';
// Specific rendered ACL permission experiment; no browser/process/model factory.
const assert=require('node:assert/strict');
const ROUTE='/api/secureshop/admin/access-control/permission';
const RECOVERY='/api/secureshop/admin/access-control/operations/';
const CELL='[data-testid="acl-cell-audit.search_by_user-admin"]';
async function permissionRecovery({page,frame,origin,policy,readOperation,check,signal,deadline,abortOwner,closeBrowser}){
 assert.equal(typeof readOperation,'function');assert.equal(typeof check,'function');assert(signal);
 assert.equal(policy.tools.find(x=>x.tool_name==='audit.search_by_user').admin,true);
 assert(Number.isFinite(deadline));assert.equal(typeof abortOwner,'function');assert.equal(typeof closeBrowser,'function');
 const posts=[],gets=[],active=new Set();let failure,committed,seen=false,timer,finish,closed=false,primary;
 const track=work=>{active.add(work);work.then(()=>active.delete(work),()=>active.delete(work));return work;};
 const bounded=async work=>{let timeout;try{return await Promise.race([work,new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('ACL_SETTLEMENT_DEADLINE')),Math.max(0,deadline-Date.now()));})]);}finally{clearTimeout(timeout);}};
 const lost=new Promise(resolve=>{finish=resolve;});
 const guard=()=>{assert.equal(closed,false,'ACL_RECOVERY_CLOSED');signal.throwIfAborted();check();};
 const observe=r=>{const u=new URL(r.url());if(u.origin!==origin)return;
  if(u.pathname===ROUTE&&r.method()==='POST')posts.push(JSON.parse(r.postData()));
  if(u.pathname.startsWith(RECOVERY)&&r.method()==='GET')gets.push(u.pathname);};
 guard();const cdp=await page.createCDPSession();page.on('request',observe);
 const paused=async e=>{
  const u=new URL(e.request.url);
  if(u.origin!==origin||u.pathname!==ROUTE||e.request.method!=='POST')return cdp.send('Fetch.continueRequest',{requestId:e.requestId});
  try{
   assert.equal(seen,false,'One ACL mutation only');seen=true;guard();assert.equal(e.responseStatusCode,200);
   const raw=await cdp.send('Fetch.getResponseBody',{requestId:e.requestId});guard();
   committed=JSON.parse(raw.base64Encoded?Buffer.from(raw.body,'base64').toString('utf8'):raw.body);
   assert.equal(posts.length,1);const p=posts[0];
   assert.equal(p.tool_name,'audit.search_by_user');assert.equal(p.role,'admin');assert.equal(p.allowed,false);
   assert.equal(p.expectedVersion,policy.version);assert.equal(committed.receipt.operationId,p.operationId);
   assert.equal(committed.allowed,false);assert.equal(committed.role,p.role);assert.equal(committed.tool_name,p.tool_name);
   assert.equal(committed.receipt.registrySha256,policy.registrySha256);
   const saved=await readOperation(p.operationId);guard();assert.equal(saved.ok,true);assert.deepEqual(saved.receipt,committed.receipt);
   await cdp.send('Fetch.failRequest',{requestId:e.requestId,errorReason:'ConnectionReset'});
  }catch(error){failure=error;await cdp.send('Fetch.failRequest',{requestId:e.requestId,errorReason:'Aborted'}).catch(()=>{});}
  finally{finish();}
 };
 const abort=()=>{failure=signal.reason||Error('ACL_RECOVERY_ABORTED');finish();};
 const tracked=e=>track(paused(e));
 cdp.on('Fetch.requestPaused',tracked);signal.addEventListener('abort',abort,{once:true});
 try{
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:origin+ROUTE,requestStage:'Response'}]});
  await frame.waitForSelector(CELL);guard();await frame.click(CELL);
  await Promise.race([lost,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ACL_RESPONSE_NOT_OBSERVED')),15000);})]);
  clearTimeout(timer);guard();if(failure)throw failure;
  await cdp.send('Fetch.disable');
  await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='Read change receipt'&&!b.disabled));
  guard();const buttons=await frame.$$('button');let recovery;
  for(const b of buttons)if(await b.evaluate(n=>n.textContent.trim()==='Read change receipt'&&!n.disabled)){assert(!recovery);recovery=b;}
  assert(recovery);const response=track(page.waitForResponse(r=>r.url()===origin+RECOVERY+committed.receipt.operationId&&r.request().method()==='GET',{timeout:15000}));
  guard();await recovery.click();const read=await response;guard();assert.equal(read.status(),200);
  assert.deepEqual((await read.json()).receipt,committed.receipt);
  await frame.waitForFunction(()=>![...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='Read change receipt'));
  guard();assert.equal(posts.length,1);assert.deepEqual(gets,[RECOVERY+committed.receipt.operationId]);
  assert.deepEqual((await readOperation(committed.receipt.operationId)).receipt,committed.receipt);guard();
  return{body:committed,physicalPermissionClick:true,responseLostAfterCommit:true,getOnlyRecovery:true,posts:1,qualificationComplete:false};
 }catch(error){primary=error;throw error;}finally{
  closed=true;clearTimeout(timer);signal.removeEventListener('abort',abort);page.off('request',observe);cdp.off('Fetch.requestPaused',tracked);
  const cleanup=[];
  const attempt=async fn=>{try{await bounded(track(Promise.resolve().then(fn)));}catch(error){cleanup.push(error);}};
  if(primary||active.size){try{abortOwner();}catch(error){cleanup.push(error);}await attempt(closeBrowser);}
  await attempt(()=>cdp.send('Fetch.disable'));
  await attempt(()=>cdp.detach());
  const pending=[...active];await attempt(()=>Promise.allSettled(pending));
  if(active.size)cleanup.push(Error('ACL_RECOVERY_OBSERVER_PENDING'));
  if(cleanup.length){const error=primary||Error('ACL_RECOVERY_CLEANUP_FAILED');error.cleanupDebt=true;error.cleanupFailureCount=cleanup.length;if(!primary)throw error;}
 }
}
module.exports={permissionRecovery,ROUTE,RECOVERY,CELL};
