'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const sha=b=>createHash('sha256').update(b).digest('hex');
const INPUT=Object.freeze({version:1,profile:'controlled-statement',message:'Please download my account statement for FF-001.',accountId:'FF-001'});
function verifyPdf(bytes){
 assert(Buffer.isBuffer(bytes)&&bytes.length>500&&bytes.length<65536);const text=bytes.toString('latin1');assert(text.startsWith('%PDF-1.4\n'));assert(text.endsWith('%%EOF\n'));
 const start=Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)?.[1]);assert(Number.isSafeInteger(start)&&start>0);assert.equal(text.slice(start,start+5),'xref\n');
 const entries=/^xref\n0 6\n0000000000 65535 f \n((?:\d{10} 00000 n \n){5})trailer\n<< \/Size 6 \/Root 1 0 R >>/.exec(text.slice(start));assert(entries);
 const offsets=entries[1].trimEnd().split('\n').map(x=>Number(x.slice(0,10)));offsets.forEach((n,i)=>assert.equal(text.slice(n,n+`${i+1} 0 obj\n`.length),`${i+1} 0 obj\n`));
 assert(text.slice(offsets[2],offsets[3]).includes('/Contents 5 0 R'));
 const stream=/5 0 obj\n<< \/Length (\d+) >>\nstream\n/.exec(text.slice(offsets[4]));assert(stream);const content=offsets[4]+stream[0].length,len=Number(stream[1]);assert.equal(text.slice(content+len,content+len+9),'endstream');assert(text.slice(content,content+len).includes(' Tj EMC'));
 return {sha256:sha(bytes),byteLength:bytes.length,objects:5,pages:1};
}
function verifyDownload(call,bytes,filename){assert.equal(call.name,'download_statement');assert.equal(call.success,true);assert.equal(call.isPDF,true);assert.deepEqual(call.params,{account_id:INPUT.accountId});assert.equal(call.pdfFilename,'statement_FF-001_2024.pdf');assert.equal(filename,call.pdfFilename);assert.match(call.pdfContent,/^[A-Za-z0-9+/]+={0,2}$/);const expected=Buffer.from(call.pdfContent,'base64');assert.equal(expected.toString('base64'),call.pdfContent);assert.deepEqual(bytes,expected);return {...verifyPdf(bytes),filename};}
function controlledProvider(){
 let count=0,hold,entered,release;const pending=new Set();
 return {provider:'mock',getActiveProviderInfo:()=>({provider:'mock',model:'controlled-statement'}),isAvailable:async()=>true,
  arm(){assert(!hold);hold=new Promise(r=>{release=r;});const ready=new Promise(r=>{entered=r;});return ready;},
  release(){release?.();hold=null;release=null;},get count(){return count;},async drain(){this.release();await Promise.allSettled([...pending]);},
  async generateResponse(){throw Error('CONTROLLED_FALLBACK_DENIED');},
  async chatWithTools(messages,_tools,{signal}={}){
   assert(++count<=8,'Controlled provider call ceiling');
   if(hold){const p=new Promise((resolve,reject)=>{const abort=()=>reject(Object.assign(Error('Controlled cancelled'),{name:'AbortError'}));signal?.addEventListener('abort',abort,{once:true});hold.then(()=>{signal?.removeEventListener('abort',abort);signal?.aborted?abort():resolve();});if(signal?.aborted)abort();});pending.add(p);entered?.();try{await p;}finally{pending.delete(p);}}
   if(messages.some(x=>x.role==='tool'))return {content:'Your synthetic account statement is ready.',tool_calls:[]};
   assert.equal(messages.at(-1).content,INPUT.message);return {content:'',tool_calls:[{function:{name:'download_statement',arguments:{account_id:INPUT.accountId}}}]};
  }};
}
function trackOwnedAgent(service){
 const Original=service.SensitiveInfoWorkshopAgent,agents=new Set(),runs=new Set(),owners=new Set();
 class Tracked extends Original{constructor(...args){super(...args);agents.add(this);}runUserExclusive(owner,operation){owners.add(owner);const run=super.runUserExclusive(owner,operation);runs.add(run);run.then(()=>runs.delete(run),()=>runs.delete(run));return run;}}
 service.SensitiveInfoWorkshopAgent=Tracked;
 return {async retire(provider){for(const agent of agents)for(const owner of owners)agent.runCoordinator.cancel(owner);await provider.drain();await Promise.allSettled([...runs]);assert.equal(runs.size,0);},restore(){assert.equal(runs.size,0);service.SensitiveInfoWorkshopAgent=Original;}};
}

function assertNoCredit(body){assert.deepEqual(body.newlyCompletedObjectives,[]);assert(!(body.judgments||[]).some(x=>x.verdict==='pass'||x.completed===true));}
function assertOwnedStatementLog(state,id){assert.deepEqual(state.completions,[]);assert.equal(state.logs.length,1);const row=state.logs[0];assert.equal(row.user_id,String(id));assert.equal(row.tool_name,'download_statement');assert.deepEqual(JSON.parse(row.params),{account_id:INPUT.accountId});}
function assertResetState({beforeGeneration,ownerAfter,siblingBefore,siblingAfter}){assert.equal(ownerAfter.generation,String(BigInt(beforeGeneration)+1n));assert.deepEqual(ownerAfter.logs,[]);assert.deepEqual(ownerAfter.completions,[]);assert.deepEqual(siblingAfter,siblingBefore);}

async function qualify({browser,origin,owner,sibling,ownerToken,siblingToken,i,f,provider,downloadDirectory,save}){
 const deadline=Date.now()+540000,remaining=()=>{const n=deadline-Date.now();assert(n>0);return n;};let requests=0;const captures=[];const contexts=[];let primary,result,browserRequests=0;const denied=[];
 const request=async(token,suffix,body)=>{assert(++requests<=30);const response=await fetch(origin+'/api/workshop/sensitive-info'+suffix,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(Math.min(remaining(),20000))});return {status:response.status,body:await response.json()};};
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i);
 const snapshot=async id=>({generation:String(await progress.getGeneration(id,'sensitive_info_disclosure')),progress:(await f.query('SELECT * FROM finflow.progress WHERE user_id=$1 ORDER BY objective_id',[String(id)])).rows,logs:(await f.query('SELECT * FROM finflow.tool_log WHERE user_id=$1 ORDER BY id',[String(id)])).rows,completions:(await i.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id',[id])).rows});
 const bindOwner=async id=>{const state=await snapshot(id);assertOwnedStatementLog(state,id);return state;};
 const open=async token=>{const context=await browser.createBrowserContext();contexts.push(context);const page=await context.newPage();await page.setCacheEnabled(false);page.setDefaultTimeout(20000);await page.setRequestInterception(true);let n=0;page.on('request',r=>{const u=new URL(r.url());if(++n>200||++browserRequests>400||(u.origin!==origin&&!['data:','blob:'].includes(u.protocol))){denied.push('BROWSER_REQUEST_DENIED');return void r.abort();}void r.continue();});await page.evaluateOnNewDocument(t=>localStorage.setItem('token',t),token);await page.goto(origin+'/workshop/sensitive-info',{waitUntil:'domcontentloaded',timeout:remaining()});await page.waitForSelector('textarea:not([disabled])');return {context,page};};
 const send=async page=>{const response=page.waitForResponse(r=>r.url()===origin+'/api/workshop/sensitive-info/chat'&&r.request().method()==='POST',{timeout:remaining()});response.catch(()=>{});await page.type('textarea',INPUT.message);await page.keyboard.press('Enter');return response;};
 const download=async(page,context,body)=>{
  assert.equal(body.success,true);assertNoCredit(body);assert.equal(body.toolCalls.length,1);const call=body.toolCalls[0];verifyDownload(call,Buffer.from(call.pdfContent,'base64'),call.pdfFilename);
  const client=await page.createCDPSession();await client.send('Browser.setDownloadBehavior',{behavior:'allowAndName',downloadPath:downloadDirectory,eventsEnabled:true,browserContextId:context.id});
  let began;const done=new Promise((resolve,reject)=>{client.on('Browser.downloadWillBegin',e=>{if(began)reject(Error('Multiple downloads'));else began=e;});client.on('Browser.downloadProgress',e=>{if(e.state==='canceled')reject(Error('Cancelled download'));if(e.state==='completed')began?.guid===e.guid?resolve(began):reject(Error('Download mismatch'));});});done.catch(()=>{});
  await page.waitForFunction(name=>[...document.querySelectorAll('button')].filter(x=>x.textContent.trim()==='⬇ Download '+name).length===1,{},call.pdfFilename);await page.evaluate(name=>[...document.querySelectorAll('button')].find(x=>x.textContent.trim()==='⬇ Download '+name).click(),call.pdfFilename);
  let timer;const event=await Promise.race([done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Download deadline')),Math.min(remaining(),20000));})]).finally(()=>clearTimeout(timer));assert.match(event.guid,/^[a-f0-9-]+$/);const file=path.join(downloadDirectory,event.guid),st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.uid===process.getuid()&&st.size<65536);const proof=verifyDownload(call,fs.readFileSync(file),event.suggestedFilename);await client.detach();return proof;
 };
 try{
  for(const [who,token,mode] of [[owner,ownerToken,'vulnerable'],[sibling,siblingToken,'fixed']]){
   assert.equal((await request(token,'/mode',{mode})).status,200);const {page,context}=await open(token);const response=await send(page);assert.equal(response.status(),200);const body=await response.json();captures.push({ownerId:who.id,mode,body});await save(captures);captures.at(-1).ownerState=await bindOwner(who.id);captures.at(-1).download=await download(page,context,body);await save(captures);await context.close();contexts.pop();
   if(who===owner){const ownerBefore=await snapshot(owner.id),siblingGeneration=String(await progress.getGeneration(sibling.id,'sensitive_info_disclosure'));const resetOther=await request(siblingToken,'/progress/reset',{userId:owner.id});assert.equal(resetOther.status,200);assert.equal(resetOther.body.reset.status,'completed');assert.deepEqual(await snapshot(owner.id),ownerBefore);assert.equal(String(await progress.getGeneration(sibling.id,'sensitive_info_disclosure')),String(BigInt(siblingGeneration)+1n));}
  }
  const beforeOwner=await snapshot(owner.id);const other=await request(siblingToken,'/progress/'+owner.id);assert.equal(other.status,200);assert.equal(other.body.completedCount,0);
  const siblingBefore=await snapshot(sibling.id),oldGeneration=beforeOwner.generation;assert.equal(siblingBefore.logs.length,1);assert.equal(siblingBefore.logs[0].tool_name,'download_statement');
  const {page}=await open(ownerToken);const entered=provider.arm();const stale=request(ownerToken,'/chat',{userMessage:INPUT.message});stale.catch(()=>{});await entered;
  const resetResponse=page.waitForResponse(r=>r.url()===origin+'/api/workshop/sensitive-info/progress/reset'&&r.request().method()==='POST');resetResponse.catch(()=>{});
  await page.evaluate(()=>{const buttons=[...document.querySelectorAll('button')].filter(x=>x.textContent.trim()==='Reset Progress'&&!x.disabled);if(buttons.length!==1)throw Error('Unique reset progress required');buttons[0].click();});
  const resetHttp=await resetResponse;assert.equal(resetHttp.status(),200);const reset=await resetHttp.json();assert.equal(reset.reset.status,'completed');provider.release();const staleHttp=await stale;assert.equal(staleHttp.status,409);await provider.drain();assert.equal(String(await progress.getGeneration(owner.id,'sensitive_info_disclosure')),String(BigInt(oldGeneration)+1n));
  await page.waitForFunction(()=>document.querySelector('textarea:not([disabled])')&&![...document.querySelectorAll('button')].some(x=>x.textContent.includes('Download statement_')));
  const after=await snapshot(owner.id);assertResetState({beforeGeneration:oldGeneration,ownerAfter:after,siblingBefore,siblingAfter:await snapshot(sibling.id)});
  assert.equal((await request(ownerToken,'/mode',{mode:'fixed'})).status,200);await page.reload({waitUntil:'domcontentloaded'});await page.waitForSelector('textarea:not([disabled])');const post=await send(page);assert.equal(post.status(),200);const body=await post.json();captures.push({ownerId:owner.id,mode:'fixed',body});await save(captures);captures.at(-1).ownerState=await bindOwner(owner.id);captures.at(-1).download=await download(page,contexts.at(-1),body);await save(captures);
  await require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter().logout(ownerToken);const count=provider.count;assert.equal((await request(ownerToken,'/chat',{userMessage:INPUT.message})).status,401);assert.equal(provider.count,count);assert.deepEqual(await snapshot(sibling.id),siblingBefore);
  const total=(await i.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=ANY($1::bigint[])',[[owner.id,sibling.id]])).rows[0].n;assert.equal(total,0);
  assert.deepEqual(denied,[]);result={profile:'controlled-statement',actualModelProof:false,modelCalls:0,genuineCredit:0,downloads:captures.map(c=>c.download),controlledCalls:provider.count,apiRequests:requests,browserRequests,ownerBound:true,resetAdvanced:true,staleDenied:true,siblingPreserved:true,revocationDenied:true};
 }catch(error){primary=error;}finally{const close=await Promise.allSettled(contexts.map(c=>c.close()));await provider.drain();if(close.some(x=>x.status==='rejected'))throw new AggregateError([...(primary?[primary]:[]),...close.filter(x=>x.status==='rejected').map(x=>x.reason)],'Statement context cleanup failed');}
 if(primary)throw primary;return result;
}
module.exports={assertOwnedStatementLog,assertResetState,trackOwnedAgent,INPUT,verifyPdf,verifyDownload,controlledProvider,assertNoCredit,qualify};
