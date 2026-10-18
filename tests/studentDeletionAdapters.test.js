'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createStudentDeletionAdapters}=require('../server/services/studentDeletionAdapters');
const {issueFinflowOwnerDeletionReceipt}=require('../server/services/finflowOwnerDeletionReceipt');
test('Excessive Agency deletion runs inside owner reset and checks its lease before and after destruction',async()=>{
 const events=[];
 const adapters=createStudentDeletionAdapters(name=>{
  if(name==='../routes/excessiveAgencyLab')return{resetOwner:async(owner,work)=>{events.push(['fence',owner]);await work();events.push(['release']);}};
  if(name==='./excessiveAgencyAttendeeLabStore')return{excessiveAgencyAttendeeLabStore:{destroyAttendee:async owner=>{events.push(['destroy',owner]);return{removed:1};}}};
  throw Error('Unexpected dependency');
 });
 assert.deepEqual(await adapters.excessive_agency({subjectId:17,check:async()=>events.push(['check'])}),{completed:true});
 assert.deepEqual(events,[['check'],['fence','17'],['check'],['destroy','17'],['check'],['release']]);
});
test('invalid owner or lost lease prevents adapter loading and destruction',async()=>{
 const adapters=createStudentDeletionAdapters(()=>{throw Error('Must not load');});
 await assert.rejects(adapters.excessive_agency({subjectId:'17',check:async()=>{}}),TypeError);
 await assert.rejects(adapters.excessive_agency({subjectId:17,check:async()=>{throw Object.assign(Error('lost'),{code:'STALE_DELETION_LEASE'});}}),{code:'STALE_DELETION_LEASE'});
 await assert.rejects(adapters.revoke_runs({subjectId:'17',check:async()=>{}}),TypeError);
 await assert.rejects(adapters.revoke_runs({subjectId:17,check:async()=>{throw Object.assign(Error('lost'),{code:'STALE_DELETION_LEASE'});}}),{code:'STALE_DELETION_LEASE'});
 await assert.rejects(adapters.session_disclosure({subjectId:'17',check:async()=>{}}),TypeError);
 await assert.rejects(adapters.session_disclosure({subjectId:17,check:async()=>{throw Object.assign(Error('lost'),{code:'STALE_DELETION_LEASE'});}}),{code:'STALE_DELETION_LEASE'});
});

test('session disclosure deletion is owner bound and lease checked around its durable delete',async()=>{
 const events=[];
 const adapters=createStudentDeletionAdapters(name=>{
  if(name==='./sessionDisclosureLab')return{getSessionDisclosureLab:()=>({
   destroyOwner:async owner=>{events.push(['destroy',owner]);return 1;}
  })};
  throw Error('Unexpected dependency');
 });
 assert.deepEqual(await adapters.session_disclosure({subjectId:23,
  check:async()=>events.push(['check'])}),{completed:true});
 assert.deepEqual(events,[['check'],['check'],['destroy',23],['check']]);
});

test('actual owner coordinator drains a cancelled run before attendee destruction',async()=>{
 const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
 const coordinator=createRunCoordinator({family:'ExcessiveAgency',ledger:null});
 const events=[];
 let entered;
 const started=new Promise(resolve=>{entered=resolve;});
 const running=coordinator.run('17',{},async execution=>{
  entered();
  await new Promise(resolve=>execution.signal.addEventListener('abort',resolve,{once:true}));
  events.push('run-drained');
  await execution.check();
 });
 const cancelled=assert.rejects(running,{name:'AbortError'});
 await started;
 const adapter=createStudentDeletionAdapters(name=>{
  if(name==='../routes/excessiveAgencyLab')return{resetOwner:(owner,work)=>coordinator.reset(owner,work)};
  if(name==='./excessiveAgencyAttendeeLabStore')return{excessiveAgencyAttendeeLabStore:{destroyAttendee:async owner=>{assert.equal(owner,'17');events.push('destroy');return{removed:1};}}};
  throw Error('Unexpected module');
 }).excessive_agency;
 assert.deepEqual(await adapter({subjectId:17,check:async()=>{}}),{completed:true});
 await cancelled;
 assert.deepEqual(events,['run-drained','destroy']);
});

test('SecureShop adapter is explicit and forwards the lease-bound cleanup scope',async()=>{
 const seen=[];
 const cleanup=async scope=>{seen.push(scope);return{completed:true,resetCount:2};};
 const adapters=createStudentDeletionAdapters(require,{secureShopCleanup:cleanup});
 const scope={subjectId:17,jobId:'job',leaseToken:'lease',check:async()=>{},signal:new AbortController().signal};
 assert.deepEqual(await adapters.secureshop(scope),{completed:true,resetCount:2});
 assert.equal(seen[0],scope);
 await assert.rejects(createStudentDeletionAdapters().secureshop(scope),/unavailable/);
});

test('workshop adapters drain owner runs, delete exact owner stores, and clear isolated process state',async()=>{
 const events=[];
 const reset=name=>async(owner,work)=>{events.push([name,'enter',owner]);await work();events.push([name,'exit',owner]);};
 const stores={
  '../database/postgres/sqlWorkshopDb':{destroyOwner:async owner=>{events.push(['aria-db',owner]);return{removed:4};}},
  '../database/postgres/nosqlWorkshopDb':{destroyOwner:async owner=>{events.push(['nova-db',owner]);return{removed:2};}},
  '../database/postgres/mcpWorkshopDb':{destroyOwner:async owner=>{events.push(['mcp-db',owner]);return{removed:2};}},
  '../database/postgres/csrfWorkshopDb':{destroyOwner:async owner=>{events.push(['csrf-db',owner]);return{removed:4};}},
  '../database/postgres/supplyChainWorkshopDb':{destroyOwner:async owner=>{events.push(['supply-db',owner]);return{removed:1};}},
 };
 const modules={
  './ariaAgentService':{reset:reset('aria')},'./novaAgentService':{reset:reset('nova')},
  '../routes/mcpWorkshop':{resetOwner:async(owner,work,options)=>{events.push(['mcp-retire',owner,options?.check]);await work();events.push(['mcp-retired',owner]);}},'../routes/csrfWorkshop':{resetOwner:reset('csrf'),clearRagOwnerState:async owner=>events.push(['csrf-rag',owner])},
  '../routes/promptInjectionWorkshop':{resetOwner:reset('dpi')},
  '../routes/ragInjection':{resetOwner:reset('rag'),clearOwnerState:async owner=>events.push(['rag-state',owner])},
  '../routes/emailAgent':{resetOwner:reset('email'),destroyOwnerArtifacts:async owner=>{events.push(['email-artifacts',owner]);return 3;}},
  '../routes/supplyChainWorkshop':{resetOwner:reset('supply')},
  '../routes/ctf':{resetOwner:reset('ctf')},
  '../database/postgres/ctfDb':{CTFHelpers:{destroyOwner:async owner=>{events.push(['ctf-db',owner]);return{removed:3};}}},
  './legacyChallengeOwnerCleanup':{getLegacyChallengeOwnerCleanup:()=>({destroyOwner:async owner=>{events.push(['legacy-db',owner]);return{removed:7,filesRemoved:1};}})},
  '../database/postgres/sensitiveLookupDb':{getSensitiveLookupDb:()=>({destroyOwner:async owner=>{events.push(['lookup-db',owner]);return{removed:1};}})},
  './csrfVictimSandbox':{resetSandbox:id=>events.push(['csrf-sandbox',id])},
  './supplyChain/codeBotSandboxRuntime':{resetOwner:async owner=>{events.push(['supply-sandbox',owner]);return{ok:true};}},
  ...stores,
 };
 const adapters=createStudentDeletionAdapters(name=>{if(!modules[name])throw Error(`Unexpected ${name}`);return modules[name];},{
  storeCleanup:{codeBotExecutionAbsent:async scope=>{events.push(['codebot-absence',scope.subjectId]);return false;}},
 });
 const scope={subjectId:31,check:async()=>events.push(['check'])};
 for(const key of ['sql_injection_workshop','nosql_injection_workshop','mcp_workshop','csrf_workshop',
  'direct_prompt_injection','indirect_prompt_injection','supply_chain_rce','ctf','legacy_challenge','sensitive_lookup']) {
  assert.deepEqual(await adapters[key](scope),{completed:true});
 }
 assert.ok(events.some(event=>event[0]==='aria-db'&&event[1]==='31'));
 const mcpRetire = events.find(event=>event[0]==='mcp-retire');
 assert.equal(mcpRetire[1], '31'); assert.equal(mcpRetire[2], scope.check);
 assert.ok(events.findIndex(event=>event[0]==='mcp-retire') < events.findIndex(event=>event[0]==='mcp-db'));
 assert.ok(events.some(event=>event[0]==='csrf-sandbox'&&event[1]==='csrf_31'));
 assert.ok(events.some(event=>event[0]==='rag-state'&&event[1]==='31'));
 assert.ok(events.some(event=>event[0]==='csrf-rag'&&event[1]==='31'));
 assert.ok(events.findIndex(event=>event[0]==='csrf-rag') < events.findIndex(event=>event[0]==='csrf-db'));
 assert.ok(events.some(event=>event[0]==='email-artifacts'&&event[1]==='31'));
  assert.ok(events.some(event=>event[0]==='supply-sandbox'&&event[1]==='31'));
  assert.ok(events.some(event=>event[0]==='codebot-absence'&&event[1]===31));
  assert.ok(events.some(event=>event[0]==='ctf-db'&&event[1]===31));
  assert.ok(events.some(event=>event[0]==='legacy-db'&&event[1]==='31'));
  assert.ok(events.some(event=>event[0]==='lookup-db'&&event[1]==='31'));
});

test('Supply Chain deletion skips its ephemeral reset only with authoritative zero-execution proof',async()=>{
 const events=[];
 const modules={
  '../routes/supplyChainWorkshop':{resetOwner:async(owner,work)=>{events.push(['fence',owner]);await work();}},
  '../database/postgres/supplyChainWorkshopDb':{destroyOwner:async owner=>{events.push(['destroy',owner]);return{removed:0};}},
  './supplyChain/codeBotSandboxRuntime':{resetOwner:async()=>{events.push(['sandbox']);return{ok:false};}},
 };
 const scope={subjectId:31,jobId:'11111111-1111-4111-8111-111111111111',check:async()=>events.push(['check'])};
 const adapter=createStudentDeletionAdapters(name=>modules[name],{
  storeCleanup:{codeBotExecutionAbsent:async received=>{assert.equal(received,scope);events.push(['absent']);return true;}},
 }).supply_chain_rce;
 assert.deepEqual(await adapter(scope),{completed:true});
 assert.equal(events.some(event=>event[0]==='sandbox'),false);
 assert.ok(events.findIndex(event=>event[0]==='absent')<events.findIndex(event=>event[0]==='destroy'));
});

test('IPI deletion drains RAG and Email owners and requires exact artifact destruction before completion', async () => {
 const events=[];
 const reset=name=>async(owner,work)=>{events.push([name,'enter',owner]);await work();events.push([name,'exit',owner]);};
 const modules={
  '../routes/ragInjection':{resetOwner:reset('rag'),clearOwnerState:async owner=>events.push(['rag-state',owner])},
  '../routes/emailAgent':{resetOwner:reset('email'),destroyOwnerArtifacts:async owner=>{events.push(['email-destroy',owner]);return 2;}},
 };
 const adapter=createStudentDeletionAdapters(name=>modules[name]).indirect_prompt_injection;
 assert.deepEqual(await adapter({subjectId:31,check:async()=>events.push(['check'])}),{completed:true});
 assert.deepEqual(events.filter(row=>row[0]!=='check'),[
  ['rag','enter','31'],['rag-state','31'],['email','enter','31'],
  ['email-destroy','31'],['email','exit','31'],['rag','exit','31'],
 ]);

 const failing=createStudentDeletionAdapters(name=>({
  '../routes/ragInjection':{resetOwner:reset('rag-fail'),clearOwnerState:async()=>{}},
  '../routes/emailAgent':{resetOwner:reset('email-fail'),destroyOwnerArtifacts:async()=>undefined},
 }[name])).indirect_prompt_injection;
 await assert.rejects(failing({subjectId:31,check:async()=>{}}), /Invalid IPI email artifact deletion receipt/);
});

test('workshop adapters reject invalid receipts and never claim failed sidecar cleanup',async()=>{
 const reset=async(_owner,work)=>work();
 const adapter=createStudentDeletionAdapters(name=>({
  './ariaAgentService':{reset},'../database/postgres/sqlWorkshopDb':{destroyOwner:async()=>({removed:1000001})},
  '../routes/mcpWorkshop':{resetOwner:reset},'../database/postgres/mcpWorkshopDb':{destroyOwner:async()=>({removed:1000001})},
  '../routes/mcpWorkshop':{resetOwner:reset},
 }[name]||(()=>{throw Error(`Unexpected ${name}`)})()));
 await assert.rejects(adapter.sql_injection_workshop({subjectId:9,check:async()=>{}}),/Invalid ARIA/);
 await assert.rejects(adapter.mcp_workshop({subjectId:9,check:async()=>{}}),/Invalid MCP deletion receipt/);
});

test('MCP retirement failure propagates without destroying the owner store', async () => {
 const failure = new Error('MCP owned resource retirement incomplete');
 const check = async () => {};
 let retirements = 0, destructions = 0;
 const adapter = createStudentDeletionAdapters(name => ({
  '../routes/mcpWorkshop': { async resetOwner(owner, work, options) {
   assert.equal(owner, '9');
   assert.equal(typeof work, 'function');
   assert.equal(options.check, check);
   await options.check();
   retirements += 1;
   // The route retires owned resources before admitting destructive work.
   throw failure;
  } },
  '../database/postgres/mcpWorkshopDb': { async destroyOwner() {
   destructions += 1;
   return { removed: 1 };
  } },
 }[name] || (() => { throw new Error(`Unexpected dependency ${name}`); })()));
 await assert.rejects(adapter.mcp_workshop({ subjectId: 9, check }), error => error === failure);
 assert.equal(retirements, 1);
 assert.equal(destructions, 0);
});

test('XSS and FinFlow durable cleanup runs inside their in-process owner fences',async()=>{
 const events=[];const reset=name=>async(owner,work)=>{events.push([name,'enter',owner]);await work();events.push([name,'exit',owner]);};
 const storeCleanup={xss:async scope=>{events.push(['xss-store',scope.subjectId]);return{completed:true,removed:2};},
  finflow:async scope=>{events.push(['finflow-store',scope.subjectId]);return{completed:true,removed:3};}};
 const adapters=createStudentDeletionAdapters(name=>({
  '../routes/xssWorkshop':{resetOwner:reset('xss')},
  '../routes/sensitiveInfoWorkshop':{resetOwner:reset('finflow')},
 }[name]),{storeCleanup,
  cleanupFinflowBackups:async scope=>{events.push(['backups',scope.subjectId,scope.jobId]);return issueFinflowOwnerDeletionReceipt({completed:true,ownerId:scope.subjectId,jobId:scope.jobId,artifactCount:2});},
  retireFinflowTraversalOwner:async owner=>{events.push(['traversal',owner]);return true;}});
 const scope={subjectId:44,jobId:'11111111-1111-4111-8111-111111111111',check:async()=>events.push(['check'])};
 assert.deepEqual(await adapters.xss(scope),{completed:true,removed:2});
 assert.deepEqual(await adapters.finflow(scope),{completed:true,removed:3});
 assert.deepEqual(events.filter(row=>row[0].endsWith('store')),[['xss-store',44],['finflow-store',44]]);
 assert.ok(events.some(row=>JSON.stringify(row)===JSON.stringify(['xss','enter','44'])));
 assert.ok(events.some(row=>JSON.stringify(row)===JSON.stringify(['finflow','exit','44'])));
 assert.deepEqual(events.filter(row=>row[0]!=='check').slice(3),[
  ['finflow','enter','44'],['backups',44,scope.jobId],['traversal','44'],['finflow-store',44],['finflow','exit','44']]);
});

test('FinFlow cleanup rejects forged backup receipts and failed traversal retirement before database deletion',async()=>{
 for(const failure of ['forged','foreign','traversal']) {
  const events=[];const jobId='11111111-1111-4111-8111-111111111111';
  const value={completed:true,ownerId:failure==='foreign'?45:44,jobId,artifactCount:0};
  const adapters=createStudentDeletionAdapters(()=>({resetOwner:async(owner,work)=>{events.push('fence');await work();}}),{
   storeCleanup:{finflow:async()=>{events.push('database');return{completed:true};}},
   cleanupFinflowBackups:async()=>{events.push('backups');return failure==='forged'?value:issueFinflowOwnerDeletionReceipt(value);},
   retireFinflowTraversalOwner:async()=>{events.push('traversal');return false;}});
  await assert.rejects(adapters.finflow({subjectId:44,jobId,check:async()=>{}}),/Invalid FinFlow .* deletion receipt/);
  assert.deepEqual(events,failure==='traversal'?['fence','backups','traversal']:['fence','backups']);
 }
});
test('durable IPI deletion forwards canonical job and lease without RAM cleanup or fabricated session',async()=>{
 const seen=[],scope={subjectId:17,jobId:'job',leaseToken:'lease',check:async()=>{}};
 const adapters=createStudentDeletionAdapters(name=>{
  if(name==='../routes/ragInjection')return{resetOwner:async(_,work)=>work(),clearOwnerState:async()=>{throw Error('RAM fallback');},durableRagComposition:()=>({deleteOwner:async binding=>seen.push(binding)})};
  if(name==='../routes/emailAgent')return{resetOwner:async(_,work)=>work(),destroyOwnerArtifacts:async()=>0};
  throw Error('Unexpected dependency');
 });
 assert.deepEqual(await adapters.indirect_prompt_injection(scope),{completed:true});assert.deepEqual(seen,[{ownerId:17,jobId:'job',leaseToken:'lease'}]);
});

test('ordered CTF deletion delegates exact lease scope and never loads legacy writers',async()=>{
 const events=[],signal=new AbortController().signal;
 const scope={subjectId:31,jobId:'job',leaseToken:'lease',signal,check:async()=>events.push('check')};
 const runtime={async deleteStudent(value){assert.equal(this,runtime);assert.deepEqual(value,scope);assert.notEqual(value,scope);events.push('ordered');return{completed:true,operationId:'00000000-0000-0000-0000-000000000001'};}};
 const adapter=createStudentDeletionAdapters(()=>{throw Error('Legacy writer loaded');},{ctfRuntime:runtime}).ctf;
 runtime.deleteStudent=()=>{throw Error('Mutated dependency');};
 assert.deepEqual(await adapter(scope),{completed:true});assert.deepEqual(events,['check','ordered','check']);
});
test('ordered CTF unavailable, pending, invalid acknowledgment and lost final lease never report deletion complete',async()=>{
 const scope={subjectId:31,jobId:'job',leaseToken:'lease',check:async()=>{}};
 const noLegacy=()=>{throw Error('Legacy writer loaded');};
 for(const ctfRuntime of [undefined,null,{}, {deleteStudent:async()=>({completed:false,pending:true})},{deleteStudent:async()=>({completed:true})},{deleteStudent:async()=>{throw Error('Database unavailable');}}]){
  await assert.rejects(createStudentDeletionAdapters(noLegacy,{ctfRuntime}).ctf(scope),/CTF authority deletion|Database unavailable/);
 }
 let checks=0;
 await assert.rejects(createStudentDeletionAdapters(noLegacy,{ctfRuntime:{deleteStudent:async()=>({completed:true,operationId:'00000000-0000-0000-0000-000000000001'})}}).ctf({...scope,check:async()=>{if(++checks===2)throw Error('Lease lost');}}),/Lease lost/);
});
