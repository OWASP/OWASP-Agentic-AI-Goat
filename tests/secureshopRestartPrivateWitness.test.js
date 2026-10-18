'use strict';
// Controlled executor output and repository doubles; no real namespace, shell or database.
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto'),{EventEmitter}=require('node:events');
const {buildRestartArgv,createOwnedRestartCommandExecutor}=require('../sidecars/sandbox-runner/owned-system/restart-command-executor');
const Wire=require('../sidecars/sandbox-runner/owned-system/restart-wire');
const {createOwnedSystemRestartTarget}=require('../sidecars/sandbox-runner/owned-system/restart-target');
const {createBoundSystemRestartService}=require('../server/services/secureshopBoundSystemRestartService');
const hash=v=>createHash('sha256').update(v).digest('hex');
function targetFixture(t,mutate=x=>x){
 const targetId=randomUUID(),markers=new Set(),inputs=[];
 const target=createOwnedSystemRestartTarget({targetId,root:'/owned-restart/targets/'+targetId,verifyChildAsset:()=>{},
 fsImpl:{mkdirSync(){},existsSync:p=>markers.has(p)},spawnImpl:(_bin,args)=>{
  const p=new EventEmitter();p.exitCode=null;p.killed=false;markers.add(args[0]);p.kill=()=>{p.killed=true;p.exitCode=0;markers.delete(args[0]);queueMicrotask(()=>p.emit('close',0));};return p;
 },executeOwnedCommand:async input=>{inputs.push(input);const stdout=input.namespaceHostname+'\n',stderr='';
  return mutate({isolation:Wire.ISOLATION,namespaceHostname:input.namespaceHostname,drained:true,stdout,stderr,
   stdoutSha256:hash(stdout),stderrSha256:hash(stderr),effectSha256:'a'.repeat(64),effectFiles:1,effectBytes:6});
 }});t.after(()=>target.close());return {target,targetId,inputs};
}
function serviceFixture({mode='vuln',onCurrent=()=>{},onHealth=()=>{},onExecute=()=>{}}={}){
 const events=[],targetId=randomUUID(),input={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:2,platformSessionId:3},operationId:randomUUID(),name:'nginx'};
 const modeAuthority={async capture(scope,feature){assert.equal(feature,'system_restart');assert.deepEqual(scope,input.scope);events.push('capture');return {snapshot:{mode},async assertCurrent(){events.push('current');onCurrent();}};},assertToken:t=>t};
 let receipt;
 const repository={ensureTarget:async()=>events.push('ensure'),begin:async()=>{events.push('begin');return {state:'running',workerToken:randomUUID()};},
 assertCurrent:async()=>events.push('repositoryCurrent'),complete:async(_input,x)=>{events.push('complete');return {state:'completed',receipt:x.receipt};},fail:async(_input,x)=>events.push(x.code),operation:async()=>({state:'completed',historical:true})};
 const client={health:async()=>{events.push('health');onHealth();},inspect:async()=>({instanceId:randomUUID(),generation:1}),
 execute:async(wire,{assertCurrent})=>{await assertCurrent();events.push('dispatch');onExecute();
 const outputText='';receipt={version:Wire.VERSION,targetId,operationId:input.operationId,requestSha256:require('../server/services/secureshopSystemRestartContract').restartRequestDigest(wire.request),
 beforeInstanceId:randomUUID(),afterInstanceId:randomUUID(),beforeGeneration:1,afterGeneration:2,effectSha256:'a'.repeat(64),outputText,outputSha256:hash(outputText),outputBytes:0,
 ownedCommandEffectSha256:'b'.repeat(64),ownedCommandEffectFiles:1,ownedCommandEffectBytes:6,command:'systemctl restart '+input.name,status:'completed',isolation:Wire.ISOLATION};return receipt;}};
 const dependencies={repository,client,modeAuthority,resolveTarget:async()=>{events.push('resolve');return {targetId};}};
 return {input,events,dependencies,service:createBoundSystemRestartService(dependencies)};
}
test('fresh private namespace is allocated only for execution and bound to exact operation/target/request',async t=>{
 const f=targetFixture(t),request={version:1,operationId:randomUUID(),name:'nginx; /usr/bin/uname -n'};
 const initial=await f.target.start();assert.equal(Object.hasOwn(initial,'witness'),false);assert.equal(f.inputs.length,0);
 const raw=await f.target.restart(request),receipt=Wire.bindRestartReceipt({targetId:f.targetId,request},raw);
 assert.equal(raw.version,3);assert.equal(receipt.version,Wire.WITNESS_VERSION);assert.match(receipt.witness.hostname,/^restart-[a-f0-9]{32}$/);
 assert.equal(f.inputs[0].command,'systemctl restart '+request.name);assert.equal(f.inputs[0].namespaceHostname,receipt.witness.hostname);
 assert.equal(receipt.stdoutText,receipt.witness.hostname+'\n');assert.equal(receipt.stderrText,'');assert.equal(receipt.drained,true);
 assert.equal(receipt.afterGeneration,receipt.beforeGeneration+1);assert.notEqual(receipt.afterInstanceId,receipt.beforeInstanceId);
 assert.deepEqual(receipt.witness,Wire.restartWitness({targetId:f.targetId,request},receipt.witness.hostname));
 const second=await f.target.restart({...request,operationId:randomUUID()});assert.notEqual(second.witness.hostname,receipt.witness.hostname);
});
test('v3 wire rejects target/operation/witness and separate stream substitutions',async t=>{
 const f=targetFixture(t),request={version:1,operationId:randomUUID(),name:'nginx'},wire={targetId:f.targetId,request};
 const receipt=Wire.bindRestartReceipt(wire,await f.target.restart(request));
 for(const change of [r=>r.witness.hostname='restart-'+'0'.repeat(32),r=>r.witness.bindingSha256='0'.repeat(64),r=>r.stdoutText='invented',
 r=>r.stderrBytes++,r=>r.drained=false,r=>r.exitCode=1,r=>r.outputText='different',r=>r.witness.extra=true]){
  const bad=structuredClone(receipt);change(bad);assert.throws(()=>Wire.validateRestartReceipt(wire,bad));
 }
 assert.throws(()=>Wire.validateRestartReceipt({...wire,targetId:randomUUID()},receipt));
 assert.throws(()=>Wire.validateRestartReceipt({...wire,request:{...request,operationId:randomUUID()}},receipt));
});
test('historical v2 and v1 receipt readers retain their exact closed shapes without fabricating witness',async t=>{
 const f=targetFixture(t),request={version:1,operationId:randomUUID(),name:'nginx'},wire={targetId:f.targetId,request};
 const v2={...Wire.bindRestartReceipt(wire,await f.target.restart(request)),version:Wire.VERSION};
 for(const k of ['witness','stdoutText','stderrText','stdoutSha256','stderrSha256','stdoutBytes','stderrBytes','drained','exitCode'])delete v2[k];
 assert.deepEqual(Wire.validateRestartReceipt(wire,v2),v2);assert.equal(Object.hasOwn(v2,'witness'),false);
 const v1={...v2,version:Wire.LEGACY_VERSION};delete v1.outputText;assert.deepEqual(Wire.validateRestartReceipt(wire,v1),v1);
});
test('undrained, wrong namespace or wrong actual stream hashes cannot produce completed target receipt',async t=>{
 for(const mutate of [x=>({...x,drained:false}),x=>({...x,namespaceHostname:'restart-'+'0'.repeat(32)}),x=>({...x,stdoutSha256:'0'.repeat(64)})]){
  const f=targetFixture(t,mutate);await assert.rejects(f.target.restart({version:1,operationId:randomUUID(),name:'nginx'}),{code:'RESTART_COMMAND_FAILED'});
  assert.equal(f.target.state().generation,1);
 }
});
test('namespace hostname is one validated argv value; caller shell command remains literal',async()=>{
 const hostname='restart-'+'a'.repeat(32),command='systemctl restart nginx; /usr/bin/uname -n';
 const argv=buildRestartArgv(command,'/owned/effect',['/usr'],hostname);assert.equal(argv[argv.indexOf('--hostname')+1],hostname);assert.equal(argv.at(-1),command);
 for(const bad of ['host; id','--bind','restart-','restart-'+'A'.repeat(32)])assert.throws(()=>buildRestartArgv(command,'/owned/effect',[],bad));
 let verified=0;const executor=createOwnedRestartCommandExecutor({verify(){verified++;throw Error('assets');}});
 await assert.rejects(executor.execute({command,operationId:randomUUID(),namespaceHostname:'x; bad'}),TypeError);assert.equal(verified,0);
});
test('shared fixed boundary denies shell punctuation before target lookup, begin or any transport',async()=>{
 for(const name of ['nginx; /usr/bin/uname -n','nginx && true','nginx\ntrue','$(id)','-option','nginx foo']){
  const f=serviceFixture({mode:'fixed'});f.input.name=name;
  await assert.rejects(f.service.execute(f.input),{code:'SYSTEM_RESTART_FIXED_DENIED'});
  assert.equal(f.events.includes('resolve'),false);assert.equal(f.events.includes('begin'),false);assert.equal(f.events.includes('health'),false);
 }
});
test('ordinary fixed restart and vulnerable literal interpolation preserve the existing service path',async()=>{
 for(const mode of ['fixed','vuln']){const f=serviceFixture({mode});if(mode==='vuln')f.input.name='nginx; /usr/bin/uname -n';
 const r=await f.service.execute(f.input);assert.equal(r.state,'completed');assert.equal(r.receipt.command,'systemctl restart '+f.input.name);assert.equal(f.events.filter(x=>x==='dispatch').length,1);}
});
test('missing trusted mode authority never falls back to vulnerable execution',()=>{
 const f=serviceFixture();delete f.dependencies.modeAuthority;assert.throws(()=>createBoundSystemRestartService(f.dependencies),TypeError);
});
test('mode revocation after await blocks dispatch; revocation after effect remains uncertain',async()=>{
 let revoked=false;const stale=Object.assign(Error('stale'),{code:'MODE_STALE'});
 const before=serviceFixture({onHealth:()=>{revoked=true;},onCurrent:()=>{if(revoked)throw stale;}});
 await assert.rejects(before.service.execute(before.input),e=>e===stale);assert.equal(before.events.includes('dispatch'),false);assert.equal(before.events.includes('begin'),false);
 revoked=false;const after=serviceFixture({onExecute:()=>{revoked=true;},onCurrent:()=>{if(revoked)throw stale;}});
 await assert.rejects(after.service.execute(after.input),{code:'SYSTEM_RESTART_OUTCOME_UNCERTAIN'});assert.equal(after.events.includes('complete'),false);assert.ok(after.events.includes('OUTCOME_UNCERTAIN'));
});

test('private saved receipt delegates exact current binding without redispatch or historical reconstruction',async()=>{
 const f=serviceFixture(),record={receiptText:'historical stored text',receiptSha256:'a'.repeat(64),receipt:{version:3}};let reads=0;
 await assert.rejects(f.service.readEvidenceReceipt(f.input),{code:'SYSTEM_RESTART_EVIDENCE_UNAVAILABLE'});
 f.dependencies.repository.readEvidenceReceipt=async input=>{reads++;assert.deepEqual(input,f.input);return record;};
 assert.strictEqual(await f.service.readEvidenceReceipt(f.input),record);assert.equal(reads,1);assert.equal(f.events.includes('dispatch'),false);assert.equal(f.events.includes('begin'),false);
 f.dependencies.repository.readEvidenceReceipt=async()=>null;assert.equal(await f.service.readEvidenceReceipt(f.input),null);
});
