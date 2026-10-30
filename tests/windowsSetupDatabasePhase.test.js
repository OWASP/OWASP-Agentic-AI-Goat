'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {EventEmitter}=require('node:events');
const {runSetupDatabasePhase,runOwnedPhase,executeDatabasePhase}=require('../scripts/install/setup-database-phase');
const tick=()=>new Promise(setImmediate);
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};}
function request(){const root=path.resolve(__dirname,'..'),homeDirectory=os.homedir(),id=crypto.createHash('sha256').update(root).digest('hex').slice(0,12);return{kind:'fresh',context:{root,homeDirectory,id,envPath:path.join(root,'.env'),directory:path.join(homeDirectory,'.owasp-ai-goat',id),appDataRoot:'/controlled/private',processEnvironment:{},config:{IDENTITY_DATABASE_URL:'postgres://controlled-runtime@localhost/fixture',IDENTITY_MIGRATION_DATABASE_URL:'postgres://controlled-migration@localhost/fixture'}}};}
function parentHarness(){
 const child=new EventEmitter(),calls=[],sent=[],admission=deferred(),barrier=deferred(),drain=deferred(),close=deferred(),lifetime=deferred();let admitted=false;
 Object.assign(child,{pid:412,connected:true,send:(message,callback)=>{sent.push(message);callback?.();}});
 const job={failure:lifetime.promise,admitGuardian:async value=>{assert.equal(value,child);calls.push('admit');await admission.promise;admitted=true;},assertGuardianOnly:async()=>{calls.push('barrier');await barrier.promise;},expectGuardianExit(){calls.push('expect-exit');},waitForDrain:async()=>{calls.push('drain');await drain.promise;},close:async()=>{calls.push('close');await close.promise;},stop:async()=>{assert.equal(admitted,true,'stop requires finished admission');calls.push('stop');}};
 const options={platform:'win32',timeoutMs:1000,killGraceMs:0,createOwnedProcess:async()=>{calls.push('create-job');return job;},spawn:(_command,_args,options)=>{calls.push('spawn');assert.equal(options.detached,false);return child;}};
 const exit=code=>{child.emit('exit',code,null);child.emit('close',code);};
 return{child,calls,sent,admission,barrier,drain,close,lifetime,job,options,exit};
}
const proof={type:'owasp-ai-goat-setup-phase-publication-proof',id:'a'.repeat(64),nonce:'b'.repeat(64)};

test('controlled Windows parent admits phase before request and joins exit, zero members and helper close',async()=>{
 const h=parentHarness();let settled=false;const pending=runSetupDatabasePhase(request(),{},h.options).then(value=>{settled=true;return value;});
 await tick();assert.deepEqual(h.calls,['create-job','spawn','admit']);assert.deepEqual(h.sent,[]);
 h.admission.resolve();await tick();assert.equal(h.sent[0].kind,'fresh');
 h.child.emit('message',proof);await tick();assert.deepEqual(h.calls.at(-1),'barrier');assert.equal(h.sent.length,1);
 h.barrier.resolve();await tick();assert.deepEqual(h.sent.at(-1),{type:'owasp-ai-goat-setup-phase-publication-approved',id:proof.id,nonce:proof.nonce});
 h.child.emit('message',{type:'result',result:{envPath:'/private/.env',secret:'excluded'}});assert.equal(h.calls.at(-1),'expect-exit');assert.equal(settled,false);
 h.exit(0);await tick();assert.equal(h.calls.at(-1),'drain');assert.equal(settled,false);
 h.drain.resolve();await tick();assert.equal(h.calls.at(-1),'close');assert.equal(settled,false);
 h.close.resolve();assert.deepEqual(await pending,{envPath:'/private/.env'});
});

test('controlled Windows publication refusal never approves or publishes and drains the owned job',async()=>{
 const h=parentHarness(),pending=runSetupDatabasePhase(request(),{},h.options).catch(error=>error);
 await tick();h.admission.resolve();await tick();h.child.emit('message',proof);h.barrier.reject(Error('remaining descendants'));await tick();
 assert.equal(h.sent.some(message=>message.type==='owasp-ai-goat-setup-phase-publication-approved'),false);assert(h.calls.includes('stop'));
 h.exit(1);h.close.resolve();assert.equal((await pending).code,'SETUP_PHASE_PUBLICATION_INVALID');
});

test('controlled Windows malformed proof and premature result fail without trusting arbitrary child PIDs',async()=>{
 for(const message of [{...proof,id:'short'},{type:'result',result:{envPath:'/private/.env'}}]){
  const h=parentHarness(),pending=runSetupDatabasePhase(request(),{},h.options).catch(error=>error);await tick();h.admission.resolve();await tick();
  h.child.emit('message',{type:'child',pid:999,grouped:true,id:crypto.randomUUID()});h.child.emit('message',message);await tick();assert(h.calls.includes('stop'));assert.equal(h.calls.includes('barrier'),false);
  h.exit(1);h.close.resolve();assert.match((await pending).code,/SETUP_PHASE_(PUBLICATION|RESULT)_INVALID/);
 }
});

test('controlled Windows cancellation sends cancel and retains completion until child exit and helper close',async()=>{
 const h=parentHarness(),controller=new AbortController();let settled=false;
 const pending=runSetupDatabasePhase(request(),{},{...h.options,signal:controller.signal}).catch(error=>{settled=true;return error;});
 await tick();h.admission.resolve();await tick();controller.abort();await tick();
 assert.equal(h.sent.at(-1).type,'cancel');assert(h.calls.includes('stop'));assert.equal(settled,false);
 h.exit(1);await tick();assert.equal(h.calls.at(-1),'close');assert.equal(settled,false);h.close.resolve();assert.equal((await pending).code,'SETUP_PHASE_CANCELLED');
});

test('controlled Windows cancellation during admission joins successful admission then stops without a request',async()=>{
 const h=parentHarness(),controller=new AbortController(),pending=runSetupDatabasePhase(request(),{},{...h.options,signal:controller.signal}).catch(error=>error);
 await tick();controller.abort();await tick();assert.equal(h.calls.includes('stop'),false);h.admission.resolve();await tick();assert(h.calls.includes('stop'));h.exit(1);h.close.resolve();
 assert.equal((await pending).code,'SETUP_PHASE_CANCELLED');assert.equal(h.sent.some(message=>message.kind==='fresh'),false);
});

test('controlled Windows helper loss with missing child close fails within a bounded join',async()=>{
 const h=parentHarness(),started=Date.now(),pending=runSetupDatabasePhase(request(),{},{...h.options,timeoutMs:20}).catch(error=>error);
 await tick();h.admission.resolve();await tick();h.lifetime.reject(Error('helper lost'));h.close.resolve();
 assert.equal((await pending).code,'SETUP_PHASE_TERMINATION_UNCERTAIN');assert(Date.now()-started<500);assert(h.calls.includes('stop'));assert(h.calls.includes('close'));
});

function childHarness(executePhase){
 const runtime=new EventEmitter(),sent=[],callbacks=[],exits=[];
 Object.assign(runtime,{pid:412,connected:true,send:(message,callback)=>{sent.push(message);if(callback)callbacks.push(callback);},exit:code=>exits.push(code)});
 runOwnedPhase({runtime,platform:'win32',executePhase,proofTimeoutMs:50});
 const activate=()=>{
  runtime.emit('message',{type:'owasp-ai-goat-owned-guardian-hello'});const challenge=sent.at(-1).challenge,nonce='c'.repeat(64);
  runtime.emit('message',{type:'owasp-ai-goat-owned-guardian-probe',challenge,nonce});
  runtime.emit('message',{type:'owasp-ai-goat-owned-guardian-activate',challenge,nonce});
 };
 return{runtime,sent,callbacks,exits,activate};
}

test('controlled Windows phase refuses requests before activation and disconnects without execution',async()=>{
 for(const event of ['request','disconnect']){
  let executed=0;const h=childHarness(async()=>{executed++;});
  if(event==='request')h.runtime.emit('message',request());else h.runtime.emit('disconnect');
  await tick();assert.equal(executed,0);assert.deepEqual(h.exits,[1]);
 }
 const h=childHarness(async()=>assert.fail('canceled activation must not execute'));
 h.activate();h.runtime.emit('message',request());h.runtime.emit('disconnect');h.callbacks.shift()();await tick();assert.deepEqual(h.exits,[1]);
});

test('controlled activated Windows phase requires matching nonce proof before publication and result',async()=>{
 const calls=[],h=childHarness(async(_request,{beforePublication})=>{calls.push('drained');await beforePublication();calls.push('publish');return{envPath:'/private/.env'};});
 h.activate();h.callbacks.shift()();h.runtime.emit('message',request());await tick();
 assert.deepEqual(calls,['drained']);const message=h.sent.at(-1);assert.equal(message.type,'owasp-ai-goat-setup-phase-publication-proof');assert.match(message.id,/^[a-f0-9]{64}$/);assert.match(message.nonce,/^[a-f0-9]{64}$/);
 h.runtime.emit('message',{type:'owasp-ai-goat-setup-phase-publication-approved',id:message.id,nonce:message.nonce});await tick();assert.deepEqual(calls,['drained','publish']);assert.equal(h.sent.at(-1).type,'result');
 for(const callback of h.callbacks)callback();assert.deepEqual(h.exits,[0]);
});

test('controlled phase mismatched publication reply or cancellation never calls publisher',async()=>{
 for(const event of ['mismatch','cancel']){
  let published=false;const h=childHarness(async(_request,{beforePublication})=>{await beforePublication();published=true;return{};});
  h.activate();h.callbacks.shift()();h.runtime.emit('message',request());await tick();const message=h.sent.at(-1);
  if(event==='mismatch')h.runtime.emit('message',{type:'owasp-ai-goat-setup-phase-publication-approved',id:message.id,nonce:'f'.repeat(64)});else h.runtime.emit('message',{type:'cancel'});
  await tick();assert.equal(published,false);assert.equal(h.sent.at(-1).type,'failure');assert.deepEqual(h.exits,[1]);
 }
});

test('controlled execution preserves lease, child/pool drain, authority proof, publication and clean ordering',async()=>{
 const saved={...process.env},calls=[];
 try{
  await executeDatabasePhase(request(),{acquire:async()=>({assertHeld(){},async beginMaintenance(){calls.push('dirty');return Object.freeze({epoch:'1'});},async finishMaintenance(){calls.push('clean');},async close(){calls.push('lease-close');}}),execute:async(_r,_s,{deferPublication})=>{calls.push('work');deferPublication(async()=>calls.push('publish'));return{};},drain:async()=>calls.push('pool-drain'),beforePublication:async()=>calls.push('guardian-only')});
  assert.deepEqual(calls,['dirty','work','pool-drain','guardian-only','publish','clean','lease-close']);
 }finally{for(const key of Object.keys(process.env))if(!(key in saved))delete process.env[key];Object.assign(process.env,saved);}
});


test('controlled Windows timed-out admission disconnects before a late activation can run',async()=>{
 const h=parentHarness();let disconnected=false;
 h.child.disconnect=()=>{disconnected=true;h.child.connected=false;h.child.emit('disconnect');h.exit(1);};
 h.job.admitGuardian=async()=>{await h.admission.promise;if(!h.child.connected)throw Error('disconnected admission');h.sent.push({kind:'unexpected activation'});};
 h.close.resolve();
 const pending=runSetupDatabasePhase(request(),{},{...h.options,timeoutMs:15}).catch(error=>error);
 assert.equal((await pending).code,'SETUP_PHASE_TERMINATION_UNCERTAIN');assert.equal(disconnected,true);
 h.admission.resolve();await tick();assert.equal(h.sent.some(message=>message.kind),false);
});
