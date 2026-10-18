'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {prepareListingAdmission,hash}=require('../server/services/secureshopListingJournalContract');
const {createListingJournalRepository}=require('../server/database/postgres/secureshopListingJournalRepository');
const {createListingsComposition}=require('../server/services/secureshopListingsComposition');
const {createListingListener}=require('../sidecars/sandbox-runner/owned-listings/http-listener');
function input(action = 'rewrite') {
  return { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 },
    persona: { id: 3, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' },
    targetId: randomUUID(), mode: 'vuln', catalogRevision: '0',
    request: action === 'rewrite' ? { version: 1, action, operationId: randomUUID(), title: 'Product', description: '<img src=x onerror=owned()>' }
      : { version: 1, action, operationId: randomUUID(), json_url: 'http://supplier/catalog', xml_url: null } };
}
function sqlFixture({ mismatch = false, commitThrows = false, rollbackThrows = false, validateImportReceipt } = {}) {
  const admissions = new Map(), events = [], queries = [], releases = [];
  const pool = { async connect() { return {
    release(damaged) { releases.push(damaged); },
    async query(sql, values = []) {
      queries.push([sql, values]);
      if (sql === 'COMMIT' && commitThrows) throw new Error('connection lost');
      if (sql === 'ROLLBACK' && rollbackThrows) throw new Error('connection lost');
      if (sql.startsWith('SELECT newly_admitted FROM secureshop_review.admit_owned_listing_operation')) {
        if (admissions.has(values[0])) return { rows: [{newly_admitted:false}] };
        admissions.set(values[0], { operation_id: values[0], target_id: values[1], binding_json: values[2], binding_sha256: values[3], request_json: values[4], request_sha256: values[5], action: values[6] });
        return { rows: [{ newly_admitted: true }] };
      }
      if(sql.startsWith('SELECT secureshop_review.publish_owned_listing_import')){
        const a=admissions.get(values[0]),previous=events.filter(e=>e.operation_id===values[0]).at(-1),effect=JSON.parse(previous.payload_json);
        const result={version:1,operationId:values[0],requestSha256:a.request_sha256,executorReceiptSha256:effect.executorReceiptSha256,importReceiptSha256:previous.payload_sha256,productIds:effect.products.map((_,i)=>100+i),catalogRevision:'1'};
        const payload_json=JSON.stringify(result);
        events.push({operation_id:values[0],event_id:values[1],sequence:values[2]+1,state:'completed',payload_json,payload_sha256:hash(payload_json)});
        return {rows:[]};
      }
      if (sql.startsWith('SELECT * FROM secureshop_review.owned_listing_admissions')) return { rows: admissions.has(values[0]) ? [admissions.get(values[0])] : [] };
      if (sql.startsWith('SELECT secureshop_review.append_owned_listing_event')) {
        events.push({ operation_id: values[0], event_id: values[1], sequence: values[2], state: values[3], payload_json: values[4], payload_sha256: values[5] }); return { rows: [] };
      }
      if (sql.startsWith('SELECT * FROM secureshop_review.owned_listing_events')) {
        const rows = events.filter(e => e.operation_id === values[0] && (!values[1] || e.event_id === values[1])).sort((a,b) => b.sequence-a.sequence);
        return { rows: sql.includes('sequence ASC') ? rows.reverse() : rows.slice(0,1) };
      }
      return { rows: [] };
    },
  }; } };
  const authority = { capture(value) { return { binding: { ...value.scope, personaId: mismatch ? 999 : value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
    async assertRemoteAdmission() {}, async withCrossStoreEffect(fn) { return fn({ query() { throw new Error('Agents connection must never receive review SQL'); } }); } }; } };
  return { pool, repository: createListingJournalRepository({ pool, personaAuthority: authority, capabilityKey:Buffer.alloc(32,7),validateImportReceipt }), admissions, events, queries, releases };
}
function graphFixture(){
 let plan=['listing.fetch_parse','listing.publish'],providerHook=async()=>{};
 const sessions=new Map(),messages=new Map(),claims=new Map(),operations=new Map(),traces=[],decisions=[],systems=[];
 let calls=0;
 const repo={async getBoundSession(id){return sessions.get(id);},async acquireBoundSession({id,binding,purpose}){const existing=[...sessions.values()].find(row=>row.purpose===purpose&&JSON.stringify(row.binding)===JSON.stringify(binding));if(existing)return existing;const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row;},async activateBoundSession(id){sessions.get(id).state='active';return true;},async getMessages(id){return structuredClone(messages.get(id)||[]);},async appendMessage(id,binding,message){messages.set(id,[...(messages.get(id)||[]),structuredClone(message)]);},async getTokens(){return 0;},async addTokens(){},async appendTraces(id,binding,rows){traces.push(...rows);}};
 const journal={async claim({sessionId,requestId}){const key=sessionId+':'+requestId;if(claims.has(key))return claims.get(key);const value={status:'claimed',claimId:requestId};claims.set(key,{...value,status:'started'});return value;},async complete({sessionId,requestId,result}){claims.set(sessionId+':'+requestId,{status:'completed',claimId:requestId,result});},async markUncertain({sessionId,requestId}){const key=sessionId+':'+requestId;if(claims.get(key)?.status!=='completed')claims.set(key,{status:'uncertain',claimId:requestId});}};
 let revoked=false;
 const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const personaAuthority={capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:check,async withPersonaEffect(fn){await check();return fn({});},async withCrossStoreEffect(fn){await check();return fn();}};}};
 const provider={async chat(args){decisions.push(args);await providerHook();const name=plan[calls++];return{provider:'ollama',model:'controlled',mocked:false,fallback:false,stop_reason:'tool_use',tool_uses:[{id:randomUUID(),name,args:{}}]};},async finalResponse(){return{provider:'ollama',model:'controlled',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Published.'};}};
 const coordinator={async run(owner,options,run){const admitted=await options.admit();if(admitted.skip)return admitted.value;return run({runId:randomUUID(),ownerKey:owner,generation:1,durableGeneration:1,signal:options.signal,check,async effect(key,fn){return fn();},async effectWithReceipt(key,fn){return{value:await fn(),receipt:{status:'completed',effectKey:key}};},async trace(){}});}};
 return{conversationRepository:repo,journal,coordinator,provider,personaAuthority,launches:{async assertCurrent(){}},revoke(){revoked=true;},setPlan(value){plan=value;calls=0;},setProviderHook(fn){providerHook=fn;},sessions,claims,decisions};
}
test('rewrite recovery forwards its original journal mode and preserves immutable encoded receipt',async()=>{
 const raw=input('rewrite');raw.mode='fixed';const graph=graphFixture(),sql=sqlFixture();let modelCalls=0;
 graph.provider={async chat(){modelCalls++;return{provider:'ollama',model:'controlled',mocked:false,fallback:false,stop_reason:'end_turn',text:'<b>Original</b>'};}};
 const capture=graph.personaAuthority.capture;
 graph.personaAuthority={capture(input){const fence=capture(input);return{...fence,async withPersonaEffect(work){return work({async query(_sql,args){
   assert.equal(args[0],raw.request.operationId);assert.equal(args[1],'secureshop_listing_rewrite');
   const session=[...graph.sessions.values()][0],saved=graph.claims.get(session.id+':'+raw.request.operationId);
   const request=require('../server/services/secureshopTurnRequest').createTurnRequest({sessionId:session.id,requestId:raw.request.operationId,binding:session.binding,message:JSON.stringify(prepareListingAdmission(raw).request)});
   return{rows:[{session_id:session.id,request_hash:request.hash,request_version:request.version,status:saved.status,result_json:saved.result}]};
  }});}};}};
 const composition=createListingsComposition({...graph,pool:sql.pool,capabilityKey:Buffer.alloc(32,7),targetManager:{resolveConfiguration(){throw Error('rewrite must not call import executor');}}});
 const first=await composition.run(raw),recovered=await composition.recover(raw);
 assert.equal(first.operation.receipt.html,'&lt;b&gt;Original&lt;/b&gt;');assert.deepEqual(recovered.modeCapability,first.modeCapability);assert.equal(recovered.modeCapability.effectiveMode,'fixed');assert.deepEqual(recovered.operation.receipt,first.operation.receipt);assert.equal(modelCalls,1);
 const saved=[...graph.claims.values()][0];delete saved.result.modeCapability;
 assert.equal((await composition.recover(raw)).modeCapability,undefined);assert.equal(modelCalls,1);
});
async function setup(t,{maxClients=512}={}){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listings-composition-'));await fs.chmod(directory,0o700);
 const raw=input('import'),prepared=prepareListingAdmission(raw),identity='a'.repeat(64),runtimeDigest='b'.repeat(64),token='x'.repeat(43);
 let effects=0;const namespace={async checkReadiness(){return{ready:true,runtimeDigest};},async execute({request,mode}){effects++;return{version:1,operationId:request.operationId,requestSha256:prepared.requestSha256,mode,products:[{name:'Observed product',price:'5.25'}],sources:[{kind:'json',uri:request.json_url,byteCount:44,sourceSha256:'c'.repeat(64),prototypeEffect:{observed:false,inheritedProperties:[]}}]};}};
 const listener=await createListingListener({token,directory,mode:'vuln',identity,namespace});const address=await listener.start();
 t.after(async()=>{await listener.close();await fs.rm(directory,{recursive:true,force:true});});
 const config={scope:raw.scope,targetId:raw.targetId,mode:raw.mode,origin:`http://127.0.0.1:${address.port}`,token,runtimeIdentity:hash(JSON.stringify({identity,runtimeDigest})),runtimeDigest,executorId:randomUUID()};
 const sql=sqlFixture(),graph=graphFixture();let resolveHook=()=>{},retireHook=async()=>{throw Error('cleanup unavailable');};
 const composition=createListingsComposition({...graph,pool:sql.pool,capabilityKey:Buffer.alloc(32,7),maxClients,targetManager:{acknowledgeRetirement:(...args)=>retireHook(...args),async resolveConfiguration(query){await resolveHook(query);return {...config,...query};}}});
 return{composition,raw,sql,graph,config,namespace,effects:()=>effects,setResolveHook(fn){resolveHook=fn;},setRetireHook(fn){retireHook=fn;}};
}
test('controlled graph uses real private HTTP receipts and canonical journal; replay dispatches once',async t=>{
 const f=await setup(t),result=await f.composition.run(f.raw);
 assert.equal(result.operation.state,'completed');assert.equal(f.effects(),1);assert.equal(f.graph.decisions.length,2);
 const observed=JSON.parse(f.sql.events.find(e=>e.state==='effect_received').payload_json);
 assert.equal(observed.products[0].price,5.25);assert.equal(observed.sources[0].sourceSha256,'c'.repeat(64));
 assert.ok(JSON.stringify(f.graph.decisions[1]).includes('Observed product'));
 assert.equal((await f.composition.run(f.raw)).replayed,true);assert.equal(f.effects(),1);assert.equal(f.graph.decisions.length,2);
 assert.ok(!JSON.stringify(result).includes(f.config.token));
});
test('recovery refuses persona revoked during private manager resolution',async t=>{
 const f=await setup(t);await f.sql.repository.admit(f.raw);await f.sql.repository.transition(f.raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 f.setResolveHook(()=>f.graph.revoke());
 await assert.rejects(f.composition.recover(f.raw),{code:'SHOP_AUTH_INVALID'});assert.equal(f.effects(),0);
});
test('persona revocation during sidecar receipt GET releases no recovery handle',async t=>{
 const f=await setup(t);
 // Produce a durable sidecar result, then retain canonical uncertainty to exercise
 // GET-only recovery. Controlled SQL state is not native transaction proof.
 await f.composition.run(f.raw);
 f.sql.events.splice(1);
 const upstream=f.config.origin,http=require('node:http');let gets=0,posts=0;
 const proxy=http.createServer(async(req,res)=>{
  const response=await fetch(upstream+req.url,{headers:{authorization:req.headers.authorization}});
  const bytes=await response.arrayBuffer();
  if(req.url.startsWith('/operations/')){gets++;f.graph.revoke();}
  if(req.method==='POST')posts++;
  res.writeHead(response.status,{'content-type':'application/json'});res.end(Buffer.from(bytes));
 });
 await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>{proxy.close(resolve);proxy.closeAllConnections();}));
 // A new app process restores registrations only after canonical admission checks.
 const config={...f.config,origin:`http://127.0.0.1:${proxy.address().port}`};
 const recovered=createListingsComposition({...f.graph,pool:f.sql.pool,capabilityKey:Buffer.alloc(32,7),targetManager:{async resolveConfiguration(){return config;}}});
 await assert.rejects(recovered.recover(f.raw),{code:'SHOP_AUTH_INVALID'});
 assert.equal(gets,1);assert.equal(posts,0);assert.equal(f.effects(),1);
});

test('explicit resume reconciles original receipt then new model publishes without another executor effect',async t=>{
 const f=await setup(t);await f.composition.run(f.raw);
 // Controlled durable response-loss boundary: executor completed but canonical
 // operation still running. Original graph turn is already recorded separately.
 f.sql.events.splice(1);f.graph.setPlan(['listing.publish']);
 const recovered=await f.composition.recover(f.raw);
 assert.equal(recovered.operation.state,'running');assert.equal(recovered.executor.state,'completed');
 const before=f.graph.decisions.length;
 const resumed=await f.composition.resume(f.raw);
 assert.equal(resumed.operation.state,'completed');assert.equal(f.effects(),1);
 assert.equal(f.graph.decisions.length,before+1);
 assert.ok(JSON.stringify(f.graph.decisions.at(-1)).includes('recoveredObservation'));
 const replay=await f.composition.resume(f.raw);assert.equal(replay.replayed,true);
 assert.equal(f.effects(),1);assert.equal(f.graph.decisions.length,before+1);
});

test('explicit shutdown disposal releases cached clients and rejects subsequent operations',async t=>{
 const f=await setup(t);await f.composition.run(f.raw);f.composition.dispose();
 await assert.rejects(f.composition.run(f.raw),{code:'LISTINGS_COMPOSITION_DISPOSED'});
 await assert.rejects(f.composition.recover(f.raw),{code:'LISTINGS_COMPOSITION_DISPOSED'});
 await assert.rejects(f.composition.resume(f.raw),{code:'LISTINGS_COMPOSITION_DISPOSED'});
 assert.equal(f.effects(),1);
});

test('separate compositions and restart share persisted conversation and resume turn admission',async t=>{
 const f=await setup(t);await f.composition.run(f.raw);
 f.sql.events.splice(2); // retain exact admitted parser receipt, no publication
 f.graph.setPlan(['listing.publish']);
 let release,entered;const waiting=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});
 f.graph.setProviderHook(async()=>{entered();await waiting;});
 const make=()=>createListingsComposition({...f.graph,pool:f.sql.pool,capabilityKey:Buffer.alloc(32,7),targetManager:{async resolveConfiguration(){return f.config;}}});
 const another=make(),before=f.graph.decisions.length;
 const first=f.composition.resume(f.raw);await started;
 await assert.rejects(another.resume(f.raw),{code:'TURN_RECOVERY_REQUIRED'});
 release();const result=await first;assert.equal(result.operation.state,'completed');
 assert.equal(f.graph.decisions.length,before+1);assert.equal(f.graph.sessions.size,1);assert.equal(f.effects(),1);
 const restart=make();assert.equal((await restart.resume(f.raw)).replayed,true);
 assert.equal(f.graph.decisions.length,before+1);assert.equal(f.graph.sessions.size,1);
});
test('serialized concurrent resume returns completed replay after first model publishes',async t=>{
 const f=await setup(t);await f.composition.run(f.raw);f.sql.events.splice(2);f.graph.setPlan(['listing.publish']);
 const original=f.graph.coordinator.run;let queue=Promise.resolve();
 f.graph.coordinator.run=(...args)=>{const result=queue.then(()=>original(...args));queue=result.catch(()=>{});return result;};
 let release,entered;const waiting=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});
 f.graph.setProviderHook(async()=>{entered();await waiting;});
 const other=createListingsComposition({...f.graph,pool:f.sql.pool,capabilityKey:Buffer.alloc(32,7),targetManager:{async resolveConfiguration(){return f.config;}}});
 const before=f.graph.decisions.length,first=f.composition.resume(f.raw);await started;
 const second=other.resume(f.raw);await new Promise(resolve=>setImmediate(resolve));release();
 const [a,b]=await Promise.all([first,second]);
 assert.equal(a.operation.state,'completed');assert.equal(b.operation.state,'completed');assert.equal(b.replayed,true);
 assert.equal(f.graph.decisions.length,before+1);assert.equal(f.effects(),1);
});
test('canonical retirement acknowledgement releases target cache while failed cleanup preserves recovery',async t=>{
 const f=await setup(t,{maxClients:1});await f.composition.run(f.raw);f.sql.events.splice(2);
 const next={...f.raw,targetId:randomUUID(),request:{...f.raw.request,operationId:randomUUID()}};
 await f.sql.repository.admit(next);await f.sql.repository.transition(next,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 await assert.rejects(f.composition.recover(next),{code:'LISTINGS_CLIENT_CAPACITY'});
 const binding={mode:f.raw.mode,targetId:f.raw.targetId,scope:f.raw.scope},operationId=randomUUID();
 await assert.rejects(f.composition.releaseRetiredTarget(binding,{operationId}),/cleanup unavailable/);
 assert.equal((await f.composition.recover(f.raw)).executor.state,'completed');
 f.setRetireHook(async(raw,options)=>{assert.deepEqual(raw,binding);assert.equal(options.operationId,operationId);return{forgotten:true,operationId,targetId:raw.targetId};});
 assert.deepEqual(await f.composition.releaseRetiredTarget(binding,{operationId}),{released:true,targetId:f.raw.targetId});
 // New target reaches its own GET (404), proving the cache slot was reclaimed.
 await assert.rejects(f.composition.recover(next),{code:'LISTINGS_HTTP'});
 assert.equal(f.effects(),1);
});
test('retired target cache remains pinned until its active executor lease settles',async t=>{
 const f=await setup(t,{maxClients:1});let release,entered;
 const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>entered=resolve),execute=f.namespace.execute;
 f.namespace.execute=async args=>{entered();await held;return execute(args);};
 const running=f.composition.run(f.raw).then(value=>({value}),error=>({error}));await started;
 const next={...f.raw,targetId:randomUUID(),request:{...f.raw.request,operationId:randomUUID()}};
 await f.sql.repository.admit(next);await f.sql.repository.transition(next,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 f.setRetireHook(async(raw,{operationId})=>({forgotten:true,operationId,targetId:raw.targetId}));
 try{
  await f.composition.releaseRetiredTarget({scope:f.raw.scope,targetId:f.raw.targetId,mode:f.raw.mode},{operationId:randomUUID()});
  f.setResolveHook(query=>{if(query.targetId===f.raw.targetId)throw Object.assign(Error('retired'),{code:'STALE_LAUNCH'});});
  await assert.rejects(f.composition.recover(next),{code:'LISTINGS_CLIENT_CAPACITY'});
 }finally{release();await running;}
 assert.ok((await running).error);
 await assert.rejects(f.composition.recover(next),{code:'LISTINGS_HTTP'});
});
