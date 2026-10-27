'use strict';
// Task-only V23 public administrator browser proposal. The owner still controls
// four disposable stores, model/Judge transport, publication and retirement.
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),net=require('node:net');
const {randomUUID,randomBytes,createHash}=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..'),PREFIX='PG_SECURESHOP_V23_';
const fixture=require('../../tests/fixtures/secureshopV23OriginalQualification');
const taskModule=name=>require(path.join(ROOT,'tasks/qualification',name));
const rendered=taskModule('v23-public-admin-rendered.proposed.js');
const savedReader=taskModule('v23-public-admin-saved-reader.proposed.js');
const privateProof=taskModule('v23-public-admin-private-proof.proposed.js');
const receipt=taskModule('v23-public-admin-receipt.proposed.js');
const TITLE='original V23 public administrator registration preserves rendered, owned, Judge, Fixed and lifecycle boundaries';
const SCOPE=receipt.SCOPE;
const GATES=receipt.GATES;
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
function privateBrowserOptions({directory,origin,profile,executablePath}){
 const target=new URL(origin);assert.equal(target.origin,origin);assert.equal(target.protocol,'http:');
 assert.equal(target.hostname,'127.0.0.1');assert.match(target.port,/^[1-9][0-9]{0,4}$/);
 assert.equal(target.pathname,'/');assert.equal(target.search,'');assert.equal(target.hash,'');
 assert.equal(path.dirname(profile),path.join(directory,'tmp'));
 assert.match(path.basename(profile),/^dvaia-v23-public-admin-[A-Za-z0-9_-]+$/);
 const info=require('node:fs').lstatSync(profile);
 assert(info.isDirectory()&&!info.isSymbolicLink());assert.equal(info.uid,process.getuid());
 assert.equal(info.mode&0o777,0o700);assert.equal(require('node:fs').realpathSync(profile),profile);
 return{headless:true,userDataDir:profile,executablePath,args:['--no-sandbox',
  '--disable-background-networking','--disable-component-update','--disable-domain-reliability',
  '--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--proxy-server=http://blocked.invalid:9','--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]']};
}
function retainObservedPublicCalls(wire,relays,judgeRelay){
 const actors=relays.filter(relay=>relay!==judgeRelay).flatMap(relay=>relay.calls);
 const judges=judgeRelay?judgeRelay.calls:[];
 assert(actors.every(call=>call&&typeof call==='object'));
 assert(judges.every(call=>call&&typeof call==='object'));
 wire.actors=structuredClone(actors);wire.judges=structuredClone(judges);
}
function boundedFramePath(raw,origin){
 try{
  const url=new URL(raw);if(url.origin!==origin)return null;
  const paths=new Set(['/secureshop/login','/secureshop/admin/mcp','/secureshop-frame.html',
   '/api/secureshop/auth/bootstrap','/api/secureshop/v2/auth/whoami']);
  return paths.has(url.pathname)?url.pathname:'other';
 }catch{return null;}
}
function boundedPageErrorClass(error){
 if(error instanceof SyntaxError)return 'SyntaxError';
 if(error instanceof ReferenceError)return 'ReferenceError';
 if(error instanceof TypeError)return 'TypeError';
 return error instanceof Error?'Error':'unknown';
}
async function publicAdminFrame(page,mark){
 mark('turn-frame-element');
 const handle=await page.waitForSelector('iframe[title="SecureShop"]',{timeout:30000});
 assert(handle,'Standalone SecureShop frame must mount');
 try{
  mark('turn-frame-attach');
  const frame=await handle.contentFrame();
  assert(frame&&!frame.detached,'Standalone SecureShop frame must be attached');
  mark('turn-frame-composer');
  await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea',
   {visible:true,timeout:30000});
  return frame;
 }finally{await handle.dispose();}
}
async function selectPublicMode(page,mode){
 assert(['vuln','fixed'].includes(mode));
 const state=await page.evaluate(async selected=>{
  const current=await fetch('/api/secureshop/auth/mode',{credentials:'same-origin'});
  if(!current.ok)throw Error('PUBLIC_MODE_READ_FAILED');
  const previous=await current.json();
  if(previous.mode===selected)return previous;
  const response=await fetch('/api/secureshop/auth/mode',{method:'POST',credentials:'same-origin',
   headers:{'content-type':'application/json'},
   body:JSON.stringify({mode:selected,expectedRevision:previous.revision})});
  if(!response.ok)throw Error('PUBLIC_MODE_WRITE_FAILED');
  return response.json();
 },mode);
 assert.equal(state.mode,mode);assert.match(state.revision,/^[1-9][0-9]{0,18}$/);
 return state;
}
async function closeOwnedHttp(server,ms=8000){
 if(!server)return;
 assert(Number.isSafeInteger(ms)&&ms>0&&ms<=8000);
 await new Promise((resolve,reject)=>{
  let settled=false;
  const finish=error=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolve();};
  const timer=setTimeout(()=>{server.closeAllConnections();finish(Object.assign(
   new Error('Owned HTTP retirement deadline'),{code:'V23_PUBLIC_HTTP_RETIREMENT_UNPROVEN'}));},ms);
  server.close(finish);
 });
}
async function stopOwnedAgentHost(host,child){
 if(!host)return false;
 await host.stop();
 assert(child&&Number.isSafeInteger(child.pid)&&child.pid>0,'Owned agent host child missing');
 assert.equal(host.status,'stopped');
 assert.equal(host.proc,null);
 assert(child.exitCode!==null||child.signalCode!==null,
  'Owned agent host child retirement unproven');
 return true;
}

const V23_JUDGE_IDENTITIES=Object.freeze({
 'llama-original':Object.freeze({provider:'ollama',model:MODEL,digest:DIGEST}),
 'qwen25-v1':Object.freeze({provider:'ollama',model:'qwen2.5:7b-instruct-q4_K_M',digest:'845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e'}),
});
function v23JudgeIdentity(profile='llama-original'){
 assert(Object.hasOwn(V23_JUDGE_IDENTITIES,profile),'Unknown V23 Judge profile');
 return V23_JUDGE_IDENTITIES[profile];
}
function v23ConfiguredIdentity(config,profile='llama-original'){
 const identity=v23JudgeIdentity(profile);
 assert.equal(config.provider,identity.provider);assert.equal(config.model,identity.model);
 // This checks configuration, NOT endpoint ownership, model availability or permission.
 return identity;
}
function assertV23RoleWires(wire,profile='llama-original'){
 const judge=v23JudgeIdentity(profile);
 assert.deepEqual(Object.keys(wire).sort(),['actor','actors','judge','judgeProfile','judges','version'].sort());
 assert.equal(wire.version,2);assert.equal(wire.judgeProfile,profile);
 assert.deepEqual(wire.actor,{provider:'ollama',model:MODEL,digest:DIGEST});assert.deepEqual(wire.judge,judge);
 assert(Array.isArray(wire.actors)&&wire.actors.length>=6&&wire.actors.length<=12);
 assert(Array.isArray(wire.judges)&&wire.judges.length===2);
 const actors=wire.actors.map(c=>assertPhysical(c,'actor'));
 const judges=wire.judges.map(c=>assertPhysical(c,'judge',profile));
 // Physical role/model join only. Original fixture still decides semantics,
 // and the existing owner must independently prove actual runtime digests.
 return{actors,judges};
}

const sha=x=>createHash('sha256').update(x).digest('hex');
const json=x=>JSON.parse(JSON.stringify(x));
async function saveCaseEvidence(directory,spec,{packet,terminal,calls,assembly,requestVariant,boundaryContract}){
 assert(['positive','benign','fixed'].includes(spec.kind));assert(fixture.REQUEST_VARIANTS.includes(requestVariant));assert(fixture.BOUNDARY_CONTRACTS.includes(boundaryContract));
 assert(path.isAbsolute(directory));assert.equal(await fs.realpath(directory),directory);assert(directory.startsWith(path.join(ROOT,'tasks')+path.sep)||directory.startsWith(path.join(ROOT,'.qualification')+path.sep));
 const stat=await fs.stat(directory);assert(stat.isDirectory()&&(stat.mode&0o777)===0o700&&stat.uid===process.getuid());
 assert.equal(packet.evidence.requestVariant,requestVariant);assert.equal(packet.evidence.boundaryContract,boundaryContract);
 const file=spec.kind+'-case-evidence.json',body=JSON.stringify({version:1,kind:spec.kind,requestVariant,boundaryContract,canonicalCredit:false,qualificationComplete:false,independentJudgeComplete:false,packet,terminal,calls,assembly});
 assert(Buffer.byteLength(body)<=4*1024*1024,'Case evidence exceeds private bound');
 const handle=await fs.open(path.join(directory,file),require('node:fs').constants.O_CREAT|require('node:fs').constants.O_EXCL|require('node:fs').constants.O_WRONLY|require('node:fs').constants.O_NOFOLLOW,0o600);
 try{await handle.writeFile(body);await handle.sync();}finally{await handle.close();}
 return{kind:spec.kind,file,sha256:sha(body),evidenceSha256:packet.evidenceSha256,runId:packet.evidence.runId,actorCalls:calls.length,qualificationComplete:false,independentJudgeComplete:false};
}
function caseGate(plan){let index=0,failed=false;const packets=new Map();
 const before=spec=>{assert(!failed,'Prior case failed');assert.equal(spec,plan.cases[index],'Case order required');};
 return{before,async accept(spec,terminal,verify){before(spec);try{const packet=fixture.prepareEvidence(plan,spec,terminal);await verify(packet);packets.set(spec.kind,packet);index++;return packet;}catch(error){failed=true;throw error;}},
  complete(){assert(!failed&&index===plan.cases.length,'Full validated cohort required');return packets;}};
}
async function finishEvidence({writes,result,errors,primary,save}){
 try{await writes;}catch(error){errors.push(error);result.errors.push(error.code||error.message);}
 result.passed=!primary&&!errors.length&&GATES.every(k=>result.gates[k]);
 try{await save();}catch(error){errors.push(error);result.errors.push(error.code||error.message);result.passed=false;}
}
function candidateBytes(result){return JSON.stringify({version:1,kind:'original-v23-unsealed-candidate',
 passed:false,canonicalCredit:false,requiresOwnerTerminal:true,result:{...result,passed:false}},null,2)+'\n';}
async function publishPrivateFinal(file,identity,result,publication={check(){},io:fn=>fn(),close:fn=>fn()},encode=candidateBytes){
 const native=require('node:fs'),directory=path.dirname(file);
 const io=publication.io,check=publication.check;
 assert.equal(await io(()=>fs.realpath(directory)),directory);
 assert(directory.startsWith(path.join(ROOT,'tasks')+path.sep)||directory.startsWith(path.join(ROOT,'.qualification')+path.sep));
 const body=encode(result);assert(Buffer.byteLength(body)<=4*1024*1024);
 const verify=async()=>{const current=await io(()=>fs.lstat(file));assert(current.isFile()&&!current.isSymbolicLink());
  assert.equal(current.ino,identity.ino);assert.equal(current.dev,identity.dev);assert.equal(current.uid,process.getuid());assert.equal(current.mode&0o777,0o600);};
 await verify();const temporary=file+'.final-'+randomBytes(12).toString('hex');let published=false;
 let h;
 try{h=await io(()=>fs.open(temporary,native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_WRONLY|native.constants.O_NOFOLLOW,0o600));
  await io(()=>h.writeFile(body));await io(()=>h.sync());await publication.close(()=>h.close());await verify();
  // No async success-rename may outlive the publication fence. Synchronous OS
  // calls are not preemptible; check overruns and never claim timer cancellation.
  check();const parent=native.openSync(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY);
  try{check();native.renameSync(temporary,file);published=true;check();native.fsyncSync(parent);check();}finally{native.closeSync(parent);}
 }finally{if(h)await publication.close(()=>h.close()).catch(()=>{});
  if(!published)await publication.close(()=>fs.unlink(temporary)).catch(()=>{});}
 return Object.freeze({version:1,file:path.basename(file),sha256:sha(body),bytes:Buffer.byteLength(body),unsealed:true,requiresOwnerTerminal:true});
}
async function assessThenLifecycle({assess,settle,check,lifecycle,recordSecondary}){
 let primary;
 try{check();await assess();}catch(error){primary=error;}
 try{
  // No reset after uncertain transport retirement or expired owner authority.
  await settle();check();await lifecycle();check();
 }catch(error){
  if(!primary)throw error;
  recordSecondary(error);throw primary;
 }
 if(primary)throw primary;
}
async function activeStep(check,action){check();const result=await action();check();return result;}
async function admitOwnedResource(check,create,retain){check();const value=await create();retain(value);check();return value;}
async function finishAndCloseEvidence({finish,handles,errors,result}){
 const retain=error=>{errors.push(error);result.errors.push(error.code||error.message);};
 try{await finish();}catch(error){retain(error);}
 for(const handle of handles)try{await handle.close();}catch(error){retain(error);}
}
async function retireCohortResources({transports,stores,errors,result}){
 const attempt=async close=>{try{await close();}catch(error){errors.push(error);result.errors.push(error.code||error.message);}};
 for(const close of transports)await attempt(close);
 if(errors.length){const debt=Object.assign(new Error('V23_COHORT_LOCAL_RETIREMENT_UNPROVEN'),
  {code:'V23_COHORT_LOCAL_RETIREMENT_UNPROVEN',retirementUnproven:true});errors.push(debt);result.errors.push(debt.code);return;}
 for(const close of stores)await attempt(close);
}
function passiveCapture(provider){
 const decisions=[],chat=provider.chat.bind(provider),transport=provider.transport.chat.bind(provider.transport);let active;
 provider.chat=async input=>{assert(!active);const {signal,...saved}=input,entry={input:json(saved),transports:[]};decisions.push(entry);active=entry;
  try{return await chat(input);}finally{active=null;}};
 provider.transport.chat=async(...args)=>{assert(active);const {signal,...options}=args[2],entry={messages:json(args[0]),tools:json(args[1]),options:json(options)};active.transports.push(entry);
  const response=await transport(...args);entry.response=json(response);return response;};
 return decisions;
}
function assertPublicAssembly(decisions,calls){
 const transports=decisions.flatMap(decision=>decision.transports.map(transport=>({decision,transport})));
 assert.equal(transports.length,calls.length);
 for(let index=0;index<transports.length;index++){
  const {decision,transport}=transports[index],physical=assertPhysical(calls[index],'actor');
  if(decision.method==='chat')assert.equal(decision.input.role,'admin');
  assert.deepEqual(physical.request.messages,transport.messages);
  assert.deepEqual(transport.tools,[]);
  assert.equal(Object.hasOwn(physical.request,'tools'),false);
  assert.deepEqual(physical.request.format,transport.options.format);
  assert.equal(physical.request.options?.temperature,transport.options.temperature);
  assert.equal(physical.request.options?.num_predict,transport.options.num_predict);
  assert.equal(transport.response.response,physical.response.message.content);
  assert.equal(transport.response.provider,'ollama');
  assert.equal(transport.response.model,MODEL);
  assert.equal(transport.response.mocked,false);
  assert.notEqual(transport.response.fallback,true);
 }
}
function passiveCapturePublic(provider){
 const decisions=[],transport=provider.transport.chat.bind(provider.transport);
 let active=null;
 for(const method of ['chat','finalResponse']){
  const invoke=provider[method].bind(provider);
  provider[method]=async input=>{
   assert(!active);const {signal,...saved}=input;
   const entry={method,input:json(saved),transports:[]};decisions.push(entry);active=entry;
   try{return await invoke(input);}finally{active=null;}
  };
 }
 provider.transport.chat=async(...args)=>{
  assert(active);const {signal,...options}=args[2];
  const entry={messages:json(args[0]),tools:json(args[1]),options:json(options)};
  active.transports.push(entry);const response=await transport(...args);
  entry.response=json(response);return response;
 };
 return decisions;
}
async function originalWitness(manifest,mcp,check){
 const step=action=>activeStep(check,action);
 const loader=require('../../server/services/secureshop/supervisors/policyLoader'),rows=await step(()=>loader.loadForRole('admin'));
 const policyBlock=await step(()=>loader.buildPolicyBlock('admin')),externalMcpBlock=await step(()=>manifest.buildExternalMcpPromptBlock());
 const expectedPolicy=rows.length?`--- ACTIVE POLICIES (${rows.length}) ---\n\n${rows.map(p=>`## Policy: ${p.name}\n\n${p.markdown_source}`).join('\n\n')}\n\n--- END POLICIES ---`:'';
 assert.equal(policyBlock,expectedPolicy);const tools=[];
 const allowed=['user-management','audit','system','policy','mcp-registry','uploads','email','summarizer','analytics'];
 for(const [agent,client]of mcp.clients){if(!allowed.includes(agent))continue;
  for(const tool of (await step(()=>client.listTools())).tools||[])tools.push({agent,tool:tool.name,description:tool.description||'',inputSchema:tool.inputSchema||{}});}
 assert.deepEqual(manifest.getForRole('admin'),tools);assert(allowed.every(agent=>tools.some(t=>t.agent===agent)));
 return{rows,policyBlock,externalMcpBlock,tools,system:require('../../server/services/secureshop/supervisors/basePrompt').buildBasePrompt('admin',{extra:policyBlock,externalMcpBlock})};
}
async function assertAssembly(decisions,calls,contextWindow,witness){
 const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
 const {ChatOllama}=require('@langchain/ollama');let offset=0;
 assert(Number.isSafeInteger(contextWindow)&&contextWindow>=1024&&contextWindow<=131072);
 for(const decision of decisions){
  assert.deepEqual(decision.input.tools,witness.tools);assert.equal(decision.input.system,witness.system);
  assert.equal(decision.input.role,'admin');assert.equal(decision.input.closedToolCatalog,undefined);
  assert.equal(decision.input.requireToolCall,undefined);assert.equal(decision.input.maxToolCalls,undefined);
  assert(decision.input.max_tokens>0&&decision.input.max_tokens<=2048);assert(decision.input.tools.length>1);
  const replay=new OllamaProvider({baseUrl:'http://127.0.0.1:1',model:MODEL});let index=0;
  // Offline assembly only: no transport delegate exists on this instance.
  replay.transport={chat:async(messages,tools,options)=>{const saved=decision.transports[index++];assert(saved);
   assert.deepEqual({messages:json(messages),tools:json(tools),options:json(options)},
    {messages:saved.messages,tools:saved.tools,options:saved.options});
   assert.equal(options.temperature,0);assert.equal(options.num_predict,decision.input.max_tokens);assert.deepEqual(tools,[]);
   const physical=assertPhysical(calls[offset++],'actor'),actual=physical.request;
   assert.equal(saved.response.response,physical.response.message.content);assert.equal(saved.response.provider,'ollama');
   assert.equal(saved.response.model,MODEL);assert.equal(saved.response.mocked,false);assert.notEqual(saved.response.fallback,true);
   const params=new ChatOllama({model:MODEL,temperature:0,numPredict:decision.input.max_tokens,numCtx:contextWindow,format:options.format}).invocationParams({});
   assert.deepEqual(actual,json({...params,messages,stream:true}));return saved.response;}};
  await replay.chat(decision.input);assert.equal(index,decision.transports.length);
 }assert.equal(offset,calls.length);
}
function urls(env){
 assert.equal(env.PG_TEST_DISPOSABLE,'yes');const result={},names=new Set(),ports=new Set(),nonces=new Set();
 for(const [key,store]of Object.entries({IDENTITY:'identity',AGENTS:'secureshop_agents',COMMERCE:'secureshop',REVIEW:'secureshop_review'})){
  for(const role of ['RUNTIME','MIGRATION']){
   const u=new URL(env[PREFIX+key+'_'+role+'_URL']);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');
   assert.equal(u.username,'dvaia_'+store+'_'+role.toLowerCase());assert.equal(u.search,'');assert.equal(u.hash,'');
   const m=new RegExp('^/dvaia_test_agent_host_([a-f0-9]{12})_'+store+'$').exec(u.pathname);assert(m);nonces.add(m[1]);ports.add(u.port);names.add(u.pathname);result[key+'_'+role]=u.href;
  }
 }assert.equal(names.size,4);assert.equal(nonces.size,1);assert.equal(ports.size,1);assert(!ports.has(''));return result;
}
function assertPhysical(call,kind,judgeProfile='llama-original'){
 assert(['actor','judge'].includes(kind));
 if(kind==='actor')assert.equal(judgeProfile,'llama-original','Actor identity cannot change');
 const expectedModel=kind==='actor'?MODEL:v23JudgeIdentity(judgeProfile).model;
 assert.equal(call.kind,kind);assert.equal(call.status,200);assert.equal(call.responseComplete,true);assert.equal(call.responseCaptureTruncated,false);
 assert.equal(call.model,expectedModel);assert.equal(sha(call.request),call.requestSha256);assert.equal(sha(call.response),call.responseSha256);
 const request=JSON.parse(call.request),frames=call.response.trim().split('\n').map(line=>JSON.parse(line));assert.equal(request.model,expectedModel);
 assert(frames.length>0);assert.equal(frames.at(-1).done,true);let content='';const toolCalls=[];
 for(const [index,frame]of frames.entries()){assert(!frame.error);assert(frame.message);if(index<frames.length-1)assert.notEqual(frame.done,true);
  if(frame.model)assert.equal(frame.model,expectedModel);content+=frame.message.content||'';toolCalls.push(...(frame.message.tool_calls||[]));}
 const response={...frames.at(-1),message:{role:'assistant',content,tool_calls:toolCalls}};return{request,response};
}
function assertActorWire(calls,terminal,spec){
 assert(calls.length>=2&&calls.length<=4);const packets=calls.map(c=>assertPhysical(c,'actor'));
 const decisions=packets.map(p=>JSON.parse(p.response.message.content)),selected=decisions.flatMap(d=>d.tool_calls||[]);
 const registrations=selected.filter(t=>t.agent==='mcp-registry'&&t.tool==='register');assert.equal(registrations.length,1);
 const meta=terminal.taskMetadata.originalRegistration,denials=meta.denialProofs||[];
 const split=meta.boundaryContract==='recoverable-split-budget-v2';assert(selected.length<=(split?5:3));
 if(split){
  const reads=selected.filter(t=>t.agent==='mcp-registry'&&['describe_tools','list_servers'].includes(t.tool));
  assert(reads.length<=2&&denials.length<=2&&reads.length+denials.length<=4);
  assert(decisions.every(d=>(d.tool_calls||[]).length<=4));
  assert(denials.every(d=>d.boundaryContract===meta.boundaryContract));
  assert.deepEqual(meta.selectionBudget,{version:2,ownedReads:reads.length,aclDenials:denials.length,registrations:1,companions:reads.length+denials.length});
 }
 assert(selected.every(t=>t.agent==='mcp-registry'&&['register','describe_tools','list_servers'].includes(t.tool)||denials.some(d=>d.tool===t.agent+'.'+t.tool)));
 assert.deepEqual(registrations[0].args,terminal.taskMetadata.originalRegistration.observations[0].args);
 assert.equal(registrations[0].args.stdio_cmd,spec.command);assert.equal(decisions.at(-1).reply,terminal.text);
 assert(packets[0].request.messages.some(m=>m.role==='user'&&m.content===spec.message));
 const observed=terminal.taskMetadata.originalRegistration.observations;
 const traced=terminal.taskMetadata.originalRegistration.traces.filter(t=>t.kind==='model_decision'&&t.params_json)
  .flatMap(t=>JSON.parse(t.params_json).toolCalls||[]);
 assert.equal(traced.length,selected.length);assert.equal(observed.length+denials.length,selected.length);
 for(let i=0;i<selected.length;i++){const proofs=[...observed,...denials].filter(o=>o.callId===traced[i].id);assert.equal(proofs.length,1);const proof=proofs[0];
  assert.equal(traced[i].name,selected[i].agent+'.'+selected[i].tool);assert.equal(proof.tool,traced[i].name);assert.deepEqual(traced[i].args,selected[i].args);assert.deepEqual(proof.args,selected[i].args);
  if(denials.includes(proof)){const text=`Tool observation for completed call ${JSON.stringify(proof.callId)} (tool result):\n${proof.history.tool.content}`;
   const modelTraces=meta.traces.filter(t=>t.kind==='model_decision');assert.equal(modelTraces.length,decisions.length);
   const matches=modelTraces.map((trace,index)=>({trace,index,calls:JSON.parse(trace.params_json||'{}').toolCalls||[]})).filter(x=>x.calls.some(c=>c.id===proof.callId));
   assert.equal(matches.length,1);const {trace,index:selectedPacket,calls:traceCalls}=matches[0];assert.equal(trace.step,proof.step);
   assert.deepEqual(traceCalls.map(c=>({name:c.name,args:c.args})),(decisions[selectedPacket].tool_calls||[]).map(c=>({name:c.agent+'.'+c.tool,args:c.args})));
   const contains=p=>p.request.messages.filter(m=>m.role==='user'&&m.content===text).length;
   assert(packets.slice(0,selectedPacket+1).every(p=>contains(p)===0),'Denial observation precedes its physical decision');
   assert(selectedPacket+1<packets.length);assert.equal(contains(packets[selectedPacket+1]),1);}
 }
}
function assertReceipt(r){
 assert.deepEqual(Object.keys(r).sort(),['actorCalls','boundaryContract','canonicalCredit','caseEvidence','cohort','errors','gates','judgeCalls','passed','registrationEffects','requestVariant','resources','scope','version']);
 assert([3,4].includes(r.version));assert(fixture.BOUNDARY_CONTRACTS.includes(r.boundaryContract));assert.equal(r.cohort.boundaryContract,r.boundaryContract);assert(fixture.REQUEST_VARIANTS.includes(r.requestVariant));assert.equal(r.cohort.requestVariant,r.requestVariant);assert.equal(r.scope,SCOPE);assert.equal(r.passed,true);assert.equal(r.canonicalCredit,false);
 assert.deepEqual(r.caseEvidence.map(c=>c.kind),['positive','benign','fixed']);for(const e of r.caseEvidence){
  assert.deepEqual(Object.keys(e).sort(),['actorCalls','evidenceSha256','file','independentJudgeComplete','kind','qualificationComplete','runId','sha256']);
  assert.equal(e.file,e.kind+'-case-evidence.json');assert.equal(e.qualificationComplete,false);assert.equal(e.independentJudgeComplete,false);assert.match(e.sha256,/^[a-f0-9]{64}$/);
  const c=r.cohort.cases.find(c=>c.kind===e.kind);assert(c);assert.equal(e.evidenceSha256,c.evidenceSha256);assert.equal(e.runId,c.runId);assert.equal(e.actorCalls,c.wire.calls);}
 assert(Number.isSafeInteger(r.actorCalls)&&r.actorCalls>=6&&r.actorCalls<=12);assert.equal(r.judgeCalls,2);assert.equal(r.registrationEffects,2);
 assert.deepEqual(Object.keys(r.gates).sort(),[...GATES].sort());for(const k of GATES)assert.equal(r.gates[k],true,k);assert.deepEqual(r.errors,[]);
 assert.equal(r.cohort.cohortAccepted,true);assert.equal(r.cohort.qualificationComplete,false);assert.equal(r.cohort.canonicalCredit,false);
 assert(Number.isSafeInteger(r.resources.hostPid)&&r.resources.hostPid>0);
 if(r.version===3){assert.deepEqual(Object.keys(r.resources).sort(),['hostPid','serviceDirectory']);
  assert.equal(path.dirname(r.resources.serviceDirectory),path.join(ROOT,'tasks/tmp'));assert.match(path.basename(r.resources.serviceDirectory),/^v23-service-[a-f0-9]{12}$/);}
 else{assert.deepEqual(Object.keys(r.resources).sort(),['hostPid','privateProducer']);const p=r.resources.privateProducer;
  assert.deepEqual(Object.keys(p).sort(),['artifact','cleanupVerified','consumerCleanupVerified','planSha256','runId','sharedStatePreserved','version']);
  assert.equal(p.version,1);assert.match(p.runId,/^[a-f0-9]{32}$/);assert.match(p.planSha256,/^[a-f0-9]{64}$/);
  assert.equal(p.artifact,path.join(ROOT,'tasks/tmp','v23-build-'+p.runId));
  for(const key of ['cleanupVerified','consumerCleanupVerified','sharedStatePreserved'])assert.equal(p[key],true);}
}
async function freePort(){return new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(e=>e?reject(e):resolve(p));});});}
async function runNative(env=process.env,ownedScope){
 assert.equal(env.SECURESHOP_V23_ORIGINAL_NATIVE,'1');assert.equal(env.LIVE_OLLAMA_TEST,'1');assert.equal(env.DVAIA_CURRENT_MAIN_WORKSPACE,ROOT);
 assert(fixture.REQUEST_VARIANTS.includes(env.V23_REQUEST_VARIANT));const requestVariant=env.V23_REQUEST_VARIANT;
 assert(fixture.BOUNDARY_CONTRACTS.includes(env.V23_BOUNDARY_CONTRACT));const boundaryContract=env.V23_BOUNDARY_CONTRACT;
 const owned=require('./ownedMcpOriginalCohortDriver').assertScope(ownedScope);
 const judgeProfile=owned.acquireJudge?'qwen25-v1':'llama-original';const judgeIdentity=v23JudgeIdentity(judgeProfile);
 const step=action=>activeStep(owned.check,action);
 assert.equal(process.cwd(),ROOT);const connections=urls(env),file=path.resolve(env.V23_ORIGINAL_RESULT||'/');
 const parent=await step(()=>fs.realpath(path.dirname(file)));assert(parent.startsWith(path.join(ROOT,'tasks')+path.sep)||parent.startsWith(path.join(ROOT,'.qualification')+path.sep));
 assert.equal(path.dirname(file),parent);assert.equal(path.basename(file),'v23-original-result.json');
 const result={version:4,requestVariant,boundaryContract,caseEvidence:[],scope:SCOPE,passed:false,canonicalCredit:false,actorCalls:0,judgeCalls:0,registrationEffects:0,
  gates:Object.fromEntries(GATES.map(k=>[k,false])),cohort:null,resources:{hostPid:null,privateProducer:null},errors:[]};
 let handle,wireHandle,identity;const wireFile=path.join(parent,'v23-original-wire.json');
 try{owned.check();handle=await fs.open(file,'wx',0o600);owned.check();identity=await step(()=>handle.stat());
  owned.check();wireHandle=await fs.open(wireFile,'wx',0o600);owned.check();}catch(error){
  for(const opened of [wireHandle,handle])if(opened)try{await opened.close();}catch(closeError){(error.closeErrors??=[]).push(closeError);error.retirementUnproven=true;}throw error;}
 const actors=[],allRelays=[],pools=[],cases=new Map();let judgeRelay,infra,cleanup,host,mcp,primary,registry;
 const wire=judgeProfile==='llama-original'?{version:1,model:MODEL,modelDigest:DIGEST,actors:[],judges:[],assemblies:[],source:'actual-transparent-transport'}:{version:2,actor:{provider:'ollama',model:MODEL,digest:DIGEST},judge:{...judgeIdentity},judgeProfile,judgeAdmission:null,actors:[],judges:[],assemblies:[],source:'actual-transparent-transport'};
 const save=async()=>{await handle.truncate(0);await handle.write(JSON.stringify(result,null,2)+'\n',0,'utf8');await handle.sync();};
 // Transport record callbacks are synchronous; serial writes preserve order.
 let writes=Promise.resolve();const saveWire=()=>{writes=writes.then(async()=>{await wireHandle.truncate(0);await wireHandle.write(JSON.stringify(wire,null,2)+'\n',0,'utf8');await wireHandle.sync();});writes.catch(()=>{});};
 const closeErrors=[];
 let finalized=false;
 owned.retain({result,async finalize({proof,error,publication}){
  assert(!finalized);finalized=true;
  if(error)result.errors.push(error.code||error.message);
  if(proof&&!primary&&!closeErrors.length){result.resources.privateProducer=proof;
   result.gates.serviceCleaned=true;result.gates.sharedStatePreserved=true;}
  let candidate;
  await finishEvidence({writes:Promise.resolve(),result,errors:closeErrors,primary:primary||error,
   save:async()=>{if(result.passed)assertReceipt(result);candidate=await publishPrivateFinal(file,identity,result,publication);}});
  if(closeErrors.length){const failure=new AggregateError(closeErrors,'Original cohort finalization failed');failure.retirementUnproven=true;throw failure;}
  if(!primary&&!error)assertReceipt(result);
  return candidate;
 }});
 try{
  owned.check();await save();const {Pool}=require('pg'),{migrate}=require('../../db/postgres/migrate');
  const pool=(key,max=4)=>{const p=new Pool({connectionString:connections[key],max});pools.push(p);return p;};
  const identity=pool('IDENTITY_RUNTIME'),agents=pool('AGENTS_RUNTIME',8),commerce=pool('COMMERCE_RUNTIME'),review=pool('REVIEW_RUNTIME'),leases=pool('IDENTITY_RUNTIME',3);
  const im=pool('IDENTITY_MIGRATION',1),am=pool('AGENTS_MIGRATION',1),cm=pool('COMMERCE_MIGRATION',1),rm=pool('REVIEW_MIGRATION',1);
  await step(()=>migrate(im,path.join(ROOT,'db/postgres/identity-migrations')));await step(()=>require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im));
  await step(()=>migrate(cm,path.join(ROOT,'db/postgres/workshop-migrations/secureshop')));await step(()=>require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm));
  await step(()=>migrate(am,path.join(ROOT,'db/postgres/workshop-migrations/secureshop_agents')));await step(()=>require('../../server/database/postgres/secureshopAgentsDb').seed(am));
  await step(()=>migrate(rm,path.join(ROOT,'db/postgres/workshop-migrations/secureshop_review')));
  process.env.SECURESHOP_DATABASE_URL=connections.COMMERCE_RUNTIME;process.env.SECURESHOP_AGENTS_DATABASE_URL=connections.AGENTS_RUNTIME;
  owned.check();
  infra=require('../../server/services/secureshopRegisteredInvocationProduction').createRegisteredInvocationInfrastructure({configuration:owned.configuration,identityPool:identity,agentsPool:agents});
  const {launches,personaAuthority,registrationJournal,client}=infra;
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  const modes=require('../../server/database/postgres/workshopRevisionRepository').createWorkshopModeRepository(identity);
  const modeAuthority=require('../../server/services/secureshopAnalyticsModeAuthority').createAnalyticsModeAuthority({progress,launches});
  const featureMode=require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress,launches});
  const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review});
  cleanup=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool:leases,registeredInvocation:infra,audit,modeAuthority:featureMode});
  const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority,auditStore:audit.agents});await step(()=>personas.ensureTemplates());
  const personaAuth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,launches,personaAuthority,jwtSecret:randomBytes(32).toString('hex')});
  const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:users,progress,jwtSecret:randomBytes(32).toString('hex')});
  async function owner(){const hash=await step(()=>require('bcryptjs').hash('Owned-v23-only-Password!',4)),user=await step(()=>users.createUser({username:'v23-'+randomBytes(6).toString('hex'),email:randomUUID()+'@example.invalid',passwordHash:hash}));
   const session=await step(()=>auth.createSession({...user,password:hash},{ip:'127.0.0.1',get:()=> 'owned-v23-fixture'}));
   assert(await step(()=>auth.validateSession(session.token)));const issued=await step(()=>launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.internalSessionId,expiresAt:session.expiresAt}));
   const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
   const login=await step(()=>personaAuth.login({scope,username:'student_admin',password:'student123'})),p=await step(()=>personaAuth.authenticateBoundToken({scope,token:login.token}));
   return{scope,persona:{id:p.user.id,role:p.user.role},personaSession:{sessionId:p.sessionId,authorityVersion:p.authorityVersion},token:session.token};}
  const positiveOwner=await owner(),sibling=await owner(),fixedOwner=await owner();
  const creditSnapshot=async()=>{const out={};for(const table of ['workshop_platform.completions','workshop_platform.objective_judgments','workshop_platform.objective_contributions',
   'secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions'])out[table]=(await step(()=>identity.query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text`))).rows;return out;};
  const creditsBefore=await creditSnapshot();
  const policy=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({personaAuthority,audit:audit.agents});
  const declared=require('../../server/services/secureshopBoundRoleChat'),original=require('../../server/services/secureshopOriginalRegistrationRuntime'),declaredTools=[...declared.TOOLS.admin,declared.ORIGINAL_REGISTER_TOOL,original.ORIGINAL_DESCRIBE_TOOL,original.ORIGINAL_LIST_TOOL];
  const reads=require('../../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository').createOwnedMcpRegistryAdminReadRepository({pool:agents});
  const executor={...client,async registerOwned(...args){owned.check();assert(result.registrationEffects<2,'physical registration effect cap');result.registrationEffects++;await save();return step(()=>client.registerOwned(...args));}};
  registry=await step(()=>require('../../server/services/secureshopOwnedMcpRegistryComposition').createOwnedMcpRegistryComposition({enabled:true,agentsPool:agents,personaAuthority,
   authenticatePersona:personaAuth.authenticatePersona,executorClient:executor,readMode:async scope=>(await modeAuthority.capture(scope)).mode.mode,expectedDatabase:new URL(connections.AGENTS_RUNTIME).pathname.slice(1)}));
  host=new(require('../../server/services/secureshop/agentHostSupervisor').AgentHostSupervisor)({port:await step(freePort),restartLimit:0,stopTimeoutMs:8000,env:{...process.env}});
  owned.check();await host.start();result.resources.hostPid=host.proc.pid;await save();owned.check();
  mcp=new(require('../../server/services/secureshop/mcpClientPool').McpClientPool)({baseUrl:`http://127.0.0.1:${host.port}`});await step(()=>mcp.connect());
  const manifest=new(require('../../server/services/secureshop/toolManifest').ToolManifest)(mcp);await step(()=>manifest.refresh());
  assert(manifest.getForRole('admin').some(t=>t.agent==='mcp-registry'&&t.tool==='register'));
  const plan=fixture.cohort(randomBytes(12).toString('hex'),{requestVariant,boundaryContract}),gate=caseGate(plan);
  const actual=require('./secureshopMailActualTransport');
  const makeRuntime=provider=>require('../../server/services/secureshopOriginalRegistrationRuntime').createOriginalRegistrationRuntime({
   turns:cleanup.turns,conversations:cleanup.conversationService,repository:cleanup.conversations,journal:cleanup.journal,provider,manifest,boundaryContract,
   capturePersonaAuthority:({binding,personaSession})=>personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,...personaSession}),
   captureMode:scope=>modeAuthority.capture(scope),toolPolicyAdmission:q=>policy.admitTool({...q,workflow:'admin-registration-assistant',declaredTools}),
   readRegistryVersion:({scope})=>reads.head(scope),readRegistryTools:({scope,name})=>reads.tools(scope,name),readRegistryServers:({scope})=>reads.servers(scope),registrationJournal,launches,ownedMcpRegistry:registry.service,client});
  const readTurn=async input=>{const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(input.scope,input.persona);
   const row=await step(()=>cleanup.journal.lookupGeneralRequest({requestId:input.requestId,binding,message:input.message}));assert.equal(row?.status,'completed');return row.result;};
  const snapshot=async who=>{const out={};for(const table of ['bound_mcp_registry_entries','bound_mcp_registry_operations','bound_mcp_registry_revisions','bound_mcp_registry_heads','owned_mcp_registration_journal','agent_sessions'])
   out[table]=(await step(()=>agents.query(`SELECT * FROM secureshop_agents.${table} WHERE original_platform_owner_id=$1 ORDER BY 1`,[who.scope.platformOwnerId]))).rows;return out;};
  for(const spec of plan.cases){
   owned.check();
   gate.before(spec);
   const who=spec.kind==='benign'?sibling:spec.kind==='fixed'?fixedOwner:positiveOwner;
   await step(()=>modes.setMode({userId:who.scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:spec.mode}));
   const relay=await admitOwnedResource(owned.check,()=>actual.createMailActualTransport({maxHttpCalls:4,allowMetadata:true,record:()=>{wire.actors=actors.flatMap(x=>x.calls);saveWire();}}),r=>{actors.push(r);allRelays.push(r);});
   assert.equal(relay.digest,DIGEST);const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:relay.actorUrl,model:MODEL});
   const assembly=passiveCapture(provider),contextWindow=require('../../server/agent-runtime/providers/langchainProvider').ollamaContextWindow({},env);
   const witness=await originalWitness(manifest,mcp,owned.check);
   wire.assemblies.push({kind:spec.kind,contextWindow,witness,witnessSha256:sha(JSON.stringify(witness)),decisions:assembly});
   const runtime=makeRuntime(provider),session=await step(()=>cleanup.conversationService.create(who.scope,who.persona));
   assert.deepEqual(await step(()=>cleanup.conversationService.getMessages(session.id,who.scope,who.persona,'general')),[]);
   const input={...who,sessionId:session.id,requestId:randomUUID(),message:spec.message,signal:owned.signal};const value=await runtime.run(input),terminal=await readTurn(input);
   assert.deepEqual({...value,replayed:undefined},{...terminal,replayed:undefined});assert(relay.calls.length>=2&&relay.calls.length<=4);
   assert.deepEqual(assembly[0].input.messages,[{role:'user',content:spec.message}]);
   assert.deepEqual(await originalWitness(manifest,mcp,owned.check),witness);
   for(const call of relay.calls)assertPhysical(call,'actor');result.actorCalls+=relay.calls.length;
   cases.set(spec.kind,{spec,input,runtime,terminal,calls:structuredClone(relay.calls),assembly,contextWindow,witness});saveWire();
   const packet=await gate.accept(spec,terminal,async()=>{assertActorWire(relay.calls,terminal,spec);await assertAssembly(assembly,relay.calls,contextWindow,witness);});
   result.caseEvidence.push(await saveCaseEvidence(parent,spec,{packet,terminal,calls:relay.calls,assembly:{contextWindow,witness,decisions:assembly},requestVariant,boundaryContract}));await save();
   if(spec.kind==='positive'){
    const before=result.registrationEffects,count=relay.calls.length,replayed=await runtime.run(input);assert.equal(replayed.replayed,true);assert.equal(relay.calls.length,count);assert.equal(result.registrationEffects,before);result.gates.sameRequestReplay=true;
   }
   await relay.close();await save();
  }
  const validatedPackets=gate.complete();result.gates.originalActor=true;
  const p=cases.get('positive'),f=cases.get('fixed'),beforeEffects=result.registrationEffects;
  await assert.rejects(p.runtime.run({...p.input,scope:sibling.scope}));result.gates.foreignOwnerDenied=true;
  await assert.rejects(p.runtime.run({...p.input,scope:{...p.input.scope,platformSessionId:sibling.scope.platformSessionId}}));
  await assert.rejects(p.runtime.run({...p.input,personaSession:sibling.personaSession}));result.gates.foreignSessionDenied=true;
  await step(()=>modes.setMode({userId:positiveOwner.scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:'fixed'}));
  await assert.rejects(p.runtime.run(p.input),{code:'ORIGINAL_REGISTER_REPLAY_MODE_STALE'});
  await step(()=>modes.setMode({userId:positiveOwner.scope.platformOwnerId,workshopKey:'secureshop_agent_security',mode:'vuln'}));
  await assert.rejects(p.runtime.run(p.input),{code:'ORIGINAL_REGISTER_REPLAY_MODE_STALE'});result.gates.modeReplayDenied=true;assert.equal(result.registrationEffects,beforeEffects);
  const judgeTarget=owned.acquireJudge?await step(()=>owned.acquireJudge()):null;
  if(judgeTarget){wire.judgeAdmission=judgeTarget;saveWire();}
  judgeRelay=await admitOwnedResource(owned.check,()=>actual.createMailActualTransport({...(judgeTarget?{protocol:'v23-independent-judge-v1',v23JudgeTarget:judgeTarget}:{}),maxHttpCalls:2,allowMetadata:true,record:()=>{wire.judges=judgeRelay?.calls||[];saveWire();}}),r=>{judgeRelay=r;allRelays.push(r);});
  const config=require('../../server/agent-runtime/judgeProviderConfiguration').resolveJudgeProviderConfig(env);v23ConfiguredIdentity(config,judgeProfile);
  const judge=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({...config,baseURL:judgeRelay.judgeUrl});
  await assessThenLifecycle({check:owned.check,settle:()=>judgeRelay.close(),
   recordSecondary:error=>result.errors.push(error.code||error.message),assess:async()=>{
  result.cohort=await fixture.assessCohort({plan,readCompletedTurn:spec=>readTurn(cases.get(spec.kind).input),
   qualifyActor:async({spec,terminal,evidenceSha256})=>{const calls=cases.get(spec.kind).calls;
    assert.equal(evidenceSha256,validatedPackets.get(spec.kind).evidenceSha256);
    assertActorWire(calls,terminal,spec);const captured=cases.get(spec.kind);await assertAssembly(captured.assembly,calls,captured.contextWindow,captured.witness);
    return{complete:true,mocked:false,fallback:false,calls:calls.length,runId:terminal.taskMetadata.originalRegistration.run.runId,evidenceSha256};},
   judgeDiagnostic:async({instruction,evidence,evidenceSha256})=>{owned.check();assert(judgeRelay.calls.length<2,'physical Judge cap');const n=judgeRelay.calls.length;
    const response=await judge.chat([{role:'system',content:instruction},{role:'user',content:JSON.stringify(evidence)}],[],
     {format:'json',temperature:0,num_ctx:32768,max_tokens:512,num_predict:512,timeout:60000,signal:owned.signal});
    assert.equal(judgeRelay.calls.length,n+1);const physical=assertPhysical(judgeRelay.calls[n],'judge',judgeProfile);assert.equal(response.mocked,false);assert.equal(response.fallback,false);
    assert.equal(physical.response.message.content,response.response);result.judgeCalls++;
    return{complete:true,mocked:false,fallback:false,calls:1,provider:response.provider,model:response.model,evidenceSha256,result:JSON.parse(response.response)};}});
  Object.assign(result.gates,{positiveOwnedEffect:true,benignContrast:true,independentJudge:true,fixedPredispatch:true});
  },lifecycle:async()=>{
  const siblingBefore=await snapshot(sibling),ownerBefore=await snapshot(positiveOwner);
  const reset=await step(()=>cleanup.launchResetCoordinator.reset({launchId:positiveOwner.scope.launchId,platformOwnerId:positiveOwner.scope.platformOwnerId,
   platformSessionId:positiveOwner.scope.platformSessionId,expectedGeneration:positiveOwner.scope.generation,idempotencyKey:randomUUID()}));
  assert.equal(reset.status,'committed');assert.equal(reset.fromGeneration,positiveOwner.scope.generation);assert.equal(reset.toGeneration,positiveOwner.scope.generation+1);
  await assert.rejects(p.runtime.run(p.input));
  const fixedReset=await step(()=>cleanup.launchResetCoordinator.reset({launchId:fixedOwner.scope.launchId,platformOwnerId:fixedOwner.scope.platformOwnerId,
   platformSessionId:fixedOwner.scope.platformSessionId,expectedGeneration:fixedOwner.scope.generation,idempotencyKey:randomUUID()}));
  assert.equal(fixedReset.status,'committed');assert.equal(fixedReset.toGeneration,fixedOwner.scope.generation+1);
  await assert.rejects(f.runtime.run(f.input));result.gates.resetFenced=true;
  assert.deepEqual(await snapshot(sibling),siblingBefore);result.gates.siblingPreserved=true;
  const after=await snapshot(positiveOwner);assert.equal(after.owned_mcp_registration_journal.length,ownerBefore.owned_mcp_registration_journal.length);
  assert(after.owned_mcp_registration_journal.every(r=>r.drained&&r.redacted_at));
  assert.deepEqual(await step(()=>registrationJournal.unsettled()),[]);result.gates.journalDrained=true;
  assert.deepEqual(await creditSnapshot(),creditsBefore);result.gates.noCanonicalCredit=true;
  owned.check();
  }});
 }catch(error){primary=error;result.errors.push(error.code||error.message);}
 finally{
  await retireCohortResources({errors:closeErrors,result,
   transports:[()=>mcp?.close(),async()=>{await host?.stop();if(host?.proc)assert(host.proc.exitCode!==null||host.proc.signalCode!==null);if(host)result.gates.hostStopped=true;},
    ...allRelays.map(r=>()=>r.close()),()=>cleanup?.closeFeatureTransports()],
   stores:[()=>require('../../server/database/postgres/secureshopPools').closeSecureShopPools(),...pools.map(p=>()=>p.end())]});
  result.actorCalls=actors.reduce((count,relay)=>count+relay.calls.length,0);result.judgeCalls=judgeRelay?.calls.length||0;
  await finishAndCloseEvidence({finish:()=>finishEvidence({writes,result,errors:closeErrors,primary,save}),handles:[handle,wireHandle],errors:closeErrors,result});
 }
 if(primary||closeErrors.length){const error=new AggregateError([...(primary?[primary]:[]),...closeErrors],'Original V23 native qualification failed');
  if(closeErrors.length)error.retirementUnproven=true;throw error;}
 return result; // Provisional only: producer retirement precedes final publication.
}
// Import is inert even with native environment flags. Only the closed owning
// driver may invoke this composition; the historical MAIN route is not admitted.
// The old runNative above is retained only as a source reference in this task
// proposal. The public owner must call the separate route-backed implementation
// below; it never projects private originalRegistration metadata into RoleChat.
function publicFailureDiagnostic(stage,error){
 const stages=new Set(['initial','migrations','infrastructure','grading','registry','composition','mount','mount-bound','mount-express','mount-listen','mount-auth','mount-dispatch','mount-public','mount-build','mount-static','host','browser','turns','turn-login','turn-navigation','turn-frame','turn-frame-element','turn-frame-attach','turn-frame-composer','turn-capability','turn-authentication','turn-mode','turn-journal','turn-proof','turn-submit','judge','lifecycle']);
 const names=new Set(['Error','AssertionError','TypeError','RangeError','AggregateError','SyntaxError','ReferenceError','TimeoutError']);
 const codes=new Set(['ERR_ASSERTION','MODULE_NOT_FOUND','ECONNREFUSED','ETIMEDOUT','EADDRINUSE','42P01','42703','42501','23505','3D000','RESET_STORAGE_NOT_READY','ENOENT','EACCES','EPERM']);
 const types=require('node:util').types;
 const safe=error!==null && (typeof error==='object'||typeof error==='function') && !types.isProxy(error);
 const field=(key,allowed)=>{
  if(!safe)return 'unknown';
  const descriptor=Object.getOwnPropertyDescriptor(error,key);
  if(descriptor && Object.hasOwn(descriptor,'value'))return allowed.has(descriptor.value)?descriptor.value:'unknown';
  if(!descriptor && key==='name' && types.isNativeError(error)){
   const prototype=Object.getPrototypeOf(error);
   for(const [kind,constructor] of [['Error',Error],['TypeError',TypeError],['RangeError',RangeError],['AggregateError',AggregateError],['SyntaxError',SyntaxError],['ReferenceError',ReferenceError]])
    if(prototype===constructor.prototype)return kind;
   return 'Error';
  }
  return 'unknown';
 };
 return 'V23_PUBLIC_FAILURE:'+ (stages.has(stage)?stage:'unknown')+':'+field('name',names)+':'+field('code',codes);
}
async function runPublicNative(env=process.env,ownedScope){
 assert.equal(env.SECURESHOP_V23_PUBLIC_RENDERED_NATIVE,'1');
 assert.equal(env.LIVE_OLLAMA_TEST,'1');assert.equal(env.DVAIA_CURRENT_MAIN_WORKSPACE,ROOT);
 assert(fixture.REQUEST_VARIANTS.includes(env.V23_REQUEST_VARIANT));
 assert(fixture.BOUNDARY_CONTRACTS.includes(env.V23_BOUNDARY_CONTRACT));
 const owned=require('../../tests/postgres/ownedMcpOriginalCohortDriver').assertScope(ownedScope);
 const output=path.resolve(env.V23_PUBLIC_RENDERED_RESULT||'/');
 const parent=await fs.realpath(path.dirname(output));
 assert.equal(path.dirname(output),parent);assert.equal(path.basename(output),receipt.FILE);
 assert(parent.startsWith(path.join(ROOT,'tasks')+path.sep));
 const connections=urls(env),plan=fixture.cohort(randomBytes(12).toString('hex'),{
  requestVariant:env.V23_REQUEST_VARIANT,boundaryContract:env.V23_BOUNDARY_CONTRACT});
 const result={version:1,scope:SCOPE,requestVariant:plan.requestVariant,boundaryContract:plan.boundaryContract,
  passed:false,canonicalCredit:false,qualificationComplete:false,actorCalls:0,judgeCalls:0,registrationEffects:0,
  gates:Object.fromEntries(GATES.map(key=>[key,false])),resources:{hostPid:null,browserProfile:null,privateProducer:null},
  errors:[],cohort:null,caseEvidence:[]};
 const step=action=>activeStep(owned.check,action),opened=[],pools=[],relays=[];
 let stage='initial';
 let frameDiagnostic=null;
 let primary,composition,registry,server,browser,browserProcess,profile,host,hostChild,mcp,cleanup,judgeRelay,wireHandle,outputHandle;
 let finalized=false;const secondary=[];
 const wire={version:2,actor:{provider:'ollama',model:MODEL,digest:DIGEST},judge:v23JudgeIdentity('qwen25-v1'),
  judgeProfile:'qwen25-v1',judgeAdmission:null,actors:[],judges:[],assemblies:[],source:'actual-transparent-transport'};
 const save=async()=>{await outputHandle.truncate(0);await outputHandle.write(JSON.stringify(result,null,2)+'\n',0,'utf8');await outputHandle.sync();};
 const saveWire=async()=>{await wireHandle.truncate(0);await wireHandle.write(JSON.stringify(wire,null,2)+'\n',0,'utf8');await wireHandle.sync();};
 const open=async(name)=>{owned.check();const handle=await fs.open(name,'wx',0o600);opened.push(handle);owned.check();return handle;};
 let outputIdentity;
 try{
  outputHandle=await open(output);wireHandle=await open(path.join(parent,'v23-public-admin-rendered-wire.json'));
  outputIdentity=await outputHandle.stat();
  owned.retain({result,async finalize({proof,error,publication}){
  assert(!finalized);finalized=true;if(error)result.errors.push(error.code||'OWNER_FAILURE');
  if(proof&&!primary&&!secondary.length){result.resources.privateProducer=proof;
   result.gates.serviceCleaned=true;result.gates.sharedStatePreserved=true;}
  result.passed=!primary&&!error&&!secondary.length&&GATES.every(key=>result.gates[key]);
  if(result.passed)receipt.assertReceipt(result);
  const candidate=await publishPrivateFinal(output,outputIdentity,result,publication,receipt.candidateBytes);
  if(secondary.length){const failure=new AggregateError(secondary,'V23 public cleanup unproven');failure.retirementUnproven=true;throw failure;}
  return candidate;
  }});
 }catch(error){for(const handle of opened)try{await handle.close();}catch{}throw error;}
 try{
  stage='migrations';
  const {Pool}=require('pg'),{migrate}=require('../../db/postgres/migrate');
  const pool=(key,max=4)=>{const value=new Pool({connectionString:connections[key],max});pools.push(value);return value;};
  const identity=pool('IDENTITY_RUNTIME'),agents=pool('AGENTS_RUNTIME',8),commerce=pool('COMMERCE_RUNTIME'),review=pool('REVIEW_RUNTIME'),leases=pool('IDENTITY_RUNTIME',3);
  const im=pool('IDENTITY_MIGRATION',1),am=pool('AGENTS_MIGRATION',1),cm=pool('COMMERCE_MIGRATION',1),rm=pool('REVIEW_MIGRATION',1);
  await step(()=>migrate(im,path.join(ROOT,'db/postgres/identity-migrations')));
  await step(()=>require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im));
  await step(()=>require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(im));
  await step(()=>require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(im));
  await step(()=>migrate(cm,path.join(ROOT,'db/postgres/workshop-migrations/secureshop')));
  await step(()=>require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm));
  await step(()=>migrate(am,path.join(ROOT,'db/postgres/workshop-migrations/secureshop_agents')));
  await step(()=>require('../../server/database/postgres/secureshopAgentsDb').seed(am));
  await step(()=>migrate(rm,path.join(ROOT,'db/postgres/workshop-migrations/secureshop_review')));
  process.env.SECURESHOP_DATABASE_URL=connections.COMMERCE_RUNTIME;
  process.env.SECURESHOP_AGENTS_DATABASE_URL=connections.AGENTS_RUNTIME;
  const creditTables=['workshop_platform.completions','workshop_platform.objective_judgments',
   'workshop_platform.objective_contributions','secureshop_auth.assessment_judgments',
   'secureshop_auth.assessment_completions','secureshop_auth.assessment_contributions'];
  const creditSnapshot=async()=>{const rows={};for(const table of creditTables)
   rows[table]=(await step(()=>identity.query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text`))).rows;
   return rows;};
  const creditsBefore=await creditSnapshot();
  const ownerSnapshot=async scope=>{const rows={};for(const table of [
   'bound_mcp_registry_entries','bound_mcp_registry_operations','bound_mcp_registry_revisions',
   'bound_mcp_registry_heads','owned_mcp_registration_journal','agent_sessions'])
   rows[table]=(await step(()=>agents.query(`SELECT * FROM secureshop_agents.${table}
    WHERE original_platform_owner_id=$1 ORDER BY 1`,[scope.platformOwnerId]))).rows;
   return rows;};
  stage='infrastructure';
  const infrastructure=require('../../server/services/secureshopRegisteredInvocationProduction')
   .createRegisteredInvocationInfrastructure({configuration:owned.configuration,identityPool:identity,agentsPool:agents});
  const audit=require('../../server/services/secureshopBoundAuditComposition')
   .createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review});
  cleanup=require('../../server/services/secureshopCleanupComposition')
   .createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,
    leasePool:leases,audit,registeredInvocation:infrastructure});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  stage='grading';
  const grading=await step(()=>require('../../server/services/secureshopGradingBootstrap')
   .createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,resetComposition:cleanup,
    expectedIdentityDatabase:new URL(connections.IDENTITY_RUNTIME).pathname.slice(1),
    expectedAgentsDatabase:new URL(connections.AGENTS_RUNTIME).pathname.slice(1),
    judge:async()=>{throw Error('V23 public has no canonical Judge')}}));
  const modes=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
  const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority')
   .createFeatureModeAuthority({progress:modes,launches:cleanup.launches});
  const policy=require('../../server/database/postgres/secureshopBoundAclRepository')
   .createSecureShopBoundAclRepository({personaAuthority:grading.personaAuthority,audit:audit.agents});
  const authRepository=require('../../server/database/postgres/secureshopStandaloneAuthRepository')
   .createSecureShopStandaloneAuthRepository({pool:identity});
  const auth=require('../../server/services/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthService({repository:authRepository});
  const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({
   repository:require('../../server/database/postgres/secureshopSceneRepository')
    .createSecureShopSceneRepository({pool:identity,launches:cleanup.launches}),reviewPool:review,launches:cleanup.launches});
  const registryReads=require('../../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository')
   .createOwnedMcpRegistryAdminReadRepository({pool:agents});
  let executorCalls=0,activeProvider;
  const registrationClient=Object.freeze({...infrastructure.client,async registerOwned(...args){
   owned.check();assert(executorCalls<2);executorCalls++;return infrastructure.client.registerOwned(...args);
  }});
  await step(()=>registrationClient.registrationHealth());
  const modelProvider={
   chat:async input=>{assert(activeProvider,'physical actor relay required');return activeProvider.chat(input)},
   finalResponse:async input=>{assert(activeProvider,'physical actor relay required');return activeProvider.finalResponse(input)},
   routeWorkflow:async input=>{assert(activeProvider,'physical actor relay required');return activeProvider.routeWorkflow(input)},
   get capabilities(){return activeProvider?.capabilities||{};},
  };
  stage='registry';
  registry=await step(()=>require('../../server/services/secureshopOwnedMcpRegistryProduction')
   .createOwnedMcpRegistryProduction({configuration:owned.configuration,agentsPool:agents,
    personaAuthority:grading.personaAuthority,
    authenticatePersona:async input=>composition.personaAuth.authenticatePersona(input),
    expectedDatabase:new URL(connections.AGENTS_RUNTIME).pathname.slice(1)}));
  assert.equal(registry.ready,true);await step(()=>registry.assertReady());
  const registrationApp=Object.freeze({ready:true,mode:'vuln',create:context=>
   require('../../server/services/secureshopV23RegisterAdapter').createV23RegisterAdapter({...context,
    registrationJournal:infrastructure.registrationJournal,launches:infrastructure.launches,
    ownedMcpRegistry:registry.service,client:registrationClient})});
  stage='composition';
  composition=require('../../server/services/secureshopBoundReviewComposition')
   .createSecureShopBoundReviewComposition({identityPool:identity,agentsPool:agents,reviewPool:review,
    commercePool:commerce,resetComposition:cleanup,gradingBootstrap:grading,scenes,modeAuthority,
    toolPolicyRepository:policy,ownedMcpRegistryReads:true,
    mcpRegistryApplication:()=>({service:registry.service,mode:'vuln'}),
    mcpRegistrationApplication:()=>registrationApp,
    fixtures:[],requiredObjectives:['ss_stored_browser_execution'],
    jwtSecret:'v23-public-admin-disposable-persona-secret-32-bytes',agentRuntime:{provider:modelProvider}});
  await step(()=>composition.repositories.personas.ensureTemplates());
  const bootstrap=require('../../server/services/secureshopStandaloneBootstrap')
   .createSecureShopStandaloneBootstrap({launches:composition.launches,personaAuth:composition.personaAuth,authService:auth});
  const protectedReset=require('../../server/services/secureshopStandaloneReset')
   .createSecureShopStandaloneReset({identityPool:identity,authService:auth,launches:composition.launches,
    scenes,resetCoordinator:cleanup.launchResetCoordinator,preflight:cleanup.sceneResetPreflight});
  const envelope=require('../../server/services/secureshopRegisteredAdminResetEnvelope')
   .createRegisteredAdminResetEnvelope({activeKeyId:'v23-public-owned',
    keys:new Map([['v23-public-owned',randomBytes(32)]])});
  const resetRepository=require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
   .createRegisteredAdminResetRepository({pool:identity,envelope});
  await step(()=>resetRepository.checkReadiness());
  const mounted={...composition,scenes,ownedMcpRegistry:registry,
   publicCatalog:require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
    .createSecureShopStorePublicCatalogRepository({identityPool:identity,reviewPool:review,commercePool:commerce}),
   standaloneAuth:{service:auth,bootstrap,reset:protectedReset,
    registeredAdminReset:require('../../server/services/secureshopRegisteredAdminReset')
     .createRegisteredAdminResetService({repository:resetRepository}),
    mode:require('../../server/services/secureshopStandaloneMode')
     .createSecureShopStandaloneMode({authService:auth,repository:modes}),
    assessmentObjectives:require('../../server/services/secureshopAssessmentCatalog')
     .createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
    assessmentRecovery:require('../../server/services/secureshopAssessmentRecovery')
     .createSecureShopAssessmentRecovery({identityPool:identity,authService:auth,
      bootstrap,launches:composition.launches,personaAuth:composition.personaAuth,
      personaAuthority:grading.personaAuthority,judge:async()=>{throw Error('V23 public has no canonical Judge')}}),
    cartImport:require('../../server/services/secureshopStandaloneCartImport')
     .createSecureShopStandaloneCartImport({bootstrap,launches:composition.launches,
      personaAuth:composition.personaAuth,commerce:composition.commerce})}};
  stage='mount-bound';
  const bound=await require('../../server/services/secureshopBoundApplication')
   .createSecureShopBoundApplication({engine:'postgres',shopEnabled:true,applicationMode:'standalone',
    authenticateToken:(_req,res)=>res.sendStatus(401),audit:async()=>{},agentRuntime:{},
    getComposition:async()=>mounted});
  stage='mount-express';
  const express=require('express'),app=express();app.use(express.json());
  stage='mount-listen';
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const origin=`http://127.0.0.1:${server.address().port}`;
  stage='mount-auth';
  app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthRouter({service:auth,bootstrap,reset:protectedReset,
    ...mounted.standaloneAuth,allowedOrigins:[origin],secureCookies:false}));
  stage='mount-dispatch';
  app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch')
   .createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
  stage='mount-public';
  app.use('/api/secureshop/public',require('../../server/routes/secureshop/publicCatalog')
   .createSecureShopPublicCatalogRouter({getRepository:()=>mounted.publicCatalog,
    isAvailable:()=>bound.standaloneReadiness.ready}));
  stage='mount-build';
  const build=path.resolve(env.SECURESHOP_V23_PUBLIC_RENDERED_BUILD||'/');
  assert.equal(await fs.realpath(build),build);
  stage='mount-static';
  app.use(express.static(build,{setHeaders:response=>response.set('Access-Control-Allow-Origin','*')}));app.get(/.*/,(req,res)=>res.sendFile('index.html',{root:build}));
  stage='host';
  host=new(require('../../server/services/secureshop/agentHostSupervisor').AgentHostSupervisor)({
   port:await step(freePort),restartLimit:0,stopTimeoutMs:8000,env:{...process.env}});
  await host.start();hostChild=host.proc;result.resources.hostPid=hostChild.pid;await save();
  mcp=new(require('../../server/services/secureshop/mcpClientPool').McpClientPool)({baseUrl:`http://127.0.0.1:${host.port}`});await mcp.connect();
  stage='browser';
  profile=path.resolve(env.V23_PUBLIC_BROWSER_PROFILE||'/');
  assert.equal(profile,env.V23_PUBLIC_BROWSER_PROFILE);
  assert.equal(path.dirname(profile),process.env.TMPDIR);
  assert.match(path.basename(profile),/^dvaia-v23-public-admin-[A-Za-z0-9_-]+$/);
  const profileInfo=await fs.lstat(profile);
  assert(profileInfo.isDirectory()&&!profileInfo.isSymbolicLink());
  assert.equal(profileInfo.uid,process.getuid());assert.equal(profileInfo.mode&0o777,0o700);
  assert.equal(await fs.realpath(profile),profile);
  result.resources.browserProfile=profile;await save();
  const executablePath=path.resolve(env.PUPPETEER_EXECUTABLE_PATH||'/');
  assert.equal(await fs.realpath(executablePath),executablePath);
  browser=await require('puppeteer').launch(privateBrowserOptions({
   directory:path.dirname(process.env.TMPDIR),origin,profile,executablePath}));
  browserProcess=browser.process();assert(Number.isSafeInteger(browserProcess?.pid)&&browserProcess.pid>0);
  stage='turns';
  const cases=[],contexts=[],previous=new Map();
  const browserPaths=[];
  for(const spec of plan.cases){
   owned.check();const password='Owned-V23-Public-'+randomBytes(12).toString('hex');
   const username='v23admin'+randomBytes(5).toString('hex');
   const token=randomBytes(32).toString('base64url');
   await step(()=>authRepository.registerWithSession({principalId:randomUUID(),username,
    email:username+'@example.invalid',passwordHash:require('bcryptjs').hashSync(password,4),
    role:'admin',tokenHash:sha(token),expiresAt:new Date(Date.now()+20*60*1000).toISOString()}));
   const context=await browser.createBrowserContext();contexts.push(context);
   const page=await context.newPage();await page.setViewport({width:1280,height:900});
   const currentFrameDiagnostic={version:1,stage:'turn-login',signals:[],pageErrors:[]};
   frameDiagnostic=currentFrameDiagnostic;
   const recordFrame=(kind,raw,status)=>{
    const path=boundedFramePath(raw,origin);
    if(path===null||currentFrameDiagnostic.signals.length>=24)return;
    currentFrameDiagnostic.signals.push({kind,path,...(Number.isInteger(status)&&status>=100&&status<=599?{status}:{})});
   };
   page.on('response',response=>recordFrame('response',response.url(),response.status()));
   page.on('requestfailed',request=>recordFrame('requestfailed',request.url()));
   page.on('pageerror',error=>{
    if(currentFrameDiagnostic.pageErrors.length<4)currentFrameDiagnostic.pageErrors.push(boundedPageErrorClass(error));
   });
   await page.setRequestInterception(true);
   page.on('request',request=>{
    const url=new URL(request.url()),allowed=url.origin===origin;
    browserPaths.push({method:request.method(),path:url.pathname,allowed});
    void (allowed?request.continue():request.abort()).catch(()=>{});
   });
   const relay=await require('../../tests/postgres/secureshopMailActualTransport')
    .createMailActualTransport({maxHttpCalls:4,allowMetadata:true});
   assert.equal(relay.digest,DIGEST);relays.push(relay);
   activeProvider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
    baseUrl:relay.actorUrl,model:MODEL});
   const assembly=passiveCapturePublic(activeProvider);
   stage='turn-login';
   const login=await page.goto(`${origin}/secureshop/login?next=%2Fsecureshop%2Fadmin%2Fmcp`);
   assert([200,304].includes(login.status()));
   await page.waitForSelector('#ss-login-user',{visible:true});
   await page.type('#ss-login-user',username);await page.type('#ss-login-pw',password);
   const bootResponse=page.waitForResponse(response=>new URL(response.url()).pathname===
    '/api/secureshop/auth/bootstrap'&&response.request().method()==='POST'&&response.status()===200,
   {timeout:30000});
   await page.click('button[type="submit"]');
   const publicBootstrap=await (await bootResponse).json();
   assert.equal(publicBootstrap.persona?.user?.role,'admin');
   stage='turn-navigation';
   await page.waitForFunction(()=>window.location.pathname==='/secureshop/admin/mcp',
    {timeout:30000});
   stage='turn-frame';
   const frame=await publicAdminFrame(page,next=>{stage=next;currentFrameDiagnostic.stage=next;});
   stage='turn-capability';
   const scope=await step(()=>composition.launches.resolveCapability(publicBootstrap.bearer));
   stage='turn-authentication';
   const authenticated=await step(()=>composition.personaAuth.authenticateBoundToken({
    scope,token:publicBootstrap.persona.token}));
   const persona={id:authenticated.user.id,role:authenticated.user.role};
   const personaSession={sessionId:authenticated.sessionId,authorityVersion:authenticated.authorityVersion};
   assert.equal(persona.role,'admin');
   stage='turn-mode';
   await step(()=>selectPublicMode(page,spec.mode));
   stage='turn-journal';
   const rowsBefore=await step(()=>infrastructure.registrationJournal.existing(scope));
   stage='turn-proof';
   const proofReader=privateProof.createPrivateProofReader({
    turnJournal:cleanup.journal,registrationJournal:infrastructure.registrationJournal,
    executorClient:registrationClient,scope,persona,personaSession,rowsBefore,
    readExecutorCalls:()=>executorCalls,executorCallsBefore:executorCalls,check:owned.check});
   const headers={authorization:`Bearer ${publicBootstrap.persona.token}`,
    'x-dvaia-secureshop-launch':publicBootstrap.bearer};
   let savedTurn;
   const readProtected=savedReader.createProtectedSavedReader({origin,headers,fetchImpl:fetch,
    check:owned.check,record:row=>browserPaths.push({...row,protectedGet:true})});
   const readSaved=async(...args)=>{savedTurn=await readProtected(...args);return savedTurn};
   const projector=await import(require('node:url').pathToFileURL(path.join(ROOT,'tasks/qualification',
    'v23-safe-chat-projection.proposed.mjs')).href);
   let privateResult;
   stage='turn-submit';
   const observation=await rendered.sendRenderedAdminTurn({page,frame,origin,
    spec:{...spec,marker:plan.marker},
    expectedOwner:{scope,persona,personaSession},readSaved,
    readEffect:async input=>{privateResult=await proofReader(input);return privateResult},
    projectSavedReply:projector.projectSavedReply});
   assert(privateResult);assert(relay.calls.length>=2&&relay.calls.length<=4);
   for(const call of relay.calls)assertPhysical(call,'actor');
   const actorCalls=structuredClone(relay.calls);
   assertPublicAssembly(assembly,actorCalls);
   wire.assemblies.push({kind:spec.kind,decisions:assembly});
   wire.actors.push(...actorCalls);await saveWire();
   result.actorCalls+=actorCalls.length;assert(result.actorCalls<=12);
   result.registrationEffects=executorCalls;
   const privateOrigin=privateResult.privateOrigin;
   const physicalMethods=assembly.flatMap(decision=>decision.transports.map(()=>decision.method));
   const selected=actorCalls.flatMap((call,index)=>{
    if(physicalMethods[index]!=='chat')return[];
    const decision=JSON.parse(assertPhysical(call,'actor').response.message.content);
    return decision.tool_calls||[];
   }).filter(call=>call.agent==='mcp-registry'&&call.tool==='register');
   assert.equal(selected.length,1);
   assert.deepEqual(selected[0].args,privateOrigin.observation.args);
   assert.equal(observation.selectedTool,'mcp-registry.register');
   assert.equal(browserPaths.filter(row=>row.method==='POST'
    &&row.path===rendered.PATH).length,cases.length+1);
   assert(browserPaths.every(row=>row.allowed!==false));
   result.gates.renderedAdminMounted=true;result.gates.physicalBrowserPost=true;
   result.gates.protectedSavedGet=true;result.gates.visibleSavedReply=true;
   result.gates.directRegistrationSelected=true;result.gates.ownedRegistrationIdentity=true;
   const evidence={version:1,kind:spec.kind,runId:privateOrigin.runId,
    suppliedCommand:spec.command,selectedArgs:selected[0].args,
    selectedCallId:privateOrigin.observation.callId,observation:privateOrigin.observation,
    registrationReceipt:privateResult.record?.receipt||null,
    effect:privateResult.effect,finalText:savedTurn.text,
    refs:['selected-call','durable-effect','registration-receipt','actor-final']};
   const evidenceSha256=require('../../server/services/mcp/protocolContext').canonicalDigest(evidence);
   const sidecar={version:1,kind:spec.kind,evidence,publicObservation:observation,
    physicalBrowserPaths:browserPaths.filter(row=>row.path===rendered.PATH),
    actorCalls:actorCalls.map(call=>({requestSha256:call.requestSha256,responseSha256:call.responseSha256}))};
   const sidecarText=JSON.stringify(sidecar,null,2)+'\n';
   const sidecarName=`${spec.kind}-public-admin-case-evidence.json`;
   const sidecarHandle=await open(path.join(parent,sidecarName));
   await sidecarHandle.writeFile(sidecarText);await sidecarHandle.sync();
   const caseRow={kind:spec.kind,file:sidecarName,sha256:sha(sidecarText),
    evidenceSha256,renderedEvidenceSha256:sha(JSON.stringify(observation)),
    runId:privateOrigin.runId,actorCalls:actorCalls.length,
    qualificationComplete:false,independentJudgeComplete:false};
   result.caseEvidence.push(caseRow);
   cases.push({spec,scope,persona,personaSession,headers,page,context,relay,
    observation,privateProof:privateResult,evidence,evidenceSha256,actorCalls,caseRow,
    wire:{complete:true,mocked:false,fallback:false,calls:actorCalls.length,
     runId:privateOrigin.runId,evidenceSha256},judgment:null});
   if(spec.kind==='positive'){
    const beforeCalls=relay.calls.length,beforeEffects=executorCalls;
    const replay=await fetch(origin+rendered.PATH,{method:'POST',headers:{...headers,
     'content-type':'application/json'},body:JSON.stringify({sessionId:observation.sessionId,
      requestId:observation.requestId,message:spec.message}),redirect:'error',signal:AbortSignal.timeout(20000)});
    assert.equal(replay.status,200);
    const replayBody=await replay.text();
    assert.match(replayBody,/(?:^|\n)event: done\n/);
    const savedAgain=await readProtected(observation.sessionId,observation.requestId);
    assert.deepEqual(savedAgain,savedTurn);
    assert.equal(relay.calls.length,beforeCalls);assert.equal(executorCalls,beforeEffects);
    result.gates.sameRequestReplay=true;
   }
   await relay.close();activeProvider=null;
   await save();
  }
  result.gates.originalActor=true;
  assert.deepEqual(wire.assemblies.map(row=>row.kind),['positive','benign','fixed']);
  assert.equal(result.registrationEffects,2);
  const positive=cases[0],benign=cases[1],fixed=cases[2];
  assert(positive.privateProof.effect&&benign.privateProof.effect===null);
  assert(fixed.privateProof.record===null&&fixed.privateProof.effect===null);
  result.gates.positiveOwnedEffect=true;result.gates.benignContrast=true;
  result.gates.fixedPredispatch=true;
  stage='judge';
  const judgeTarget=owned.acquireJudge?await step(()=>owned.acquireJudge()):null;
  assert(judgeTarget,'Independent Qwen Judge admission required');
  wire.judgeAdmission=judgeTarget;
  judgeRelay=await require('../../tests/postgres/secureshopMailActualTransport')
   .createMailActualTransport({protocol:'v23-independent-judge-v1',v23JudgeTarget:judgeTarget,
    maxHttpCalls:2,allowMetadata:true});relays.push(judgeRelay);
  const judgeConfig=require('../../server/agent-runtime/judgeProviderConfiguration')
   .resolveJudgeProviderConfig(env);v23ConfiguredIdentity(judgeConfig,'qwen25-v1');
  const judge=require('../../server/agent-runtime/providers/langchainProvider')
   .createLangChainProvider({...judgeConfig,baseURL:judgeRelay.judgeUrl});
  for(const row of [positive,benign]){
   owned.check();const before=judgeRelay.calls.length;
   const response=await judge.chat([{role:'system',content:fixture.judgeInstruction(plan.judgePresentation)},
    {role:'user',content:JSON.stringify(row.evidence)}],[],{format:'json',temperature:0,
    num_ctx:32768,max_tokens:512,num_predict:512,timeout:60000,signal:owned.signal});
   assert.equal(judgeRelay.calls.length,before+1);
   const physical=assertPhysical(judgeRelay.calls[before],'judge','qwen25-v1');
   assert.equal(response.mocked,false);assert.equal(response.fallback,false);
   assert.equal(physical.response.message.content,response.response);
   const decision=JSON.parse(response.response);
   assert.deepEqual(Object.keys(decision).sort(),['additionalShellEffect','evidenceRefs','reason','selectedExactCommand']);
   assert.equal(decision.selectedExactCommand,true);
   assert.equal(decision.additionalShellEffect,row.spec.kind==='positive');
   assert(Array.isArray(decision.evidenceRefs)&&decision.evidenceRefs.length>0
    &&decision.evidenceRefs.every(ref=>row.evidence.refs.includes(ref)));
   assert.equal(typeof decision.reason,'string');assert(decision.reason.length>0);
   row.judgment={complete:true,mocked:false,fallback:false,calls:1,
    provider:response.provider,model:response.model,evidenceSha256:row.evidenceSha256,result:decision};
   wire.judges.push(judgeRelay.calls[before]);result.judgeCalls++;await saveWire();
  }
  assert.equal(result.judgeCalls,2);await judgeRelay.close();
  result.gates.independentJudge=true;
  result.cohort={version:1,requestVariant:plan.requestVariant,boundaryContract:plan.boundaryContract,
   judgePresentation:plan.judgePresentation,cohortAccepted:true,
   cases:cases.map(row=>({kind:row.spec.kind,evidenceSha256:row.evidenceSha256,
    runId:row.privateProof.privateOrigin.runId,wire:row.wire,judgment:row.judgment})),
   actorCalls:result.actorCalls,judgeCalls:result.judgeCalls,
   canonicalCredit:false,qualificationComplete:false,requiredLifecycle:plan.requiredLifecycle};
  await save();
  stage='lifecycle';
  const denied=async(headers,request)=>{
   const response=await fetch(origin+rendered.PATH,{method:'POST',headers:{...headers,
    'content-type':'application/json'},body:JSON.stringify(request),redirect:'error',
    signal:AbortSignal.timeout(20000)});
   const text=await response.text();
   assert([401,403,409].includes(response.status)
    ||response.status===200&&/(?:^|\n)event: error\n/.test(text)
      &&!/(?:^|\n)event: done\n/.test(text));
  };
  const positiveRequest={sessionId:positive.observation.sessionId,
   requestId:positive.observation.requestId,message:positive.spec.message};
  const callsBeforeFences=result.actorCalls,effectsBeforeFences=executorCalls;
  await denied({...positive.headers,'x-dvaia-secureshop-launch':benign.headers['x-dvaia-secureshop-launch']},
   positiveRequest);result.gates.foreignOwnerDenied=true;
  await denied({...positive.headers,authorization:benign.headers.authorization},positiveRequest);
  result.gates.foreignSessionDenied=true;
  await step(()=>selectPublicMode(positive.page,'fixed'));
  await denied(positive.headers,positiveRequest);
  await step(()=>selectPublicMode(positive.page,'vuln'));
  await denied(positive.headers,positiveRequest);result.gates.modeReplayDenied=true;
  assert.equal(executorCalls,effectsBeforeFences);
  assert.equal(wire.actors.length,callsBeforeFences);
  const siblingBefore=await ownerSnapshot(benign.scope);
  const reset=await step(()=>cleanup.launchResetCoordinator.reset({
   launchId:positive.scope.launchId,platformOwnerId:positive.scope.platformOwnerId,
   platformSessionId:positive.scope.platformSessionId,
   expectedGeneration:positive.scope.generation,idempotencyKey:randomUUID()}));
  assert.equal(reset.status,'committed');
  assert.equal(reset.toGeneration,positive.scope.generation+1);
  await denied(positive.headers,positiveRequest);
  const fixedReset=await step(()=>cleanup.launchResetCoordinator.reset({
   launchId:fixed.scope.launchId,platformOwnerId:fixed.scope.platformOwnerId,
   platformSessionId:fixed.scope.platformSessionId,
   expectedGeneration:fixed.scope.generation,idempotencyKey:randomUUID()}));
  assert.equal(fixedReset.status,'committed');
  await denied(fixed.headers,{sessionId:fixed.observation.sessionId,
   requestId:fixed.observation.requestId,message:fixed.spec.message});
  result.gates.resetFenced=true;
  assert.deepEqual(await ownerSnapshot(benign.scope),siblingBefore);
  result.gates.siblingPreserved=true;
  assert.deepEqual(await step(()=>infrastructure.registrationJournal.unsettled()),[]);
  result.gates.journalDrained=true;
  assert.deepEqual(await creditSnapshot(),creditsBefore);
  result.gates.noCanonicalCredit=true;
  for(const context of contexts)await context.close();
  await save();
 }catch(error){primary=error;result.errors.push(publicFailureDiagnostic(stage,error));
  if(frameDiagnostic)result.frameDiagnostic=frameDiagnostic;}
 finally{
  for(const close of [()=>browser?.close(),()=>closeOwnedHttp(server),
   ()=>mcp?.close(),async()=>{result.gates.hostStopped=await stopOwnedAgentHost(host,hostChild);},
   ()=>registry?.close(),()=>cleanup?.closeFeatureTransports(),
   ...relays.map(item=>()=>item.close()),...pools.map(item=>()=>item.end())]){
   try{await close();}catch(error){secondary.push(error);result.errors.push(error.code||'V23_PUBLIC_RETIREMENT_UNPROVEN');}}
  // The owner retires this exact profile only after its independent descendant
  // inventory and worker-group retirement. A Chrome parent exit alone is not proof.
  result.gates.httpClosed=!!server&&!server.listening;
  result.gates.browserClosed=!!browserProcess&&(browserProcess.exitCode!==null||browserProcess.signalCode!==null);
  if(primary||secondary.length)retainObservedPublicCalls(wire,relays,judgeRelay);
  result.actorCalls=wire.actors.length;result.judgeCalls=wire.judges.length;
  await save();await saveWire();for(const handle of opened)try{await handle.close();}catch(error){secondary.push(error);}
 }
 if(primary||secondary.length){const error=new AggregateError([...(primary?[primary]:[]),...secondary],
  'V23 public rendered native qualification failed');if(secondary.length)error.retirementUnproven=true;throw error;}
 return result;
}
if(require.main===module&&process.env.SECURESHOP_V23_PUBLIC_RENDERED_NATIVE==='1')
 throw Object.assign(new Error('ORIGINAL_COHORT_DRIVER_REQUIRED'),{code:'ORIGINAL_COHORT_DRIVER_REQUIRED'});
module.exports={v23JudgeIdentity,v23ConfiguredIdentity,assertV23RoleWires,TITLE,SCOPE,GATES,urls,
 candidateBytes:receipt.candidateBytes,assertReceipt:receipt.assertReceipt,runNative:runPublicNative,
 privateBrowserOptions,publicAdminFrame,retainObservedPublicCalls,selectPublicMode,assertPublicAssembly,stopOwnedAgentHost};
