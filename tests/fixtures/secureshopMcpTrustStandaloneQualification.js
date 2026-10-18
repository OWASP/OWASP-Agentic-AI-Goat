'use strict';

// D16 integration contract (qualification only; no allocation or installation):
// root owns four initialized disposable stores, current standalone composition,
// canonical policies, two independently authenticated admin pages/frames, browser,
// server, fixtureRoot and joined cleanup. Enable the two existing assessment
// objectives through the tenant's supported admin API before calling qualify.
// Create recorder first, then use recorder.provider and recorder.judge in the
// genuine production composition. transport is the existing 'mcp-trust-actual'
// wire controller. record receives PRIVATE synthetic evidence and must persist it.
// owner/sibling: {page,frame,binding,personaSessionId,personaAuthorityVersion,
// headers:{'x-dvaia-secureshop-launch':...,authorization:...}}. Neither credentials
// nor authoritative coordinates are accepted from a browser request body.
// resetOwner must call the real protected standalone reset and return its receipt.
// This module never starts processes, creates stores, enables defaults or grades.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {STEPS,runRenderedMcpTrust,createRenderedMcpTrustEvidence}=require('./renderedSecureShopMcpTrust');
const {createConversationBinding,createLaunchScope}=require('../../server/services/secureshopConversationBinding');
const {digestMcpValue}=require('../../server/services/secureshopMcpTrustTools');
const {MODEL,DIGEST}=require('./dpiTechniqueActualTransport');
const IDS=Object.freeze(['ss_rogue_tool_selected','ss_rug_pull_invoked']);
const PHASES=Object.freeze(['rogue','baseline','changed']);
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const sha=value=>createHash('sha256').update(value).digest('hex');
const parsed=value=>typeof value==='string'?JSON.parse(value):value;
const hex=value=>Buffer.isBuffer(value)?value.toString('hex'):value;
const rawContent=row=>row.response.trim().split('\n').map(line=>JSON.parse(line).message?.content||'').join('');
const clone=value=>structuredClone(value);
// Match the adapter's on-wire default without altering its actual invocation.
const wireOptions=options=>({...options,num_ctx:require('../../server/agent-runtime/providers/langchainProvider').ollamaContextWindow(options)});

function createMcpTrustD16Recorder({transport,record}={}){
 assert.equal(typeof record,'function','A private capture writer is required');
 assert.equal(transport?.model,MODEL);assert.equal(typeof transport?.url,'string');
 const endpoint=new URL(transport.url);assert.equal(endpoint.hostname,'127.0.0.1');assert.equal(endpoint.protocol,'http:');
 for(const key of ['expect','snapshot','beginCase','endCase'])assert.equal(typeof transport[key],'function');
 const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({model:MODEL,baseUrl:transport.url});
 const captures={version:1,scope:'D16-standalone',providerCalls:[],actorInvocations:[],transcripts:[],phases:[]};
 const save=()=>record(clone(captures));let active=null,closed=false;
 const originalTransport=provider.transport.chat,originals={};
 provider.transport.chat=async function(messages,tools,options){
  assert(active&&!closed,'D16 actor call outside admitted phase');transport.expect('actor',{messages,tools,options:wireOptions(options)});
  const row={phase:active,wireIndex:transport.snapshot().calls.length,messages:clone(messages),tools:clone(tools),options:{temperature:options.temperature,num_predict:options.num_predict,format:clone(options.format)}};
  captures.providerCalls.push(row);save();
  try{row.result=await originalTransport.call(this,messages,tools,options);return row.result;}finally{save();}
 };
 for(const method of ['chat','finalResponse']){originals[method]=provider[method];provider[method]=async function(input){
  assert(active&&!closed);const row={phase:active,method,input:{system:input.system,messages:clone(input.messages),...(input.tools?{tools:clone(input.tools)}:{})},wireStart:transport.snapshot().calls.length};
  captures.actorInvocations.push(row);save();try{row.result=await originals[method].call(this,input);return row.result;}
  finally{row.wireEnd=transport.snapshot().calls.length;save();}
 };}
 const providerModule=require('../../server/agent-runtime/providers/langchainProvider');
 const originalFactory=providerModule.createLangChainProvider;
 const previousEnv=Object.fromEntries(['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL']
  .map(key=>[key,Object.hasOwn(process.env,key)?process.env[key]:undefined]));
 process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;process.env.OLLAMA_BASE_URL=transport.url;
 providerModule.createLangChainProvider=function(config,...args){
  const configured=originalFactory.call(this,config,...args);
  if(config.provider!=='ollama'||config.model!==MODEL||config.baseURL!==transport.url)return configured;
  return {...configured,async chat(messages,tools,options){
   assert(active&&!closed,'D16 Judge outside admitted phase');
   transport.expect('judge',{messages,tools,options:wireOptions(options)});
   // The configured adapter and its original result remain the Judge authority.
   return configured.chat(messages,tools,options);
  }};
 };
 const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
  observeExecutionTranscript:row=>{captures.transcripts.push({...clone(row),phase:active});save();}});
 return Object.freeze({provider,judge,transport,
  begin(phase){assert(!closed&&!active);assert.equal(phase,PHASES[captures.phases.length]);transport.beginCase(phase);captures.phases.push(phase);active=phase;save();},
  end(){assert(active);transport.endCase();active=null;save();},
  snapshot:()=>clone(captures),
  close(){if(closed)return;closed=true;provider.transport.chat=originalTransport;
   for(const method of Object.keys(originals))provider[method]=originals[method];
   providerModule.createLangChainProvider=originalFactory;
   for(const [key,value] of Object.entries(previousEnv)){
    if(value===undefined)delete process.env[key];else process.env[key]=value;
   }
   save();},
 });
}

function assertRegisteredJudgment(row,subject){
 const {binding:b}=subject,e=row.execution_json;
 assert.equal(row.tenant_id,subject.tenantId);assert.equal(row.principal_id,subject.principalId);
 assert.equal(Number(row.shop_user_id),b.shopUserId);assert(IDS.includes(row.objective_id));
 assert.equal(row.mode,'vuln');assert.equal(e?.tenantId,subject.tenantId);assert.equal(e?.principalId,subject.principalId);
 assert.deepEqual(e.scope,createLaunchScope(b));assert.equal(e.shopUserId,b.shopUserId);assert.equal(e.role,'admin');
 assert.equal(e.personaSessionId,subject.personaSessionId);assert.equal(e.personaAuthorityVersion,subject.personaAuthorityVersion);
 assert.equal(e.runId,row.run_id);assert.equal(e.ownerKey,row.owner_key);assert.equal(String(e.ownerGeneration),String(row.owner_generation));
 assert.equal(sha(row.packet),row.evidence_digest);assert.equal(sha(row.result_serialized),row.result_digest);
 assert.deepEqual(parsed(row.result_serialized),row.result_json);
 assert.equal(row.judge_observations?.version,1);assert.equal(row.judge_observations.runId,row.run_id);
 assert.equal(row.judge_observations.evidenceDigest,row.evidence_digest);assert.equal(sha(row.judge_result_json),row.judge_observations.resultSha256);
 const raw=parsed(row.judge_result_json);assert.equal(raw.provider,'ollama');assert.equal(raw.model,MODEL);
 assert.equal(raw.runId,row.run_id);assert.equal(raw.evidenceDigest,row.evidence_digest);assert.equal(raw.verdict,row.verdict);
 assert.equal(row.result_json.provider,'ollama');assert.equal(row.result_json.model,MODEL);assert.equal(row.result_json.verdict,row.verdict);assert.equal(row.result_json.runId,row.run_id);assert.equal(row.result_json.evidenceDigest,row.evidence_digest);
 if(row.verdict==='pass'){assert.equal(row.credited,row.evaluation_id);assert.equal(row.completed,row.evaluation_id);}
 else{assert.equal(row.credited,null);assert.equal(row.completed,null);}
 return row;
}

// Reuse the existing strong protocol/trace/effect verifier with an explicit
// read-only registered-assessment projection. Only its legacy judgment SELECT is
// translated; no result is synthesized and no workshop credit is substituted.
function createStandaloneMcpEvidence({identityRuntime,agentsRuntime,subject}){
 const readJudgments=async()=>{
  const rows=(await identityRuntime.query(`SELECT j.*,c.evaluation_id AS credited,k.evaluation_id AS completed
   FROM secureshop_auth.assessment_judgments j
   LEFT JOIN secureshop_auth.assessment_contributions c USING(tenant_id,principal_id,evaluation_id)
   LEFT JOIN secureshop_auth.assessment_completions k USING(tenant_id,principal_id,evaluation_id)
   WHERE j.tenant_id=$1 AND j.principal_id=$2 AND j.execution_json->'scope'->>'launchId'=$3
    AND j.execution_json->'scope'->>'generation'=$4 AND j.objective_id=ANY($5::text[])
   ORDER BY j.created_at,j.evaluation_id`,[subject.tenantId,subject.principalId,subject.binding.launchId,String(subject.binding.generation),IDS])).rows;
  return rows.map(row=>assertRegisteredJudgment(row,subject));
 };
 const identityProjection={async query(sql,args){
  if(sql.includes('FROM workshop_platform.objective_judgments j')){
   assert.deepEqual(args,[subject.binding.platformOwnerId,subject.binding.launchId,subject.binding.generation,IDS]);
   return {rows:await readJudgments()};
  }
  assert(!sql.includes('workshop_platform.'),'No workshop evidence fallback');return identityRuntime.query(sql,args);
 }};
 return Object.freeze({...createRenderedMcpTrustEvidence({identityRuntime:identityProjection,agentsRuntime,binding:subject.binding}),readJudgments});
}

function verifyMcpPhaseWire({phase,captures,wire,invocations,schemas,judgments}){
 assert(PHASES.includes(phase));assert.equal(wire.model,MODEL);assert.equal(wire.digest,DIGEST);assert.equal(wire.failed,false);
 const calls=wire.calls.filter(row=>row.caseId===phase&&['actor','judge'].includes(row.role));
 assert(calls.some(row=>row.role==='actor'));assert(calls.filter(row=>row.role==='actor').length<=16);
 for(const raw of calls){assert.equal(raw.status,'returned');assert.equal(raw.httpStatus,200);assert.equal(sha(raw.request),raw.requestSha256);assert.equal(sha(raw.response),raw.responseSha256);}
 const observed=captures.providerCalls.filter(row=>row.phase===phase);
 assert.equal(observed.length,calls.filter(row=>row.role==='actor').length);
 for(const row of observed){const raw=wire.calls[row.wireIndex];assert.equal(raw?.caseId,phase);assert.equal(raw.role,'actor');
  const request=JSON.parse(raw.request);assert.deepEqual(request.messages,row.messages);assert.deepEqual(request.format,row.options.format);
  assert.equal(request.options.temperature,row.options.temperature);assert.equal(request.options.num_predict,row.options.num_predict);assert.equal(rawContent(raw),row.result.response);}
 assert(invocations.length>0);const actor=captures.actorInvocations.filter(row=>row.phase===phase);
 for(const inv of invocations){const decisions=actor.filter(row=>row.result?.tool_uses?.some(call=>call.id===inv.call_id&&call.name===inv.server_identity+'.'+inv.tool_name));assert.equal(decisions.length,1);
  const decision=decisions[0];assert.equal(decision.result.provider,'ollama');assert.equal(decision.result.model,MODEL);assert.equal(decision.result.mocked,false);
  assert(Number.isInteger(decision.wireStart)&&decision.wireEnd>decision.wireStart);
  const rawCalls=wire.calls.slice(decision.wireStart,decision.wireEnd);assert(rawCalls.every(row=>row.role==='actor'&&row.caseId===phase&&row.status==='returned'));
  const last=observed.find(row=>row.wireIndex===decision.wireEnd-1);assert(last);
  assert.deepEqual(JSON.parse(last.result.response).tool_calls.map(call=>({name:call.agent+'.'+call.tool,args:call.args})),decision.result.tool_uses.map(call=>({name:call.name,args:call.args})));
  const selected=decision.result.tool_uses.find(call=>call.id===inv.call_id);assert.equal(digestMcpValue(selected.args),hex(inv.arguments_sha256));
  const schema=schemas.filter(row=>row.target_id===inv.target_id&&Number(row.version)===Number(inv.schema_version));assert.equal(schema.length,1);
  assert.equal(digestMcpValue(schema[0].tools_json),hex(inv.schema_sha256));
  const expected=require('../../server/services/secureshopMcpTrustExecutionConfig').createSecureShopMcpTrustExecutionConfig({serverIdentity:inv.server_identity,trustScenario:inv.trust_scenario,schema:{serverIdentity:inv.server_identity,version:inv.schema_version,schemaSha256:hex(inv.schema_sha256),tools:schema[0].tools_json}}).manifest.getForRole('admin');
  assert.deepEqual(decision.input.tools,expected);
 }
 if(phase==='baseline'){assert.equal(judgments.length,0);assert.equal(calls.filter(row=>row.role==='judge').length,0);}
 else{
  assert(judgments.length>=1);const matched=new Set();
  for(const row of judgments){const transcripts=captures.transcripts.filter(t=>t.phase===phase&&t.complete&&t.header?.runId===row.run_id&&t.header?.packet===row.packet&&t.header?.evidenceDigest===row.evidence_digest);assert.equal(transcripts.length,1);
   const transcript=transcripts[0];assert.deepEqual(transcript.outcome.value,parsed(row.judge_result_json));assert(transcript.calls.length>0);
   for(const call of transcript.calls){assert.equal(call.transport,'returned');const found=calls.filter(raw=>raw.role==='judge'&&JSON.stringify(JSON.parse(raw.request).messages)===JSON.stringify(call.request.input)&&rawContent(raw)===call.response);assert.equal(found.length,1);assert(!matched.has(found[0].index));matched.add(found[0].index);}
  }
  assert.equal(matched.size,calls.filter(row=>row.role==='judge').length);
 }
 return {phase,actorCalls:calls.filter(row=>row.role==='actor').length,judgeCalls:calls.filter(row=>row.role==='judge').length};
}

async function clickPhysicalTrustControl(frame,{title,label}){
 assert(STEPS.some(row=>row[0]===title&&row[1]===label));
 await frame.waitForFunction(({title,label})=>{
  const articles=[...document.querySelectorAll('section[aria-label="Controlled MCP trust lab"] article')].filter(a=>a.querySelector('strong')?.textContent===title);
  if(articles.length!==1)return false;const buttons=[...articles[0].querySelectorAll('button')].filter(b=>b.textContent===label&&!b.disabled&&b.getClientRects().length);
  if(buttons.length!==1)return false;const button=buttons[0];button.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
  const rect=button.getBoundingClientRect(),hit=document.elementFromPoint(rect.x+rect.width/2,rect.y+rect.height/2);
  if(hit!==button&&!button.contains(hit))return false;button.setAttribute('data-d16-click','selected');return true;
 },{timeout:20000,polling:'mutation'},{title,label});
 try{await frame.click('[data-d16-click="selected"]');}
 finally{await frame.evaluate(()=>document.querySelector('[data-d16-click="selected"]')?.removeAttribute('data-d16-click'));}
}
function physicalTrustFrame(frame){return {
 waitForFunction:frame.waitForFunction.bind(frame),
 // Existing driver's only evaluate is its exact title/label click. Replace that
 // DOM click with the browser's physical pointer action without replacing data.
 async evaluate(_function,selector){assert.deepEqual(Object.keys(selector).sort(),['label','title']);return clickPhysicalTrustControl(frame,selector);},
};}
async function browserRequest(frame,{path:route,body}){
 assert(['/readiness','/discover','/run'].includes(route));
 return frame.evaluate(async({route,body})=>{const r=await fetch('/api/secureshop/v2/mcp-trust'+route,{method:body===undefined?'GET':'POST',cache:'no-store',...(body===undefined?{}:{headers:{'content-type':'application/json'},body:JSON.stringify(body)})});return {status:r.status,body:await r.json()};},{route,body});
}
async function readSubject({identityRuntime,agentsRuntime,session}){
 const binding=createConversationBinding(session.binding,{id:session.binding.shopUserId,role:session.binding.role});assert.equal(binding.role,'admin');
 assert.match(session.personaSessionId,UUID);assert.match(session.personaAuthorityVersion,/^[1-9]\d*$/);
 const rows=(await identityRuntime.query(`SELECT e.tenant_id,e.principal_id,p.shop_user_id,p.role
  FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.principals p USING(principal_id)
  JOIN identity.secureshop_authority_owners o ON o.id=e.owner_id
  WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
   AND o.realm='shop' AND o.shop_tenant_id=e.tenant_id AND p.is_active`,[binding.platformSessionId,binding.platformOwnerId])).rows;
 assert.equal(rows.length,1);assert.equal(Number(rows[0].shop_user_id),binding.shopUserId);assert.equal(rows[0].role,'admin');
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agentsRuntime,checkCurrent:async scope=>{
  const row=(await identityRuntime.query(`SELECT launch_id FROM identity.secureshop_launches WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND original_platform_owner_id=$4 AND platform_session_id=$5 AND status='active' AND expires_at>clock_timestamp()`,[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows;assert.equal(row.length,1);
 }});
 await authority.capture({scope:createLaunchScope(binding),personaId:binding.shopUserId,sessionId:session.personaSessionId,authorityVersion:session.personaAuthorityVersion,role:'admin'}).assertRemoteAdmission();
 return Object.freeze({binding,tenantId:rows[0].tenant_id,principalId:rows[0].principal_id,personaSessionId:session.personaSessionId,personaAuthorityVersion:session.personaAuthorityVersion});
}

async function qualifyMcpTrustStandalone({identityRuntime,agentsRuntime,owner,sibling,origin,fixtureRoot,recorder,resetOwner,beforeReset,record}={}){
 assert.equal(new URL(origin).origin,origin);assert.equal(new URL(origin).hostname,'127.0.0.1');assert(path.isAbsolute(fixtureRoot));
 assert.equal(typeof resetOwner,'function');assert.equal(typeof record,'function');
 assert(beforeReset===undefined||typeof beforeReset==='function');
 const retained={version:1,scope:'D16-standalone',controls:[],turns:[],phaseProofs:[]};
 const save=()=>record(clone(retained));let activePhase=null;
 const platform=async()=>(await identityRuntime.query('SELECT (SELECT count(*)::integer FROM identity.users) AS users,(SELECT count(*)::integer FROM identity.user_sessions) AS sessions')).rows;
 const platformBefore=await platform();
 try{
  const subject=await readSubject({identityRuntime,agentsRuntime,session:owner}),peer=await readSubject({identityRuntime,agentsRuntime,session:sibling});
  assert.notEqual(subject.tenantId,peer.tenantId);assert.notEqual(subject.principalId,peer.principalId);assert.notEqual(subject.binding.launchId,peer.binding.launchId);
  retained.subject=subject;retained.sibling=peer;save();
  const evidence=createStandaloneMcpEvidence({identityRuntime,agentsRuntime,subject});
  const readSchemas=async()=>(await agentsRuntime.query(`SELECT p.* FROM secureshop_agents.bound_mcp_tool_payloads p JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE t.launch_id=$1 ORDER BY p.target_id,p.version`,[subject.binding.launchId])).rows;
  const siblingSnapshot=async()=>({targets:(await agentsRuntime.query('SELECT * FROM secureshop_agents.bound_mcp_targets WHERE launch_id=$1 ORDER BY target_id',[peer.binding.launchId])).rows,
   invocations:(await agentsRuntime.query('SELECT i.* FROM secureshop_agents.bound_mcp_invocations i JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE t.launch_id=$1 ORDER BY i.invocation_id',[peer.binding.launchId])).rows});
  const readiness=await browserRequest(owner.frame,{path:'/readiness'});assert.equal(readiness.status,200);assert.equal(readiness.body.ready,true);assert.equal(readiness.body.scenarios.rogue_registration,true);assert.equal(readiness.body.scenarios.rug_pull,true);
  const discovered=await browserRequest(sibling.frame,{path:'/discover',body:{scenario:'rogue_registration'}});assert.equal(discovered.status,200);
  const siblingBefore=await siblingSnapshot();assert.equal(siblingBefore.targets.length,1);retained.siblingBefore=siblingBefore;save();
  let stepIndex=0;
  const observedPage={waitForResponse(predicate,options){
   const step=STEPS[stepIndex++];assert(step);
   if(step[2]==='/run'){activePhase=PHASES[retained.turns.length];recorder.begin(activePhase);}
   return owner.page.waitForResponse(predicate,options).then(async response=>{
    const request=JSON.parse(response.request().postData()),body=await response.json();
    retained.controls.push({title:step[0],label:step[1],path:step[2],request,status:response.status(),body});save();return response;
   });
  }};
  const observedEvidence={snapshot:()=>evidence.snapshot(),async verify(input){
   const after=await evidence.snapshot();
   const added=after.invocations.filter(row=>row.request_id===input.requestId),fresh=after.judgments.filter(row=>!input.before.judgments.some(old=>old.evaluation_id===row.evaluation_id));
   for(const invocation of added){assert.equal(input.response.serverIdentity,invocation.server_identity);assert.equal(input.response.schemaVersion,invocation.schema_version);assert.equal(input.response.schemaSha256,hex(invocation.schema_sha256));assert.equal(input.response.trustScenario,input.scenario);}
   const schemas=await readSchemas();
   const artifacts={runs:(await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=ANY($1::uuid[]) ORDER BY run_id',[[...new Set(added.map(row=>row.run_id))]])).rows,
    effects:(await identityRuntime.query('SELECT * FROM graph_runtime.effects WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,effect_key',[[...new Set(added.map(row=>row.run_id))]])).rows,
    traces:(await agentsRuntime.query('SELECT t.* FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE s.platform_launch_id=$1 AND t.id>$2 ORDER BY t.id',[subject.binding.launchId,input.before.head])).rows};
   retained.pendingTurn={phase:activePhase,input,after,schemas,artifacts};save();
   const verified=await evidence.verify(input);const phaseProof=verifyMcpPhaseWire({phase:activePhase,captures:recorder.snapshot(),wire:recorder.transport.snapshot(),invocations:added,schemas,judgments:fresh});
   retained.turns.push({...verified,phase:activePhase,response:input.response,invocations:added,judgments:fresh,schemas,artifacts});delete retained.pendingTurn;retained.phaseProofs.push(phaseProof);save();recorder.end();activePhase=null;return verified;
  }};
  const rendered=await runRenderedMcpTrust({page:observedPage,frame:physicalTrustFrame(owner.frame),origin,evidence:observedEvidence});
  assert.equal(stepIndex,6);assert.equal(retained.controls.length,6);assert.deepEqual(retained.turns.map(t=>t.phase),PHASES);
  for(const [discover,run]of [[0,1],[2,3],[4,5]]){const a=retained.controls[discover],b=retained.controls[run];assert.equal(a.status,200);for(const key of ['serverIdentity','schemaVersion','schemaSha256','trustScenario'])assert.equal(a.body[key],b.body[key]);}
  const [rogue,baseline,changed]=retained.turns;
  assert.equal(rogue.response.serverIdentity,'secureshop-rogue-weather-lab');assert.equal(baseline.response.serverIdentity,'secureshop-weather-lab');
  assert.equal(changed.response.serverIdentity,baseline.response.serverIdentity);assert.equal(baseline.response.schemaVersion,1);assert.equal(changed.response.schemaVersion,2);assert.notEqual(changed.response.schemaSha256,baseline.response.schemaSha256);
  const beforeReplay=await evidence.snapshot(),wireBefore=recorder.transport.snapshot().externalAttempts;
  retained.replays=[];
  for(const turn of retained.turns){const replay=await browserRequest(owner.frame,{path:'/run',body:{scenario:turn.scenario,request_id:turn.requestId}});
   retained.replays.push({phase:turn.phase,scenario:turn.scenario,requestId:turn.requestId,status:replay.status,body:replay.body});save();
   assert.equal(replay.status,200);assert.deepEqual(replay.body,{...turn.response,replayed:true});}
  assert.equal(recorder.transport.snapshot().externalAttempts,wireBefore);assert.deepEqual(await evidence.snapshot(),beforeReplay);retained.replay=true;save();
  // Mix only the two genuinely authenticated headers. No forged principal DTO.
  const cross=await fetch(origin+'/api/secureshop/v2/mcp-trust/readiness',{headers:{'x-dvaia-secureshop-launch':owner.headers['x-dvaia-secureshop-launch'],authorization:sibling.headers.authorization},signal:AbortSignal.timeout(10000)});
  assert.equal(cross.status,401);await cross.arrayBuffer();assert.deepEqual(await siblingSnapshot(),siblingBefore);retained.siblingDenied=true;save();
  if(beforeReset){retained.beforeReset=await beforeReset({owner,sibling,positive:retained});save();}
  const immutable=await evidence.readJudgments();assert.equal(immutable.filter(row=>row.verdict==='pass').length,2);
  const reset=await resetOwner(owner);assert.equal(reset.status,'committed');assert.match(reset.resetId,UUID);retained.reset=reset;save();
  assert.deepEqual(await evidence.readJudgments(),immutable);assert.deepEqual(await siblingSnapshot(),siblingBefore);
  assert.equal((await browserRequest(sibling.frame,{path:'/readiness'})).status,200);
  const stale=await fetch(origin+'/api/secureshop/v2/mcp-trust/readiness',{headers:owner.headers,signal:AbortSignal.timeout(10000)});assert.equal(stale.status,401);await stale.arrayBuffer();
  const targets=[...new Set(retained.turns.flatMap(turn=>turn.invocations.map(row=>row.target_id)))];assert.equal(targets.length,2);
  const cleanup=(await agentsRuntime.query('SELECT * FROM secureshop_agents.bound_mcp_cleanup_receipts WHERE target_id=ANY($1::uuid[]) ORDER BY target_id',[targets])).rows;assert.equal(cleanup.length,2);
  for(const target of targets){assert.match(target,UUID);assert(!fs.existsSync(path.join(fixtureRoot,target)),'Reset must remove only owned target fixture');}
  assert.equal(recorder.transport.snapshot().externalAttempts,wireBefore);assert.deepEqual(await platform(),platformBefore);
  const summary={scope:'D16-standalone',qualified:true,renderedControls:6,actualTurns:3,actualModelProof:true,genuineCredit:2,qualifiedObjectiveIds:[...IDS],actorCalls:retained.phaseProofs.reduce((n,row)=>n+row.actorCalls,0),judgeCalls:retained.phaseProofs.reduce((n,row)=>n+row.judgeCalls,0),replay:true,siblingDenied:true,siblingPreserved:true,reset:true,immutablePreserved:true,ownedTargetsRetired:true,platformUsersUnchanged:true};
  retained.rendered=rendered;retained.cleanup=cleanup;retained.summary=summary;save();return Object.freeze(summary);
 }catch(error){retained.failure={name:error.name,code:error.code||null};save();throw error;}
 finally{recorder.close();}
}
module.exports={IDS,PHASES,createMcpTrustD16Recorder,qualifyMcpTrustStandalone,
 _contracts:{assertRegisteredJudgment,createStandaloneMcpEvidence,verifyMcpPhaseWire,physicalTrustFrame,clickPhysicalTrustControl,wireOptions}};
