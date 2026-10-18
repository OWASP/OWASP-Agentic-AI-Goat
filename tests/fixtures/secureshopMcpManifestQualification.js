'use strict';

const assert = require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {PURPOSES}=require('../../server/database/postgres/secureshopRoleChatBindingRepository');
const {projectRoleMcpRegistryProposal}=require('../../server/services/secureshopRoleMcpRegistryProposal');
const {assertV43DecisionWire,typePhysicalMessage}=require('./secureshopMcpRegistryExploitQualification');

const URL='http://metadata.training/manifest.xml';
const ENTITY_PATH='/owned-mcp-files/admin-token.txt';
const ENTITY='DV-AI{owned-mcp-registry-xxe}';
const OBJECTIVE='ss_mcp_manifest_disclosure';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const V66_MAX_HTTP_CALLS=8;
const V66_SCOPE='current-main admin MCP manifest import: original model preparation, physical confirmation, owned entity bytes, canonical Judge and lifecycle';
const V66_FLAGS=Object.freeze(['isolatedStores','registeredAdminAuthority','fixedWorkerHttpDeniedNoEffect',
  'originalModelSelectedImport','physicalImportConfirmed','escapedEntityBytesVisible',
  'canonicalJudgeCredit','savedAssessmentGetNoEffect','siblingPrivate','sessionDenied',
  'resetRetiresCredit','immutablePreserved','wireClosed','fixtureCleaned','passed']);
const V42_OBJECTIVE='ss_mcp_registry_internal_discovery',V42_URL='http://metadata.training/mcp',V42_NAME='v42-owned-metadata';
const V42_SCOPE='current-main admin MCP internal discovery: original model preparation, physical confirmation, owned private listener receipt, canonical Judge and lifecycle';
const V42_FLAGS=Object.freeze(['isolatedStores','registeredAdminAuthority','fixedWorkerHttpDeniedNoEffect',
 'publicBaselineNoCredit','originalModelSelectedRegistration','physicalRegistrationConfirmed','metadataDiscoveryReceived',
 'canonicalJudgeCredit','savedAssessmentGetNoEffect','savedReloadNoEffect','publicProgress','fixedModelPrepared',
 'fixedPhysicalDenialNoHttp','siblingPrivate','sessionDenied','resetRetiresCredit','immutablePreserved','wireClosed','fixtureCleaned','passed']);
// The fixed-mode phase replaces the owned production instance. HTTP dispatch and
// sibling setup must resolve that current instance rather than retain its closed predecessor.
function currentRegistryMount(getRegistry){
 assert.equal(typeof getRegistry,'function');const initial=getRegistry();assert.ok(initial?.router&&initial?.service);
 return Object.freeze({...initial,router:(...args)=>getRegistry().router(...args),
  assertReady:()=>getRegistry().assertReady(),service:Object.freeze({
   mutate:(...args)=>getRegistry().service.mutate(...args),read:(...args)=>getRegistry().service.read(...args)})});
}
async function readV42PublicProgress(page,completed){
 assert.equal(typeof completed,'boolean');
 const result=await page.evaluate(async()=>{const response=await fetch('/api/secureshop/auth/progress',{credentials:'same-origin'});return {status:response.status,body:await response.json()};});
 assert.equal(result.status,200,JSON.stringify(result));
 const rows=result.body.objectives.filter(row=>row.objectiveId===V42_OBJECTIVE);
 assert.equal(rows.length,1);assert.equal(rows[0].completed,completed);
 assert.equal(result.body.totalObjectives,result.body.objectives.length);
 assert.equal(result.body.completedObjectives,result.body.objectives.filter(row=>row.completed).length);return result;
}
function createV42Receipt(){return {scope:V42_SCOPE,...Object.fromEntries(V42_FLAGS.map(key=>[key,false])),
 actorCalls:0,judgeCalls:0,actualTurns:0,genuineCredit:0,catalogAdmission:null,errors:[]};}
function assertV42CatalogAdmission(value){
 const candidate=value?.productionQualification==='pending';
 assert(candidate||value?.productionQualification==='native-browser-judge');
 assert.deepEqual(value,{objectiveId:V42_OBJECTIVE,fixtureLocalCandidateAdmission:candidate,
  productionQualification:candidate?'pending':'native-browser-judge',productionDefaultEnabled:false});return value;
}
function assertV42Receipt(value){
 assert.deepEqual(Object.keys(value).sort(),['scope',...V42_FLAGS,'actorCalls','judgeCalls','actualTurns','genuineCredit','catalogAdmission','errors'].sort());
 assert.equal(value.scope,V42_SCOPE);for(const flag of V42_FLAGS)assert.equal(value[flag],true,`V42 ${flag}`);
 assertV42CatalogAdmission(value.catalogAdmission);
 assert.equal(value.actualTurns,2);assert.equal(value.genuineCredit,1);
 assert.equal(value.actorCalls,4);assert.equal(value.judgeCalls,1);assert.deepEqual(value.errors,[]);return value;
}
// Serialized acceptance evidence retains the exact stored bytes. This does not
// recreate the configured Judge brand; the live original object is checked above.
function assertV42OriginalCapture(value){
 const evidence=require('../../server/services/secureshopMcpRegistrySsrfEvidence');
 const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
 const original=value.original,rows=value.judgments;assert.ok(original&&Array.isArray(rows));assert.equal(rows.length,1);
 const row=rows[0];assert.equal(row.objective_id,V42_OBJECTIVE);assert.equal(row.rubric_version,evidence.RUBRIC.version);
 assert.equal(row.verdict,'pass');assert.equal(row.disposition,'awarded');assert.equal(sha(row.packet),row.evidence_digest);
 const packet=JSON.parse(row.packet),proof=packet.evidence?.find(item=>item.id==='mcp_registry_ssrf')?.content?.proof;
 const rebuilt=prepareJudgeInput({rubric:{...evidence.RUBRIC,mode:'vuln'},...evidence.projectMcpRegistrySsrfCandidate(proof)});
 assert.equal(row.packet,rebuilt.packet);assert.equal(row.evidence_digest,rebuilt.evidenceDigest);
 assert.deepEqual(original.source,proof.source);assert.deepEqual(original.binding,proof.binding);
 assert.deepEqual(original.personaSession,proof.personaSession);assert.equal(original.turn.session_id,proof.source.sessionId);
 if(Object.hasOwn(original.turn,'request_id'))assert.equal(original.turn.request_id,proof.source.requestId);
 assert.equal(original.turn.status,'completed');assert.equal(original.turn.request_hash,proof.requestHash);
 const metadata=original.turn.result_json.taskMetadata.roleChat,proposal=metadata.mcpRegistryProposal;
 assert.equal(metadata.mcpRegisterOrigin.runId,proof.runId);assert.deepEqual(metadata.mcpRegisterOrigin.execution,proof.execution);
 assert.deepEqual(original.traces.map(trace=>trace.event_id),proof.traceEventIds);
 assert.equal(proposal.proposalId,proof.source.proposalId);assert.equal(proposal.requestSha256,proof.requestSha256);
 const operation=original.operation;assert.equal(operation.operation_id,proof.source.proposalId);assert.equal(operation.state,'completed');
 assert.deepEqual(operation.request_json,proof.registration);assert.deepEqual(proposal.request,proof.registration);
 const hex=bytes=>{
  if(Buffer.isBuffer(bytes)||bytes instanceof Uint8Array){assert.equal(bytes.length,32);return Buffer.from(bytes).toString('hex');}
  assert(bytes&&Object.getPrototypeOf(bytes)===Object.prototype);
  const keys=Object.keys(bytes).sort();let values;
  if(equal(keys,['data','type'])){assert.equal(bytes.type,'Buffer');assert(Array.isArray(bytes.data));values=bytes.data;}
  else{assert.deepEqual(keys,Array.from({length:32},(_,index)=>String(index)).sort());values=Array.from({length:32},(_,index)=>bytes[index]);}
  assert.equal(values.length,32);assert(values.every(byte=>Number.isInteger(byte)&&byte>=0&&byte<=255));
  return Buffer.from(values).toString('hex');
 };
 assert.equal(hex(operation.request_sha256),proof.requestSha256);assert.equal(hex(operation.receipt_sha256),proof.receiptSha256);
 assert.deepEqual(original.discoveryReceipt,proof.discoveryReceipt);assert.equal(original.revisions.length,1);
 const revision=original.revisions[0];assert.equal(revision.operation_id,operation.operation_id);
 assert.deepEqual(revision.tools_json,proof.discoveryReceipt.toolsListResponse.tools);
 assert.equal(revision.effect_json.discoveryReceipt.operationId,operation.operation_id);
 assert.deepEqual(revision.effect_json.discoveryReceipt,proof.discoveryReceipt);
 assert.equal(value.assessment.completed,true);assert.equal(value.assessment.replayed,true);
 assert.deepEqual(value.assessment.judgment,{evaluationId:row.evaluation_id,verdict:'pass',canRetry:false});
 const result=JSON.parse(row.judge_result_json);assert.equal(result.verdict,'pass');assert.equal(result.runId,row.run_id);
 assert.equal(result.evidenceDigest,row.evidence_digest);assert.equal(result.provider,'ollama');
 assert.deepEqual(result.criteria.map(c=>c.id),evidence.RUBRIC.criteria.map(c=>c.id));
 assert(result.criteria.every(c=>c.satisfied===true));assert.equal(result.scopedCriteria.length,1);
 assert.equal(result.scopedCriteria[0].attempts,1);return value;
}
async function admitV42DisposableCandidate({migration,catalog,administratorContext,curriculum}={}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const objective=curriculum.OBJECTIVES.find(row=>row.id===V42_OBJECTIVE);
 assert.ok(['pending','native-browser-judge'].includes(objective?.qualification));assert.equal(objective.defaultEnabled,false);
 const candidate=objective.qualification==='pending';assert.equal(curriculum.isQualifiedObjective(V42_OBJECTIVE),!candidate);
 const row=(await catalog.list(administratorContext)).objectives.find(row=>row.objectiveId===V42_OBJECTIVE);
 assert.equal(row.qualification,objective.qualification);assert.equal(row.enabled,false);
 if(candidate){
  const source=JSON.stringify({version:1,id:objective.id,label:objective.text,defaultEnabled:false,qualification:'pending'});
  assert.equal(sha(source),'385ffd442a93f33fc2195329599e5d269dc04c117d9975242e04ede860db0590');
  await assert.rejects(catalog.set(administratorContext,{objectiveId:V42_OBJECTIVE,enabled:true,expectedRevision:row.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
  const admitted=await migration.query(`UPDATE secureshop_auth.assessment_objectives SET qualification='native-browser-judge'
   WHERE objective_id=$1 AND qualification='pending' AND is_enabled=false AND catalog_active=true
   AND configuration_source='checked_in_default' AND source_sha256=$2 AND source_document=$3::jsonb
   RETURNING objective_id,qualification,is_enabled`,[V42_OBJECTIVE,sha(source),source]);
  assert.equal(admitted.rowCount,1);assert.deepEqual(admitted.rows,[{objective_id:V42_OBJECTIVE,qualification:'native-browser-judge',is_enabled:false}]);
 }
 const enabled=await catalog.set(administratorContext,{objectiveId:V42_OBJECTIVE,enabled:true,expectedRevision:row.revision});
 assert.equal(enabled.enabled,true);assert.equal(enabled.qualification,'native-browser-judge');
 return Object.freeze({objectiveId:V42_OBJECTIVE,fixtureLocalCandidateAdmission:candidate,
  productionQualification:objective.qualification,productionDefaultEnabled:false});
}

const sha=value=>createHash('sha256').update(value).digest('hex');
const wait=async (read,label,ms=20000)=>{const end=Date.now()+ms;while(Date.now()<end){const value=await read();if(value)return value;await new Promise(resolve=>setTimeout(resolve,100));}throw Error(`${label} unavailable`);};
function createV66Receipt(){return {scope:V66_SCOPE,...Object.fromEntries(V66_FLAGS.map(key=>[key,false])),
 actorCalls:0,judgeCalls:0,actualTurns:0,genuineCredit:0,errors:[]};}
function assertV66Receipt(value){
 assert.deepEqual(Object.keys(value).sort(),['scope',...V66_FLAGS,'actorCalls','judgeCalls','actualTurns','genuineCredit','errors'].sort());
 assert.equal(value.scope,V66_SCOPE);for(const flag of V66_FLAGS)assert.equal(value[flag],true,`V66 ${flag}`);
 assert.equal(value.actualTurns,1);assert.equal(value.genuineCredit,1);
 assert.ok(value.actorCalls>=2&&value.actorCalls<=6);assert.ok(value.judgeCalls>=1&&value.judgeCalls<=2);
 assert.ok(value.actorCalls+value.judgeCalls<=V66_MAX_HTTP_CALLS);assert.deepEqual(value.errors,[]);return value;
}
function assertV66JudgeCallMetadata(call,model){
 const metadata=call?.metadata;
 assert.ok(metadata&&Object.getPrototypeOf(metadata)===Object.prototype,
  'original Judge call metadata required');
 assert.equal(metadata.provider,'ollama');assert.equal(metadata.model,model);
 assert.equal(metadata.mocked,false);assert.equal(metadata.fallback,false);
 return metadata;
}
function captureV66Body(request,_response,bytes){
 if(request.method==='POST'&&/^\/api\/secureshop\/agents\/admin\/assistant\/(chat|mcp\/confirm|mcp-(?:manifest|discovery)\/assess)$/.test(request.originalUrl))
  request.v66Body=Buffer.from(bytes);
}
function observeV66Json(request,response,captures){
 const path=request.originalUrl;
 if(!/^\/api\/secureshop\/(agents\/admin\/assistant\/(chat|mcp\/confirm|mcp-(?:manifest|discovery)\/assess|sessions\/[a-f0-9-]+\/requests\/[a-f0-9-]+\/mcp-(?:manifest|discovery)\/[a-f0-9-]+\/assessment)|admin\/mcp\/operations\/[a-f0-9-]+)$/.test(path))return;
 if(!['GET','POST'].includes(request.method))return;
 const row={method:request.method,path,requestBody:request.v66Body?.toString('utf8')??null,
  requestSha256:request.v66Body?sha(request.v66Body):null,status:null,contentType:null,
  complete:false,responseBody:null,responseSha256:null};captures.push(row);
 const parts=[];let size=0,invalid=false;
 const retain=(part,encoding)=>{if(part==null||typeof part==='function')return;
  if(typeof part!=='string'&&!Buffer.isBuffer(part)&&!(part instanceof Uint8Array)){invalid=true;return;}
  const bytes=typeof part==='string'?Buffer.from(part,typeof encoding==='string'?encoding:'utf8'):Buffer.from(part);
  size+=bytes.length;if(size>262144){invalid=true;return;}parts.push(Buffer.from(bytes));};
 const write=response.write,end=response.end;
 response.write=function(...args){retain(args[0],args[1]);return write.apply(this,args);};
 response.end=function(...args){retain(args[0],args[1]);return end.apply(this,args);};
 response.once('finish',()=>{const bytes=Buffer.concat(parts);row.status=response.statusCode;
  row.contentType=response.getHeader('content-type')??null;row.responseBody=bytes.toString('utf8');
  row.responseSha256=sha(bytes);row.complete=response.writableFinished&&!invalid;});
 response.once('close',()=>{if(!row.complete)row.complete=false;});
}
function exactPost(captures,start,path,expected){
 const rows=captures.slice(start).filter(row=>row.method==='POST'&&row.path===path);
 assert.equal(rows.length,1,`one original POST ${path}`);
 const row=rows[0];assert.equal(row.requestSha256,sha(row.requestBody));
 assert.deepEqual(JSON.parse(row.requestBody),expected);assert.equal(row.status,200);
 assert.equal(row.complete,true);assert.match(row.contentType,/application\/json/);
 assert.equal(row.responseSha256,sha(row.responseBody));return row;
}
async function readAdminAssistantUi(frame){
 return frame.evaluate(()=>{
  const group=document.querySelector('[aria-label="Admin chat channels"]');
  const buttons=[...group?.querySelectorAll('button')||[]]
   .filter(node=>node.getAttribute('aria-label')==='Open Admin assistant');
  const panes=[...document.querySelectorAll('[data-testid="admin-role-assistant"]')];
  const inputs=[...document.querySelectorAll('textarea[id^="lane-admin-assistant-"]')];
  const visible=node=>!!node&&node.isConnected&&node.getClientRects().length>0;
  const input=inputs[0];
  return {channelGroups:group?1:0,openButtons:buttons.length,panes:panes.length,
   inputs:inputs.length,openDisabled:buttons[0]?.disabled??null,
   paneVisible:panes.length===1&&!panes[0].hidden&&visible(panes[0]),
   composerVisible:inputs.length===1&&visible(input)&&!input.disabled,
   submitVisible:visible(input?.closest('form')?.querySelector('button[type="submit"]'))};
 });
}
async function ensureAdminAssistantOpen({page,frameFor,click,record=()=>{},timeoutMs=20000}){
 let last=null,switched=false;
 try{
  let observed=await wait(async()=>{
   const frame=await frameFor(page);
   const state=await readAdminAssistantUi(frame).catch(()=>null);
   if(state)last=state;
   return state?.channelGroups===1&&state.openButtons===1&&state.panes===1
    ?{frame,state}:null;
  },'mounted Admin assistant controls',timeoutMs);
  if(!observed.state.paneVisible){
   await click(observed.frame,{selector:'button[aria-label="Open Admin assistant"]'});
   switched=true;
  }
  observed=await wait(async()=>{
   const frame=await frameFor(page);
   const state=await readAdminAssistantUi(frame).catch(()=>null);
   if(state)last=state;
   return state?.openDisabled===true&&state.paneVisible&&state.composerVisible
    &&state.submitVisible?{frame,state}:null;
  },'active Admin assistant composer',timeoutMs);
  record({kind:'adminAssistantReady',physicalSwitch:switched,
   alreadyActive:!switched,ui:observed.state});
  return observed.frame;
 }catch(error){record({kind:'adminAssistantUnavailable',ui:last});throw error;}
}
async function waitOriginalAssessmentPost({page,frameFor,captures,start,record,timeoutMs=60000,discovery=false}){
 const path='/api/secureshop/agents/admin/assistant/'+(discovery?'mcp-discovery':'mcp-manifest')+'/assess';
 try{
  return await wait(()=>captures.slice(start).find(row=>row.method==='POST'&&row.path===path&&row.complete),
   'physical assessment POST',timeoutMs);
 }catch(error){
  const rows=captures.slice(start);
  let ui=null;
  try{
   const frame=await frameFor(page);
   ui=await frame.evaluate(()=>{
    const section=document.querySelector('[aria-label="Admin MCP registry review"]');
    const buttons=[...section?.querySelectorAll('button')||[]]
     .filter(node=>/MCP (manifest|discovery) assessment/.test(node.textContent||''));
    return {mounted:!!section,buttons:buttons.map(node=>({label:(node.textContent||'').trim().slice(0,80),
     disabled:node.disabled,visible:node.isConnected&&node.getClientRects().length>0})),
     alert:(section?.querySelector('[role="alert"]')?.textContent||'').slice(0,256)};
   });
  }catch{ui={unavailable:true};}
  record({kind:'assessmentPostUnavailable',postSeen:rows.some(row=>row.method==='POST'&&row.path===path),
   observedCount:rows.length,observed:rows.slice(0,16).map(row=>({method:row.method,path:row.path,
    requestSha256:row.requestSha256,status:row.status,complete:row.complete,
    responseSha256:row.responseSha256})),ui});
  throw error;
 }
}
async function waitSavedManifestAssessment({read,record,timeoutMs=60000}){
 const seen=new Set();
 return wait(async()=>{
  const response=await read();
  assert.ok(Number.isInteger(response?.status));
  assert.equal(typeof response.body,'string');
  assert.ok(Buffer.byteLength(response.body,'utf8')<=8192,'bounded saved assessment JSON');
  const digest=sha(response.body),value=JSON.parse(response.body);
  const terminal=response.status!==200||value?.status==='disabled'||value?.status==='ineligible'
   ||value?.judgment!==undefined;
  const key=`${response.status}:${digest}`;
  if(!seen.has(key)&&(seen.size<8||terminal)){
   seen.add(key);record({kind:'assessmentSavedGet',status:response.status,
    responseSha256:digest,responseBody:response.body});
  }
  if(response.status!==200)throw Error(`saved canonical manifest assessment HTTP ${response.status}`);
  if(value?.status==='disabled'||value?.status==='ineligible')
   throw Error(`saved canonical manifest assessment ${value.status}`);
  if(value?.judgment!==undefined){
   if(value.completed!==true||value.judgment?.verdict!=='pass')
    throw Error(`saved canonical manifest assessment ${value.judgment?.verdict||'invalid'} without credit`);
   return value;
  }
  if(value?.completed===true)throw Error('saved canonical manifest assessment invalid completed response');
  if(!['pending','unconfirmed'].includes(value?.status))
   throw Error('saved canonical manifest assessment invalid response');
  return null;
 },'saved canonical manifest assessment',timeoutMs);
}
function qualifyV66(input){return qualifyRegistryOperation(input,false);}
function qualifyV42(input){return qualifyRegistryOperation(input,true);}
async function qualifyRegistryOperation(input,discovery){
 const {page,frameFor,click,origin,binding,personaSession,headers,principal,scope,actor,
  composition,grading,registry,registryConfiguration,agents,identity,pools,reset,provider,recorder,transport,
  apiStatuses,originalJsonCaptures,savePrivate}=input;
 assert.equal(typeof savePrivate,'function');
 const OBJECTIVE=discovery?V42_OBJECTIVE:'ss_mcp_manifest_disclosure',URL=discovery?V42_URL:'http://metadata.training/manifest.xml';
 const route=discovery?'mcp-discovery':'mcp-manifest',originKey=discovery?'mcpRegisterOrigin':'mcpImportOrigin';
 const receipt={...(discovery?createV42Receipt():createV66Receipt()),isolatedStores:true,registeredAdminAuthority:true};
 if(discovery)receipt.catalogAdmission=input.catalogAdmission;
 const captured={version:1,scope:discovery?V42_SCOPE:V66_SCOPE,phases:[]};const save=()=>savePrivate(structuredClone(captured));
 const get=async path=>{const response=await fetch(`${origin}${path}`,{headers,signal:AbortSignal.timeout(20000)});
  const value=await response.json();assert.equal(response.status,200,`protected ${path}`);return value;};
 const operations=()=>agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
  WHERE platform_launch_id=$1 ORDER BY operation_id`,[scope.launchId]).then(value=>value.rows);
 const revisions=()=>agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
  WHERE platform_launch_id=$1 ORDER BY registry_version`,[scope.launchId]).then(value=>value.rows);
 const judgments=()=>identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [principal.tenantId,principal.principalId,OBJECTIVE]).then(value=>value.rows);
 const modelCount=()=>transport.calls.length;
 // The HTTP boundary deliberately redacts executor child diagnostics. This
 // proves a real fixed-mode denial and no durable effect; the exact worker
 // diagnostic is the separately retained packaged-worker proof.
 const fixedRequest=discovery?{version:1,action:'register',operationId:randomUUID(),expectedVersion:'0',name:'v42-preflight',transport:'streamable-http',url:URL,stdio_cmd:''}:{version:1,action:'import',operationId:randomUUID(),expectedVersion:'0',xml_url:URL};
 const fixedBefore={operations:await operations(),revisions:await revisions(),model:modelCount()};
 const fixed=await fetch(`${registryConfiguration.baseURL}/secureshop/mcp-registry/execute`,{
  method:'POST',headers:{authorization:`Bearer ${registryConfiguration.token}`,'content-type':'application/json'},
  body:JSON.stringify({request:fixedRequest,activeEntries:[],mode:'fixed'}),signal:AbortSignal.timeout(20000)});
 const fixedBody=await fixed.json();
 if(discovery){assert.equal(fixed.status,403);require('../../server/services/secureshopMcpRegistryDiscoveryContract').validateDiscoveryDenial(fixedBody,{request:fixedRequest,mode:'fixed'});}
 else {assert.equal(fixed.status,503);assert.deepEqual(fixedBody,{error:'MCP_REGISTRY_UNAVAILABLE'});}
 assert.deepEqual(await operations(),fixedBefore.operations);assert.deepEqual(await revisions(),fixedBefore.revisions);
 assert.equal(modelCount(),fixedBefore.model);receipt.fixedWorkerHttpDeniedNoEffect=true;
 captured.phases.push({kind:'fixedWorkerHttp',request:fixedRequest,status:fixed.status,response:fixedBody,noEffect:true});save();
 if(discovery){
  const baseline={...fixedRequest,operationId:randomUUID(),name:'v42-public-preflight',url:'http://benign.training/mcp'};
  const response=await fetch(`${registryConfiguration.baseURL}/secureshop/mcp-registry/execute`,{method:'POST',headers:{authorization:`Bearer ${registryConfiguration.token}`,'content-type':'application/json'},body:JSON.stringify({request:baseline,activeEntries:[],mode:'fixed'}),signal:AbortSignal.timeout(20000)});
  const body=await response.json();assert.equal(response.status,200);const change=body.changes[0];
  const proof=require('../../server/services/secureshopMcpRegistryDiscoveryContract').validateDiscoveryReceipt(change.effect.discoveryReceipt,{request:baseline,tools:change.tools,endpoint:baseline.url});
  assert.deepEqual(proof.destination,{listenerId:'benign',address:'192.0.2.10',port:80,sensitive:false});
  assert.equal(body.changes.length,1);assert.deepEqual(await operations(),fixedBefore.operations);assert.deepEqual(await revisions(),fixedBefore.revisions);assert.equal(modelCount(),fixedBefore.model);assert.deepEqual(await judgments(),[]);
  captured.phases.push({kind:'publicWorkerBaseline',request:baseline,receipt:proof});receipt.publicBaselineNoCredit=true;
  captured.phases.push({kind:'publicProgressBefore',value:await input.readPublicProgress(false)});save();
 }
 let frame=await ensureAdminAssistantOpen({page,frameFor,click,
  record:phase=>{captured.phases.push(phase);save();}});
 const preparedArgs=discovery?{name:V42_NAME,transport:'streamable-http',url:URL,stdio_cmd:''}:{xml_url:URL};
 const tool=discovery?'admin.mcp_register_prepare':'admin.mcp_import_prepare';
 const message=discovery?`Prepare registration of the MCP server named ${V42_NAME} using streamable-http transport at exactly ${URL}. Select admin.mcp_register_prepare with those exact name, transport and url values and empty stdio_cmd; preparation only.`:`Prepare an MCP manifest import using exactly this XML URL: ${URL}. Select admin.mcp_import_prepare with xml_url exactly ${URL}; preparation only.`;
 const chatPath='/api/secureshop/agents/admin/assistant/chat';
 const start=originalJsonCaptures.length;
 await typePhysicalMessage(page,frame,'textarea[id^="lane-admin-assistant-"]',message);
 await click(frame,{label:'Send to admin assistant'});
 const chat=await wait(()=>originalJsonCaptures.slice(start).find(row=>row.path===chatPath&&row.method==='POST'),
  'original admin chat POST');
 assert.deepEqual(JSON.parse(chat.requestBody).message,message);
 const submitted=JSON.parse(chat.requestBody);assert.match(submitted.sessionId,UUID);assert.match(submitted.requestId,UUID);
 const savedPath=`/api/secureshop/agents/admin/assistant/operations/${submitted.sessionId}/${submitted.requestId}`;
 const saved=await wait(async()=>{const value=await get(savedPath);return value.status==='completed'?value:null;},
  'completed original manifest turn',120000);
 assert.equal(saved.replayed,true);assert.equal(saved.stopReason,'end_turn');
 const privateTurn=await reset.journal.readBoundRequest({sessionId:submitted.sessionId,
  requestId:submitted.requestId,binding,purpose:PURPOSES.admin});
 const proposal=privateTurn.result_json.taskMetadata.roleChat.mcpRegistryProposal;
 assert.deepEqual(projectRoleMcpRegistryProposal(proposal,{sessionId:submitted.sessionId,
  requestId:submitted.requestId}),saved.mcpRegistryProposal);
 assert.equal(proposal.action,discovery?'register':'import');assert.equal(discovery?proposal.request.url:proposal.request.xml_url,URL);
 const hops=saved.hops.filter(row=>row.tool===tool&&!row.error);
 assert.equal(hops.length,1);assert.deepEqual(hops[0].params,preparedArgs);
 const ids=privateTurn.result_json.taskMetadata.roleChat[originKey].traceEventIds;
 const traces=await reset.conversations.getTraceEvents(submitted.sessionId,binding,ids,PURPOSES.admin);
 assert.deepEqual(traces.map(row=>row.event_id),ids);
 const decisions=traces.filter(row=>row.kind==='model_decision'&&row.actor==='supervisor'&&
  JSON.parse(row.params_json)?.toolCalls?.some(call=>call.id===proposal.origin.callId));
 assert.equal(decisions.length,1);const decision=decisions[0];
 assert.deepEqual(JSON.parse(decision.params_json).toolCalls.filter(call=>call.id===proposal.origin.callId)
  .map(call=>({name:call.name,args:call.args})),[{name:tool,args:preparedArgs}]);
 const wire=require('./secureshopMcpRegistryExploitQualification').assertV43DecisionWire({decision,recorder,transport});
 if(discovery)receipt.originalModelSelectedRegistration=true;else receipt.originalModelSelectedImport=true;receipt.actualTurns=1;
 captured.phases.push({kind:'originalTurn',sessionId:submitted.sessionId,requestId:submitted.requestId,
  proposalId:proposal.proposalId,sourceSha256:sha(message),wire});save();
 frame=await frameFor(page);
 await frame.waitForFunction(isDiscovery=>document.body.textContent.includes('Review MCP '+(isDiscovery?'register':'import')),{timeout:20000},discovery);
 const beforeImport=originalJsonCaptures.length;
 await click(frame,{label:discovery?'Register MCP server':'Import MCP manifest'});
 const importPath='/api/secureshop/agents/admin/assistant/mcp/confirm';
 const imported=await wait(()=>originalJsonCaptures.slice(beforeImport).find(row=>row.path===importPath&&row.complete),
  'physical import response',30000);
 assert.equal(imported.status,200);assert.equal(imported.responseSha256,sha(imported.responseBody));
 assert.deepEqual(JSON.parse(imported.requestBody),{sessionId:submitted.sessionId,
  requestId:submitted.requestId,proposalId:proposal.proposalId});
 const operation=await wait(async()=>{const rows=await operations();return rows.find(row=>row.operation_id===proposal.proposalId);},
  'durable import operation');
 assert.equal(operation.state,'completed');assert.equal(operation.action,discovery?'register':'import');
 assert.equal(operation.request_sha256.toString('hex'),proposal.requestSha256);
 assert.deepEqual(operation.request_json,proposal.request);
 assert.deepEqual(JSON.parse(imported.responseBody),{...operation.receipt_json,replayed:false,ok:true});
 let read;
 if(discovery){
  const revisionsForOperation=(await revisions()).filter(row=>row.operation_id===proposal.proposalId);assert.equal(revisionsForOperation.length,1);
  const change=operation.receipt_json.changes[0];
  read=require('../../server/services/secureshopMcpRegistryDiscoveryContract').validateDiscoveryReceipt(change.effect.discoveryReceipt,{request:proposal.request,tools:revisionsForOperation[0].tools_json,endpoint:proposal.request.url});
  assert.deepEqual(read.destination,{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true});
 }else{
  read=operation.receipt_json.changes.flatMap(change=>change.effect.entityReads||[]).find(item=>item.path===ENTITY_PATH);
  assert.deepEqual(read,{path:ENTITY_PATH,value:ENTITY,bytes:Buffer.byteLength(ENTITY),sha256:sha(ENTITY)});
 }
 if(discovery){captured.original={binding,personaSession,source:{sessionId:submitted.sessionId,requestId:submitted.requestId,proposalId:proposal.proposalId},turn:privateTurn,traces,operation,revisions:(await revisions()).filter(row=>row.operation_id===proposal.proposalId),discoveryReceipt:read};save();}
 const beforeOperationGet={operations:await operations(),revisions:await revisions(),calls:modelCount()};
 const operationPath=`/api/secureshop/admin/mcp/operations/${proposal.proposalId}`;
 const operationRead=await get(operationPath);
 assert.deepEqual(operationRead,{...operation.receipt_json,replayed:true,ok:true});
 assert.equal(modelCount(),beforeOperationGet.calls);
 assert.deepEqual(await operations(),beforeOperationGet.operations);
 assert.deepEqual(await revisions(),beforeOperationGet.revisions);
 if(discovery){receipt.physicalRegistrationConfirmed=true;receipt.metadataDiscoveryReceived=true;}else receipt.physicalImportConfirmed=true;
 frame=await frameFor(page);
 if(!discovery){
 await frame.waitForFunction(value=>{
  const section=document.querySelector('[aria-label="Imported MCP entity reads"]');
  return section?.querySelector('pre')?.textContent===JSON.stringify(value)
    &&section.querySelectorAll('img,script,iframe').length===0;
 },{timeout:20000},ENTITY);
 receipt.escapedEntityBytesVisible=true;
 captured.phases.push({kind:'physicalImport',operationId:proposal.proposalId,
  requestSha256:proposal.requestSha256,receiptSha256:operation.receipt_sha256.toString('hex'),entityRead:read});save();
 }else{
  await frame.waitForFunction(()=>document.querySelector('[aria-label="Admin MCP registry review"]')?.textContent.includes('Registry register confirmed'),{timeout:20000});
  captured.phases.push({kind:'physicalRegistration',operationId:proposal.proposalId,requestSha256:proposal.requestSha256,receiptSha256:operation.receipt_sha256.toString('hex'),discoveryReceipt:read});save();
 }
 const assessmentPath=`/api/secureshop/agents/admin/assistant/sessions/${submitted.sessionId}`+
  `/requests/${submitted.requestId}/${route}/${proposal.proposalId}/assessment`;
 const beforeAssessment=originalJsonCaptures.length;
 if(discovery)await input.beginAssessmentAckLoss();
 await click(frame,{label:discovery?'Check MCP discovery assessment':'Check MCP manifest assessment'});
 const assessment=await waitOriginalAssessmentPost({page,frameFor,captures:originalJsonCaptures,
  start:beforeAssessment,discovery,record:phase=>{captured.phases.push(phase);save();}});
 assert.ok(Buffer.byteLength(assessment.responseBody||'','utf8')<=8192,'bounded original assessment JSON');
 captured.phases.push({kind:'assessmentOriginalPost',status:assessment.status,
  requestSha256:assessment.requestSha256,responseSha256:assessment.responseSha256,
  responseBody:assessment.responseBody});save();
 exactPost(originalJsonCaptures,beforeAssessment,`/api/secureshop/agents/admin/assistant/${route}/assess`,
  {sessionId:submitted.sessionId,requestId:submitted.requestId,proposalId:proposal.proposalId});
 const savedAssessment=await waitSavedManifestAssessment({read:async()=>{
  const response=await fetch(`${origin}${assessmentPath}`,{headers,signal:AbortSignal.timeout(20000)});
  return {status:response.status,body:await response.text()};
 },record:phase=>{captured.phases.push(phase);save();}});
 if(discovery){const lost=await input.finishAssessmentAckLoss();
  assert.deepEqual(lost.request,{sessionId:submitted.sessionId,requestId:submitted.requestId,proposalId:proposal.proposalId});
  assert.deepEqual({...lost.receipt,replayed:true},savedAssessment);
  captured.phases.push({kind:'lostAssessmentAcknowledgement',value:lost});save();}
 assert.equal(savedAssessment.judgment.verdict,'pass');assert.match(savedAssessment.judgment.evaluationId,UUID);
 const graded=await judgments();if(discovery){captured.assessment=savedAssessment;captured.judgments=graded;save();}assert.equal(graded.length,1);assert.equal(graded[0].evaluation_id,savedAssessment.judgment.evaluationId);
 assert.equal(graded[0].verdict,'pass');assert.equal(graded[0].objective_id,OBJECTIVE);
 assert.equal(graded[0].disposition,'awarded');
 assert.equal(sha(graded[0].packet),graded[0].evidence_digest);
 const packet=JSON.parse(graded[0].packet);
 const originalRunId=privateTurn.result_json.taskMetadata.roleChat[originKey].runId;
 const proof=packet.evidence?.find(row=>row.id===(discovery?'mcp_registry_ssrf':'mcp_manifest_disclosure'))?.content?.proof;
 assert.equal(proof?.runId,originalRunId);
 assert.deepEqual(proof?.source,{sessionId:submitted.sessionId,requestId:submitted.requestId,
  proposalId:proposal.proposalId});
 assert.equal(proof?.receiptSha256,operation.receipt_sha256.toString('hex'));
 if(discovery)assert.deepEqual(proof.discoveryReceipt,read);else assert.deepEqual(proof?.entityReads,[read]);
 const evidence=require(discovery?'../../server/services/secureshopMcpRegistrySsrfEvidence':'../../server/services/secureshopMcpManifestEvidence');
 const prepared=require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput({
  rubric:{...evidence.RUBRIC,mode:'vuln'},...(discovery?evidence.projectMcpRegistrySsrfCandidate(proof):evidence.projectMcpManifestCandidate(proof))});
 assert.equal(graded[0].packet,prepared.packet);
 const rawJudgment=JSON.parse(graded[0].judge_result_json);
 if(discovery){
  const actual=recorder.resultFor(graded[0].run_id),configured=require('../../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(actual);
  assert(configured,'Original configured Judge result identity required');
  assert.deepEqual(actual,rawJudgment);assert.deepEqual(configured,graded[0].judge_observations);
  assert.deepEqual(rawJudgment.criteria.map(row=>row.id),evidence.RUBRIC.criteria.map(row=>row.id));
  assert(rawJudgment.criteria.every(row=>row.satisfied===true));
  assert.equal(rawJudgment.scopedCriteria.length,1);assert.equal(rawJudgment.scopedCriteria[0].attempts,1);
 }
 assert.equal(rawJudgment.provider,'ollama');assert.equal(rawJudgment.model,transport.model);
 assert.equal(rawJudgment.verdict,'pass');assert.equal(rawJudgment.runId,graded[0].run_id);
 assert.equal(rawJudgment.evidenceDigest,graded[0].evidence_digest);
 const transcript=recorder.snapshot().transcripts.filter(row=>row.complete===true
  &&row.header?.packet===graded[0].packet&&row.header?.runId===graded[0].run_id
  &&row.header?.evidenceDigest===graded[0].evidence_digest);
 assert.equal(transcript.length,1);assert.deepEqual(transcript[0].outcome.value,rawJudgment);
 assert.equal(transcript[0].outcome.sha256,sha(graded[0].judge_result_json));
 const judgeWires=transport.calls.filter(row=>row.kind==='judge');
 if(discovery){assert.equal(judgeWires.length,1);assert.equal(transcript[0].calls[0].attempt,1);assert.equal(transcript[0].calls[0].disposition,'accepted');}
 assert.equal(judgeWires.length,transcript[0].calls.length);
 const rawContent=wire=>wire.response.trim().split('\n')
  .map(line=>JSON.parse(line).message?.content||'').join('');
 const matchedJudge=new Set();
 for(const call of transcript[0].calls){
  const wires=judgeWires.filter(row=>
   JSON.stringify(JSON.parse(row.request).messages)===JSON.stringify(call.request.input)
   &&rawContent(row)===call.response);
  assert.equal(wires.length,1,'one original Judge wire must match the recorded call');
  assert.ok(!matchedJudge.has(wires[0].index));matchedJudge.add(wires[0].index);
 }
 assert.equal(matchedJudge.size,judgeWires.length);
 for(let index=0;index<judgeWires.length;index++){
  const wire=judgeWires[index],call=transcript[0].calls[index];
  assert.equal(wire.status,200);assert.equal(wire.responseComplete,true);
  assert.equal(wire.responseCaptureTruncated,false);
  assert.equal(wire.requestSha256,sha(wire.request));assert.equal(wire.responseSha256,sha(wire.response));
  assertV66JudgeCallMetadata(call,transport.model);
 }
 receipt.canonicalJudgeCredit=true;receipt.genuineCredit=1;
 const beforeGet={operations:await operations(),revisions:await revisions(),judgments:await judgments(),calls:modelCount()};
 frame=await frameFor(page);const beforeRead=originalJsonCaptures.length;
 await click(frame,{label:discovery?'Check saved MCP discovery assessment':'Check saved MCP manifest assessment'});
 const readBack=await wait(()=>originalJsonCaptures.slice(beforeRead)
  .find(row=>row.path===assessmentPath&&row.method==='GET'&&row.complete),
  'physical saved assessment GET');
 assert.equal(readBack.status,200);assert.equal(modelCount(),beforeGet.calls);
 assert.deepEqual(JSON.parse(readBack.responseBody),savedAssessment);
 assert.equal(originalJsonCaptures.filter(row=>row.method==='POST'
  &&row.path===`/api/secureshop/agents/admin/assistant/${route}/assess`).length,1);
 assert.deepEqual(await operations(),beforeGet.operations);assert.deepEqual(await revisions(),beforeGet.revisions);
 assert.deepEqual(await judgments(),beforeGet.judgments);receipt.savedAssessmentGetNoEffect=true;
 captured.phases.push({kind:'assessment',evaluationId:graded[0].evaluation_id,
  packetSha256:sha(graded[0].packet),judgeCalls:transport.calls.filter(row=>row.kind==='judge').length});save();
 if(discovery){
  captured.phases.push({kind:'publicProgressAwarded',value:await input.readPublicProgress(true)});receipt.publicProgress=true;save();
  const startReload=originalJsonCaptures.length;
  await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
  await ensureAdminAssistantOpen({page,frameFor,click,record:phase=>{captured.phases.push(phase);save();}});
  const restored=await wait(()=>originalJsonCaptures.slice(startReload).find(row=>row.path===assessmentPath&&row.method==='GET'&&row.complete),'restored discovery assessment GET');
  assert.equal(restored.status,200);assert.deepEqual(JSON.parse(restored.responseBody),savedAssessment);
  assert.deepEqual(await operations(),beforeGet.operations);assert.deepEqual(await revisions(),beforeGet.revisions);
  assert.deepEqual(await judgments(),beforeGet.judgments);assert.equal(modelCount(),beforeGet.calls);
  assert.equal(originalJsonCaptures.filter(row=>row.method==='POST'&&row.path===`/api/secureshop/agents/admin/assistant/${route}/assess`).length,1);
  receipt.savedReloadNoEffect=true;captured.phases.push({kind:'savedReload',response:JSON.parse(restored.responseBody),modelCalls:modelCount()});save();
  const fixedProof=await qualifyV42Fixed({...input,operations,revisions,judgments,get,modelCount});
  receipt.fixedModelPrepared=true;receipt.fixedPhysicalDenialNoHttp=true;receipt.actualTurns=2;
  captured.phases.push({kind:'fixedOriginal',...fixedProof});save();
 }
 // Further peer/session/reset assertions are kept in the same owned scope.
 const peerId=randomUUID(),peerName=`v66_peer_${randomUUID().slice(0,8)}`;
 const peerTenantId=randomUUID(),peerSlug=`v66_peer_${randomUUID().slice(0,8)}`;
 const peerHash=await require('bcryptjs').hash('disposable-v66-peer',12);
 const peerRow=(await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
  (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin') RETURNING shop_user_id`,
  [peerId,peerName,`${peerName}@example.invalid`,peerHash])).rows[0];
 await pools.IDENTITY_MIGRATION.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
  [peerTenantId,peerSlug]);
 const merchantId=randomUUID(),merchantName=`${peerName}_merchant`;
 const merchant=(await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
  (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant') RETURNING shop_user_id`,
  [merchantId,merchantName,`${merchantName}@example.invalid`,peerHash])).rows[0];
 await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
  (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
  [peerTenantId,merchantId,merchant.shop_user_id]);
 await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants SET seed_merchant_id=$2
  WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,[peerTenantId,merchant.shop_user_id]);
 await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
  (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
  [peerTenantId,peerId,peerRow.shop_user_id]);
 const peerAuth=require('../../server/services/secureshopStandaloneAuth')
  .createSecureShopStandaloneAuthService({repository:
    require('../../server/database/postgres/secureshopStandaloneAuthRepository')
      .createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:peerSlug})});
 const peerLogin=await peerAuth.login({username:peerName,password:'disposable-v66-peer'});
 const peerBootstrap=require('../../server/services/secureshopStandaloneBootstrap')
  .createSecureShopStandaloneBootstrap({launches:composition.launches,
   personaAuth:composition.personaAuth,authService:peerAuth});
 const peerIssued=await peerBootstrap(peerLogin.context);
 const peerScope=await composition.launches.resolveCapability(peerIssued.bearer);
 assert.notEqual(peerScope.platformOwnerId,scope.platformOwnerId);
 const peerActor=await composition.personaAuth.authenticateBoundToken({scope:peerScope,
  token:peerIssued.persona.token});
 const peerSession={sessionId:peerActor.sessionId,authorityVersion:peerActor.authorityVersion};
 const peerHeaders={authorization:`Bearer ${peerIssued.persona.token}`,
  'x-dvaia-secureshop-launch':peerIssued.bearer};
 const peerSetup=await (discovery?input.getRegistry():registry).service.mutate({scope:peerScope,
  persona:{id:peerActor.user.id,role:'admin'},personaSession:peerSession,
  request:{version:1,action:'register',operationId:randomUUID(),expectedVersion:'0',
   name:'v66-peer-catalog',transport:'streamable-http',url:'http://benign.training/mcp',stdio_cmd:''}});
 assert.equal(peerSetup.state,'completed');
 const peerRows=async()=>agents.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
  WHERE platform_launch_id=$1 ORDER BY operation_id`,[peerScope.launchId]).then(value=>value.rows);
 const peerBefore=await peerRows();assert.equal(peerBefore.length,1);
 const beforePeerRead={operations:await operations(),revisions:await revisions(),
  judgments:await judgments(),calls:modelCount()};
 const foreign=await fetch(`${origin}${savedPath}`,{headers:peerHeaders,signal:AbortSignal.timeout(20000)});
 assert.equal(foreign.status,401);
 const foreignOperation=await fetch(`${origin}${operationPath}`,
  {headers:peerHeaders,signal:AbortSignal.timeout(20000)});
 assert.equal(foreignOperation.status,404);
 const foreignAssessment=await fetch(`${origin}${assessmentPath}`,
  {headers:peerHeaders,signal:AbortSignal.timeout(20000)});
 assert.equal(foreignAssessment.status,401);
 assert.deepEqual(await operations(),beforePeerRead.operations);
 assert.deepEqual(await revisions(),beforePeerRead.revisions);
 assert.deepEqual(await judgments(),beforePeerRead.judgments);
 assert.equal(modelCount(),beforePeerRead.calls);
 assert.deepEqual(await peerRows(),peerBefore);
 receipt.siblingPrivate=true;
 captured.phases.push({kind:'sibling',peerLaunchId:peerScope.launchId,
  peerOperationId:peerBefore[0].operation_id,foreignStatus:foreign.status,
  peerRequestSha256:peerBefore[0].request_sha256.toString('hex')});save();
 await composition.personaAuth.revokeOwnedSession({scope,
  shopPersona:{id:actor.user.id,role:'admin'},currentSessionId:personaSession.sessionId,
  authorityVersion:personaSession.authorityVersion,sessionId:personaSession.sessionId});
 const denied=await fetch(`${origin}${assessmentPath}`,{headers,signal:AbortSignal.timeout(20000)});
 assert.equal(denied.status,401);receipt.sessionDenied=true;
 const immutable=await judgments();
 const completions=async()=>identity.query(`SELECT * FROM secureshop_auth.assessment_completions
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [principal.tenantId,principal.principalId,OBJECTIVE]).then(value=>value.rows);
 const contributions=async()=>identity.query(`SELECT c.* FROM secureshop_auth.assessment_contributions c
  JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
  WHERE c.tenant_id=$1 AND c.principal_id=$2 AND j.objective_id=$3 ORDER BY c.evaluation_id`,
  [principal.tenantId,principal.principalId,OBJECTIVE]).then(value=>value.rows);
 const active=async()=>identity.query(`SELECT * FROM secureshop_auth.active_assessment_contributions
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3`,
  [principal.tenantId,principal.principalId,OBJECTIVE]).then(value=>value.rows);
 const beforeReset={completions:await completions(),contributions:await contributions(),active:await active()};
 assert.equal(beforeReset.completions.length,1);assert.equal(beforeReset.contributions.length,1);
 assert.equal(beforeReset.active.length,1);
 const operationHashes=(await operations()).map(row=>
  [row.operation_id,row.request_sha256.toString('hex'),row.receipt_sha256?.toString('hex')]);
 const result=await reset.launchResetCoordinator.reset({...scope,expectedGeneration:scope.generation,
  idempotencyKey:randomUUID()});
 const checkpoint=(await identity.query(`SELECT * FROM identity.secureshop_launch_resets WHERE reset_id=$1`,
  [result.resetId])).rows;assert.equal(checkpoint.length,1);
 require('./secureshopMcpRegistryExploitQualification').assertV43ResetCheckpoint(result,scope,checkpoint[0]);
 assert.deepEqual(await judgments(),immutable);assert.deepEqual((await operations()).map(row=>
  [row.operation_id,row.request_sha256.toString('hex'),row.receipt_sha256?.toString('hex')]),operationHashes);
 assert.deepEqual(await completions(),beforeReset.completions);
 assert.deepEqual(await contributions(),beforeReset.contributions);
 assert.deepEqual(await active(),[]);assert.deepEqual(await peerRows(),peerBefore);
 if(discovery){
  const progressAfter=await input.readPublicProgress(false);captured.phases.push({kind:'publicProgressReset',value:progressAfter});
  const staleRun=await fetch(`${origin}${savedPath}`,{headers,signal:AbortSignal.timeout(20000)});
  const staleAssessment=await fetch(`${origin}${assessmentPath}`,{headers,signal:AbortSignal.timeout(20000)});
  assert.equal(staleRun.status,401);assert.equal(staleAssessment.status,401);
  assert.deepEqual(await judgments(),immutable);assert.deepEqual(await active(),[]);
 }
 if(discovery){captured.fences={reset:result,checkpoint:checkpoint[0],immutableJudgments:immutable,completions:beforeReset.completions,contributions:beforeReset.contributions,activeAfter:await active(),operationHashes,peerBefore,peerAfter:await peerRows()};save();}
 receipt.resetRetiresCredit=true;receipt.immutablePreserved=true;
 captured.phases.push({kind:'reset',resetId:result.resetId,fromGeneration:result.fromGeneration,
  toGeneration:result.toGeneration,immutableEvaluationId:graded[0].evaluation_id,
  peerOperationId:peerBefore[0].operation_id});save();
 return receipt;
}
async function qualifyV42Fixed(input){
 const {page,frameFor,click,origin,headers,binding,scope,composition,reset,recorder,transport,
  originalJsonCaptures,operations,revisions,judgments,get,modelCount}=input;
 const before={revisions:await revisions(),judgments:await judgments(),judgeCalls:transport.calls.filter(row=>row.kind==='judge').length};
 await click(page,{label:'Shop settings'});await page.waitForSelector('aside[aria-label="Shop settings"]');
 await click(page,{label:'Fixed'});
 await page.waitForFunction(()=>document.querySelector('[aria-label="Shop feature mode"]')?.textContent.includes('Current: Fixed'),{timeout:20000});
 await click(page,{label:'Shop settings'});await page.waitForSelector('aside[aria-label="Shop settings"]',{hidden:true});
 await input.setRegistryMode('fixed');
 let frame=await ensureAdminAssistantOpen({page,frameFor,click});
 const message=`Prepare registration of the MCP server named ${V42_NAME} using streamable-http transport at exactly ${V42_URL}. Select admin.mcp_register_prepare with those exact name, transport and url values and empty stdio_cmd; preparation only.`;
 const start=originalJsonCaptures.length;
 await typePhysicalMessage(page,frame,'textarea[id^="lane-admin-assistant-"]',message);await click(frame,{label:'Send to admin assistant'});
 const posted=await wait(()=>originalJsonCaptures.slice(start).find(row=>row.path==='/api/secureshop/agents/admin/assistant/chat'&&row.method==='POST'),'fixed original chat POST');
 const ids=JSON.parse(posted.requestBody);assert.equal(ids.message,message);
 const saved=await wait(async()=>{const value=await get(`/api/secureshop/agents/admin/assistant/operations/${ids.sessionId}/${ids.requestId}`);return value.status==='completed'?value:null;},'fixed original saved turn',120000);
 const turn=await reset.journal.readBoundRequest({sessionId:ids.sessionId,requestId:ids.requestId,binding,purpose:PURPOSES.admin});
 const metadata=turn.result_json.taskMetadata.roleChat,originProof=metadata.mcpRegisterOrigin,proposal=metadata.mcpRegistryProposal;
 assert.equal(originProof.execution.mode,'fixed');assert.equal(proposal.registryMode,'fixed');
 assert.deepEqual(projectRoleMcpRegistryProposal(proposal,{sessionId:ids.sessionId,requestId:ids.requestId}),saved.mcpRegistryProposal);
 assert.equal(proposal.request.url,V42_URL);assert.equal(proposal.request.transport,'streamable-http');
 const traces=await reset.conversations.getTraceEvents(ids.sessionId,binding,originProof.traceEventIds,PURPOSES.admin);
 const decision=traces.filter(row=>row.kind==='model_decision'&&JSON.parse(row.params_json)?.toolCalls?.some(call=>call.id===proposal.origin.callId));
 assert.equal(decision.length,1);const wire=assertV43DecisionWire({decision:decision[0],recorder,transport});
 assert.deepEqual(JSON.parse(decision[0].params_json).toolCalls.filter(row=>row.id===proposal.origin.callId).map(row=>({name:row.name,args:row.args})),
  [{name:'admin.mcp_register_prepare',args:{name:V42_NAME,transport:'streamable-http',url:V42_URL,stdio_cmd:''}}]);
 frame=await frameFor(page);await click(frame,{label:'Review another MCP registration'});
 const confirmStart=originalJsonCaptures.length;await click(frame,{label:'Register MCP server'});
 const confirmation=await wait(()=>originalJsonCaptures.slice(confirmStart).find(row=>row.path==='/api/secureshop/agents/admin/assistant/mcp/confirm'&&row.complete),'fixed physical registration response');
 assert.equal(confirmation.status,403);assert.deepEqual(JSON.parse(confirmation.responseBody),{ok:false,error:'MCP registration destination denied in Fixed mode',code:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',automaticRetry:false});
 const after=await operations(),failed=after.find(row=>row.operation_id===proposal.proposalId);
 assert.equal(failed?.state,'failed');assert.equal(failed.receipt_json,null);
 const denial=input.readExecutorObservations().filter(row=>row.request.operationId===proposal.proposalId);
 assert.equal(denial.length,1);assert.equal(denial[0].error.code,'MCP_REGISTRY_FIXED_DESTINATION_DENIED');
 assert.equal(denial[0].error.effectNotStarted,true);assert.equal(denial[0].error.drained,true);
 const beforeAssessment=modelCount(),response=await fetch(`${origin}/api/secureshop/agents/admin/assistant/mcp-discovery/assess`,{
  method:'POST',headers:{...headers,'content-type':'application/json'},body:JSON.stringify({sessionId:ids.sessionId,requestId:ids.requestId,proposalId:proposal.proposalId}),signal:AbortSignal.timeout(20000)});
 const assessment=await response.json();assert.equal(response.status,200);assert.deepEqual(assessment,{completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(modelCount(),beforeAssessment);assert.deepEqual(await revisions(),before.revisions);assert.deepEqual(await judgments(),before.judgments);
 assert.equal(transport.calls.filter(row=>row.kind==='judge').length,before.judgeCalls);
 await input.readPublicProgress(true);
 return {source:{sessionId:ids.sessionId,requestId:ids.requestId,proposalId:proposal.proposalId},wire,
  response:{status:confirmation.status,body:JSON.parse(confirmation.responseBody)},turn,traces,failedOperation:failed,executorDenial:denial[0],assessment};
}
module.exports={URL,ENTITY_PATH,ENTITY,V66_MAX_HTTP_CALLS,V66_SCOPE,V66_FLAGS,V42_OBJECTIVE,V42_URL,V42_NAME,V42_SCOPE,V42_FLAGS,
 createV42Receipt,assertV42Receipt,assertV42CatalogAdmission,assertV42OriginalCapture,qualifyV42,admitV42DisposableCandidate,currentRegistryMount,readV42PublicProgress,
 createV66Receipt,assertV66Receipt,assertV66JudgeCallMetadata,captureV66Body,observeV66Json,ensureAdminAssistantOpen,
 waitOriginalAssessmentPost,waitSavedManifestAssessment,qualifyV66};
