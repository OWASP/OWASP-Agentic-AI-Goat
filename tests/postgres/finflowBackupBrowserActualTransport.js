'use strict';
const assert=require('node:assert/strict'),http=require('node:http'),path=require('node:path'),fs=require('node:fs');
const {performance}=require('node:perf_hooks'),{AsyncLocalStorage}=require('node:async_hooks'),{createHash}=require('node:crypto');
const {saveBounded}=require('../fixtures/boundedJsonArtifact');
const {createResponseCapture}=require('./secureshopMailActualTransport');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha=x=>createHash('sha256').update(x).digest('hex');
const upstreamContext=new AsyncLocalStorage(),upstreamToken=Object.freeze({});
const MCP_RECON_TIMING=Object.freeze({decisionMs:90000,responseMs:90000,runMs:290000,judgeMs:90000,caseMs:300000,refusalCaseMs:100000,wireMs:95000,totalMs:720000,childSeconds:840,parentSeconds:960,cleanupSeconds:120});
const MCP_RECON_120_TIMING=Object.freeze({...MCP_RECON_TIMING,judgeMs:120000,wireMs:125000,refusalCaseMs:130000,totalMs:750000,childSeconds:870,parentSeconds:990});
function reconTiming(reconJudge120=false,recon70b=true){assert.equal(typeof reconJudge120,'boolean');assert(!reconJudge120||recon70b===true);return reconJudge120?MCP_RECON_120_TIMING:MCP_RECON_TIMING;}
function selectedMcpModel(policyCohort,recon70b=false){assert.equal(typeof recon70b,'boolean');if(recon70b)assert.equal(policyCohort,'mcp-mounted-recon');if(policyCohort==='ea-route-actual-objective-seven-70b'){const p=require('../fixtures/excessiveAgencyActualWirePolicy').configuration(policyCohort);return {model:p.model,digest:p.digest};}return recon70b?{model:'llama3.3:70b',digest:'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'}:{model:MODEL,digest:DIGEST};}
const allowsUpstream=()=>upstreamContext.getStore()===upstreamToken;
function transportProfile(cohort,recon70b=false,reconJudge120=false){
 const timing=reconTiming(reconJudge120,recon70b);
 selectedMcpModel(cohort,recon70b);
 if(cohort==='ipi-email-trigger-actual')return {ids:['setup','clean-control','attack'],generate:0,chat:44,actor:16,judge:28,tags:1,version:0,metadata:1,external:45,overallMs:540000,perCaseChat:18,email:true};
 if(cohort==='ipi-rag-query-actual')return {ids:['owner-upload','owner-query'],generate:0,chat:14,actor:8,judge:6,tags:1,version:0,metadata:1,external:15,overallMs:540000,perCaseChat:10,rag:true};
 if(cohort==='admin-enum')return {ids:['fresh-owner-1','fresh-owner-2','fresh-owner-3','fixed'].flatMap(id=>[id+':turn-1',id+':turn-2']),generate:80,chat:16,tags:9,version:8,metadata:17,external:113,overallMs:1080000,perCaseChat:2,perCaseGenerate:10,adminEnum:true};
 if(cohort==='xss-email-builder-four-actual'){const p=require('../fixtures/xssReflectedActualWirePolicy').builderConfiguration();return {ids:p.CASES.map(x=>x.id),...p.wireBudget,overallMs:540000,perCaseChat:2,perCaseGenerate:5,builder:true};}
 if(cohort==='secureshop-registry-admin-chat')return {ids:['registered-catalog'],generate:0,chat:4,tags:1,version:0,metadata:1,external:5,overallMs:240000,perCaseChat:4,registryAdmin:true};
 if(cohort==='secureshop-registry-role-chat'){
  const overallMs=1500000,chat=53;
  // One upstream pin, initial Overview health plus its five-second polls,
  // reachability before each actor call, and four bounded UI remounts.
  const tags=1+(1+Math.ceil(overallMs/5000))+chat+4;
  return {ids:[...Array.from({length:9},(_,index)=>`registry-role-${index+1}`),'registered-vuln','registered-fixed'],generate:0,chat,tags,version:0,metadata:tags,external:chat+tags,overallMs,perCaseChat:5,registryAdmin:true,registryRoleChat:true};
 }
 if(['ea-route-actual-eight','ea-route-actual-remaining-four','ea-route-actual-objective-four','ea-route-actual-objective-seven-8b','ea-route-actual-objective-seven-70b'].includes(cohort)){const p=require('../fixtures/excessiveAgencyActualWirePolicy').configuration(cohort);return {ids:p.CASES.map(x=>'objective_'+x.id),...p.wireBudget,overallMs:900000,perCaseChat:6,ea:true,ea70b:cohort==='ea-route-actual-objective-seven-70b',wireVersion:p.PROFILE+'-wire-v1'};}
 if(['xss-reflected-three-actual','xss-reflected-r3-actual'].includes(cohort)){const p=require('../fixtures/xssReflectedActualWirePolicy').configuration(cohort);return {ids:p.CASES.map(x=>x.id),...p.wireBudget,overallMs:600000,perCaseChat:4,reflected:true};}
 if(cohort===undefined)return {ids:['admin_backup','admin_dl_backup'],generate:20,chat:4,tags:3,version:2,metadata:5,external:29,overallMs:600000,perCaseChat:2};
 if(cohort==='codebot-current-clean-fixed')return {ids:['clean_request','fixed:transform-denial'],generate:0,chat:40,tags:1,version:0,metadata:1,external:41,overallMs:360000,perCaseChat:20,codebot:true};
 if(cohort==='codebot-current-representative')return {ids:['rce_cmd','clean_request'],generate:0,chat:40,tags:1,version:0,metadata:1,external:41,overallMs:360000,perCaseChat:20,codebot:true};
 if(cohort==='codebot-current-full-six')return {ids:['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd','sibling:clean_request'],generate:0,chat:140,tags:1,version:0,metadata:1,external:141,overallMs:360000,perCaseChat:20,codebot:true};
 if(cohort==='mcp-mounted-recon')return {ids:['recon-benign','recon-positive','recon-named-refusal'],generate:2,chat:8,tags:1,version:0,metadata:1,external:11,overallMs:recon70b?timing.totalMs:600000,perCaseChat:4,perCaseGenerate:1,mcp:true,recon:true,...(recon70b?{recon70b:true,timing}:{})};
 if(cohort==='mcp-mounted-poisoning-positive')return {ids:['poisoning-positive'],generate:1,chat:6,tags:1,version:0,metadata:1,external:8,overallMs:600000,perCaseChat:6,perCaseGenerate:1,mcp:true,poisoning:true,positive:true};
 if(cohort==='mcp-mounted-poisoning-contrast')return {ids:['poisoning-clean'],generate:1,chat:4,tags:1,version:0,metadata:1,external:6,overallMs:600000,perCaseChat:4,perCaseGenerate:1,mcp:true,poisoning:true};
 if(cohort==='mcp-mounted-supply-chain')return {ids:['supply-positive','supply-benign'],generate:2,chat:20,tags:1,version:0,metadata:1,external:23,overallMs:600000,perCaseChat:10,perCaseGenerate:1,mcp:true};
 if(cohort==='mcp-mounted-http')return {ids:['sensitive-positive','sibling-benign','fixed-denial'],generate:3,chat:30,tags:1,version:0,metadata:1,external:34,overallMs:600000,perCaseChat:10,perCaseGenerate:1,mcp:true};
 assert(['plain','adversarial','traversal'].includes(cohort),'Closed qualification cohort');
 if(cohort==='traversal'){const ids=['traversal_secrets','traversal_passwd','traversal_llm'].flatMap(id=>['benign','fixed','vulnerable'].map(phase=>id+':'+phase));return {ids,generate:90,chat:18,tags:10,version:9,metadata:19,external:127,overallMs:1200000,perCaseChat:2};}
 const phases=cohort==='plain'?['normal','plain_unauthorized_request','fixed_identical_input']:['normal','ordinary_admin_request','adversarial_request','fixed_identical_input'];
 const ids=['admin_read_logs','admin_llm_logs'].flatMap(id=>phases.map(phase=>id+':'+phase));const n=ids.length;
 return {ids,generate:n*10,chat:n*2,tags:n+1,version:n,metadata:2*n+1,external:14*n+1,overallMs:n*120000+120000,perCaseChat:2};
}
function caseDeadlineFor(profile,overallDeadline,now=()=>performance.now(),caseId){if(profile.recon70b){assert(profile.recon);assert(profile.ids.includes(caseId));return Math.min(overallDeadline,now()+(caseId==='recon-named-refusal'?profile.timing.refusalCaseMs:profile.timing.caseMs));}return (profile.codebot||profile.rag||profile.email)?overallDeadline:Math.min(overallDeadline,now()+(profile.registryRoleChat?300000:120000));}
function budget(profile=transportProfile()){
 const p=profile;
 const counts={external:0,incoming:0,metadata:0,tags:0,version:0,generate:0,chat:0};
 return {counts,incoming(){assert(counts.incoming<p.external);counts.incoming++;},reserve(kind){
  assert(['tags','version','generate','chat'].includes(kind));assert(counts.external<p.external);
  if(kind==='tags')assert(counts.tags<p.tags);if(kind==='version')assert(counts.version<p.version);
  if(kind==='generate')assert(counts.generate<p.generate);if(kind==='chat')assert(counts.chat<p.chat);
  if(['tags','version'].includes(kind))assert(counts.metadata<p.metadata);else assert(counts.generate+counts.chat<p.generate+p.chat);
  counts.external++;counts[kind]++;if(['tags','version'].includes(kind))counts.metadata++;
 }};
}
const RAG_ACTOR_FORMAT = Object.freeze({ oneOf: [
  { type: 'object', properties: { action: { const: 'search_document' }, query: { type: 'string', minLength: 1, maxLength: 500 }, topK: { type: 'integer', minimum: 1, maximum: 10 } }, required: ['action', 'query', 'topK'], additionalProperties: false },
  { type: 'object', properties: { action: { const: 'answer' }, answer: { type: 'string', minLength: 1, maxLength: 8000 } }, required: ['action', 'answer'], additionalProperties: false },
] });
function ragRequestRole(value){
 assert.equal(value.options.temperature,0);
 if(value.options.num_predict===1200){assert.equal(value.options.num_ctx,undefined);assert.equal(value.messages.length,2);assert.equal(value.messages[0].role,'system');assert.equal(value.messages[1].role,'user');assert(value.messages[0].content.includes('Choose the next action for this document question.'));assert(value.messages[1].content.startsWith('Question: '));assert.deepEqual(value.format,RAG_ACTOR_FORMAT);return 'actor';}
 assert.equal(value.options.num_predict,900);assert.equal(value.options.num_ctx,32768);assert(value.format&&typeof value.format==='object'&&!Array.isArray(value.format));assert.equal(value.messages.length,2);assert.equal(value.messages[0].role,'system');assert.equal(value.messages[1].role,'user');return 'judge';
}
function emailRequestRole(value){
 const o=value.options;assert(o&&Object.keys(o).every(k=>['temperature','num_predict','num_ctx'].includes(k)));
 assert(Array.isArray(value.messages)&&value.messages.length>=2&&value.messages.every(m=>typeof m.content==='string'&&Object.keys(m).every(k=>['role','content'].includes(k))&&['system','user','assistant'].includes(m.role)));
 assert.equal(value.messages[0].role,'system');
 if(o.num_predict===128){assert.equal(o.temperature,0.2);const formats=[false,true].map(x=>require('../../server/agent-runtime/indirectEmailGraph').emailDecisionFormat(x));assert(formats.some(x=>require('node:util').isDeepStrictEqual(x,value.format)));assert(value.messages[0].content.includes(require('../../server/agent-runtime/indirectEmailGraph').EMAIL_DECISION_PROTOCOL));return 'actor';}
 if(o.num_predict===512){assert([0.3,0.7].includes(o.temperature));assert(value.format===undefined);assert(value.messages.at(-1).content.startsWith('SERVER-AUTHORED RESPONSE REQUEST:'));return 'actor';}
 assert.equal(o.temperature,0);assert.equal(o.num_ctx,32768);assert(Number.isSafeInteger(o.num_predict)&&o.num_predict>=1&&o.num_predict<=16384);assert(value.format&&typeof value.format==='object'&&!Array.isArray(value.format));assert.equal(value.messages.length,2);assert.equal(value.messages[1].role,'user');return 'judge';
}
function validateRequest(method,url,body,profile){
 if(profile?.email){
  if(method==='GET'&&url==='/api/tags'){assert.equal(body.length,0);return 'tags';}
  assert.equal(method,'POST');assert.equal(url,'/api/chat');assert(body.length>0&&body.length<=262144);const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));assert(Object.keys(v).every(k=>['model','stream','options','format','messages','tools'].includes(k)));assert(!v.tools||v.tools.length===0);emailRequestRole(v);return 'chat';
 }
 if(profile?.rag){
  if(method==='GET'&&url==='/api/tags'){assert.equal(body.length,0);return 'tags';}
  assert.equal(method,'POST');assert.equal(url,'/api/chat');assert(body.length>0&&body.length<=262144);
  const value=JSON.parse(body);assert.equal(value.model,MODEL);assert([true,false].includes(value.stream));assert(Object.keys(value).every(k=>['model','stream','options','format','messages','tools'].includes(k)));assert(!value.tools||value.tools.length===0);assert(Array.isArray(value.messages)&&value.messages.every(m=>typeof m.content==='string'&&['system','user'].includes(m.role)));assert(value.options&&Object.keys(value.options).every(k=>['temperature','num_predict','num_ctx'].includes(k)));ragRequestRole(value);return 'chat';
 }

 if(profile?.builder)return require('../fixtures/xssReflectedActualWirePolicy').validateBuilderRequest(method,url,body);
 if(profile?.registryRoleChat){
  if(method==='GET'&&url==='/api/tags'){assert.equal(body.length,0);return 'tags';}
  assert.equal(method,'POST');assert.equal(url,'/api/chat');assert(body.length>0&&body.length<=262144);
  const v=JSON.parse(body),expected=profile.roleWire;
  assert.equal(v.model,MODEL);assert.equal(v.stream,true);
  assert.deepEqual(Object.keys(v).sort(),['format','messages','model','options','stream'].sort());
  assert(!v.tools);assert.deepEqual(Object.keys(v.options).sort(),['num_ctx','num_predict','temperature'].sort());
  assert.equal(v.options.num_ctx,8192);assert.equal(v.options.temperature,0);
  assert(Number.isSafeInteger(v.options.num_predict)&&v.options.num_predict>0&&v.options.num_predict<=2048);
  if(expected){
   assert(['routeWorkflow','chat','finalResponse'].includes(expected.phase));
   if(expected.phase==='routeWorkflow'){
    assert.deepEqual(v.format,require('../../server/agent-runtime/providers/workflowRouteContract').WORKFLOW_ROUTE_SCHEMA);
    assert(v.options.num_predict<=256);
    assert.equal(v.messages.length,2);
    assert.deepEqual(v.messages.map(item=>item.role),['system','user']);
   }
   assert.deepEqual(v.format,expected.format);assert.equal(v.options.num_predict,expected.numPredict);
   assert(Array.isArray(v.messages)&&v.messages.length===expected.messages.length);
   assert.deepEqual(v.messages.map(({role,content})=>({role,content})),expected.messages);
   expected.accepted++;assert.equal(expected.accepted,1);
  }else{
   assert.deepEqual(v.format,require('../../server/services/secureshop/providers/ollamaProvider').DECISION_SCHEMA);
   assert(Array.isArray(v.messages)&&v.messages.length>0&&v.messages[0].role==='system');
   assert(v.messages.every(item=>Object.keys(item).sort().join(',')==='content,role'
    &&['system','user','assistant'].includes(item.role)&&typeof item.content==='string'));
  }
  return 'chat';
 }
 if(profile?.registryAdmin){
  if(method==='GET'&&url==='/api/tags'){assert.equal(body.length,0);return 'tags';}
  assert.equal(method,'POST');assert.equal(url,'/api/chat');assert(body.length>0&&body.length<=262144);
  const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));
  assert(Object.keys(v).every(k=>['model','stream','options','format','messages','tools'].includes(k)));
  assert.deepEqual(v.format,require('../../server/services/secureshop/providers/ollamaProvider').DECISION_SCHEMA);
  assert(!v.tools||v.tools.length===0);assert(Array.isArray(v.messages)&&v.messages.length>0);
  assert(v.options&&Object.keys(v.options).every(k=>['temperature','num_predict'].includes(k)));
  assert.equal(v.options.temperature,0);assert(Number.isSafeInteger(v.options.num_predict)&&v.options.num_predict>0&&v.options.num_predict<=2048);
  return 'chat';
 }

 if(profile?.ea)return require('../fixtures/excessiveAgencyActualWirePolicy').validateRequest(method,url,body,profile.ea70b?'ea-route-actual-objective-seven-70b':profile.wireVersion==='ea-route-actual-objective-seven-8b-wire-v1'?'ea-route-actual-objective-seven-8b':undefined);
 if(profile?.reflected)return require('../fixtures/xssReflectedActualWirePolicy').validateRequest(method,url,body);
 if(profile?.codebot)return require('../fixtures/codeBotCurrentWirePolicyV2').validateRequest(method,url,body);
 if(profile?.mcp)return require('../fixtures/mcpMountedHttpWirePolicy').validateRequest(method,url,body,profile);
 if(method==='GET'&&['/api/tags','/api/version'].includes(url)){assert.equal(body.length,0);return url==='/api/tags'?'tags':'version';}
 assert.equal(method,'POST');assert(['/api/generate','/api/chat'].includes(url));assert(body.length>0&&body.length<=262144);const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));
 const keys=['model','stream','options','format',...(url==='/api/chat'?['messages','tools']:['prompt','system','template','raw','keep_alive'])];assert(Object.keys(v).every(k=>keys.includes(k)));assert(v.options&&typeof v.options==='object'&&!Array.isArray(v.options));const o=v.options;assert(Object.keys(o).every(k=>['temperature','num_predict','num_ctx','top_p','top_k','stop'].includes(k)));if(url==='/api/generate'){assert.equal(o.num_ctx,8192);assert((o.temperature===0&&o.num_predict===400&&v.format==='json')||([0.3,0.1].includes(o.temperature)&&o.num_predict===700));}else{assert.equal(o.temperature,0);assert.equal(o.num_predict,900);assert.equal(o.num_ctx,32768);assert(v.format&&typeof v.format==='object');assert(!v.tools||v.tools.length===0);}if(o.top_p!==undefined)assert(Number.isFinite(o.top_p)&&o.top_p>=0&&o.top_p<=1);if(o.top_k!==undefined)assert(Number.isInteger(o.top_k)&&o.top_k>=0&&o.top_k<=100);if(o.stop!==undefined)assert(Array.isArray(o.stop)&&o.stop.length<=8&&o.stop.every(x=>typeof x==='string'&&Buffer.byteLength(x)<=128));
 if(url==='/api/chat')assert(Array.isArray(v.messages)&&v.messages.length);else assert.equal(typeof v.prompt,'string');
 return url==='/api/chat'?'chat':'generate';
}
function registryRoleRejection(error,{method,url,body,roleWire,activeCase}){
 const frame=String(error?.stack||'').split('\n').map(line=>line.match(/(?:\/|\\)([A-Za-z0-9_.-]+\.(?:js|mjs)):(\d+):(\d+)/))
  .find(Boolean);
 let request={method:typeof method==='string'&&/^[A-Z]{1,8}$/.test(method)?method:'unknown',
  path:url==='/api/chat'||url==='/api/tags'?url:'other',bytes:Buffer.isBuffer(body)?body.length:0};
 try{
  const value=JSON.parse(body);
  if(value&&typeof value==='object'&&!Array.isArray(value)){
   const options=value.options&&typeof value.options==='object'&&!Array.isArray(value.options)?value.options:{};
   const topKeys=Object.keys(value),optionKeys=Object.keys(options);
   request={...request,keys:topKeys.filter(key=>['model','stream','options','format','messages','tools'].includes(key)).sort(),
    unknownKeys:topKeys.filter(key=>!['model','stream','options','format','messages','tools'].includes(key)).length,
    optionKeys:optionKeys.filter(key=>['temperature','num_predict','num_ctx'].includes(key)).sort(),
    unknownOptionKeys:optionKeys.filter(key=>!['temperature','num_predict','num_ctx'].includes(key)).length,
    numCtx:Number.isSafeInteger(options.num_ctx)?options.num_ctx:null,
    numPredict:Number.isSafeInteger(options.num_predict)?options.num_predict:null,
    temperature:typeof options.temperature==='number'&&Number.isFinite(options.temperature)?options.temperature:null,
    formatSha256:value.format===undefined?null:sha(JSON.stringify(value.format)),
    messagesSha256:Array.isArray(value.messages)?sha(JSON.stringify(value.messages)):null,
    messageRoles:Array.isArray(value.messages)?value.messages.slice(0,16).map(item=>
     ['system','user','assistant','tool'].includes(item?.role)?item.role:'other'):[],
    messageCount:Array.isArray(value.messages)?value.messages.length:null};
  }
 }catch{/* Invalid JSON is only a structural fact. */}
  return {code:'REQUEST_DENIED_OR_INCOMPLETE',name:/^[A-Za-z]{1,40}$/.test(error?.name||'')?error.name:'Error',
  errorCode:/^[A-Z0-9_]{1,60}$/.test(error?.code||'')?error.code:null,
  assertionFrame:frame?{file:frame[1],line:Number(frame[2]),column:Number(frame[3])}:null,
  activeCase:/^(?:registry-role-[1-9]|registered-(?:vuln|fixed))$/.test(activeCase||'')?activeCase:null,
  request,expected:roleWire?{phase:roleWire.phase,formatSha256:sha(JSON.stringify(roleWire.format)),
   messagesSha256:sha(JSON.stringify(roleWire.messages)),numPredict:roleWire.numPredict,
   accepted:roleWire.accepted}:null};
}
function validateResponse(row,{recon70b=false,ea70b=false}={}) {
  const selected=selectedMcpModel(ea70b?'ea-route-actual-objective-seven-70b':recon70b?'mcp-mounted-recon':undefined,recon70b);
  assert.equal(row.status, 200); assert.equal(row.responseComplete, true); assert.equal(row.responseCaptureTruncated, false);
  assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);
  if (row.kind === 'version') {
    const v=JSON.parse(row.response);assert(v&&typeof v.version==='string'&&/^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$/.test(v.version));
  } else if (row.kind === 'tags') {
    assert.ok(JSON.parse(row.response).models?.some(value => (value.name === selected.model || value.model === selected.model) && value.digest === selected.digest));
  } else {
    const frames = row.response.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(frames.length); assert.equal(frames.at(-1).done, true); assert.equal(frames.at(-1).done_reason, 'stop');
    assert.ok(frames.every(frame => !frame.error && frame.model === selected.model));
    if(['codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'].includes(row.profile))require('../fixtures/codeBotCurrentWirePolicyV2').validateToolFrames(frames,row);else assert.ok(frames.every(frame=>!frame.tool_calls&&!frame.message?.tool_calls));
    if(row.kind==='generate')assert(frames.every(f=>typeof f.response==='string'));else assert(frames.every(f=>f.message&&typeof f.message.content==='string'));
    assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);
  }
}
function validateTimedResponse(row, deadline, now = () => performance.now(),selection={}) {
  assert.ok(now() < deadline, 'Absolute wire deadline');
  validateResponse(row,selection);
  assert.ok(now() < deadline, 'Absolute wire deadline after parsing');
}
async function closeOwned(resources, servers, timeoutMs = 5000) {
  const waiting = resources.map(resource => new Promise(resolve => resource.once('close', resolve)));
  for (const resource of resources) resource.destroy();
  waiting.push(...servers.map(server => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
  let timer; try {
    await Promise.race([Promise.all(waiting), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Physical close deadline')), timeoutMs); })]);
  } finally { clearTimeout(timer); }
}
function assertDispatchDeadline(deadline,now=()=>performance.now()){assert(now()<deadline,'Absolute deadline before upstream dispatch');}
function serializedBytes(value){
 if(value===null||typeof value!=='object')return Buffer.byteLength(JSON.stringify(value));
 if(Array.isArray(value))return 2+Math.max(0,value.length-1)+value.reduce((n,x)=>n+serializedBytes(x),0);
 const entries=Object.entries(value);return 2+Math.max(0,entries.length-1)+entries.reduce((n,[k,v])=>n+Buffer.byteLength(JSON.stringify(k))+1+serializedBytes(v),0);
}
function saveWire(file,value){const next=serializedBytes(value)+1,old=fs.existsSync(file)?fs.statSync(file).size:0;assert(old+next<=64*1024*1024,'Aggregate wire and atomic temporary ceiling');saveBounded(file,value);}
async function createTransport({ evidence, policyCohort,recon70b=false,reconJudge120=false }) {
  const selected=selectedMcpModel(policyCohort,recon70b);
  const profile=transportProfile(policyCohort,recon70b,reconJudge120);
  const calls = [], failures = [], sockets = new Set(), upstreams = new Set(), servers = [];
  const limits = budget(profile); let closing = false, activeCase = null, caseDeadline = null, caseCounts = null, roleWire = null; const overallDeadline = performance.now() + profile.overallMs;
  function checkpoint() { saveWire(path.join(evidence, 'actual-model-wire.json'), { ...((profile.reflected||profile.builder||profile.adminEnum||profile.rag||profile.email)?{profile:policyCohort}:{}), version: profile.registryAdmin?policyCohort+'-wire-v1':profile.ea?profile.wireVersion:(profile.reflected||profile.builder||profile.adminEnum||profile.rag||profile.email)?policyCohort+'-wire-v1':policyCohort==='codebot-current-clean-fixed'?'codebot-current-clean-fixed-wire-v1':policyCohort==='codebot-current-full-six'?'codebot-current-full-six-wire-v1':policyCohort==='codebot-current-representative'?'codebot-current-wire-v1':['mcp-mounted-http','mcp-mounted-supply-chain','mcp-mounted-poisoning-contrast','mcp-mounted-poisoning-positive','mcp-mounted-recon'].includes(policyCohort)?policyCohort+'-wire-v1':policyCohort==='traversal'?'finflow-traversal-wire-v1':policyCohort?'finflow-policy-wire-v1':'finflow-backup-browser-wire-v1', model: selected.model, digest: selected.digest, ...(recon70b?{timing:profile.timing}:{}), counts: limits.counts, calls, failures, physicalPending: sockets.size + upstreams.size, closed: closing && !sockets.size && !upstreams.size }); }
  function forward(kind, method, pathname, body, downstream) {
    assert.equal(failures.length,0,'Previous transport failure');
    if(!['tags','version'].includes(kind)){assert(caseCounts);assert(caseCounts[kind] < (kind==='generate'?(profile.perCaseGenerate||10):profile.perCaseChat));caseCounts[kind]++;}
    limits.reserve(kind); if(!['tags','version'].includes(kind)) assert.ok(activeCase && performance.now() < caseDeadline && performance.now() < overallDeadline, 'Case admission deadline');
    const row = { ...((profile.codebot||profile.reflected||profile.builder||profile.adminEnum||profile.rag||profile.email)?{profile:policyCohort}:{}), ...(profile.email&&kind==='chat'?{role:emailRequestRole(JSON.parse(body))}:{}), ...(profile.rag&&kind==='chat'?{role:ragRequestRole(JSON.parse(body))}:{}), ...(profile.ea&&kind==='chat'?{role:require('../fixtures/excessiveAgencyActualWirePolicy').requestRole(JSON.parse(body))}:{}), index: calls.length, kind, caseId: activeCase, method, path: pathname, requestBytes: body.length, requestSha256: sha(body), request: body.toString(), terminal: 'pending' };
    const deadline = Math.min(overallDeadline, ['tags','version'].includes(kind) ? performance.now()+5000 : Math.min(caseDeadline,performance.now()+(profile.recon70b?profile.timing.wireMs:profile.codebot&&JSON.parse(body).options.num_predict===1024?120000:90000))); 
    calls.push(row); checkpoint();
    return new Promise((resolve, reject) => {
      let timer, settled = false;
      const capture = createResponseCapture(row);
      const finish = (error) => { if (settled) return; settled = true; if (error) { row.terminal = 'incomplete'; failures.push({ index: row.index, code: 'WIRE_INCOMPLETE' }); } else row.terminal = 'returned'; checkpoint(); error ? reject(error) : resolve(row); };
      try { assertDispatchDeadline(deadline); } catch(error) { finish(error); return; }
      const upstream = upstreamContext.run(upstreamToken, () => http.request({ hostname: '127.0.0.1', port: 11434, path: pathname, method, headers: { 'content-type': 'application/json', 'content-length': body.length } }, response => {
        capture.headers(response.statusCode);
        downstream?.writeHead(response.statusCode, { 'content-type': response.headers['content-type'] || 'application/json' });
        response.on('data', chunk => { if (!capture.data(chunk)) { upstream.destroy(Error('Bounded response')); return; } downstream?.write(chunk); });
        response.on('end', () => { capture.finish(true, 'end'); try { validateTimedResponse(row, deadline,undefined,{recon70b,ea70b:profile.ea70b}); downstream?.end(); finish(); } catch (error) { upstream.destroy(error); downstream?.destroy(); finish(error); } });
        response.on('aborted', () => { capture.finish(false, 'aborted'); finish(Error('Aborted response')); });
        response.on('error', error => { capture.finish(false, 'error'); finish(error); });
      }));
      upstreams.add(upstream);
      timer = setTimeout(() => upstream.destroy(Error('Wire deadline')), Math.max(1,deadline-performance.now()));
      upstream.once('close', () => { clearTimeout(timer); upstreams.delete(upstream); capture.finish(false, 'closed'); if (!settled) finish(Error('Incomplete close')); });
      upstream.once('error', error => { capture.finish(false, 'error'); downstream?.destroy(); finish(error); });
      downstream?.once('close', () => { if (!downstream.writableFinished) upstream.destroy(Error('Consumer closed')); });
      upstream.end(body);
    });
  }
  async function listen(kind) {
    const server = http.createServer(async (req, res) => {
      let body=Buffer.alloc(0);
      let timer; try {
        limits.incoming(); assert.ok(!closing); timer = setTimeout(() => req.destroy(), 5000);
        const chunks = []; let bytes = 0;
        for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 262144); chunks.push(chunk); }
        clearTimeout(timer); body = Buffer.concat(chunks);
        const requested = validateRequest(req.method, req.url, body,{...profile,recon70b,roleWire});
        if(profile.builder&&['chat','generate'].includes(requested)){assert(caseCounts);if(requested==='chat'){assert(caseCounts.judge<2);caseCounts.judge++;}else{const html=JSON.parse(body).options.num_predict===1000;const key=html?'html':'decision';caseCounts[key] ||= 0;assert(caseCounts[key]<(html?1:4));caseCounts[key]++;}}
        if(profile.email&&requested==='chat'){const role=emailRequestRole(JSON.parse(body));assert(caseCounts);const cap=role==='actor'?(activeCase==='setup'?0:8):(activeCase==='setup'?8:10);assert(caseCounts[role]<cap);assert(calls.filter(r=>r.role===role).length<(role==='actor'?16:28));caseCounts[role]++;}
        if(profile.rag&&requested==='chat'){const role=ragRequestRole(JSON.parse(body));assert(caseCounts);const cap=role==='actor'?(activeCase==='owner-query'?8:0):(activeCase==='owner-upload'?4:2);assert(caseCounts[role]<cap);assert(calls.filter(r=>r.role===role).length<(role==='actor'?8:6));caseCounts[role]++;}
        if(profile.ea&&requested==='chat'){const role=require('../fixtures/excessiveAgencyActualWirePolicy').requestRole(JSON.parse(body));assert(caseCounts);assert(caseCounts[role]<(role==='actor'?4:2));caseCounts[role]++;}
        if(profile.reflected&&requested==='chat'){const role=require('../fixtures/xssReflectedActualWirePolicy').requestRole(JSON.parse(body));assert(caseCounts);assert(caseCounts[role]<2);caseCounts[role]++;}
        if(profile.codebot&&requested==='chat'){const role=require('../fixtures/codeBotCurrentWirePolicyV2').requestRole(JSON.parse(body));assert(caseCounts);assert(caseCounts[role]<(role==='actor'?8:12));caseCounts[role]++;}
        if(profile.mcp&&!(['tags','version'].includes(requested))){const role=require('../fixtures/mcpMountedHttpWirePolicy').requestRole(req.url,JSON.parse(body));assert(caseCounts);if(profile.recon){assert(role==='actor'||role==='judge'||role==='phrase');if(activeCase==='recon-named-refusal')assert.equal(role,'judge');if(activeCase==='recon-benign')assert.notEqual(role,'judge');assert(caseCounts[role]<(role==='phrase'?1:2));}assert(caseCounts[role]<(profile.poisoning?(role==='actor'||role==='observed'?2:role==='phrase'?1:profile.positive&&role==='judge'?2:0):(role==='actor'?8:role==='judge'?2:1)));caseCounts[role]++;}
        await forward(requested, req.method, req.url, body, res);
      } catch(error) { failures.push(profile.registryRoleChat
       ?registryRoleRejection(error,{method:req.method,url:req.url,body,roleWire,activeCase})
       :{code:'REQUEST_DENIED_OR_INCOMPLETE'});
       if (!res.headersSent) res.writeHead(503); res.end(); checkpoint(); }
      finally { clearTimeout(timer); }
    });
    server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    servers.push(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    return `http://127.0.0.1:${server.address().port}`;
  }
  async function close() {
    closing = true;
    try {
      await closeOwned([...upstreams, ...sockets], servers);
      assert.equal(upstreams.size + sockets.size, 0);
    } finally { checkpoint(); }
  }

  try {
    await forward('tags', 'GET', '/api/tags', Buffer.alloc(0));
    const actorUrl = await listen('generate');
    const used = new Set();
    return {model:selected.model,digest:selected.digest,recon70b,reconJudge120, actorUrl, judgeUrl: actorUrl, close,
      beginRoleWire(expected){assert(profile.registryRoleChat&&activeCase?.startsWith('registry-role-')&&!roleWire);
        assert.deepEqual(Object.keys(expected).sort(),['format','messages','numPredict','phase'].sort());
        assert(['routeWorkflow','chat','finalResponse'].includes(expected.phase));
        roleWire={...structuredClone(expected),accepted:0};return roleWire;},
      endRoleWire(expected){assert.equal(roleWire,expected);assert.equal(roleWire.accepted,1);roleWire=null;},
      beginCase(id) { assert.equal(activeCase,null);assert.equal(roleWire,null); assert.equal(id,profile.ids[used.size]); assert.ok(!used.has(id)); used.add(id); activeCase=id; caseCounts={generate:0,chat:0,actor:0,observed:0,judge:0,phrase:0}; caseDeadline=caseDeadlineFor(profile,overallDeadline,undefined,id); }, endCase(){ assert.ok(activeCase);assert.equal(roleWire,null); assert.ok(performance.now()<caseDeadline); activeCase=null; caseDeadline=null; caseCounts=null; }, snapshot(){return {counts:{...limits.counts},calls:structuredClone(calls),failures:structuredClone(failures)};}, assertComplete() { assert.equal(failures.length, 0); assert.equal(activeCase,null);assert.equal(roleWire,null); assert.equal(used.size,profile.ids.length); for (const row of calls) validateResponse(row,{recon70b,ea70b:profile.ea70b}); } };
  } catch (error) { try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], 'Transport setup/cleanup failed'); } throw error; }
}
module.exports={reconTiming,MCP_RECON_120_TIMING,MCP_RECON_TIMING,selectedMcpModel,emailRequestRole,RAG_ACTOR_FORMAT,ragRequestRole,caseDeadlineFor,transportProfile,createTransport,allowsUpstream,validateRequest,registryRoleRejection,validateResponse,validateTimedResponse,budget,assertDispatchDeadline,serializedBytes,closeOwned,MODEL,DIGEST};
