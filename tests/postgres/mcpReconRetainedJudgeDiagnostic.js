'use strict';
// Retained-packet diagnostic only: no actors, databases, completion service or credit.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const root=path.resolve(__dirname,'../..');
const nodePath='/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node',nodeSha='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861';
const PROFILES=Object.freeze({
 historical70b:Object.freeze({id:'historical70b',model:'llama3.3:70b',modelDigest:'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa',
  base:'backups/private-recovery/mcp-mounted-http/run-jnwm1qcv/',retainedVerdict:'unavailable',retainedErrorCode:'JUDGE_TIMEOUT',wireTerminal:'incomplete',evidencePrefix:'mcp-recon-judge70b-',fixedPairDigests:null,
  inputPins:Object.freeze({'canonical-mcp-http-evidence.json':'39800ee2490ec9a348d45316471349d0eeaf4450d9b3627a3785102c1993d4ad','actual-model-wire.json':'b5750b06aa6904b56698c7864eefb355a8a1651a5f48323457a9ddddafab47be'})}),
 exact8b:Object.freeze({id:'exact8b',model:'llama3.1:8b',modelDigest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
  base:'backups/private-recovery/mcp-mounted-http/run-w7t1ssk9/',retainedVerdict:'fail',retainedErrorCode:null,wireTerminal:'returned',evidencePrefix:'mcp-recon-judge8b-',
  fixedPairDigests:Object.freeze(['a31bed1791d64d5b2e765e1683f0ef252c59c88cd49f2192bf69fe08e2c4c334','b50b2acabbb4132d5f4d8502c3378661124446e5080a1efd8acf68581a2f487a']),
  inputPins:Object.freeze({'canonical-mcp-http-evidence.json':'1172b2baf2040db4ab80356520c6c4ccaeb3b8bbfd18ff1272f161d42caadbff','actual-model-wire.json':'a7f559fcbc198c7a544177843e1abe941294a44be855513609c7c795d7964936'})})
});
const sha=value=>createHash('sha256').update(value).digest('hex');
function bytes(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{assert(fs.fstatSync(fd).isFile());return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function selectProfile(id='historical70b'){assert.equal(typeof id,'string');assert(Object.hasOwn(PROFILES,id),`Unknown closed diagnostic profile: ${id}`);return PROFILES[id];}
function profileInputs(profile){return Object.fromEntries(Object.entries(profile.inputPins).map(([name,pin])=>[profile.base+name,pin]));}
function parseArgs(argv){assert(Array.isArray(argv)&&argv.length>=1,'Use --plan or --run [--judge-120] [--profile exact8b]');const action=argv[0];assert(['--plan','--run'].includes(action),'Use --plan or --run [--judge-120] [--profile exact8b]');let judge120=false,profileId='historical70b';const seen=new Set();
 for(let i=1;i<argv.length;i++){const arg=argv[i];assert(!seen.has(arg),`Duplicate option: ${arg}`);seen.add(arg);if(arg==='--judge-120'){judge120=true;continue;}assert.equal(arg,'--profile',`Unknown option: ${arg}`);assert(i+1<argv.length,'Missing --profile value');profileId=argv[++i];assert(!profileId.startsWith('--'),'Missing --profile value');}
 return {action,judge120,profile:selectProfile(profileId)};
}
function admission(profile=PROFILES.historical70b){
 assert.equal(fs.realpathSync(process.execPath),nodePath);assert.equal(sha(bytes(nodePath)),nodeSha);
 const inputs=profileInputs(profile);
 for(const [name,pin]of Object.entries(inputs))assert.equal(sha(bytes(path.join(root,name))),pin,name);
 const cases=JSON.parse(bytes(path.join(root,profile.base+'canonical-mcp-http-evidence.json'))),wire=JSON.parse(bytes(path.join(root,profile.base+'actual-model-wire.json')));
 const positive=cases.filter(x=>x.id==='recon-positive'),benign=cases.filter(x=>x.id==='recon-benign');assert.equal(positive.length,1);assert.equal(benign.length,1);assert.deepEqual(benign[0].records,[]);assert.deepEqual(benign[0].body.objectiveCandidates,[]);assert.deepEqual(benign[0].body.judgments,[]);
 assert.equal(positive[0].records.length,1);const record=positive[0].records[0],packetText=record.packet_record.packet,packet=JSON.parse(packetText);assert.equal(packet.rubric.objectiveId,'mcp_recon');assert.equal(packet.rubric.version,'mcp_owned_recon.v2');
 const original=wire.calls[5];assert.equal(original.caseId,'recon-positive');assert.equal(original.terminal,profile.wireTerminal);assert.equal(record.judgment.verdict,profile.retainedVerdict);assert.equal(record.judgment.result_json.errorCode,profile.retainedErrorCode);assert.deepEqual(positive[0].completions,[]);assert.equal(sha(original.request),original.requestSha256);assert.equal(sha(original.response),original.responseSha256);
 assert.deepEqual(JSON.parse(JSON.parse(original.request).messages[1].content),packet.evidence);
 const sources=['tests/postgres/mcpReconRetainedJudgeDiagnostic.js','tests/fixtures/mcpMountedHttpComposition.js','server/agent-runtime/objectiveJudge.js','server/agent-runtime/judgeErrors.js','server/agent-runtime/judgeExecutionTranscript.js','server/agent-runtime/sourceComparisonVerifier.js','server/services/mcpObjectiveGrader.js','server/services/mcp/timing.js','package.json','package-lock.json'];
 return {packet,packetText,record,inputs,pins:Object.fromEntries(sources.map(name=>[name,sha(bytes(path.join(root,name)))])),benign:{id:'recon-benign',retainedNoCandidate:true,canonicalPacketExists:false,calibrated:false}};
}
function successorCases(packet) {
 const {reconRubric}=require('../../server/services/mcpObjectiveGrader')._internals;
 const {NAMED_REFUSAL}=require('../fixtures/mcpMountedHttpComposition');
 assert.equal(packet.rubric.version,'mcp_owned_recon.v2');
 const positive=structuredClone(packet);positive.rubric=reconRubric(packet.rubric);
 const prior=structuredClone(positive.rubric);prior.version=packet.rubric.version;prior.criteria[0].description=packet.rubric.criteria[0].description;
 assert.deepEqual(prior,packet.rubric,'Only rubric version and concise-output guidance may change');
 assert(positive.rubric.criteria[0].description.startsWith(packet.rubric.criteria[0].description));
 assert.deepEqual(positive.evidence,packet.evidence);assert.deepEqual(positive.facts,packet.facts);
 const refusal=structuredClone(positive);assert.equal(refusal.evidence.filter(x=>x.id==='answer').length,1);
 refusal.evidence.find(x=>x.id==='answer').content=NAMED_REFUSAL;
 const restored=structuredClone(refusal);restored.evidence.find(x=>x.id==='answer').content=positive.evidence.find(x=>x.id==='answer').content;assert.deepEqual(restored,positive);
 return [{id:'retained-positive-v3',input:positive,expected:'pass',controlledAnswer:false},{id:'controlled-named-refusal-v3',input:refusal,expected:'fail',controlledAnswer:true}];
}
function diagnosticTiming(judge120=false){assert.equal(typeof judge120,'boolean');const env=judge120?{MCP_RUN_TIMEOUT_MS:'290000',MCP_RECON_JUDGE_TIMEOUT_MS:'120000'}:{};const timing=require('../../server/services/mcp/timing').createMcpReconTiming({env});return {judge120,productionJudgeTimeoutMs:timing.judgeTimeoutMs,wireMs:judge120?125000:90000,outerMs:judge120?280000:220000,productionConfig:env};}
function planCases(packet,profile){const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');const plans=successorCases(packet).map(c=>{const p=prepareJudgeInput(c.input);assert.equal(p.evidenceError,undefined);return {id:c.id,expected:c.expected,controlledAnswer:c.controlledAnswer,packet:p.packet,packetSha256:sha(p.packet),evidenceDigest:p.evidenceDigest,rubricVersion:c.input.rubric.version,input:c.input};});
 if(profile.fixedPairDigests)assert.deepEqual(plans.map(x=>x.packetSha256),profile.fixedPairDigests,'Exact-8B fixed pair drift');return plans;
}
function calibrationStatus(results,cases){assert(Array.isArray(results)&&Array.isArray(cases)&&results.length<=cases.length);if(results.some((x,index)=>x.id!==cases[index].id||x.expected!==cases[index].expected||x.result.verdict!==x.expected))return 'diagnostic-pair-not-qualified';return results.length===cases.length?'diagnostic-pair-qualified':'running';}
async function main(){
 const parsed=parseArgs(process.argv.slice(2)),profile=parsed.profile,{model,modelDigest}=profile,admitted=admission(profile),timing=diagnosticTiming(parsed.judge120);
 const {createObjectiveJudge,prepareJudgeInput,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');const prepared=prepareJudgeInput(admitted.packet);assert.equal(prepared.evidenceError,undefined);assert.equal(prepared.packet,admitted.packetText);assert.equal(prepared.evidenceDigest,admitted.record.judgment.evidence_digest);const planned=planCases(admitted.packet,profile),cases=planned.map(x=>({id:x.id,expected:x.expected,controlledAnswer:x.controlledAnswer,input:x.input})),casePlans=planned.map(({input,...row})=>row);
 const plan={diagnosticOnly:true,profile:profile.id,model,modelDigest,nodePath,nodeSha,inputPins:admitted.inputs,sourcePins:admitted.pins,packetSha256:sha(admitted.packetText),evidenceDigest:prepared.evidenceDigest,judgeVersion:JUDGE_VERSION,benign:admitted.benign,cases:casePlans,noActor:true,noDatabase:true,noCredit:true,bounds:{judgeInvocations:2,maxChatCalls:4,maxChatCallsPerCase:2,...timing,contextTokens:32768,maxOutput:900}};
 if(parsed.action==='--plan'){console.log(JSON.stringify(plan));return;}
 const evidence=fs.mkdtempSync(path.join(root,'backups/private-recovery/'+profile.evidencePrefix));fs.chmodSync(evidence,0o700);
 const state={...plan,status:'running',pid:process.pid,evidence,calls:[],invalidAttempts:[],results:[],cleanup:null};const save=()=>{const target=path.join(evidence,'result.json'),temp=target+'.tmp';fs.writeFileSync(temp,JSON.stringify(state,null,2)+'\n',{mode:0o600});fs.renameSync(temp,target);};save();
 const pending=new Set(),sockets=new Set(),controller=new AbortController(),outer=setTimeout(()=>controller.abort(new DOMException('Diagnostic outer deadline','TimeoutError')),timing.outerMs);
 const interrupted=()=>controller.abort(new DOMException('Diagnostic interrupted','AbortError'));process.once('SIGTERM',interrupted);process.once('SIGINT',interrupted);
 let activeCase=null;
 async function request(kind,payload,signal){
  assert(kind==='tags'||state.calls.filter(x=>x.kind==='judge').length<4&&state.calls.filter(x=>x.kind==='judge'&&x.caseId===activeCase).length<2,'Physical Judge call cap');assert.equal(pending.size,0,'Concurrent calls forbidden');
  const text=payload===null?'':JSON.stringify(payload);assert(Buffer.byteLength(text)<=262144);const row={index:state.calls.length,kind,caseId:activeCase,request:text,requestSha256:sha(text),status:'pending',startedAt:new Date().toISOString(),response:'',responseSha256:sha('')};state.calls.push(row);save();
  return new Promise((resolve,reject)=>{
   const abort=AbortSignal.any([controller.signal,signal||controller.signal,AbortSignal.timeout(kind==='tags'?5000:timing.wireMs)]);let settled=false;const parts=[];
   const finish=(error)=>{if(settled)return;settled=true;row.response=Buffer.concat(parts).toString('utf8');row.responseSha256=sha(row.response);row.finishedAt=new Date().toISOString();row.status=error?'incomplete':'returned';row.responseComplete=!error;if(error)row.error={name:error.name,message:error.message};save();pending.delete(req);abort.removeEventListener('abort',onAbort);error?reject(error):resolve(row.response);};
   const req=http.request({hostname:'127.0.0.1',port:11434,path:kind==='tags'?'/api/tags':'/api/chat',method:kind==='tags'?'GET':'POST',headers:kind==='tags'?{}:{'content-type':'application/json','content-length':Buffer.byteLength(text)}},response=>{
    row.httpStatus=response.statusCode;save();let size=0;response.on('data',chunk=>{parts.push(chunk);size+=chunk.length;row.response=Buffer.concat(parts).toString('utf8');row.responseSha256=sha(row.response);save();if(size>4194304)req.destroy(Error('Raw response cap'));});response.on('end',()=>finish(response.statusCode===200?null:Error('Ollama HTTP status')));response.on('aborted',()=>finish(Error('Response aborted')));response.on('error',finish);
   });const onAbort=()=>req.destroy(abort.reason);pending.add(req);req.on('socket',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});req.on('error',finish);req.on('close',()=>{if(!settled)finish(Error('Request closed before terminal'));});abort.addEventListener('abort',onAbort,{once:true});if(abort.aborted)onAbort();req.end(text);
  });
 }
 try{
  const tags=JSON.parse(await request('tags',null));assert(tags.models?.some(x=>(x.name===model||x.model===model)&&x.digest===modelDigest),'Installed selected model digest mismatch');state.installedModelVerified=true;save();
  const judge=createObjectiveJudge({timeoutMs:timing.productionJudgeTimeoutMs,contextTokens:32768,captureInvalidAttempt:async row=>{state.invalidAttempts.push({caseId:activeCase,...row});save();},model:{chat:async(messages,tools,options)=>{
   assert.deepEqual(tools,[]);assert.equal(options.temperature,0);assert.equal(options.num_ctx,32768);assert.equal(options.num_predict,900);assert.equal(options.max_tokens,900);assert(options.format);const raw=await request('judge',{model,messages,stream:true,format:options.format,options:{temperature:options.temperature,num_ctx:options.num_ctx,num_predict:options.num_predict}},options.signal);
   const rows=raw.trim().split('\n').map(line=>JSON.parse(line)),last=rows.at(-1);assert(last?.done===true&&last.done_reason==='stop');assert(rows.every(x=>x.model===model));return {provider:'ollama',model,response:rows.map(x=>x.message?.content||'').join(''),metadata:last};
  }}});
  for(const c of cases){activeCase=c.id;const result=await judge({...c.input,execution:{signal:controller.signal,runId:admitted.record.judgment.run_id}});state.results.push({id:c.id,expected:c.expected,controlledAnswer:c.controlledAnswer,result});state.status=calibrationStatus(state.results,cases);save();if(state.status==='diagnostic-pair-not-qualified')break;}
  state.status=calibrationStatus(state.results,cases);if(state.status!=='diagnostic-pair-qualified')process.exitCode=1;save();
 }catch(error){state.status='diagnostic-failed';state.error={name:error.name,message:error.message};save();process.exitCode=1;}
 finally{
  clearTimeout(outer);process.removeListener('SIGTERM',interrupted);process.removeListener('SIGINT',interrupted);for(const req of pending)req.destroy();for(const socket of sockets)socket.destroy();for(let n=0;n<100&&(pending.size||sockets.size);n++)await new Promise(resolve=>setTimeout(resolve,10));
  state.cleanup={pendingAbsent:pending.size===0,socketsAbsent:sockets.size===0,sourceUnchanged:Object.entries(admitted.pins).every(([name,pin])=>sha(bytes(path.join(root,name)))===pin)};if(Object.values(state.cleanup).some(x=>!x)){state.status='diagnostic-failed';process.exitCode=1;}save();console.log(JSON.stringify({evidence,status:state.status,verdicts:state.results.map(x=>({id:x.id,verdict:x.result.verdict})),cleanup:state.cleanup}));
 }
}
if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=1;});
module.exports={successorCases,diagnosticTiming,selectProfile,profileInputs,parseArgs,admission,planCases,calibrationStatus};
