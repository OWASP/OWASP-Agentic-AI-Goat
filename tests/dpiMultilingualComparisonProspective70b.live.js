'use strict';
// Standalone semantic calibration. No application, database, actor, or credit import.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),os=require('node:os');
const {createDpiExistentialComparison}=require('../server/agent-runtime/dpiExistentialComparison');
const ROOT=path.resolve(__dirname,'..'),CORPUS=path.join(__dirname,'fixtures/dpiMultilingualSemanticProspective-v2.json');
const CONTRACT=path.join(ROOT,'server/agent-runtime/dpiExistentialComparison.js');
const PARSER=path.join(ROOT,'server/agent-runtime/referenceComparisonVerifier.js');
const OUTPUT=path.join(ROOT,'backups/private-recovery'),MODEL='llama3.3:70b';
const DIGEST='a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa';
const PINS=new Map([[CORPUS,'336f1096b66c7993d7e5d06fdb7e2c71689a41a2f7869abdbbb35201c26ef81a'],[CONTRACT,'cb6f7c7af55872acbd84836bd4af78e74cf35a3fa2a9719350ca8a87f09407d4'],[PARSER,'477f1f4b5fbc0032cf5a6ab5650f4d2310fc04a9d27a567edda9c8f64e8a2e2b']]);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function pin(){for(const [file,hash] of PINS)assert.equal(sha(fs.readFileSync(file)),hash,`Pinned input changed: ${file}`);}
function rows(){pin();const c=JSON.parse(fs.readFileSync(CORPUS,'utf8'));assert.equal(c.version,2);assert.equal(c.objective,'multi_language');assert.equal(c.cases.length,8);assert.equal(new Set(c.cases.map(x=>x.id)).size,8);for(const x of c.cases){assert.equal(typeof x.request,'string');assert.equal(typeof x.response,'string');assert(x.request.trim()&&x.response.trim());assert(['pass','fail'].includes(x.expectedVerdict));}return c.cases;}
function comparison(row){return createDpiExistentialComparison({primary:true,objective:'multi_language',protocolVersion:'dpi-answer-comparison-v12'},[{id:'request',source:'student_input',content:row.request},{id:'response',source:'assistant_response',content:row.response}]);}
async function body(response,limit=1048576){const chunks=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.byteLength;if(bytes>limit)throw Error('HTTP response too large');chunks.push(Buffer.from(chunk));}return Buffer.concat(chunks).toString('utf8');}
function record(fd,value){fs.writeSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd);}
async function fetchBound(url,options,deadline,perCall=180000){const left=deadline-Date.now();if(left<=0)throw Error('Global deadline exceeded');return fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(Math.min(left,perCall))});}
async function main(){const cases=rows();if(process.argv.length===2){process.stdout.write(JSON.stringify({plan:true,cases:8,model:MODEL,digest:DIGEST,maxPhysicalChats:32,perChatMs:180000,globalMs:6000000,physicalMemoryBytes:os.totalmem(),maxModelBytes:45_000_000_000,outputParent:OUTPUT,pins:[...PINS].map(([file,hash])=>({path:file,sha256:hash}))})+'\n');return;}
 assert.deepEqual(process.argv.slice(2),['--run']);assert(fs.lstatSync(OUTPUT).isDirectory());const deadline=Date.now()+6000000;
 assert(os.totalmem()>=60*1024**3,'Insufficient physical memory for 70B qualification');
 const tags=await fetchBound('http://127.0.0.1:11434/api/tags',{method:'GET'},deadline,5000);assert.equal(tags.status,200);const tagsRaw=await body(tags),models=JSON.parse(tagsRaw).models?.filter(x=>x.name===MODEL);assert.equal(models?.length,1);assert.equal(models[0].digest,DIGEST);assert(Number.isSafeInteger(models[0].size)&&models[0].size<=45_000_000_000&&models[0].size+12*1024**3<os.totalmem(),'70B memory budget unsupported');pin();
 const dir=fs.mkdtempSync(path.join(OUTPUT,'dpi-multilingual-comparison-v12-70b-'));fs.chmodSync(dir,0o700);const fd=fs.openSync(path.join(dir,'wire.jsonl'),'wx',0o600);const summary={attempted:0,matches:0,falsePositive:[],falseNegative:[],inconclusive:[],unavailable:[],invalid:[],physicalChats:0};
 try{record(fd,{kind:'metadata',version:1,model:MODEL,digest:DIGEST,corpusSha256:PINS.get(CORPUS),contractSha256:PINS.get(CONTRACT),tagsRaw,startedAt:new Date().toISOString()});
 for(const row of cases){pin();const c=comparison(row),values=[],stageResults=[];let actual='unavailable',error=null;
  for(const stage of c.stages){if(stage.skip?.())break;let accepted=false,repair;
   for(let attempt=1;attempt<=2;attempt++){pin();assert(summary.physicalChats<32);const prepared=stage.messages(repair),request={model:MODEL,stream:false,messages:prepared.messages,format:prepared.format,options:{temperature:0,num_predict:900,num_ctx:32768}};const rawRequest=JSON.stringify(request);let status=null,rawResponse=null,usage=null,validation=null,wireModel=null,done=null,doneReason=null;
    try{const response=await fetchBound('http://127.0.0.1:11434/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:rawRequest},deadline);status=response.status;rawResponse=await body(response);if(status!==200)throw Error(`HTTP ${status}`);const wire=JSON.parse(rawResponse);wireModel=wire.model;done=wire.done;doneReason=wire.done_reason;usage=Object.fromEntries(['prompt_eval_count','eval_count','total_duration','load_duration','prompt_eval_duration','eval_duration'].filter(k=>wire[k]!==undefined).map(k=>[k,wire[k]]));if(wire.model!==MODEL||wire.done!==true||wire.done_reason!=='stop'||typeof wire.message?.content!=='string')throw Error('Incomplete or truncated model response');const value=stage.validate(wire.message.content);values.push(value);accepted=true;}catch(cause){validation=String(cause.message);repair=stage.repairMessage(cause);}
    summary.physicalChats++;record(fd,{kind:'stage',caseId:row.id,stage:stage.id,attempt,rawRequest,httpStatus:status,rawResponse,wireModel,done,doneReason,usage,accepted,validation,finishedAt:new Date().toISOString()});if(accepted)break;
   }stageResults.push({stage:stage.id,accepted});if(!accepted){error=`${stage.id} invalid or unavailable`;break;}
  }
  if(!error){try{actual=c.combine(...values).verdict;}catch(cause){actual='invalid';error=String(cause.message);}}
  summary.attempted++;if(actual===row.expectedVerdict)summary.matches++;else if(actual==='pass'&&row.expectedVerdict==='fail')summary.falsePositive.push(row.id);else if(actual==='fail'&&row.expectedVerdict==='pass')summary.falseNegative.push(row.id);else if(Object.hasOwn(summary,actual))summary[actual].push(row.id);else summary.invalid.push(row.id);
  record(fd,{kind:'case',id:row.id,expectedVerdict:row.expectedVerdict,actualVerdict:actual,requestSha256:sha(row.request),responseSha256:sha(row.response),stages:stageResults,error,finishedAt:new Date().toISOString()});
 }pin();record(fd,{kind:'summary',...summary,finishedAt:new Date().toISOString()});process.stdout.write(JSON.stringify({output:dir,summary})+'\n');
 }finally{fs.closeSync(fd);}
}
main().catch(error=>{process.stderr.write(String(error.stack||error)+'\n');process.exitCode=1;});
