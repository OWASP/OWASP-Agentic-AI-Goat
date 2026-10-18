'use strict';
// Provider conformance only: no agent, corpus, grading, or production imports.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..'),INPUT='tests/release-inputs/ollama-root-ref-conformance-input-v1.json',INPUT_SHA='313bd79ee27962bdfd38ec96f92f4037794c82dd857050c7539f83e3ea79abd6';
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',MAX=262144;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
function save(dir,value){const p=path.join(dir,'result.json'),tmp=p+'.tmp';fs.writeFileSync(tmp,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});fs.renameSync(tmp,p);}
function createWire({request=http.request,clock=()=>performance.now()}={}){
 let calls=0,stopped=false;const sockets=new Set(),requests=new Set();
 async function call(endpoint,body,deadline,row){
  if(stopped)throw fail('CANCELLED');
  assert((calls===0&&endpoint==='/api/tags'&&!body)||(calls>0&&calls<3&&endpoint==='/api/chat'&&body));calls++;
  row.request=body||'';row.requestSha256=sha(row.request);row.status='pending';let req,res,timer;const chunks=[];let size=0;
  try{await new Promise((resolve,reject)=>{
   const remaining=deadline-clock();if(remaining<=0)return reject(fail('DEADLINE'));
   req=request({hostname:'127.0.0.1',port:11434,path:endpoint,method:body?'POST':'GET',agent:false,headers:body?{'content-type':'application/json','content-length':Buffer.byteLength(body)}:{}},value=>{
    res=value;row.httpStatus=res.statusCode;res.on('data',chunk=>{size+=chunk.length;if(size>MAX){req.destroy(fail('RESPONSE_LIMIT'));return;}chunks.push(Buffer.from(chunk));});
    res.once('error',reject);res.once('aborted',()=>reject(fail('RESPONSE_ABORTED')));res.once('end',()=>{if(clock()>=deadline)return reject(fail('DEADLINE'));resolve();});
   });requests.add(req);req.once('close',()=>requests.delete(req));req.once('socket',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});req.once('error',reject);
   timer=setTimeout(()=>req.destroy(fail('DEADLINE')),remaining);req.end(body||undefined);
  });if(row.httpStatus!==200)throw fail('HTTP_STATUS');row.status='complete';}
  catch(error){row.status='incomplete';row.errorCode=['DEADLINE','RESPONSE_LIMIT','HTTP_STATUS','RESPONSE_ABORTED'].includes(error.code)?error.code:'HTTP_FAILURE';throw error;}
  finally{clearTimeout(timer);req?.destroy();res?.destroy();const raw=Buffer.concat(chunks);row.rawResponse=raw.toString('utf8');row.responseSha256=sha(raw);row.responseBytes=raw.length;row.observedBytes=size;}
  return row.rawResponse;
 }
 async function close(){const deadline=clock()+5000;while(sockets.size&&clock()<deadline)await new Promise(r=>setTimeout(r,10));return {localSockets:sockets.size,localSocketsClosed:sockets.size===0,remoteInferenceSettled:null};}
 return {call,close,abort(){stopped=true;for(const req of requests)req.destroy(fail('CANCELLED'));}};
}
function decode(raw){const frames=raw.trim().split('\n').map(JSON.parse);assert(frames.length);for(const [i,f]of frames.entries()){assert.equal(f.model,MODEL);assert(!f.error&&!f.message?.tool_calls);assert.equal(f.message?.role,'assistant');assert.equal(typeof f.message.content,'string');assert.equal(f.done,i===frames.length-1);}assert(['stop','length'].includes(frames.at(-1).done_reason));return {text:frames.map(f=>f.message.content).join(''),termination:frames.at(-1).done_reason,frames:frames.length};}
async function runPair(input,{wire,record=()=>{},clock=()=>performance.now()}={}){
 const Ajv=require('ajv'),ajv=new Ajv({strict:false}),state={purpose:'provider-conformance-not-agent-proof',status:'running',calls:[],cases:[],remoteInferenceSettled:null};const until=clock()+50000;
 try{const metadata={kind:'metadata'};state.calls.push(metadata);record(state);const tags=JSON.parse(await wire.call('/api/tags',null,Math.min(until,clock()+5000),metadata));assert(tags.models.some(x=>(x.name===MODEL||x.model===MODEL)&&x.digest===DIGEST));record(state);
  for(const key of ['rootRef','inlineRoot']){const row={kind:'chat',schema:key};state.calls.push(row);record(state);const body=JSON.stringify({model:MODEL,messages:input.messages,stream:true,format:input.schemas[key],options:{temperature:0,num_predict:128,num_ctx:32768}});const decoded=decode(await wire.call('/api/chat',body,Math.min(until,clock()+20000),row));const item={schema:key,termination:decoded.termination,frames:decoded.frames,schemaValid:false,jsonValid:false};state.cases.push(item);try{const value=JSON.parse(decoded.text);item.jsonValid=true;const validate=ajv.compile(input.schemas[key]);item.schemaValid=validate(value);item.errors=(validate.errors||[]).map(e=>({keyword:e.keyword,instancePath:e.instancePath}));}catch{item.errorCode='INVALID_JSON';}record(state);}
  state.status='complete';
 }catch{state.status='incomplete';state.failureCode='CONFORMANCE_INCOMPLETE';}
 finally{state.cleanup=await wire.close();if(!state.cleanup.localSocketsClosed)state.status='incomplete';record(state);}return state;
}
async function gate(stream=process.stdin){await new Promise((resolve,reject)=>{let b='';const timer=setTimeout(()=>done(fail('RELEASE_TIMEOUT')),5000);function done(e){clearTimeout(timer);stream.removeListener('data',data);stream.removeListener('end',end);stream.removeListener('error',done);e?reject(e):resolve();}function data(x){b+=x;if(b!=='1')done(fail('RELEASE_INVALID'));}function end(){done(b==='1'?null:fail('RELEASE_INVALID'));}stream.on('data',data);stream.once('end',end);stream.once('error',done);stream.resume();});}
function admit(env){assert.equal(env.OLLAMA_CONFORMANCE_NATIVE,'1');const input=fs.readFileSync(path.join(ROOT,INPUT));assert.equal(sha(input),INPUT_SHA);const out=env.OLLAMA_CONFORMANCE_OUTPUT;assert.equal(fs.realpathSync(out),out);assert.equal(path.dirname(path.dirname(out)),path.join(ROOT,'backups/private-recovery/ollama-conformance'));assert.equal(path.basename(out),'results');const stat=fs.lstatSync(out);assert(stat.isDirectory()&&stat.uid===process.getuid()&&(stat.mode&511)===448);const journal=JSON.parse(fs.readFileSync(path.join(out,'../ownership.json')));assert.equal(journal.nativePid,process.pid);assert.equal(journal.parentPid,process.ppid);assert.equal(journal.nativeStarted,true);assert.equal(journal.evidenceRoot,path.dirname(out));const raw=fs.readFileSync(env.OLLAMA_CONFORMANCE_MANIFEST);assert.equal(sha(raw),env.OLLAMA_CONFORMANCE_MANIFEST_SHA256);assert.equal(journal.manifestSha256,sha(raw));const m=JSON.parse(raw);assert.equal(m.root,ROOT);assert.equal(m.node.path,fs.realpathSync(process.execPath));assert.equal(m.node.sha256,sha(fs.readFileSync(process.execPath)));for(const f of m.files){assert(!path.isAbsolute(f.path)&&!f.path.split('/').includes('..'));const p=path.join(ROOT,f.path);assert.equal(fs.realpathSync(p),p);assert.equal(sha(fs.readFileSync(p)),f.sha256);}return {input:JSON.parse(input),out};}
module.exports={createWire,decode,runPair,gate,admit,INPUT,INPUT_SHA};
if(require.main===module)gate().then(()=>{const {input,out}=admit(process.env);const wire=createWire(),stop=()=>wire.abort();process.on('SIGTERM',stop);process.on('SIGINT',stop);return runPair(input,{wire,record:s=>save(out,s)}).finally(()=>{process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);});}).then(s=>{if(s.status!=='complete')process.exitCode=1;}).catch(()=>{process.exitCode=1;});
