'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const sha=x=>createHash('sha256').update(x).digest('hex');
function validateUrls(env,port){
 assert(Number.isInteger(port)&&port>0&&port<65536);
 for(const store of ['IDENTITY','CTF'])for(const role of ['RUNTIME','MIGRATION']){
  const u=new URL(env[`PG_CTF_STAGE9_${store}_${role}_URL`]);
  assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(Number(u.port),port);
  assert.equal(u.pathname,`/owasp_ai_goat_test_ctf_stage9_${store.toLowerCase()}`);assert.equal(u.username,`dvaia_${store.toLowerCase()}_${role.toLowerCase()}`);assert.equal(u.password+u.search+u.hash,'');
 }
 const d=new URL(env.PG_CTF_STAGE9_CTF_DELIVERY_URL),c=new URL(env.PG_CTF_STAGE9_CTF_RUNTIME_URL);
 assert.equal(d.protocol,'postgresql:');assert.equal(d.host,c.host);assert.equal(d.pathname,c.pathname);assert.equal(d.username,'dvaia_ctf_delivery');assert.equal(d.password+d.search+d.hash,'');
}
function read(file,max){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const a=fs.fstatSync(fd);assert(a.isFile()&&a.uid===process.getuid()&&a.nlink===1&&(a.mode&0o077)===0&&a.size<=max);const b=fs.readFileSync(fd),z=fs.fstatSync(fd);assert.equal(b.length,a.size);assert.equal(z.mtimeMs,a.mtimeMs);return b;}finally{fs.closeSync(fd);}}
function admit(env=process.env){
 assert.equal(env.CTF_STAGE9_MAIN_ISOLATED,'1');assert.equal(env.PG_TEST_DISPOSABLE,'yes');const mode=env.CTF_STAGE9_MODE||'controlled';assert(['controlled','actual','stage6-actual'].includes(mode));
 const source=path.resolve(__dirname,'../..'),evidence=env.CTF_STAGE9_EVIDENCE_ROOT;
 assert.equal(fs.realpathSync(evidence),evidence);assert.equal(path.dirname(evidence),source+'/backups/private-recovery/'+(mode==='stage6-actual'?'ctf-stage6-authority':'ctf-stage9'));
 const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700);
 const j=JSON.parse(read(path.join(evidence,'ownership.json'),65536));assert.equal(j.cohort,mode==='stage6-actual'?'ctf-stage6-authority-main':'ctf-stage9-main');assert.equal(j.owner,env.CTF_STAGE9_OWNER);assert.equal(j.sourceRoot,source);assert.equal(j.nativePid,process.pid);assert.equal(j.parentPid,process.ppid);assert.equal(j.nativeStarted,true);assert.equal(process.cwd(),path.join(evidence,'runtime'));validateUrls(env,j.databasePort);
 const bytes=read(env.CTF_STAGE9_MANIFEST,32*1024*1024);assert.equal(sha(bytes),env.CTF_STAGE9_MANIFEST_SHA256);const m=JSON.parse(bytes);assert.equal(m.workspace,source);assert.equal(m.cohort,j.cohort);
 const assertLoaded=()=>{for(const file of Object.keys(require.cache)){assert(file.startsWith(source+'/'));const rel=path.relative(source,file).split(path.sep).join('/'),pin=rel.startsWith('node_modules/')?m.dependencyInventory[rel.slice(13)]?.sha256:m.sourcePins[rel];assert.equal(sha(fs.readFileSync(file)),pin,'Unpinned loaded module: '+rel);}};assertLoaded();let input=null;if(mode==='actual'){assert.equal(env.CTF_STAGE9_INPUT_SHA256,'698f21f2d8adb4660c606545a7e4f6faf976ca2bdeaa1720bf71780f98e89cae');assert.equal(env.CTF_STAGE9_INPUT,path.join(source,'tests/release-inputs/ctf-stage9-actual-frozen-inputs.json'));const raw=read(env.CTF_STAGE9_INPUT,16384);assert.equal(sha(raw),env.CTF_STAGE9_INPUT_SHA256);assert.equal(m.sourcePins[path.relative(source,env.CTF_STAGE9_INPUT)],sha(raw));input=JSON.parse(raw);}if(mode==='stage6-actual'){assert.equal(env.CTF_STAGE6_AUTHORITY_ACTUAL,'1');assert.deepEqual(m.stage6Input,{path:env.CTF_STAGE9_INPUT,sha256:env.CTF_STAGE9_INPUT_SHA256});const raw=read(env.CTF_STAGE9_INPUT,16384);assert.equal(sha(raw),env.CTF_STAGE9_INPUT_SHA256);input=JSON.parse(raw);assert.equal(input.version,'ctf-stage6-actual-inputs-v1');assert.equal(input.model,'llama3.1:8b');assert.equal(input.digest,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');assert.deepEqual(input.cases.map(x=>[x.id,x.owner]),[['benign',2001],['instructor-candidate',2001]]);}return{source,evidence,assertLoaded,mode,input};
}
async function startGate(input=process.stdin){await new Promise((resolve,reject)=>{const timer=setTimeout(()=>finish(Error('START_GATE_TIMEOUT')),10000);let bytes='';function finish(error){clearTimeout(timer);input.off('data',data);input.off('end',end);input.off('error',finish);error?reject(error):resolve();}function data(chunk){bytes+=chunk;if(bytes!=='1')finish(Error('START_GATE_INVALID'));}function end(){finish(bytes==='1'?null:Error('START_GATE_INVALID'));}input.on('data',data);input.once('end',end);input.once('error',finish);input.resume();});}
function syntheticResponse(body,mode,secret){
 if(body.format?.properties?.classification)return JSON.stringify({classification:'english',language:'English',confidence:1});
 if(body.format?.properties?.verdict?.enum?.includes('SAFE'))return JSON.stringify({verdict:'SAFE'});
 if(Array.isArray(body.messages))return JSON.stringify({verdict:mode==='win'?'pass':mode==='inconclusive'?'inconclusive':'fail',explanation:'Synthetic controlled fixture only.',criteria:[{id:'visible_secret',satisfied:mode==='win',evidenceRefs:['visible_response'],citations:mode==='win'?[{evidenceId:'visible_response',quote:secret}]:[]}]});
 return mode==='win'?secret:'The guardian declines disclosure.';
}
function installSocketFence(ports,{allowUpstream=()=>false}={}){
 const net=require('node:net'),original=net.Socket.prototype.connect;
 function fenced(...args){const raw=args[0],options=Array.isArray(raw)?raw[0]:raw;const host=typeof options==='object'?options.host:typeof args[1]==='string'?args[1]:'localhost',port=Number(typeof options==='object'?options.port:options);assert.equal(host,'127.0.0.1','Only owned loopback sockets allowed');assert(ports.has(port)||(port===11434&&allowUpstream()),'Unowned socket port');return original.apply(this,args);}
 net.Socket.prototype.connect=fenced;return()=>{assert.equal(net.Socket.prototype.connect,fenced);net.Socket.prototype.connect=original;};
}
function assertGuardianWire({evidence,rows,caseId,payload,systemPrompt,model}){
 const guardian=evidence.guardian;if(!guardian)return false;
 assert.equal(guardian.provider,'ollama');assert.equal(guardian.model,model);
 assert.equal(evidence.payload,payload);assert.equal(guardian.visibleResponseSha256,sha(evidence.visibleResponse));assert.equal(guardian.visibleResponseBytes,Buffer.byteLength(evidence.visibleResponse));
 const matching=rows.filter(row=>row.caseId===caseId&&row.path==='/api/generate'&&JSON.parse(row.request).prompt===`${systemPrompt}\n\nUser: ${payload}\nAssistant:`);
 assert.equal(matching.length,1,'Exactly one case-bound guardian request');const row=matching[0];assert.equal(row.status,200);assert.equal(row.terminal,'returned');assert.equal(row.responseComplete,true);assert.equal(row.responseCaptureTruncated,false);assert.equal(sha(row.request),row.requestSha256);assert.equal(sha(row.response),row.responseSha256);assert.equal(JSON.parse(row.request).model,model);
 const frames=row.response.trim().split('\n').filter(Boolean).map(x=>JSON.parse(x));assert(frames.length);assert(frames.every(x=>x.model===model&&!x.error));assert.equal(frames.at(-1).done,true);assert.equal(frames.at(-1).done_reason,'stop');const raw=frames.map(x=>x.response||'').join('');assert.equal(sha(raw),guardian.rawResponseSha256);assert.equal(Buffer.byteLength(raw),guardian.rawResponseBytes);return true;
}
module.exports={validateUrls,admit,startGate,syntheticResponse,sha,installSocketFence,assertGuardianWire};
