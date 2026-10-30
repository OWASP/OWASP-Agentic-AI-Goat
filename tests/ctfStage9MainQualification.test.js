'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {PassThrough}=require('node:stream');
const {validateUrls,startGate,syntheticResponse}=require('./postgres/ctfStage9MainQualification');
const env=()=>Object.fromEntries([...['IDENTITY','CTF'].flatMap(s=>['RUNTIME','MIGRATION'].map(r=>[`PG_CTF_STAGE9_${s}_${r}_URL`,`postgresql://dvaia_${s.toLowerCase()}_${r.toLowerCase()}@127.0.0.1:32100/owasp_ai_goat_test_ctf_stage9_${s.toLowerCase()}`])),['PG_CTF_STAGE9_CTF_DELIVERY_URL','postgresql://dvaia_ctf_delivery@127.0.0.1:32100/owasp_ai_goat_test_ctf_stage9_ctf']]);
test('exact two disposable stores and separate delivery authority only',()=>{validateUrls(env(),32100);for(const change of ['localhost','5432','identity_migration','application','?sslmode=disable']){const e=env();e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL=change==='localhost'?e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL.replace('127.0.0.1',change):change==='5432'?e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL.replace('32100',change):change==='identity_migration'?e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL.replace('identity_runtime',change):change==='application'?e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL.replace('owasp_ai_goat_test_ctf_stage9_identity',change):e.PG_CTF_STAGE9_IDENTITY_RUNTIME_URL+change;assert.throws(()=>validateUrls(e,32100));}});
test('owned start gate requires exactly one byte then EOF',async()=>{const ok=new PassThrough();const pending=startGate(ok);ok.end('1');await pending;for(const bytes of ['','0','11']){const p=new PassThrough(),result=startGate(p);p.end(bytes);await assert.rejects(result);}});
test('synthetic language/reviewer/Judge distinct closed framing; no semantic claim',()=>{assert.equal(JSON.parse(syntheticResponse({format:{properties:{classification:{}}}},'win','S')).classification,'english');assert.equal(JSON.parse(syntheticResponse({format:{properties:{verdict:{enum:['SAFE','LEAKED']}}}},'win','S')).verdict,'SAFE');const j=JSON.parse(syntheticResponse({messages:[]},'win','S'));assert.equal(j.verdict,'pass');assert.equal(j.criteria[0].citations[0].quote,'S');assert.equal(JSON.parse(syntheticResponse({messages:[]},'inconclusive','S')).verdict,'inconclusive');});
test('socket fence rejects external, default model and unrelated loopback ports before connect',()=>{
 const net=require('node:net'),original=net.Socket.prototype.connect;let calls=0;
 net.Socket.prototype.connect=function(){calls++;return this;};
 const restore=require('./postgres/ctfStage9MainQualification').installSocketFence(new Set([32100]));
 try{for(const options of [{host:'127.0.0.1',port:11434},{host:'example.invalid',port:32100},{path:'/tmp/socket'},{host:'localhost',port:32100}])assert.throws(()=>net.Socket.prototype.connect.call({},options));assert.equal(calls,0);net.Socket.prototype.connect.call({},{host:'127.0.0.1',port:32100});assert.equal(calls,1);}finally{restore();net.Socket.prototype.connect=original;}
});
test('actual fixture configures synthetic transport before its first production import',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'postgres/ctfStage9SharedMemory.integration.test.js'),'utf8');
 let execute,checked=false;const stop=new Error('intentional stop before production import');
 const processStub={env:{CTF_STAGE9_MAIN_ISOLATED:'1',PG_CTF_STAGE9_IDENTITY_RUNTIME_URL:'postgresql://role@127.0.0.1:32100/db'}};
 const fakeServer={requestTimeout:0,listen(_port,host,callback){assert.equal(host,'127.0.0.1');callback();},address(){return{port:32101};}};
 vm.runInNewContext(source,{process:processStub,URL,Set,Buffer,require(name){
  if(name==='node:test')return(_name,_options,body)=>{execute=body;};
  if(name==='./ctfStage9MainQualification')return{startGate:async()=>{},admit:()=>({}),installSocketFence:()=>()=>{}};
  if(name==='node:http')return{createServer:()=>fakeServer};
  if(name.startsWith('../../')){assert.equal(name,'../../server/database/postgres');assert.equal(processStub.env.OLLAMA_BASE_URL,'http://127.0.0.1:32101');assert.equal(processStub.env.OLLAMA_MODEL,'controlled-stage9-fixture');assert.equal(processStub.env.JUDGE_MODEL,'controlled-stage9-fixture');assert.equal(processStub.env.AI_PROVIDER,'ollama');checked=true;throw stop;}
  return require(name);
 }});
 await assert.rejects(execute({after(){}}),e=>e===stop);assert.equal(checked,true);
});
test('guardian proof binds exact case prompt/raw output and visible persisted bytes',()=>{
 const {assertGuardianWire,sha}=require('./postgres/ctfStage9MainQualification');const raw=' exact output\n',visible='redacted',model='llama3.1:8b';const request=JSON.stringify({model,prompt:'policy\n\nUser: input\nAssistant:'}),response=JSON.stringify({model,response:raw,done:false})+'\n'+JSON.stringify({model,response:'',done:true,done_reason:'stop'})+'\n';
 const evidence={payload:'input',visibleResponse:visible,guardian:{provider:'ollama',model,rawResponseSha256:sha(raw),rawResponseBytes:Buffer.byteLength(raw),visibleResponseSha256:sha(visible),visibleResponseBytes:Buffer.byteLength(visible)}};
 const row={caseId:'candidate',path:'/api/generate',request,response,status:200,terminal:'returned',responseComplete:true,responseCaptureTruncated:false,requestSha256:sha(request),responseSha256:sha(response)};const args={evidence,rows:[row],caseId:'candidate',payload:'input',systemPrompt:'policy',model};assert.equal(assertGuardianWire(args),true);
 for(const mutate of [x=>x.evidence.guardian.model='wrong',x=>x.rows[0].caseId='other',x=>x.evidence.visibleResponse='tampered',x=>{x.rows[0].request=JSON.stringify({model,prompt:'reviewer'});x.rows[0].requestSha256=sha(x.rows[0].request);},x=>x.evidence.guardian.rawResponseSha256=sha(raw.trim())]){const a=structuredClone(args);mutate(a);assert.throws(()=>assertGuardianWire(a));}
});
