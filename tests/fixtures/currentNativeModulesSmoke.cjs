'use strict';
// Preserved Sept27 native smoke, main-only authority. Root executes after review.
// No application imports, database URLs, model session/inference or downloads.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{createRequire}=require('node:module'),{spawn}=require('node:child_process');
const EXPECTED='/Users/averma5/Documents/github/OWASP Agentic AI GOAT';
assert.equal(path.resolve(__dirname,'../..'),EXPECTED);
assert.equal(fs.realpathSync(EXPECTED),EXPECTED);
const evidence=path.resolve(process.argv[3]);
assert.equal(fs.realpathSync(evidence),evidence);
const evidenceParent=path.join(EXPECTED,'backups/private-recovery/native-modules');
assert.equal(path.dirname(evidence),evidenceParent);
assert.match(path.basename(evidence),/^run-[a-z0-9_-]{6,40}$/);
for(const dir of [evidenceParent,evidence]){const st=fs.lstatSync(dir);assert(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid());assert.equal(st.mode&0o777,0o700);}
const resultPath=path.join(evidence,'native-smoke-result.json');
assert.equal(fs.existsSync(resultPath),false);
assert.equal(process.version,'v26.10.0');
const root=fs.realpathSync(process.argv[2]);assert.equal(root,EXPECTED);
const modules=fs.realpathSync(path.join(root,'node_modules'));assert.equal(modules,path.join(root,'node_modules'));
const req=createRequire(path.join(root,'package.json'));
function ownedRequire(name){const resolved=fs.realpathSync(req.resolve(name));assert(resolved.startsWith(modules+path.sep));return req(name);}
async function run(name,dir){
 if(name==='sqlite3'){
  const sqlite=ownedRequire('sqlite3');let db;
  try{await new Promise((ok,no)=>{db=new sqlite.Database(':memory:',e=>e?no(e):ok());});await new Promise((ok,no)=>db.exec('CREATE TABLE smoke(v INTEGER); INSERT INTO smoke VALUES(17),(25)',e=>e?no(e):ok()));const row=await new Promise((ok,no)=>db.get('SELECT sum(v) AS total FROM smoke',(e,r)=>e?no(e):ok(r)));assert.equal(row.total,42);}
  finally{if(db)await new Promise((ok,no)=>db.close(e=>e?no(e):ok()));}
 }else if(name==='better-sqlite3'){
  const Database=ownedRequire(name),db=new Database(':memory:');try{db.exec('CREATE TABLE smoke(v INTEGER)');db.prepare('INSERT INTO smoke VALUES (?)').run(42);assert.equal(db.prepare('SELECT v FROM smoke').get().v,42);}finally{db.close();}
 }else if(name==='hnswlib-node'){
  const {HierarchicalNSW}=ownedRequire(name),index=new HierarchicalNSW('l2',3);index.initIndex(4,16,32,100);index.addPoint([1,0,0],7);index.addPoint([0,1,0],9);assert.equal(index.searchKnn([1,0,0],1).neighbors[0],7);const file=path.join(dir,'smoke.hnsw');index.writeIndexSync(file);assert(fs.statSync(file).size>0);const reload=new HierarchicalNSW('l2',3);reload.readIndexSync(file);assert.equal(reload.searchKnn([0,1,0],1).neighbors[0],9);
 }else if(name==='bcrypt'){
  const bcrypt=ownedRequire(name),hash=await bcrypt.hash('owned synthetic smoke',4);assert(await bcrypt.compare('owned synthetic smoke',hash));assert.equal(await bcrypt.compare('different',hash),false);
 }else if(name==='@napi-rs/canvas'){
  const {createCanvas}=ownedRequire(name),canvas=createCanvas(2,2),ctx=canvas.getContext('2d');ctx.fillStyle='#ff0000';ctx.fillRect(0,0,2,2);assert.deepEqual(Array.from(ctx.getImageData(0,0,1,1).data),[255,0,0,255]);const png=canvas.toBuffer('image/png');assert.equal(png.subarray(1,4).toString(),'PNG');
 }else if(name==='sharp'){
  const sharp=ownedRequire(name),png=await sharp({create:{width:2,height:2,channels:4,background:{r:255,g:0,b:0,alpha:1}}}).png().toBuffer();const image=await sharp(png).raw().toBuffer({resolveWithObject:true});assert.equal(image.info.width,2);assert.equal(image.info.height,2);assert.deepEqual(Array.from(image.data.subarray(0,4)),[255,0,0,255]);
 }else if(name==='onnxruntime-node'){
  const ort=ownedRequire(name);const entry=fs.realpathSync(req.resolve(name));const bindingPath=path.join(path.dirname(entry),'binding.js');assert(fs.realpathSync(bindingPath).startsWith(modules+path.sep));const {binding,initOrt}=req(bindingPath);initOrt();assert.equal(typeof binding.InferenceSession,'function');const backends=binding.listSupportedBackends();assert(Array.isArray(backends)&&backends.some(x=>x.name==='cpu'));const tensor=new ort.Tensor('float32',Float32Array.from([1,2]),[2]);assert.deepEqual(Array.from(tensor.data),[1,2]);return {backends,session:'UNTESTED: no existing small ONNX fixture found; binding initialization and tensor only'};
 }else throw Error('Unknown closed smoke');
 return {operation:'passed'};
}
assert.ok(process.argv.length===4||(process.argv.length===7&&process.argv[4]==='--worker'));
if(process.argv[4]==='--worker'){
 const deny=()=>{throw Error('Native smoke network/subprocess denied');};
 for(const [module,names] of [['node:net',['connect','createConnection','createServer']],['node:dgram',['createSocket']],['node:http',['request','get','createServer']],['node:https',['request','get','createServer']],['node:tls',['connect','createServer']],['node:child_process',['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']]])for(const name of names)require(module)[name]=deny;
 globalThis.fetch=deny;
 const dir=fs.realpathSync(process.argv[6]);assert.equal(path.dirname(dir),evidence);assert.match(path.basename(dir),/^native-smoke-[A-Za-z0-9]+$/);const st=fs.lstatSync(dir);assert(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid());assert.equal(st.mode&0o777,0o700);
 run(process.argv[5],dir).then(result=>{const addons=Object.keys(require.cache).filter(p=>p.endsWith('.node'));assert(addons.length>0,'No actual native addon loaded');for(const p of addons)assert(fs.realpathSync(p).startsWith(modules+path.sep),'Addon outside main');console.log(JSON.stringify({name:process.argv[5],result,addons:addons.map(p=>({path:path.relative(root,p),sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}))}));},error=>{console.error(error.stack);process.exitCode=1;});
}else{
 (async()=>{assert.deepEqual(fs.readdirSync(evidence),[],'Evidence root must be new and empty');const dir=fs.mkdtempSync(path.join(evidence,'native-smoke-'));fs.chmodSync(dir,0o700);const report={node:process.version,executable:process.execPath,root,evidence,scriptSha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),manifestPins:Object.fromEntries(['package.json','package-lock.json'].map(f=>[f,crypto.createHash('sha256').update(fs.readFileSync(path.join(root,f))).digest('hex')])),scope:'Native addon smoke only; no application/model readiness claim',cases:[],limitations:['ONNX model session not exercised: no existing tiny fixture found','No native subprocesses expected from these APIs; exact worker process timeout only']};
 try{for(const name of ['sqlite3','better-sqlite3','hnswlib-node','bcrypt','@napi-rs/canvas','sharp','onnxruntime-node']){
  const result=await new Promise(resolve=>{const child=spawn(process.execPath,['--max-old-space-size=256',__filename,root,evidence,'--worker',name,dir],{cwd:root,env:{PATH:path.dirname(process.execPath),HOME:dir,TMPDIR:dir},stdio:['ignore','pipe','pipe']});let out='',err='',overflow=false,timedOut=false;const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},15000);function collect(which,data){if(Buffer.byteLength(out)+Buffer.byteLength(err)+data.length>65536){overflow=true;child.kill('SIGKILL');return;}if(which==='out')out+=data;else err+=data;}child.stdout.on('data',d=>collect('out',d));child.stderr.on('data',d=>collect('err',d));child.on('error',e=>{err+=e.code||'SPAWN_FAILED';});child.on('close',(code,signal)=>{clearTimeout(timer);let pidAbsent=false;try{process.kill(child.pid,0);}catch(e){if(e.code==='ESRCH')pidAbsent=true;else err+='PID_ABSENCE_CHECK_FAILED';}resolve({name,pid:child.pid,pidAbsent,code,signal,timedOut,overflow,stdout:out,stderr:err});});});
  report.cases.push(result);
 }
 report.status=report.cases.every(c=>c.code===0&&c.pidAbsent&&!c.timedOut&&!c.overflow)?'passed_with_explicit_onnx_session_gap':'failed';
 }finally{fs.rmSync(dir,{recursive:true,force:true});report.ownedScratchRemoved=!fs.existsSync(dir);fs.writeFileSync(resultPath,JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});}
 console.log(JSON.stringify({status:report.status,report:resultPath}));if(report.status==='failed')process.exitCode=1;
 })().catch(e=>{console.error(e.stack);process.exitCode=1;});
}
