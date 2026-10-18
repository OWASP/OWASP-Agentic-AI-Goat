'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const C=require('../fixtures/dpiCurrentOwnedContractV2'),ROOT=path.resolve(__dirname,'../..');
const KEYS=['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'];
function read(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);assert(s.isFile()&&s.nlink===1&&s.size<32*1024*1024);return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function urls(env,port,nonce){assert.match(nonce,/^[a-f0-9]{12}$/);assert(Number.isInteger(port)&&port>0&&port<65536);for(const [i,key]of KEYS.entries()){const u=new URL(env[key]);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(Number(u.port),port);assert.equal(u.pathname,'/dvaia_test_dpi_current_'+nonce+'_identity');assert.equal(u.username,'dvaia_identity_'+(i?'migration':'runtime'));assert.equal(u.password+u.search+u.hash,'');}for(const k of Object.keys(env))if(/(?:DATABASE_URL|MIGRATION_DATABASE_URL)$/.test(k))assert(KEYS.includes(k));}
function assertLoaded(manifest,cache=require.cache){for(const file of Object.keys(cache)){if(!file.startsWith(ROOT+path.sep)||file.includes(path.sep+'node_modules'+path.sep))continue;const p=path.relative(ROOT,file);assert.match(manifest.sourcePins[p]||'',/^[a-f0-9]{64}$/,'Loaded main source absent from manifest');assert.equal(fs.realpathSync(file),file);assert.equal(C.sha(read(file)),manifest.sourcePins[p]);}}
function hasActualModelProof(qualification){return qualification?.turns?.some(t=>t.status===200&&Number.isInteger(t.actualActorCalls)&&t.actualActorCalls>0&&Number.isInteger(t.actualJudgeCalls)&&t.actualJudgeCalls>0&&t.actorBinding?.actorCalls===t.actualActorCalls&&t.judgeBinding?.judgeCalls===t.actualJudgeCalls&&/^[a-f0-9]{64}$/.test(t.judgeBinding?.transcriptSha256||''))===true;}
function compactWire(snapshot){if(!snapshot)return null;return {version:snapshot.version,model:snapshot.model,digest:snapshot.digest,counts:Object.fromEntries(['external','actor','judge','tags',...(Object.hasOwn(snapshot.counts,'review')?['review']:[])].map(k=>[k,snapshot.counts[k]])),physicalPending:snapshot.physicalPending,handlersPending:snapshot.handlersPending,closed:snapshot.closed,failureCount:snapshot.failures.length};}
function assertReceiptBound(value){assert(Buffer.byteLength(JSON.stringify(value))+1<=1024*1024,'DPI terminal receipt exceeds parent byte limit');}
function admit(env=process.env){
 assert.equal(env.DPI_CURRENT_NATIVE,'1');assert.equal(env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(env.DPI_CURRENT_SOURCE_ROOT),ROOT);
 const evidence=fs.realpathSync(env.DPI_CURRENT_EVIDENCE_ROOT);assert.equal(path.dirname(evidence),path.join(ROOT,'backups/private-recovery/dpi-current'));const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700);assert.equal(fs.realpathSync(process.cwd()),path.join(evidence,'runtime'));assert(!fs.existsSync(path.join(process.cwd(),'.env')));
 const raw=read(env.DPI_CURRENT_MANIFEST);assert.equal(C.sha(raw),env.DPI_CURRENT_MANIFEST_SHA256);const manifest=JSON.parse(raw);assert.equal(manifest.workspace,ROOT);assert.equal(manifest.cohort,'dpi-current-owned');assert.equal(manifest.model,C.MODEL);assert.equal(manifest.modelDigest,C.DIGEST);
 const selected=env.DPI_CURRENT_SELECTOR||'all';assert(['all',C.RETAINED_FOUR,C.RETAINED_FIXED,C.RETAINED_RETRY,C.UX_MODE].includes(selected));assert.equal(manifest.selector??'all',selected);
 assert.equal(manifest.inputSha256,C.sha(JSON.stringify(C.cases())));assert.deepEqual(manifest.budgets,C.TOTAL);
 for(const name of ['tests/postgres/dpiCurrentOwnedMain.js','tests/postgres/dpiCurrentOwnedActualTransport.js','tests/fixtures/dpiCurrentOwnedContractV2.js','tests/fixtures/dpiCurrentOwnedQualification.js','tests/fixtures/dpiCurrentOwnedWireBinding.js'])assert.match(manifest.sourcePins[name],/^[a-f0-9]{64}$/);
 for(const [p,h]of Object.entries(manifest.sourcePins)){assert(!path.isAbsolute(p)&&!p.split('/').includes('..'));const file=path.join(ROOT,p);assert.equal(fs.realpathSync(file),file);assert.equal(C.sha(read(file)),h);}
 const owner=JSON.parse(read(path.join(evidence,'ownership.json')));assert.equal(owner.owner,env.DPI_CURRENT_OWNER);assert.equal(owner.sourceRoot,ROOT);assert.equal(owner.evidenceRoot,evidence);assert.equal(owner.scenario,'dpi-current-owned');assert.equal(owner.nativePid,process.pid);assert.equal(owner.nativeStarted,true);assert.equal(owner.parentPid,process.ppid);assert.equal(owner.manifestSha256,C.sha(raw));assert.match(owner.containerId,/^[a-f0-9]{64}$/);urls(env,owner.databasePort,owner.nonce);
 const logs=path.join(evidence,'runtime/logs');assert.equal(env.LOGS_DIR,logs);const ls=fs.lstatSync(logs);assert.equal(fs.realpathSync(logs),logs);assert(ls.isDirectory()&&ls.uid===process.getuid()&&(ls.mode&0o777)===0o700);
 return {evidence,port:owner.databasePort,manifest};
}
async function run(){
 await require('./ctfStage9MainQualification').startGate();const a=admit(),transportModule=require('./dpiCurrentOwnedActualTransport'),ports=new Set([a.port]);require('./ctfStage9MainQualification').installSocketFence(ports,{allowUpstream:transportModule.allowsUpstream});
 const Module=require('node:module'),load=Module._load;Module._load=function(name){if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('LEGACY_DATABASE_DENIED');return Reflect.apply(load,this,arguments);};
 const state={status:'preparing',installedWrites:false,actualModelProof:false,cleanupFailures:[]},save=()=>{assertReceiptBound(state);require('../fixtures/boundedJsonArtifact').saveBounded(path.join(a.evidence,'result.json'),state);};let proxy,pg;const pools=[];
 try{
  state.stage='transport';save();proxy=await transportModule.createTransport({evidence:a.evidence});for(const u of [proxy.actorUrl,proxy.judgeUrl])ports.add(Number(new URL(u).port));
  Object.assign(process.env,{AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:proxy.actorUrl,OLLAMA_MODEL:C.MODEL,JUDGE_MODEL:C.MODEL,JUDGE_CONTEXT_TOKENS:'32768',AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',LMSTUDIO_BASE_URL:proxy.actorUrl+'/denied'});
  pg=require('../../server/database/postgres');for(const key of [...KEYS,KEYS[0]])pools.push(pg.createPool(process.env,key));
  state.stage='cohort';save();state.qualification=await require('../fixtures/dpiCurrentOwnedQualification').qualify({pools,transport:proxy,ports,evidence:a.evidence,persist:async q=>{state.qualification=q;save();}});proxy.assertComplete();assertLoaded(a.manifest);state.status='checks-passed-cleanup-pending';state.actualModelProof=hasActualModelProof(state.qualification);
 }catch(error){state.status='failed';state.failure=require('./finflow0055Main').safeFailure(error,state.stage);}
 finally{
  const actions=pools.map((p,i)=>['pool'+i,()=>p.end()]);actions.push(['shared-pools',()=>pg?.closePostgresPools()],['transport',()=>proxy?.close()]);
  const outcomes=await require('../fixtures/secureshopAnalyticsBrowserOwner').settleOwnership(actions,10000);state.cleanupFailures=outcomes.filter(x=>x.status!=='fulfilled');state.wireSummary=compactWire(proxy?.snapshot());
  if(state.status==='checks-passed-cleanup-pending'&&!state.cleanupFailures.length)state.status='passed';else state.status='failed';save();
 }return state;
}
module.exports={admit,urls,assertLoaded,hasActualModelProof,compactWire,assertReceiptBound,KEYS,run};if(require.main===module)run().then(s=>{if(s.status!=='passed')process.exitCode=1;}).catch(()=>{process.stderr.write('DPI_CURRENT_FAILED\n');process.exitCode=1;});
