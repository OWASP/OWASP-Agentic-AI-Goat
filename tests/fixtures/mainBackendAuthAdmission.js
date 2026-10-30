'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const SOURCE=path.resolve(__dirname,'../..');
const FIXTURES=Object.freeze(['tests/postgres/fullApplicationBackendAuth.integration.test.js','tests/postgres/agentRunAuthenticatedOwnership.integration.test.js']);
function awaitStartupGate(read=fs.readSync){const byte=Buffer.alloc(1);assert.equal(read(0,byte,0,1,null),1);assert.equal(byte[0],49);}
function admit(environment,{source=SOURCE,io=fs,nativePid=process.pid}={}){
 const rendered=environment.PG_MAIN_RENDERED_PLATFORM==='1';
 if(environment.PG_MAIN_RENDERED_PLATFORM!==undefined)assert.equal(environment.PG_MAIN_RENDERED_PLATFORM,'1');
 const renderedStandalone=environment.PG_MAIN_RENDERED_STANDALONE==='1';
 if(environment.PG_MAIN_RENDERED_STANDALONE!==undefined)assert.equal(environment.PG_MAIN_RENDERED_STANDALONE,'1');
 assert(!(rendered&&renderedStandalone));
 const boundSessions=environment.PG_MAIN_BOUND_SESSIONS==='1';
 if(environment.PG_MAIN_BOUND_SESSIONS!==undefined)assert.equal(environment.PG_MAIN_BOUND_SESSIONS,'1');
 assert(!boundSessions||rendered);
 const capacity=environment.PG_MAIN_CAPACITY_200==='1';
 const standaloneCore=environment.PG_FULL_BACKEND_STANDALONE_CORE==='1';
 if(environment.PG_FULL_BACKEND_STANDALONE_CORE!==undefined)assert.equal(environment.PG_FULL_BACKEND_STANDALONE_CORE,'1');
 assert(!(standaloneCore&&(rendered||boundSessions||capacity)));
 assert(!renderedStandalone||standaloneCore);
 assert(!(capacity&&(rendered||renderedStandalone)));
 assert.equal(environment.PG_FULL_BACKEND_RENDERED,rendered||renderedStandalone?'1':undefined);
 if(environment.PG_MAIN_CAPACITY_200!==undefined)assert.equal(environment.PG_MAIN_CAPACITY_200,'1');
 assert.equal(environment.PG_FULL_BACKEND_CAPACITY,capacity?'1':undefined);
 assert.equal(environment.PG_MAIN_BACKEND_AUTH,'1');assert.equal(environment.PG_TEST_DISPOSABLE,'yes');
 assert.equal(environment.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE,undefined,'Main is not a copied workspace');
 for(const key of ['PG_FULL_BACKEND_MCP_INDIRECT','PG_FULL_BACKEND_SECURESHOP','PG_SQL_NOVA_CATALOG'])assert.equal(environment[key],undefined);
 assert.equal(io.realpathSync(source),source);
 const evidence=environment.MAIN_BACKEND_AUTH_EVIDENCE,root=environment.OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT;
 assert.equal(typeof evidence,'string');assert.equal(typeof root,'string');
 assert.equal(io.realpathSync(evidence),evidence);assert.equal(io.realpathSync(root),root);
 assert(evidence.startsWith(path.join(source,'backups/private-recovery/backend-auth')+path.sep));assert.equal(path.dirname(root),evidence);assert.equal(path.basename(root),'runtime');
 for(const directory of [evidence,root]){const st=io.lstatSync(directory);assert(st.isDirectory()&&!st.isSymbolicLink());assert.equal(st.uid,process.getuid());assert.equal(st.mode&0o777,0o700);}
 const journal=path.join(evidence,'ownership.json'),st=io.lstatSync(journal);assert(st.isFile()&&!st.isSymbolicLink()&&st.size<=65536);assert.equal(st.uid,process.getuid());assert.equal(st.mode&0o077,0);
 const owner=JSON.parse(io.readFileSync(journal,'utf8'));assert.equal(owner.cohort,capacity?'main-capacity-200':'main-backend-auth');assert.equal(owner.evidenceRoot,evidence);assert.equal(owner.nativeStarted,true);assert.equal(owner.nativePid,nativePid);assert.equal(owner.sourceRoot,source);
 if(standaloneCore)assert.deepEqual(owner.standaloneCore,{profile:renderedStandalone?'standalone-core-rendered':'standalone-core',modelCalls:0,sourceCopy:false});
 else assert.equal(owner.standaloneCore,undefined);
 assert.match(owner.owner,/^[a-f0-9]{32}$/);assert.match(owner.containerId,/^[a-f0-9]{64}$/);assert(Number.isInteger(owner.databasePort)&&owner.databasePort>0&&owner.databasePort<=65535);
 const appData=environment.MAIN_BACKEND_AUTH_APP_DATA,record=owner.privateAppData;
 assert.equal(typeof appData,'string');assert.equal(io.realpathSync(appData),appData);assert(!appData.startsWith(source+path.sep)&&appData!==source&&!source.startsWith(appData+path.sep));
 const dataStat=io.lstatSync(appData);assert(dataStat.isDirectory()&&!dataStat.isSymbolicLink());assert.equal(dataStat.uid,process.getuid());assert.equal(dataStat.mode&0o777,0o700);
 assert(record);assert.equal(record.path,appData);assert.equal(record.device,dataStat.dev);assert.equal(record.inode,dataStat.ino);assert.equal(record.uid,dataStat.uid);
 let renderedPlatform=null,renderedStandaloneProof=null;
 if(rendered){
  const proof=owner.renderedPlatform;assert(proof);assert.equal(proof.boundSessions,boundSessions?true:undefined);assert.equal(proof.profile,'rendered-platform');
  assert.equal(proof.buildRoot,path.join(source,'client/build'));assert.equal(io.realpathSync(proof.buildRoot),proof.buildRoot);
  assert.match(proof.buildInventorySha256,/^[a-f0-9]{64}$/);
  assert.equal(environment.PG_FULL_BACKEND_BROWSER,proof.browser);assert.equal(environment.PG_FULL_BACKEND_BROWSER_SHA256,proof.browserSha256);
  assert(path.isAbsolute(proof.browser));assert.match(proof.browserSha256,/^[a-f0-9]{64}$/);
  renderedPlatform=Object.freeze({...proof});
 }else assert.equal(owner.renderedPlatform,undefined);
 if(renderedStandalone){
  const proof=owner.renderedStandalone;assert(proof);assert.equal(proof.profile,'standalone-core-rendered');
  assert.equal(proof.buildRoot,path.join(source,'client/build'));assert.equal(io.realpathSync(proof.buildRoot),proof.buildRoot);
  assert.match(proof.buildInventorySha256,/^[a-f0-9]{64}$/);
  assert.equal(environment.PG_FULL_BACKEND_BROWSER,proof.browser);assert.equal(environment.PG_FULL_BACKEND_BROWSER_SHA256,proof.browserSha256);
  assert(path.isAbsolute(proof.browser));assert.match(proof.browserSha256,/^[a-f0-9]{64}$/);
  renderedStandaloneProof=Object.freeze({...proof});
 }else assert.equal(owner.renderedStandalone,undefined);
 if(!rendered&&!renderedStandalone){for(const key of ['PG_FULL_BACKEND_BROWSER','PG_FULL_BACKEND_BROWSER_SHA256'])assert.equal(environment[key],undefined);}
 if(capacity){const u=new URL(environment.PG_CAPACITY_OBSERVER_URL);assert.equal(u.href,`postgresql://ownership_test_admin@127.0.0.1:${owner.databasePort}/postgres`);}
 else assert.equal(environment.PG_CAPACITY_OBSERVER_URL,undefined);
 return Object.freeze({source,root,evidence,appData,port:owner.databasePort,capacity,renderedPlatform,renderedStandalone:renderedStandaloneProof,
  ...(standaloneCore?{standaloneCore:Object.freeze({...owner.standaloneCore})}:{})});
}
function launchLocation(source,root,file){
 assert(typeof file==='string'&&!path.isAbsolute(file)&&!file.split(/[\\/]/).includes('..'));
 return {file:path.join(source,file),cwd:root}; // dotenv defaults to private cwd; never main .env.
}
function ownershipEnvironment(environment){
 const result={PG_TEST_DISPOSABLE:'yes',PG_AUTHENTICATED_RUN_READS:'1'};
 for(const [to,from]of Object.entries({PG_READS_TEST_RUNTIME_URL:'IDENTITY_DATABASE_URL',PG_READS_TEST_MIGRATION_URL:'IDENTITY_MIGRATION_DATABASE_URL',PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL:'SECURESHOP_AGENTS_DATABASE_URL',PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL:'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL'})){assert.equal(typeof environment[from],'string');result[to]=environment[from];}
 return result;
}
function fileHash(file){const fd=fs.openSync(file,'r'),hash=createHash('sha256'),buffer=Buffer.alloc(65536);try{let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0)hash.update(buffer.subarray(0,n));return hash.digest('hex');}finally{fs.closeSync(fd);}}
function snapshotDirectory(directory){
 const rows=[];function walk(p,rel){const st=fs.lstatSync(p);if(st.isSymbolicLink()){rows.push([rel,'link',fs.readlinkSync(p)]);return;}if(st.isDirectory()){rows.push([rel,'directory',st.mode&0o777]);for(const n of fs.readdirSync(p).sort())walk(path.join(p,n),path.posix.join(rel,n));return;}assert(st.isFile());rows.push([rel,'file',st.mode&0o777,fileHash(p)]);}
 try{walk(directory,'');}catch(e){if(e.code==='ENOENT'&&rows.length===0)return null;throw e;}return rows;
}
module.exports={awaitStartupGate,admit,launchLocation,ownershipEnvironment,snapshotDirectory,FIXTURES};
