'use strict';
// Actual authority module with controlled private-storage/Docker providers.
// No Windows native APIs, Docker daemon or installer is executed.
const test=require('node:test'),assert=require('node:assert/strict');
const {createLocalDockerAuthorityStorage,resolveLocalDockerHost,verifyDockerAuthority,authorityDigest,LocalDockerAuthorityError}=require('../scripts/local-docker-authority');
const directory='C:\\Users\\Learner\\private',filename=directory+'\\local-docker.json',host='npipe:////./pipe/docker_engine';
const authority={version:1,workspaceId:'workspace123',host,daemonId:'daemon-owned',source:'environment-host',platform:'win32'};
const wire=value=>Buffer.from(JSON.stringify({version:value.version,workspaceId:value.workspaceId,host:value.host,daemonId:value.daemonId,source:value.source},null,2)+'\n');
function fixture(initial){
 const files=new Map(),calls=[],retained=new Map();if(initial!==undefined)files.set(filename,Buffer.from(initial));let unsafe=false,fault=null;
 const fileSystem={async lstat(p){calls.push(['lstat',p]);if(!files.has(p))throw Object.assign(Error('absent'),{code:'ENOENT'});return {};},async readFile(){throw Error('raw unbounded read forbidden');},async open(){throw Error('POSIX open forbidden');},async link(){throw Error('POSIX link forbidden');},async chmod(){throw Error('chmod authority forbidden');},async rm(){throw Error('uncertain state removal forbidden');}};
 const privateState={
  inspectPrivateDirectory(p){calls.push(['inspect',p]);if(unsafe||p!==directory)throw Error('synthetic private directory secret diagnostic');},
  readPrivateFile(p){calls.push(['read',p]);if(unsafe||!files.has(p))throw Object.assign(Error('synthetic denied native read'),{code:'ENOENT'});return Buffer.from(files.get(p));},
 };
 const journal={createJournal({filePath,bytes}){
  calls.push(['create',filePath,Buffer.from(bytes)]);
  if(files.has(filePath)&&(!retained.has(filePath)||!retained.get(filePath).equals(bytes)))throw Error('controlled exclusive collision');
  if(retained.has(filePath)&&!retained.get(filePath).equals(bytes))throw Error('controlled retained intent conflict');
  retained.set(filePath,Buffer.from(bytes));if(fault==='before'){fault=null;throw Error('synthetic before promotion failure');}
  files.set(filePath,Buffer.from(bytes));if(fault==='after'){fault=null;throw Error('synthetic lost promotion acknowledgement');}
 }};
 const options={filesystemPlatform:'win32',privateState,journal,fileSystem},storage=createLocalDockerAuthorityStorage(options);
 return {storage,files,calls,retained,options,deny(){unsafe=true;},fault(value){fault=value;}};
}
test('Windows assertions use native private admission and one bounded snapshot for authority parsing',async()=>{
 const f=fixture(wire(authority));assert.equal(await f.storage.assertPrivateDirectory(directory,{platform:'linux'}),undefined);
 const snapshot=await f.storage.assertPrivateStateFile(filename,{platform:'darwin'});assert(Buffer.isBuffer(snapshot));snapshot.fill(0);
 const start=f.calls.length,result=await f.storage.readLocalDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32'});
 assert.deepEqual(result,authority);assert(Object.isFrozen(result));assert.deepEqual(f.calls.slice(start).map(c=>c[0]),['inspect','lstat','read']);assert(f.files.get(filename).equals(wire(authority)));
});
test('Windows missing metadata is advisory, while observed denied files never become missing or replacement authority',async()=>{
 const absent=fixture();assert.equal(await absent.storage.readLocalDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32'}),null);assert(!absent.calls.some(c=>c[0]==='read'||c[0]==='create'));
 const f=fixture(wire(authority));f.options.privateState.readPrivateFile=()=>{throw Object.assign(Error('secret denied'),{code:'ENOENT'});};
 await assert.rejects(f.storage.resolveDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32',environment:{DOCKER_HOST:host},persist:true,execute:async()=>{throw Error('daemon must not be contacted');}}),e=>e instanceof LocalDockerAuthorityError&&e.code==='LOCAL_DOCKER_AUTHORITY_INVALID'&&!String(e.stack).includes('secret denied'));
 assert(!f.calls.some(c=>c[0]==='create'));assert(f.files.get(filename).equals(wire(authority)));
});
test('Windows fresh authority uses exact existing JSON with native create-new and preserves named pipe/digest',async()=>{
 const f=fixture(),docker=[];
 const result=await f.storage.resolveDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32',environment:{DOCKER_HOST:host,DOCKER_TLS_VERIFY:'ambient',DOCKER_CERT_PATH:'ambient'},persist:true,execute:async(command,args,options)=>{
  docker.push({command,args,options});return {stdout:'"daemon-owned"'};
 }});
 assert.equal(result.persisted,true);assert.equal(result.authority.host,host);assert(f.files.get(filename).equals(wire(authority)));assert.match(authorityDigest(result.authority),/^[a-f0-9]{64}$/);
 assert.deepEqual(docker[0].args,['--host',host,'info','--format','{{json .ID}}']);assert.equal(docker[0].options.env.DOCKER_HOST,undefined);assert.equal(docker[0].options.env.DOCKER_TLS_VERIFY,undefined);
 assert.equal(f.calls.filter(c=>c[0]==='create').length,1);assert(!f.files.has(filename+'.pending'));
});
test('Windows saved authority ignores conflicting ambient endpoints but rejects daemon replacement',async()=>{
 const f=fixture(wire(authority));const result=await f.storage.resolveDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32',environment:{DOCKER_HOST:'tcp://remote.invalid:2375',DOCKER_CONTEXT:'remote'},execute:async(_command,args,options)=>{
  assert.deepEqual(args.slice(0,3),['--host',host,'info']);assert.equal(options.env.DOCKER_CONTEXT,undefined);assert.equal(options.env.DOCKER_HOST,undefined);return {stdout:'"daemon-owned"'};
 }});assert.equal(result.persisted,true);assert.equal(f.calls.filter(c=>c[0]==='create').length,0);
 await assert.rejects(f.storage.resolveDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32',environment:{},execute:async()=>({stdout:'"different-daemon"'})}),/different daemon/);
 await assert.rejects(verifyDockerAuthority({authority,environment:{},execute:async()=>({stdout:'"different-daemon"'})}),/different daemon/);
});
test('Windows remote/malformed/ambiguous endpoint selection is denied without daemon access',async()=>{
 let calls=0;for(const value of ['tcp://remote.invalid:2375','ssh://remote.invalid','unix:///var/run/docker.sock','npipe:////remote/pipe/docker_engine','npipe:////./pipe/docker_engine\n'])await assert.rejects(resolveLocalDockerHost({platform:'win32',environment:{DOCKER_HOST:value},execute:async()=>{calls++;}}),LocalDockerAuthorityError);
 await assert.rejects(resolveLocalDockerHost({platform:'win32',environment:{DOCKER_HOST:host,DOCKER_CONTEXT:'default'},execute:async()=>{calls++;}}),/both set/);assert.equal(calls,0);
});
test('Windows uncertain native persistence retains intent and exact bytes before/after promotion',async()=>{
 for(const point of ['before','after']){const f=fixture();f.fault(point);await assert.rejects(f.storage.writeLocalDockerAuthority({directory,authority}),LocalDockerAuthorityError);
  const retained=Buffer.from(f.retained.get(filename));assert(retained.equals(wire(authority)));if(point==='after')assert(f.files.get(filename).equals(retained));
  await f.storage.writeLocalDockerAuthority({directory,authority});assert(f.files.get(filename).equals(retained));assert.equal(f.retained.size,1);
 }
});
test('Windows existing unrelated authority or legacy pending file is never overwritten or removed',async()=>{
 const existing=fixture(wire({...authority,daemonId:'operator-owned'})),bytes=Buffer.from(existing.files.get(filename));await assert.rejects(existing.storage.writeLocalDockerAuthority({directory,authority}),LocalDockerAuthorityError);assert(existing.files.get(filename).equals(bytes));
 const legacy=fixture();legacy.files.set(filename+'.pending',Buffer.from('retained legacy data'));await assert.rejects(legacy.storage.writeLocalDockerAuthority({directory,authority}),/pending.*review/);assert.equal(legacy.files.get(filename+'.pending').toString(),'retained legacy data');assert(!legacy.calls.some(c=>c[0]==='create'));
});
test('Windows malformed, foreign workspace and oversized snapshots deny without creation',async()=>{
 for(const bytes of [Buffer.from('{partial'),wire({...authority,workspaceId:'foreign'}),wire({...authority,host:'tcp://remote.invalid:2375'}),Buffer.alloc(1024*1024+1)]){const f=fixture(bytes);await assert.rejects(f.storage.readLocalDockerAuthority({directory,workspaceId:authority.workspaceId,platform:'win32'}),LocalDockerAuthorityError);assert(!f.calls.some(c=>c[0]==='create'));assert(f.files.get(filename).equals(bytes));}
 const unsafe=fixture(wire(authority));unsafe.deny();await assert.rejects(unsafe.storage.assertPrivateDirectory(directory),LocalDockerAuthorityError);await assert.rejects(unsafe.storage.assertPrivateStateFile(filename),LocalDockerAuthorityError);
});
test('filesystem platform is independent of selected Docker platform and POSIX bypass is removed',async()=>{
 let nativeCalls=0;const stat={uid:1,mode:0o700,isFile:()=>false,isDirectory:()=>true,isSymbolicLink:()=>false};
 const storage=createLocalDockerAuthorityStorage({filesystemPlatform:'darwin',privateState:new Proxy({}, {get(){nativeCalls++;throw Error('wrong native filesystem');}}),fileSystem:{async lstat(){return stat;}}});
 await storage.assertPrivateDirectory('/controlled',{uid:1,platform:'win32'});stat.mode=0o777;await assert.rejects(storage.assertPrivateDirectory('/controlled',{uid:1,platform:'win32'}),LocalDockerAuthorityError);assert.equal(nativeCalls,0);
 const f=fixture(wire(authority));await f.storage.assertPrivateDirectory(directory,{platform:'darwin'});assert.equal(f.calls[0][0],'inspect');
});
