'use strict';
// The actual installer function and JS adapter run against a controlled native
// executor. No Windows APIs, installers, sidecars or databases are executed.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),fsp=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),{createRequire}=require('node:module');
const {prepareSetupPrivateDirectory:prepare}=require('../scripts/setup-application');
const {createWindowsPrivateState}=require('../scripts/lib/windows-private-state');
const file=path.resolve(__dirname,'../scripts/setup-application.js');
const id='abcdef123456',homeDirectory='C:\\Users\\Learner',privateBase=homeDirectory+'\\.dvaia',directory=privateBase+'\\'+id;
const denied={code:'SETUP_PRIVATE_DIRECTORY_INVALID',message:'Private setup directory unavailable'};
function controlled(){
 const calls=[],existing=new Map();let deniedPath=null,deniedOperation=null;
 const privateState=createWindowsPrivateState({platform:'win32',systemRoot:'C:\\Windows',execute(executable,args,wire){
  const request=JSON.parse(wire.input);calls.push(request);
  if(request.path===deniedPath&&request.operation===deniedOperation)throw Object.assign(Error('synthetic private diagnostic'),{stderr:'synthetic private diagnostic'});
  if(request.operation==='ensurePrivateDirectory'){if(!existing.has(request.path))existing.set(request.path,{volumeSerial:27,fileId:(existing.size+1).toString(16).padStart(16,'0')});}
  else if(request.operation!=='inspectPrivateDirectory'||!existing.has(request.path))throw Error('controlled directory unavailable');
  return JSON.stringify({version:1,ok:true,operation:request.operation,path:request.path,size:null,identity:existing.get(request.path)});
 }});
 return {calls,existing,options:{homeDirectory,directory,id,filesystemPlatform:'win32',privateState},deny(p,operation){deniedPath=p;deniedOperation=operation;}};
}
test('Windows installer creates only explicit private base and workspace leaves then rechecks both',async()=>{
 const f=controlled();await prepare(f.options);
 assert.deepEqual(f.calls.map(r=>[r.operation,r.path]),[['ensurePrivateDirectory',privateBase],['ensurePrivateDirectory',directory],['inspectPrivateDirectory',privateBase],['inspectPrivateDirectory',directory]]);
 assert.deepEqual([...f.existing.keys()],[privateBase,directory]);const original=[...f.existing.values()];
 await prepare(f.options);assert.deepEqual([...f.existing.values()],original);
 assert(!f.calls.some(r=>r.path===homeDirectory||r.operation==='createPrivateFile'));
});
test('Windows private-base or workspace admission failure stops and retains already created directory',async()=>{
 for(const [p,operation,expected] of [[privateBase,'ensurePrivateDirectory',1],[directory,'ensurePrivateDirectory',2],[privateBase,'inspectPrivateDirectory',3],[directory,'inspectPrivateDirectory',4]]){
  const f=controlled();f.deny(p,operation);await assert.rejects(prepare(f.options),error=>{assert.equal(error.code,denied.code);assert.equal(error.message,denied.message);assert.equal(error.cause,undefined);assert(!String(error.stack).includes('synthetic private diagnostic'));return true;});
  assert.equal(f.calls.length,expected);if(expected>1)assert(f.existing.has(privateBase));
  assert(!f.calls.some(r=>/delete|remove/i.test(r.operation)));
 }
});
test('Windows installer rejects escape, UNC/device, ambiguous components and unrelated directory identity before executor',async()=>{
 const f=controlled();for(const change of [{homeDirectory:'\\\\host\\share'},{homeDirectory:'C:\\Users\\Learner\\..\\Other'},{homeDirectory:'C:\\Users\\Learner.'},{homeDirectory:'C:\\Users\\NUL'},{directory:'C:\\Users\\Learner\\other\\'+id},{directory:directory+':stream'},{directory:'\\\\?\\'+directory},{id:'not-an-installation'},{id:'ABCDEF123456'},{directory:privateBase},{homeDirectory:'C:\\'}]){
  await assert.rejects(prepare({...f.options,...change}),denied);
 }assert.equal(f.calls.length,0);assert.equal(f.existing.size,0);
});
test('Windows drive-letter normalization preserves requested installation suffix and workspace ID',async()=>{
 const f=controlled();await prepare({...f.options,homeDirectory:'c:'+homeDirectory.slice(2),directory:'c:'+directory.slice(2)});
 assert.deepEqual(f.calls.map(r=>r.path),[privateBase,directory,privateBase,directory]);assert(f.existing.has(directory));
});
test('POSIX private-directory preparation retains recursive mkdir and chmod behavior',async t=>{
 const base=await fsp.mkdtemp(path.join(os.tmpdir(),'setup-private-directory-'));t.after(()=>fsp.rm(base,{recursive:true,force:true}));
 const target=path.join(base,'private','installation');await prepare({homeDirectory:base,directory:target,id,filesystemPlatform:'darwin',privateState:new Proxy({}, {get(){throw Error('native authority must not be used');}})});
 assert.equal((await fsp.stat(target)).mode&0o777,0o700);await fsp.chmod(target,0o755);await prepare({directory:target,filesystemPlatform:'linux'});assert.equal((await fsp.stat(target)).mode&0o777,0o700);
});
function variant(platform,filesystem){
 const module={exports:{}},requireHere=createRequire(file);vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,__dirname:path.dirname(file),Buffer,console,process:{...process,platform},require:n=>n==='node:fs/promises'?filesystem:requireHere(n)});return module.exports.prepareSetupPrivateDirectory;
}
test('default installer filesystem authority follows actual host rather than selected sidecar platform',async()=>{
 const calls=[],posix=variant('darwin',{async mkdir(p,options){calls.push(['mkdir',p,options]);},async chmod(p,mode){calls.push(['chmod',p,mode]);}});
 await posix({directory:'/controlled/private',platform:'win32',privateState:new Proxy({}, {get(){throw Error('wrong filesystem platform');}})});
 assert.equal(calls.length,2);assert.equal(calls[0][0],'mkdir');assert.equal(calls[0][2].recursive,true);assert.equal(calls[1][2],0o700);
 const f=controlled(),native=variant('win32',new Proxy({}, {get(){throw Error('POSIX mode checks unavailable');}}));
 const {filesystemPlatform,...options}=f.options;await native(options);assert.equal(f.calls.length,4);
});
test('installer call retains fresh no-overwrite ordering and does not forward logical platform to filesystem authority',()=>{
 const source=fs.readFileSync(file,'utf8'),fresh=source.indexOf('Fresh setup will not overwrite'),prepareCall=source.indexOf('await prepareSetupPrivateDirectory({ homeDirectory, directory, id });'),runtime=source.indexOf('const runtime = await (prepareRuntime || prepareInstalledRuntime)',prepareCall);
 assert(fresh>0&&fresh<prepareCall&&prepareCall<runtime);assert(!source.includes('prepareSetupPrivateDirectory({ homeDirectory, directory, id, platform'));
 assert(source.includes('filesystemPlatform = process.platform'));assert(source.includes('native.ensurePrivateDirectory(privateBase)'));assert(source.includes('native.ensurePrivateDirectory(directory)'));
});
