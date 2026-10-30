'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),http=require('node:http'),net=require('node:net');
const STATE_VERSION=2;
function statePath(workspace){return path.join(os.homedir(),'.owasp-ai-goat',crypto.createHash('sha256').update(fs.realpathSync(workspace)).digest('hex').slice(0,12),'launcher.json');}
function error(code,message){return Object.assign(new Error(message),{code});}
function windowsState(){return require('./lib/windows-private-state');}
function ensurePrivateDirectory(stateFile){
 const directory=path.dirname(stateFile);
 if(process.platform==='win32'){
  // Create only the two requested leaves, sequentially, under an existing
  // home. Native admission checks every ancestor; no recursive mkdir fallback.
  windowsState().ensurePrivateDirectory(path.dirname(directory));
  windowsState().ensurePrivateDirectory(directory);return;
 }
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const stat=fs.lstatSync(directory);
 if(!stat.isDirectory()||stat.isSymbolicLink()||(process.platform!=='win32'&&((stat.mode&0o077)||stat.uid!==process.getuid())))
  throw error('LAUNCHER_STATE_DIRECTORY_UNSAFE','Launcher state directory is not private');
}
function readState(stateFile,workspace){
 let stat,raw,bytes,identity;
 if(process.platform==='win32'){
  // lstat is an existence observation only. Bytes and file identity come from
  // the same native read handle; ACL/one-link/reparse checks happen there.
  fs.lstatSync(stateFile);
  const snapshot=windowsState().readPrivateFileSnapshot(stateFile);
  if(snapshot.size>4096)throw error('LAUNCHER_STATE_UNSAFE','Launcher state exceeds its bounded size');
  bytes=snapshot.bytes;raw=bytes.toString('utf8');identity=snapshot.identity;
 }else{
  stat=fs.lstatSync(stateFile);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>4096||(stat.mode&0o077)||stat.uid!==process.getuid())
   throw error('LAUNCHER_STATE_UNSAFE','Launcher state is not a private regular file');
  raw=fs.readFileSync(stateFile,'utf8');
 }
 let state;
 try{state=JSON.parse(raw);}catch{throw error('LAUNCHER_STATE_INVALID','Invalid launcher state');}
 if(!state||typeof state!=='object'||Array.isArray(state)||![1,STATE_VERSION].includes(state.version)
  ||state.workspace!==fs.realpathSync(workspace)||!Number.isInteger(state.port)||state.port<1||state.port>65535
  ||!/^[a-f0-9]{64}$/.test(state.token)
  ||(state.version===STATE_VERSION&&(!Number.isSafeInteger(state.ownerPid)||state.ownerPid<1)))
  throw error('LAUNCHER_STATE_INVALID','Invalid launcher state or workspace binding');
 return process.platform==='win32'?{state,raw,bytes,identity}:{state,raw,stat};
}
function ownerAbsent(pid){
 try{process.kill(pid,0);return false;}catch(cause){
  if(cause.code==='ESRCH')return true;
  if(cause.code==='EPERM')return false;
  throw error('LAUNCHER_OWNER_UNKNOWN','Launcher owner cannot be verified');
 }
}
function controlPortClosed(port,{timeoutMs=500}={}){
 return new Promise((resolve,reject)=>{
  const socket=net.createConnection({host:'127.0.0.1',port});let settled=false;
  const finish=(value,cause)=>{if(settled)return;settled=true;socket.destroy();cause?reject(cause):resolve(value);};
  socket.setTimeout(timeoutMs,()=>finish(null,error('LAUNCHER_PORT_UNKNOWN','Launcher control port could not be verified')));
  socket.once('connect',()=>finish(false));
  socket.once('error',cause=>cause.code==='ECONNREFUSED'?finish(true):finish(null,error('LAUNCHER_PORT_UNKNOWN','Launcher control port could not be verified')));
 });
}
function removeMatchingState(stateFile,observed){
 if(process.platform==='win32'){
  // Native deletion compares the retained exact bytes and native identity on
  // its exclusive held handle. Denial/uncertainty retains state; no unlink.
  windowsState().deleteMatchingPrivateFile(stateFile,observed.bytes,observed.identity);return true;
 }
 let current;
 try{current=fs.lstatSync(stateFile);}catch(cause){if(cause.code==='ENOENT')return false;throw cause;}
 if(!current.isFile()||current.isSymbolicLink()||current.dev!==observed.stat.dev||current.ino!==observed.stat.ino
  ||fs.readFileSync(stateFile,'utf8')!==observed.raw)
  throw error('LAUNCHER_STATE_CHANGED','Launcher state changed during recovery');
 fs.unlinkSync(stateFile);return true;
}
async function recoverStaleController({workspace,stateFile,observed}){
 const record=observed||readState(stateFile,workspace);
 if(record.state.version!==STATE_VERSION)
  throw error('LAUNCHER_LEGACY_STATE','Legacy launcher state has no owner proof; inspect it manually. No process or port was killed.');
 if(!ownerAbsent(record.state.ownerPid))
  throw error('LAUNCHER_OWNER_PRESENT','Launcher owner is still present or cannot be ruled out; controller state was retained. No process or port was killed.');
 if(!await controlPortClosed(record.state.port))
  throw error('LAUNCHER_PORT_OCCUPIED','Launcher control port is occupied; controller state was retained. No process or port was killed.');
 if(!ownerAbsent(record.state.ownerPid))
  throw error('LAUNCHER_OWNER_PRESENT','Launcher owner appeared during recovery; controller state was retained.');
 removeMatchingState(stateFile,record);
 return {controllerRecovered:true,childrenStopped:false};
}
function publishState(stateFile,state){
 const raw=JSON.stringify(state)+'\n';
 if(process.platform==='win32'){
  const bytes=Buffer.from(raw,'utf8'),created=windowsState().createPrivateFile(stateFile,bytes);
  const snapshot=windowsState().readPrivateFileSnapshot(stateFile);
  if(snapshot.size!==bytes.length||!snapshot.bytes.equals(bytes)
    ||snapshot.identity.volumeSerial!==created.identity.volumeSerial||snapshot.identity.fileId!==created.identity.fileId)
   throw error('LAUNCHER_STATE_CHANGED','Launcher state changed during publication');
  return {raw,bytes,identity:snapshot.identity};
 }
 const temporary=`${stateFile}.${crypto.randomBytes(12).toString('hex')}.tmp`;
 let fd;
 try{
  fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,raw);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  fs.linkSync(temporary,stateFile);
  return {raw,stat:fs.lstatSync(stateFile)};
 }finally{
  if(fd!==undefined)fs.closeSync(fd);
  try{fs.unlinkSync(temporary);}catch(cause){if(cause.code!=='ENOENT')throw cause;}
 }
}
async function createController({workspace,stateFile=statePath(workspace),stop}){
 ensurePrivateDirectory(stateFile);
 let existing=false;
 try{fs.lstatSync(stateFile);existing=true;}catch(cause){if(cause.code!=='ENOENT')throw cause;}
 if(existing)await recoverStaleController({workspace,stateFile});
 const token=crypto.randomBytes(32).toString('hex');let stopping=false,closePromise,publication;
 const server=http.createServer((req,res)=>{
  const supplied=Buffer.from(req.headers.authorization||'');const expected=Buffer.from('Bearer '+token);
  if(supplied.length!==expected.length||!crypto.timingSafeEqual(supplied,expected)){res.writeHead(403);return res.end();}
  if(req.method!=='POST'||req.url!=='/stop'){res.writeHead(404);return res.end();}
  if(stopping){res.writeHead(202);return res.end('Stopping');}stopping=true;
  Promise.resolve().then(stop).then(()=>{res.writeHead(200);res.end('Stopped',()=>{
   const pending=close();
   // requestStop checks release separately and reports retained state. Native
   // cleanup failure must not become an unhandled rejection or raw fallback.
   if(process.platform==='win32')void pending.catch(()=>{});
  });},()=>{
   stopping=false;res.writeHead(500);res.end('Owned process shutdown failed');
  });
 });
 async function close(){
  if(closePromise)return closePromise;
  closePromise=(async()=>{
   if(server.listening)await new Promise(resolve=>server.close(resolve));
   if(publication){try{removeMatchingState(stateFile,publication);}catch(cause){if(cause.code!=='ENOENT'&&cause.code!=='LAUNCHER_STATE_CHANGED')throw cause;}}
  })();return closePromise;
 }
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  publication=publishState(stateFile,{version:STATE_VERSION,workspace:fs.realpathSync(workspace),port:server.address().port,token,ownerPid:process.pid});
  return{close,stateFile};
 }catch(cause){await close();if(cause.code==='EEXIST')throw error('LAUNCHER_STATE_EXISTS','Launcher state already exists; an owner may be starting. No process or port was killed.');throw cause;}
}
function postStop(state,{timeoutMs=15000}={}){
 return new Promise((resolve,reject)=>{
  const req=http.request({host:'127.0.0.1',port:state.port,path:'/stop',method:'POST',agent:false,
   headers:{Authorization:'Bearer '+state.token,Connection:'close'},timeout:timeoutMs},res=>{
   res.resume();res.on('end',()=>res.statusCode===200?resolve():reject(error('LAUNCHER_STOP_REJECTED','Launcher rejected shutdown ('+res.statusCode+')')));
  });
  req.on('timeout',()=>req.destroy(error('LAUNCHER_STOP_TIMEOUT','Owned launcher shutdown timed out; state was retained.')));
  req.on('error',reject);req.end();
 });
}
async function waitForStateRelease(stateFile,observed,timeoutMs){
 const deadline=Date.now()+Math.min(timeoutMs,1000);
 while(true){
  let current;
  try{current=fs.lstatSync(stateFile);}catch(cause){if(cause.code==='ENOENT')return;throw cause;}
  if(process.platform==='win32'){
   let snapshot;
   try{snapshot=windowsState().readPrivateFileSnapshot(stateFile);}catch(cause){
    // The authenticated controller can delete between existence and native
    // read. A scrubbed native denial alone is not absence; a fresh named
    // ENOENT observation is required. Present/inaccessible state still fails.
    try{fs.lstatSync(stateFile);}catch(missing){if(missing.code==='ENOENT')return;}
    throw cause;
   }
   if(snapshot.identity.volumeSerial!==observed.identity.volumeSerial||snapshot.identity.fileId!==observed.identity.fileId)return;
   if(snapshot.size>4096||!snapshot.bytes.equals(observed.bytes))
    throw error('LAUNCHER_STATE_CHANGED','Launcher state changed during shutdown');
   if(Date.now()>=deadline)
    throw error('LAUNCHER_STATE_RETAINED','Owned shutdown responded, but its controller state remains; inspect before restart.');
   await new Promise(resolve=>setTimeout(resolve,20));continue;
  }
  if(current.dev!==observed.stat.dev||current.ino!==observed.stat.ino)return;
  let raw;
  try{raw=fs.readFileSync(stateFile,'utf8');}catch(cause){if(cause.code==='ENOENT')return;throw cause;}
  if(raw!==observed.raw)
   throw error('LAUNCHER_STATE_CHANGED','Launcher state changed during shutdown');
  if(Date.now()>=deadline)
   throw error('LAUNCHER_STATE_RETAINED','Owned shutdown responded, but its controller state remains; inspect before restart.');
  await new Promise(resolve=>setTimeout(resolve,20));
 }
}
async function requestStop({workspace,stateFile=statePath(workspace),timeoutMs=15000}){
 const observed=readState(stateFile,workspace),{state}=observed;
 if(state.version===STATE_VERSION&&ownerAbsent(state.ownerPid))
  return recoverStaleController({workspace,stateFile,observed});
 try{await postStop(state,{timeoutMs});}
 catch(cause){
  if(cause.code==='LAUNCHER_STOP_TIMEOUT'||cause.code==='LAUNCHER_STOP_REJECTED')throw cause;
  if(state.version===STATE_VERSION&&ownerAbsent(state.ownerPid))
   return recoverStaleController({workspace,stateFile,observed});
  throw error('LAUNCHER_UNAVAILABLE','Owned launcher unavailable; controller state was retained. No PID or port was killed.');
 }
 await waitForStateRelease(stateFile,observed,timeoutMs);
 return{stopped:true,controllerRecovered:false};
}
function ownedShutdown(child,{platform=process.platform,kill=process.kill.bind(process),job,graceMs=5000}={}){
 let promise;
 if(platform==='win32')return()=>promise ||= (async()=>{
  if(!job||typeof job.stop!=='function'||typeof job.close!=='function')
   throw error('LAUNCHER_OWNED_JOB_UNAVAILABLE','Owned Windows Job Object authority is unavailable');
  await job.stop({graceMs});
  await job.close();
 })();
 return()=>promise ||= new Promise(resolve=>{
  if(!child.pid)return resolve();
  const signal=s=>{try{kill(-child.pid,s);}catch(e){if(e.code!=='ESRCH')throw e;}};
  signal('SIGTERM');
  // Wait the grace window even if npm exits first: its owned descendants can still be alive.
  setTimeout(()=>{signal('SIGKILL');resolve();},graceMs);
 });
}
if(require.main===module){const workspace=path.resolve(__dirname,'..');requestStop({workspace}).then(result=>console.log(result.controllerRecovered
 ? 'Stale controller state recovered. Application children were not proven stopped; check service ports before restart.'
 : 'Owned application stopped.')).catch(e=>{if(e.code==='ENOENT'){console.log('No owned launcher state found; nothing was stopped.');return;}console.error(e.message);process.exitCode=1;});}
module.exports={statePath,createController,requestStop,ownedShutdown};
