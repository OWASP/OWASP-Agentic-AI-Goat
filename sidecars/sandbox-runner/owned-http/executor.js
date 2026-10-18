'use strict';
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const {parseUrl} = require('./worker');
const ROOT='/usr/local/libexec/';
const ASSETS=Object.freeze(['/usr/bin/bwrap','/usr/local/bin/node',`${ROOT}dvaia-owned-http-init`,`${ROOT}dvaia-owned-http-supervisor`,`${ROOT}dvaia-owned-http-worker.js`,`${ROOT}dvaia-owned-http-manifest.json`,`${ROOT}dvaia-owned-http-hosts`,`${ROOT}dvaia-owned-http-nsswitch`,`${ROOT}dvaia-owned-http-resolv`,'/usr/share/dvaia/mcp-target.seccomp.bpf']);
const REGISTRY='/usr/share/dvaia/owned-http-assets.json';
function fail(code){throw Object.assign(Error(code),{code});}
function trustedBytes(file,max=268435456){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const before=fs.fstatSync(fd);if(!before.isFile()||before.uid!==0||(before.mode&0o022)||before.nlink!==1||before.size>max)fail('HTTP_ASSET_UNTRUSTED');const bytes=fs.readFileSync(fd);const after=fs.fstatSync(fd);if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)fail('HTTP_ASSET_CHANGED');return bytes;}finally{fs.closeSync(fd);}
}
function trustedHash(file){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const before=fs.fstatSync(fd);if(!before.isFile()||before.uid!==0||(before.mode&0o022)||before.nlink!==1||before.size>268435456)fail('HTTP_ASSET_UNTRUSTED');
  const hash=crypto.createHash('sha256'),chunk=Buffer.alloc(1048576);let offset=0;
  while(offset<before.size){const count=fs.readSync(fd,chunk,0,Math.min(chunk.length,before.size-offset),offset);if(count===0)fail('HTTP_ASSET_CHANGED');hash.update(chunk.subarray(0,count));offset+=count;}
  const after=fs.fstatSync(fd);if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)fail('HTTP_ASSET_CHANGED');return hash.digest('hex');
 }finally{fs.closeSync(fd);}
}
function verifyAssets(){
 const registry=JSON.parse(trustedBytes(REGISTRY,16384));
 if(Object.keys(registry).sort().join(',')!==[...ASSETS].sort().join(','))fail('HTTP_ASSET_REGISTRY_INVALID');
 for(const file of ASSETS)if(trustedHash(file)!==registry[file])fail('HTTP_ASSET_CHANGED');
 return registry;
}
function createOwnedHttpExecutor({expectedProfile,timeoutMs=8000}={}){
 if(!/^dvaia-owned-http-[a-f0-9]{12}$/.test(expectedProfile||'')||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw TypeError('Qualified dedicated HTTP profile required');
 async function checkReadiness(){
  if(process.platform!=='linux'||process.getuid()===0)fail('HTTP_PLATFORM_UNAVAILABLE');
  const label=(await fsp.readFile('/proc/self/attr/current','utf8')).trim();if(label!==`${expectedProfile} (enforce)`)fail('HTTP_PROFILE_UNAVAILABLE');
  const status=await fsp.readFile('/proc/self/status','utf8');for(const key of ['CapEff','CapPrm','CapInh','CapAmb'])if(!new RegExp('^'+key+':\\s+0+$','m').test(status))fail('HTTP_SUPERVISOR_CAPABILITIES');
  const hashes=verifyAssets();return {ready:true,manifestSha256:hashes[`${ROOT}dvaia-owned-http-manifest.json`]};
 }
 async function execute({input,signal}){
  if(!input||Object.keys(input).sort().join(',')!=='canary,mode,url'||!['fixed','vuln'].includes(input.mode)||!/^[a-f0-9]{64}$/.test(input.canary))fail('HTTP_REQUEST_INVALID');
  parseUrl(input.url);const bytes=JSON.stringify(input);if(Buffer.byteLength(bytes)>4096)fail('HTTP_REQUEST_INVALID');
  await checkReadiness();if(signal?.aborted)fail('HTTP_OPERATION_ABORTED');
  const argv=['--uid','0','--gid','0','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP','--cap-add','CAP_NET_BIND_SERVICE','--unshare-user','--unshare-net','--unshare-pid','--unshare-uts','--unshare-ipc','--die-with-parent','--new-session','--clearenv','--tmpfs','/','--dev','/dev','--dir','/proc'];
  for(const p of ['/usr','/bin','/lib','/lib64'])if(fs.existsSync(p))argv.push('--dir',p,'--ro-bind',p,p);
  argv.push('--dir','/etc','--ro-bind',`${ROOT}dvaia-owned-http-hosts`,'/etc/hosts','--ro-bind',`${ROOT}dvaia-owned-http-nsswitch`,'/etc/nsswitch.conf','--ro-bind',`${ROOT}dvaia-owned-http-resolv`,'/etc/resolv.conf','--dir','/tmp','--hostname','mcp-owned-http','--seccomp','3','--chdir','/tmp',`${ROOT}dvaia-owned-http-init`,'--initialize');
  const fd=fs.openSync('/usr/share/dvaia/mcp-target.seccomp.bpf',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  // Recheck the exact opened filter, not only its pathname before launch.
  try {const filter=Buffer.alloc(fs.fstatSync(fd).size);if(filter.length>65536||fs.readSync(fd,filter,0,filter.length,0)!==filter.length)fail('HTTP_ASSET_CHANGED');const hash=crypto.createHash('sha256').update(filter).digest('hex');if(hash!==verifyAssets()['/usr/share/dvaia/mcp-target.seccomp.bpf'])fail('HTTP_ASSET_CHANGED');}catch(error){fs.closeSync(fd);throw error;}
  return new Promise((resolve,reject)=>{
   let child;try{child=spawn(`${ROOT}dvaia-owned-http-supervisor`,argv,{env:{PATH:'/usr/bin:/bin'},stdio:['pipe','pipe','pipe',fd]});}catch(error){fs.closeSync(fd);reject(error);return;}fs.closeSync(fd);
   let failure=null,count=0;const chunks=[],errors=[];
   const stop=code=>{failure ||= Object.assign(Error(code),{code});child.kill('SIGTERM');};
   const abort=()=>stop('HTTP_OPERATION_ABORTED');signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
   const timer=setTimeout(()=>stop('HTTP_EXECUTION_TIMEOUT'),timeoutMs);
   const append=(data,stdout)=>{count+=data.length;if(count>65536){stop('HTTP_OUTPUT_LIMIT');return;}if(stdout)chunks.push(data);else errors.push(data);};
   child.stdout.on('data',data=>append(data,true));child.stderr.on('data',data=>append(data,false));
   child.stdin.on('error',()=>{stop('HTTP_INPUT_FAILURE');});child.on('error',error=>{failure ||= error;});
   // Packaged subreaper kills and joins its own adopted namespace descendants.
   // Settle only after close (process reaped and all inherited pipes closed).
   child.once('close',code=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);if(failure)return reject(failure);if(code!==0)return reject(Object.assign(Error('HTTP_CHILD_FAILED'),{code:'HTTP_CHILD_FAILED',exitCode:code,diagnostic:Buffer.concat(errors).toString('utf8').slice(0,2048)}));try{resolve({drained:true,result:JSON.parse(Buffer.concat(chunks).toString('utf8'))});}catch(error){reject(error);}});
   child.stdin.end(bytes);
  });
 }
 return Object.freeze({execute,checkReadiness});
}
module.exports={createOwnedHttpExecutor,ASSETS};
