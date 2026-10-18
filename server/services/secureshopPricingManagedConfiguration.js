'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const {workspaceId}=require('../../scripts/application-data-root');
const {normalizePrivatePath}=require('../../scripts/lib/windows-private-state');
const {validateAuthorityState,authorityDigest}=require('../../scripts/local-docker-authority');
const fail=()=>Object.assign(Error('Owned Pricing managed configuration unavailable'),{code:'PRICING_MANAGED_CONFIGURATION_INVALID'});
const hash=x=>createHash('sha256').update(x).digest('hex');
const capturedRecords=new WeakSet();
const FIELDS=['version','enabled','workspaceId','ownerId','dockerAuthoritySha256','containerName','containerId','imageId','packageSha256','profile','port','token'];
function validate(value,{root}){
 const id=workspaceId(root);
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join()!==[...FIELDS].sort().join()||value.version!==1||typeof value.enabled!=='boolean'||value.workspaceId!==id||value.containerName!=='dvaia-pricing-'+id||value.profile!=='dvaia-owned-pricing-http-'+id||!['containerId','dockerAuthoritySha256','packageSha256'].every(k=>/^[a-f0-9]{64}$/.test(value[k]))||!/^sha256:[a-f0-9]{64}$/.test(value.imageId)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.ownerId)||!Number.isInteger(value.port)||value.port<1024||value.port>65535||!/^[A-Za-z0-9_-]{43,128}$/.test(value.token))throw fail();
 return Object.freeze(Object.fromEntries(FIELDS.map(key=>[key,value[key]])));
}
function captureFile(filename,limit){
 let fd;
 try{const parent=fs.lstatSync(path.dirname(filename));if(!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==process.getuid()||(parent.mode&0o077))throw fail();
  fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const before=fs.fstatSync(fd);
  if(!before.isFile()||before.uid!==process.getuid()||(before.mode&0o077)||before.nlink!==1||before.size>limit)throw fail();
  const bytes=fs.readFileSync(fd),after=fs.fstatSync(fd),named=fs.lstatSync(filename);
  if(bytes.length!==before.size||before.ino!==named.ino||before.dev!==named.dev||named.isSymbolicLink()||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw fail();
  return {bytes,identity:{dev:before.dev,ino:before.ino},sha256:hash(bytes)};
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
function load({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}){
 if(process.platform==='win32'){try{root=normalizePrivatePath(root);home=normalizePrivatePath(home);}catch{throw fail();}}
 const directory=path.join(home,'.dvaia',workspaceId(root)),filename=path.join(directory,'pricing-managed.json');
 // Absence is optional; admission/read failures after this observation are not.
 try{const named=fs.lstatSync(filename);if(!named.isFile()||named.isSymbolicLink())throw fail();}catch(error){if(error.code==='ENOENT')return null;throw fail();}
 // Present Pricing state also supplies POSIX identity to activation/CAS. Native
 // identity support must be implemented across those consumers before admission.
 if(process.platform==='win32')throw fail();
 let captured;try{captured=captureFile(filename,16384);}catch{throw fail();}
 try{const config=validate(JSON.parse(captured.bytes),{root}),authorityCapture=captureFile(path.join(directory,'local-docker.json'),8192),authority=validateAuthorityState(JSON.parse(authorityCapture.bytes),{workspaceId:workspaceId(root)});
  if(authorityDigest(authority)!==config.dockerAuthoritySha256)throw fail();
  const record=Object.freeze({config,authority,filename,sha256:captured.sha256,identity:Object.freeze(captured.identity)});capturedRecords.add(record);return record;
 }catch{throw fail();}
}
function environment(options={}){const record=load(options);if(!record?.config.enabled)return Object.freeze({});const env=options.environment||process.env;if(env.SS_BOUND_PRICING_ENABLED!==undefined&&env.SS_BOUND_PRICING_ENABLED!=='true')throw fail();return Object.freeze({SS_BOUND_PRICING_ENABLED:'true'});}
function paths({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}) {
 if(!path.isAbsolute(root)||!path.isAbsolute(home))throw fail();
 const directory=path.join(home,'.dvaia',workspaceId(root));return {directory,filename:path.join(directory,'pricing-managed.json')};
}
function assertPrivateDirectory(directory){const stat=fs.lstatSync(directory);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o077))throw fail();return stat;}
function syncParent(directory){const fd=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function removeOwned(filename,identity){const current=fs.lstatSync(filename);if(current.dev!==identity.dev||current.ino!==identity.ino||current.isSymbolicLink())throw fail();fs.unlinkSync(filename);}
function publishImmutable(filename,bytes){
 const directory=path.dirname(filename);assertPrivateDirectory(directory);
 const pending=path.join(directory,'.pricing-'+require('node:crypto').randomBytes(12).toString('hex')+'.pending');let fd,created=false,pendingIdentity;
 try{fd=fs.openSync(pending,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);pendingIdentity=fs.fstatSync(fd);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  try{fs.linkSync(pending,filename);created=true;}catch(error){if(error.code!=='EEXIST')throw error;}
 }finally{if(fd!==undefined)fs.closeSync(fd);if(pendingIdentity)removeOwned(pending,pendingIdentity);}
 syncParent(directory);
 const current=captureFile(filename,16384);if(!current.bytes.equals(Buffer.from(bytes)))throw fail();return created;
}
function stage({root,home,value}={}){
 const config=validate(value,{root}),location=paths({root,home});if(config.enabled)throw fail();
 const authority=validateAuthorityState(JSON.parse(captureFile(path.join(location.directory,'local-docker.json'),8192).bytes),{workspaceId:workspaceId(root)});if(authorityDigest(authority)!==config.dockerAuthoritySha256)throw fail();
 const existing=load({root,home});if(existing){if(JSON.stringify(existing.config)!==JSON.stringify(config))throw fail();return Object.freeze({created:false,record:existing});}
 const created=publishImmutable(location.filename,Buffer.from(JSON.stringify(config)+'\n'));
 return Object.freeze({created,record:load({root,home})});
}
function compareAndSwap({root,home,expected,enabled}={}){
 if(!capturedRecords.has(expected)||typeof enabled!=='boolean')throw fail();
 const {filename,directory}=paths({root,home});if(expected.filename!==filename)throw fail();assertPrivateDirectory(directory);
 const lock=path.join(directory,'.pricing-managed.lock');let lockFd,lockIdentity,pending,pendingIdentity;
 const same=current=>current&&current.sha256===expected.sha256&&current.identity.ino===expected.identity.ino&&current.identity.dev===expected.identity.dev;
 try{
  lockFd=fs.openSync(lock,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);lockIdentity=fs.fstatSync(lockFd);
  if(!same(load({root,home})))throw fail();if(expected.config.enabled===enabled)return expected;
  const config=validate({...expected.config,enabled},{root});pending=path.join(directory,'.pricing-activate-'+require('node:crypto').randomBytes(12).toString('hex')+'.pending');
  const fd=fs.openSync(pending,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  pendingIdentity=fs.fstatSync(fd);
  try{fs.writeFileSync(fd,JSON.stringify(config)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  if(!same(load({root,home})))throw fail();fs.renameSync(pending,filename);pending=undefined;syncParent(directory);return load({root,home});
 }finally{if(pending&&pendingIdentity)removeOwned(pending,pendingIdentity);if(lockFd!==undefined){fs.closeSync(lockFd);removeOwned(lock,lockIdentity);}}
}
module.exports={validate,load,environment,paths,stage,compareAndSwap,_private:{captureFile,publishImmutable,assertPrivateDirectory}};
