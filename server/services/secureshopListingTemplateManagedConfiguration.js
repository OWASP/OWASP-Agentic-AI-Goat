'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {workspaceId}=require('../../scripts/application-data-root');
const {validateAuthorityState,authorityDigest}=require('../../scripts/local-docker-authority');
const privateFiles=require('./secureshopPricingManagedConfiguration')._private;
const fields=['version','workspaceId','ownerId','architecture','dockerAuthoritySha256','sourceSha256','imageId','profile','profileSha256','container','containerId','port','enabled'];
const captures=new WeakSet();
const fail=()=>Object.assign(Error('Managed listing template configuration unavailable'),{code:'LISTING_TEMPLATE_MANAGED_INVALID'});
function paths({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}){
 if(!path.isAbsolute(root)||!path.isAbsolute(home)||fs.realpathSync(root)!==root||fs.realpathSync(home)!==home)throw fail();
 const directory=path.join(home,'.owasp-ai-goat',workspaceId(root));if(fs.existsSync(directory)&&fs.realpathSync(directory)!==directory)throw fail();
 return{directory,filename:path.join(directory,'listing-template-managed.json'),stage:path.join(directory,'listing-template-provisioning.json')};
}
function validate(raw,{root=path.resolve(__dirname,'../..')}={},staged=false){
 const id=workspaceId(root),keys=staged?[...fields.filter(k=>!['containerId','enabled'].includes(k)),'activateRequested']:fields;
 if(!raw||Object.getPrototypeOf(raw)!==Object.prototype||Object.keys(raw).sort().join()!==[...keys].sort().join()
  ||raw.version!==1||raw.workspaceId!==id||raw.architecture!=='arm64'
  ||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(raw.ownerId)||!['dockerAuthoritySha256','sourceSha256','profileSha256'].every(k=>/^[a-f0-9]{64}$/.test(raw[k]))
  ||!/^sha256:[a-f0-9]{64}$/.test(raw.imageId)||raw.profile!=='owasp-ai-goat-owned-listing-template-'+id
  ||raw.container!=='owasp-ai-goat-listing-template-'+id||!Number.isInteger(raw.port)||raw.port<8109||raw.port>8118
  ||staged&&typeof raw.activateRequested!=='boolean'||!staged&&(!/^[a-f0-9]{64}$/.test(raw.containerId)||typeof raw.enabled!=='boolean'))throw fail();
 return Object.freeze(Object.fromEntries(keys.map(k=>[k,raw[k]])));
}
function capture(options={},staged=false){
 const p=paths(options),filename=staged?p.stage:p.filename;let raw;
 try{raw=privateFiles.captureFile(filename,16384);}catch(error){if(error.code==='ENOENT')return null;throw fail();}
 try{
  const value=validate(JSON.parse(raw.bytes),options,staged);
  if(!raw.bytes.equals(Buffer.from(JSON.stringify(value)+'\n'))||(fs.lstatSync(filename).mode&0o777)!==0o600)throw fail();
  const authorityFile=privateFiles.captureFile(path.join(p.directory,'local-docker.json'),8192);
  const authority=validateAuthorityState(JSON.parse(authorityFile.bytes),{workspaceId:value.workspaceId});
  if(authorityDigest(authority)!==value.dockerAuthoritySha256)throw fail();
  const record=Object.freeze({value,authority,filename,sha256:raw.sha256,identity:Object.freeze(raw.identity),authoritySha256:authorityFile.sha256,authorityIdentity:Object.freeze(authorityFile.identity)});captures.add(record);return record;
 }catch{throw fail();}
}
function stage({root,home,value}){
 const v=validate(value,{root},true),p=paths({root,home});privateFiles.publishImmutable(p.stage,Buffer.from(JSON.stringify(v)+'\n'));return capture({root,home},true);
}
function assertCaptured(record,options,staged=false){
 if(!captures.has(record))throw fail();const now=capture(options,staged);
 if(!now||now.sha256!==record.sha256||now.identity.dev!==record.identity.dev||now.identity.ino!==record.identity.ino
  ||now.authoritySha256!==record.authoritySha256||now.authorityIdentity.dev!==record.authorityIdentity.dev||now.authorityIdentity.ino!==record.authorityIdentity.ino)throw fail();return now;
}
function publish({root,home,expected,expectedStage,value}){
 const p=paths({root,home}),v=validate(value,{root});if(!captures.has(expectedStage)||expectedStage.filename!==p.stage||Object.entries(expectedStage.value).some(([k,w])=>k!=='activateRequested'&&v[k]!==w))throw fail();if(expected!==null&&(!captures.has(expected)||expected.filename!==p.filename))throw fail();
 privateFiles.assertPrivateDirectory(p.directory);
 const lock=path.join(p.directory,'.listing-template-managed.lock');let fd,identity,pending,pendingIdentity;
 const assertCurrent=()=>{assertCaptured(expectedStage,{root,home},true);const now=capture({root,home});if(expected===null){if(now)throw fail();}
  else assertCaptured(expected,{root,home});};
 try{
  fd=fs.openSync(lock,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);identity=fs.fstatSync(fd);assertCurrent();
  if(expected&&JSON.stringify(expected.value)===JSON.stringify(v))return expected;
  pending=path.join(p.directory,'.listing-template-'+crypto.randomBytes(12).toString('hex')+'.pending');const output=fs.openSync(pending,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);pendingIdentity=fs.fstatSync(output);
  try{fs.writeFileSync(output,JSON.stringify(v)+'\n');fs.fsyncSync(output);}finally{fs.closeSync(output);}
  assertCurrent();if(expected===null){fs.linkSync(pending,p.filename);}else{fs.renameSync(pending,p.filename);pending=null;}
  const parent=fs.openSync(p.directory,fs.constants.O_RDONLY);try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
 }finally{
  const remove=(name,st)=>{const now=fs.lstatSync(name);if(now.dev!==st.dev||now.ino!==st.ino||now.isSymbolicLink())throw fail();fs.unlinkSync(name);};
  if(pending&&pendingIdentity)remove(pending,pendingIdentity);if(fd!==undefined){fs.closeSync(fd);remove(lock,identity);}
 }
 return capture({root,home});
}
module.exports={paths,validate,capture,stage,publish,assertCaptured};
