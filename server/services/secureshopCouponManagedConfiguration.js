'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{randomUUID,createHash}=require('node:crypto');
const {workspaceId}=require('../../scripts/application-data-root');
const windowsPrivateState=require('../../scripts/lib/windows-private-state');
const fail=()=>Object.assign(Error('Private coupon configuration unavailable'),{code:'COUPON_MANAGED_CONFIGURATION_INVALID'});
function paths({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}){if(process.platform==='win32'){try{root=windowsPrivateState.normalizePrivatePath(root);home=windowsPrivateState.normalizePrivatePath(home);}catch{throw fail();}}if(!path.isAbsolute(root)||!path.isAbsolute(home))throw fail();const directory=path.join(home,'.dvaia',workspaceId(root));return{directory,filename:path.join(directory,'coupons-managed.json'),workspaceId:workspaceId(root)};}
function record(bytes,id){const value=JSON.parse(bytes);if(!value||Object.keys(value).sort().join()!==['version','workspaceId','enabled'].sort().join()||value.version!==1||value.workspaceId!==id||typeof value.enabled!=='boolean')throw fail();return Object.freeze({config:Object.freeze(value),sha256:createHash('sha256').update(bytes).digest('hex')});}
function privateDirectory(directory){const s=fs.lstatSync(directory);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)||(process.getuid&&s.uid!==process.getuid()))throw fail();return s;}
function load(options={}){
 const p=paths(options);let fd;
 try{const named=fs.lstatSync(p.filename);if(!named.isFile()||named.isSymbolicLink())throw fail();}catch(error){if(error.code==='ENOENT')return null;throw fail();}
 try{if(process.platform==='win32'){const before=windowsPrivateState.inspectPrivateDirectory(p.directory),bytes=windowsPrivateState.readPrivateFile(p.filename),after=windowsPrivateState.inspectPrivateDirectory(p.directory);if(!before?.identity||!after?.identity||before.identity.volumeSerial!==after.identity.volumeSerial||before.identity.fileId!==after.identity.fileId||!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>2048)throw fail();return record(bytes,p.workspaceId);}
 privateDirectory(p.directory);fd=fs.openSync(p.filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);const before=fs.fstatSync(fd);if(!before.isFile()||before.nlink!==1||(before.mode&0o077)||(process.getuid&&before.uid!==process.getuid())||before.size<1||before.size>2048)throw fail();const bytes=Buffer.alloc(before.size+1),count=fs.readSync(fd,bytes,0,bytes.length,0),after=fs.fstatSync(fd),named=fs.lstatSync(p.filename);if(count!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||named.dev!==before.dev||named.ino!==before.ino||named.isSymbolicLink())throw fail();return record(bytes.subarray(0,count),p.workspaceId);
 }catch{throw fail();}finally{if(fd!==undefined)fs.closeSync(fd);}
}
function activateNew(options={}){
 if(process.platform==='win32')throw fail();
 const p=paths(options);privateDirectory(p.directory);const existing=load(options);if(existing)return{activationEnabled:existing.config.enabled,changed:false};
 const temporary=path.join(p.directory,'.coupon-'+randomUUID());let fd,identity,created=false;
 try{fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);identity=fs.fstatSync(fd);fs.writeFileSync(fd,JSON.stringify({version:1,workspaceId:p.workspaceId,enabled:true})+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;try{fs.linkSync(temporary,p.filename);created=true;}catch(error){if(error.code!=='EEXIST')throw error;}const directory=fs.openSync(p.directory,fs.constants.O_RDONLY);try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
 }finally{if(fd!==undefined)fs.closeSync(fd);if(identity){const named=fs.lstatSync(temporary);if(named.dev!==identity.dev||named.ino!==identity.ino||named.isSymbolicLink())throw fail();fs.unlinkSync(temporary);}}
 const result=load(options);if(!result)throw fail();return{activationEnabled:result.config.enabled,changed:created};
}
function environment(options={}){const record=load(options);return record?Object.freeze({SS_BOUND_COUPONS_ENABLED:String(record.config.enabled)}):Object.freeze({});}
module.exports={paths,load,activateNew,environment};
