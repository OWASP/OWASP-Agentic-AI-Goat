'use strict';
// Explicit fresh setup. Never repair malformed credentials or rotate an account.
const fs=require('node:fs'),path=require('node:path');
const windowsPrivateState=require('./windows-private-state');
const unavailable=()=>Object.assign(new Error('Private administrator journal unavailable'),{code:'SETUP_ADMINISTRATOR_JOURNAL_INVALID'});
const trainingCredentials=()=>({username:'admin',email:'admin@dvaia.local',password:'admin123'});
function validate(bytes){
 const value=JSON.parse(bytes.toString('utf8'));
 const trainingCredential=value?.username==='admin'&&value?.email==='admin@dvaia.local'&&value?.password==='admin123';
 if(!value||Array.isArray(value)||Object.keys(value).sort().join(',')!=='email,password,username'||typeof value.username!=='string'||value.username.length<3||value.username.length>50||typeof value.email!=='string'||!value.email.includes('@')||typeof value.password!=='string'||(!trainingCredential&&value.password.length<12)||Buffer.byteLength(value.password)>72)throw unavailable();
 return Object.freeze({...value});
}
function windowsJournal(root,privateState,exists){
 try{
  const normalized=windowsPrivateState.normalizePrivatePath(root),file=windowsPrivateState.normalizePrivatePath(path.win32.join(normalized,'administrator.json'));
  privateState.inspectPrivateDirectory(normalized);
  // Existence is advisory only: native CREATE_NEW rejects a raced-in file.
  // A denied existing read must never be interpreted as a missing journal.
  if(!exists(file))privateState.createPrivateFile(file,Buffer.from(JSON.stringify(trainingCredentials(),null,2)+'\n'));
  const bytes=privateState.readPrivateFile(file);
  if(!Buffer.isBuffer(bytes)||bytes.length>4096)throw unavailable();
  const value=validate(bytes);
  privateState.inspectPrivateDirectory(normalized);
  // Native creation flushes file bytes and verifies a safe reread; native
  // existing reads validate owner/ACL/link/identity stability. The helper does
  // not provide parent-directory durability. This narrow integration must not
  // be used to qualify or unblock the global Windows installer publication.
  return value;
 }catch{throw unavailable();}
}
function directory(p){const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700)throw unavailable();return s;}
function ensureAdministratorJournal({directory:root,platform=process.platform,privateState=windowsPrivateState,exists=fs.existsSync}={}){
 // Injection is a controlled-test seam, not native operating-system proof.
 if(platform==='win32')return windowsJournal(root,privateState,exists);
 let fd;
 try{
  if(typeof root!=='string'||!path.isAbsolute(root))throw unavailable();const parent=directory(root),file=path.join(root,'administrator.json');
  let present=true;try{fs.lstatSync(file);}catch(e){if(e.code!=='ENOENT')throw e;present=false;}
  if(!present){
   // Never expose the fresh training credentials before both fsync operations.
   fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
   fs.writeFileSync(fd,JSON.stringify(trainingCredentials(),null,2)+'\n');
   fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  }
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const before=fs.fstatSync(fd);
  if(!before.isFile()||before.uid!==process.getuid()||(before.mode&0o777)!==0o600||before.nlink!==1||before.size>4096)throw unavailable();
  const bytes=fs.readFileSync(fd),value=validate(bytes);
  fs.fsyncSync(fd);const after=fs.fstatSync(fd),named=fs.lstatSync(file),parentAfter=directory(root);
  if(bytes.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||after.mode!==before.mode||after.uid!==before.uid||after.nlink!==1||named.isSymbolicLink()||named.ino!==before.ino||named.dev!==before.dev||named.mode!==before.mode||named.uid!==before.uid||named.nlink!==1||parentAfter.ino!==parent.ino||parentAfter.dev!==parent.dev)throw unavailable();
  fs.closeSync(fd);fd=undefined;const d=fs.openSync(root,fs.constants.O_RDONLY);try{fs.fsyncSync(d);}finally{fs.closeSync(d);}
  return Object.freeze({...value});
 }catch{throw unavailable();}finally{if(fd!==undefined)fs.closeSync(fd);}
}
module.exports={ensureAdministratorJournal,validateAdministratorJournal:validate};
