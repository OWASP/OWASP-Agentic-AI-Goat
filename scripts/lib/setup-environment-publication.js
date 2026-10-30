'use strict';
// Explicit fresh setup only. This journal is private data, never diagnostic output.
const fs=require('node:fs'),path=require('node:path'),{randomBytes,createHash}=require('node:crypto');
const GENERATED=['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET'];
const fail=()=>Object.assign(new Error('Private setup publication unavailable'),{code:'SETUP_PUBLICATION_INVALID'});
function directory(p,privateOnly=false){const s=fs.lstatSync(p);if(s.isSymbolicLink()||!s.isDirectory()||s.uid!==process.getuid()||(s.mode&(privateOnly?0o077:0o022)))throw fail();return s;}
function syncDirectory(p){const fd=fs.openSync(p,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function boundedRead(fd,size){if(!Number.isSafeInteger(size)||size<0||size>1024*1024)throw fail();const bytes=Buffer.alloc(size);let offset=0;while(offset<size){const count=fs.readSync(fd,bytes,offset,size-offset,offset);if(!count)throw fail();offset+=count;}return bytes;}
function read(p,links=1){let fd;try{fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.nlink!==links||s.size>1024*1024)throw fail();const bytes=boundedRead(fd,s.size),after=fs.fstatSync(fd),named=fs.lstatSync(p);if(bytes.length!==s.size||after.size!==s.size||after.mtimeMs!==s.mtimeMs||after.ctimeMs!==s.ctimeMs||after.mode!==s.mode||after.uid!==s.uid||after.nlink!==s.nlink||named.mode!==s.mode||named.uid!==s.uid||named.nlink!==s.nlink||named.isSymbolicLink()||named.ino!==s.ino||named.dev!==s.dev)throw fail();return bytes;}finally{if(fd!==undefined)fs.closeSync(fd);}}
function syncExact(p,bytes){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd),named=fs.lstatSync(p);if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o777)!==0o600||st.nlink!==1||named.isSymbolicLink()||st.ino!==named.ino||st.dev!==named.dev||st.size!==bytes.length||!boundedRead(fd,st.size).equals(bytes))throw fail();fs.fsyncSync(fd);}finally{fs.closeSync(fd);}if(!read(p).equals(bytes))throw fail();}
function exists(p){try{fs.lstatSync(p);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
function create(p,bytes){const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDirectory(path.dirname(p));}
function encode(environment){return Object.entries(environment).map(([k,v])=>{if(!/^[A-Z][A-Z0-9_]*$/.test(k)||typeof v!=='string'||/[\r\n\0]/.test(v))throw fail();return `${k}=${JSON.stringify(v)}`;}).join('\n')+'\n';}
// Windows payloads are retained by the native publication helper. Metadata
// probes below only choose recovery; held native handles establish authority.
function prepareWindowsFreshEnvironment(options,dependencies){
 const {root,directory:privateDirectory,id,envPath,environment}=options;
 const {normalizePrivatePath,MAX_FILE_BYTES}=require('./windows-private-state');
 const privateState=dependencies.privateState||require('./windows-private-state');
 const publication=dependencies.publication||require('./windows-private-publication');
 const present=dependencies.exists||exists;
 const normalizedRoot=normalizePrivatePath(root),normalizedPrivate=normalizePrivatePath(privateDirectory);
 if(root!==normalizedRoot||privateDirectory!==normalizedPrivate||envPath!==path.win32.join(root,'.env')||id!==createHash('sha256').update(path.win32.resolve(root)).digest('hex').slice(0,12))throw fail();
 normalizePrivatePath(envPath);if(GENERATED.some(k=>Object.hasOwn(environment,k)))throw fail();encode(environment);
 privateState.inspectPrivateDirectory(privateDirectory);
 const intentPath=path.win32.join(privateDirectory,'fresh-environment.publication.json'),resultPath=intentPath+'.result';
 normalizePrivatePath(resultPath);
 // Do not reinterpret a POSIX recovery journal or unrelated temporary file.
 if(present(path.win32.join(privateDirectory,'fresh-environment.pending.json'))||present(path.win32.join(root,'.env.setup-publication')))throw fail();
 const operationHash=createHash('sha256').update('owasp-ai-goat:fresh-environment:1\0').update(root).update('\0').update(privateDirectory).update('\0').update(id).digest('hex');
 const operationId=operationHash.slice(0,8)+'-'+operationHash.slice(8,12)+'-4'+operationHash.slice(13,16)+'-'+((parseInt(operationHash[16],16)&3)|8).toString(16)+operationHash.slice(17,20)+'-'+operationHash.slice(20,32);
 const binding={targetPath:envPath,intentPath,operationId};
 let bytes,full;
 if(present(resultPath)){
  bytes=privateState.readPrivateFile(resultPath);
  if(!Buffer.isBuffer(bytes)||bytes.length>MAX_FILE_BYTES||Buffer.from(bytes.toString('utf8'),'utf8').equals(bytes)===false)throw fail();
  const text=bytes.toString('utf8');if(!text.endsWith('\n'))throw fail();full={};
  for(const line of text.slice(0,-1).split('\n')){
   const match=/^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);if(!match||Object.hasOwn(full,match[1]))throw fail();full[match[1]]=JSON.parse(match[2]);
  }
  if(Object.keys(full).sort().join(',')!==[...Object.keys(environment),...GENERATED].sort().join(',')||Object.entries(environment).some(([k,v])=>full[k]!==v)||GENERATED.some(k=>! /^[a-f0-9]{96}$/.test(full[k]))||!Buffer.from(encode(full)).equals(bytes))throw fail();
 }else{
  if(present(envPath)||present(intentPath))throw fail();
  full={...environment,...Object.fromEntries(GENERATED.map(k=>[k,randomBytes(48).toString('hex')]))};bytes=Buffer.from(encode(full));
  if(bytes.length>MAX_FILE_BYTES)throw fail();
 }
 const prepared=publication.preparePrivatePublication({...binding,originalBytes:null,resultBytes:bytes});
 const matches=receipt=>receipt.intentSha256===prepared.intentSha256&&receipt.size===bytes.length&&receipt.identity.volumeSerial===prepared.identity.volumeSerial&&receipt.identity.fileId===prepared.identity.fileId;
 if(prepared.size!==bytes.length||!privateState.readPrivateFile(resultPath).equals(bytes))throw fail();
 return Object.freeze({environment:Object.freeze({...full}),publish(){try{
  privateState.inspectPrivateDirectory(privateDirectory);
  if(!privateState.readPrivateFile(resultPath).equals(bytes)||!matches(publication.inspectPrivatePublication(binding)))throw fail();
  const committed=publication.publishPrivatePublication(binding);if(committed.state!=='committed'||!matches(committed))throw fail();
 }catch{throw fail();}}});
}
function prepareFreshEnvironmentPublication({root,directory:privateDirectory,id,envPath,environment}={},dependencies={}){
 try{
  if((dependencies.platform||process.platform)==='win32')return prepareWindowsFreshEnvironment({root,directory:privateDirectory,id,envPath,environment},dependencies);
  if(!path.isAbsolute(root)||!path.isAbsolute(privateDirectory)||envPath!==path.join(root,'.env')||id!==createHash('sha256').update(path.resolve(root)).digest('hex').slice(0,12))throw fail();
  const rootStat=directory(root),privateStat=directory(privateDirectory,true),identity={version:1,kind:'fresh',workspace:fs.realpathSync(root),privateDirectory:fs.realpathSync(privateDirectory),id,envPath:path.join(fs.realpathSync(root),'.env'),keys:Object.keys(environment).sort()};
  if(GENERATED.some(k=>Object.hasOwn(environment,k)))throw fail();encode(environment);
  const pending=path.join(privateDirectory,'fresh-environment.pending.json'),temporary=path.join(root,'.env.setup-publication');
  const verifyDirectories=()=>{const a=directory(root),b=directory(privateDirectory,true);if(a.dev!==rootStat.dev||a.ino!==rootStat.ino||b.dev!==privateStat.dev||b.ino!==privateStat.ino)throw fail();};
  if(!exists(pending)){
   if(exists(envPath)||exists(temporary))throw fail();
   const full={...environment,...Object.fromEntries(GENERATED.map(k=>[k,randomBytes(48).toString('hex')]))};
   create(pending,Buffer.from(JSON.stringify({identity,environment:full,bytes:encode(full)})+'\n'));
  }
  const pendingBytes=read(pending),saved=JSON.parse(pendingBytes.toString('utf8'));
  if(Object.keys(saved).sort().join(',')!=='bytes,environment,identity'||JSON.stringify(saved.identity)!==JSON.stringify(identity)||Object.keys(saved.environment).sort().join(',')!==[...Object.keys(environment),...GENERATED].sort().join(',')||Object.entries(environment).some(([k,v])=>saved.environment[k]!==v)||GENERATED.some(k=>! /^[a-f0-9]{96}$/.test(saved.environment[k]))||saved.bytes!==encode(saved.environment))throw fail();
  // A prior attempt may have written all bytes but failed fsync. Re-establish
  // durability before any caller can use the retained generated secrets.
  const pendingFd=fs.openSync(pending,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(pendingFd);}finally{fs.closeSync(pendingFd);}syncDirectory(privateDirectory);
  if(!read(pending).equals(pendingBytes))throw fail();verifyDirectories();
  return Object.freeze({environment:Object.freeze({...saved.environment}),publish(){
   try{
    verifyDirectories();if(!read(pending).equals(pendingBytes))throw fail();const bytes=Buffer.from(saved.bytes);
    if(exists(envPath)){
     if(exists(temporary)){const a=fs.lstatSync(envPath),b=fs.lstatSync(temporary);if(a.dev!==b.dev||a.ino!==b.ino||!read(envPath,2).equals(bytes)||!read(temporary,2).equals(bytes))throw fail();fs.unlinkSync(temporary);syncDirectory(root);}
     if(!read(envPath).equals(bytes))throw fail();syncExact(envPath,bytes);syncDirectory(root);return;
    }
    if(exists(temporary)){if(!read(temporary).equals(bytes))throw fail();}else create(temporary,bytes);
    syncExact(temporary,bytes);verifyDirectories();fs.linkSync(temporary,envPath);syncDirectory(root);fs.unlinkSync(temporary);syncDirectory(root);if(!read(envPath).equals(bytes))throw fail();
   }catch{throw fail();}
  }});
 }catch{throw fail();}
}
module.exports={prepareFreshEnvironmentPublication};
