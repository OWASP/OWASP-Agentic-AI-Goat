'use strict';
// Deterministic observation of an explicitly reviewed replay closure, not an
// import resolver or an authority capability. No files are executed or changed.
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const invalid=()=>Object.assign(Error('Maintenance replay source unavailable'),{code:'APPLICATION_MAINTENANCE_REPLAY_SOURCE_INVALID'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const MAX_ENTRIES=20000,MAX_FILE=32*1024*1024,MAX_TOTAL=256*1024*1024;
function captureMaintenanceReplaySource({root,files=[],directories=[]}={}){
 try{
  if(typeof root!=='string'||!path.isAbsolute(root)||fs.realpathSync(root)!==root||!Array.isArray(files)||!Array.isArray(directories)||!files.length&&!directories.length||files.length+directories.length>MAX_ENTRIES)throw invalid();
  const relative=p=>{if(typeof p!=='string'||!p.isWellFormed()||!p||p.includes('\\')||p.includes('\0')||p.split('/').some(x=>!x||x==='.'||x==='..')||path.isAbsolute(p))throw invalid();return p;};
  const selected=[...files,...directories].map(relative);if(new Set(selected).size!==selected.length)throw invalid();
  const safeStat=p=>{const s=fs.lstatSync(p);if(s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o022))throw invalid();return s;};
  const initialRoot=safeStat(root);if(!initialRoot.isDirectory())throw invalid();
  const rows=new Map(),parents=new Map([[root,initialRoot]]);let total=0;
  const checkParents=p=>{let current=root;for(const part of p.split('/').slice(0,-1)){current=path.join(current,part);const s=safeStat(current);if(!s.isDirectory())throw invalid();const prior=parents.get(current);if(prior&&(prior.dev!==s.dev||prior.ino!==s.ino||prior.mode!==s.mode))throw invalid();parents.set(current,s);}};
  const observe=(p,recursive)=>{
   if(rows.has(p))throw invalid();if(rows.size>=MAX_ENTRIES)throw invalid();checkParents(p);
   const absolute=path.join(root,p),before=safeStat(absolute),mode=before.mode&0o777;
   if(before.isDirectory()){
    if(!recursive)throw invalid();rows.set(p,{path:p,kind:'directory',mode});
    for(const name of fs.readdirSync(absolute).sort())observe(relative(`${p}/${name}`),true);
   }else{
    if(!before.isFile()||before.nlink!==1||before.size>MAX_FILE||total+before.size>MAX_TOTAL)throw invalid();
    const fd=fs.openSync(absolute,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let bytes,opened;
    try{opened=fs.fstatSync(fd);if(!opened.isFile()||opened.uid!==process.getuid()||(opened.mode&0o022)||opened.nlink!==1||!Number.isSafeInteger(opened.size)||opened.size<0||opened.size>MAX_FILE||opened.size>MAX_TOTAL-total||opened.dev!==before.dev||opened.ino!==before.ino||opened.mode!==before.mode||opened.size!==before.size||opened.mtimeMs!==before.mtimeMs||opened.ctimeMs!==before.ctimeMs)throw invalid();bytes=Buffer.alloc(opened.size);let offset=0;while(offset<bytes.length){const count=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!count)throw invalid();offset+=count;}const after=fs.fstatSync(fd);if(after.size!==opened.size||after.mtimeMs!==opened.mtimeMs||after.ctimeMs!==opened.ctimeMs||after.mode!==opened.mode||after.nlink!==1||bytes.length!==opened.size)throw invalid();}finally{fs.closeSync(fd);}
    total+=bytes.length;rows.set(p,{path:p,kind:'file',mode,size:bytes.length,sha256:sha(bytes)});
   }
   const after=safeStat(absolute);if(after.dev!==before.dev||after.ino!==before.ino||after.mode!==before.mode||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw invalid();
  };
  for(const p of [...files].sort())observe(p,false);for(const p of [...directories].sort())observe(p,true);
  // Recheck recorded ancestors. This detects observed replacement, not an
  // atomic filesystem snapshot or protection against a swap-and-restore writer.
  for(const [name,prior]of parents){const now=safeStat(name);if(!now.isDirectory()||now.dev!==prior.dev||now.ino!==prior.ino||now.mode!==prior.mode)throw invalid();}
  const manifest=Object.freeze({version:1,files:Object.freeze([...files].sort()),directories:Object.freeze([...directories].sort()),entries:Object.freeze([...rows.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0).map(Object.freeze))});
  return Object.freeze({manifest,sha256:sha(JSON.stringify(manifest))});
 }catch{throw invalid();}
}
function verifyMaintenanceReplaySource({root,manifest,expectedSha256}={}){
 try{
  if(typeof expectedSha256!=='string'||!/^[a-f0-9]{64}$/.test(expectedSha256)||!manifest||sha(JSON.stringify(manifest))!==expectedSha256)throw invalid();
  const current=captureMaintenanceReplaySource({root,files:manifest.files,directories:manifest.directories});
  if(current.sha256!==expectedSha256)throw invalid();return current;
 }catch{throw invalid();}
}
module.exports={captureMaintenanceReplaySource,verifyMaintenanceReplaySource};
