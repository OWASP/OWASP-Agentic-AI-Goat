'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const entry=path.join(__dirname,'postgres/ownedSystemOriginalBrowserOwner.js');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
async function fixture(){
 const root=path.resolve(__dirname,'..'),dir=await fs.mkdtemp(path.join(root,'tasks/qualification/v24-browser-control-'));
 const binary=path.join(dir,'Google Chrome.app/Contents/MacOS/Google Chrome');
 await fs.mkdir(path.dirname(binary),{recursive:true});const bytes=Buffer.from('controlled executable; never launched\n');
 await fs.writeFile(binary,bytes,{mode:0o775});await fs.chmod(binary,0o775);
 const alias=path.join(dir,'alias');await fs.link(binary,alias);
 const original=await fs.readFile(entry,'utf8');
 const source=original.replaceAll('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',binary);
 const load=(io=fs)=>{
  const module={exports:{}},local=require('node:module').createRequire(entry);
  vm.runInNewContext('(function(require,module,exports,__filename,__dirname){'+source+'\n})',
   {Buffer,AbortController,AbortSignal,performance,process,setTimeout,clearTimeout})
   (id=>id==='node:fs/promises'?io:local(id),module,module.exports,entry,path.dirname(entry));
  return module.exports._internals;
 };
 return {root,dir,binary,alias,bytes,load,close:()=>fs.rm(dir,{recursive:true,force:true})};
}
test('installed browser two-link digest accepted, private/source two-link digest denied',async()=>{
 const f=await fixture();try{
  assert.equal((await fs.stat(f.binary)).nlink,2);
  assert.equal(await f.load().browserRuntimeHash(f.binary),hash(f.bytes));
  await assert.rejects(f.load().fileHash(f.binary),{code:'SYSTEM_ORIGINAL_FILE'});
  await assert.rejects(f.load().browserRuntimeHash(f.alias),{code:'SYSTEM_ORIGINAL_PATH'});
  await fs.unlink(f.binary);await fs.symlink(f.alias,f.binary);
  await assert.rejects(f.load().browserRuntimeHash(f.binary),{code:'SYSTEM_ORIGINAL_PATH'});
 }finally{await f.close();}
});
test('browser zero-link/nonregular/owner/mode and same-identity metadata drift deny',async()=>{
 for(const fault of ['zero','nonregular','owner','mode','link-drift','inode-drift','content']){
  const f=await fixture();try{let calls=0,changed=false;
   const io={...fs,open:async(...args)=>{
    assert.ok(args[1]&require('node:fs').constants.O_NOFOLLOW);assert.ok(args[1]&require('node:fs').constants.O_NONBLOCK);
    const fd=await fs.open(...args);
    return {close:()=>fd.close(),stat:async()=>{const s=await fd.stat();calls++;
     if(fault==='zero')s.nlink=0;if(fault==='nonregular')s.isFile=()=>false;
     if(fault==='owner')s.uid++;if(fault==='mode')s.mode=0o100777;
     if(fault==='link-drift'&&calls>1)s.nlink++;if(fault==='inode-drift'&&calls>1)s.ino++;
     return s;},read:async(...a)=>{const r=await fd.read(...a);if(fault==='content'&&!changed){changed=true;await fs.writeFile(f.alias,Buffer.alloc(f.bytes.length,65));}return r;}};
   }};
   await assert.rejects(f.load(io).browserRuntimeHash(f.binary));
  }finally{await f.close();}
 }
});
test('actual emitted controller permits only selected browser hardlinks and retains private/zero/drift checks',async()=>{
 const f=await fixture();try{
 const source='CONF='+JSON.stringify({root:f.root,node:'unused',browser:f.binary})+'\nEXPECTED='+JSON.stringify(hash(f.bytes))+'\nALIAS='+JSON.stringify(f.alias)+'\n'+f.load().CONTROLLER+String.raw`
fingerprint(CONF['browser'],EXPECTED)
try:fingerprint(ALIAS,EXPECTED);raise AssertionError('private hardlinks accepted')
except RuntimeError:pass
original_fstat=os.fstat
from types import SimpleNamespace
fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
for field,value in (('st_nlink',0),('st_mode',stat.S_IFIFO|0o775),('st_uid',os.getuid()+1)):
 def invalid(fd):
  s=original_fstat(fd);row={k:getattr(s,k) for k in fields};row[field]=value
  return SimpleNamespace(**row)
 os.fstat=invalid
 try:fingerprint(CONF['browser'],EXPECTED);raise AssertionError('invalid file accepted')
 except RuntimeError:pass
os.fstat=original_fstat
for field in ('st_nlink','st_ino','st_gid'):
 calls=[]
 def drift(fd):
  s=original_fstat(fd);calls.append(1)
  if len(calls)==1:return s
  row={k:getattr(s,k) for k in fields};row[field]+=1
  return SimpleNamespace(**row)
 os.fstat=drift
 try:fingerprint(CONF['browser'],EXPECTED);raise AssertionError('drift accepted')
 except RuntimeError:pass
os.fstat=original_fstat
try:fingerprint(CONF['browser'],'0'*64);raise AssertionError('wrong hash accepted')
except RuntimeError:pass
os.unlink(CONF['browser']);os.symlink(ALIAS,CONF['browser'])
try:fingerprint(CONF['browser'],EXPECTED);raise AssertionError('symlink accepted')
except RuntimeError:pass
print('browser-hardlinks-checked')
`;
 assert.equal(execFileSync('/opt/homebrew/bin/python3',['-B','-c',source],{cwd:f.root,timeout:10000,maxBuffer:16384,
  env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(f.root,'tasks/tmp'),PYTHONDONTWRITEBYTECODE:'1'}}).toString().trim(),'browser-hardlinks-checked');
 }finally{await f.close();}
});
