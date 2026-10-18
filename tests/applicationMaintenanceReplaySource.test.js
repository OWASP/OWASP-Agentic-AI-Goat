'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {captureMaintenanceReplaySource:capture,verifyMaintenanceReplaySource:verify}=require('../scripts/lib/application-maintenance-replay-source');
function fixture(work){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'replay-source-')));fs.mkdirSync(path.join(root,'migrations'));fs.writeFileSync(path.join(root,'migrations','0001.sql'),'SELECT 1;');fs.writeFileSync(path.join(root,'initializer.js'),'module.exports=1;');fs.writeFileSync(path.join(root,'package-lock.json'),'{}');try{work(root);}finally{fs.rmSync(root,{recursive:true,force:true});}}
const input=root=>({root,files:['initializer.js','package-lock.json'],directories:['migrations']});
const deny=fn=>assert.throws(fn,{code:'APPLICATION_MAINTENANCE_REPLAY_SOURCE_INVALID'});
test('manifest deterministic across supplied order and verifies exact retained digest',()=>fixture(root=>{const a=capture(input(root)),b=capture({...input(root),files:['package-lock.json','initializer.js']});assert.deepEqual(a,b);assert.equal(verify({root,manifest:JSON.parse(JSON.stringify(a.manifest)),expectedSha256:a.sha256}).sha256,a.sha256);assert(Object.isFrozen(a.manifest.entries[0]));deny(()=>verify({root,manifest:a.manifest,expectedSha256:'0'.repeat(64)}));}));
test('bytes, permissions, new and removed migrations each deny retained replay',()=>fixture(root=>{const a=capture(input(root)),check=()=>verify({root,manifest:a.manifest,expectedSha256:a.sha256}),file=path.join(root,'initializer.js');fs.writeFileSync(file,'changed');deny(check);fs.writeFileSync(file,'module.exports=1;');fs.chmodSync(file,0o600);deny(check);fs.chmodSync(file,0o644);fs.writeFileSync(path.join(root,'migrations','0002.sql'),'SELECT 2;');deny(check);fs.unlinkSync(path.join(root,'migrations','0002.sql'));fs.unlinkSync(path.join(root,'migrations','0001.sql'));deny(check);}));
test('traversal, overlapping closure, symlink, hardlink and writable files deny',()=>fixture(root=>{deny(()=>capture({...input(root),files:['../escape']}));deny(()=>capture({...input(root),files:['migrations/0001.sql']}));const p=path.join(root,'initializer.js');fs.chmodSync(p,0o666);deny(()=>capture(input(root)));fs.chmodSync(p,0o644);fs.linkSync(p,path.join(root,'alias'));deny(()=>capture(input(root)));fs.unlinkSync(path.join(root,'alias'));fs.renameSync(p,p+'.saved');fs.symlinkSync(p+'.saved',p);deny(()=>capture(input(root)));}));
test('file mutation during actual read fails instead of recording mixed observation',()=>fixture(root=>{const original=fs.readSync;let changed=false;try{fs.readSync=(fd,...rest)=>{const result=original(fd,...rest);if(typeof fd==='number'&&!changed){changed=true;fs.appendFileSync(path.join(root,'initializer.js'),'more');}return result;};deny(()=>capture(input(root)));}finally{fs.readSync=original;}assert(changed);}));
test('growth between lstat and open is rejected before allocation or read',()=>fixture(root=>{
 const file=path.join(root,'initializer.js'),open=fs.openSync,alloc=Buffer.alloc,read=fs.readSync;let grew=false,allocations=0,reads=0;
 try{
  fs.openSync=(name,...args)=>{if(name===file&&!grew){grew=true;fs.truncateSync(file,32*1024*1024+1);}return open(name,...args);};
  Buffer.alloc=(...args)=>{allocations++;return alloc(...args);};fs.readSync=(...args)=>{reads++;return read(...args);};
  deny(()=>capture({root,files:['initializer.js']}));
 }finally{fs.openSync=open;Buffer.alloc=alloc;fs.readSync=read;}
 assert.equal(grew,true);assert.equal(allocations,0);assert.equal(reads,0);
}));
test('opened descriptor permission change rejects before allocation or read',()=>fixture(root=>{
 const file=path.join(root,'initializer.js'),open=fs.openSync,alloc=Buffer.alloc,read=fs.readSync;let changed=false,allocations=0,reads=0;
 try{fs.openSync=(name,...args)=>{const fd=open(name,...args);if(name===file&&!changed){changed=true;fs.fchmodSync(fd,0o666);}return fd;};Buffer.alloc=(...a)=>{allocations++;return alloc(...a);};fs.readSync=(...a)=>{reads++;return read(...a);};deny(()=>capture({root,files:['initializer.js']}));}
 finally{fs.openSync=open;Buffer.alloc=alloc;fs.readSync=read;}
 assert(changed);assert.equal(allocations,0);assert.equal(reads,0);
}));
test('ancestor replacement retaining the same file inode is observed and denied',()=>fixture(root=>{
 const directory=path.join(root,'migrations'),file=path.join(directory,'0001.sql'),open=fs.openSync;let replaced=false;
 try{fs.openSync=(name,...args)=>{if(name===file&&!replaced){replaced=true;fs.renameSync(directory,directory+'.old');fs.mkdirSync(directory);fs.renameSync(path.join(directory+'.old','0001.sql'),file);}return open(name,...args);};deny(()=>capture({root,files:['migrations/0001.sql']}));}
 finally{fs.openSync=open;}assert(replaced);
}));
