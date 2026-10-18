'use strict';
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {createMcpTargetStore,_internals}=require('../../sidecars/sandbox-runner/mcpTargets');
async function fixture(t,options={}){
 const {pythonExecutable,...storeOptions}=options;
 if(pythonExecutable!==undefined&&(!path.isAbsolute(pythonExecutable)||/[\r\n]/.test(pythonExecutable)))throw new TypeError('Absolute fixture Python executable required');
 const base=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-mcp-target-'));
 const owned=await fs.lstat(base);
 t.after(async()=>{
  const current=await fs.lstat(base);
  if(!current.isDirectory()||current.isSymbolicLink()||current.dev!==owned.dev||current.ino!==owned.ino||current.uid!==owned.uid)throw Error('Fixture cleanup ownership changed');
  async function writableDirectories(directory){
   const info=await fs.lstat(directory);
   if(info.isSymbolicLink())return;
   if(!info.isDirectory()||info.uid!==owned.uid)throw Error('Fixture cleanup directory ownership changed');
   await fs.chmod(directory,(info.mode&0o777)|0o700);
   for(const name of await fs.readdir(directory)){
    const child=path.join(directory,name),entry=await fs.lstat(child);
    if(entry.isDirectory()&&!entry.isSymbolicLink())await writableDirectories(child);
   }
  }
  await writableDirectories(base);await fs.rm(base,{recursive:true,force:true});
 });
 const source=path.join(base,'source'),root=path.join(base,'private');
 for(const [name,value] of [['var/secrets/master_key.txt','MASTER=A'],['opt/app/config/.env','DB_PASSWORD=A'],['opt/lab/bin/rotate_keys.sh','#!/bin/sh'],['home/mcp-admin/readme','home'],['etc/passwd','mcp:x:1000:1000']]){const file=path.join(source,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,value);}
 await fs.cp(path.join(__dirname,'../../sidecars/sandbox-runner/labfs/opt/lab/packages'),path.join(source,'opt/lab/packages'),{recursive:true});
 await fs.chmod(path.join(source,'opt/lab/bin/rotate_keys.sh'),0o700);
 const flockExecutable=path.join(base,'flock-helper.py');
 await fs.writeFile(flockExecutable,"#!/usr/bin/env python3\nimport fcntl,sys\nf=open(sys.argv[1],'a+')\ntry: fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(75)\nsys.stdout.write('MCP_TARGET_LOCK_READY\\n');sys.stdout.flush();sys.stdin.buffer.read()\nsys.exit(int(sys.argv[2]) if len(sys.argv)>2 else 0)\n");
 await fs.chmod(flockExecutable,0o700);
 const seccompFilterPath=path.join(base,'mcp-target.seccomp.bpf');
 const seccompMetadataPath=path.join(base,'mcp-target.seccomp.json');
 const filter=Buffer.alloc(8);await fs.writeFile(seccompFilterPath,filter,{mode:0o400});
 const arch=process.arch==='arm64'?'arm64':'amd64';
 await fs.writeFile(seccompMetadataPath,JSON.stringify({arch,sha256:crypto.createHash('sha256').update(filter).digest('hex'),version:1})+'\n',{mode:0o400});
 await fs.mkdir(root,{mode:0o700});
 const lockOptions={flockExecutable:pythonExecutable||flockExecutable,flockArguments:lockFile=>pythonExecutable?['-B',flockExecutable,lockFile]:[lockFile],seccompFilterPath,seccompMetadataPath,seccompOwnerUid:process.getuid?.()??0,
  tarExecutable:flockExecutable,
  runtimeSources:_internals.RUNTIME_DESTINATIONS,runtimeOwnerUid:process.getuid?.()??0,
  runtimeLstat:async()=>({isFile:()=>true,isSymbolicLink:()=>false,uid:process.getuid?.()??0,mode:0o100500})};
 return{base,source,root,lockOptions,store:createMcpTargetStore({root,fixtureRoot:source,clock:()=> '2026-09-13T12:34:56.000Z',...lockOptions,...storeOptions})};
}
module.exports={fixture};
