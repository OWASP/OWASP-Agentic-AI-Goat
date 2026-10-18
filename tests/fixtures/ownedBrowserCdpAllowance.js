'use strict';
// Qualification-only: learn only a verified owned Chromium child's CDP endpoint.
const fs=require('node:fs'),path=require('node:path');
function install({browserExecutable,ownedRoot,addEndpoint,removeEndpoint,childProcess=require('node:child_process')}) {
 const executable=fs.realpathSync(browserExecutable),root=fs.realpathSync(ownedRoot),original=childProcess.spawn;
 childProcess.spawn=function(command,args,options){
  let owned=false;
  try {
   const profiles=Array.isArray(args)?args.filter(x=>typeof x==='string'&&x.startsWith('--user-data-dir=')):[];
   if(fs.realpathSync(command)===executable&&profiles.length===1){
    const profile=profiles[0].slice('--user-data-dir='.length),real=fs.realpathSync(profile),stat=fs.lstatSync(profile);
    owned=real.startsWith(root+path.sep)&&stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid();
   }
  } catch {}
  const child=original.call(this,command,args,options);
  if(!owned||!Number.isSafeInteger(child.pid)||!child.stderr)return child;
  let buffered='',endpoint,closed=false;
  const end=()=>{closed=true;if(endpoint){removeEndpoint(endpoint);endpoint=undefined;}child.stderr.removeListener('data',read);};
  const read=chunk=>{
   if(closed||endpoint)return;
   buffered+=chunk.toString('utf8');if(buffered.length>8192){end();return;}
   let index;
   while((index=buffered.indexOf('\n'))!==-1){const line=buffered.slice(0,index).trim();buffered=buffered.slice(index+1);
    const match=/^DevTools listening on ws:\/\/127\.0\.0\.1:([1-9][0-9]{3,4})\/devtools\/browser\/[a-f0-9-]{36}$/.exec(line);
    if(match&&Number(match[1])<=65535){endpoint={name:'fixture_owned_browser_'+child.pid,host:'127.0.0.1',port:Number(match[1])};addEndpoint(endpoint);break;}
   }
  };
  child.stderr.on('data',read);child.once('exit',end);child.once('close',end);return child;
 };
 return()=>{childProcess.spawn=original;};
}
module.exports={install};
