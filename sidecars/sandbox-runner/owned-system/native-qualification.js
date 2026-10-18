'use strict';
// Disposable image only. Direct supervisor argv below is qualification code,
// not an HTTP API or a caller-selectable worker path.
const assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto');
const {spawn,spawnSync}=require('node:child_process');
const {createSystemConfigExecutor,buildReadArgv,FIXTURES,INIT,SUPERVISOR,loadAssets}=require('./executor');
const request=path=>({operationId:crypto.randomUUID(),path});
const result={checks:[],node:process.version,arch:process.arch,uid:process.getuid()};
async function joined(argv, stopAfterOutput=false){return new Promise((resolve,reject)=>{const child=spawn(SUPERVISOR,argv,{stdio:['ignore','pipe','pipe']});let out='',err='';const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('Bounded supervisor probe timed out'));},5000);child.stdout.on('data',b=>{out+=b;if(stopAfterOutput){stopAfterOutput=false;setTimeout(()=>child.kill('SIGTERM'),100);}});child.stderr.on('data',b=>err+=b);child.on('error',reject);child.on('close',code=>{clearTimeout(timer);resolve({code,out,err});});});}
(async()=>{
 assert.equal(process.version,'v26.9.0');assert.equal(process.arch,'arm64');assert.equal(process.getuid(),10001);
 const executor=createSystemConfigExecutor({spawnImpl(binary,argv,options){const child=spawn(binary,argv,options);let captured='';child.stdout.on('data',b=>{if(captured.length<4096)captured+=b.toString().slice(0,4096-captured.length);});child.once('close',()=>{const marker=argv.at(-1),index=captured.indexOf(marker);if(index>=0){try{result.lastWorkerObservation=JSON.parse(Buffer.from(captured.slice(index+marker.length),'base64').toString())}catch{}}});return child;}});executor.assertReady();
 const metadataArgv=buildReadArgv(request('application.json'),'__SYSTEM_CONFIG_'+'a'.repeat(64)+'__',['/usr','/bin','/lib','/lib64'].filter(fs.existsSync));const metadataCut=metadataArgv.lastIndexOf(INIT);
 const metadataChild=spawn(SUPERVISOR,metadataArgv,{stdio:['ignore','pipe','pipe','pipe','pipe','pipe','pipe','pipe','pipe']});
 for(const[fd,bytes]of [[3,Buffer.alloc(0)],...Object.values(loadAssets()).map((b,i)=>[i+4,b]),...Object.values(FIXTURES).map((b,i)=>[i+7,b])]){metadataChild.stdio[fd].on('error',()=>{});metadataChild.stdio[fd].end(fd===4?Buffer.from(`const fs=require('fs');for(const path of ['/app/config/application.json','/app/.env']){const s=fs.statSync(path);process.stderr.write(JSON.stringify({path,mode:s.mode,nlink:s.nlink,size:s.size})+'\\n');}`):bytes);}
 let meta='',metaErr='';metadataChild.stderr.on('data',b=>metaErr+=b.toString().slice(0,4096-metaErr.length));metadataChild.stdout.on('data',b=>meta+=b);const metaTimer=setTimeout(()=>metadataChild.kill('SIGKILL'),5000);const metaExit=await new Promise((resolve,reject)=>{metadataChild.on('error',reject);metadataChild.on('close',resolve)});clearTimeout(metaTimer);result.fixtureMetadata={exitCode:metaExit,stdout:meta,stderr:metaErr};

 for(const p of ['application.json','....//.env','missing','/etc/passwd','....//....//etc/passwd']){
 const r=await executor.read(request(p));assert.equal(r.status,'completed');assert.equal(r.drained,true);assert.equal(r.exitCode,0);
 if(['application.json','....//.env'].includes(p)){assert.equal(r.readResult.ok,true);assert.equal(r.readResult.content,FIXTURES[p==='application.json'?'/app/config/application.json':'/app/.env']);}
 else assert.equal(r.readResult.ok,false);
 result.checks.push({path:p,readOk:r.readResult.ok,targetPath:r.readResult.targetPath,sha:r.readResult.contentSha256});
 }
 assert.throws(()=>loadAssets(()=>Buffer.from('tamper')),e=>e.code==='SYSTEM_CONFIG_ASSET_INVALID');
 assert.throws(()=>createSystemConfigExecutor({existsSync:name=>name!==INIT}).assertReady(),e=>e.code==='SYSTEM_CONFIG_ISOLATION_UNAVAILABLE');
 assert.throws(()=>createSystemConfigExecutor({existsSync:name=>name!==SUPERVISOR}).assertReady(),e=>e.code==='SYSTEM_CONFIG_ISOLATION_UNAVAILABLE');
 const tmp=fs.mkdtempSync('/tmp/system-asset-tamper-');try{fs.cpSync(__dirname,tmp,{recursive:true});fs.appendFileSync(tmp+'/worker.js','\n// altered');assert.throws(()=>require(tmp+'/executor').createSystemConfigExecutor(),e=>e.code==='SYSTEM_CONFIG_ASSET_INVALID');}finally{fs.rmSync(tmp,{recursive:true,force:true});}
 assert.throws(()=>createSystemConfigExecutor({spawnSyncImpl(binary,args,options){const changed=[...args];changed[changed.indexOf(INIT)]='/usr/bin/false';return spawnSync(binary,changed,options);}}).assertReady(),e=>e.code==='SYSTEM_CONFIG_ISOLATION_UNAVAILABLE');
 result.checks.push('actual copied worker tamper and substituted nonattesting init probe fail closed; missing helpers separately controlled');
 // Same namespace argv/FD fixtures as production, replacing only the final
 // command for trusted containment observations. Real read above attests caps.
 const marker='__SYSTEM_CONFIG_'+'a'.repeat(64)+'__',argv=buildReadArgv(request('application.json'),marker,['/usr','/bin','/lib','/lib64'].filter(fs.existsSync));const cut=argv.lastIndexOf(INIT);
 const probe=`const fs=require('fs'),net=require('net');let denied=0;for(const effect of [()=>fs.writeFileSync('/app/.env','changed'),()=>fs.writeFileSync('/app/new','changed'),()=>fs.writeFileSync('/app/config/new','changed'),()=>fs.renameSync('/app/config','/app/moved'),()=>fs.mkdirSync('/app/new-directory'),()=>fs.mkdirSync('/app/config/new-directory')]){try{effect()}catch(e){if(['EROFS','EACCES','EPERM','EBUSY'].includes(e.code))denied++}};if(denied!==6||fs.existsSync('/private-qualification-sentinel')||fs.existsSync('/proc/self/status'))process.exit(10);const s=net.connect({host:'1.1.1.1',port:80});s.on('connect',()=>process.exit(11));s.on('error',e=>process.exit(['ENETUNREACH','EHOSTUNREACH'].includes(e.code)?0:12));setTimeout(()=>process.exit(13),500);`;
 const assets=loadAssets();const child=spawn(SUPERVISOR,[...argv.slice(0,cut),'/usr/local/bin/node','-e',probe],{stdio:['ignore','pipe','pipe','pipe','pipe','pipe','pipe','pipe','pipe']});
 for(const[fd,bytes]of [[3,Buffer.alloc(0)],...Object.values(assets).map((b,i)=>[i+4,b]),...Object.values(FIXTURES).map((b,i)=>[i+7,b])]){child.stdio[fd].on('error',()=>{});child.stdio[fd].end(bytes);}
 let probeErr='';child.stderr.on('data',b=>probeErr+=b);const timer=setTimeout(()=>child.kill('SIGKILL'),5000);const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve)});clearTimeout(timer);assert.equal(code,0,probeErr);result.checks.push('same namespace argv read-only fixture, private sentinel/proc absent, unreachable external network');
 // No PID namespace for this trusted subreaper stress: the detached grandchild
 // becomes an actual orphan in the container namespace and must be joined.
 const orphan=`const c=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});console.log(c.pid);c.unref();`;
 const drained=await joined(['--unshare-user','--unshare-net','--cap-drop','ALL','--cap-add','CAP_NET_ADMIN','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--dev','/dev','/usr/local/bin/node','-e',orphan]);
 assert.equal(drained.code,0,drained.err);const pid=Number(drained.out.trim());assert.ok(Number.isSafeInteger(pid)&&pid>1);assert.throws(()=>process.kill(pid,0),e=>e.code==='ESRCH');result.checks.push({detachedGrandchildPid:pid,absentAfterSupervisorJoin:true});
 const held=await joined(['--unshare-user','--unshare-net','--cap-drop','ALL','--cap-add','CAP_NET_ADMIN','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--dev','/dev','/usr/local/bin/node','-e',orphan+'setInterval(()=>{},1000);'],true);assert.equal(held.code,124,held.err);const heldPid=Number(held.out.trim());assert.ok(Number.isSafeInteger(heldPid)&&heldPid>1);assert.throws(()=>process.kill(heldPid,0),e=>e.code==='ESRCH');result.checks.push({terminatedDetachedGrandchildPid:heldPid,absentAfterSupervisorJoin:true});
 result.http = await require('./http-native-qualification').qualifySystemHttp();
 result.status='passed';console.log(JSON.stringify(result));
})().catch(e=>{console.error(JSON.stringify({...result,status:'failed',error:e.stack}));process.exitCode=1;});
