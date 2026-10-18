'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {plan,provision,provisionForSetup}=require('../scripts/install/audit-sql-target');
async function fixture(t){
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'audit-port-unit-'));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const options={root,home:path.join(root,'home'),dockerHost:'unix:///fixture/docker.sock'};
 const p=plan(options);await fs.mkdir(path.dirname(p.file),{recursive:true,mode:0o700});
 const config={version:1,enabled:false,workspace:p.id,container:p.name,volume:p.volume,database:p.database,dockerHost:p.dockerHost,port:8094,password:'a'.repeat(64),token:'b'.repeat(64)};
 const calls=[],stop=Error('controlled Docker boundary');
 options.run=async(...args)=>{calls.push(args);throw stop;};
 return {options,p,config,calls,stop,async write(value=config,mode=0o600){await fs.writeFile(p.file,JSON.stringify(value)+'\n',{mode});return fs.readFile(p.file);}};
}
for(const port of [8094,8095,8097])test(`repeat audit provisioning preserves private saved port ${port} before Docker`,async t=>{
 const f=await fixture(t),before=await f.write({...f.config,port});
 await assert.rejects(provision(f.options),error=>error===f.stop);
 assert.equal(f.calls.length,1);assert.deepEqual(f.calls[0][1],['--host',f.options.dockerHost,'image','ls','--quiet','postgres:18']);
 assert.deepEqual(await fs.readFile(f.p.file),before);
});
test('fresh audit provisioning records collision-free default8097 without claiming successful Docker provisioning',async t=>{
 const f=await fixture(t);await assert.rejects(provision(f.options),error=>error===f.stop);
 const saved=JSON.parse(await fs.readFile(f.p.file));assert.equal(saved.port,8097);assert.equal(saved.enabled,false);assert.equal(saved.activationPending,true);assert.equal(f.calls.length,1);
 assert.equal((await fs.stat(f.p.file)).mode&0o777,0o600);
});
for(const localImage of ['', 'sha256:present'])test(`audit image ${localImage ? 'present' : 'absent'} probe requires exact digest inspection before container provisioning`,async t=>{
 const f=await fixture(t),commands=[];
 f.options.run=async(_file,args)=>{
  const command=args.slice(2).join(' ');commands.push(command);
  if(command==='image ls --quiet postgres:18')return{exitCode:0,stdout:localImage};
  if(command==='pull postgres:18')return{exitCode:0,stdout:'pulled'};
  if(command==='image inspect postgres:18')return{exitCode:0,stdout:JSON.stringify([{Id:`sha256:${'a'.repeat(64)}`}])};
  throw f.stop;
 };
 await assert.rejects(provision(f.options),error=>error===f.stop);
 assert.deepEqual(commands,localImage
  ? ['image ls --quiet postgres:18','image inspect postgres:18','container ls -a --filter name=^/'+f.p.name+'$ --format json']
  : ['image ls --quiet postgres:18','pull postgres:18','image inspect postgres:18','container ls -a --filter name=^/'+f.p.name+'$ --format json']);
 assert.equal(JSON.parse(await fs.readFile(f.p.file)).image,`sha256:${'a'.repeat(64)}`);
});
test('audit image probe failure cannot be treated as a missing image',async t=>{
 const f=await fixture(t),error=Object.assign(Error('controlled Docker failure'),{code:'MCP_INSTALL_COMMAND_FAILED',result:{exitCode:1}});
 f.options.run=async(...args)=>{f.calls.push(args);throw error;};
 await assert.rejects(provision(f.options),failure=>failure===error);
 assert.equal(f.calls.length,1);assert.equal(JSON.parse(await fs.readFile(f.p.file)).image,undefined);
});
async function partialRecovery(t,change={},run){
 const f=await fixture(t),oldHost=f.options.dockerHost,newHost='unix:///fixture/verified.sock';
 const before=await f.write({...f.config,activationPending:true,...change});
 const commands=[],stop=Error('controlled stop after authority recovery');
 const execute=run||(async(_file,args)=>{commands.push(args.slice(2));
  if(args[1]!==newHost)throw Error('wrong Docker authority');
  if(args[2]==='container'||args[2]==='volume')return{exitCode:0,stdout:''};
  throw stop;
 });
 const invoke=(verified={persisted:true,authority:{version:1,workspaceId:f.p.id,host:newHost}})=>provisionForSetup({
  root:f.options.root,homeDirectory:f.options.home,platform:'linux',environment:{},resolveAuthority:async()=>verified,
  provisionTarget:options=>provision({...options,run:execute}),activate:async()=>assert.fail('incomplete provisioning cannot activate'),
 });
 return{f,before,commands,stop,invoke,newHost,oldHost};
}
test('verified retained authority recovers only pre-image audit configuration with exact private evidence',async t=>{
 const x=await partialRecovery(t);await assert.rejects(x.invoke(),error=>error===x.stop);
 assert.deepEqual(x.commands.map(args=>args.slice(0,2)),[['container','ls'],['volume','ls'],['image','ls']]);
 const after=JSON.parse(await fs.readFile(x.f.p.file));const before=JSON.parse(x.before);
 assert.equal(after.dockerHost,x.newHost);assert.equal(after.port,before.port);
 assert.equal(after.password,before.password);assert.equal(after.token,before.token);
 assert.deepEqual(await fs.readFile(x.f.p.file+'.host-recovery'),x.before);
});
test('partial audit recovery refuses established image, provisioning, port, activation or unknown format',async t=>{
 for(const change of [{image:`sha256:${'a'.repeat(64)}`},{provisioned:true},{databasePort:55432},{activationPending:false},{version:2}]){
  const x=await partialRecovery(t,change);await assert.rejects(x.invoke(),/AUDIT_SQL_OWNERSHIP_CONFLICT/);
  assert.deepEqual(await fs.readFile(x.f.p.file),x.before);assert.equal(x.commands.length,0);
 }
});
test('partial audit recovery refuses named resources and unverified authority without changing state',async t=>{
 const x=await partialRecovery(t,{},async(_file,args)=>{
  x.commands.push(args.slice(2));return{exitCode:0,stdout:x.f.p.name};
 });
 await assert.rejects(x.invoke(),/AUDIT_SQL_OWNERSHIP_CONFLICT/);
 assert.deepEqual(await fs.readFile(x.f.p.file),x.before);
 await assert.rejects(x.invoke({persisted:false,authority:{version:1,workspaceId:x.f.p.id,host:x.newHost}}),/AUDIT_SQL_DOCKER_AUTHORITY_INVALID/);
 assert.deepEqual(await fs.readFile(x.f.p.file),x.before);
});
test('partial audit recovery rejects same-byte file replacement during destination probes',async t=>{
 let replaced=false;
 const x=await partialRecovery(t,{},async(_file,args)=>{
  if(args[2]==='container'&&!replaced){
   const replacement=x.f.p.file+'.replacement';await fs.writeFile(replacement,x.before,{flag:'wx',mode:0o600});
   await fs.rename(replacement,x.f.p.file);replaced=true;
  }
  return{exitCode:0,stdout:''};
 });
 await assert.rejects(x.invoke(),/AUDIT_SQL_CONFIGURATION_CHANGED/);
 assert.equal(replaced,true);assert.deepEqual(await fs.readFile(x.f.p.file),x.before);
 await assert.rejects(fs.lstat(x.f.p.file+'.host-recovery'),{code:'ENOENT'});
});
test('explicit audit port conflict rejects without Docker or changing saved state',async t=>{
 const f=await fixture(t),before=await f.write();await assert.rejects(provision({...f.options,port:8095}),/OWNERSHIP_CONFLICT/);
 assert.equal(f.calls.length,0);assert.deepEqual(await fs.readFile(f.p.file),before);
});
test('foreign audit workspace rejects before Docker and preserves private state',async t=>{
 const f=await fixture(t),before=await f.write({...f.config,workspace:'foreign'});await assert.rejects(provision(f.options),/OWNERSHIP_CONFLICT/);
 assert.equal(f.calls.length,0);assert.deepEqual(await fs.readFile(f.p.file),before);
});
test('nonprivate saved audit state rejects before Docker without rewriting permissions',async t=>{
 const f=await fixture(t),before=await f.write(f.config,0o644);await assert.rejects(provision(f.options),/Private configuration required/);
 assert.equal(f.calls.length,0);assert.deepEqual(await fs.readFile(f.p.file),before);assert.equal((await fs.stat(f.p.file)).mode&0o777,0o644);
});
test('invalid or missing saved audit port cannot inherit fresh default or reach Docker',async t=>{
 const f=await fixture(t);
 for(const port of [undefined,null,'8094',0,1023,65536,8094.5]){
  const before=await f.write({...f.config,port});await assert.rejects(provision(f.options),/Owned local Docker authority required|OWNERSHIP_CONFLICT/);
  assert.equal(f.calls.length,0);assert.deepEqual(await fs.readFile(f.p.file),before);
 }
});
