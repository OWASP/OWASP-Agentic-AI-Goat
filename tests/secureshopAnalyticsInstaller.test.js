'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{randomUUID}=require('node:crypto');
const installer=require('../scripts/install/analytics-target'),authority=require('../scripts/local-docker-authority');
test('fresh and resumed database startup retries transport failures within a bound and never retries bad credentials',async()=>{
 let calls=0,pauses=0;
 await installer._internals.awaitDatabase({query:async sql=>{assert.equal(sql,'SELECT 1');if(++calls<3)throw Object.assign(Error('starting'),{code:'57P03'});}},{attempts:3,pause:async()=>{pauses++;}});
 assert.equal(calls,3);assert.equal(pauses,2);
 calls=0;const denied=Object.assign(Error('invalid password'),{code:'28P01'});
 await assert.rejects(installer._internals.awaitDatabase({query:async()=>{calls++;throw denied;}},{attempts:3,pause:async()=>{throw Error('must not wait');}}),error=>error===denied);assert.equal(calls,1);
 calls=0;await assert.rejects(installer._internals.awaitDatabase({query:async()=>{calls++;throw Object.assign(Error('offline'),{code:'ECONNREFUSED'});}},{attempts:3,pause:async()=>{}}),{code:'ANALYTICS_DATABASE_UNAVAILABLE'});assert.equal(calls,3);
});
test('installer refuses resources without a private ownership intent before any mutation',async()=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-analytics-install-control-')),p=installer.plan({root:path.join(home,'source'),homeDirectory:home});await fs.mkdir(p.directory,{recursive:true,mode:0o700});
 const original={resolve:authority.resolveDockerAuthority,verify:authority.verifyDockerAuthority,bound:authority.executeBoundDocker};const calls=[];
 authority.resolveDockerAuthority=async()=>({authority:{version:1,workspaceId:p.workspaceId,host:'unix:///owned.sock',daemonId:'owned'},persisted:true});authority.verifyDockerAuthority=async()=>{};
 authority.executeBoundDocker=async({args})=>{calls.push(args);if(args[0]==='container')return{stdout:JSON.stringify([{Id:'foreign',Config:{Labels:{}}}])};if(args[0]==='volume')throw Object.assign(Error('missing'),{code:1,stderr:'No such volume'});throw Error('Mutation attempted');};
 try {await assert.rejects(installer.provision({root:p.root,homeDirectory:home}),{code:'ANALYTICS_UNOWNED_RESOURCE'});assert.deepEqual(calls.map(args=>args.slice(0,2)),[['container','inspect'],['volume','inspect']]);await assert.rejects(fs.stat(p.managedFile),{code:'ENOENT'});}
 finally{authority.resolveDockerAuthority=original.resolve;authority.verifyDockerAuthority=original.verify;authority.executeBoundDocker=original.bound;await fs.rm(home,{recursive:true,force:true});}
});
test('repeat intent binds native immutable image, private credentials and reserved loopback port',()=>{
 const p=installer.plan({root:'/owned/workspace',homeDirectory:'/owned/home'}),digest='a'.repeat(64);
 const intent={version:1,workspaceId:p.workspaceId,ownerId:randomUUID(),authoritySha256:digest,imageId:'sha256:'+'b'.repeat(64),password:'c'.repeat(64),port:19096};
 assert.equal(installer._internals.checkIntent(intent,p,digest),intent);
 for(const bad of [{...intent,workspaceId:'d'.repeat(12)},{...intent,port:0},{...intent,imageId:'postgres:18'},{...intent,password:'fixture'},{...intent,databaseUrl:'postgres://app'}])assert.throws(()=>installer._internals.checkIntent(bad,p,digest));
 assert.throws(()=>installer._internals.volumeOwned({Name:p.volumeName,Labels:{'dvaia.workspace':p.workspaceId,'dvaia.purpose':'owned-analytics','dvaia.owner':'someone-else'}},p,intent.ownerId));
});
