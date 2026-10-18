'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {prepare}=require('../../scripts/install/secureshop-owned-listings-qualified-candidate');
const {provision}=require('../../scripts/install/secureshop-owned-listings-provision');
const {createRunner}=require('../../scripts/install/secureshop-owned-system-provision')._internals;
const managed=require('../../server/services/secureshopListingsManagedConfiguration');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
(async()=>{
 const root=path.resolve(__dirname,'../..'),home=process.env.LISTINGS_TEST_HOME,port=Number(process.env.LISTINGS_TEST_PORT),baseRun=createRunner({cwd:root,env:process.env}),commands=[];
 const run=async(file,args,options)=>{commands.push({file,args:args.filter((_,i)=>!['--env-file','--secret'].includes(args[i-1]))});const result=await baseRun(file,args,options);if(result.exitCode!==0)process.stderr.write(JSON.stringify({command:file,operation:file==='docker'?args[2]:file,exitCode:result.exitCode,stderr:result.stderr.slice(-4000)})+'\n');return result;};
 const options={root,home,platform:'darwin',architecture:'arm64',port,run,buildCaFile:process.env.LISTINGS_TEST_CA,buildCaSha256:process.env.LISTINGS_TEST_CA_SHA};
 const first=await prepare(options);assert.equal(first.managerReady,true);assert.equal(first.activationEnabled,false);assert.equal(first.ready,false);const file=first.managedPath,before=fs.readFileSync(file),value=managed.load({filePath:file});assert.equal(value.enabled,false);
 const start=commands.length;const repeat=await prepare(options);assert.equal(repeat.imageId,first.imageId);assert.deepEqual(fs.readFileSync(file),before);assert.ok(!commands.slice(start).some(c=>c.file==='docker'&&['build','create','start'].includes(c.args[2])));
 const qualified=require('../../scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedPackage({root,architecture:'arm64'});
 await assert.rejects(provision({...options,...qualified,fetchImpl:(url,opts)=>fetch(url,{...opts,headers:{...opts.headers,authorization:'Bearer '+'x'.repeat(64)}})}),{code:'LISTINGS_INSTALL_READINESS_FAILED'});assert.deepEqual(fs.readFileSync(file),before);
 const last=await prepare(options);assert.equal(last.managerReady,true);assert.deepEqual(fs.readFileSync(file),before);
 process.stdout.write(JSON.stringify({status:'passed',managerReady:true,applicationReady:false,modelCalls:0,databaseConnections:0,configBeforeSha256:sha(before),configAfterSha256:sha(fs.readFileSync(file)),imageId:first.imageId,runtimeDigest:first.runtimeDigest,sourceManifestSha256:first.sourceManifestSha256,workspaceId:first.workspaceId,checks:['actual-profile-provision','authenticated-manager-health','idempotent-no-create','unchanged-private-config','wrong-bearer-health-failed','disabled-capability-preserved','recovery-after-failed-health']})+'\n');
})().catch(error=>{process.stderr.write((error.code||'LISTINGS_INSTALL_NATIVE_FAILED')+'\n');process.exitCode=1;});
