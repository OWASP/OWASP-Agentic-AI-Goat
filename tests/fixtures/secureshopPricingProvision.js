'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {provision,prepare}=require('../../scripts/install/secureshop-owned-pricing-provision');
const managed=require('../../server/services/secureshopPricingManagedConfiguration');
const {createRunner}=require('../../scripts/install/secureshop-owned-system-provision')._internals;
const root=process.cwd(),home=process.env.HOME,environment={...process.env,SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
const baseRun=createRunner({cwd:root,env:environment}),counts={build:0,create:0,start:0};
const run=async(file,args,options)=>{if(file==='docker')for(const key of Object.keys(counts))if(args.includes(key))counts[key]++;const result=await baseRun(file,args,options);if(file==='docker'&&args.includes('start')&&result.exitCode){let message=result.stderr;const record=managed.load({root,home});if(record)message=message.replaceAll(record.config.token,'[redacted]');console.error(JSON.stringify({diagnostic:'docker-start',exitCode:result.exitCode,stderr:message.slice(0,4096)}));}return result;};
const execute=async(file,args,opts)=>{const r=await run(file,args,{timeoutMs:opts?.timeout||30000});if(r.exitCode)throw Error('owned command failed');return r;};
(async()=>{
 const options={root,home,platform:'darwin',architecture:'arm64',port:Number(process.env.PRICING_PORT),environment,run,execute,onDiagnostic:value=>console.error(JSON.stringify(value))};
 const before=await prepare(options);assert.equal(before.mutating,false);assert.equal(managed.load(options),null);assert.deepEqual(counts,{build:0,create:0,start:0});
 const first=await provision(options),record=managed.load(options);assert.equal(first.enabled,true);const baseline={...counts};
 await provision(options);assert.deepEqual(counts,baseline);assert.equal(managed.load(options).sha256,record.sha256);
 const stopped=await run('docker',['--host',record.authority.host,'stop','--time','20',record.config.containerId],{timeoutMs:25000});assert.equal(stopped.exitCode,0);
 await provision(options);assert.equal(counts.build,baseline.build);assert.equal(counts.create,baseline.create);assert.equal(counts.start,baseline.start+1);assert.equal(managed.load(options).sha256,record.sha256);
 const wrong=await prepare({...options,execute:async()=>({stdout:'"wrong-daemon"'})}).then(()=>false,()=>true);assert.equal(wrong,true);
 fs.writeFileSync(process.env.PRICING_RESULT,JSON.stringify({status:'passed',counts,first,tokenSha256:crypto.createHash('sha256').update(record.config.token).digest('hex'),recordSha256:record.sha256,repeatPreserved:true,restartSameIdentity:true,wrongAuthorityDenied:true})+'\n',{mode:0o600});
})().catch(e=>{console.error(JSON.stringify({code:e.code||e.name,message:String(e.message).slice(0,150)}));process.exitCode=1;});
