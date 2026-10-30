'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises');
const path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),tar=require('tar-stream');
const {admitImage,recoverImportedImage,_internals:i}=require('./postgres/ownedMcpImageAdmission');
const {PINS}=require('./postgres/ownedMcpBoundedBuild');
const {IMAGE_PROBE}=require('../scripts/install/secureshop-owned-mcp-registry')._internals;
test('unapproved V24 imports and recovery deny before archive or Docker access',async()=>{
 let calls=0;const run=async()=>{calls++;throw Error('must not run');};
 for(const target of ['v24-system','v24-policy'])for(const method of [admitImage,recoverImportedImage])
  await assert.rejects(method({target,run}),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
 assert.equal(calls,0);
});
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
async function fixture(t,change={}){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'image-admission-control-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const runId='a'.repeat(32),packageDigest='b'.repeat(64),layer=Buffer.from('synthetic layer, never executed');
  const config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:['sha256:'+sha(layer)]},config:{User:'10001:10001',Entrypoint:['node','sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'],Labels:{'owasp-ai-goat.registry.package':packageDigest,'owasp-ai-goat.build-run':runId}},...change.config}));
  const imageId='sha256:'+sha(config),configPath='blobs/sha256/'+sha(config),layerPath='blobs/sha256/'+sha(layer);
  const descriptor={mediaType:'application/vnd.oci.image.config.v1+json',digest:imageId,size:config.length};
  const oci=Buffer.from(JSON.stringify({schemaVersion:2,config:descriptor,layers:[{mediaType:'application/vnd.oci.image.layer.v1.tar',digest:'sha256:'+sha(layer),size:layer.length}]}));
  const ociPath='blobs/sha256/'+sha(oci);
  const runtimeImageId='sha256:'+sha(oci);
  const blobs=[['index.json',Buffer.from(JSON.stringify({schemaVersion:2,manifests:[{mediaType:'application/vnd.oci.image.manifest.v1+json',digest:'sha256:'+sha(oci),size:oci.length}]}))],
    ['manifest.json',Buffer.from(JSON.stringify([{Config:configPath,RepoTags:change.tags||null,Layers:[layerPath]}]))],
    ['oci-layout',Buffer.from('{"imageLayoutVersion":"1.0.0"}')],[configPath,config],[ociPath,oci],[layerPath,layer]];
  const pack=tar.pack(),chunks=[];
  const collecting=(async()=>{for await(const chunk of pack)chunks.push(chunk);})();
  for(const [name,bytes]of blobs)pack.entry({name,size:bytes.length,mode:0o444},bytes);
  if(change.extra)pack.entry({name:'../../foreign',size:1},'x');
  if(change.duplicate)pack.entry({name:'manifest.json',size:2},'[]');
  pack.finalize();await collecting;
  const archive=Buffer.concat(chunks),expected={runId,imageId,packageDigest,archiveBytes:archive.length,archiveSha256:sha(archive)};
  const spec=i.specification(root,expected);await fs.mkdir(spec.directory,{recursive:true});await fs.writeFile(spec.archive,archive,{mode:0o600});
  const calls=[];let loaded=false,probeId=null,token,finished=false;
  const cid='c'.repeat(64),digest='d'.repeat(64);
  const row=()=>({Id:cid,Name:'/owasp-ai-goat-v23-assets-'+runId,Image:change.runtimePresent?runtimeImageId:imageId,Config:{User:'10001:10001',Labels:{'owasp-ai-goat.admission':token},Entrypoint:['node'],Cmd:['-e',IMAGE_PROBE]},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],Memory:536870912,NanoCpus:1000000000,PidsLimit:32,LogConfig:{Type:'none'},SecurityOpt:['no-new-privileges']},Mounts:[],State:{Running:false,ExitCode:0}});
  const run=async(actual,args,options={})=>{
    assert.equal(actual.archive,spec.archive);calls.push(args);
    if(args[0]==='info')return JSON.stringify(change.daemon||PINS.daemon);
    if(args[0]==='image'&&args[1]==='ls')return PINS.postgres+' postgres:18\n'+(loaded||change.candidatePresent?imageId+' <none>:<none>\n':'')+(change.runtimePresent&&args.includes('--all')?runtimeImageId+' <none>:<none>\n':'')+(change.foreign&&(loaded||change.runtimePresent)?'sha256:'+'e'.repeat(64)+' unrelated:tag\n':'');
    if(args[0]==='ps')return probeId?probeId+'\n':'';
    if(args[0]==='volume')return '';
    if(args[0]==='image'&&args[1]==='load'){
      if(change.replaceArchive){await fs.rename(spec.archive,spec.archive+'.original');await fs.writeFile(spec.archive,Buffer.alloc(archive.length),{mode:0o600});}
      let bytes=0;for await(const chunk of options.input)bytes+=chunk.length;assert.equal(bytes,archive.length);
      if(change.loadFailure)throw Object.assign(Error('load rejected'),{code:'ADMISSION_DOCKER_FAILED',diagnostic:{exitCode:1,stderr:'controlled rejection'}});loaded=true;return 'Loaded image ID: '+imageId;
    }
    if(args[0]==='image'&&args[1]==='inspect'){
      const value={Id:change.runtimePresent?runtimeImageId:imageId,Architecture:'arm64',Os:'linux',Config:JSON.parse(config).config};
      if(change.runtimePresent){value.Descriptor={mediaType:'application/vnd.oci.image.manifest.v1+json',digest:runtimeImageId,size:oci.length};value.RootFS={Type:'layers',Layers:JSON.parse(config).rootfs.diff_ids};}
      if(change.badDescriptor)value.Descriptor.digest=imageId;if(change.badRootfs)value.RootFS.Layers=[];if(change.badConfig)value.Config.Env=['foreign'];
      return JSON.stringify([value]);
    }
    if(args[0]==='create'){
      token=args[args.indexOf('--label')+1].split('=')[1];
      const intent=JSON.parse(await fs.readFile(path.join(actual.directory,'probe-intent.json')));
      assert.deepEqual(intent.argv,['--host',spec.host,...args]);assert.equal(intent.token,token);
      assert.equal(intent.name,'owasp-ai-goat-v23-assets-'+runId);assert.equal(intent.imageId,actual.expected.imageId);
      assert.equal(intent.daemon,PINS.daemon);assert.equal(intent.executable,spec.docker);
      assert.equal((await fs.stat(path.join(actual.directory,'probe-intent.json'))).mode&0o777,0o600);
      await assert.rejects(fs.access(path.join(actual.directory,'probe-created.json')));
      probeId=cid;if(change.createReplyLost)throw Error('lost create reply');
      if(change.createdJournalFailure)await fs.mkdir(path.join(actual.directory,'probe-created.json'));
      return cid;
    }
    if(args[0]==='container'){const value=row();if(change.foreignProbe)value.Config.Labels['owasp-ai-goat.admission']='foreign';if(change.probeMemory)value.HostConfig.Memory=0;return JSON.stringify([value]);}
    if(args[0]==='start'){assert.equal(JSON.parse(await fs.readFile(path.join(actual.directory,'probe-created.json'))).id,cid);finished=true;return digest;}
    if(args[0]==='rm'){assert.equal(args[1],cid);if(change.removeFailure)throw Error('remove refused');probeId=null;return cid;}
    assert.fail('unexpected '+args.join(' '));
  };
  return{root,spec,expected,calls,archive,runtimeImageId,run:(attempt=1)=>admitImage({root,expected,run,verifyDocker:false,attempt}),recover:()=>recoverImportedImage({root,expected,run,verifyDocker:false}),probeFinished:()=>finished};
}
test('untagged exact OCI/Docker archive imports once and probes with no archive copy',async t=>{
  const f=await fixture(t),result=await f.run().catch(error=>{throw Error(JSON.stringify(error.errors?.map(x=>({code:x.code,message:x.message}))));});
  assert.equal(result.imageId,f.expected.imageId);assert.equal(result.runtimeDigest,'d'.repeat(64));assert.equal(result.qualificationComplete,false);
  assert.deepEqual(await fs.readFile(f.spec.archive),f.archive);
  assert.equal(f.calls.filter(x=>x[0]==='image'&&x[1]==='load').length,1);
  assert(!f.calls.some(x=>['tag','build','pull'].includes(x[0])));
  assert(f.probeFinished());
  assert.deepEqual((await fs.readdir(f.spec.directory)).sort(),['admission-intent.json','admission-result.json','image.tar','probe-cleanup.json','probe-created.json','probe-intent.json']);
  const intent=await fs.readFile(path.join(f.spec.directory,'probe-intent.json'));
  const cleanup=JSON.parse(await fs.readFile(path.join(f.spec.directory,'probe-cleanup.json')));
  assert.equal(cleanup.intentSha256,sha(intent));assert.equal(cleanup.status,'removed');assert.equal(cleanup.absenceVerified,true);
});
test('unpersistable exclusive probe intent prevents container creation',async t=>{
  const f=await fixture(t),journal=path.join(f.spec.directory,'probe-intent.json');
  await fs.writeFile(journal,'existing authority',{mode:0o600});
  await assert.rejects(f.run());assert(!f.calls.some(x=>x[0]==='create'));
  assert.equal(await fs.readFile(journal,'utf8'),'existing authority');
});
test('lost create reply retains durable authority without name adoption or retry',async t=>{
  const f=await fixture(t,{createReplyLost:true});await assert.rejects(f.run());
  const intent=JSON.parse(await fs.readFile(path.join(f.spec.directory,'probe-intent.json')));
  assert.equal(intent.imageId,f.expected.imageId);assert.match(intent.token,/^[a-f0-9]{32}$/);
  await assert.rejects(fs.access(path.join(f.spec.directory,'probe-created.json')));
  const cleanup=JSON.parse(await fs.readFile(path.join(f.spec.directory,'probe-cleanup.json')));
  assert.equal(cleanup.status,'uncertain');assert.equal(cleanup.id,null);assert.equal(cleanup.absenceVerified,false);
  assert.equal(f.calls.filter(x=>x[0]==='create').length,1);
  assert(!f.calls.some(x=>['rm','container','start'].includes(x[0])));
});
test('captured ID journal failure cleans only captured identity and cannot pass',async t=>{
  const f=await fixture(t,{createdJournalFailure:true});await assert.rejects(f.run());
  assert(!f.probeFinished());assert.equal(f.calls.filter(x=>x[0]==='rm').length,1);
  const cleanup=JSON.parse(await fs.readFile(path.join(f.spec.directory,'probe-cleanup.json')));
  assert.equal(cleanup.status,'removed');assert.equal(cleanup.id,'c'.repeat(64));
});
for(const change of [{extra:true},{duplicate:true},{tags:['postgres:18']},{config:{architecture:'amd64'}}])test('unsafe archive rejected before any daemon command',async t=>{
  const f=await fixture(t,change);await assert.rejects(f.run());assert.equal(f.calls.length,0);
});
test('archive digest mismatch prevents import',async t=>{
  const f=await fixture(t);f.expected.archiveSha256='f'.repeat(64);await assert.rejects(f.run());assert(!f.calls.some(x=>x[1]==='load'));
});
test('archive symlink rejected without contacting Docker',async t=>{
  const f=await fixture(t);await fs.rename(f.spec.archive,f.spec.archive+'.retained');await fs.symlink(f.spec.archive+'.retained',f.spec.archive);
  await assert.rejects(f.run());assert.equal(f.calls.length,0);
});
test('wrong daemon refuses before import intent',async t=>{
  const f=await fixture(t,{daemon:'foreign'});await assert.rejects(f.run());assert(!f.calls.some(x=>x[1]==='load'));
  await assert.rejects(fs.access(path.join(f.spec.directory,'admission-intent.json')));
});
for(const change of [{foreign:true},{loadFailure:true},{foreignProbe:true},{removeFailure:true},{probeMemory:true}])test('unknown load, changed assets, or probe cleanup failure cannot pass',async t=>{
  const f=await fixture(t,change);await assert.rejects(f.run(),AggregateError);
  assert(!f.calls.some(x=>x[0]==='image'&&x[1]==='rm'));
  if(change.foreignProbe)assert(!f.calls.some(x=>x[0]==='rm'));
  const receipt=JSON.parse(await fs.readFile(path.join(f.spec.directory,'admission-result.json')));
  assert(receipt.error||receipt.preservationError);assert.equal(receipt.automaticRetry,false);
  assert.equal((await fs.stat(f.spec.archive)).size,f.archive.length);
});
test('same open descriptor cannot silently adopt an archive pathname replacement',async t=>{
  const f=await fixture(t,{replaceArchive:true});await assert.rejects(f.run(),AggregateError);
  const receipt=JSON.parse(await fs.readFile(path.join(f.spec.directory,'admission-result.json')));
  assert.equal(receipt.error,'ADMISSION_ARCHIVE_CHANGED');assert(!f.probeFinished());
  assert.deepEqual(await fs.readFile(f.spec.archive+'.original'),f.archive);
});
test('invalid root or unbounded archive expectation rejected',()=>{
  assert.throws(()=>i.specification('/'));
  assert.throws(()=>i.specification('/tmp/repo',{runId:'../escape'}));
});
test('failed command retains bounded stderr and actual exit code',async t=>{
  const f=await fixture(t),docker=path.join(f.root,'fake-docker');
  await fs.writeFile(docker,'#!/bin/sh\nprintf "daemon load rejected: missing blob" >&2\nexit 42\n',{mode:0o700});
  await assert.rejects(i.command({...f.spec,docker},['image','load']),error=>{
    assert.equal(error.code,'ADMISSION_DOCKER_FAILED');assert.equal(error.diagnostic.exitCode,42);
    assert.equal(error.diagnostic.stderr,'daemon load rejected: missing blob');return true;
  });
});
test('command output overflow retains only bounded diagnostic tail',async t=>{
  const f=await fixture(t),docker=path.join(f.root,'fake-docker');
  await fs.writeFile(docker,'#!/bin/sh\ni=0; while [ "$i" -lt 3072 ]; do printf "%01024d" 0 >&2; i=$((i+1)); done\n',{mode:0o700});
  await assert.rejects(i.command({...f.spec,docker},[],{timeoutMs:5000}),error=>{
    assert.equal(error.code,'ADMISSION_OUTPUT_LIMIT');assert(error.diagnostic.stderrTailBytes<=16384);
    assert(error.diagnostic.outputBytes>2*1024**2);return true;
  });
});
test('explicit second attempt preserves original evidence and uses same archive',async t=>{
  const change={loadFailure:true},f=await fixture(t,change);await assert.rejects(f.run());
  const old=await fs.readFile(path.join(f.spec.directory,'admission-result.json'));
  const prior=JSON.parse(old);assert.equal(prior.diagnostic.archiveBytesRead,f.archive.length);assert.equal(prior.diagnostic.archiveSha256Read,sha(f.archive));
  change.loadFailure=false;await f.run(2);
  assert.deepEqual(await fs.readFile(path.join(f.spec.directory,'admission-result.json')),old);
  assert.deepEqual(await fs.readFile(f.spec.archive),f.archive);
  assert.equal(JSON.parse(await fs.readFile(path.join(f.spec.directory,'admission-attempt-2/admission-result.json'))).result.imageId,f.expected.imageId);
});
for(const kind of ['uncertain','success','present','exclusive','probe'])test('second attempt refuses unsafe predecessor: '+kind,async t=>{
  const change={loadFailure:true},f=await fixture(t,change);await assert.rejects(f.run());
  const target=path.join(f.spec.directory,'admission-result.json'),prior=JSON.parse(await fs.readFile(target));
  if(kind==='uncertain')prior.error='ADMISSION_COMMAND_TIMEOUT';
  if(kind==='success')prior.result={imageId:f.expected.imageId};
  if(kind==='present')change.candidatePresent=true;
  if(kind==='exclusive')await fs.mkdir(path.join(f.spec.directory,'admission-attempt-2'));
  if(kind==='probe')await fs.writeFile(path.join(f.spec.directory,'probe-intent.json'),'{}');
  await fs.writeFile(target,JSON.stringify(prior));
  const count=f.calls.length;await assert.rejects(f.run(2));
  assert(!f.calls.slice(count).some(x=>x[1]==='load'||x[0]==='create'));
});
test('explicit recovery admits exact hidden manifest identity without loading again',async t=>{
  const change={loadFailure:true},f=await fixture(t,change);await assert.rejects(f.run());await assert.rejects(f.run(2));
  const old=await fs.readFile(path.join(f.spec.directory,'admission-result.json'));change.runtimePresent=true;
  const count=f.calls.length,result=await f.recover();
  assert.equal(result.configImageId,f.expected.imageId);assert.equal(result.runtimeImageId,f.runtimeImageId);
  assert(!f.calls.slice(count).some(x=>['load','build','pull','tag'].includes(x[1])||x[0]==='tag'));
  assert(f.calls.slice(count).filter(x=>x[0]==='image'&&x[1]==='ls').every(x=>x.includes('--all')));
  assert.deepEqual(await fs.readFile(path.join(f.spec.directory,'admission-result.json')),old);
  const intent=JSON.parse(await fs.readFile(path.join(f.spec.directory,'admission-recovery-1/recovery-intent.json')));
  assert(intent.priorReceipts.every(x=>x.inventoryComplete===false));
  await assert.rejects(f.recover());
});
for(const fault of ['badDescriptor','badRootfs','badConfig','foreign'])test('recovery rejects exact identity or inventory mismatch: '+fault,async t=>{
  const change={loadFailure:true},f=await fixture(t,change);await assert.rejects(f.run());await assert.rejects(f.run(2));change.runtimePresent=true;change[fault]=true;
  const count=f.calls.length;await assert.rejects(f.recover());assert(!f.calls.slice(count).some(x=>x[0]==='create'||x[1]==='load'));
});
