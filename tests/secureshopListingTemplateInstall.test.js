'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const path=require('node:path');
const fs=require('node:fs');
const os=require('node:os');
const installer=require('../scripts/install/secureshop-owned-listing-template');
const managed=require('../server/services/secureshopListingTemplateManagedConfiguration');
const contract=require('../server/services/secureshopListingTemplateExecutorContract');
const {workspaceId}=require('../scripts/application-data-root');
const ROOT=path.resolve(__dirname,'..');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function controlledFetch({badHealth=false,badEffect=false,badRender=false}={}){
 const calls=[];
 const fetchImpl=async(url,options)=>{
  calls.push({url,options});
  assert.equal(new URL(url).hostname,'127.0.0.1');
  assert.equal(options.redirect,'error');
  if(url.endsWith('/health'))return new Response(JSON.stringify({status:'ok',listingTemplate:{enabled:true,available:!badHealth,isolation:contract.ISOLATION}}));
  assert.ok(url.endsWith('/secureshop/listing-template-render'));
  assert.equal(options.method,'POST');
  const request=contract.normalizeListingTemplateExecution(JSON.parse(options.body));
  assert.equal(request.templateSource,'Hello {{ title }}');
  assert.equal(request.title,'world');
  const rendered=badRender?'unexpected':'Hello world';
  return new Response(JSON.stringify({version:1,operationId:request.operationId,productId:request.productId,
   requestSha256:contract.listingTemplateExecutionDigest(request),sourceSha256:request.sourceSha256,
   isolation:contract.ISOLATION,rendered,renderedSha256:sha(Buffer.from(rendered)),exitCode:0,
   timedOut:false,truncated:false,drained:true,workerAttested:true,
   commandEffectObserved:badEffect,effectSha256:badEffect?sha('effect'):null}));
 };
 return {calls,fetchImpl};
}
test('inert readiness performs one real exact render after bounded health',async()=>{
 const f=controlledFetch();
 const receipt=await installer._internals.inertReadiness({p:{port:8109},fetchImpl:f.fetchImpl,readinessAttempts:1});
 assert.equal(receipt.rendered,'Hello world');
 assert.deepEqual(f.calls.map(c=>new URL(c.url).pathname),['/health','/secureshop/listing-template-render']);
});
for(const [name,flags,renderCalls]of [
 ['unhealthy',{badHealth:true},0],['unexpected effect',{badEffect:true},1],['unexpected rendering',{badRender:true},1]
])test('inert readiness denies '+name,async()=>{
 const f=controlledFetch(flags);
 await assert.rejects(installer._internals.inertReadiness({p:{port:8109},fetchImpl:f.fetchImpl,readinessAttempts:1}));
 assert.equal(f.calls.filter(c=>c.options.method==='POST').length,renderCalls);
});
test('managed record has distinct bounded identity and port',()=>{
 const id=workspaceId(ROOT),base={version:1,workspaceId:id,ownerId:crypto.randomUUID(),architecture:'arm64',
  dockerAuthoritySha256:sha('authority'),sourceSha256:sha('source'),imageId:'sha256:'+sha('image'),
  profile:'dvaia-owned-listing-template-'+id,profileSha256:sha('profile'),
  container:'dvaia-listing-template-'+id,containerId:sha('container'),port:8109,enabled:false};
 assert.deepEqual(managed.validate(base,{root:ROOT}),base);
 for(const port of [8108,8119])assert.throws(()=>managed.validate({...base,port},{root:ROOT}),{code:'LISTING_TEMPLATE_MANAGED_INVALID'});
 assert.throws(()=>managed.validate({...base,container:'dvaia-policy-renderer-'+id},{root:ROOT}),{code:'LISTING_TEMPLATE_MANAGED_INVALID'});
});
test('source manifest is closed to the distinct package and three borrowed qualified assets',()=>{
 const source=installer.sourceManifest(ROOT),names=Object.keys(source.files);
 assert.equal(names.length,12);
 assert.ok(names.includes('sidecars/sandbox-runner/listing-template/Dockerfile'));
 assert.ok(names.includes('sidecars/sandbox-runner/policy-render/process-supervisor.c'));
 assert.ok(names.includes('sidecars/sandbox-runner/policy-render/assets/nunjucks-3.2.4.js'));
 assert.ok(!names.some(name=>name.includes('policy-init.c')));
 assert.equal(require('../scripts/install/secureshop-owned-policy-renderer').sourceManifest(ROOT).sha256,
  '56627efeebbc2b25d8ff2eeae7247a34d4f7eae752cb678fcad07d0433246279');
});
test('startup skips an absent optional package without contacting Docker',async t=>{
 const home=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'listing-template-absent-'));
 t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 let calls=0;
 const result=await installer.startExisting({root:ROOT,home,platform:'darwin',architecture:'arm64',
  run:async()=>{calls++;throw Error('Docker must not run');}});
 assert.deepEqual(result,{ready:false,enabled:false,absent:true});
 assert.equal(calls,0);
});
test('distinct staged record publishes once and detects same-byte inode replacement',t=>{
 const home=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'listing-template-private-'));
 t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const id=workspaceId(ROOT),directory=path.join(home,'.dvaia',id);
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const authority={version:1,workspaceId:id,host:'unix:///var/run/docker.sock',daemonId:'controlled-template-daemon',source:'environment-host'};
 fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify(authority),{mode:0o600});
 const {authorityDigest}=require('../scripts/local-docker-authority');
 const base={version:1,workspaceId:id,ownerId:crypto.randomUUID(),architecture:'arm64',
  dockerAuthoritySha256:authorityDigest(authority),sourceSha256:sha('source'),imageId:'sha256:'+sha('image'),
  profile:'dvaia-owned-listing-template-'+id,profileSha256:sha('profile'),
  container:'dvaia-listing-template-'+id,port:8109};
 const stage=managed.stage({root:ROOT,home,value:{...base,activateRequested:true}});
 const record=managed.publish({root:ROOT,home,expected:null,expectedStage:stage,
  value:{...base,containerId:sha('container'),enabled:true}});
 assert.equal(record.value.enabled,true);
 const bytes=fs.readFileSync(record.filename);
 fs.renameSync(record.filename,record.filename+'.old');fs.writeFileSync(record.filename,bytes,{mode:0o600});
 assert.throws(()=>managed.assertCaptured(record,{root:ROOT,home}),{code:'LISTING_TEMPLATE_MANAGED_INVALID'});
});
