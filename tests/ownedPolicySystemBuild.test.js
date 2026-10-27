'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {TARGETS,LIMITS,validateCandidate,requireApprovedTarget}=require('./postgres/ownedPolicySystemBuild');
test('Listings metadata binds its actual two-stage recipe without borrowing build authority',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const contract=require('./postgres/ownedPolicySystemBuild'),metadata=require('./postgres/ownedPolicySystemMetadata');
 const spec=TARGETS['listings-package'],retention=contract.metadataRetentionSpecification('listings-package');
 const recipe=fs.readFileSync(path.join(__dirname,'../sidecars/sandbox-runner/owned-listings/Dockerfile.candidate'),'utf8');
 assert.deepEqual([...recipe.matchAll(/^FROM node:26\.10\.0-slim@(sha256:[a-f0-9]{64})/gm)].map(x=>x[1]),[spec.base,spec.base]);
 assert.deepEqual([...recipe.matchAll(/apt-get install -y --no-install-recommends ([a-z0-9 -]+) &&/g)].map(x=>x[1].split(' ')),retention.stages.map(x=>x.packages));
 assert.equal(spec.metadataSourcePolicy,'listings-trixie-freshness-v1');
 assert.equal(retention.kind,'listings-original-apt-retention');
 assert.throws(()=>validateCandidate('listings-package',{},{}),{code:'BUILD_TARGET_METADATA_ONLY'});
 assert.throws(()=>requireApprovedTarget('listings-package'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
 const binding={runId:'a'.repeat(32),target:'listings-package',base:spec.base};
 const guest=metadata.guestMetadataSource(binding,{retention:retention.mode});
 assert.match(guest,/listings-original-apt-retention/);
 assert.doesNotThrow(()=>new Function(guest));
});
test('Pricing metadata target matches original fourteen-file recipe without build authority',()=>{
 const pricing=require('./postgres/ownedPricingOriginalBuild'),spec=TARGETS['v33-pricing'];
 const retention=require('./postgres/ownedPolicySystemBuild').metadataRetentionSpecification('v33-pricing');
 assert.equal(spec.base,pricing.BASE);assert.equal(spec.metadataOnly,true);
 assert.equal(spec.metadataSourcePolicy,'v33-pricing-trixie-freshness-v1');
 assert.deepEqual(retention.stages,pricing.STAGES);
 assert.equal(retention.kind,'v33-pricing-original-apt-retention');
 assert.equal(retention.mode,'v33-pricing-metadata-retention-v1');
 assert.throws(()=>validateCandidate('v33-pricing',{},{}),{code:'BUILD_TARGET_METADATA_ONLY'});
 assert.throws(()=>requireApprovedTarget('v33-pricing'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
});
function candidate(target){
 const spec=TARGETS[target],dockerfile=spec.sourceRoot+'Dockerfile';
 return {manifest:{version:1,target,platform:'linux/arm64',baseImageDigest:spec.base,
  dependencyLockSha256:'a'.repeat(64),limits:{...LIMITS},entrypoint:[...spec.entrypoint],user:'10001:10001',dockerfile,
  files:{[dockerfile]:{sha256:'b'.repeat(64),bytes:100,mode:0o444}}},
 lock:{version:1,baseImageDigest:spec.base,architecture:'arm64',releaseSha256:'c'.repeat(64),keyringSha256:'d'.repeat(64),
  packages:spec.packages.map(name=>({name,version:'controlled-version',sha256:'e'.repeat(64),bytes:100,architecture:'arm64'}))}};
}
test('both exact target drafts remain ineligible even when structurally valid',()=>{
 for(const target of ['v24-system','v24-policy']){
  const {manifest,lock}=candidate(target);
  assert.deepEqual(validateCandidate(target,manifest,lock),{structurallyValid:true,eligible:false,reason:'DEPENDENCY_LOCK_NOT_APPROVED'});
  assert.throws(()=>requireApprovedTarget(target),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
 }
 assert.deepEqual(LIMITS,require('./postgres/ownedMcpBoundedBuild').LIMITS);
});
test('V23 metadata target matches original Dockerfile requirements but grants no build authority',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const spec=TARGETS['v23-registry'];
 assert.equal(spec.metadataSourcePolicy,'v23-trixie-freshness-v1');
 assert.equal(TARGETS['v24-policy'].metadataSourcePolicy,undefined);
 assert.equal(TARGETS['v24-system'].metadataSourcePolicy,'v24-system-trixie-freshness-v1');
 const manifest=require('../scripts/install/manifests/secureshop-owned-mcp-registry-build.json');
 assert.equal(manifest.dockerfile,'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate');
 const dockerfile=fs.readFileSync(path.join(__dirname,'..',manifest.dockerfile),'utf8');
 const bases=[...dockerfile.matchAll(/^FROM node:26\.10\.0-slim@(sha256:[a-f0-9]{64})(?: AS build)?$/gm)].map(match=>match[1]);
 assert.deepEqual(bases,[spec.base,spec.base]);
 const installs=[...dockerfile.matchAll(/apt-get install -y --no-install-recommends ([a-z0-9 -]+) &&/g)]
  .map(match=>match[1].trim().split(' '));
 assert.deepEqual(installs,[['gcc','libc6-dev','libseccomp-dev'],['bubblewrap','libseccomp2']]);
 assert.deepEqual(spec.packages,[...new Set(installs.flat())].sort());
 assert.deepEqual(spec.installPackages,installs.flat());
 assert.ok(Object.isFrozen(spec)&&Object.isFrozen(spec.packages)&&Object.isFrozen(spec.installPackages));
 assert.equal(spec.metadataOnly,true);assert.equal(spec.sourceRoot,undefined);
 assert.throws(()=>validateCandidate('v23-registry',{},{}),{code:'BUILD_TARGET_METADATA_ONLY'});
 assert.throws(()=>requireApprovedTarget('v23-registry'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
 assert.match(dockerfile,/npm ci --ignore-scripts --no-audit --no-fund/);
});
test('closed target rejects changed base, scope, entrypoint, resource caps and dependency evidence',()=>{
 for(const change of [x=>x.manifest.baseImageDigest='sha256:'+'0'.repeat(64),
  x=>x.manifest.limits.disk++,x=>x.manifest.entrypoint=['sh'],x=>x.manifest.user='root',
  x=>x.manifest.files['../private']={sha256:'a'.repeat(64),bytes:1,mode:0o444},
  x=>x.manifest.files[x.manifest.dockerfile].bytes=2*1024**2,
  x=>x.lock.packages.pop(),x=>x.lock.packages.push(x.lock.packages[0]),
  x=>x.lock.releaseSha256='',x=>x.lock.packages[0].architecture='amd64']){
  const value=candidate('v24-system');change(value);assert.throws(()=>validateCandidate('v24-system',value.manifest,value.lock));
 }
 for(const target of ['unknown','__proto__',{},null])assert.throws(()=>requireApprovedTarget(target),{code:'BUILD_TARGET_UNKNOWN'});
});
test('System retention binds the original config recipe and one stage, without borrowing V23 authority',()=>{
 const {metadataRetentionSpecification}=require('./postgres/ownedPolicySystemBuild');
 const text=require('node:fs').readFileSync(require('node:path').join(__dirname,'postgres/system_config_owned_executor.py'),'utf8');
 const spec=TARGETS['v24-system'],retention=metadataRetentionSpecification('v24-system');
 assert.equal(spec.base,'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5');
 assert.equal(retention.mode,'v24-system-metadata-retention-v1');
 assert.equal(retention.kind,'v24-system-original-apt-retention');
 assert.deepEqual(retention.stages,[{name:'system',packages:['gcc','libc6-dev','bubblewrap']}]);
 const configRecipe=text.slice(text.indexOf('class OwnedSystemExecutor:'),text.indexOf('class OwnedSystemRestartExecutor:'));
 const identity=require('node:fs').readFileSync(require('node:path').join(__dirname,'postgres/system_diagnostic_owned_executor.py'),'utf8');
 assert.equal(/^BASE='(sha256:[a-f0-9]{64})'$/m.exec(identity)?.[1],spec.base);
 assert.match(text,/from system_diagnostic_owned_executor import \(\s*BASE,/);
 assert.match(configRecipe,/FROM node@/);
 assert.match(configRecipe,/apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap &&/);
 assert.match(configRecipe,/ENTRYPOINT \["\/usr\/local\/bin\/node","\/qualification\/owned-system\/http-listener.js"\]/);
 assert.equal(spec.metadataSourcePolicy,'v24-system-trixie-freshness-v1','explicit System policy, not implicit V23 authority');
 assert.equal(TARGETS['v23-registry'].metadataSourcePolicy,'v23-trixie-freshness-v1');
 assert.equal(TARGETS['v24-policy'].metadataSourcePolicy,undefined);
 assert.equal(metadataRetentionSpecification('v24-policy').sourcePolicy,'v24-policy-trixie-freshness-v1');
 assert.deepEqual(metadataRetentionSpecification('v23-registry').stages,
  [{name:'build',packages:['gcc','libc6-dev','libseccomp-dev']},{name:'runtime',packages:['bubblewrap','libseccomp2']}]);
 assert(Object.isFrozen(retention)&&Object.isFrozen(retention.stages)&&Object.isFrozen(retention.stages[0])&&Object.isFrozen(retention.stages[0].packages));
 assert.throws(()=>metadataRetentionSpecification('__proto__'));
 assert.throws(()=>requireApprovedTarget('v24-system'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
});
test('renderer retention is exact original two-stage input, explicit freshness, and never build authority',async()=>{
 const inputs=await require('./postgres/ownedPolicyRendererBuildInputs').capturePolicyRendererBuildInputs(require('node:path').resolve(__dirname,'..'));
 const {metadataRetentionSpecification,metadataSourcePolicy}=require('./postgres/ownedPolicySystemBuild');
 const spec=TARGETS['v24-policy'],retained=metadataRetentionSpecification('v24-policy');
 assert.equal(spec.base,inputs.recipe.base);
 assert.deepEqual(retained.stages,inputs.recipe.stages.map(({name,packages})=>({name,packages})));
 assert.equal(retained.mode,'v24-policy-metadata-retention-v1');assert.equal(retained.kind,'v24-policy-original-apt-retention');
 assert.equal(metadataSourcePolicy('v24-policy'),null,'legacy non-retained candidate unchanged');
 assert.equal(metadataSourcePolicy('v24-policy',true),'v24-policy-trixie-freshness-v1');
 for(const target of ['v23-registry','v24-system','v33-pricing'])assert.equal(metadataSourcePolicy(target,true),TARGETS[target].metadataSourcePolicy);
 assert(Object.isFrozen(retained.stages[0].packages));
 assert.throws(()=>metadataSourcePolicy('v24-policy',{}));
 assert.throws(()=>requireApprovedTarget('v24-policy'),{code:'DEPENDENCY_LOCK_NOT_APPROVED'});
});
