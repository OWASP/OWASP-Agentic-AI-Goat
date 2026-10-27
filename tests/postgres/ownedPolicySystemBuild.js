'use strict';

// Import-inert prerequisite contract. No manifest or dependency lock has
// been approved yet. Structural validity is never execution authority.
const {isDeepStrictEqual}=require('node:util');
const LIMITS=Object.freeze({disk:6*1024**3,export:1024**3,output:2*1024**2,buildMs:300000});
const TARGETS=Object.freeze({
 'v03-diagnostic':Object.freeze({base:'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5',
  metadataOnly:true,metadataSourcePolicy:'v03-diagnostic-trixie-freshness-v1',
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev']),
  installPackages:Object.freeze(['gcc','libc6-dev','bubblewrap'])}),
 'listings-package':Object.freeze({base:'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',
  metadataOnly:true,metadataSourcePolicy:'listings-trixie-freshness-v1',
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev','libseccomp-dev','libseccomp2']),
  installPackages:Object.freeze(['gcc','libc6-dev','libseccomp-dev','bubblewrap','libseccomp2'])}),
 'v33-pricing':Object.freeze({base:'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',
  metadataOnly:true,metadataSourcePolicy:'v33-pricing-trixie-freshness-v1',
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev','libseccomp-dev','libseccomp2']),
  installPackages:Object.freeze(['gcc','libc6-dev','libseccomp-dev','bubblewrap','libseccomp2'])}),
 'v24-system':Object.freeze({base:'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5',
  // Prospective local metadata policy, not a Debian requirement or a change
  // to the original Dockerfile: stable90d, updates/security7d, earlier signed
  // Valid-Until always wins. The failed seven-day run remains failed evidence.
  metadataSourcePolicy:'v24-system-trixie-freshness-v1',
  sourceRoot:'sidecars/sandbox-runner/owned-system/',entrypoint:Object.freeze(['/usr/local/bin/node','/qualification/owned-system/http-listener.js']),
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev']),
  installPackages:Object.freeze(['gcc','libc6-dev','bubblewrap'])}),
 'v24-policy':Object.freeze({base:'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',
  sourceRoot:'sidecars/sandbox-runner/policy-render/',entrypoint:Object.freeze(['/usr/local/bin/node','/app/policy-render/listener.js']),
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev']),
  installPackages:Object.freeze(['gcc','libc6-dev','bubblewrap'])}),
 // Only Debian metadata discovery for the original packaged registry image.
 // Its cross-directory 20-file build authority and npm lock are separate;
 // this entry deliberately provides no permissive sourceRoot/build manifest.
 'v23-registry':Object.freeze({base:'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',
  metadataOnly:true,metadataSourcePolicy:'v23-trixie-freshness-v1',
  packages:Object.freeze(['bubblewrap','gcc','libc6-dev','libseccomp-dev','libseccomp2']),
  installPackages:Object.freeze(['gcc','libc6-dev','libseccomp-dev','bubblewrap','libseccomp2'])}),
});
// Retention contracts are target-specific metadata evidence, never execution
// authority. Existing non-retained candidates and V23 stage ordering stay fixed.
const METADATA_RETENTION=Object.freeze({
 'v03-diagnostic':Object.freeze({mode:'v03-diagnostic-metadata-retention-v1',kind:'v03-diagnostic-original-apt-retention',
  stages:Object.freeze([Object.freeze({name:'diagnostic',packages:Object.freeze(['gcc','libc6-dev','bubblewrap'])})])}),
 'listings-package':Object.freeze({mode:'listings-metadata-retention-v1',kind:'listings-original-apt-retention',
  stages:Object.freeze([
   Object.freeze({name:'build',packages:Object.freeze(['gcc','libc6-dev','libseccomp-dev'])}),
   Object.freeze({name:'runtime',packages:Object.freeze(['bubblewrap','libseccomp2'])}),
  ])}),
 'v24-policy':Object.freeze({mode:'v24-policy-metadata-retention-v1',kind:'v24-policy-original-apt-retention',
  // Explicit local policy for the original ec7758 Node/trixie base. Reuse the
  // existing bounded trixie policy arithmetic, not another target's receipt.
  // Original Dockerfile has no local Max-ValidTime override. Stable releases
  // may be older than seven days; allow <=90d stable / <=7d updates/security,
  // always limited by earlier signed Valid-Until and APT signature verification.
  // Legacy non-retained candidate behavior is deliberately unchanged.
  sourcePolicy:'v24-policy-trixie-freshness-v1',
  stages:Object.freeze([
   Object.freeze({name:'build',packages:Object.freeze(['gcc','libc6-dev'])}),
   Object.freeze({name:'runtime',packages:Object.freeze(['bubblewrap'])}),
  ])}),
 'v33-pricing':Object.freeze({mode:'v33-pricing-metadata-retention-v1',kind:'v33-pricing-original-apt-retention',
  stages:Object.freeze([
   Object.freeze({name:'build',packages:Object.freeze(['gcc','libc6-dev','libseccomp-dev'])}),
   Object.freeze({name:'runtime',packages:Object.freeze(['bubblewrap','libseccomp2'])}),
  ])}),
 'v23-registry':Object.freeze({mode:'v23-metadata-retention-v1',kind:'v23-original-apt-retention',
  stages:Object.freeze([
   Object.freeze({name:'build',packages:Object.freeze(['gcc','libc6-dev','libseccomp-dev'])}),
   Object.freeze({name:'runtime',packages:Object.freeze(['bubblewrap','libseccomp2'])}),
  ])}),
 'v24-system':Object.freeze({mode:'v24-system-metadata-retention-v1',kind:'v24-system-original-apt-retention',
  stages:Object.freeze([Object.freeze({name:'system',packages:Object.freeze(['gcc','libc6-dev','bubblewrap'])})])}),
});
const fail=code=>Object.assign(new Error(code),{code});
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
function targetSpecification(target){
 if(typeof target!=='string'||!Object.hasOwn(TARGETS,target))throw fail('BUILD_TARGET_UNKNOWN');
 return TARGETS[target];
}
function metadataRetentionSpecification(target){
 targetSpecification(target);
 return METADATA_RETENTION[target]||null;
}
function metadataSourcePolicy(target,retained=false){
 const spec=targetSpecification(target);
 if(typeof retained!=='boolean')throw fail('BUILD_METADATA_RETENTION');
 return (retained?METADATA_RETENTION[target]?.sourcePolicy:null)??spec.metadataSourcePolicy??null;
}
function validateCandidate(target,manifest,lock){
 const spec=targetSpecification(target);
 if(spec.metadataOnly)throw fail('BUILD_TARGET_METADATA_ONLY');
 if(!manifest||manifest.version!==1||manifest.target!==target||manifest.platform!=='linux/arm64'
  ||manifest.baseImageDigest!==spec.base||!digest(manifest.dependencyLockSha256)
  ||!isDeepStrictEqual(manifest.limits,LIMITS)||!isDeepStrictEqual(manifest.entrypoint,spec.entrypoint)
  ||manifest.user!=='10001:10001'||!manifest.files||Array.isArray(manifest.files)
  ||Object.keys(manifest.files).length<1||Object.keys(manifest.files).length>128)throw fail('BUILD_TARGET_MANIFEST_INVALID');
 let bytes=0;
 for(const [name,row] of Object.entries(manifest.files)){
  if(!name.startsWith(spec.sourceRoot)||name.split('/').some(p=>!p||p==='.'||p==='..')||name.includes('\\')
   ||!row||!digest(row.sha256)||!Number.isSafeInteger(row.bytes)||row.bytes<0||row.bytes>1024**2
   ||![0o444,0o555].includes(row.mode))throw fail('BUILD_TARGET_SOURCE_INVALID');
  bytes+=row.bytes;
 }
 if(bytes>16*1024**2||!Object.hasOwn(manifest.files,manifest.dockerfile))throw fail('BUILD_TARGET_SOURCE_INVALID');
 if(!lock||lock.version!==1||lock.baseImageDigest!==spec.base||lock.architecture!=='arm64'
  ||!digest(lock.releaseSha256)||!digest(lock.keyringSha256)||!Array.isArray(lock.packages)
  ||lock.packages.length<3||lock.packages.length>128)throw fail('BUILD_DEPENDENCY_LOCK_INVALID');
 const names=new Set();
 for(const row of lock.packages){
  if(!row||typeof row.name!=='string'||!/^[a-z0-9][a-z0-9+.-]*$/.test(row.name)||names.has(row.name)
   ||typeof row.version!=='string'||!row.version||row.version.length>128||!digest(row.sha256)
   ||!Number.isSafeInteger(row.bytes)||row.bytes<=0||row.bytes>LIMITS.export
   ||!['arm64','all'].includes(row.architecture))throw fail('BUILD_DEPENDENCY_LOCK_INVALID');
  names.add(row.name);
 }
 if(spec.packages.some(name=>!names.has(name)))throw fail('BUILD_DEPENDENCY_LOCK_INVALID');
 return Object.freeze({structurallyValid:true,eligible:false,reason:'DEPENDENCY_LOCK_NOT_APPROVED'});
}
function requireApprovedTarget(target){
 targetSpecification(target);
 // Do not accept caller-supplied hashes, an env flag, or a structurally valid
 // draft as a reviewed source/dependency authority. Activation is separate.
 throw fail('DEPENDENCY_LOCK_NOT_APPROVED');
}
module.exports={TARGETS,LIMITS,targetSpecification,metadataRetentionSpecification,metadataSourcePolicy,validateCandidate,requireApprovedTarget};
