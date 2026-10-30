'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {LIMITS,createMetadataBudget,metadataPrerequisites}=require('./postgres/ownedPolicySystemMetadata');
const retainedSource='Types: deb\n# http://snapshot.debian.org/archive/debian/20260918T000000Z\nURIs: http://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n\nTypes: deb\n# http://snapshot.debian.org/archive/debian-security/20260918T000000Z\nURIs: http://deb.debian.org/debian-security\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n';
const binding=(runId='a'.repeat(32))=>({runId,target:'v24-policy',base:require('./postgres/ownedPolicySystemBuild').TARGETS['v24-policy'].base});
const policy='v23-trixie-freshness-v1',policyNow=Date.parse('Wed, 21 Oct 2026 12:00:00 GMT');
const systemPolicy='v24-system-trixie-freshness-v1';
const rendererPolicy='v24-policy-trixie-freshness-v1';
test('Pricing has a distinct closed metadata envelope and cannot borrow another target receipt',()=>{
 const m=require('./postgres/ownedPolicySystemMetadata');
 // Synthetic DTO construction only, never a retained acquisition conversion.
 const row=retainedEnvelope();row.binding.target='v33-pricing';
 row.candidate.sourcePolicy.policy='v33-pricing-trixie-freshness-v1';
 row.candidate.retainedMetadata.kind='v33-pricing-original-apt-retention';
 row.candidate.retainedMetadata.binding={...row.binding};
 assert.doesNotThrow(()=>m.validateResultEnvelope(JSON.stringify(row),row.binding));
 assert.equal(m.canonicalSources('debian.sources',retainedSource,row.candidate.sourcePolicy.policy),m.canonicalSources('debian.sources',retainedSource,policy));
 for(const other of ['v23-registry','v24-system']){
  assert.throws(()=>m.validateResultEnvelope(JSON.stringify(row),{...row.binding,target:other}));
  const changed=structuredClone(row);changed.candidate.retainedMetadata.kind=require('./postgres/ownedPolicySystemBuild').metadataRetentionSpecification(other).kind;
  assert.throws(()=>m.validateResultEnvelope(JSON.stringify(changed),row.binding));
 }
 const wrongPolicy=structuredClone(row);wrongPolicy.candidate.sourcePolicy.policy=policy;
 assert.throws(()=>m.validateResultEnvelope(JSON.stringify(wrongPolicy),row.binding));
 assert.throws(()=>m.guestMetadataSource(row.binding,{retention:'v23-metadata-retention-v1'}));
 assert.doesNotThrow(()=>m.guestMetadataSource(row.binding,{retention:'v33-pricing-metadata-retention-v1'}));
});
const releaseNames=['deb.debian.org_debian_dists_trixie_InRelease','deb.debian.org_debian_dists_trixie-updates_InRelease','deb.debian.org_debian-security_dists_trixie-security_InRelease'];
function releaseText(name,{date,until}={}){
 const suite=name.includes('trixie-security')?'trixie-security':name.includes('trixie-updates')?'trixie-updates':'trixie';
 date??=suite==='trixie'?'Sat, 12 Sep 2026 12:00:00 UTC':'Tue, 20 Oct 2026 12:00:00 UTC';
 return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nCodename: ${suite}\nDate: ${date}${until?'\nValid-Until: '+until:''}\n-----BEGIN PGP SIGNATURE-----\ncontrolled-not-a-real-signature\n-----END PGP SIGNATURE-----\n`;
}
function v23Evidence(row){
 const {sourcePolicyWitness,canonicalSources,authenticatedReleaseFreshness}=require('./postgres/ownedPolicySystemMetadata');
 const sha=text=>require('node:crypto').createHash('sha256').update(text).digest('hex');
 row.sourceSnapshot.files=[{path:'/etc/apt/sources.list.d/debian.sources',text:retainedSource,bytes:437,sha256:sha(retainedSource)}];
 row.candidate.sources=[{name:'debian.sources',sha256:sha(retainedSource)},{name:'main.list',sha256:sha('')}];
 row.candidate.keyringPath='/usr/share/keyrings/debian-archive-keyring.pgp';
 row.candidate.sourcePolicy=sourcePolicyWitness([['debian.sources',retainedSource],['main.list','']],policy,canonicalSources);
 row.candidate.releaseFreshness=releaseNames.map(name=>authenticatedReleaseFreshness(name,releaseText(name),policyNow));
 row.candidate.indices=[...row.candidate.releaseFreshness.map(({name,sha256})=>({name,sha256,bytes:Buffer.byteLength(releaseText(name))})),row.candidate.indices[1]];
 return row;
}
function envelope(ok=true,runId){const text='deb http://deb.debian.org/debian trixie main\n',sha=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
 const result={version:2,kind:'owned-policy-system-metadata-result',binding:binding(runId),ok,commandFailure:null,
 candidate:ok?candidate():null,errorCode:ok?null:'METADATA_SOURCE_INVALID',sourceSnapshot:{version:1,kind:'owned-image-apt-sources',files:[{
 path:'/etc/apt/sources.list.d/debian.list',text,bytes:Buffer.byteLength(text),sha256:sha(text)}]}};
 if(ok)result.candidate.sources=[{name:'debian.list',sha256:sha(text)},{name:'main.list',sha256:sha('')}];return result;}
function commandFailure(){const stream=text=>{const data=Buffer.from(text);return {base64:data.toString('base64'),bytesObserved:data.length,bytesRetained:data.length,
 retainedSha256:require('node:crypto').createHash('sha256').update(data).digest('hex'),observedSha256:require('node:crypto').createHash('sha256').update(data).digest('hex'),truncated:false};};
 return {version:1,executable:'/usr/bin/apt-get',args:[...require('./postgres/ownedPolicySystemMetadata').metadataAptOptions(12345),'update','--error-on=any'],exitCode:100,signal:null,partial:false,stdout:stream('Get:1 Debian\n'),stderr:stream('E: exact controlled apt failure\n')};}
test('failed command evidence rejects forged shape, byte counts, hashes and false completeness',()=>{
 const {validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 const value=()=>{const row=envelope(false);row.errorCode='METADATA_COMMAND_FAILED';row.commandFailure=commandFailure();return row;};
 assert.deepEqual(validateResultEnvelope(JSON.stringify(value()),binding()).commandFailure,commandFailure());
 const opts=require('./postgres/ownedPolicySystemMetadata').metadataAptOptions(12345);
 for(const [executable,args] of [
  ['/usr/bin/apt-get',[...opts,'--simulate','--no-install-recommends','install','gcc','libc6-dev','bubblewrap']],
  ['/usr/bin/apt-get',[...opts,'--print-uris','--download-only','--yes','--no-install-recommends','install','gcc','libc6-dev','bubblewrap']],
  ['/usr/bin/apt-cache',[...opts,'show','libc6:arm64=2.41-12']],
  ['/usr/lib/apt/apt-helper',['cat-file','/metadata/lists/debian_Packages.lz4']],
  ['/usr/bin/sha256sum',['/metadata/lists/debian_InRelease']]]){
  const row=value();Object.assign(row.commandFailure,{executable,args});assert.doesNotThrow(()=>validateResultEnvelope(JSON.stringify(row),binding()));
 }
 for(const [executable,args] of [['/usr/bin/sha256sum',['/etc/shadow']],['/usr/lib/apt/apt-helper',['cat-file','/metadata/lists/../secret']],['/usr/bin/apt-cache',[...opts,'show','--option']]]){
  const row=value();Object.assign(row.commandFailure,{executable,args});assert.throws(()=>validateResultEnvelope(JSON.stringify(row),binding()));
 }
 for(const mutate of [r=>r.executable='/bin/sh',r=>r.extra=true,r=>r.args=['x\nsecret'],r=>r.args=['x'.repeat(4097)],
  r=>r.stdout.bytesRetained++,r=>r.stderr.retainedSha256='0'.repeat(64),r=>r.stderr.observedSha256='0'.repeat(64),r=>r.stderr.truncated=true,
  r=>r.stdout.base64+='!',r=>r.stderr.bytesObserved--,r=>r.exitCode=0,r=>r.exitCode=null,r=>r.signal='unsafe signal',
  r=>Object.assign(r,{exitCode:0,signal:'SIGKILL'}),r=>Object.assign(r,{exitCode:100,signal:'SIGKILL'}),
  r=>r.stdout.bytesRetained=32769]){const row=value();mutate(row.commandFailure);assert.throws(()=>validateResultEnvelope(JSON.stringify(row),binding()));}
 const relabeled=value();relabeled.errorCode='METADATA_DEADLINE';assert.throws(()=>validateResultEnvelope(JSON.stringify(relabeled),binding()));
 const interrupted=value();interrupted.errorCode='METADATA_DEADLINE';Object.assign(interrupted.commandFailure,{partial:true,exitCode:null,signal:'SIGKILL'});
 assert.doesNotThrow(()=>validateResultEnvelope(JSON.stringify(interrupted),binding()));
 for(const mutate of [a=>a.push('--allow-unauthenticated'),a=>a[9]='Acquire::http::Proxy=http://example.com:80',a=>a[a.length-1]='--allow-insecure-repositories',a=>a[13]='Acquire::Retries=9']){
  const row=value();mutate(row.commandFailure.args);assert.throws(()=>validateResultEnvelope(JSON.stringify(row),binding()));
 }
 const success=envelope();success.commandFailure=commandFailure();assert.throws(()=>validateResultEnvelope(JSON.stringify(success),binding()));
});
test('source envelope binds exact run/base/target and rejects malformed or forged captures',()=>{
 const {validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 assert.equal(validateResultEnvelope(JSON.stringify(envelope(false)),binding()).ok,false);
 for(const mutate of [r=>r.binding.runId='b'.repeat(32),r=>r.binding.target='v24-system',r=>r.binding.base='sha256:'+'1'.repeat(64),
  r=>r.extra=true,r=>r.sourceSnapshot.extra=true,r=>r.sourceSnapshot.files[0].extra=true,
  r=>r.sourceSnapshot.files.push({...r.sourceSnapshot.files[0]}),r=>r.sourceSnapshot.files[0].path='/etc/apt/sources.list.d/../secret.list',
  r=>r.sourceSnapshot.files[0].path='/host/secret',r=>r.sourceSnapshot.files[0].bytes++,r=>r.sourceSnapshot.files[0].sha256='f'.repeat(64),
  r=>r.sourceSnapshot.files[0].text+='tampered',r=>r.sourceSnapshot.files[0].text='x'.repeat(65537),r=>r.candidate=candidate(),
  r=>r.errorCode=null,r=>r.sourceSnapshot.files=[]]){
  const row=envelope(false);mutate(row);assert.throws(()=>validateResultEnvelope(JSON.stringify(row),binding()));
 }
 assert.throws(()=>validateResultEnvelope('{',binding()));
 assert.throws(()=>validateResultEnvelope('x'.repeat(LIMITS.report+1),binding()),{code:'METADATA_REPORT_LIMIT'});
});
function candidate(){return {version:1,candidateOnly:true,qualified:false,requestedPackages:['bubblewrap','gcc','libc6-dev'],
 release:'ID=debian\nVERSION_CODENAME=bookworm\n',keyringPath:'/usr/share/keyrings/debian-archive-keyring.gpg',keyringBytes:20,keyringSha256:'a'.repeat(64),installedStatusSha256:'b'.repeat(64),
 sources:[{name:'debian.sources',sha256:'c'.repeat(64)}],indices:[{name:'debian_InRelease',sha256:'d'.repeat(64),bytes:32},
 {name:'debian_Packages.lz4',sha256:'e'.repeat(64),bytes:48}],selection:"'http://deb.debian.org/debian/pool/main/b/bubblewrap/bubblewrap_1_arm64.deb' file.deb 5 SHA256:"+'f'.repeat(64),
 selected:[{name:'bubblewrap',version:'1',architecture:'arm64',filename:'pool/main/b/bubblewrap/bubblewrap_1_arm64.deb',bytes:5,sha256:'f'.repeat(64)}],
 compressedBytes:80,expandedBytes:100,expandedMeterStage:'after-update-before-offline-resolution',diagnosticBytes:100};}
function retainedEnvelope(){
 const row=v23Evidence(envelope());row.version=3;row.binding.target='v23-registry';
 row.candidate.requestedPackages=[...require('./postgres/ownedPolicySystemBuild').TARGETS['v23-registry'].packages];
 const c=row.candidate;c.selection="'http://deb.debian.org/debian/pool/main/b/bubblewrap/bubblewrap_1_arm64.deb' bubblewrap_1_arm64.deb 5 SHA256:"+'f'.repeat(64);
 const objects=[{kind:'keyring',url:null,sha256:c.keyringSha256,bytes:c.keyringBytes},{kind:'installed-status',url:null,sha256:c.installedStatusSha256,bytes:19}];
 for(const [i,release]of c.releaseFreshness.entries()){
  const prefix=i===2?'http://deb.debian.org/debian-security/dists/':'http://deb.debian.org/debian/dists/';
  objects.push({kind:'upstream',url:prefix+release.codename+'/InRelease',sha256:release.sha256,bytes:Buffer.byteLength(releaseText(release.name))});
  objects.push({kind:'upstream',url:prefix+release.codename+'/main/binary-arm64/Packages.xz',sha256:String(i+1).repeat(64),bytes:30});
 }
 for(const item of objects)item.file='objects/'+item.sha256;
 c.compressedBytes=objects.filter(o=>o.kind==='upstream').reduce((sum,o)=>sum+o.bytes,0);
 c.selectionKind='deduplicated-stage-uri-aggregate';
 c.retainedMetadata={version:1,kind:'v23-original-apt-retention',binding:{...row.binding},capBytes:144*1024**2,
  retainedBytes:objects.reduce((sum,o)=>sum+o.bytes,0),objects,
  stages:[['build',['gcc','libc6-dev','libseccomp-dev']],['runtime',['bubblewrap','libseccomp2']]].map(([name,packages])=>({
   name,packages,selection:c.selection,simulation:'Inst bubblewrap (1 Debian [arm64])\n',selected:structuredClone(c.selected),installedStatusSha256:c.installedStatusSha256}))};
 return row;
}
function systemRetainedEnvelope(){
 // Controlled source/row DTO, not an observation of the original System base
 // and not genuine APT/signature proof. The serialized guest is tested below.
 const row=retainedEnvelope(),spec=require('./postgres/ownedPolicySystemBuild').TARGETS['v24-system'];
 row.binding={...row.binding,target:'v24-system',base:spec.base};
 row.candidate.requestedPackages=[...spec.packages];
 row.candidate.sourcePolicy.policy=systemPolicy;
 Object.assign(row.candidate.retainedMetadata,{kind:'v24-system-original-apt-retention',binding:{...row.binding},
  stages:[{...row.candidate.retainedMetadata.stages[0],name:'system',packages:['gcc','libc6-dev','bubblewrap']}]});
 return row;
}
function rendererRetainedEnvelope(){
 // Synthetic DTO only. Real guest capture is exercised below, independently
 // of original-base signature replay in ownedAptAuthentication tests.
 const row=retainedEnvelope(),contract=require('./postgres/ownedPolicySystemBuild').metadataRetentionSpecification('v24-policy');
 row.binding.target='v24-policy';row.candidate.requestedPackages=['bubblewrap','gcc','libc6-dev'];
 row.candidate.sourcePolicy.policy=rendererPolicy;
 row.candidate.retainedMetadata.kind=contract.kind;row.candidate.retainedMetadata.binding={...row.binding};
 row.candidate.retainedMetadata.stages.forEach((stage,i)=>Object.assign(stage,contract.stages[i]));
 return row;
}
test('renderer retained envelope binds original stages/base and explicit unchanged freshness ceilings',()=>{
 const m=require('./postgres/ownedPolicySystemMetadata'),row=rendererRetainedEnvelope();
 assert.doesNotThrow(()=>m.validateResultEnvelope(JSON.stringify(row),row.binding));
 assert.deepEqual(row.candidate.releaseFreshness.map(r=>r.maximumSeconds),[7776000,604800,604800]);
 assert.equal(m.canonicalSources('debian.sources',retainedSource,rendererPolicy),m.canonicalSources('debian.sources',retainedSource,systemPolicy));
 const source=m.guestMetadataSource(row.binding,{retention:'v24-policy-metadata-retention-v1'});
 assert.match(source,/"sourcePolicy":"v24-policy-trixie-freshness-v1"/);
 assert.match(source,/"retentionStages":\[\{"name":"build","packages":\["gcc","libc6-dev"\]\},\{"name":"runtime","packages":\["bubblewrap"\]\}\]/);
 assert.doesNotMatch(m.guestMetadataSource(row.binding),/"sourcePolicy":"v24-policy-trixie-freshness-v1"/,'legacy non-retained source policy unchanged');
 for(const mutate of [r=>r.binding.base=require('./postgres/ownedPolicySystemBuild').TARGETS['v24-system'].base,
  r=>r.binding.target='v23-registry',r=>r.candidate.sourcePolicy.policy=systemPolicy,
  r=>r.candidate.retainedMetadata.kind='v23-original-apt-retention',r=>r.candidate.retainedMetadata.stages.reverse(),
  r=>r.candidate.retainedMetadata.stages[0].packages.push('libseccomp-dev'),r=>r.candidate.retainedMetadata.stages.pop(),
  r=>r.candidate.releaseFreshness[0].maximumSeconds++,r=>r.candidate.releaseFreshness[1].expiresAt++,
  r=>r.candidate.retainedMetadata.objects[3].url=r.candidate.retainedMetadata.objects[3].url.replace('trixie/','other/'),
  r=>r.candidate.retainedMetadata.objects[2].sha256='0'.repeat(64),r=>r.candidate.installedStatusSha256='0'.repeat(64)]){
  const changed=structuredClone(row);mutate(changed);assert.throws(()=>m.validateResultEnvelope(JSON.stringify(changed),row.binding));
 }
 for(const retention of ['v23-metadata-retention-v1','v24-system-metadata-retention-v1','v33-pricing-metadata-retention-v1'])
  assert.throws(()=>m.guestMetadataSource(row.binding,{retention}));
 const missing=structuredClone(row);missing.candidate.selection=missing.candidate.selection.replace(/ SHA256:[a-f0-9]{64}/g,'');
 for(const stage of missing.candidate.retainedMetadata.stages)stage.selection=missing.candidate.selection;
 assert.doesNotThrow(()=>m.validateResultEnvelope(JSON.stringify(missing),row.binding),'optional legacy display is not SHA256 authority');
});
test('System retained metadata has one original stage and explicitly bound System freshness policy',()=>{
 const {validateResultEnvelope,guestMetadataSource,metadataAptOptions}=require('./postgres/ownedPolicySystemMetadata');
 const value=systemRetainedEnvelope();
 assert.equal(validateResultEnvelope(JSON.stringify(value),value.binding).candidate.qualified,false);
 const generated=guestMetadataSource(value.binding,{retention:'v24-system-metadata-retention-v1'});
 assert.match(generated,/v24-system-original-apt-retention/);
 assert.match(generated,/"retentionStages":\[\{"name":"system","packages":\["gcc","libc6-dev","bubblewrap"\]\}\]/);
 assert.doesNotMatch(generated,/"sourcePolicy":"v23-trixie-freshness-v1"/);
 assert.match(generated,/"sourcePolicy":"v24-system-trixie-freshness-v1"/);
 for(const mutate of [r=>r.binding.base=binding().base,r=>r.binding.target='v23-registry',
  r=>r.candidate.retainedMetadata.kind='v23-original-apt-retention',
  r=>r.candidate.retainedMetadata.stages.push(structuredClone(r.candidate.retainedMetadata.stages[0])),
  r=>r.candidate.retainedMetadata.stages[0].name='build',
  r=>r.candidate.retainedMetadata.stages[0].packages.reverse(),
  r=>r.candidate.retainedMetadata.stages[0].packages.push('libseccomp-dev'),
  r=>r.candidate.retainedMetadata.stages[0].installedStatusSha256='9'.repeat(64),
  r=>r.candidate.retainedMetadata.stages[0].simulation='Inst bubblewrap (2 Debian [arm64])\n',
  r=>r.candidate.indices[0].sha256='1'.repeat(64),r=>r.candidate.indices[0].bytes++,
  r=>r.candidate.retainedMetadata.objects[3].url=r.candidate.retainedMetadata.objects[3].url.replace('trixie/','trixie-other/'),
  r=>r.candidate.retainedMetadata.capBytes++,r=>r.candidate.retainedMetadata.retainedBytes++,
  r=>r.candidate.sourcePolicy={},r=>r.candidate.sourcePolicy.policy=policy,
  r=>delete r.candidate.sourcePolicy,r=>r.candidate.releaseFreshness=[],r=>r.version=2]){
  const bad=structuredClone(value);mutate(bad);assert.throws(()=>validateResultEnvelope(JSON.stringify(bad),value.binding));
 }
 // Rehashing a different original source cannot borrow retained trixie objects.
 for(const text of [retainedSource.replace('trixie trixie-updates','bookworm'),retainedSource.replace('Components: main','Components: contrib'),retainedSource+retainedSource]){
  const bad=structuredClone(value),file=bad.sourceSnapshot.files[0];
  file.text=text;file.bytes=Buffer.byteLength(text);file.sha256=require('node:crypto').createHash('sha256').update(text).digest('hex');
  bad.candidate.sources[0].sha256=file.sha256;
  assert.throws(()=>validateResultEnvelope(JSON.stringify(bad),value.binding));
 }
 for(const mode of ['v23-metadata-retention-v1','unknown','/metadata-retained',true])
  assert.throws(()=>guestMetadataSource(value.binding,{retention:mode}),{code:'METADATA_RETENTION_MODE'});
 assert.throws(()=>guestMetadataSource(value.binding,{retention:'v24-system-metadata-retention-v1',packages:['curl']}));
 const withoutDisplay=structuredClone(value);withoutDisplay.candidate.selection=withoutDisplay.candidate.selection.replace(/ SHA256:[a-f0-9]{64}/,'');
 withoutDisplay.candidate.retainedMetadata.stages[0].selection=withoutDisplay.candidate.selection;
 assert.equal(validateResultEnvelope(JSON.stringify(withoutDisplay),value.binding).ok,true);
 const {validateCandidateReport}=require('./postgres/ownedPolicySystemMetadata');
 assert.throws(()=>validateCandidateReport(withoutDisplay.candidate,'v24-system'),{code:'METADATA_REPORT_INVALID'},'legacy non-retained validation stays unchanged');
 assert.throws(()=>validateCandidateReport(withoutDisplay.candidate,'v24-system',{}),{code:'METADATA_REPORT_INVALID'});
 for(const mutate of [r=>r.candidate.selected[0].sha256='',r=>r.candidate.selected[0].bytes++,r=>r.candidate.selected.push(r.candidate.selected[0])]){
  const bad=structuredClone(withoutDisplay);mutate(bad);assert.throws(()=>validateResultEnvelope(JSON.stringify(bad),value.binding));
 }
 const failed=envelope(false);failed.version=3;failed.binding=value.binding;failed.errorCode='METADATA_COMMAND_FAILED';failed.commandFailure=commandFailure();
 const prefix=[...metadataAptOptions(12345),'--simulate','--no-install-recommends','install'];
 failed.commandFailure.args=[...prefix,'gcc','libc6-dev','bubblewrap'];
 assert.equal(validateResultEnvelope(JSON.stringify(failed),value.binding).ok,false);
 for(const packages of [['gcc','libc6-dev'],['bubblewrap'],['gcc','libc6-dev','libseccomp-dev'],['bubblewrap','gcc','libc6-dev']]){
  failed.commandFailure.args=[...prefix,...packages];assert.throws(()=>validateResultEnvelope(JSON.stringify(failed),value.binding));
 }
});
test('v3 raw metadata retention binds two independent original stage resolutions without claiming signature replay',()=>{
 const {validateResultEnvelope,guestMetadataSource}=require('./postgres/ownedPolicySystemMetadata');
 const value=retainedEnvelope();assert.equal(validateResultEnvelope(JSON.stringify(value),value.binding).version,3);
 for(const mutate of [r=>r.candidate.retainedMetadata.binding.runId='c'.repeat(32),r=>r.candidate.retainedMetadata.objects.pop(),
  r=>r.candidate.retainedMetadata.objects[2].url+='?secret=x',r=>r.candidate.retainedMetadata.objects[2].url='http://evil.invalid/InRelease',
  r=>r.candidate.retainedMetadata.objects[2].sha256='0'.repeat(64),r=>r.candidate.retainedMetadata.objects[2].file='../secret',
  r=>r.candidate.retainedMetadata.objects[3].bytes=32*1024**2+1,r=>r.candidate.retainedMetadata.retainedBytes++,
  r=>r.candidate.retainedMetadata.objects.push({...r.candidate.retainedMetadata.objects[2]}),
  r=>r.candidate.retainedMetadata.stages.reverse(),r=>r.candidate.retainedMetadata.stages[0].packages.push('curl'),
  r=>r.candidate.retainedMetadata.stages[1].installedStatusSha256='c'.repeat(64),
  r=>r.candidate.retainedMetadata.stages[0].simulation='Inst bubblewrap (2 Debian [arm64])\n',
  r=>r.candidate.retainedMetadata.stages[0].simulation+='Inst bubblewrap (1 Debian [arm64])\n',
  r=>r.candidate.retainedMetadata.stages[0].selected[0].sha256='1'.repeat(64),
  r=>r.candidate.selectionKind='actual-single-command',r=>r.version=2]){
  const bad=structuredClone(value);mutate(bad);assert.throws(()=>validateResultEnvelope(JSON.stringify(bad),value.binding));
 }
 assert.throws(()=>guestMetadataSource(binding(),{retention:'v23-metadata-retention-v1'}));
 assert.throws(()=>guestMetadataSource(value.binding,{retention:'/arbitrary/path'}));
});
test('retention writes exact raw upstream bytes to immutable objects and fails closed on partial writes',t=>{
 const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
 const {createMetadataRetention}=require('./postgres/ownedPolicySystemMetadata');
 for(const scenario of ['success','short','zero','diskfull','fsync','pending','object-cap','symlink','owner','mode']){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'metadata-retain-control-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const map=p=>{assert.ok(p==='/metadata-retained'||p.startsWith('/metadata-retained/'));return root+p.slice('/metadata-retained'.length);};
  const fake={...fs,lstatSync(p){const info=fs.lstatSync(map(p));return {isDirectory:()=>info.isDirectory(),isSymbolicLink:()=>scenario==='symlink',uid:scenario==='owner'?1:0,mode:scenario==='mode'?0o755:info.mode};},
   realpathSync:p=>p,readdirSync:p=>fs.readdirSync(map(p)),mkdirSync:(p,o)=>fs.mkdirSync(map(p),o),openSync:(p,...args)=>fs.openSync(map(p),...args),
   renameSync:(a,b)=>fs.renameSync(map(a),map(b)),unlinkSync:p=>fs.unlinkSync(map(p)),chmodSync:(p,mode)=>fs.chmodSync(map(p),mode),
   writeSync(fd,raw,offset,length){if(scenario==='zero')return 0;if(scenario==='diskfull')throw Object.assign(Error('full'),{code:'ENOSPC'});return fs.writeSync(fd,raw,offset,scenario==='short'?Math.min(3,length):length);},
   fsyncSync:fd=>{if(scenario==='fsync')throw Error('sync failed');fs.fsyncSync(fd);}};
  if(['symlink','owner','mode'].includes(scenario)){assert.throws(()=>createMetadataRetention(fake,crypto,binding()));continue;}
  const retain=createMetadataRetention(fake,crypto,binding(),'v24-policy-original-apt-retention');
  try{
   const raw=Buffer.from([0,255,10,13,1]),url='http://deb.debian.org/debian/dists/trixie/main/binary-arm64/Packages.xz';
   const item=retain.begin('upstream',url,scenario==='object-cap'?4:32*1024**2);
   if(['zero','diskfull','object-cap'].includes(scenario)){assert.throws(()=>item.write(raw));assert.throws(()=>retain.manifest([]));continue;}
   item.write(raw);
   if(scenario==='pending'){assert.throws(()=>retain.manifest([]));continue;}
   if(scenario==='fsync'){assert.throws(()=>item.finish());assert.throws(()=>retain.manifest([]));continue;}
   const record=item.finish();assert.equal(record.sha256,crypto.createHash('sha256').update(raw).digest('hex'));
   assert.deepEqual(fs.readFileSync(root+'/'+record.file),raw);assert.equal(fs.statSync(root+'/'+record.file).mode&0o777,0o444);
   assert.throws(()=>retain.begin('upstream',url,1));assert.throws(()=>retain.begin('upstream','http://evil.invalid/dists/x',1));
   const manifest=retain.manifest([]);assert.equal(manifest.retainedBytes,raw.length);
   retain.writeReport('{"controlled":true}',manifest);assert.equal(fs.statSync(root+'/result.json').mode&0o777,0o444);
   assert.throws(()=>retain.writeReport('{}',manifest));
  }finally{retain.close();}
 }
});
test('V23 metadata packages and failure commands bind exact target without relabeling V24',()=>{
 const {validateResultEnvelope,validateCandidateReport,metadataAptOptions,guestMetadataSource}=require('./postgres/ownedPolicySystemMetadata');
 const spec=require('./postgres/ownedPolicySystemBuild').TARGETS['v23-registry'];
 const v23={...binding(),target:'v23-registry',base:spec.base};
 const result=()=>{const row=envelope();row.binding={...v23};row.candidate.requestedPackages=[...spec.packages];return v23Evidence(row);};
 assert.equal(validateResultEnvelope(JSON.stringify(result()),v23).candidate.qualified,false);
 for(const mutate of [row=>row.candidate.requestedPackages.pop(),
  row=>row.candidate.requestedPackages.splice(row.candidate.requestedPackages.indexOf('libseccomp-dev'),1),
  row=>row.candidate.requestedPackages.push('curl'),row=>row.candidate.requestedPackages.reverse(),
  row=>row.binding.target='v24-policy']){
  const row=result();mutate(row);assert.throws(()=>validateResultEnvelope(JSON.stringify(row),v23));
 }
 assert.throws(()=>validateCandidateReport(candidate(),'v23-registry'),{code:'METADATA_REPORT_INVALID'});
 assert.throws(()=>validateCandidateReport(result().candidate),{code:'METADATA_REPORT_INVALID'});
 for(const prefix of [['--print-uris','--download-only','--yes','--no-install-recommends','install'],
  ['--simulate','--no-install-recommends','install']]){
  const failed=()=>{const row=envelope(false);row.binding={...v23};row.errorCode='METADATA_COMMAND_FAILED';row.commandFailure=commandFailure();
   row.commandFailure.args=[...metadataAptOptions(12345),...prefix,...spec.installPackages];return row;};
  assert.equal(validateResultEnvelope(JSON.stringify(failed()),v23).ok,false);
  for(const mutate of [args=>args.pop(),args=>args.push('curl'),args=>args.reverse(),
   args=>args.splice(args.indexOf('libseccomp-dev'),1)]){
   const row=failed();mutate(row.commandFailure.args);assert.throws(()=>validateResultEnvelope(JSON.stringify(row),v23));
  }
  const mislabeled=failed();mislabeled.binding=binding();
  assert.throws(()=>validateResultEnvelope(JSON.stringify(mislabeled),binding()));
 }
 for(const extra of [{packages:['curl']},{installPackages:['curl']},{target:'v23-invocation'}])
  assert.throws(()=>guestMetadataSource({...v23,...extra}));
});
test('V23 per-suite policy splits retained mixed suites and binds exact source reconstruction',()=>{
 const {canonicalSources,sourcePolicyWitness,validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 const normalized=canonicalSources('debian.sources',retainedSource,policy);
 const blocks=normalized.trim().split('\n\n');assert.equal(blocks.length,3);
 assert.match(blocks[0],/Suites: trixie\n/);assert.match(blocks[0],/Valid-Until-Max: 7776000$/);
 for(const block of blocks.slice(1))assert.match(block,/Valid-Until-Max: 604800$/);
 assert.doesNotMatch(normalized,/Min|Check-Date|Check-Valid-Until|Trusted/);
 assert.doesNotMatch(canonicalSources('debian.sources',retainedSource),/Valid-Until-Max/,'historical V24 unchanged');
 for(const value of [retainedSource.replace('trixie trixie-updates','stable'),retainedSource.replace('trixie trixie-updates','bookworm'),
  retainedSource.replace('trixie trixie-updates','trixie trixie'),retainedSource.replace('trixie-security','trixie'),
  retainedSource.replace('http://deb.debian.org/debian\n','http://deb.debian.org/debian http://security.debian.org/debian\n'),
  retainedSource.replace('Components: main','Components: main contrib'),retainedSource+'\nValid-Until-Max: 99999999',
  retainedSource+'\nCheck-Date: no',retainedSource+'\nValid-Until-Min: 99999999'])
  assert.throws(()=>canonicalSources('debian.sources',value,policy));
 assert.throws(()=>canonicalSources('debian.sources',retainedSource,'caller-policy'));
 assert.throws(()=>sourcePolicyWitness([['main.list','deb http://deb.debian.org/debian trixie main']],policy,canonicalSources));
 assert.throws(()=>sourcePolicyWitness([['debian.sources',retainedSource],['debian.sources','']],policy,canonicalSources));
 const row=v23Evidence(envelope());row.binding.target='v23-registry';row.candidate.requestedPackages=[...require('./postgres/ownedPolicySystemBuild').TARGETS['v23-registry'].packages];
 assert.doesNotThrow(()=>validateResultEnvelope(JSON.stringify(row),row.binding));
 for(const mutate of [r=>r.candidate.sourcePolicy.files[0].sha256='f'.repeat(64),r=>r.candidate.sourcePolicy.policy='other',
  r=>r.candidate.releaseFreshness[0].expiresAt++,r=>r.candidate.releaseFreshness[0].maximumSeconds++,
  r=>r.candidate.releaseFreshness[0].sha256='f'.repeat(64),r=>r.candidate.releaseFreshness.pop(),
  r=>r.candidate.releaseFreshness[1]=r.candidate.releaseFreshness[0],
  r=>r.candidate.indices.push({name:'foreign_InRelease',sha256:'e'.repeat(64),bytes:12})]){
  const changed=structuredClone(row);mutate(changed);assert.throws(()=>validateResultEnvelope(JSON.stringify(changed),row.binding));
 }
});
test('actual pure time-policy check rejects expired, future and ambiguous Release fields (not signed-APT proof)',()=>{
 const {authenticatedReleaseFreshness:check}=require('./postgres/ownedPolicySystemMetadata');
 const stable=releaseNames[0],day=86400000;
 assert.equal(check(stable,releaseText(stable),policyNow).maximumSeconds,90*86400);
 const issued=Date.parse('Sat, 12 Sep 2026 12:00:00 GMT');
 assert.doesNotThrow(()=>check(stable,releaseText(stable),issued+90*day));
 assert.throws(()=>check(stable,releaseText(stable),issued+90*day+1));
 assert.throws(()=>check(stable,releaseText(stable,{until:'Tue, 20 Oct 2026 12:00:00 UTC'}),policyNow));
 for(const name of releaseNames.slice(1)){
  assert.throws(()=>check(name,releaseText(name,{date:'Mon, 12 Oct 2026 12:00:00 UTC'}),policyNow));
  assert.throws(()=>check(name,releaseText(name,{until:'Wed, 21 Oct 2026 11:59:59 UTC'}),policyNow));
 }
 assert.throws(()=>check(stable,releaseText(stable,{date:'Wed, 21 Oct 2026 12:00:11 UTC'}),policyNow));
 for(const text of [releaseText(stable).replace('Date: ','Date: Sat, 12 Sep 2026 12:00:00 UTC\nDate: '),
  releaseText(stable).replace('Codename: trixie','Codename: trixie\nCodename: trixie'),
  releaseText(stable).replace('Codename: trixie','Codename: stable'),
  releaseText(stable).replace('Date: ','Valid-Until: Tue, 20 Oct 2026 12:00:00 UTC\nValid-Until: Thu, 22 Oct 2026 12:00:00 UTC\nDate: '),
  releaseText(stable).replace('Date: Sat, 12 Sep','Date: Sun, 12 Sep'),
  releaseText(stable).replace('Date: ','date: '),releaseText(stable).replace('Date: ','Date : '),
  releaseText(stable).replaceAll('\n','\r\n'),
  releaseText(stable).replace('Date: Sat, 12 Sep 2026 12:00:00 UTC','Date: Tue, 31 Feb 2026 12:00:00 UTC'),
  releaseText(stable).replace('\n-----BEGIN PGP SIGNATURE-----','\n folded-date\n-----BEGIN PGP SIGNATURE-----')])assert.throws(()=>check(stable,text,policyNow));
 assert.throws(()=>check('../'+stable,releaseText(stable),policyNow));
});
test('System local policy has closed source authority and actual time-arithmetic expiry negatives, not signature proof',()=>{
 const {canonicalSources,sourcePolicyWitness,authenticatedReleaseFreshness:check,validateResultEnvelope,metadataAptOptions}=require('./postgres/ownedPolicySystemMetadata');
 const normalized=canonicalSources('debian.sources',retainedSource,systemPolicy),blocks=normalized.trim().split('\n\n');
 assert.equal(blocks.length,3);
 assert.match(blocks[0],/Suites: trixie\n[\s\S]*Valid-Until-Max: 7776000$/);
 for(const block of blocks.slice(1))assert.match(block,/Valid-Until-Max: 604800$/);
 assert.doesNotMatch(normalized,/Min|Check-Date|Check-Valid-Until|Trusted/);
 assert.equal(normalized,canonicalSources('debian.sources',retainedSource,policy),'V23 output is unchanged, authority label is distinct');
 const witness=sourcePolicyWitness([['debian.sources',retainedSource],['main.list','']],systemPolicy,canonicalSources);
 assert.equal(witness.policy,systemPolicy);
 const options=metadataAptOptions(12345);
 for(const option of ['Acquire::Max-ValidTime=604800','Acquire::Check-Valid-Until=true','Acquire::Check-Date=true',
  'Acquire::Max-FutureTime=10','Acquire::AllowInsecureRepositories=false','Acquire::AllowDowngradeToInsecureRepositories=false','Acquire::Retries=0'])assert(options.includes(option));
 assert(!options.some(option=>/Min-ValidTime|7776000|Check-Date=false|Check-Valid-Until=false/.test(option)));
 for(const text of [retainedSource.replace('trixie trixie-updates','stable'),retainedSource.replace('trixie trixie-updates','bookworm'),
  retainedSource.replace('trixie trixie-updates','trixie trixie'),retainedSource.replace('Components: main','Components: main contrib'),
  retainedSource.replace('/debian\n','/debian-security\n'),retainedSource.replace('Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp','Signed-By: /tmp/keyring'),
  retainedSource+'\nTrusted: yes',retainedSource+'\nValid-Until-Min: 7776000',retainedSource+'\nCheck-Valid-Until: no'])
  assert.throws(()=>canonicalSources('debian.sources',text,systemPolicy));
 const day=86400000,issued=Date.parse('Sat, 12 Sep 2026 12:00:00 GMT'),stable=releaseNames[0];
 assert.equal(check(stable,releaseText(stable),issued+40*day).expiresAt,issued+90*day);
 assert.throws(()=>check(stable,releaseText(stable),issued+90*day+1));
 assert.throws(()=>check(stable,releaseText(stable,{until:'Tue, 20 Oct 2026 12:00:00 UTC'}),policyNow));
 assert.throws(()=>check(stable,releaseText(stable,{date:'Wed, 21 Oct 2026 12:00:11 UTC'}),policyNow));
 for(const name of releaseNames.slice(1)){
  const result=check(name,releaseText(name),policyNow);assert.equal(result.maximumSeconds,7*86400);
  assert.throws(()=>check(name,releaseText(name),Date.parse(result.date)+7*day+1));
  assert.throws(()=>check(name,releaseText(name,{until:'Wed, 21 Oct 2026 11:59:59 UTC'}),policyNow));
 }
 const system=systemRetainedEnvelope(),v23=retainedEnvelope();
 for(const [row,otherPolicy]of [[system,policy],[v23,systemPolicy]]){
  row.candidate.sourcePolicy.policy=otherPolicy;
  assert.throws(()=>validateResultEnvelope(JSON.stringify(row),row.binding));
 }
 // The historical failed envelope remains parseable as failure, with no
 // retroactive success/policy fields or invented Release-header evidence.
 const failed=envelope(false);failed.version=3;failed.binding=system.binding;
 failed.errorCode='METADATA_COMMAND_FAILED';failed.commandFailure=commandFailure();
 const validated=validateResultEnvelope(JSON.stringify(failed),failed.binding);
 assert.equal(validated.ok,false);assert.equal(validated.candidate,null);
});
test('candidate validation rejects empty or disconnected package/index evidence',()=>{
 const {validateCandidateReport}=require('./postgres/ownedPolicySystemMetadata');
 assert.equal(validateCandidateReport(candidate()).qualified,false);
 assert.throws(()=>validateCandidateReport({version:1,candidateOnly:true,qualified:false}));
 for(const mutate of [r=>r.selected=[],r=>r.indices=[],r=>r.selection='unrelated',r=>r.compressedBytes=0,
  r=>r.expandedBytes=LIMITS.expandedTotal+1,r=>r.keyringSha256='unknown',r=>r.requestedPackages=['gcc'],
  r=>r.selected[0].filename='pool/../escape.deb',r=>r.selected.push({...r.selected[0]})]){
  const value=candidate();mutate(value);assert.throws(()=>validateCandidateReport(value),{code:'METADATA_REPORT_INVALID'});
 }
});
test('retained APT security URI without legacy MD5 display still requires exact package SHA256 and joins',()=>{
 const {validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 const filename='pool/updates/main/l/linux/linux-libc-dev_6.12.113-1_all.deb';
 const sha256='b2d475e01aaf0030c72bd3a0300d311f8be64aa9e82d82eae5da1a04f4010071';
 // Exact public package/URI shape observed in retained70bd8631 output.
 // This controlled row is not a new signed-APT or downloaded-package proof.
 const value=()=>{
  const row=v23Evidence(envelope());row.binding.target='v23-registry';
  row.candidate.requestedPackages=[...require('./postgres/ownedPolicySystemBuild').TARGETS['v23-registry'].packages];
  row.candidate.selected=[{name:'linux-libc-dev',version:'6.12.113-1',architecture:'all',filename,bytes:3021244,sha256}];
  row.candidate.selection="'http://deb.debian.org/debian-security/"+filename+"' linux-libc-dev_6.12.113-1_all.deb 3021244 \n";
  return row;
 };
 const check=row=>validateResultEnvelope(JSON.stringify(row),row.binding);
 assert.equal(check(value()).candidate.qualified,false);
 const displayed=value();displayed.candidate.selection=displayed.candidate.selection.trimEnd()+' SHA256:'+sha256+'\n';assert.doesNotThrow(()=>check(displayed));
 const md5=value();md5.candidate.selection=md5.candidate.selection.trimEnd()+' MD5Sum:'+'a'.repeat(32)+'\n';assert.doesNotThrow(()=>check(md5));
 for(const mutate of [r=>r.candidate.selected[0].sha256='',r=>delete r.candidate.selected[0].sha256,
  r=>r.candidate.selected[0].sha256='f'.repeat(63),r=>r.candidate.selected[0].sha256=null,
  r=>r.candidate.selection=r.candidate.selection.trimEnd()+' SHA256:'+'e'.repeat(64)+'\n',
  r=>r.candidate.selection=r.candidate.selection.trimEnd()+' MD5Sum:'+'a'.repeat(31)+'\n',
  r=>r.candidate.selection=r.candidate.selection.trimEnd()+' SHA1:'+'a'.repeat(40)+'\n',
  r=>r.candidate.selection=r.candidate.selection.trimEnd()+' unknown\n',
  r=>r.candidate.selection+=r.candidate.selection,r=>r.candidate.selected.push({...r.candidate.selected[0]}),
  r=>r.candidate.selected[0].bytes++,r=>r.candidate.selection=r.candidate.selection.replace('3021244','3021245'),
  r=>r.candidate.selection=r.candidate.selection.replace('deb.debian.org','foreign.invalid'),
  r=>r.candidate.selection=r.candidate.selection.replace('linux-libc-dev_6.12.113','linux-libc-dev_6.12.114'),
  r=>r.candidate.selection=r.candidate.selection.replace("' linux-libc", "?token=forbidden' linux-libc")]){
  const row=value();mutate(row);assert.throws(()=>check(row));
 }
 const legacy=envelope();legacy.candidate.selection=legacy.candidate.selection.replace(/ SHA256:[a-f0-9]+$/,'');
 assert.throws(()=>check(legacy),'historical V24 missing-display policy unchanged');
});
test('closed apt source grammar rejects source-local trust/expiry and alternate methods',()=>{
 const {canonicalSources,guestMetadataSource}=require('./postgres/ownedPolicySystemMetadata');
 const basic='deb http://deb.debian.org/debian bookworm main';
 assert.match(canonicalSources('main.list',basic),/signed-by=\/usr\/share\/keyrings\/debian-archive-keyring.gpg/);
 for(const value of [basic.replace('http://deb.debian.org/debian','file:/tmp/index'),
  basic.replace('http://deb.debian.org/debian','mirror+file:/tmp/list'),
  basic.replace('deb ','deb [check-valid-until=no] '),basic.replace('deb ','deb [trusted=yes] '),
  basic.replace('deb ','deb [allow-insecure=yes] '),basic.replace('deb.debian.org','example.com'),
  basic.replace('deb ','deb [signed-by=/tmp/untrusted] ')])assert.throws(()=>canonicalSources('main.list',value));
 const deb822='Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg';
 assert.match(canonicalSources('debian.sources',deb822),/URIs: http:\/\/deb.debian.org/);
 for(const suffix of ['\nCheck-Valid-Until: no','\nTrusted: yes','\nURIs: file:/tmp/index'])
  assert.throws(()=>canonicalSources('debian.sources',deb822+suffix));
 new (require('node:vm').Script)(guestMetadataSource(binding()));
});
test('exact retained trixie source preserves its declared pgp keyring without alias assumptions',()=>{
 const {canonicalSources,validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 assert.equal(Buffer.byteLength(retainedSource),437);
 assert.equal(require('node:crypto').createHash('sha256').update(retainedSource).digest('hex'),'f02a6fd0c0a28e5f47d4512c0e5d264138378272850fe41dcb370ec885a3fcba');
 const result=canonicalSources('debian.sources',retainedSource);assert.match(result,/Signed-By: \/usr\/share\/keyrings\/debian-archive-keyring.pgp/);
 assert.doesNotMatch(result,/keyring.gpg/);
 for(const replacement of ['/tmp/foreign.pgp','/usr/share/keyrings/debian-archive-keyring.pgp/../foreign','/usr/share/keyrings/foreign.pgp'])
  assert.throws(()=>canonicalSources('debian.sources',retainedSource.replaceAll('/usr/share/keyrings/debian-archive-keyring.pgp',replacement)));
 const forged=envelope();forged.candidate.keyringPath='/usr/share/keyrings/debian-archive-keyring.pgp';
 assert.throws(()=>validateResultEnvelope(JSON.stringify(forged),binding()),{code:'METADATA_ENVELOPE_INVALID'});
});
test('admitted CONNECT transport rejects alternate authority and joins failed tunnel/TLS without direct fallback',async()=>{
 const {EventEmitter}=require('node:events'),vm=require('node:vm');
 const source=require('./postgres/ownedPolicySystemMetadata').admittedMetadataGet.toString();
 async function exercise(kind){
  const seen=[],closed=[];let request;
  const http={request(options,callback){
   seen.push(options);const client=new EventEmitter();client.destroy=()=>queueMicrotask(()=>{closed.push('request');client.emit('close');});
   client.end=()=>queueMicrotask(()=>{
    if(options.method==='CONNECT'){
     const socket=new EventEmitter();socket.destroy=()=>queueMicrotask(()=>{closed.push('tunnel');socket.emit('close');});
     if(kind==='bad-status')client.emit('connect',{statusCode:407},socket,Buffer.alloc(0));
     else client.emit('connect',{statusCode:200},socket,Buffer.alloc(0));
     client.emit('close');
    }else{
     const response=new EventEmitter();response.statusCode=200;response.destroy=()=>queueMicrotask(()=>{closed.push('response');response.emit('close');});
     callback(response);if(kind==='abort')return;
     response.emit('data',Buffer.from('signed index'));response.emit('end');response.emit('close');client.emit('close');
    }
   });return client;
  }};
  const tls={connect(options){
   assert.equal(options.servername,'deb.debian.org');assert.equal(options.rejectUnauthorized,true);
   assert.deepEqual(Array.from(options.ALPNProtocols),['http/1.1']);
   const socket=new EventEmitter();socket.authorized=kind!=='bad-cert';socket.alpnProtocol='http/1.1';
   socket.destroy=()=>queueMicrotask(()=>{closed.push('tls');socket.emit('close');});
   queueMicrotask(()=>socket.emit('secureConnect'));return socket;
  }};
  const invoke=vm.runInNewContext('('+source+')',{require:name=>({'node:http':http,'node:tls':tls,'node:events':{EventEmitter}}[name]),
   URL,Buffer,setTimeout,clearTimeout,queueMicrotask});
  const authority={host:'127.0.0.1',port:23456};
  assert.throws(()=>invoke(new URL('http://security.debian.org/debian-security/dists/bookworm/InRelease'),authority,null,()=>{}),/METADATA_DESTINATION/);
  assert.throws(()=>invoke(new URL('http://deb.debian.org/debian/dists/bookworm/InRelease'),{host:'localhost',port:23456},null,()=>{}),/METADATA_UPSTREAM_AUTHORITY/);
  assert.throws(()=>invoke(new URL('http://deb.debian.org/debian/dists/bookworm/InRelease'),{host:'127.0.0.1',port:0},null,()=>{}),/METADATA_UPSTREAM_AUTHORITY/);
  assert.equal(seen.length,0,'rejected destinations must never open a socket');
  const controller=new AbortController(),failures=[];
  request=invoke(new URL('http://deb.debian.org/debian/dists/bookworm/InRelease'),authority,controller.signal,()=>{});
  request.on('error',error=>failures.push(error.message));
  if(kind==='abort')await new Promise(resolve=>setImmediate(resolve));
  if(kind==='abort')controller.abort();
  await request.closed;
  assert.equal(seen[0].method,'CONNECT');assert.equal(seen[0].host,'127.0.0.1');
  assert.equal(seen[0].port,23456);assert.equal(seen[0].path,'deb.debian.org:443');
  assert.equal(seen.filter(item=>item.method==='GET').length,kind==='bad-status'||kind==='bad-cert'?0:1);
  assert.equal(failures.length,kind==='bad-status'||kind==='bad-cert'||kind==='abort'?1:0);
  assert.ok(closed.includes('tunnel'));
  return failures;
 }
 assert.deepEqual(await exercise('bad-status'),['METADATA_CONNECT_STATUS']);
 assert.deepEqual(await exercise('bad-cert'),['METADATA_TLS_AUTHORITY']);
 assert.deepEqual(await exercise('abort'),['METADATA_ABORTED']);
});
test('real Node HTTP client writes final GET only to the admitted TLS tunnel',async()=>{
 const vm=require('node:vm'),realHttp=require('node:http'),net=require('node:net');
 const {EventEmitter}=require('node:events'),{Duplex}=require('node:stream');
 const source=require('./postgres/ownedPolicySystemMetadata').admittedMetadataGet.toString();
 let wire='',responseBytes='',connectCalls=0,directAttempts=0;
 const secure=new Duplex({allowHalfOpen:false,read(){},write(chunk,_encoding,callback){
  wire+=chunk.toString();callback();
  if(wire.includes('\r\n\r\n'))queueMicrotask(()=>{secure.push('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');secure.push(null);});
 }});
 secure.authorized=true;secure.alpnProtocol='http/1.1';secure.setNoDelay=()=>secure;secure.setKeepAlive=()=>secure;
 const tunnel=new EventEmitter();tunnel.destroy=()=>queueMicrotask(()=>tunnel.emit('close'));
 secure.once('close',()=>tunnel.destroy());
 const http={request(options,callback){
  if(options.method==='CONNECT'){
   connectCalls++;const request=new EventEmitter();request.destroy=()=>queueMicrotask(()=>request.emit('close'));
   request.end=()=>queueMicrotask(()=>{request.emit('connect',{statusCode:200},tunnel,Buffer.alloc(0));request.emit('close');});return request;
  }
  return realHttp.request(options,callback);
 }};
 const tls={connect(options){assert.equal(options.socket,tunnel);assert.equal(options.servername,'deb.debian.org');
  assert.equal(options.rejectUnauthorized,true);queueMicrotask(()=>secure.emit('secureConnect'));return secure;}};
 const invoke=vm.runInNewContext('('+source+')',{require:name=>({'node:http':http,'node:tls':tls,'node:events':{EventEmitter}}[name]),
  URL,Buffer,setTimeout,clearTimeout,queueMicrotask});
 const originalConnect=net.Socket.prototype.connect;
 net.Socket.prototype.connect=function(){directAttempts++;throw Error('DIRECT_CONNECTION_ATTEMPT');};
 try{
  const request=invoke(new URL('http://deb.debian.org/debian/dists/bookworm/InRelease'),{host:'127.0.0.1',port:23456},null,
   incoming=>{incoming.on('data',chunk=>{responseBytes+=chunk.toString();});});
  request.on('error',error=>assert.fail(error.message));
  await request.closed;
  assert.equal(connectCalls,1);assert.equal(directAttempts,0);
  assert.match(wire,/^GET \/debian\/dists\/bookworm\/InRelease HTTP\/1\.1\r\n/);
  assert.match(wire,/Host: deb\.debian\.org\r\n/i);assert.equal(responseBytes,'OK');
 }finally{net.Socket.prototype.connect=originalConnect;secure.destroy();}
});
test('serialized guest runs the fixed apt flow and cancels a stalled child without network',async t=>{
 const {EventEmitter}=require('node:events'),vm=require('node:vm'),crypto=require('node:crypto');
 const {guestMetadataSource,validateResultEnvelope}=require('./postgres/ownedPolicySystemMetadata');
 for(const scenario of ['renderer-retention','renderer-retention-status-changed','renderer-retention-apt-failed','renderer-retention-expired',
  'renderer-retention-signed-expired','renderer-retention-updates-expired','renderer-retention-security-expired',
  'pricing-retention','success','v23-success','v23-retention','v23-retention-status-changed','system-retention','system-retention-status-changed','system-retention-apt-failed',
  'system-retention-expired','system-retention-signed-expired','system-retention-updates-expired','system-retention-security-expired',
  'system-retention-future','system-retention-duplicate-date','system-retention-release-symlink',
  'v23-expired','v23-signed-expired','v23-release-symlink','retained-pgp','apt-failed','apt-truncated','keyring-symlink','stalled','parse-failure','symlink','dangling-main','invalid-proxy']){
  const pricing=scenario==='pricing-retention';
  const renderer=scenario.startsWith('renderer-');
  const v23=scenario.startsWith('v23-')||pricing;
  const system=scenario.startsWith('system-');
  const retained=scenario.startsWith('v23-retention')||system||pricing||renderer;
  const currentBinding={...binding(),target:pricing?'v33-pricing':v23?'v23-registry':system?'v24-system':'v24-policy'};
  const currentSpec=require('./postgres/ownedPolicySystemBuild').TARGETS[currentBinding.target];
  currentBinding.base=currentSpec.base;
  const stalled=scenario==='stalled';
  const commands=[],writes=[],killed=[];let output='',deadline,proxyHandler;
  const source=scenario==='retained-pgp'||v23||system||renderer?retainedSource:'Types: '+(scenario==='parse-failure'?'deb deb-src':'deb')+'\nURIs: https://deb.debian.org/debian\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg';
  const releases=Object.fromEntries(releaseNames.map(name=>{
   let options={};
   if(name===releaseNames[0]){
    if(['v23-expired','system-retention-expired','renderer-retention-expired'].includes(scenario))options={date:'Wed, 01 Jul 2026 12:00:00 UTC'};
    if(['v23-signed-expired','system-retention-signed-expired','renderer-retention-signed-expired'].includes(scenario))options={until:'Tue, 20 Oct 2026 12:00:00 UTC'};
    if(scenario==='system-retention-future')options={date:'Wed, 21 Oct 2026 12:00:11 UTC'};
   }
   if(name===releaseNames[1]&&['system-retention-updates-expired','renderer-retention-updates-expired'].includes(scenario)||name===releaseNames[2]&&['system-retention-security-expired','renderer-retention-security-expired'].includes(scenario))
    options={date:'Mon, 12 Oct 2026 12:00:00 UTC'};
   let text=releaseText(name,options);
   if(name===releaseNames[0]&&scenario==='system-retention-duplicate-date')text=text.replace('Date: ','Date: Sat, 12 Sep 2026 12:00:00 UTC\nDate: ');
   return ['/metadata/lists/'+name,text];
  }));
  const fakeFs={readFileSync(file,encoding){
   const values={'/etc/os-release':'ID=debian\n','/usr/share/keyrings/debian-archive-keyring.gpg':'controlled keyring',
    '/usr/share/keyrings/debian-archive-keyring.pgp':'different controlled pgp keyring',
    '/etc/apt/sources.list.d/debian.sources':source,'/var/lib/dpkg/status':'controlled installed status',...releases};
   if(scenario.endsWith('retention-status-changed')&&file==='/var/lib/dpkg/status'&&commands.some(row=>row.args.includes('--simulate')))values[file]+=' changed';
   assert.ok(Object.hasOwn(values,file),file);return encoding?values[file]:Buffer.from(values[file]);
  },existsSync:()=>false,mkdirSync(){},writeFileSync:(...args)=>writes.push(args),statSync:file=>({isFile:()=>true,size:releases[file]?Buffer.byteLength(releases[file]):10}),
  lstatSync:file=>{
   if(file==='/var/lib/dpkg/status')return {isFile:()=>true,isSymbolicLink:()=>false,size:27};
   if(Object.hasOwn(releases,file))return {isFile:()=>true,isSymbolicLink:()=>scenario.endsWith('release-symlink'),size:Buffer.byteLength(releases[file])};
   if(file==='/etc/apt/sources.list'&&scenario!=='dangling-main')throw Object.assign(Error('absent'),{code:'ENOENT'});
   if(/debian-archive-keyring\.(gpg|pgp)$/.test(file))return {isFile:()=>true,isDirectory:()=>false,isSymbolicLink:()=>scenario==='keyring-symlink',
    size:Buffer.byteLength(file.endsWith('.pgp')?'different controlled pgp keyring':'controlled keyring')};
   return {isFile:()=>file.endsWith('.sources'),isDirectory:()=>!file.endsWith('.sources'),
    isSymbolicLink:()=>scenario==='symlink'&&file.endsWith('.sources')||scenario==='dangling-main'&&file==='/etc/apt/sources.list',size:Buffer.byteLength(source)};
  },realpathSync:file=>file,
  readdirSync:dir=>dir==='/etc/apt/sources.list.d'?['debian.sources']:v23||system||renderer?[...releaseNames,'debian_Packages.lz4']:['debian_InRelease','debian_Packages.lz4']};
  let retainedRoot;
  if(retained){
   const realFs=require('node:fs'),path=require('node:path');retainedRoot=realFs.mkdtempSync(path.join(require('node:os').tmpdir(),'serialized-metadata-'));
   realFs.chmodSync(retainedRoot,0o700);t.after(()=>realFs.rmSync(retainedRoot,{recursive:true,force:true}));
   const mapped=file=>retainedRoot+file.slice('/metadata-retained'.length);
   for(const method of ['lstatSync','readdirSync','mkdirSync','openSync','chmodSync','unlinkSync']){
    const previous=fakeFs[method];fakeFs[method]=(file,...args)=>{
     if(!file.startsWith('/metadata-retained'))return previous?.(file,...args);
     const result=realFs[method](mapped(file),...args);
     if(method==='lstatSync')Object.defineProperty(result,'uid',{value:0});return result;
    };
   }
   fakeFs.renameSync=(a,b)=>realFs.renameSync(mapped(a),mapped(b));
   for(const method of ['writeSync','closeSync','fsyncSync'])fakeFs[method]=realFs[method].bind(realFs);
  }
  const proxy=new EventEmitter();proxy.listen=(_port,_host,callback)=>callback();proxy.address=()=>({port:12345});proxy.close=()=>{};
  const response=new EventEmitter();response.writeHead=()=>{};response.write=()=>true;response.end=()=>{};response.destroy=()=>{};
  const proxyRequests=[];
  const http={createServer:handler=>{proxyHandler=handler;return proxy;},request(options,callback){
   proxyRequests.push(options);const req=new EventEmitter();req.destroy=()=>queueMicrotask(()=>req.emit('close'));
   req.end=()=>queueMicrotask(()=>{
    if(options.method==='CONNECT'){
     const socket=new EventEmitter();socket.destroy=()=>queueMicrotask(()=>socket.emit('close'));
     req.emit('connect',{statusCode:200},socket,Buffer.alloc(0));req.emit('close');
    }else{
     assert.equal(options.host,'deb.debian.org');assert.match(options.path,/^\/(?:debian|debian-security)\/dists\//);
     const incoming=new EventEmitter();incoming.statusCode=200;incoming.pause=()=>{};incoming.resume=()=>{};
     incoming.destroy=()=>queueMicrotask(()=>incoming.emit('close'));
     const releaseName=releaseNames.find(name=>options.path.endsWith('/'+(name.includes('trixie-security')?'trixie-security':name.includes('trixie-updates')?'trixie-updates':'trixie')+'/InRelease'));
     callback(incoming);incoming.emit('data',Buffer.from(retained&&releaseName?releases['/metadata/lists/'+releaseName]:'controlled signed-index bytes'));
     incoming.emit('end');incoming.emit('close');req.emit('close');
    }
   });return req;
  }};
  const tls={connect(options){assert.equal(options.servername,'deb.debian.org');assert.equal(options.rejectUnauthorized,true);
   const socket=new EventEmitter();socket.authorized=true;socket.alpnProtocol='http/1.1';
   socket.destroy=()=>queueMicrotask(()=>socket.emit('close'));
   queueMicrotask(()=>socket.emit('secureConnect'));return socket;
  }};
  const cp={spawn(file,args,options){
   commands.push({file,args});assert.equal(options.env.HOME,'/metadata');
   const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();
   child.kill=signal=>{killed.push(signal);queueMicrotask(()=>child.emit('close',null));};
   queueMicrotask(()=>{
    let text='';
    if(args.includes('update')){
     if(stalled){deadline();return;}
     if(scenario.startsWith('apt-')||scenario==='system-retention-apt-failed'||scenario==='renderer-retention-apt-failed'){
      child.stdout.emit('data',Buffer.from('Get:1 controlled Debian index\n'));
      child.stderr.emit('data',Buffer.from(scenario==='apt-truncated'?'E'.repeat(40000):'E: Release file expired (controlled exact diagnostic)\n'));
      child.emit('close',100,null);return;
     }
     if(retained){
      for(const suite of ['trixie','trixie-updates','trixie-security'])for(const suffix of ['InRelease','main/binary-arm64/Packages.xz']){
       proxyHandler({method:'GET',url:'http://deb.debian.org/'+(suite==='trixie-security'?'debian-security':'debian')+'/dists/'+suite+'/'+suffix},response);
      }
     }else proxyHandler({method:'GET',url:'http://deb.debian.org/debian/dists/bookworm/InRelease'},response);
    }else if(args.includes('--print-uris'))text=retained?retainedEnvelope().candidate.selection:candidate().selection;
    else if(args.includes('--simulate'))text='Inst bubblewrap (1 Debian [arm64])\n';
    else if(file==='/usr/bin/apt-cache')text='Package: bubblewrap\nVersion: 1\nArchitecture: arm64\nFilename: pool/main/b/bubblewrap/bubblewrap_1_arm64.deb\nSize: 5\nSHA256: '+'f'.repeat(64)+'\n';
    else if(file==='/usr/bin/sha256sum')text=(releases[args[0]]?crypto.createHash('sha256').update(releases[args[0]]).digest('hex'):'d'.repeat(64))+'  index\n';
    else if(file==='/usr/lib/apt/apt-helper')text='controlled expanded index';
    if(text)child.stdout.emit('data',Buffer.from(text));queueMicrotask(()=>child.emit('close',0));
   });return child;
  }};
  const processDouble={env:{OWASP_AI_GOAT_METADATA_PROXY_PORT:scenario==='invalid-proxy'?'23456x':'23456'},stdout:{write:value=>{output+=value;}},stderr:{write(){}},exitCode:0};
  await vm.runInNewContext(guestMetadataSource(currentBinding,retained?{retention:renderer?'v24-policy-metadata-retention-v1':pricing?'v33-pricing-metadata-retention-v1':system?'v24-system-metadata-retention-v1':'v23-metadata-retention-v1'}:{}),{require:name=>({'node:fs':fakeFs,'node:http':http,'node:tls':tls,'node:events':{EventEmitter},'node:child_process':cp,'node:crypto':crypto}[name]),
   Buffer,URL,AbortController,Date:class extends Date{static now(){return policyNow;}},process:processDouble,setTimeout:callback=>{deadline=callback;return 1;},clearTimeout(){}});
  if(scenario==='invalid-proxy'){
   assert.equal(processDouble.exitCode,1);assert.equal(output,'');assert.equal(commands.length,0);
   assert.equal(proxyRequests.length,0);continue;
  }
  const result=validateResultEnvelope(output,currentBinding);
  if(stalled){assert.equal(result.ok,false);assert.equal(result.errorCode,'METADATA_DEADLINE');assert.deepEqual(killed,['SIGKILL']);assert.equal(result.commandFailure.partial,true);}
  else if(scenario.endsWith('retention-status-changed')){
   assert.equal(result.ok,false);assert.equal(result.errorCode,'METADATA_STATUS_CHANGED');assert.equal(result.candidate,null);
   assert.equal(require('node:fs').existsSync(retainedRoot+'/result.json'),false);
   assert.equal(commands.filter(row=>row.args.includes('--simulate')).length,1);
  }
  else if(['renderer-retention-expired','renderer-retention-signed-expired','renderer-retention-updates-expired','renderer-retention-security-expired',
   'v23-expired','v23-signed-expired','v23-release-symlink','system-retention-expired','system-retention-signed-expired',
   'system-retention-updates-expired','system-retention-security-expired','system-retention-future','system-retention-duplicate-date','system-retention-release-symlink'].includes(scenario)){
   assert.equal(result.ok,false);assert.equal(result.candidate,null);assert.equal(commands.length,1,'no resolution after invalid authenticated release');
   assert.equal(result.errorCode,scenario.endsWith('release-symlink')?'METADATA_RELEASE_PATH':'METADATA_RELEASE_FRESHNESS');
   if(retained)assert.equal(require('node:fs').existsSync(retainedRoot+'/result.json'),false,'no success artifact after failed time-policy check');
  }
  else if(scenario.startsWith('apt-')||scenario==='system-retention-apt-failed'||scenario==='renderer-retention-apt-failed'){
   assert.equal(result.ok,false);assert.equal(result.candidate,null);assert.equal(result.errorCode,'METADATA_COMMAND_FAILED');
   const failure=result.commandFailure;assert.equal(failure.executable,'/usr/bin/apt-get');assert.ok(failure.args.includes('update'));
   assert.equal(failure.exitCode,100);assert.equal(failure.signal,null);assert.equal(failure.partial,false);assert.equal(commands.length,1);
   assert.equal(Buffer.from(failure.stdout.base64,'base64').toString(),'Get:1 controlled Debian index\n');
   assert.equal(Buffer.from(failure.stderr.base64,'base64').toString(),scenario==='apt-truncated'?'E'.repeat(32768):'E: Release file expired (controlled exact diagnostic)\n');
   assert.equal(failure.stderr.truncated,scenario==='apt-truncated');assert.equal(failure.stderr.bytesObserved,scenario==='apt-truncated'?40000:54);
   assert.equal(failure.stderr.observedSha256,crypto.createHash('sha256').update(scenario==='apt-truncated'?'E'.repeat(40000):'E: Release file expired (controlled exact diagnostic)\n').digest('hex'));
   if(scenario==='apt-truncated')assert.notEqual(failure.stderr.observedSha256,failure.stderr.retainedSha256);
  }
  else if(['parse-failure','symlink','dangling-main','keyring-symlink'].includes(scenario)){
   assert.equal(result.ok,false);assert.equal(result.candidate,null);assert.equal(commands.length,0,'no apt before source admission');
   assert.equal(result.errorCode,scenario==='parse-failure'?'METADATA_SOURCE_INVALID':scenario==='keyring-symlink'?'METADATA_KEYRING_PATH':'METADATA_SOURCE_PATH');
   if(scenario==='parse-failure'||scenario==='keyring-symlink')assert.equal(result.sourceSnapshot.files[0].text,source);
   else assert.equal(result.sourceSnapshot,null);
  }
  else{
   assert.equal(result.ok,true);assert.equal(processDouble.exitCode,0);
   assert.equal(result.candidate.keyringPath,'/usr/share/keyrings/debian-archive-keyring.'+(scenario==='retained-pgp'||v23||system||renderer?'pgp':'gpg'));
   assert.equal(result.candidate.keyringSha256,crypto.createHash('sha256').update(scenario==='retained-pgp'||v23||system||renderer?'different controlled pgp keyring':'controlled keyring').digest('hex'));
   const update=commands.find(row=>row.args.includes('update'));
   for(const option of ['Acquire::Check-Date=true','Acquire::Check-Valid-Until=true','Acquire::Max-ValidTime=604800','Acquire::Retries=0'])assert.ok(update.args.includes(option));
   assert.ok(commands.filter(row=>row.args.includes('install')).every(row=>row.args.includes('--simulate')||row.args.includes('--print-uris')));
   const installs=commands.filter(row=>row.args.includes('install'));
   assert.equal(installs.length,retained&&!system?4:2);
   for(const [i,row]of installs.entries())assert.deepEqual(Array.from(row.args.slice(row.args.indexOf('install')+1)),renderer?(i<2?['gcc','libc6-dev']:['bubblewrap']):retained&&!system?(i<2?['gcc','libc6-dev','libseccomp-dev']:['bubblewrap','libseccomp2']):currentSpec.installPackages);
   if(renderer){
    assert.equal(result.candidate.sourcePolicy.policy,rendererPolicy);assert.equal(result.candidate.retainedMetadata.kind,'v24-policy-original-apt-retention');
    assert.deepEqual(result.candidate.retainedMetadata.stages.map(row=>[row.name,row.packages]),[['build',['gcc','libc6-dev']],['runtime',['bubblewrap']]]);
    assert.deepEqual(result.candidate.releaseFreshness.map(row=>row.maximumSeconds),[7776000,604800,604800]);
   }
   if(system){
    assert.equal(result.candidate.sourcePolicy.policy,systemPolicy);assert.equal(result.candidate.releaseFreshness.length,3);
    const sourceWrite=writes.find(([name])=>name==='/metadata/sources/debian.sources');assert(sourceWrite);
    assert.equal(sourceWrite[1],require('./postgres/ownedPolicySystemMetadata').canonicalSources('debian.sources',source,systemPolicy));
    assert.deepEqual(result.candidate.releaseFreshness.map(row=>row.maximumSeconds),[7776000,604800,604800]);
    assert.equal(result.candidate.retainedMetadata.kind,'v24-system-original-apt-retention');
    assert.deepEqual(result.candidate.retainedMetadata.stages.map(row=>[row.name,row.packages]),[['system',['gcc','libc6-dev','bubblewrap']]]);
   }
   if(retained){
    if(pricing){assert.equal(result.candidate.retainedMetadata.kind,'v33-pricing-original-apt-retention');assert.equal(result.candidate.sourcePolicy.policy,'v33-pricing-trixie-freshness-v1');}
    const fs=require('node:fs');assert.equal(result.version,3);
    assert.deepEqual(JSON.parse(fs.readFileSync(retainedRoot+'/result.json','utf8')),result);
    assert.equal(result.candidate.retainedMetadata.objects.length,8);
    for(const row of result.candidate.retainedMetadata.objects){
     const raw=fs.readFileSync(retainedRoot+'/'+row.file);assert.equal(raw.length,row.bytes);
     assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),row.sha256);
    }
    assert.equal(fs.readdirSync(retainedRoot+'/partial').length,0);
   }
   assert.deepEqual(result.candidate.requestedPackages,currentSpec.packages);
   assert.equal(writes.length,2);assert.match(writes[0][1],/Architectures: arm64/);
   assert.equal(proxyRequests[0].method,'CONNECT');assert.equal(proxyRequests[0].host,'127.0.0.1');
   assert.equal(proxyRequests[0].port,23456);assert.equal(proxyRequests[0].path,'deb.debian.org:443');
   assert.ok(proxyRequests.some(row=>row.method==='GET'));
  }
 }
});
test('metadata acquisition uses owned lifecycle and cleans private resources on command failure',async t=>{
 const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
 const {acquireMetadata}=require('./postgres/ownedPolicySystemMetadata');
 const build=require('./postgres/ownedMcpBoundedBuild');
 for(const scenario of ['success','acquisition-failed','both-failed','semantic-failed']){
  const failed=scenario!=='success',cleanupFailed=scenario==='both-failed';
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'metadata-control-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.mkdir(path.join(root,'tasks/tmp'),{recursive:true});const runId=(failed?'a':'b').repeat(32),spec=build.specification(root,runId),calls=[];
  const network={version:1,bridge:{Id:'controlled-bridge'},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:'',firewall6:'',nft:{nftables:[]},forwarding:'1\n0\n'};
  const inventory=JSON.stringify(build.PINS.daemon)+'\n'+build.PINS.postgres+' postgres:18\n\nCONTAINERS\n\nVOLUMES\n\nNETWORK\n'+JSON.stringify(network)+'\n';
  assert.throws(()=>build._internals.checkInventory(inventory.split('\nNETWORK\n')[0]),{code:'BUILD_SHARED_NETWORK_UNPROVEN'});
  const runner=async(_spec,op,options)=>{
   calls.push(op);
   if(op==='inventory')return inventory;
   if(op==='start'||op==='inspect')return JSON.stringify({ID:'private',DockerRootDir:spec.mount+'/data',Driver:'overlay2',Architecture:'arm64'});
   if(op==='metadata-acquire'){
    assert.deepEqual(options.args,[require('./postgres/ownedPolicySystemBuild').TARGETS['v24-policy'].base]);
    let source='';for await(const chunk of options.input)source+=chunk;assert.match(source,/guestMetadataMain/);
    const diagnostic=build._internals.metadataDiagnostics();
    diagnostic.push(Buffer.from('OWASP_AI_GOAT_METADATA_STAGE=apt-update\n'));
    options.onDiagnostics(diagnostic.finish({code:failed&&scenario!=='semantic-failed'?1:0,signal:null,stdoutBytes:0}));
    if(failed&&scenario!=='semantic-failed')throw Object.assign(Error('controlled'),{code:'CONTROLLED_TIMEOUT'});
    const result=envelope(scenario!=='semantic-failed',runId);
    if(scenario==='semantic-failed'){result.errorCode='METADATA_COMMAND_FAILED';result.commandFailure=commandFailure();}
    return JSON.stringify(result);
   }
   if(op==='metadata-cleanup'){
    const diagnostic=build._internals.metadataDiagnostics();
    diagnostic.push(Buffer.from('OWASP_AI_GOAT_METADATA_STAGE=cleanup-mounts\n'));
    options.onDiagnostics(diagnostic.finish({code:cleanupFailed?93:0,signal:null,stdoutBytes:0}));
    if(cleanupFailed)throw Object.assign(Error('controlled cleanup'),{code:'CONTROLLED_CLEANUP_FAILED'});
    return 'absent';
   }
   return '';
  };
  const invoke=()=>acquireMetadata({root,runId,target:'v24-policy',verify:async()=>{},runner});
  if(failed)await assert.rejects(invoke());else assert.equal((await invoke()).executionApproved,false);
  assert.equal(calls.at(-2),'metadata-cleanup');assert.equal(calls.at(-1),'inventory');
  const receipt=JSON.parse(await fs.readFile(path.join(spec.artifact,'metadata-result.json'),'utf8'));
  assert.equal(receipt.acquisitionDiagnostics.lastStage,'apt-update');
  assert.equal(receipt.acquisitionDiagnostics.exitCode,failed&&scenario!=='semantic-failed'?1:0);
  assert.equal(receipt.acquisitionDiagnostics.rawStderrRetained,false);
  assert.equal(receipt.cleanupDiagnostics.lastStage,'cleanup-mounts');
  assert.equal(receipt.cleanupDiagnostics.exitCode,cleanupFailed?93:0);
  assert.equal(receipt.cleanupVerified,!cleanupFailed);
  assert.deepEqual(receipt.cleanupErrors,cleanupFailed?['CONTROLLED_CLEANUP_FAILED']:[]);
  assert.equal(receipt.error,scenario==='semantic-failed'?'METADATA_COMMAND_FAILED':failed?'CONTROLLED_TIMEOUT':null);
  assert.deepEqual(receipt.commandFailure,scenario==='semantic-failed'?commandFailure():null);
  assert.equal(receipt.executionApproved,false);
  if(scenario==='semantic-failed'){assert.equal(receipt.candidate,null);assert.deepEqual(receipt.sourceSnapshot,envelope(false,runId).sourceSnapshot);}
  if(scenario==='acquisition-failed')assert.equal(receipt.sourceSnapshot,null);
 }
});
async function* chunks(...values){yield* values;}
test('metadata budget meters actual streamed bytes before writing, not declared content length',async()=>{
 const budget=createMetadataBudget(),written=[];
 const result=await budget.transfer('compressed',chunks(Buffer.from('ab'),Buffer.from('c')),async chunk=>written.push(chunk));
 assert.equal(result.bytes,3);assert.equal(Buffer.concat(written).toString(),'abc');
 assert.equal(budget.snapshot().compressed,3);
 budget.reserve('compressed',LIMITS.compressedTotal-3);
 await assert.rejects(budget.transfer('compressed',chunks(Buffer.from('!')),async()=>assert.fail('overflow must not be written')),
  {code:'METADATA_COMPRESSED_LIMIT'});
 assert.equal(budget.snapshot().failed,true);
});
test('all operations share aggregate report/diagnostic/expanded limits and one deadline',async()=>{
 for(const [kind,limit] of [['expanded',LIMITS.expandedTotal],['diagnostics',LIMITS.diagnostics],['report',LIMITS.report]]){
  const budget=createMetadataBudget();budget.reserve(kind,limit);
  await assert.rejects(budget.transfer(kind,chunks(Buffer.from('x')),async()=>assert.fail()),{code:'METADATA_'+kind.toUpperCase()+'_LIMIT'});
 }
 let now=0;const budget=createMetadataBudget({now:()=>now});
 now=LIMITS.deadlineMs;assert.throws(()=>budget.check(),{code:'METADATA_DEADLINE'});
});
test('release and source caps fail closed, cancellation preserves exact reason',async()=>{
 const budget=createMetadataBudget();
 await assert.rejects(budget.transfer('compressed',chunks(Buffer.alloc(LIMITS.release+1)),async()=>assert.fail(),{release:true}),{code:'METADATA_FILE_LIMIT'});
 const many=createMetadataBudget();for(let n=0;n<LIMITS.sources;n++)await many.transfer('compressed',chunks(Buffer.from('x')),async()=>{});
 await assert.rejects(many.transfer('compressed',chunks(Buffer.from('x')),async()=>assert.fail()),{code:'METADATA_SOURCE_LIMIT'});
 const controller=new AbortController(),error=Error('controlled abort'),cancel=createMetadataBudget({signal:controller.signal});
 await assert.rejects(cancel.transfer('expanded',chunks(Buffer.from('a'),Buffer.from('b')),async()=>controller.abort(error)),e=>e===error);
 assert.equal(cancel.snapshot().expanded,1);
});
test('closed exact base prerequisites honestly deny execution until metered authentication and apt staging exist',()=>{
 for(const target of ['v24-system','v24-policy']){
  const value=metadataPrerequisites(target);assert.equal(value.executable,false);assert.equal(value.missing.length,2);
  assert.equal(value.packages.join(','),'bubblewrap,gcc,libc6-dev');
 }
 assert.throws(()=>metadataPrerequisites('arbitrary'),{code:'BUILD_TARGET_UNKNOWN'});
 const v23=metadataPrerequisites('v23-registry');
 assert.equal(v23.executable,false);assert.equal(v23.missing.length,2);
 assert.deepEqual(v23.packages,['bubblewrap','gcc','libc6-dev','libseccomp-dev','libseccomp2']);
 assert.equal(v23.baseImageDigest,metadataPrerequisites('v24-policy').baseImageDigest);
});

test('V03 retention admits only each exact target/kind pair before filesystem access',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const source=fs.readFileSync(require.resolve('./postgres/ownedPolicySystemMetadata'),'utf8');
 const start=source.indexOf('function createMetadataRetention('),end=source.indexOf('module.exports.createMetadataRetention=');
 assert(start>=0&&end>start);
 const retention=vm.runInNewContext('('+source.slice(start,end).trim()+')');
 const targets=require('./postgres/ownedPolicySystemBuild');
 const names=['v23-registry','v24-system','v33-pricing','v24-policy','listings-package','v03-diagnostic'];
 const fake=()=>{const calls=[];return {calls,lstatSync(){calls.push('stat');return {isDirectory:()=>true,isSymbolicLink:()=>false,uid:0,mode:0o40700};},realpathSync:()=>'/metadata-retained',readdirSync:()=>[],mkdirSync(p){calls.push(p);}};};
 for(const target of names)for(const other of names){
  const io=fake(),kind=targets.metadataRetentionSpecification(other).kind;
  if(target===other){retention(io,{}, {target},kind);assert.equal(io.calls.length,3);}
  else{assert.throws(()=>retention(io,{}, {target},kind),/METADATA_RETENTION_INVALID/);assert.equal(io.calls.length,0);}
 }
 for(const target of [undefined,'__proto__','unknown',1]){const io=fake();assert.throws(()=>retention(io,{}, {target},'v03-diagnostic-original-apt-retention'),/METADATA_RETENTION_INVALID/);assert.equal(io.calls.length,0);}
});
test('complete controlled V03 metadata envelope retains exact diagnostic binding',()=>{
 const api=require('./postgres/ownedPolicySystemMetadata'),row=structuredClone(systemRetainedEnvelope());
 row.binding.target='v03-diagnostic';row.candidate.sourcePolicy.policy='v03-diagnostic-trixie-freshness-v1';
 row.candidate.retainedMetadata.kind='v03-diagnostic-original-apt-retention';
 row.candidate.retainedMetadata.binding={...row.binding};row.candidate.retainedMetadata.stages[0].name='diagnostic';
 assert.equal(api.validateResultEnvelope(JSON.stringify(row),row.binding).ok,true);
 for(const kind of ['v24-system-original-apt-retention','listings-original-apt-retention']){
  const wrong=structuredClone(row);wrong.candidate.retainedMetadata.kind=kind;
  assert.throws(()=>api.validateResultEnvelope(JSON.stringify(wrong),row.binding));
 }
});
