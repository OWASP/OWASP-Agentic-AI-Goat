'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const candidate=require('../scripts/install/secureshop-owned-system-architecture-candidate'),root=path.resolve(__dirname,'..');
const amd={root,hostArchitecture:'x64',daemonArchitecture:'x86_64',daemonOs:'linux'},arm={root,hostArchitecture:'arm64',daemonArchitecture:'aarch64',daemonOs:'linux'};
// Synthetic closed-source package tests architecture parsing only, never native
// AMD64 qualification. The checked-in historical candidate is tested separately.
function controlledAmdCandidate(t){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'system-amd-candidate-'));
 t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const dest=path.join(temp,'sidecars/sandbox-runner/owned-system');fs.mkdirSync(dest,{recursive:true});
 const source=path.join(root,'sidecars/sandbox-runner/owned-system'),name='local-package-amd64.candidate.json';
 const original=JSON.parse(fs.readFileSync(path.join(source,name)));
 for(const file of Object.keys(original.files)){
  const bytes=Buffer.from(`synthetic architecture fixture: ${file}\n`);
  fs.mkdirSync(path.dirname(path.join(dest,file)),{recursive:true});
  fs.writeFileSync(path.join(dest,file),bytes);
  original.files[file]=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
 }
 fs.writeFileSync(path.join(dest,name),JSON.stringify(original));
 return {input:{...amd,root:temp},dest,name,original};
}
test('closed native architecture selection preserves ARM descriptor, controlled AMD64 remains unactivated',t=>{
 const controlled=controlledAmdCandidate(t),a=candidate.select(arm),b=candidate.select(controlled.input);assert.equal(a.managedVersion,1);assert.equal(a.status,'qualified_arm64');assert.equal(b.managedVersion,2);assert.equal(b.status,'unqualified_candidate');assert.equal(b.qualification,null);assert.equal(b.baseImage,'sha256:0e6e6feab3409d135561b2dac7f75dad902ceb5e14c35de4521155779ae70cee');assert.equal(candidate.assertActivatable(arm).sha256,a.sha256);assert.throws(()=>candidate.assertActivatable(controlled.input),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});
 for(const bad of ['amd64','x86_64','ia32','ARM64','toString',undefined])assert.throws(()=>candidate.select({...amd,hostArchitecture:bad}));
 assert.throws(()=>candidate.select({...amd,daemonArchitecture:'arm64'}),{code:'SYSTEM_INSTALL_ARCHITECTURE_CONFLICT'});assert.throws(()=>candidate.select({...amd,daemonOs:'windows'}));
});
test('image and durable record architecture binding reject cross-platform reinterpretation',t=>{
 const a=candidate.select(arm),b=candidate.select(controlledAmdCandidate(t).input),id='sha256:'+'a'.repeat(64);
 assert.equal(candidate.assertImage(b,{Os:'linux',Architecture:'amd64',Id:id}),true);
 assert.throws(()=>candidate.assertImage(b,{Os:'linux',Architecture:'arm64',Id:id}));
 assert.equal(candidate.assertRecordArchitecture(a,{version:1,architecture:'arm64',sourceManifestSha256:a.sha256}),true);
 assert.equal(candidate.assertRecordArchitecture(b,{version:2,architecture:'amd64',sourceManifestSha256:b.sha256}),true);
 assert.throws(()=>candidate.assertRecordArchitecture(b,{version:1,architecture:'amd64',sourceManifestSha256:b.sha256}));
 assert.throws(()=>candidate.assertRecordArchitecture(b,{version:1,architecture:'arm64',sourceManifestSha256:a.sha256}));
});
test('candidate closed source map rejects activation receipt injection, arbitrary keys and changed Dockerfile',t=>{
 const {input,dest,name,original}=controlledAmdCandidate(t);assert.equal(candidate.select(input).status,'unqualified_candidate');
 for(const mutate of [v=>v.qualification='forged-native.json',v=>v.files['../../private']='a'.repeat(64),v=>v.status='qualified']){const value=structuredClone(original);mutate(value);fs.writeFileSync(path.join(dest,name),JSON.stringify(value));assert.throws(()=>candidate.select(input));}
 fs.writeFileSync(path.join(dest,name),JSON.stringify(original));fs.appendFileSync(path.join(dest,'Dockerfile.local.amd64.candidate'),'\n# drift');assert.throws(()=>candidate.select(input),{code:'SYSTEM_PACKAGE_SOURCE_CHANGED'});
});

test('checked-in AMD64 candidate has complete preview source closure but remains unqualified and inactive',()=>{
 const selected=candidate.select(amd);
 assert.equal(selected.status,'unqualified_candidate');assert.equal(selected.qualification,null);
 assert.equal(Object.keys(selected.files).length,42);
 assert.throws(()=>candidate.assertActivatable(amd),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});
 const directory=path.join(root,'sidecars/sandbox-runner/owned-system');
 const docker=fs.readFileSync(path.join(directory,'Dockerfile.local.amd64.candidate'),'utf8');
 for(const line of docker.split('\n').filter(line=>line.startsWith('COPY --chown=0:0 '))){
  for(const file of line.split(/\s+/).slice(2,-1))assert.ok(Object.hasOwn(selected.files,file),`COPY asset missing from frozen source: ${file}`);
 }
 for(const file of ['upload-preview-contract.js','upload-preview-dependencies.js','upload-preview-executor.js',
  'upload-preview-http-handler.js','upload-preview-http-listener.js','upload-preview-worker.js','upload-preview-init.c',
  'upload-preview-runtime/package.json','upload-preview-runtime/package-lock.json'])assert.ok(Object.hasOwn(selected.files,file),file);
 assert.match(docker,/gcc -static[^\n]+upload-preview-init\.c -o \/usr\/local\/libexec\/dvaia-upload-preview-init/);
 assert.match(docker,/node \/opt\/dvaia-owned-system\/upload-preview-dependencies\.js --build-manifest/);
 assert.match(docker,/npm ci --omit=dev --ignore-scripts --include=optional --bin-links=false/);
 assert.match(docker,/USER 10001:10001/);
 assert.doesNotMatch(docker,/^(?:ENV|VOLUME|EXPOSE|CMD|ADD)\s/m);
 assert.equal(Object.hasOwn(selected.files,'upload-preview-native-qualification.js'),false);
});
