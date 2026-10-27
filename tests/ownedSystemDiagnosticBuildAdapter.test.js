'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),vm=require('node:vm');
const {EventEmitter}=require('node:events');
const adapter=require('./postgres/ownedSystemDiagnosticBuildAdapter');
const inputs=require('./postgres/ownedSystemDiagnosticBuildInputs');
const system=require('./postgres/ownedSystemConfigBuildAdapter')._internals;
const targets=require('./postgres/ownedPolicySystemBuild');
const metadata=require('./postgres/ownedPolicySystemMetadata');
const I=adapter._internals,runId='a'.repeat(32);
const plan=()=>adapter.diagnosticBuildPlan(I.ROOT,runId);
const pythonCommand=env=>env.PYTHON||'python3';
test('unpacker interpreter uses explicit override or controlled PATH without skipping',()=>{
 assert.equal(pythonCommand({PYTHON:'/configured/python3'}),'/configured/python3');
 assert.equal(pythonCommand({}),'python3');
});

test('actual fixed plan has distinct metadata/build identity and no execution authority',async()=>{
 const p=await plan();
 assert.equal(p.target,'original-v03-diagnostic');assert.equal(p.binding.target,'v03-diagnostic');
 assert.equal(p.metadata.kind,'private-v03-diagnostic-metadata');
 assert.equal(p.metadata.metadataRetention.mode,'v03-diagnostic-metadata-retention-v1');
 assert.equal(p.binding.base,inputs.RECIPE.base);
 assert.equal(p.metadata.guestSourceSha256,inputs._internals.sha(p.metadataGuestSource));
 assert.equal(p.executionApproved,false);assert.equal(p.runtimeAvailable,false);
 assert.equal(p.boundedDerivation.runtimeAdmitted,false);
 assert.match(p.commands.build,/stop_private_relay/);
 assert.match(p.commands.build,/dvaia\.diagnostic\.inputs=/);
 assert.match(p.commands.build,/dvaia-diagnostic-build:/);
 assert.match(p.commands.build,/docker --host "unix:\/\/\$root\/fs\/docker.sock" build/);
 assert.match(p.commands.handoff,/'target':'original-v03-diagnostic'/);
 assert.equal(await adapter.verifyDiagnosticBuildPlan(p),true);
 await assert.rejects(adapter.withPrivateDiagnosticImage(p),/DIAGNOSTIC_BUILD_NOT_ADMITTED/);
 assert.throws(()=>targets.requireApprovedTarget('v03-diagnostic',{},{}));
 assert.throws(()=>targets.validateCandidate('v03-diagnostic',{},{}),/METADATA_ONLY/);
});

test('changed command, input, helper, target, and authority flags cannot verify as plans',async()=>{
 const p=await plan();
 for(const mutate of [v=>v.commands.build+='\necho changed',v=>v.captured.recipe.generatedEntry.source+='x',
  v=>v.helperHashes['tests/postgres/ownedAptAuthentication.js']='0'.repeat(64),
  v=>v.binding.target='v24-system',v=>v.target='original-v24-system',v=>v.executionApproved=true]){
  const altered=structuredClone(p);mutate(altered);await assert.rejects(adapter.verifyDiagnosticBuildPlan(altered),/DIAGNOSTIC_PLAN_/);
 }
 await assert.rejects(adapter.diagnosticBuildPlan(I.ROOT,runId,inputs.RECIPE),/DIAGNOSTIC_PLAN_BINDING/);
 await assert.rejects(adapter.diagnosticBuildPlan('/foreign',runId),/DIAGNOSTIC_PLAN_BINDING/);
});

test('in-memory derivation requires exact reviewed source and keeps original module untouched',async()=>{
 const original=await fs.readFile(path.join(I.ROOT,'tests/postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert.equal(inputs._internals.sha(original),I.SOURCE_SHA);
 const derived=I.deriveSource(original);
 assert.notEqual(derived,original);assert.match(derived,/private-v03-diagnostic-metadata/);
 assert.throws(()=>I.deriveSource(original+'\n'),/DIAGNOSTIC_DERIVATION_SOURCE/);
 assert.throws(()=>I.replaceOnce('xx','x','y'),/DIAGNOSTIC_DERIVATION_ANCHOR/);
 assert.equal(await fs.readFile(path.join(I.ROOT,'tests/postgres/ownedMcpBoundedBuild.js'),'utf8'),original);
});

test('diagnostic metadata retains independent stage and closed authentication/freshness grammar',()=>{
 const spec=targets.targetSpecification('v03-diagnostic'),retention=targets.metadataRetentionSpecification('v03-diagnostic');
 assert.deepEqual(retention.stages,[{name:'diagnostic',packages:['gcc','libc6-dev','bubblewrap']}]);
 assert.notEqual(retention.kind,targets.metadataRetentionSpecification('v24-system').kind);
 assert.equal(spec.metadataOnly,true);
 const source='deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian trixie main\n';
 assert.match(metadata.canonicalSources('main.list',source,spec.metadataSourcePolicy),/valid-until-max=7776000/);
 assert.throws(()=>metadata.canonicalSources('main.list',source.replace('deb [','deb [trusted=yes '),spec.metadataSourcePolicy));
 assert.throws(()=>metadata.canonicalSources('main.list',source,'v03-unreviewed-policy'));
 const stage={name:'diagnostic',packages:['gcc','libc6-dev','bubblewrap'],selection:"'http://deb.debian.org/debian/pool/gcc.deb' gcc.deb 1",selected:[{name:'gcc',version:'1',architecture:'arm64',filename:'pool/gcc.deb',bytes:1,sha256:'a'.repeat(64)}]};
 assert.deepEqual(system.systemArtifacts([stage],'v03-diagnostic')[0].stages,['diagnostic']);
 for(const mutate of [v=>v.name='system',v=>v.packages.reverse(),v=>v.selected[0].bytes++,v=>v.selection=v.selection.replace('deb.debian.org','foreign.invalid')]){
  const s=structuredClone(stage);mutate(s);assert.throws(()=>system.systemArtifacts([s],'v03-diagnostic'));
 }
 assert.throws(()=>metadata.validateResultEnvelope(JSON.stringify({binding:{runId,target:'v24-system',base:spec.base}}),{runId,target:'v03-diagnostic',base:spec.base}),/ENVELOPE/);
});

test('actual shared APT implementation admits distinct diagnostic stages and rejects forged or failed authentication',async()=>{
 // Reuse controlled dependency fixture, not its test registrations or any live APT.
 const filename=path.join(__dirname,'ownedAptAuthentication.test.js'),source=await fs.readFile(filename,'utf8');
 const local=require('node:module').createRequire(filename),m={exports:{}};
 const controlledRequire=Object.assign(id=>id==='node:test'?()=>{}:local(id),{resolve:local.resolve});
 vm.runInNewContext('(function(require,module,exports){'+source+'\nmodule.exports={fixture,lifecycle};})',
  {Buffer,AbortController,AbortSignal,structuredClone,setTimeout,clearTimeout,queueMicrotask})(controlledRequire,m,m.exports);
 for(const fault of ['', 'apt', 'selection', 'package', 'integrity']){
  const f=m.exports.fixture('v03-diagnostic',fault);
  if(fault==='integrity'){await assert.rejects(f.api.admitRetained(f.binding));assert.equal(f.commands.length,0);continue;}
  const cap=await f.api.admitRetained(f.binding);
  if(fault){await assert.rejects(f.api.authenticate(cap,m.exports.lifecycle()));if(fault==='apt')assert.equal(f.commands.length,1);}
  else{const result=await f.api.authenticate(cap,m.exports.lifecycle());assert.equal(result.stages[0].name,'diagnostic');assert.equal(result.method,'original-base-apt-closed-replay');}
  await assert.rejects(f.api.authenticate(cap,m.exports.lifecycle()),/ADMISSION/);
 }
 const f=m.exports.fixture('v03-diagnostic');
 f.retained.kind=targets.metadataRetentionSpecification('v24-system').kind;
 f.files.set('/metadata-retained/manifest.json',Buffer.from(JSON.stringify(f.retained)));
 await assert.rejects(f.api.admitRetained(f.binding),/TARGET_STAGES/);assert.equal(f.commands.length,0);
});

test('real metadata validators bind diagnostic run, base, source policy and retained stage without borrowing System proof',async()=>{
 const filename=path.join(__dirname,'ownedPolicySystemMetadata.test.js'),source=await fs.readFile(filename,'utf8');
 const local=require('node:module').createRequire(filename),m={exports:{}};
 const controlledRequire=Object.assign(id=>id==='node:test'?()=>{}:local(id),{resolve:local.resolve});
 vm.runInNewContext('(function(require,module,exports){'+source+'\nmodule.exports={systemRetainedEnvelope};})',
  {Buffer,AbortController,AbortSignal,structuredClone,URL,setTimeout,clearTimeout,queueMicrotask})(controlledRequire,m,m.exports);
 const row=JSON.parse(JSON.stringify(m.exports.systemRetainedEnvelope()));
 row.binding.target='v03-diagnostic';row.candidate.sourcePolicy.policy='v03-diagnostic-trixie-freshness-v1';
 row.candidate.retainedMetadata.kind='v03-diagnostic-original-apt-retention';
 row.candidate.retainedMetadata.binding={...row.binding};row.candidate.retainedMetadata.stages[0].name='diagnostic';
 metadata.validateResultEnvelope(JSON.stringify(row),row.binding);
 for(const mutate of [v=>v.binding.target='v24-system',v=>v.binding.runId='b'.repeat(32),
  v=>v.candidate.retainedMetadata.kind='v24-system-original-apt-retention',v=>v.candidate.retainedMetadata.stages[0].name='system',
  v=>v.candidate.sourcePolicy.policy='v24-system-trixie-freshness-v1',v=>v.candidate.retainedMetadata.objects[0].sha256='0'.repeat(64),
  v=>v.candidate.releaseFreshness[0].maximumSeconds++]){
  const changed=structuredClone(row);mutate(changed);assert.throws(()=>metadata.validateResultEnvelope(JSON.stringify(changed),row.binding));
 }
});

async function emittedGuest(fault){
 const p=await plan(),events=[],files=new Map(),proc=new EventEmitter();
 proc.env={DVAIA_ARTIFACT_DEADLINE_SECONDS:String(Number(process.hrtime.bigint())/1e9+30),DVAIA_ARTIFACT_PROXY_PORT:'1234'};
 proc.hrtime=process.hrtime;
 const fakeFs={async readFile(){return Buffer.from('{}');},async open(name){return{
  async writeFile(bytes){files.set(name,Buffer.from(bytes));},async sync(){if(fault==='publication'&&name.endsWith('closure.json.partial'))throw Error('write failure');},async close(){},
 };},async link(from,to){files.set(to,files.get(from));if(to.endsWith('/ready.json'))setImmediate(()=>proc.emit('SIGTERM'));},async unlink(name){files.delete(name);}};
 const stage={name:'diagnostic',packages:['gcc','libc6-dev','bubblewrap'],selection:"'http://deb.debian.org/debian/pool/gcc.deb' gcc.deb 1",selected:[{name:'gcc',version:'1',architecture:'arm64',filename:'pool/gcc.deb',bytes:1,sha256:'a'.repeat(64)}]};
 const modules={ownedAptAuthentication:{async admitRetained(binding){assert.equal(binding.target,'v03-diagnostic');events.push('admit');return {};},async authenticate(){events.push('authenticate');if(fault==='auth')throw Object.assign(Error('auth'),{code:'CONTROLLED_AUTH_FAILURE'});return {binding:p.binding,method:'original-base-apt-closed-replay'};}},
  ownedPolicySystemMetadata:{validateResultEnvelope:()=>({candidate:{}}),validateRetainedMetadata:()=>({stages:[stage],objects:[]})},
  ownedMcpDependencyClosure:{failureDiagnostic:require('./postgres/ownedMcpDependencyClosure').failureDiagnostic,_internals:{validateArtifacts(){}},async acquireArtifacts({artifacts}){events.push('acquire');assert.deepEqual(Array.from(artifacts[0].stages),['diagnostic']);return{bytes:{npm:0},artifacts};},artifactReader(){return()=>{throw Error('unrequested');};}},
  ownedMcpArtifactReplay:{replayCertificate:()=>({}),createReplay(){events.push('replay');return{firstFailure:new Promise(()=>{}),failureRecord:()=>null,async listen(){events.push('listen');return{port:3456};},async close(){events.push('close');if(fault==='close')throw Error('close failure');return{closed:true,absenceVerified:true,active:0};}};}}};
 // Execute the actual emitted guestMain invocation; replace only its embedded
 // source-module loader with controlled dependencies, never the guest function.
 const start=p.guestSource.indexOf('\n(');assert.ok(start>0);
 const source='load=controlledLoad;'+p.guestSource.slice(start);
 const context={controlledLoad:name=>modules[name],Buffer,URL,AbortController,setTimeout,clearTimeout,process:proc,
  require:id=>id==='node:fs/promises'?fakeFs:require(id)};
 await vm.runInNewContext(source,context);
 return{events,code:proc.exitCode,files:Object.fromEntries([...files].filter(([name])=>!name.endsWith('.partial')).map(([name,bytes])=>[path.basename(name),JSON.parse(bytes)]))};
}
test('actual emitted guest authenticates before acquisition and preserves failed publication/retirement',async()=>{
 const ok=await emittedGuest('');assert.equal(ok.code,0);assert.deepEqual(ok.events,['admit','authenticate','acquire','replay','listen','close']);
 assert.equal(ok.files['ready.json'].metadataAuthenticated,true);
 const auth=await emittedGuest('auth');assert.deepEqual(auth.events,['admit','authenticate']);assert.equal(auth.files['terminal.json'].failure,'CONTROLLED_AUTH_FAILURE');assert.equal(auth.code,1);
 const publication=await emittedGuest('publication');assert.equal(publication.code,1);assert.equal(publication.files['ready.json'],undefined);
 const close=await emittedGuest('close');assert.equal(close.code,2);assert.deepEqual(close.files['terminal.json'].cleanupErrors,['SYSTEM_REPLAY_JOIN']);
});

test('actual emitted Python unpacker accepts exact synthetic bytes and rejects name, checksum and mode mutations',async()=>{
 const p=await plan(),temporary=await fs.mkdtemp(path.join(I.ROOT,'tasks/tmp/diagnostic-unpack-control-'));
 const program=String.raw`
import sys,os,json,shlex,io,tarfile,hashlib,shutil
packet=json.load(sys.stdin);parent=sys.argv[1]
tokens=shlex.split(packet['command']);source=next(x for x in tokens if x.startswith('\nimport sys,os,tarfile,hashlib,json'))
body=b'synthetic-only';rows={'owned-system/example.js':dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=0o644)}
recipe=packet['recipe'];directories=[dict(name='.',mode=0o700),dict(name='owned-system',mode=0o755)]
for case in ('ok','foreign','checksum','mode'):
 root=parent+'/'+case;os.mkdir(root);os.mkdir(root+'/fs');data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as archive:
  info=tarfile.TarInfo('foreign' if case=='foreign' else 'owned-system/example.js');info.size=len(body);info.mode=0o666 if case=='mode' else 0o644
  archive.addfile(info,io.BytesIO(b'X'+body[1:] if case=='checksum' else body))
 oldin,oldargs=sys.stdin,sys.argv
 sys.stdin=type('Input',(),{'buffer':io.BytesIO(data.getvalue())})();sys.argv=['unpack',root,json.dumps(rows),json.dumps(recipe),json.dumps(directories)]
 try:
  try:exec(compile(source,'actual-emitted-unpacker','exec'),{})
  except (AssertionError,OSError):assert case!='ok'
  else:
   assert case=='ok';assert open(root+'/fs/system-context/owned-system/example.js','rb').read()==body
   assert open(root+'/fs/system.Dockerfile').read()==recipe['dockerfile']
 finally:sys.stdin,sys.argv=oldin,oldargs
print('four-emitted-unpacker-cases')
`;
 try{const result=require('node:child_process').spawnSync(pythonCommand(process.env),['-I','-S','-B','-c',program,temporary],{input:JSON.stringify({command:p.commands.build,recipe:inputs.RECIPE}),encoding:'utf8',timeout:10000,maxBuffer:65536});assert.ifError(result.error);assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/four-emitted-unpacker-cases/);}
 finally{await fs.rm(temporary,{recursive:true,force:true});}
});
