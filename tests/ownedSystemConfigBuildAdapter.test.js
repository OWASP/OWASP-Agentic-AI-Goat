'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),vm=require('node:vm');
const {EventEmitter}=require('node:events');
const adapter=require('./postgres/ownedSystemConfigBuildAdapter'),I=adapter._internals;
const input=require('./postgres/ownedSystemConfigPrivateBuild'),C=input._internals;
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
async function recipe(){
 const source=await fs.readFile(path.join(C.ROOT,C.PROVIDER),'utf8');
 const body=/def original_dockerfile\(\):\n  return '''FROM node@'''\+BASE\+'''([\s\S]*?)'''/.exec(source)[1];
 const dockerfile='FROM node@'+C.BASE+body;
 return {version:1,target:'v24-system',base:C.BASE,platform:'linux/arm64',sourceRoot:C.SOURCE,
  dockerfile,dockerfileSha256:hash(dockerfile),packages:[...C.PACKAGES],user:'10001:10001',entrypoint:[...C.ENTRYPOINT]};
}
test('failed-slot export preserves exact empty/partial bytes with provenance, never metadata authority',async()=>{
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'e'.repeat(32),await recipe());
 for(const slot of ['system','policy']){
  const success=plan.commands[slot+'Export'],failed=plan.commands[slot+'FailureExport'];
  assert.equal(success,plan.slots[slot].metadata.phases.retainedExport.replaceAll('$root/fs/metadata-retained',`$root/fs/${slot}-metadata-retained`));
  assert(success.includes("assert 8<=len(objects)<=64"));assert(!success.includes('failed-slot-raw-metadata'));
  const prefix=`/usr/bin/python3 -I -S -B - "$root/fs/${slot}-metadata-retained"`;
  assert.equal(failed.slice(0,failed.indexOf(prefix)),success.slice(0,success.indexOf(prefix)));
  assert(failed.includes(JSON.stringify(JSON.stringify({slot,binding:plan.slots[slot].binding,metadataSourceSha256:plan.slots[slot].metadata.guestSourceSha256}))));
 }
 const temporary=await fs.realpath(process.env.TMPDIR||path.join(C.ROOT,'tasks/tmp'));
 assert(temporary.startsWith(C.ROOT+path.sep));
 const directory=await fs.mkdtemp(path.join(temporary,'system-failed-slot-control-'));
 const script=I.FAILED_SLOT_ARCHIVE+String.raw`
import tempfile,shutil,types
parent=sys.argv[1]
# Real private files/bytes/tar stream; only root UID is controlled on the host.
real_lstat=os.lstat;real_fstat=os.fstat
def rootstat(s):return types.SimpleNamespace(**{**{k:getattr(s,k) for k in dir(s) if k.startswith('st_')},'st_uid':0})
os.lstat=lambda *a,**k:rootstat(real_lstat(*a,**k));os.fstat=lambda *a,**k:rootstat(real_fstat(*a,**k))
root=parent+'/slot';os.mkdir(root,0o700)
proof=dict(slot='policy',binding=dict(runId='e'*32,target='v24-policy',base='sha256:'+'a'*64),metadataSourceSha256='b'*64)
def capture():
 output=io.BytesIO();failed_slot_archive(root,proof,output)
 with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as t:return {n:t.extractfile(n).read() for n in t.getnames()}
empty=capture();assert set(empty)=={'failure-provenance.json'}
p=json.loads(empty['failure-provenance.json']);assert p['empty'] and not p['authenticated'] and not p['qualificationComplete'] and p['binding']==proof['binding']
for name in ('objects','partial'):os.mkdir(root+'/'+name,0o700)
raw=b'not JSON\x00partial signed bytes';f=os.open(root+'/partial/0001',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(f,raw);os.close(f)
report=b'{"incomplete":';f=os.open(root+'/result.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(f,report);os.close(f)
out=capture();assert out['raw/partial/0001']==raw and out['raw/result.json']==report
p=json.loads(out['failure-provenance.json']);assert not p['empty'] and p['bytes']==len(raw)+len(report)
for row in p['objects']:assert hashlib.sha256(out['raw/'+row['file']]).hexdigest()==row['sha256']
def denied():
 try:capture()
 except (AssertionError,OSError):return
 raise AssertionError('unsafe failure archive accepted')
os.symlink('result.json',root+'/manifest.json');denied();os.unlink(root+'/manifest.json')
os.link(root+'/result.json',root+'/manifest.json');denied();os.unlink(root+'/manifest.json')
os.mkdir(root+'/unexpected',0o700);denied();os.rmdir(root+'/unexpected')
os.chmod(root+'/result.json',0o644);denied();os.chmod(root+'/result.json',0o600)
os.truncate(root+'/partial/0001',32*1048576+1);denied();os.truncate(root+'/partial/0001',0)
os.mkfifo(root+'/manifest.json',0o600);denied();os.unlink(root+'/manifest.json')
class Broken:
 def write(self,data):raise OSError('sink fault')
try:failed_slot_archive(root,proof,Broken());raise AssertionError('write fault accepted')
except OSError:pass
print('empty-partial-provenance-and-denials')
`;
 try{
  const r=require('node:child_process').spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',script,directory],
   {encoding:'utf8',timeout:10000,maxBuffer:65536});
 assert.equal(r.status,0,r.stderr);assert.equal(r.stdout.trim(),'empty-partial-provenance-and-denials');
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
test('actual paired plan controller and both emitted children compile and enforce phase-specific barriers',async()=>{
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'e'.repeat(32),await recipe());
 const match=/<<'OWASP_AI_GOAT_RELAY_LIFECYCLE'\n([\s\S]*?)\nOWASP_AI_GOAT_RELAY_LIFECYCLE\n/.exec(plan.commands.relayStart);
 assert(match,'real plan must contain its fixed controller');
 const source=match[1]+'\n';
 const program=String.raw`
import ast,sys,json,types,copy,contextlib,io
source=sys.stdin.read();tree=ast.parse(source);compile(tree,'actual-controller','exec')
children=None
for node in tree.body:
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CHILDREN' for t in node.targets):
  children=json.loads(ast.literal_eval(node.value.args[0]))
assert set(children)=={'adapter','connector'}
def definitions(parsed):
 # Execute exact emitted definitions, never its socket-serving entry point or
 # signal/audit registration. Kernel/process observations below are controlled.
 body=[]
 for node in parsed.body:
  if isinstance(node,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.ClassDef)):body.append(node)
  elif isinstance(node,ast.Assign):
   try:ast.literal_eval(node.value)
   except (ValueError,TypeError):continue
   body.append(node)
 return compile(ast.Module(body=body,type_ignores=[]),'actual-definitions','exec')
for mode,child in children.items():
 assert len(child.encode())<=65536
 parsed=ast.parse(child);compile(parsed,'actual-'+mode,'exec');ns={};exec(definitions(parsed),ns)
 assert ns['TRANSPORT_MODE']==mode
 assert ns['HOST_LIMITS']=={'registry-1.docker.io':128*1048576,'auth.docker.io':1048576,'deb.debian.org':132*1048576,'production.cloudfront.docker.com':136*1048576}
 assert ns['TOTAL']==261*1048576
 charged=ns['Budget']();charged.charge('production.cloudfront.docker.com',136*1048576)
 try:charged.charge('production.cloudfront.docker.com',1);raise AssertionError('blob cap overflow')
 except ns['Denied']:pass
 charged.charge('deb.debian.org',125*1048576)
 try:charged.charge('auth.docker.io',1);raise AssertionError('aggregate cap overflow')
 except ns['Denied']:pass
 assert charged.total==261*1048576 and charged.hosts['production.cloudfront.docker.com']==136*1048576
 row=dict(version=1,policy=ns['PAIR_POLICY'],runId=ns['TRANSPORT_RUN'],sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0)
 ns['pair_read']=lambda *args:copy.deepcopy(row)
 budget=ns['Budget']();ns['PAIR_BUDGET']=budget
 for i in range(32):budget.admit()
 try:budget.admit();raise AssertionError('overhead overflow')
 except ns['Denied']:pass
 row.update(sequence=1,phase='system-artifacts',allocation=33,starts=dict(adapter=32,connector=32),quota=1,artifactCount=1)
 budget.admit();assert ns['pair_budget_snapshot']()['connections']==33
 row.update(sequence=2,phase='policy-overhead',allocation=65,starts=dict(adapter=33,connector=33),quota=32,artifactCount=0)
 for i in range(32):budget.admit()
 assert ns['pair_budget_snapshot']()['connections']==65
 try:budget.admit();raise AssertionError('second overhead overflow')
 except ns['Denied']:pass
ns={};exec(definitions(tree),ns)
records={};row=dict(version=1,policy=ns['PAIR_POLICY'],runId=ns['RUN'],sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0)
def save(name,value):
 if name in records:raise FileExistsError(name)
 records[name]=copy.deepcopy(value)
ns.update(save=save,pair_read=lambda *args:copy.deepcopy(row),authority=lambda:None,
 remaining=lambda *args:None,proc=lambda pid:{},check_child=lambda *args:None,
 read=lambda p:'1000' if p.endswith('acquisition.deadline') else json.dumps(dict(pid=11 if 'adapter' in p else 12,start=1,net=2)),
 time=types.SimpleNamespace(monotonic=lambda:100),os=types.SimpleNamespace(listdir=lambda p:[p.split('/')[-2]]))
def checkpoint(end):return dict(rows={m:dict(activeWorkers=0,sequence=1) for m in children})
ns['checkpoint']=checkpoint
with contextlib.redirect_stdout(io.StringIO()):ns['idle']()
row.update(sequence=2,phase='policy-overhead',allocation=65,starts=dict(adapter=33,connector=33))
with contextlib.redirect_stdout(io.StringIO()):ns['idle']()
assert set(records)=={'pair.idle.0.intent','pair.idle.0.result','pair.idle.2.intent','pair.idle.2.result'}
assert all(records['pair.idle.'+str(seq)+'.result']['quiescent'] is True for seq in (0,2))
before=copy.deepcopy(records)
try:ns['idle']();raise AssertionError('idle overwrite')
except FileExistsError:pass
assert records==before
for seq in (0,2):
 records.clear();row['sequence']=seq;row['phase']='system-overhead' if seq==0 else 'policy-overhead'
 row['allocation']=32 if seq==0 else 65;row['starts']=dict(adapter=0,connector=0) if seq==0 else dict(adapter=33,connector=33)
 def failure(end):raise RuntimeError('unjoined worker')
 ns['checkpoint']=failure
 try:ns['idle']();raise AssertionError('failed barrier accepted')
 except RuntimeError as e:assert str(e)=='unjoined worker'
 assert records['pair.idle.'+str(seq)+'.result']['quiescent'] is False
row.update(sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0))
packet=dict(rows={m:dict(activeWorkers=0,admission=dict(workerLimitRejected=7 if m=='adapter' else 0,connectionLimitRejected=0,saturated=False),
 deniedAuthorities=dict(hosts={},unclassified=0,overflow=0),pairBudget=dict(policy=ns['PAIR_POLICY'],lifetime=320,connections=14,credit=copy.deepcopy(row))) for m in children})
ns['checkpoint']=lambda end:copy.deepcopy(packet)
observed,counts,proof=ns['pair_observe']()
assert counts==dict(adapter=14,connector=14) and proof['rows']['adapter']['admission']['workerLimitRejected']==7
for key,value in (('workerLimitRejected',True),('workerLimitRejected',65536),('connectionLimitRejected',1),('saturated',True)):
 prior=packet['rows']['adapter']['admission'][key];packet['rows']['adapter']['admission'][key]=value
 try:ns['pair_observe']();raise AssertionError('bad admission accepted')
 except ns['RelayFailure']:pass
 packet['rows']['adapter']['admission'][key]=prior
`;
 const result=require('node:child_process').spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',program],
  {input:source,encoding:'utf8',timeout:5000,maxBuffer:32768});
 assert.equal(result.status,0,result.stderr);
});
function stage(){
 return {name:'system',packages:[...C.PACKAGES],selection:"'http://deb.debian.org/debian/pool/main/g/gcc/gcc_1_arm64.deb' gcc.deb 123 SHA256:"+'a'.repeat(64),
 selected:[{name:'gcc',version:'1',architecture:'arm64',filename:'pool/main/g/gcc/gcc_1_arm64.deb',sha256:'a'.repeat(64),bytes:123}]};
}
function policyStages(){
 const build={...stage(),name:'build',packages:['gcc','libc6-dev']};
 const runtime={...stage(),name:'runtime',packages:['bubblewrap'],
  selection:stage().selection.replaceAll('gcc','bubblewrap').replaceAll('a'.repeat(64),'b'.repeat(64)),
  selected:[{...stage().selected[0],name:'bubblewrap',filename:stage().selected[0].filename.replaceAll('gcc','bubblewrap'),sha256:'b'.repeat(64)}]};
 return [build,runtime];
}
function metadataPlan(){
 return {binding:{runId:'a'.repeat(32),target:'v24-system',base:C.BASE},commands:{
 inspect:'GUARD\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n',inventory:'inventory'},
 phases:{version:1,preflight:'preflight',prepare:'prepare',namespace:'namespace',relayStart:'relayStart',daemonStart:'daemonStart',
 metadataFetch:'metadataFetch',stop:'stop',evidence:'evidence',retainedExport:'retainedExport',cleanup:'cleanup'}};
}
test('public entry rejects caller runners and forged image capability before work',async()=>{
 await assert.rejects(adapter.withPrivateSystemImage({runner(){throw Error('must not run');}}),/SYSTEM_PRODUCER_OPTIONS/);
 assert.throws(()=>adapter.assertSystemImageCapability({controlled:false,imageId:'sha256:'+'a'.repeat(64)}),/SYSTEM_IMAGE_NOT_LIVE/);
});
test('adapter resolves producer lazily at invocation and forwards exact capability/options without receipt reconstruction',async()=>{
 const filename=path.join(__dirname,'postgres/ownedSystemConfigBuildAdapter.js');
 const source=await fs.readFile(filename,'utf8'),module={exports:{}},calls=[];
 const {createRequire}=require('node:module'),local=createRequire(filename);
 const capability=Object.freeze({}),options=Object.freeze({sentinel:true}),callback=()=>{},owner=Object.freeze({live:true});
 const sentinel=Error('producer denied');let deny=false;
 const producer={assertSystemImageCapability(value){assert.equal(value,capability);if(deny)throw sentinel;return owner;},
  async withPrivateSystemImage(value,fn){assert.equal(value,options);assert.equal(fn,callback);throw sentinel;}};
 vm.runInNewContext('(function(require,module,exports,__dirname,__filename){'+source+'\n})',{Buffer,process,AbortSignal})(
  id=>{calls.push(id);return id==='./ownedSystemImageProducer'?producer:local(id);},module,module.exports,path.dirname(filename),filename);
 assert.equal(calls.includes('./ownedSystemImageProducer'),false,'import alone must not resolve producer/cyclic driver');
 assert.equal(module.exports.assertSystemImageCapability(capability),owner);
 deny=true;assert.throws(()=>module.exports.assertSystemImageCapability(capability),error=>error===sentinel);
 await assert.rejects(module.exports.withPrivateSystemImage(options,callback),error=>error===sentinel);
 assert.equal(calls.filter(id=>id==='./ownedSystemImageProducer').length,3);
});
test('System single stage derives exact Debian-only URLs; V23 stages and npm cannot be relabeled',()=>{
 const good=I.systemArtifacts([stage()]);assert.equal(good.length,1);assert.equal(good[0].kind,'deb');assert.equal(good[0].algorithm,'sha256');
 for(const mutate of [
 s=>s.name='build',s=>s.packages.push('curl'),s=>s.selected[0].bytes++,s=>s.selected[0].sha256='x',
 s=>s.selection=s.selection.replace('deb.debian.org','registry.npmjs.org'),
 s=>s.selection=s.selection.replace('gcc_1_arm64.deb','../gcc_1_arm64.deb'),
 s=>s.selection+='\n'+s.selection,s=>s.selected.push({...s.selected[0]}),
 s=>s.selected[0].architecture='amd64',s=>s.selection=s.selection.replace('http://','http://secret@')
 ]){const s=stage();mutate(s);assert.throws(()=>I.systemArtifacts([s]));}
 assert.throws(()=>I.systemArtifacts([stage(),stage()]));
});
test('tar is exact original55 members and excludes recipe from COPY context',async()=>{
 const capture=await input.captureSystemBuildInputs(C.ROOT,await recipe());
 const archive=await I.contextBytes(C.ROOT,capture),members=[];let offset=0;
 while(archive.subarray(offset,offset+512).some(Boolean)){
  const header=archive.subarray(offset,offset+512),name=header.subarray(0,100).toString().split('\0')[0];
  const size=parseInt(header.subarray(124,136).toString().replace(/\0/g,''),8);
  const checksum=parseInt(header.subarray(148,156).toString().replace(/\0/g,'').trim(),8);
  const checked=Buffer.from(header);checked.fill(32,148,156);assert.equal(checked.reduce((a,b)=>a+b,0),checksum);
  const bytes=archive.subarray(offset+512,offset+512+size),row=capture.context.files.find(x=>x.name===name);
  assert(row);assert.equal(hash(bytes),row.sha256);members.push(name);offset+=512+Math.ceil(size/512)*512;
 }
 assert.deepEqual(members,C.CONTEXT_FILES);assert.equal(members.length,55);assert(!members.includes('Dockerfile'));
 assert.throws(()=>I.tarFile('../bad',Buffer.from('x'),0o644));
});
test('fixed emitted build uses exact recipe outside context and private offline-only Docker',async()=>{
 const captured=await input.captureSystemBuildInputs(C.ROOT,await recipe());
 const commands=I.commandsFor(metadataPlan(),{},captured,{sha256:'f'.repeat(64)});
 assert(commands.build.includes('--pull=false --network=host --platform linux/arm64'));
 assert(commands.build.includes('stop_private_relay'));
 assert(commands.build.indexOf('stop_private_relay')<commands.build.indexOf('300 docker'));
 assert(commands.build.includes('"$root/fs/system.Dockerfile"'));
 assert(commands.startArtifacts.includes('node@'+C.BASE));
 assert(commands.retireArtifacts.includes('State.ExitCode'));assert(commands.retireArtifacts.includes('State.OOMKilled'));
 assert(commands.retireArtifacts.includes('ps --all --quiet --no-trunc'));
 assert(commands.handoff.includes("process('daemon','/usr/bin/dockerd')"));
 const producer=await fs.readFile(path.join(C.ROOT,'tests/postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert(producer.includes('time.monotonic()+300'));assert(producer.includes('$root/fs/daemon.start'));
 assert(!commands.build.includes('npm_ca'));assert(!commands.build.includes('owasp-ai-goat.registry'));
 assert.throws(()=>I.commandsFor({...metadataPlan(),commands:{inspect:'changed'}},{},captured,{sha256:'f'.repeat(64)}),/GUARD_SHAPE/);
});
test('serialized loader compiles with closed shared module inventory, not registry plan or consumer',async()=>{
 const guest=await I.guestSource(C.ROOT,metadataPlan().binding);
 assert.equal(hash(guest.text),guest.sha256);new vm.Script(guest.text);
 assert.deepEqual(Object.keys(guest.hashes).sort(),I.GUEST_MODULES.map(x=>'tests/postgres/'+x+'.js').sort());
 assert(guest.text.includes('apt.authenticate'));assert(!I.GUEST_MODULES.includes('ownedMcpOriginalBuildAdapter'));
});
test('actual inert System plan binds current metadata policy, original context and dependency bytes',async()=>{
 const plan=await adapter.systemBuildPlan(C.ROOT,'e'.repeat(32),await recipe());
 assert.equal(plan.target,'original-v24-system');assert.equal(plan.binding.target,'v24-system');
 assert.equal(plan.captured.context.files.length,55);assert.equal(plan.captured.recipe.base,C.BASE);
 assert.equal(plan.executionApproved,false);assert.equal(plan.runtimeAvailable,false);
 assert.equal(plan.commands.metadataFetch,plan.metadata.phases.metadataFetch);
 assert.equal(plan.commands.stop,plan.metadata.phases.stop);
 assert(plan.commands.build.includes('--pull=false'));
 await adapter.verifyPlan(plan);
 const changed=structuredClone(plan);changed.helperHashes['tests/postgres/ownedAptAuthentication.js']='0'.repeat(64);
 await assert.rejects(adapter.verifyPlan(changed),/SYSTEM_HELPER_CHANGED/);
});

async function guestCase(fault='',mode='legacy',seed=null,target='v24-system'){
 const events=[],files=new Map([['/metadata-retained/result.json',Buffer.from('{}')]]),proc=new EventEmitter();
 if(seed)files.set('/system-closure/closure.json',Buffer.from(JSON.stringify(seed)));
 proc.env={OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS:String(Number(process.hrtime.bigint())/1e9+30),OWASP_AI_GOAT_ARTIFACT_PROXY_PORT:'1234'};
 proc.hrtime=process.hrtime;proc.exitCode=undefined;
 const published=()=>Object.fromEntries([...files].filter(([name])=>name.endsWith('.json')).map(([name,b])=>[path.basename(name),JSON.parse(b)]));
 const fakeFs={
  async readFile(name){return files.get(name);},
  async open(name,flags){
   if(name.endsWith('terminal.json.partial')&&fault==='terminal')throw Error('publication');
   let data=files.get(name)||Buffer.alloc(0);
   return {async writeFile(b){data=Buffer.from(b);files.set(name,data);},async sync(){if(fault==='sync'&&name.endsWith('closure.json.partial'))throw Error('sync');},
    async close(){},async stat(){return {isFile:()=>true,nlink:1,uid:0,mode:0o400,size:data.length};},async readFile(){return data;}};
  },
  async link(from,to){assert(!files.has(to));files.set(to,files.get(from));
   if(to.endsWith('/ready.json'))setImmediate(()=>proc.emit('SIGTERM'));},
  async unlink(name){files.delete(name);}
 };
 const stages=target==='v03-diagnostic'?[{...stage(),name:'diagnostic'}]:target==='v24-system'?[stage()]:policyStages();
 const binding={...metadataPlan().binding,target,base:require('./postgres/ownedPolicySystemBuild').TARGETS[target].base};
 const rows=I.systemArtifacts(stages,target);
 const auth={method:'original-base-apt-closed-replay',binding};
 const apt={async admitRetained(binding){events.push('admit');return {binding};},
  async authenticate(cap,lifecycle){events.push('authenticate');assert(lifecycle.deadline>0);assert(lifecycle.signal instanceof AbortSignal);
   if(fault==='auth')throw Object.assign(Error('apt failed'),{code:'APT_PRIMARY',cleanupDebt:[{pid:12}],replayCleanupError:'JOIN'});
   return auth;}};
 const objectName=require('./postgres/ownedMcpDependencyClosure')._internals.objectName;
 const record={version:1,artifactBytesVerified:true,bytes:{npm:0,deb:rows.reduce((n,r)=>n+r.bytes,0),total:rows.reduce((n,r)=>n+r.bytes,0)},artifacts:rows.map(r=>({...r,actualBytes:r.bytes,file:'objects/'+objectName(r)}))};
 const closure={failureDiagnostic:require('./postgres/ownedMcpDependencyClosure').failureDiagnostic,_internals:{validateArtifacts:()=>{},objectName},async acquireArtifacts(opts){events.push('acquire');assert.deepEqual(JSON.parse(JSON.stringify(opts.artifacts)),rows);
   if(fault && typeof fault==='object')throw fault;
   if(fault==='acquire')throw Object.assign(Error('acquire'),{code:'ACQUIRE'});return record;},
 artifactReader(directory,receipt){assert.equal(directory,'/system-closure/artifacts');assert.deepEqual(JSON.parse(JSON.stringify(receipt)),record);
  return require('./postgres/ownedMcpDependencyClosure').artifactReader(directory,receipt);}};
 let failureResolve;const firstFailure=new Promise(r=>{failureResolve=r;});let failed=null;
 const service={firstFailure,failureRecord:()=>failed,async listen(){events.push('listen');
   if(fault==='listen')throw Object.assign(Error('listen'),{code:'LISTEN'});
   if(fault==='first')setImmediate(()=>{failed={version:1,cause:'CLOSURE_UNLISTED_URL',counters:{requests:1,connections:1,bytes:0,active:1}};failureResolve(failed);});
   return {port:3456};},
 async close(){events.push('close');if(fault==='close')throw Error('close');
 return {closed:true,absenceVerified:true,active:0,failure:failed?.cause||null};}};
 const modules={ownedAptAuthentication:apt,ownedPolicySystemMetadata:{
 validateResultEnvelope:()=>({candidate:{}}),validateRetainedMetadata:()=>({stages,objects:[]})},
 ownedMcpDependencyClosure:closure,ownedMcpArtifactReplay:{replayCertificate:()=>({}),createReplay(opts){events.push('replay');assert(!Object.hasOwn(opts,'npmSourceWitness'));return service;}}};
 const run=vm.runInNewContext('('+I.guestMain.toString()+')',{Buffer,URL,AbortController,setTimeout,clearTimeout,process:proc,
 require:id=>id==='node:fs/promises'?fakeFs:require(id)});
 await run(name=>modules[name],binding,I.systemArtifacts,mode);
 return {events,files:published(),exitCode:proc.exitCode};
}
test('serialized guest authenticates before acquisition, publishes closure, then retires on normal stop',async()=>{
 const f=await guestCase();assert.equal(f.exitCode,0);
 assert.deepEqual(f.events,['admit','authenticate','acquire','replay','listen','close']);
 assert.equal(f.files['closure.json'].acquired.bytes.npm,0);
 assert.equal(f.files['terminal.json'].failure,null);assert.deepEqual(f.files['terminal.json'].cleanupErrors,[]);
});
test('V03 serialized terminal retains bounded sanitized provenance without secrets',async()=>{
 const secret='SECRET_TOKEN_'+ 'x'.repeat(200000);
 const primary=Object.assign(Error(secret),{code:'ECONNRESET',url:'https://secret.invalid/'+secret,closureTransport:'body',closureArtifact:{index:3,kind:'deb',algorithm:'sha256',digest:'a'.repeat(64),stage:'body',url:secret,headers:{authorization:secret}}});
 const f=await guestCase(primary,'legacy',null,'v03-diagnostic'),terminal=f.files['terminal.json'],bytes=JSON.stringify(terminal);
 assert.equal(f.exitCode,1);assert.equal(terminal.failure,'ECONNRESET');assert.deepEqual(terminal.cleanupErrors,[]);assert.equal(terminal.result,null);assert(!f.files['ready.json']);
 assert.deepEqual(terminal.failureDiagnostic,{artifact:{index:3,kind:'deb',algorithm:'sha256',digest:'a'.repeat(64),stage:'body'},transport:'body'});
 assert(Buffer.byteLength(bytes)<1024);for(const value of ['SECRET_TOKEN','secret.invalid','authorization'])assert(!bytes.includes(value));
});
test('V03 serialized terminal rejects invalid diagnostic fields',async()=>{
 const f=await guestCase(Object.assign(Error('secret'),{code:'ECONNRESET',closureTransport:'secret',closureArtifact:{index:-1,kind:'deb',algorithm:'sha256',digest:'a'.repeat(64),stage:'body'}}),'legacy',null,'v03-diagnostic');
 assert.deepEqual(f.files['terminal.json'].failureDiagnostic,{artifact:null,transport:null});assert.equal(f.exitCode,1);
});
test('diagnostic terminal addition leaves non-V03 failure and successful V03 schema unchanged',async()=>{
 const other=await guestCase(Object.assign(Error('secret'),{code:'ECONNRESET'}));
 assert(!Object.hasOwn(other.files['terminal.json'],'failureDiagnostic'));assert.equal(other.exitCode,1);
 const success=await guestCase('','acquire',null,'v03-diagnostic');
 assert.equal(success.exitCode,0);assert(!Object.hasOwn(success.files['acquisition-terminal.json'],'failureDiagnostic'));
});
test('V03 terminal publication failure remains failed without a terminal',async()=>{
 const f=await guestCase('terminal','legacy',null,'v03-diagnostic');assert.equal(f.exitCode,2);assert(!f.files['terminal.json']);
});
test('shared APT cleanup debt vetoes acquisition and is durably retained',async()=>{
 const f=await guestCase('auth');assert.equal(f.exitCode,2);assert(!f.events.includes('acquire'));
 assert.equal(f.files['terminal.json'].failure,'APT_PRIMARY');assert.deepEqual(f.files['terminal.json'].cleanupErrors,['SYSTEM_APT_CLEANUP_DEBT']);
});
test('guest early acquisition/listen failures retain primary without false readiness',async()=>{
 for(const [fault,code]of [['acquire','ACQUIRE'],['listen','LISTEN']]){
  const f=await guestCase(fault);assert.equal(f.exitCode,1);assert.equal(f.files['terminal.json'].failure,code);
  assert(!f.files['ready.json']);if(fault==='listen')assert(f.events.includes('close'));
 }
});
test('guest automatic first-failure finalization does not require SIGTERM',async()=>{
 const f=await guestCase('first');assert.equal(f.exitCode,1);
 assert.equal(f.files['replay-failure.json'].cause,'CLOSURE_UNLISTED_URL');
 assert.equal(f.events.filter(x=>x==='close').length,1);
});
test('publication and replay retirement failure cannot report clean guest exit',async()=>{
 for(const fault of ['terminal','close','sync']){
  const f=await guestCase(fault);assert.equal(f.exitCode,fault==='sync'?1:2);
  if(fault==='close')assert.deepEqual(f.files['terminal.json'].cleanupErrors,['SYSTEM_REPLAY_JOIN']);
  if(fault==='sync')assert(!f.files['ready.json']);
 }
});
test('pair guest acquires each exact original target without starting its replay lease',async()=>{
 for(const target of ['v24-system','v24-policy']){
  const f=await guestCase('','acquire',null,target);assert.equal(f.exitCode,0);
  assert.deepEqual(f.events,['admit','authenticate','acquire']);
  assert.equal(f.files['closure.json'].binding.target,target);
  assert.deepEqual(f.files['acquisition-terminal.json'],{version:1,binding:{...metadataPlan().binding,target,base:require('./postgres/ownedPolicySystemBuild').TARGETS[target].base},result:null,failure:null,cleanupErrors:[]});
  assert(!f.files['ready.json']);assert(!f.files['terminal.json']);
 }
});
test('pair replay-only guest uses retained exact acquisition, never reauthenticates or opens upstream acquisition',async()=>{
 for(const target of ['v24-system','v24-policy']){
  const acquired=await guestCase('','acquire',null,target);
  const replayed=await guestCase('','replay',acquired.files['closure.json'],target);
  assert.equal(replayed.exitCode,0);assert.deepEqual(replayed.events,['replay','listen','close']);
  assert.equal(replayed.files['ready.json'].closureSha256,hash(JSON.stringify(acquired.files['closure.json'])));
  assert.equal(replayed.files['terminal.json'].result.absenceVerified,true);
  const bad=structuredClone(acquired.files['closure.json']);bad.acquired.artifacts[0].digest='0'.repeat(64);
  const failed=await guestCase('','replay',bad,target);assert.equal(failed.exitCode,1);assert.deepEqual(failed.events,[]);
  assert.equal(failed.files['terminal.json'].failure,'SYSTEM_CLOSURE_EVIDENCE');
 }
});
test('renderer artifact stages remain literal, preserve selected URLs, and deduplicate cross-stage objects',()=>{
 const stages=policyStages(),rows=I.systemArtifacts(stages,'v24-policy');assert.equal(rows.length,2);
 assert.deepEqual(rows.flatMap(r=>r.stages).sort(),['build','runtime']);
 const overlap=structuredClone(stages);overlap[1].selection=overlap[0].selection;overlap[1].selected=overlap[0].selected;
 const merged=I.systemArtifacts(overlap,'v24-policy');assert.equal(merged.length,1);assert.deepEqual(merged[0].stages,['build','runtime']);
 for(const mutate of [s=>s.reverse(),s=>s[1].packages.push('curl'),s=>s[0].selected[0].bytes++,s=>s[0].selection=s[0].selection.replace('deb.debian.org','evil.invalid')]){
  const bad=structuredClone(stages);mutate(bad);assert.throws(()=>I.systemArtifacts(bad,'v24-policy'));
 }
 assert.throws(()=>I.systemArtifacts(stages,'v24-system'));assert.throws(()=>I.systemArtifacts(stages,'v33-pricing'));
});
test('actual closed pair plan preserves both recipes, distinct target identities and one acquisition retirement',async()=>{
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'b'.repeat(32),await recipe());
 assert.equal(plan.target,I.PAIR_TARGET);assert.equal(plan.executionApproved,false);assert.equal(plan.runtimeAvailable,false);
 assert.equal(plan.limits.disk,6*1024**3);assert.equal(plan.limits.acquisitionMs,300000);assert.equal(plan.holderLease.totalMs,3636000);
 assert.deepEqual(plan.wirePolicy,require('./postgres/ownedSystemBoundedDerivation').PAIR_WIRE_POLICY);
 for(const mutate of [p=>delete p.wirePolicy,p=>p.wirePolicy.cloudfrontBytes++,p=>p.wirePolicy.totalBytes++,p=>p.wirePolicy.name='arbitrary']){
  const changed=structuredClone(plan);mutate(changed);assert.notEqual(adapter.planDigest(changed),adapter.planDigest(plan));
  await assert.rejects(adapter.verifyPlan(changed),{code:'SYSTEM_PAIR_WIRE_POLICY'});
 }
 assert.equal(plan.slots.system.captured.context.files.length,55);assert.equal(plan.slots.policy.captured.context.files.length,11);
 for(const relative of ['server/services/secureshopSystemConfigClient.js','server/services/secureshopPolicySandboxRuntime.js',
  'server/services/secureshopPromptPolicyContract.js']){
  assert.equal(plan.helperHashes[relative],hash(await fs.readFile(path.join(C.ROOT,relative))));
  const changed=structuredClone(plan);changed.helperHashes[relative]='0'.repeat(64);
  await assert.rejects(adapter.verifyPlan(changed),{code:'SYSTEM_HELPER_CHANGED'});
 }
 assert.notEqual(plan.slots.system.binding.base,plan.slots.policy.binding.base);
 const original=await fs.readFile(path.join(C.ROOT,'sidecars/sandbox-runner/policy-render/Dockerfile'),'utf8');
 assert.equal(plan.slots.policy.captured.recipe.dockerfile,original);
 for(const slot of ['system','policy']){
  const c=plan.commands;
  assert(c[slot+'Metadata'].includes(`source=$root/fs/${slot}-metadata-retained,target=/metadata-retained`));
  assert(c[slot+'Acquire'].includes(`$root/fs/${slot}-acquire.cid`));
  assert(c[slot+'Replay'].includes(`$root/fs/${slot}.cid`));
  assert(c[slot+'AcquireRetire'].includes(`$root/fs/${slot}-closure/acquisition-terminal.json`));
  assert(c[slot+'ReplayRetire'].includes(`$root/fs/${slot}-closure/terminal.json`));
  assert(c[slot+'Replay'].includes('proxy_port=0; deadline=0'));assert(!c[slot+'Replay'].includes('proxy_port=$(relay_control authority)'));
  assert(c[slot+'Build'].includes('--pull=false --network=host --platform linux/arm64'));
  assert(!c[slot+'Build'].includes('\nstop_private_relay\n'));
  assert(c[slot+'Export'].includes(`$root/fs/${slot}-metadata-retained`));
  new vm.Script(plan.slots[slot].acquisitionSource);new vm.Script(plan.slots[slot].replaySource);
 }
 assert(plan.commands.policyBuild.includes('-f "$root/fs/policy-context/policy-render/Dockerfile"'));
 assert(plan.commands.acquisitionRetire.endsWith('stop_private_relay\n'));
 assert(I.PAIR_PHASES.indexOf('policyAcquireRetire')<I.PAIR_PHASES.indexOf('acquisitionRetire'));
 assert(I.PAIR_PHASES.indexOf('acquisitionRetire')<I.PAIR_PHASES.indexOf('systemReplay'));
 assert(I.PAIR_PHASES.indexOf('systemReplayRetire')<I.PAIR_PHASES.indexOf('policyReplay'));
 await adapter.verifyPlan(plan);
 const bytes=await I.rendererContextBytes(C.ROOT,plan.slots.policy.captured);
 let offset=0;const names=[];while(bytes.subarray(offset,offset+512).some(Boolean)){
  const name=bytes.subarray(offset,offset+100).toString().split('\0')[0],size=parseInt(bytes.subarray(offset+124,offset+136).toString().replace(/\0/g,''),8);
  const row=plan.slots.policy.captured.context.files.find(r=>r.name===name);assert(row);assert.equal(hash(bytes.subarray(offset+512,offset+512+size)),row.sha256);
  names.push(name);offset+=512+Math.ceil(size/512)*512;
 }
 assert.deepEqual(names,plan.slots.policy.captured.context.files.map(r=>r.name));
 const shellQuote=value=>/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)?value:"'"+value.replaceAll("'","'\"'\"'")+"'";
 const {spawnSync}=require('node:child_process');let maximum=0;
 for(const [name,command]of Object.entries(plan.commands)){
  const parsed=spawnSync('/bin/sh',['-n'],{input:command,encoding:'utf8',timeout:3000,maxBuffer:65536});
  assert.equal(parsed.status,0,name+': '+parsed.stderr);
  const argv=['sudo','-n','timeout','--signal=TERM','--kill-after=10','310','/bin/sh','-c',command,'owned-system-build',plan.spec.guest,plan.runId];
  if(name.endsWith('Metadata'))argv.push(plan.slots[name.startsWith('policy')?'policy':'system'].binding.base);
  maximum=Math.max(maximum,Buffer.byteLength(argv.map(shellQuote).join(' '))+1);
 }
 assert(maximum<131072,'actual one-layer SSH command must fit Linux per-argument ceiling: '+maximum);
});
async function pairObservationFixture(){
 // Reuse source-owned synthetic DTO builders without registering/executing
 // their tests. These are controlled witnesses, never signed native evidence.
 const filename=path.join(__dirname,'ownedPolicySystemMetadata.test.js'),source=await fs.readFile(filename,'utf8');
 const local=require('node:module').createRequire(filename),module={exports:{}};
 vm.runInNewContext('(function(require,module,exports){'+source+'\nmodule.exports={systemRetainedEnvelope,rendererRetainedEnvelope};})',
  {Buffer,structuredClone,URL,AbortController})(id=>id==='node:test'?()=>{}:local(id),module,module.exports);
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'a'.repeat(32),await recipe());
 const pins=require('./postgres/ownedMcpBoundedBuild').PINS;
 const network={version:1,bridge:{},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:[],firewall6:[],nft:[],forwarding:{}};
 const inventory=JSON.stringify(pins.daemon)+'\n'+pins.postgres+' postgres:18\nNETWORK\n'+JSON.stringify(network);
 const values={inventory,inspect:JSON.stringify({ID:'controlled-private-daemon-id',DockerRootDir:plan.spec.mount+'/data',Driver:'overlay2',Architecture:'arm64'}),handoff:JSON.stringify(physical(plan))};
 for(const slot of ['system','policy']){
  const envelope=module.exports[slot==='system'?'systemRetainedEnvelope':'rendererRetainedEnvelope']();
  assert.deepEqual(JSON.parse(JSON.stringify(envelope.binding)),plan.slots[slot].binding);
  const retained=envelope.candidate.retainedMetadata,artifacts=I.systemArtifacts(retained.stages,envelope.binding.target),total=artifacts.reduce((n,row)=>n+row.bytes,0);
  const record={version:1,binding:envelope.binding,authentication:{binding:envelope.binding,version:1,method:'original-base-apt-closed-replay',
   retainedManifestSha256:hash(JSON.stringify(retained)),keyringSha256:envelope.candidate.keyringSha256,installedStatusSha256:envelope.candidate.installedStatusSha256,
   stages:retained.stages.map(stage=>({name:stage.name,selectionSha256:hash(stage.selection)})),expandedBytes:envelope.candidate.expandedBytes},
   acquired:{version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,qualificationComplete:false,bytes:{deb:total,npm:0,total},
    artifacts:artifacts.map(row=>({...row,actualBytes:row.bytes,file:'objects/'+require('./postgres/ownedMcpDependencyClosure')._internals.objectName(row)})),
    attemptProof:{version:1,attempts:artifacts.map((row,index)=>({index,kind:row.kind,digest:row.digest,ordinal:1,outcome:'verified'}))}}};
  const raw=JSON.stringify(record),acquisition={version:1,binding:envelope.binding,result:null,failure:null,cleanupErrors:[]};
  const ready={version:1,binding:envelope.binding,port:slot==='system'?23001:23002,closureSha256:hash(raw),metadataAuthenticated:true,artifactBytesVerified:true};
  const packet={'closure.json':raw,'acquisition-terminal.json':JSON.stringify(acquisition),'ready.json':null,'replay-intent.json':null,'replay-failure.json':null,'terminal.json':null};
  const terminal={version:1,binding:envelope.binding,result:{failure:null,closed:true,absenceVerified:true,active:0},failure:null,cleanupErrors:[]};
  values[slot+'Metadata']=JSON.stringify(envelope);values[slot+'Acquire']=JSON.stringify(acquisition);
  values[slot+'MetadataRetire']='absent\n';values[slot+'AcquireRetire']='absent\n';values[slot+'ReplayRetire']='absent\n';values[slot+'Replay']=JSON.stringify(ready);
  values[slot+'Evidence']=[JSON.stringify(packet),JSON.stringify({...packet,'ready.json':JSON.stringify(ready),'terminal.json':JSON.stringify(terminal)})];
  values[slot+'Image']=JSON.stringify([{Id:'sha256:'+(slot==='system'?'1':'2').repeat(64),Architecture:'arm64',Os:'linux',Config:{User:plan.slots[slot].captured.recipe.user,
   Entrypoint:plan.slots[slot].captured.recipe.entrypoint,Labels:{['owasp-ai-goat.'+slot+'.inputs']:plan.slots[slot].captured.inputSha256,'owasp-ai-goat.build-run':plan.runId}}}]);
 }
 const policy=plan.connectionPolicy.name,phases=['system-overhead','system-artifacts','policy-overhead','policy-artifacts','sealed'];
 let credit={version:1,policy,runId:plan.runId,sequence:0,phase:phases[0],allocation:32,starts:{adapter:0,connector:0},quota:32,artifactCount:0},connections=0,sequence=0;
 const snapshot=()=>({version:1,runId:plan.runId,variant:'metadata-idle-barrier-v4',rows:Object.fromEntries(['adapter','connector'].map(mode=>[mode,{
  kind:'transport-audit',variant:'metadata-idle-barrier-v4',runId:plan.runId,mode,sequence:++sequence,trigger:'checkpoint',activeWorkers:0,
  counts:{dnsSubprocesses:0,externalConnectAttempts:0,unixConnectAttempts:0,peerChecks:0,peerDenied:0},
  // Retained successful 1c9dd0 overhead: adapter7, connector0. This is not an
  // artifact retry allowance; the count must stay unchanged through artifacts.
  deniedAuthorities:{hosts:{},unclassified:0,overflow:0},admission:{workerLimitRejected:mode==='adapter'?7:0,connectionLimitRejected:0,saturated:false},
  pairBudget:{policy,lifetime:320,connections,credit:structuredClone(credit)}}]))});
 for(const [i,name]of I.PAIR_CREDIT_PHASES.entries()){
  connections+=i%2===0?14:credit.artifactCount;
  const before=snapshot(),slot=i===0?'system':'policy';
  const quota=i%2===0?I.systemArtifacts(JSON.parse(values[slot+'Metadata']).candidate.retainedMetadata.stages,plan.slots[slot].binding.target).length:i===1?32:0;
  const artifactCount=i%2===0?quota:0,allocation=credit.allocation+quota;
  credit={version:1,policy,runId:plan.runId,sequence:i+1,phase:phases[i+1],allocation,starts:{adapter:connections,connector:connections},quota:artifactCount?Math.min(2*artifactCount,allocation-connections):quota,artifactCount};
  values[name]=JSON.stringify({version:1,policy,runId:plan.runId,before,after:snapshot()});
 }
 const indices={};const observations=I.PAIR_PHASES.map(name=>({name,value:Array.isArray(values[name])?values[name][indices[name]=(indices[name]??-1)+1]:values[name]||''}));
 return {plan,observations};
}
test('failure export selection preserves a complete slot only after actual target-bound metadata validation',async()=>{
 const {plan,observations}=await pairObservationFixture();
 for(const slot of ['system','policy']){
  assert.equal(I.pairMetadataComplete(plan,observations,slot),true);
  assert.equal(I.pairMetadataComplete(plan,observations.filter(r=>r.name!==slot+'Metadata'),slot),false);
  for(const change of [v=>v.binding.runId='f'.repeat(32),v=>v.ok=false,v=>delete v.candidate.retainedMetadata,
    v=>v.candidate.retainedMetadata.objects[0].bytes++]){
   const rows=structuredClone(observations),row=rows.find(r=>r.name===slot+'Metadata'),value=JSON.parse(row.value);change(value);row.value=JSON.stringify(value);
   assert.equal(I.pairMetadataComplete(plan,rows,slot),false);
  }
 }
});
test('pair phase credit proofs use real admission counters and exact signed acquisition joins before advancement',async()=>{
 const {plan,observations}=await pairObservationFixture();
 const terminal=I.validatePairCredits(plan,observations);assert.equal(terminal.phase,'sealed');assert.equal(terminal.quota,0);
 for(const name of I.PAIR_PHASES){
  const prior=observations.slice(0,observations.findIndex(row=>row.name===name));
  I.validatePairPhaseAdmission(plan,prior,name);
 }
 for(const change of [
  p=>p.after.rows.adapter.pairBudget.connections++,p=>p.after.rows.connector.pairBudget.credit.quota++,
  p=>p.before.rows.adapter.admission.connectionLimitRejected++,p=>p.before.rows.adapter.activeWorkers++,
  p=>p.after.rows.adapter.pairBudget.credit.sequence=0,p=>p.after.rows.adapter.pairBudget.credit.allocation=321,
  p=>p.after.rows.adapter.runId='b'.repeat(32),p=>delete p.after.rows.adapter.pairBudget,
  p=>p.after.rows.adapter.pairBudget.connections=p.after.rows.adapter.counts.peerChecks,
 ]){const copy=structuredClone(observations),row=copy.find(r=>r.name==='systemReserve'),p=JSON.parse(row.value);change(p);row.value=JSON.stringify(p);assert.throws(()=>I.validatePairCredits(plan,copy));}
 const rows=structuredClone(observations),e=rows.find(r=>r.name==='systemEvidence'),p=JSON.parse(e.value),c=JSON.parse(p['closure.json']);
 c.authentication.method='candidate-only';p['closure.json']=JSON.stringify(c);e.value=JSON.stringify(p);
 assert.throws(()=>I.validatePairPhaseAdmission(plan,rows.slice(0,rows.findIndex(r=>r.name==='policyOverhead')),'policyOverhead'),/CLOSURE/);
});
test('retained overhead rejection counts do not authorize artifact, ACK, rollback or saturated counters',async()=>{
 const {plan,observations}=await pairObservationFixture();
 for(const [name,side,mutate] of [
  ['systemReserve','before',r=>r.admission.workerLimitRejected=65536],
  ['systemReserve','before',r=>r.admission.workerLimitRejected=true],
  ['systemReserve','before',r=>r.admission.saturated=true],
  ['systemReserve','after',r=>r.admission.workerLimitRejected++],
  ['policyOverhead','before',r=>r.admission.workerLimitRejected++],
  ['policyReserve','before',r=>r.admission.workerLimitRejected--],
  ['acquisitionSeal','before',r=>r.admission.workerLimitRejected++],
  ['policyReserve','before',r=>r.deniedAuthorities.unclassified++],
 ]){
  const copy=structuredClone(observations),row=copy.find(r=>r.name===name),proof=JSON.parse(row.value);
  mutate(proof[side].rows.adapter);row.value=JSON.stringify(proof);assert.throws(()=>I.validatePairCredits(plan,copy));
 }
 const copy=structuredClone(observations);
 for(const name of ['policyReserve','acquisitionSeal']){
  const row=copy.find(r=>r.name===name),proof=JSON.parse(row.value);
  for(const side of ['before','after'])proof[side].rows.adapter.admission.workerLimitRejected=9;
  row.value=JSON.stringify(proof);
 }
 I.validatePairCredits(plan,copy); // Only the second overhead introduced two.
});
async function pairRelayFixture(){
 const {plan,observations}=await pairObservationFixture(),credit=I.validatePairCredits(plan,observations),files={};
 for(const mode of ['adapter','connector']){
  const last=JSON.parse(observations.find(r=>r.name==='acquisitionSeal').value).after.rows[mode];
  const n=credit.starts[mode],terminal={kind:'relay-terminal',connections:n,bytes:9,
   hostBytes:{'registry-1.docker.io':0,'auth.docker.io':0,'deb.debian.org':9,'production.cloudfront.docker.com':0},
   records:Array.from({length:n},()=>({host:'deb.debian.org',status:'closed'})),unjoinedWorkers:0,unresolvedResolverCleanup:0,cleanupVerified:true};
  // Exact public host/status projection from the successful System metadata
  // terminal e3a4cdf1efda56a0a99fc97d95840e313dddc0395ee8117446e3e257ffaef020,
  // tasks/qualification/v24-system-metadata-1c9dd0cde95443a0ac36a1feb2d18bbf/terminal.json.
  // Embedded so CI needs no ignored capture. Four denials have no claimed cause.
  const retainedOverhead=[
   ['registry-1.docker.io','closed'],['auth.docker.io','closed'],
   ['registry-1.docker.io','closed'],['registry-1.docker.io','closed'],
   ['registry-1.docker.io','denied'],['registry-1.docker.io','denied'],
   ['production.cloudfront.docker.com','denied'],['production.cloudfront.docker.com','denied'],
   ...Array.from({length:6},()=>['deb.debian.org','closed']),
  ].map(([host,status])=>({host,status}));
  terminal.records.splice(0,14,...retainedOverhead);
  terminal.records.forEach((row,index)=>{row.connection=index+1;});
  const policyStart=JSON.parse(observations.find(r=>r.name==='policyOverhead').value).after.rows[mode].pairBudget.connections;
  terminal.records[policyStart].status='denied'; // Controlled second overhead.
  files['relay.'+mode+'.log']=JSON.stringify(terminal)+'\n'+JSON.stringify({...last,trigger:'terminal'})+'\n';
 }
 return {plan,observations,packet:{runId:plan.runId,files}};
}
test('successful sealed acquisition requires complete bounded terminal admission records, not peer counters',async()=>{
 const {plan,observations,packet}=await pairRelayFixture();I.validatePairRelayTerminal(plan,observations,JSON.stringify(packet));
 // Matching actual wire limits; no caller policy can enlarge them or the total.
 for(const mode of ['adapter','connector']){
  const rewrite=changes=>{const copy=structuredClone(packet),rows=copy.files['relay.'+mode+'.log'].trim().split('\n').map(JSON.parse);
   Object.assign(rows[0].hostBytes,changes);rows[0].bytes=Object.values(rows[0].hostBytes).reduce((a,b)=>a+b,0);
   copy.files['relay.'+mode+'.log']=rows.map(JSON.stringify).join('\n');return JSON.stringify(copy);};
  I.validatePairRelayTerminal(plan,observations,rewrite({'production.cloudfront.docker.com':136*1024**2}));
  assert.throws(()=>I.validatePairRelayTerminal(plan,observations,rewrite({'production.cloudfront.docker.com':136*1024**2+1})));
  I.validatePairRelayTerminal(plan,observations,rewrite({'production.cloudfront.docker.com':136*1024**2,'deb.debian.org':125*1024**2}));
  assert.throws(()=>I.validatePairRelayTerminal(plan,observations,rewrite({'production.cloudfront.docker.com':136*1024**2,'deb.debian.org':125*1024**2,'auth.docker.io':1})));
 }
 const falsePolicy=structuredClone(plan);falsePolicy.wirePolicy.cloudfrontBytes++;
 assert.throws(()=>I.validatePairRelayTerminal(falsePolicy,observations,JSON.stringify(packet)));
 for(const mutate of [
  row=>row.connections++,row=>row.records.pop(),row=>row.records[14].status='denied',row=>row.bytes++,
  row=>row.records[0].status='unknown',row=>row.records[0].host='unknown.invalid',
  row=>row.records[row.records.length-1].status='denied',
  row=>row.unjoinedWorkers++,row=>row.cleanupVerified=false
 ]){const copy=structuredClone(packet),rows=copy.files['relay.adapter.log'].trim().split('\n').map(JSON.parse);mutate(rows[0]);
  copy.files['relay.adapter.log']=rows.map(JSON.stringify).join('\n');assert.throws(()=>I.validatePairRelayTerminal(plan,observations,JSON.stringify(copy)));}
 for(const mutate of [row=>row.admission.workerLimitRejected++,row=>row.admission.connectionLimitRejected++,
  row=>row.admission.saturated=true,row=>row.deniedAuthorities.unclassified++,row=>row.counts.peerDenied++]){
  const copy=structuredClone(packet),rows=copy.files['relay.adapter.log'].trim().split('\n').map(JSON.parse);mutate(rows[1]);
  copy.files['relay.adapter.log']=rows.map(JSON.stringify).join('\n');assert.throws(()=>I.validatePairRelayTerminal(plan,observations,JSON.stringify(copy)));
 }
 // Maximum permitted records, four before/after grants and both process audit
 // snapshots remain below the unchanged raw evidence bound (not a new cap).
 const maximumRecords=JSON.stringify({records:Array.from({length:320},()=>({host:'production.cloudfront.docker.com',status:'closed'}))});
 const grants=observations.filter(r=>I.PAIR_CREDIT_PHASES.includes(r.name));
 assert(2*Buffer.byteLength(maximumRecords)+grants.reduce((n,r)=>n+Buffer.byteLength(r.value),0)+32768<262144);
});
test('retained artifact record37 failure is privately branded only after every later safety join',async()=>{
 const {plan,observations,packet}=await pairRelayFixture();
 const rewrite=(p,mode,mutate)=>{const key='relay.'+mode+'.log',rows=p.files[key].trim().split('\n').map(JSON.parse);mutate(rows);p.files[key]=rows.map(JSON.stringify).join('\n');};
 // Exact public record37 projection from run22oo5nit/039-evidence.stdout:
 // System artifact interval[14,49), adapter deb.debian.org denied; connector
 // closed. This asserts no cause/errno and retains the original rejection.
 // Reapply that actual record to this controlled one-artifact System segment;
 // the synthetic census is not relabeled as the native35-object census.
 const artifactStart=JSON.parse(observations.find(r=>r.name==='systemReserve').value).before.rows.adapter.pairBudget.connections;
 rewrite(packet,'adapter',rows=>{rows[0].records[artifactStart]={host:'deb.debian.org',status:'denied',connection:artifactStart+1};});
 let denied;try{I.validatePairRelayTerminal(plan,observations,JSON.stringify(packet));assert.fail('denied admitted');}catch(e){denied=e;}
 assert.equal(denied.code,'SYSTEM_PAIR_RELAY_TERMINAL');assert.equal(I.isPairRelayQualificationFailure(denied),true);
 assert.equal(I.isPairRelayQualificationFailure({code:denied.code}),false);
 assert.equal(I.isPairRelayQualificationFailure(Object.assign(Error(denied.message),denied)),false);
 for(const change of [rows=>rows[0].unjoinedWorkers++,rows=>rows[0].unresolvedResolverCleanup++,
  rows=>rows[0].records.at(-1).host='unknown.invalid',rows=>rows[0].records.at(-1).status='unknown',
  rows=>rows[0].hostBytes['production.cloudfront.docker.com']=136*1024**2+1,
  rows=>rows[1].deniedAuthorities.unclassified++,rows=>rows[1].admission.connectionLimitRejected++]){
  const copy=structuredClone(packet);rewrite(copy,'connector',change);
  assert.throws(()=>I.validatePairRelayTerminal(plan,observations,JSON.stringify(copy)),e=>{
   assert.equal(e.code,'SYSTEM_PAIR_RELAY_TERMINAL');assert.equal(I.isPairRelayQualificationFailure(e),false);return true;
  });
 }
});
test('pair claim validates both complete target-specific metadata/auth/body/image/replay observations, not a success flag',async()=>{
 const {plan,observations}=await pairObservationFixture();
 const result=await I.validatePairDriverObservations(plan,observations);assert.equal(result.target,I.PAIR_TARGET);
 assert.equal(result.runtimeAvailable,false);assert.notEqual(result.images.system.imageId,result.images.policy.imageId);
 assert(Object.isFrozen(result.images.policy));assert.equal(I.validatePairAcquisitionBudget(plan,observations),10);
 const consumer=require('./postgres/ownedSystemPrivateHttpConsumer')._internals;
 const handoff=JSON.parse(observations.find(row=>row.name==='handoff').value);
 const {version,target,runId,...coordinates}=handoff;
 assert.deepEqual(result.physical,coordinates);
 for(const slot of ['system','policy']){
  const binding={version:1,target:'original-v24-'+slot,runId:plan.runId,daemonId:result.daemonId,
   imageId:result.images[slot].imageId,inputSha256:result.images[slot].inputSha256,physical:result.physical};
  assert.deepEqual(consumer.validateBinding(binding),binding);
  assert.throws(()=>consumer.validateBinding({...binding,physical:handoff}),/SYSTEM_BINDING/);
  assert.throws(()=>consumer.validateBinding({...binding,physical:{...result.physical,extra:true}}),/SYSTEM_BINDING/);
 }
 for(const mutate of [
  rows=>{const r=rows.find(row=>row.name==='handoff'),p=JSON.parse(r.value);p.runId='f'.repeat(32);r.value=JSON.stringify(p);},
  rows=>{const r=rows.find(row=>row.name==='handoff'),p=JSON.parse(r.value);p.target='original-v24-policy';r.value=JSON.stringify(p);},
  rows=>rows.pop(),rows=>rows.find(r=>r.name==='policyReplayRetire').value='present',
  rows=>rows.find(r=>r.name==='policyImage').value=rows.find(r=>r.name==='systemImage').value,
  rows=>{const r=rows.findLast(r=>r.name==='policyEvidence'),p=JSON.parse(r.value),t=JSON.parse(p['terminal.json']);t.result.absenceVerified=false;p['terminal.json']=JSON.stringify(t);r.value=JSON.stringify(p);},
  rows=>{const r=rows.find(r=>r.name==='policyEvidence'),p=JSON.parse(r.value),c=JSON.parse(p['closure.json']);c.authentication.stages.pop();p['closure.json']=JSON.stringify(c);r.value=JSON.stringify(p);},
  rows=>{const r=rows.find(r=>r.name==='systemEvidence'),p=JSON.parse(r.value),c=JSON.parse(p['closure.json']);c.acquired.bytes.total++;p['closure.json']=JSON.stringify(c);r.value=JSON.stringify(p);},
  rows=>{const r=rows.find(r=>r.name==='policyMetadata'),e=JSON.parse(r.value);e.binding.base=plan.binding.base;r.value=JSON.stringify(e);}
 ]){const copy=structuredClone(observations);mutate(copy);await assert.rejects(I.validatePairDriverObservations(plan,copy));}
});
test('combined target Debian accounting accepts exactly128MiB and rejects the next byte before policy acquisition',async()=>{
 const {plan,observations}=await pairObservationFixture();
 for(const slot of ['system','policy']){
  const row=observations.find(r=>r.name===slot+'Metadata'),value=JSON.parse(row.value),candidate=value.candidate;
  candidate.selected[0].bytes=64*1024**2;candidate.selection=candidate.selection.replace(' 5 SHA256:',' '+64*1024**2+' SHA256:');
  for(const stage of candidate.retainedMetadata.stages){stage.selected=structuredClone(candidate.selected);stage.selection=candidate.selection;}
  row.value=JSON.stringify(value);
 }
 assert.equal(I.validatePairAcquisitionBudget(plan,observations),128*1024**2);
 const row=observations.find(r=>r.name==='systemMetadata'),value=JSON.parse(row.value),candidate=value.candidate;
 const extra={name:'gcc',version:'1',architecture:'arm64',filename:'pool/main/g/gcc/gcc_1_arm64.deb',bytes:1,sha256:'e'.repeat(64)};
 candidate.selected.push(extra);candidate.selection+="\n'http://deb.debian.org/debian/"+extra.filename+"' gcc_1_arm64.deb 1 SHA256:"+extra.sha256;
 candidate.retainedMetadata.stages[0].selected=structuredClone(candidate.selected);
 candidate.retainedMetadata.stages[0].selection=candidate.selection;candidate.retainedMetadata.stages[0].simulation+='Inst gcc (1 Debian [arm64])\n';
 row.value=JSON.stringify(value);
 assert.throws(()=>I.validatePairAcquisitionBudget(plan,observations),{code:'SYSTEM_PAIR_ARTIFACT_BOUND'});
});
test('actual emitted acquisition wait admits only completed publication with real exited/zero and no OOM',async t=>{
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'pair-wait-'));
 t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'d'.repeat(32),await recipe());
 await fs.mkdir(path.join(directory,'fs','policy-closure'),{recursive:true});
 const terminal=path.join(directory,'fs','policy-closure','acquisition-terminal.json');await fs.writeFile(terminal,'{"completed":true}');
 const source=plan.commands.policyAcquire.slice(plan.commands.policyAcquire.indexOf('\nattempt=0\n'));
 const {spawnSync}=require('node:child_process');
 const execute=(running,exitCode,oom)=>spawnSync('/bin/sh',['-c',
  'set -eu\nroot=$1; cid=controlled\nsystem_identity(){ :; }\ndocker(){ case "$*" in *State.Running*) printf "%s" "$RUNNING";; *State.ExitCode*) printf "%s" "$EXIT_CODE";; *State.OOMKilled*) printf "%s" "$OOM";; *) exit 98;; esac; }\nsleep(){ exit 96; }\n'+source,'controlled',directory],
  {encoding:'utf8',timeout:3000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin',RUNNING:running,EXIT_CODE:exitCode,OOM:oom}});
 assert.equal(execute('false','0','false').status,0);
 for(const args of [['false','1','false'],['false','0','true'],['unknown','0','false'],['true','0','false']])assert.notEqual(execute(...args).status,0);
 await fs.unlink(terminal);assert.notEqual(execute('false','0','false').status,0);
});
test('actual emitted context unpackers consume original tar bytes and reject a changed member before recipe publication',async t=>{
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'pair-unpack-'));t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const plan=await adapter.systemPolicyBuildPlan(C.ROOT,'c'.repeat(32),await recipe());
 const {spawnSync}=require('node:child_process');
 for(const slot of ['system','policy']){
  const bytes=await(slot==='system'?I.contextBytes:I.rendererContextBytes)(C.ROOT,plan.slots[slot].captured);
  const command=plan.commands[slot+'Build'],start=command.indexOf('/usr/bin/python3 -I -S -B -c ',command.indexOf('\ncheck_mount; check_runtime; system_identity\n'));
  const end=command.indexOf('\nport=$(',start);assert(start>0&&end>start);
  const unpack=command.slice(start,end),root=path.join(directory,slot);await fs.mkdir(path.join(root,'fs'),{recursive:true});
  const run=spawnSync('/bin/sh',['-c','set -eu\nroot=$1\n'+unpack,'controlled',root],{input:bytes,timeout:5000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin'}});
  assert.equal(run.status,0,run.stderr.toString());
  assert.equal(await fs.readFile(path.join(root,'fs',slot+'.Dockerfile'),'utf8'),plan.slots[slot].captured.recipe.dockerfile);
  for(const row of plan.slots[slot].captured.context.files)assert.equal(hash(await fs.readFile(path.join(root,'fs',slot+'-context',row.name))),row.sha256);
  const badRoot=path.join(directory,slot+'-bad');await fs.mkdir(path.join(badRoot,'fs'),{recursive:true});
  const bad=Buffer.from(bytes);bad[512]^=1;
  const failed=spawnSync('/bin/sh',['-c','set -eu\nroot=$1\n'+unpack,'controlled',badRoot],{input:bad,timeout:5000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin'}});
  assert.notEqual(failed.status,0);await assert.rejects(fs.access(path.join(badRoot,'fs',slot+'.Dockerfile')));
 }
});
test('wrong plan and pre-abort invoke no phase driver',async()=>{
 let calls=0;
 const plan={};const options={expectedPlanSha256:adapter.planDigest(plan),phase:async()=>{calls++;},record:async()=>{},verify:async()=>{}};
 await assert.rejects(I.runControlledPipeline(plan,{...options,expectedPlanSha256:'a'.repeat(64)}),/PLAN_ADMISSION/);
 const c=new AbortController();c.abort();await assert.rejects(I.runControlledPipeline(plan,{...options,signal:c.signal}));
 assert.equal(calls,0);
});

function physical(plan){
 return {version:1,target:I.TARGET,runId:plan.runId,privateDockerHost:'unix://'+plan.spec.socket,
 namespaceInode:'net:[1234]',filesystemIdentity:{device:1,inode:2},
 daemonProcess:{pid:101,startTicks:'123',exe:'/usr/bin/dockerd'},
 namespaceHolder:{pid:102,startTicks:'124',exe:'/usr/bin/sleep'}};
}
test('typed physical handoff binds System target, private socket and complete process identity',()=>{
 const plan={runId:'a'.repeat(32),spec:{socket:'/var/tmp/owned/fs/docker.sock'}};
 assert(Object.isFrozen(I.validatePhysicalHandoff(physical(plan),plan)));
 for(const mutate of [
 h=>h.target='original-v23-registry',h=>h.privateDockerHost='unix:///var/run/docker.sock',
 h=>h.daemonProcess.startTicks='',h=>h.namespaceHolder.pid=h.daemonProcess.pid,
 h=>h.daemonProcess.exe='/bin/sh',h=>h.filesystemIdentity.inode=0,
 h=>h.extra=true,h=>h.runId='b'.repeat(32)
 ]){const h=physical(plan);mutate(h);assert.throws(()=>I.validatePhysicalHandoff(h,plan));}
});
const RETAINED='tasks/qualification/v24-system-metadata-1c9dd0cde95443a0ac36a1feb2d18bbf';
async function retainedAvailable(){try{await fs.access(path.join(C.ROOT,RETAINED,'validated-envelope.json'));return true;}catch{return false;}}
async function pipelineCase(fault='',diagnostic=false){
 // Retained metadata is actual acquisition evidence; image/phase outcomes below
 // are explicitly controlled simulations, not real build or runtime evidence.
 const raw=await fs.readFile(path.join(C.ROOT,RETAINED,'validated-envelope.json'));
 assert.equal(hash(raw),'dc714b838f6277ff9fa9ffbed331684c75bc8eb4b82dfe792da7dba4bf335b14');
 const source=await fs.readFile(path.join(C.ROOT,RETAINED,'acquisition-output.json'));
 assert.equal(hash(source),'54c5fd3ae2f800800c7feb9514ffd5b25a3196c4ef169b06563ec42f54b2efe7');
 // The launcher validation copy sorts object keys. Replay the retained actual
 // guest bytes: sourcePolicy's original object/array ordering is authenticated.
 let wireRaw=JSON.parse(source).raw;
 const envelope=JSON.parse(wireRaw),captured=diagnostic
  ?await require('./postgres/ownedSystemDiagnosticBuildInputs').captureDiagnosticBuildInputs(C.ROOT)
  :await input.captureSystemBuildInputs(C.ROOT,await recipe());
 assert.deepEqual(envelope,JSON.parse(raw));
 if(diagnostic){
  // Synthetic diagnostic-shaped control, not a claim that historical System
  // acquisition authenticated the diagnostic target.
  envelope.binding.target='v03-diagnostic';
  envelope.candidate.sourcePolicy.policy='v03-diagnostic-trixie-freshness-v1';
  envelope.candidate.retainedMetadata.kind='v03-diagnostic-original-apt-retention';
  envelope.candidate.retainedMetadata.binding={...envelope.binding};
  envelope.candidate.retainedMetadata.stages[0].name='diagnostic';
  wireRaw=JSON.stringify(envelope);
 }
 const spec=require('./postgres/ownedMcpBoundedBuild').specification(C.ROOT,envelope.binding.runId);
 const plan={version:1,target:diagnostic?'original-v03-diagnostic':I.TARGET,runId:envelope.binding.runId,binding:envelope.binding,spec,captured,
 commands:{},guestSource:'controlled-guest',metadataGuestSource:'controlled-metadata',helperHashes:{},metadata:{buildSources:{}}};
 const rows=I.systemArtifacts(envelope.candidate.retainedMetadata.stages,diagnostic?'v03-diagnostic':'v24-system');
 const bytes=rows.reduce((n,r)=>n+r.bytes,0);
 const actual=JSON.parse(wireRaw),retained=actual.candidate.retainedMetadata;
 const closure={version:1,binding:plan.binding,authentication:{binding:plan.binding,version:1,method:'original-base-apt-closed-replay',
 retainedManifestSha256:hash(JSON.stringify(retained)),keyringSha256:actual.candidate.keyringSha256,
 installedStatusSha256:actual.candidate.installedStatusSha256,stages:retained.stages.map(s=>({name:s.name,selectionSha256:hash(s.selection)})),expandedBytes:actual.candidate.expandedBytes},
 acquired:{version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,qualificationComplete:false,
 bytes:{deb:bytes,npm:0,total:bytes},artifacts:rows.map(r=>({...r,actualBytes:r.bytes,file:'objects/'+hash(r.algorithm+':'+r.digest)}))}};
 if(fault.startsWith('auth:')){const key=fault.slice(5);if(key==='extra')closure.authentication.extra=true;else delete closure.authentication[key];}
 if(fault==='object')closure.acquired.artifacts[0].file='objects/'+'0'.repeat(64);
 if(fault==='total')closure.acquired.bytes.total++;
 const closureText=JSON.stringify(closure),ready={version:1,binding:plan.binding,port:1234,closureSha256:hash(closureText),metadataAuthenticated:true,artifactBytesVerified:true};
 const packet={'closure.json':closureText,'terminal.json':JSON.stringify({version:1,binding:plan.binding,
 failure:fault==='semantic'?'REPLAY_UNLISTED':null,cleanupErrors:[],result:{failure:null,closed:true,absenceVerified:true,active:0}})};
 const inventory=JSON.parse(await fs.readFile(path.join(C.ROOT,RETAINED,'inventory-before.json'),'utf8')).text;
 const daemon={ID:'controlled-private-id',DockerRootDir:spec.mount+'/data',Driver:'overlay2',Architecture:'arm64'};
 const image={Id:'sha256:'+'d'.repeat(64),Architecture:'arm64',Os:'linux',Config:{User:'10001:10001',Entrypoint:[...captured.recipe.entrypoint],
 Labels:{[diagnostic?'owasp-ai-goat.diagnostic.inputs':'owasp-ai-goat.system.inputs']:captured.inputSha256,'owasp-ai-goat.build-run':plan.runId}}};
 if(fault==='diagnostic-label')image.Config.Labels={'owasp-ai-goat.system.inputs':captured.inputSha256,'owasp-ai-goat.build-run':plan.runId};
 const calls=[],records=[];let inspect=0;
 const phase=async(name,{input})=>{
  calls.push(name);
  if(input){const chunks=[];for await(const b of input)chunks.push(Buffer.from(b));const body=Buffer.concat(chunks);
   if(name==='build')assert(body.length>0);}
  if(name==='build'&&fault==='build')throw Object.assign(Error('build failed'),{code:'BUILD_FAILED'});
  if(name==='retireArtifacts'&&fault==='retirement')throw Object.assign(Error('retirement unproven'),{code:'RETIREMENT'});
  if(name==='inventory')return inventory;
  if(name==='inspect'){inspect++;return JSON.stringify({...daemon,...(fault==='daemon'&&inspect>1?{ID:'replacement'}:{})});}
  if(name==='metadataFetch')return wireRaw;
  if(name==='startArtifacts')return JSON.stringify(ready);
  if(name==='closureEvidence')return JSON.stringify(packet);
  if(name==='image')return JSON.stringify([image]);
  if(name==='handoff')return JSON.stringify({...physical(plan),target:fault==='diagnostic-handoff'?I.TARGET:plan.target});
  if(name==='retireArtifacts')return 'absent\n';
  if(name==='cleanup')return fault==='cleanup'?'still-present\n':'absent\n';
  return '';
 };
 const record=async(name,value)=>{records.push([name,value]);if(fault==='journal'&&name==='closureEvidence-result')throw Object.assign(Error('journal'),{code:'JOURNAL'});};
 try{return {value:await I.runControlledPipeline(plan,{expectedPlanSha256:adapter.planDigest(plan),phase,record,verify:async()=>{}}),calls,records,plan};}
 catch(error){return {error,calls,records,plan};}
}
test('diagnostic observation replay joins distinct stage/image/handoff and rejects System substitution',async t=>{
 if(!await retainedAvailable()){t.skip('Pinned synthetic-control seed unavailable');return;}
 const positive=await pipelineCase('',true);assert.ifError(positive.error);
 assert.equal(positive.value.target,'original-v03-diagnostic');assert.equal(positive.value.runtimeAvailable,false);
 for(const fault of ['diagnostic-label','diagnostic-handoff','auth:method','object','total']){
  const denied=await pipelineCase(fault,true);assert(denied.error,fault);
  assert.equal(denied.error.result.buildCompleted,false);
 }
});
test('driver observation replay joins full actual-source-shaped evidence before immutable binding projection',async t=>{
 if(!await retainedAvailable()){t.skip('Pinned acquisition evidence unavailable');return;}
 const f=await pipelineCase();assert.ifError(f.error);
 const observations=[];
 for(const [name,value]of f.records){if(name.endsWith('-result'))observations.push({name:name.slice(0,-7),value});if(name==='handoff-result')break;}
 const b=await I.validateDriverObservations(f.plan,observations);
 assert.equal(b.runId,f.plan.runId);assert.equal(b.inputSha256,f.plan.captured.inputSha256);assert(Object.isFrozen(b.physical));
 for(const mutate of [r=>r.pop(),r=>r.push({...r[0]}),r=>r[0].name='handoff',r=>r.find(x=>x.name==='image').value='[]',
  r=>r.find(x=>x.name==='closureEvidence').value='{}']){
  const rows=structuredClone(observations);mutate(rows);await assert.rejects(I.validateDriverObservations(f.plan,rows));
 }
 assert.throws(()=>adapter.assertSystemImageCapability(b),/SYSTEM_IMAGE_NOT_LIVE/);
});
test('retained System single-stage35-dependency metadata drives controlled full build/retirement path',async t=>{
 if(!await retainedAvailable()){t.skip('Pinned acquisition evidence unavailable; no synthetic authenticity replacement');return;}
 const f=await pipelineCase();assert.ifError(f.error);
 assert.equal(f.value.buildCompleted,true);assert.equal(f.value.cleanupVerified,true);assert.equal(f.value.runtimeAvailable,false);
 assert(f.calls.indexOf('retireArtifacts')<f.calls.indexOf('handoff'));
 assert(f.calls.indexOf('stop')<f.calls.indexOf('cleanup'));
 assert.equal(f.records.find(([n])=>n==='controlled-image')[1].controlled,true);
});
test('full authenticated witness and acquired object accounting cannot be stripped or forged',async t=>{
 if(!await retainedAvailable()){t.skip('Pinned acquisition evidence unavailable');return;}
 for(const field of ['version','retainedManifestSha256','keyringSha256','installedStatusSha256','stages','expandedBytes','extra']){
  const f=await pipelineCase('auth:'+field);assert.equal(f.error?.result.failure,'SYSTEM_CLOSURE_EVIDENCE',field);assert(!f.calls.includes('build'));
 }
 for(const fault of ['object','total']){const f=await pipelineCase(fault);assert.equal(f.error?.result.failure,'SYSTEM_CLOSURE_EVIDENCE');assert(!f.calls.includes('build'));}
 const bad=await pipelineCase('cleanup');assert.equal(bad.error?.result.cleanupVerified,false);assert(bad.error.result.cleanupErrors.includes('SYSTEM_CLEANUP_UNPROVEN'));
});
test('controlled build failures preserve primary; unresolved retirement or evidence publication retains owned disk',async t=>{
 if(!await retainedAvailable()){t.skip('Pinned acquisition evidence unavailable');return;}
 for(const fault of ['build','daemon','semantic','retirement','journal']){
  const f=await pipelineCase(fault);assert(f.error, fault);assert.equal(f.error.result.buildCompleted,false);
  if(['retirement','journal'].includes(fault)){
   assert.equal(f.error.result.cleanupVerified,false);assert(!f.calls.includes('cleanup'));
   if(fault==='journal')assert(f.calls.includes('stop'),'publication failure still stops owned daemons but retains disk');
  }else{assert.equal(f.error.result.cleanupVerified,true);assert(f.calls.includes('cleanup'));}
  if(fault==='daemon')assert(!f.calls.includes('build'));
  if(fault==='build')assert.equal(f.error.result.failure,'BUILD_FAILED');
 }
});

test('diagnostic credit checkpoint stays on stderr and readiness remains one strict JSON document',async()=>{
 const source=await fs.readFile(path.join(__dirname,'postgres/ownedSystemConfigBuildAdapter.js'),'utf8');
 const match=/const start = guard\+identity\+\(diagnostic\?('(?:\\.|[^'])*'):\x27\x27\)\+String.raw\x60/.exec(source);
 assert.ok(match,'exact diagnostic-only emitted prefix');
 const prefix=vm.runInNewContext(match[1]);
 const checkpoint={version:1,runId:'a'.repeat(32),variant:'metadata-idle-barrier-v4',rows:{}};
 const ready={version:1,binding:{runId:'a'.repeat(32)},metadataAuthenticated:true,artifactBytesVerified:true};
 const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
 const execute=credit=>require('node:child_process').spawnSync('/bin/sh',['-c',
  'relay_control() { printf "%s\\n" '+quote(JSON.stringify(checkpoint))+'; };\n'+credit+
  'printf "%s\\n" '+quote(JSON.stringify(ready))],{encoding:'utf8',timeout:1000,maxBuffer:65536});
 const actual=execute(prefix);assert.equal(actual.status,0);
 assert.deepEqual(JSON.parse(actual.stdout),ready);
 assert.deepEqual(JSON.parse(actual.stderr),checkpoint,'checkpoint evidence is retained, not discarded');
 const historical=execute(prefix.replace(' >&2',''));
 assert.equal(historical.status,0);assert.throws(()=>JSON.parse(historical.stdout),error=>error.name==='SyntaxError');
 const other=execute('');assert.deepEqual(JSON.parse(other.stdout),ready);assert.equal(other.stderr,'');
});


