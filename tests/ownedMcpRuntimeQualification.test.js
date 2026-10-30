'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const {qualify,RUNTIME_IMAGE,RUNTIME_DIGEST,_internals:i}=require('./postgres/ownedMcpRuntimeQualification');
const {PINS}=require('./postgres/ownedMcpBoundedBuild');
const root=path.resolve(__dirname,'..');
async function harness(t,fault={}){
  const temporary=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'runtime-control-'));
  await fs.mkdir(path.join(temporary,'tasks/tmp'),{recursive:true});
  const nonce=crypto.randomBytes(6).toString('hex'),spec=i.specification(temporary,nonce,RUNTIME_DIGEST),calls=[];
  await assert.rejects(fs.access(spec.directory),{code:'ENOENT'});
  t.after(()=>fs.rm(temporary,{recursive:true,force:true}));
  let exists=false,profile=false,running=false,started=false,finished=false;
  const id='c'.repeat(64);
  const receipt={status:'passed',modelCalls:0,runtimeDigest:RUNTIME_DIGEST,qualificationComplete:false};
  const row=()=>({Id:id,Name:'/'+spec.name,Image:RUNTIME_IMAGE,Config:{Labels:{'owasp-ai-goat.runtime':nonce},User:'10001:10001',OpenStdin:true,Entrypoint:['node'],Cmd:['-'],Env:['SECURESHOP_MCP_REGISTRY_PROFILE='+spec.profile]},HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],Memory:536870912,NanoCpus:1000000000,PidsLimit:128,LogConfig:{Type:'none'},SecurityOpt:['apparmor='+spec.profile,'seccomp=unconfined'],Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=16m'}},Mounts:[],State:{Running:running,ExitCode:0}});
  const journal=async name=>JSON.parse(await fs.readFile(path.join(spec.directory,name+'.json')));
  const docker=async(s,args,options={})=>{
    assert.equal(s.root,temporary);calls.push(args);
    if(args[0]==='info')return JSON.stringify(fault.daemon||PINS.daemon);
    if(args[0]==='image'&&args[1]==='ls'){assert(args.includes('--all'));return PINS.postgres+' postgres:18\n'+(fault.missingImage?'':RUNTIME_IMAGE+' <none>:<none>\n')+(fault.changedInventory&&finished?'foreign:tag\n':'');}
    if(args[0]==='ps')return exists?id+'\n':'';
    if(args[0]==='volume')return '';
    if(args[0]==='create'){
      assert(profile);const intent=await journal('intent');assert.deepEqual(intent.argv,args);assert.equal(intent.runtimeImageId,RUNTIME_IMAGE);
      assert.equal((await fs.stat(path.join(spec.directory,'intent.json'))).mode&0o777,0o600);
      exists=true;if(fault.lostCreate)throw Object.assign(Error('lost create'),{code:'ADMISSION_COMMAND_TIMEOUT'});return id;
    }
    if(args[0]==='container'){
      const value=row();if(fault.foreign)value.Config.Labels['owasp-ai-goat.runtime']='foreign';
      if(fault.mount)value.Mounts=[{Type:'bind',Destination:'/tmp'}];
      if(fault.memory)value.HostConfig.Memory=0;
      return JSON.stringify([value]);
    }
    if(args[0]==='start'){
      assert.equal((await journal('created')).id,id);started=true;running=true;
      let script='';for await(const chunk of options.input)script+=chunk;
      assert.equal(script,i.fixture(RUNTIME_DIGEST));assert.equal(options.timeoutMs,180000);
      if(fault.startFailure)throw Object.assign(Error('start timed out'),{code:'ADMISSION_COMMAND_TIMEOUT'});
      running=false;finished=true;return JSON.stringify({...receipt,...(fault.falseReceipt?{runtimeDigest:'0'.repeat(64)}:{})});
    }
    if(args[0]==='stop'){assert.equal(args[3],id);if(!fault.unjoined)running=false;return id;}
    if(args[0]==='rm'){assert.equal(args[1],id);assert(!running);if(fault.removeFailure)throw Error('remove failed');exists=false;finished=true;return id;}
    assert.fail('Unexpected Docker command '+args.join(' '));
  };
  const remote=async(s,operation,policy)=>{
    calls.push(['guest',operation]);assert.equal(s.guest,spec.guest);assert(policy.includes('profile "'+spec.profile+'"'));
    if(operation==='install'){assert.equal((await journal('intent')).policySha256,crypto.createHash('sha256').update(policy).digest('hex'));profile=true;if(fault.installFailure)throw Error('install reply lost');}
    else{assert(!exists);if(fault.cleanupFailure)throw Error('profile cleanup failed');profile=false;}
  };
  return {spec,calls,journal,run:()=>qualify({root:temporary,nonce,docker,remote,verifyHost:false,readTemplate:()=>fs.readFile(path.join(root,i.TEMPLATE),'utf8')}),state:()=>({exists,profile,started,running})};
}
test('runtime gate streams fixture to exact pinned image and removes only owned resources',async t=>{
  const h=await harness(t),result=await h.run();assert.equal(result.cleanupVerified,true);assert.equal(result.qualificationComplete,false);
  assert.deepEqual(h.state(),{exists:false,profile:false,started:true,running:false});
  assert(!h.calls.some(x=>['build','load','pull','tag'].includes(x[0])||x[0]==='image'&&x[1]==='rm'));
  const receipt=await h.journal('result');assert.equal(receipt.cleanupVerified,true);assert.equal(receipt.containerAbsent,true);
  assert(h.calls.findIndex(x=>x[0]==='rm')<h.calls.findIndex(x=>x[0]==='guest'&&x[1]==='cleanup'));
});
test('exclusive intent namespace prevents any profile or container creation',async t=>{
  const h=await harness(t);await fs.mkdir(h.spec.directory,{mode:0o700});await assert.rejects(h.run());
  assert(!h.calls.some(x=>x[0]==='guest'||x[0]==='create'));
});
test('lost create reply retains profile and durable name authority, never adopts name',async t=>{
  const h=await harness(t,{lostCreate:true});await assert.rejects(h.run());
  assert(h.state().exists&&h.state().profile);assert.equal(h.calls.filter(x=>x[0]==='create').length,1);
  assert(!h.calls.some(x=>['rm','container'].includes(x[0])||x[0]==='guest'&&x[1]==='cleanup'));
  const receipt=await h.journal('result');assert.equal(receipt.cleanupVerified,false);assert.equal(receipt.containerAbsent,false);
});
test('local start timeout is followed by exact remote stop and join before profile cleanup',async t=>{
  const h=await harness(t,{startFailure:true});await assert.rejects(h.run());
  assert(h.calls.some(x=>x[0]==='stop'));assert.equal(h.state().running,false);assert.equal(h.state().profile,false);
  assert.equal((await h.journal('result')).cleanupVerified,true);
});
for(const fault of ['foreign','removeFailure','cleanupFailure','unjoined','changedInventory'])test('uncertain cleanup or shared-state change cannot qualify: '+fault,async t=>{
  const h=await harness(t,{[fault]:true,...(fault==='unjoined'?{startFailure:true}:{})});await assert.rejects(h.run());
  assert.equal((await h.journal('result')).cleanupVerified,false);
  if(['foreign','removeFailure','unjoined'].includes(fault))assert(!h.calls.some(x=>x[0]==='guest'&&x[1]==='cleanup'));
  if(fault==='foreign')assert(!h.calls.some(x=>x[0]==='rm'));
});
for(const fault of ['mount','memory','falseReceipt','installFailure'])test('boundary/fixture/setup failure fails closed and attempts safe cleanup: '+fault,async t=>{
  const h=await harness(t,{[fault]:true});await assert.rejects(h.run());const receipt=await h.journal('result');assert.equal(receipt.result,null);assert.equal(receipt.cleanupVerified,true);
  if(['mount','memory','installFailure'].includes(fault))assert(!h.state().started);
});
for(const fault of [{missingImage:true},{daemon:'foreign'}])test('wrong daemon or missing image fails before mutations',async t=>{
  const h=await harness(t,fault);await assert.rejects(h.run());assert(!h.calls.some(x=>x[0]==='guest'||x[0]==='create'));
});
test('identities and paths cannot select arbitrary cleanup targets',()=>{
  assert.throws(()=>i.specification('/', 'a'.repeat(12),RUNTIME_DIGEST));
  assert.throws(()=>i.specification(root,'../../escape',RUNTIME_DIGEST));
  assert.throws(()=>i.specification(root,'a'.repeat(12),'0'.repeat(64)));
});
test('guest lost reply waits complete remote deadline before cleanup can begin',async()=>{
  const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();child.pid=1;
  const events=[];const run=i.createGuest({launch(_file,args,options){assert.equal(options.env.HOME,path.join(root,'tasks/l'));assert.equal(options.env.HOME,options.env.LIMA_HOME);assert(args.includes('25'));assert(args.includes('--kill-after=5'));queueMicrotask(()=>child.emit('close',1));return child;},delay:async ms=>{events.push(ms);}});
  await assert.rejects(run(i.specification(root,'a'.repeat(12),RUNTIME_DIGEST),'install','policy'));
  assert.deepEqual(events,[45000]);
});
test('unknown guest operation is rejected before spawning',async()=>{
  const run=i.createGuest({launch(){assert.fail('must not spawn');}});
  await assert.rejects(run(i.specification(root,'a'.repeat(12),RUNTIME_DIGEST),'delete-arbitrary','policy'));
});
async function shellPolicyHarness(t){
  const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'runtime-policy-control-'));
  t.after(()=>fs.rm(directory,{recursive:true,force:true}));
  const nonce='a'.repeat(12),profile='owasp-ai-goat-owned-mcp-registry-'+nonce,guest=path.join(directory,'guest-'+nonce),labels=path.join(directory,'labels');
  const policy='controlled policy bytes',digest=crypto.createHash('sha256').update(policy).digest('hex');await fs.writeFile(labels,'');
  const stubs=`sha256sum() { /usr/bin/shasum -a 256 "$1"; }
apparmor_parser() {
 case "$1" in
 --skip-kernel-load) return 0;;
 -a) printf '%s (enforce)\\n' "$profile" > "$TEST_LABELS"; [ "\${TEST_ADD_FAILURE:-0}" = 0 ];;
 -R) printf '' > "$TEST_LABELS";;
 *) return 92;;
 esac
}
`;
  const run=(operation,env={})=>new Promise((resolve,reject)=>{
    // Only path and kernel adapter substitutions: all ownership/marker checks
    // and removal statements execute unchanged against private test files.
    const script=stubs+i.scripts[operation].replace('/var/tmp/owasp-ai-goat-v23-runtime-','$TEST_GUEST_PREFIX')
      .replace('cat /sys/kernel/security/apparmor/profiles','[ "${TEST_READ_FAILURE:-0}" = 0 ] && cat "$TEST_LABELS"');
    const child=require('node:child_process').spawn('/bin/sh',['-c',script,'test-policy',guest,nonce,profile,digest],{env:{PATH:process.env.PATH,TMPDIR:process.env.TMPDIR,TEST_LABELS:labels,TEST_GUEST_PREFIX:path.join(directory,'guest-'),...env},stdio:['pipe','pipe','pipe']});
    child.on('error',reject);child.stdout.resume();child.stderr.resume();child.on('close',code=>resolve(code));child.stdin.end(operation==='install'?policy:undefined);
  });
  return{run,guest,labels,profile};
}
test('actual ownership shell installs marker then removes exact policy files',async t=>{
  const h=await shellPolicyHarness(t);assert.equal(await h.run('install'),0);
  assert.match(await fs.readFile(path.join(h.guest,'loaded'),'utf8'),/^a{12} [a-f0-9]{64}\n$/);
  assert.equal(await h.run('cleanup'),0);await assert.rejects(fs.access(h.guest),{code:'ENOENT'});assert.equal(await fs.readFile(h.labels,'utf8'),'');
});
test('failed profile add cannot authorize unloading name-colliding profile',async t=>{
  const h=await shellPolicyHarness(t);assert.notEqual(await h.run('install',{TEST_ADD_FAILURE:'1'}),0);
  await assert.rejects(fs.access(path.join(h.guest,'loaded')),{code:'ENOENT'});
  assert.notEqual(await h.run('cleanup'),0);assert.equal(await fs.readFile(h.labels,'utf8'),h.profile+' (enforce)\n');await fs.access(h.guest);
});
test('unreadable profile list is not treated as absence',async t=>{
  const h=await shellPolicyHarness(t);assert.notEqual(await h.run('install',{TEST_READ_FAILURE:'1'}),0);await assert.rejects(fs.access(h.guest),{code:'ENOENT'});
});
test('foreign successful-load marker prevents profile and directory deletion',async t=>{
  const h=await shellPolicyHarness(t);assert.equal(await h.run('install'),0);await fs.writeFile(path.join(h.guest,'loaded'),'foreign');
  assert.notEqual(await h.run('cleanup'),0);assert.equal(await fs.readFile(h.labels,'utf8'),h.profile+' (enforce)\n');await fs.access(h.guest);
});
