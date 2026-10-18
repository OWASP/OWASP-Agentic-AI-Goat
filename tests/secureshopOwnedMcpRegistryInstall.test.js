'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict');
const {
  plan,
  _internals: i
} = require('../scripts/install/secureshop-owned-mcp-registry');
const p = plan({
  root: process.cwd(),
  home: '/owned',
  platform: 'linux',
  imageId: 'sha256:' + 'a'.repeat(64)
});
function fixture() {
  const r = {
      networkId: 'b'.repeat(64),
      containerId: 'c'.repeat(64)
    },
    token = 'x'.repeat(64);
  const labels = {
    'dvaia.registry.workspace': p.workspace,
    'dvaia.registry.owner': p.profile
  };
  return {
    r,
    token,
    n: {
      Id: r.networkId,
      Name: p.network,
      Driver: 'bridge',
      Internal: false,
      EnableIPv6: false,
      Labels: labels,
      Containers: {
        [r.containerId]: {}
      }
    },
    c: {
      Id: r.containerId,
      Name: '/' + p.container,
      Image: p.imageId,
      Config: {
        Labels: labels,
        User: '10001:10001',
        Entrypoint: ['node', 'sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'],
        Cmd: [],
        Env: ['SECURESHOP_MCP_REGISTRY_ENABLED=true', 'SECURESHOP_MCP_REGISTRY_TOKEN=' + token, 'SECURESHOP_MCP_REGISTRY_PROFILE=' + p.profile, 'SECURESHOP_MCP_REGISTRY_HOST=0.0.0.0', 'SECURESHOP_MCP_REGISTRY_PORT=8094']
      },
      HostConfig: {
        ReadonlyRootfs: true,
        NetworkMode: p.network,
        CapDrop: ['ALL'],
        Memory: 536870912,
        NanoCpus: 1000000000,
        PidsLimit: 128,
        RestartPolicy: {
          Name: 'unless-stopped'
        },
        SecurityOpt: ['apparmor=' + p.profile, 'seccomp=unconfined'],
        PortBindings: {
          '8094/tcp': [{
            HostIp: '127.0.0.1',
            HostPort: '8095'
          }]
        },
        Tmpfs: {
          '/tmp': 'rw,nosuid,nodev,noexec,size=16m'
        }
      },
      Mounts: [],
      NetworkSettings: {
        Networks: {
          [p.network]: {
            NetworkID: r.networkId
          }
        }
      }
    }
  };
}
test('closed plan uses distinct host port and immutable image on explicit daemon', () => {
  assert.equal(p.port, 8095);
  assert.equal(p.dockerHost, 'unix:///var/run/docker.sock');
  assert.throws(() => plan({
    imageId: 'tag:latest'
  }));
  assert.throws(() => plan({
    imageId: p.imageId,
    platform: 'win32'
  }));
  const mac = plan({
    imageId: p.imageId,
    platform: 'darwin',
    home: '/owned',
    colimaProfile: 'colima-test'
  });
  assert.equal(mac.dockerHost, 'unix:///owned/.colima/test/docker.sock');
});
test('dedicated bridge rejects internal-policy drift and sibling endpoints', () => {
  const {
    n,
    r
  } = fixture();
  assert.equal(i.validateNetwork(n, p, r), n);
  for (const change of [x => x.Internal = true, x => x.Id = 'd'.repeat(64), x => x.Containers['e'.repeat(64)] = {}, x => x.Labels = {}]) {
    const bad = structuredClone(n);
    change(bad);
    assert.throws(() => i.validateNetwork(bad, p, r));
  }
});
test('exact service contract rejects ownership, token, privilege, mount, egress and publish drift', () => {
  const {
    c,
    r,
    token
  } = fixture();
  assert.equal(i.validateContainer(c, p, r, token), c);
  for (const change of [x => x.Id = 'd'.repeat(64), x => x.Image = 'sha256:' + 'e'.repeat(64), x => x.Config.Env[1] = 'SECURESHOP_MCP_REGISTRY_TOKEN=wrong', x => x.HostConfig.Privileged = true, x => x.HostConfig.CapAdd = ['SYS_ADMIN'], x => x.HostConfig.ReadonlyRootfs = false, x => x.Mounts = [{
    Type: 'bind',
    Destination: '/host'
  }], x => x.HostConfig.PortBindings['8094/tcp'][0].HostIp = '0.0.0.0', x => x.NetworkSettings.Networks.extra = {}, x => x.HostConfig.RestartPolicy.Name = 'always']) {
    const bad = structuredClone(c);
    change(bad);
    assert.throws(() => i.validateContainer(bad, p, r, token));
  }
});
test('immutable image probe computes packaged asset digest and rejects modified asset bytes', () => {
  const vm = require('node:vm'),
    crypto = require('node:crypto');
  const bytes = Buffer.alloc(200000, 97),
    manifest = {
      '/asset': crypto.createHash('sha256').update(bytes).digest('hex')
    };
  let result;
  const run = value => { let offset=0; return vm.runInNewContext(i.IMAGE_PROBE, {
    Buffer,
    require: name => name === 'fs' ? {
      readFileSync: p => { assert(p.endsWith('assets.json')); return JSON.stringify(manifest); },
      openSync: () => 1,
      readSync: (_fd,buffer,start,length) => { assert(length<=65536); const n=Math.min(length,value.length-offset);value.copy(buffer,start,offset,offset+n);offset+=n;return n; },
      closeSync: () => {},
      lstatSync: () => ({
        isFile: () => true,
        isSymbolicLink: () => false,
        uid: 0,
        mode: 0o444
      })
    } : name === 'crypto' ? crypto : {
      ASSETS: ['/asset']
    },
    process: {
      stdout: {
        write: x => result = x
      }
    }
  }); };
  run(bytes);
  assert.equal(result, crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex'));
  assert.throws(() => run(Buffer.from('changed')));
});
test('managed lifecycle stages private credentials, reuses exact IDs, and rolls back only new resources on health failure', async () => {
  const fs = require('node:fs/promises'),
    os = require('node:os'),
    path = require('node:path');
  const {
    provision
  } = require('../scripts/install/secureshop-owned-mcp-registry');
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-controls-'));
  let network = null,
    container = null,
    probe = null,
    healthFailure = false,
    removalLie = null;
  const calls = [];
  const digest = 'f'.repeat(64);
  const options = {
    root: process.cwd(),
    home,
    platform: 'linux',
    imageId: p.imageId,
    environment: {},
    readinessOptions: {
      timeoutMs: 1,
      intervalMs: 1
    },
    installProfile: async () => {},
    createClient: ({
      expectedRuntimeDigest
    }) => ({
      health: async () => {
        assert.equal(expectedRuntimeDigest, digest);
        if (healthFailure) throw Error('controlled unavailable');
        return {
          ready: true,
          runtimeDigest: digest
        };
      }
    })
  };
  const local = plan(options),
    ok = x => ({
      exitCode: 0,
      stdout: typeof x === 'string' ? x : JSON.stringify(x)
    });
  options.run = async (file, argv, commandOptions) => {
    assert.equal(file, 'docker');
    const a = argv.slice(2);
    assert.deepEqual(commandOptions.allowExitCodes, a[1] === 'inspect' ? [0, 1] : [0]);
    calls.push(a);
    if (a[0] === 'image') return ok([{
      Id: p.imageId,
      Architecture: 'arm64',
      Os: 'linux',
      Config: {
        User: '10001:10001',
        Entrypoint: ['node', 'sidecars/sandbox-runner/owned-mcp-registry/http-listener.js']
      }
    }]);
    if (a[0] === 'info') return ok('"arm64"');
    if (a[1] === 'inspect') {
      const v = a[0] === 'network' ? network : probe && [probe.Id, probe.Name.slice(1)].includes(a[2]) ? probe : container && [container.Id, container.Name.slice(1)].includes(a[2]) ? container : null;
      return v ? ok([v]) : {
        exitCode: 1,
        stderr: a[0] === 'network' ? `Error response from daemon: network ${a[2]} not found` : `Error: No such container: ${a[2]}`
      };
    }
    if (a[0] === 'create' && a.includes('--entrypoint')) {
      probe = {
        Id: '1'.repeat(64),
        Name: '/' + a[a.indexOf('--name') + 1],
        Image: p.imageId,
        Config: {
          Labels: {
            'dvaia.registry.probe': local.workspace
          }
        },
        HostConfig: {
          NetworkMode: 'none'
        },
        State: {
          Running: false,
          ExitCode: 0
        }
      };
      return ok(probe.Id);
    }
    if (a[0] === 'start' && a[1] === '--attach') return ok(digest);
    if (a[0] === 'rm' && probe?.Id === a[1]) {
      probe = null;
      return ok('');
    }
    if (a[0] === 'network' && a[1] === 'create') {
      assert.equal(a.includes('--internal'), false);
      network = {
        Id: 'b'.repeat(64),
        Name: local.network,
        Driver: 'bridge',
        Internal: false,
        EnableIPv6: false,
        Labels: {
          'dvaia.registry.workspace': local.workspace,
          'dvaia.registry.owner': local.profile
        },
        Containers: {}
      };
      return ok(network.Id);
    }
    if (a[0] === 'create') {
      const env = await fs.readFile(a[a.indexOf('--env-file') + 1], 'utf8');
      assert.equal((await fs.stat(a[a.indexOf('--env-file') + 1])).mode & 0o777, 0o600);
      const token = env.match(/SECURESHOP_MCP_REGISTRY_TOKEN=(.+)/)[1];
      assert(!argv.some(x => x.includes(token)));
      container = fixture().c;
      container.Name = '/' + local.container;
      container.Config.Labels = {
        'dvaia.registry.workspace': local.workspace,
        'dvaia.registry.owner': local.profile
      };
      container.Config.Env = env.trim().split('\n');
      container.HostConfig.NetworkMode = local.network;
      container.HostConfig.SecurityOpt = ['apparmor=' + local.profile, 'seccomp=unconfined'];
      container.NetworkSettings.Networks = {
        [local.network]: {
          NetworkID: network.Id
        }
      };
      container.State = {
        Running: false
      };
      network.Containers = {
        [container.Id]: {}
      };
      return ok(container.Id);
    }
    if (a[0] === 'start') {
      container.State.Running = true;
      container.State.Status = 'running';
      container.NetworkSettings.Ports = {'8094/tcp': [{HostIp:'127.0.0.1',HostPort:'8095'}]};
      return ok('');
    }
    if (a[0] === 'stop') {
      container.State.Running = false;
      return ok('');
    }
    if (a[0] === 'rm') {
      assert.equal(a[1], container.Id);
      if (removalLie === 'container') return ok('');
      container = null;
      network.Containers = {};
      return ok('');
    }
    if (a[0] === 'network' && a[1] === 'rm') {
      assert.equal(a[2], network.Id);
      if (removalLie === 'network') return ok('');
      network = null;
      return ok('');
    }
    throw Error('Unexpected command ' + a[0]);
  };
  try {
    const first = await provision(options);
    assert.equal(first.ready, true);
    assert.equal(first.activationEnabled, false);
    const before = await fs.readFile(local.configFile, 'utf8');
    const repeat = await provision(options);
    assert.equal(repeat.containerId, first.containerId);
    assert.equal(await fs.readFile(local.configFile, 'utf8'), before);
    assert.equal(calls.filter(x => x[0] === 'create' && !x.includes('--entrypoint')).length, 1);
    container.HostConfig.Privileged = true;
    await assert.rejects(provision(options), {
      code: 'REGISTRY_CONTAINER_CONFLICT'
    });
    container.HostConfig.Privileged = false;
    // Separate private installation: health failure removes only resources created by this invocation.
    container = null;
    network = null;
    await fs.unlink(local.configFile);
    await fs.unlink(local.receiptFile);
    healthFailure = true;
    await assert.rejects(provision(options));
    assert.equal(container, null);
    assert.equal(network, null);
    assert.equal(JSON.parse(await fs.readFile(local.configFile)).enabled, false);
    for (const kind of ['container', 'network']) {
      container = null;
      network = null;
      await fs.unlink(local.configFile);
      await fs.unlink(local.receiptFile);
      removalLie = kind;
      await assert.rejects(provision(options), error => error.rollbackIncomplete === true);
      const retained = JSON.parse(await fs.readFile(local.receiptFile));
      assert.equal(retained[kind + 'Id'], kind === 'container' ? 'c'.repeat(64) : 'b'.repeat(64));
      assert.equal(JSON.parse(await fs.readFile(local.configFile)).enabled, false);
    }
  } finally {
    await fs.rm(home, {
      recursive: true,
      force: true
    });
  }
});
test('health readiness retries only GET health until delayed startup is ready', async () => {
  let clock = 0,
    calls = 0;
  const digest = 'f'.repeat(64),
    last = Error('listener not bound');
  const client = {
    health: async () => {
      calls++;
      if (calls < 3) throw last;
      return {
        ready: true,
        runtimeDigest: digest
      };
    },
    execute: () => {
      throw Error('Execute must never be retried');
    }
  };
  const ready = await i.waitForHealth(client, digest, {
    timeoutMs: 10,
    intervalMs: 2,
    now: () => clock,
    sleep: async ms => {
      clock += ms;
    }
  });
  assert.equal(ready.runtimeDigest, digest);
  assert.equal(calls, 3);
  assert.equal(clock, 4);
});
test('health readiness exhaustion retains exact last failure within fixed deadline', async () => {
  let clock = 0,
    calls = 0;
  const failure = Object.assign(Error('controlled unavailable'), {
    code: 'CONTROLLED_UNAVAILABLE'
  });
  await assert.rejects(i.waitForHealth({
    health: async () => {
      calls++;
      throw failure;
    }
  }, 'f'.repeat(64), {
    timeoutMs: 5,
    intervalMs: 2,
    now: () => clock,
    sleep: async ms => {
      clock += ms;
    }
  }), error => error.code === 'REGISTRY_READINESS_TIMEOUT' && error.cause === failure);
  assert.equal(clock, 5);
  assert.equal(calls, 3);
});

test('Docker absent inspection matches exact kind and requested identity only', () => {
  const name='dvaia-owned-mcp-registry-c231599fa8cd-internal';
  const observed={exitCode:1,stderr:`Error response from daemon: network ${name} not found\n`};
  assert.equal(i.isMissingInspect(observed,['network','inspect',name]),true);
  assert.equal(i.isMissingInspect({exitCode:1,stderr:'Error: No such container: exact-id'},['container','inspect','exact-id']),true);
  for (const [result,args] of [[observed,['network','inspect','different']], [observed,['container','inspect',name]], [{...observed,exitCode:125},['network','inspect',name]], [{...observed,stderr:observed.stderr+'permission denied'},['network','inspect',name]], [{exitCode:1,stderr:'network not found'},['network','inspect',name]]]) assert.equal(i.isMissingInspect(result,args),false);
});

test('only an unstarted created container may lack its endpoint network ID',()=>{
 const {c,r,token}=fixture();c.NetworkSettings.Networks[p.network].NetworkID='';c.State={Status:'created',Running:false};
 assert.equal(i.validateContainer(c,p,r,token),c);
 for(const state of [{Status:'running',Running:true},{Status:'exited',Running:false},{Status:'created',Running:true}]){c.State=state;assert.throws(()=>i.validateContainer(c,p,r,token));}
 c.State={Status:'created',Running:false};c.NetworkSettings.Networks[p.network].NetworkID='e'.repeat(64);assert.throws(()=>i.validateContainer(c,p,r,token));
});

test('running admission requires exact realized loopback publication before health',()=>{
 const {c,r,token}=fixture();c.State={Running:true,Status:'running'};c.NetworkSettings.Ports={'8094/tcp':[{HostIp:'127.0.0.1',HostPort:'8095'}]};
 assert.equal(i.validateRunningContainer(c,p,r,token),c);
 for(const change of [x=>x.NetworkSettings.Ports['8094/tcp']=null,x=>x.NetworkSettings.Ports={},x=>x.NetworkSettings.Ports['8094/tcp'][0].HostIp='0.0.0.0',x=>x.NetworkSettings.Ports['8094/tcp'][0].HostPort='8094',x=>x.NetworkSettings.Ports['8094/tcp'].push({HostIp:'::',HostPort:'8095'}),x=>x.NetworkSettings.Ports['9999/tcp']=null,x=>x.State.Running=false]){const bad=structuredClone(c);change(bad);assert.throws(()=>i.validateRunningContainer(bad,p,r,token),{code:'REGISTRY_RUNTIME_PORT_UNAVAILABLE'});}
});

test('transition network admits only the two recorded IDs without weakening normal admission', () => {
 const {n,r}=fixture(), candidate='d'.repeat(64);n.Containers[candidate]={};
 assert.throws(()=>i.validateNetwork(n,p,r));
 assert(i.validateTransitionNetwork(n,p,r,[r.containerId,candidate]));
 n.Containers['e'.repeat(64)]={};assert.throws(()=>i.validateTransitionNetwork(n,p,r,[r.containerId,candidate]));
});
test('replacement rejects a forged maintenance capability before any command', async () => {
 let called=false;
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace({maintenanceScope:{assertHeld(){}},run(){called=true;}}),{code:'APPLICATION_MAINTENANCE_SCOPE_INVALID'});
 assert.equal(called,false);
});

async function replacementFixture(work,{readiness=true}={}) {
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
 const home=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'registry-replacement-control-')));
 const env={IDENTITY_DATABASE_URL:'postgres://runtime@127.0.0.1:5544/identity',IDENTITY_MIGRATION_DATABASE_URL:'postgres://migration@127.0.0.1:5544/identity'};
 const abort=new AbortController(),events=[];
 const opts={root:process.cwd(),home,platform:'linux',imageId:'sha256:'+'d'.repeat(64),applicationEnvironment:env,environment:{}};
 const target=plan(opts),{c,r,token}=fixture();
 c.State={Running:true,Status:'running'};c.NetworkSettings.Ports={'8094/tcp':[{HostIp:'127.0.0.1',HostPort:'8095'}]};
 const containers=new Map([[c.Id,c]]);let debt=0;
 const digest='f'.repeat(64),oldDigest='e'.repeat(64);
 const build={version:1,packageDigest:'a'.repeat(64),dockerHost:target.dockerHost,imageId:p.imageId};
 const next={...build,imageId:opts.imageId,packageDigest:'b'.repeat(64)};
 const profile=await fs.readFile(path.join(process.cwd(),'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in'),'utf8');
 const record={version:1,workspace:target.workspace,imageId:p.imageId,dockerHost:target.dockerHost,profileSha256:crypto.createHash('sha256').update(profile.replaceAll('@@SUPERVISOR_PROFILE@@',target.profile)).digest('hex'),port:8095,mode:'vuln',token,runtimeDigest:oldDigest,...r,phase:'ready'};
 const config={version:1,workspace:target.workspace,enabled:true,baseURL:'http://127.0.0.1:8095',token,runtimeDigest:oldDigest,mode:'vuln'};
 await fs.mkdir(target.directory,{recursive:true,mode:0o700});
 const buildFile=path.join(target.directory,'secureshop-owned-mcp-registry-build.json');
 await i.writePrivate(target.receiptFile,record,null);await i.writePrivate(target.configFile,config,null);await i.writePrivate(buildFile,build,null);
 const run=async(_command,argv,options)=>{
  const a=argv.slice(2);events.push(options.stage);
  if(a[1]==='inspect'){
   let value;
   if(a[0]==='image')value={Id:opts.imageId,Architecture:'arm64',Os:'linux',Config:{User:'10001:10001',Entrypoint:c.Config.Entrypoint,Labels:{'dvaia.registry.package':next.packageDigest}}};
   if(a[0]==='network')value={...fixture().n,Containers:Object.fromEntries([...containers.values()].filter(x=>x.NetworkSettings?.Networks?.[p.network]).map(x=>[x.Id,{}]))};
   if(a[0]==='container')value=containers.get(a[2])||[...containers.values()].find(x=>x.Name==='/'+a[2]);
   if(!value)return {exitCode:1,stdout:'',stderr:'Error: No such container: '+a[2]};
   return {exitCode:0,stdout:JSON.stringify([value])};
  }
  if(a[0]==='create'){
   const probe=a.includes('--entrypoint'),id=(probe?'1':'2').repeat(64),name=a[a.indexOf('--name')+1];
   const value=probe?{Id:id,Name:'/'+name,Image:opts.imageId,Config:{Labels:{'dvaia.registry.probe':p.workspace}},HostConfig:{NetworkMode:'none'},State:{Running:false,ExitCode:0}}:structuredClone(c);
   if(!probe){value.Id=id;value.Name='/'+name;value.Image=opts.imageId;value.State={Running:false,Status:'created'};value.Config.Labels['dvaia.registry.upgrade']=a.find(x=>x.startsWith('dvaia.registry.upgrade=')).split('=')[1];}
   containers.set(id,value);return {exitCode:0,stdout:id};
  }
  if(a[0]==='network'&&a[1]==='disconnect'){containers.get(a[3]).NetworkSettings.Networks={};return{exitCode:0,stdout:''};}
  if(a[0]==='network'&&a[1]==='connect'){containers.get(a[3]).NetworkSettings.Networks={[p.network]:{NetworkID:r.networkId}};return{exitCode:0,stdout:''};}
  if(a[0]==='start'){const value=containers.get(a.at(-1));value.State={Running:!a.includes('--attach'),Status:'running',ExitCode:0};return {exitCode:0,stdout:a.includes('--attach')?digest:''};}
  if(a[0]==='stop'){containers.get(a.at(-1)).State={Running:false,Status:'exited'};return {exitCode:0,stdout:''};}
  if(a[0]==='rename'){containers.get(a[1]).Name='/'+a[2];return {exitCode:0,stdout:''};}
  if(a[0]==='rm'){containers.delete(a[1]);return {exitCode:0,stdout:''};}
  throw Error('Unexpected Docker command');
 };
 try {
  await require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:env,signal:abort.signal,acquire:async()=>({signal:abort.signal,assertHeld(){abort.signal.throwIfAborted();},async beginMaintenance(){return{};},async finishMaintenance(){},async close(){}}),drain:async()=>{}},async maintenanceScope=>{
   const options={...opts,maintenanceScope,previousBuild:build,nextBuild:next,run,createPool:()=>({async query(){return{rows:[{invocations:debt,operations:0}]};},async end(){}}),createClient:({expectedRuntimeDigest})=>({async health(){return{ready:true,runtimeDigest:expectedRuntimeDigest};}}),verifyReadiness:async()=>readiness};
   await work({options,target,containers,events,record,config,build,next,buildFile,fs,abort,setDebt:value=>{debt=value;}});
  });
 } finally {await fs.rm(home,{recursive:true,force:true});}
}
test('replacement preserves token/preferences and old rollback container, publishes only after readiness',async()=>replacementFixture(async h=>{
 const out=await require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options);
 assert.equal(out.upgraded,true);assert.equal(out.activationEnabled,true);
 assert.deepEqual(await i.readPrivate(h.target.configFile),{...h.config,runtimeDigest:'f'.repeat(64)});
 assert.deepEqual(await i.readPrivate(h.buildFile),h.next);
 assert.equal(h.containers.get(h.record.containerId).State.Running,false);
 assert(h.containers.get(h.record.containerId).Name.includes('-rollback-'));
 assert.equal(h.containers.size,2);assert.deepEqual(h.containers.get(h.record.containerId).NetworkSettings.Networks,{});
}));
test('candidate readiness failure restores exact old records and running container',async()=>replacementFixture(async h=>{
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),{code:'REGISTRY_UPGRADE_NOT_READY'});
 assert.deepEqual(await i.readPrivate(h.target.configFile),h.config);assert.deepEqual(await i.readPrivate(h.target.receiptFile),h.record);assert.deepEqual(await i.readPrivate(h.buildFile),h.build);
 assert.equal(h.containers.size,1);assert.equal(h.containers.get(h.record.containerId).State.Running,true);assert.equal(h.containers.get(h.record.containerId).Name,'/'+p.container);
},{readiness:false}));
test('unresolved old executor debt prevents stop or replacement',async()=>replacementFixture(async h=>{
 h.setDebt(1);await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),{code:'REGISTRY_UPGRADE_UNRESOLVED_DEBT'});
 assert(!h.events.includes('upgrade-old-stop'));assert.equal(h.containers.size,1);
}));
test('profile drift is rejected before stopping the installed service',async()=>replacementFixture(async h=>{
 const current={...h.record,profileSha256:'0'.repeat(64)};await i.writePrivate(h.target.receiptFile,current,h.record);
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),{code:'REGISTRY_UPGRADE_PROFILE_DRIFT'});
 assert(!h.events.includes('upgrade-old-stop'));assert.equal(h.containers.size,1);
}));
test('scope loss after candidate validation prevents rollback/publication and retains transition',async()=>{
 let verified=false;
 await assert.rejects(replacementFixture(async h=>{
 h.options.verifyReadiness=async()=>{h.abort.abort();return true;};
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),e=>e.rollbackIncomplete===true);
 assert(!h.events.some(x=>x.startsWith('upgrade-rollback')));
 assert.deepEqual(await i.readPrivate(h.target.configFile),h.config);
 const path=require('node:path');assert.equal((await i.readPrivate(path.join(h.target.directory,'secureshop-owned-mcp-registry-upgrade.json'))).phase,'candidate-start-intent');
 assert(await h.fs.stat(h.target.receiptFile+'.lock'));verified=true;
 }),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
 assert.equal(verified,true);
});
test('publication CAS refuses foreign private state and never overwrites it on rollback',async()=>replacementFixture(async h=>{
 const changed={...h.config,enabled:false};h.options.verifyReadiness=async()=>{await i.writePrivate(h.target.configFile,changed,h.config);return true;};
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),e=>e.code==='REGISTRY_PRIVATE_STATE_CHANGED'&&e.rollbackIncomplete===true);
 assert.deepEqual(await i.readPrivate(h.target.configFile),changed);assert.equal(h.containers.size,1);assert.equal(h.containers.get(h.record.containerId).State.Running,true);
}));
test('lost candidate create acknowledgement rolls back only the fully verified transition identity',async()=>replacementFixture(async h=>{
 const run=h.options.run;h.options.run=async(...args)=>{const result=await run(...args);if(args[2].stage==='upgrade-create')throw Error('lost acknowledgement');return result;};
 await assert.rejects(require('../scripts/install/secureshop-owned-mcp-registry').replace(h.options),/lost acknowledgement/);
 assert.equal(h.containers.size,1);assert.equal(h.containers.get(h.record.containerId).State.Running,true);
 assert.deepEqual(await i.readPrivate(h.target.receiptFile),h.record);
}));

test('closed rehearsal namespace changes only resource names and exact ownership labels',()=>{
 const options={root:process.cwd(),home:'/owned',platform:'linux',imageId:p.imageId};
 const namespaced=plan({...options,resourceNamespace:'012345abcdef'});
 assert.equal(plan(options).container,p.container);assert.equal(plan(options).network,p.network);
 assert.equal(namespaced.container,p.container+'-qualification-012345abcdef');
 assert.equal(namespaced.network,namespaced.container+'-internal');
 assert.equal(namespaced.profile,p.profile);assert.equal(namespaced.destination,p.destination);
 assert.equal(namespaced.directory,p.directory);assert.equal(namespaced.configFile,p.configFile);
 const {c,n,r,token}=fixture();c.Name='/'+namespaced.container;c.HostConfig.NetworkMode=namespaced.network;c.NetworkSettings.Networks={[namespaced.network]:{NetworkID:r.networkId}};
 c.Config.Labels['dvaia.registry.namespace']=namespaced.resourceNamespace;n.Name=namespaced.network;n.Labels['dvaia.registry.namespace']=namespaced.resourceNamespace;
 assert.equal(i.validateContainer(c,namespaced,r,token),c);assert.equal(i.validateNetwork(n,namespaced,r),n);
 for(const value of [undefined,'ffffffffffff']){
  c.Config.Labels['dvaia.registry.namespace']=value;n.Labels['dvaia.registry.namespace']=value;
  assert.throws(()=>i.validateContainer(c,namespaced,r,token));assert.throws(()=>i.validateNetwork(n,namespaced,r));
 }
 const base=fixture();base.c.Config.Labels['dvaia.registry.namespace']='012345abcdef';base.n.Labels['dvaia.registry.namespace']='012345abcdef';
 assert.throws(()=>i.validateContainer(base.c,p,base.r,base.token));assert.throws(()=>i.validateNetwork(base.n,p,base.r));
 for(const value of ['',null,1,'../installed','012345ABCDEF','012345abcde','012345abcdef0'])assert.throws(()=>plan({...options,resourceNamespace:value}),{code:'REGISTRY_NAMESPACE_INVALID'});
});
test('configurationHome isolates private records without changing canonical Docker or SSH authority',()=>{
 const options={root:process.cwd(),home:'/canonical-home',platform:'darwin',colimaProfile:'colima-default',imageId:p.imageId,resourceNamespace:'012345abcdef'};
 const normal=plan(options),isolated=plan({...options,configurationHome:'/owned-rehearsal'});
 assert.equal(normal.directory,'/canonical-home/.dvaia/'+p.workspace);
 assert.equal(isolated.directory,'/owned-rehearsal/.dvaia/'+p.workspace);
 for(const key of ['dockerHost','sshConfig','sshHost','profile','destination','container','network','root','workspace'])assert.equal(isolated[key],normal[key]);
 assert.equal(isolated.dockerHost,'unix:///canonical-home/.colima/default/docker.sock');
 assert.equal(isolated.sshConfig,'/canonical-home/.colima/_lima/colima-default/ssh.config');
 for(const value of [null,'relative',1])assert.throws(()=>plan({...options,configurationHome:value}),{code:'REGISTRY_CONFIGURATION_HOME_INVALID'});
});
