'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs/promises'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {
  setupOwnedMcpRegistry,
  preflightOwnedMcpRegistryArchitecture,
  _internals: i
} = require('../scripts/install/secureshop-owned-mcp-registry-setup');
const {
  workspaceId
} = require('../server/services/mcp/ownedManagedConfiguration');
const authority = require('../scripts/install/manifests/secureshop-owned-mcp-registry-build.json');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const dockerInfo = (architecture, daemonId='fixture-daemon') => JSON.stringify(daemonId)+'|'+JSON.stringify(architecture);
const previousPackageDigest = 'a8354f9a976710127b04776ba01a093b68949e4832bcd65da42e40bb279bbfd3';
test('V42 package successor preserves unrelated inputs and V39 package history', () => {
  const historical = structuredClone(authority);
  delete historical.files['server/services/secureshopMcpRegistryDiscoveryContract.js'];
  Object.assign(historical.files, {
    "server/services/secureshopMcpSchemaDigest.js": "bf5bf97e4de2a0c537895c4f31e19c4f00fe9dff119c2d9293d803ba855745e9",
    "sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate": "11d014be46b01c36520955ec3b4cffb806ade7d7d0c746837ec5bcf94973be96",
    "sidecars/sandbox-runner/owned-mcp-registry/worker.js": "74086f0754463193c3465c9c02862af8e361dd62b2d069f3a875eeae793d3204",
    "sidecars/sandbox-runner/owned-mcp-registry/executor.js": "6ff43d80a5126ea4b375048b91911a92680002b837d39babfd881504b8208f6b",
    "sidecars/sandbox-runner/owned-mcp-registry/http-handler.js": "489d507b29954489f9ad81b600195bcee43b982defe99bad81c8fe0c29b7c840",
    "tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs": "0d4e82b8668beb585a36dc574aa5444f406f0be38dfab8cc37b2ac92840d2bd8"
});
  historical.scope = historical.scope.replace('20 explicit', '19 explicit');
  assert.equal(sha(JSON.stringify(historical)), '986c172bfe9ec7bf0a167d22be21ad9d4f4ff2339318ea8c3896e69f43a3255e');
  historical.files['sidecars/sandbox-runner/owned-mcp-registry/worker.js'] = '755fa5a0d08260aaf0317a0a69a190e01c5e653e5b9ddfd037a17fb9d5d52324';
  assert.equal(sha(JSON.stringify(historical)), previousPackageDigest);
  // Preserve the registration-tracking package identity before the separate
  // V39 atomic endpoint successor. Neither identity attests a rebuilt image.
  const registrationPackage = structuredClone(authority);
  registrationPackage.files['sidecars/sandbox-runner/owned-mcp-registry/worker.js'] =
    'c1f756624c107c5841f6182ee7072afc2cd6e74eca849044684c3257be1a474a';
  assert.equal(sha(JSON.stringify(registrationPackage)), 'c20c2de942f9fa8f631ee39e3152414c69fca169e1b729d027a3dbb4d3e142a7');
  assert.equal(i.packageDigest(), 'e8eaa01581b15bd903f13e805bdf37f021e29472f8d967c2a3058d2109129923');
});
test('streamed build archive contains exactly verified20 main files and no private context', async () => {
  const files = await i.capture(process.cwd()),
    extract = require('tar-stream').extract(),
    seen = {};
  const complete = new Promise((resolve, reject) => {
    extract.on('entry', (header, stream, next) => {
      const chunks = [];
      stream.on('data', x => chunks.push(x));
      stream.on('end', () => {
        assert.equal(header.type, 'file');
        seen[header.name] = sha(Buffer.concat(chunks));
        next();
      });
    });
    extract.on('finish', resolve);
    extract.on('error', reject);
  });
  i.contextStream(files).pipe(extract);
  await complete;
  assert.deepEqual(seen, authority.files);
  assert.equal(Object.keys(seen).length, 20);
  assert(!Object.keys(seen).some(x => x.startsWith('tasks/') || x.includes('.env') || x.startsWith('backups/')));
});
test('build source reader rejects FIFO and never reads beyond admitted file size', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-source-control-'));
  try {
    const fifo = path.join(directory, 'fifo');
    execFileSync('/usr/bin/mkfifo', [fifo]);
    await assert.rejects(i.readBuildSource(fifo, '0'.repeat(64)), {code:'REGISTRY_BUILD_SOURCE_INVALID'});
    const file = path.join(directory, 'source');
    await fs.writeFile(file, '{}');
    let maximum = 0;
    const io = Object.create(fs);
    io.open = async (name, flags) => {
      const fd = await fs.open(name, flags);
      return {
        stat: () => fd.stat(),
        close: () => fd.close(),
        read: async (buffer, offset, length, position) => {
          maximum = Math.max(maximum, length);
          const result = await fd.read(buffer, offset, length, position);
          await fs.appendFile(file, 'growing');
          return result;
        }
      };
    };
    await assert.rejects(i.readBuildSource(file, sha('{}'), io), {code:'REGISTRY_BUILD_SOURCE_CHANGED'});
    assert.equal(maximum, 2);
  } finally {
    await fs.rm(directory, {recursive:true});
  }
});
test('build source reader rejects a changed path identity after descriptor read', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-source-identity-'));
  try {
    const file = path.join(directory, 'source');
    await fs.writeFile(file, '{}');
    const io = Object.create(fs);
    io.open = async (name, flags) => {
      const fd = await fs.open(name, flags);
      return {
        stat: () => fd.stat(),
        close: () => fd.close(),
        read: async (...args) => {
          const result = await fd.read(...args);
          await fs.rename(file, path.join(directory, 'original'));
          await fs.writeFile(file, '{}');
          return result;
        }
      };
    };
    await assert.rejects(i.readBuildSource(file, sha('{}'), io), {code:'REGISTRY_BUILD_SOURCE_CHANGED'});
  } finally {
    await fs.rm(directory, {recursive:true});
  }
});
test('automatic build pins image once then reuses immutable receipt without another build', async () => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-build-control-'));
  const imageId = 'sha256:' + 'a'.repeat(64),
    digest = i.packageDigest();
  let builds = 0,
    provisions = 0;
  const options = {
    root: process.cwd(),
    homeDirectory: home,
    platform: 'linux',
    environment: {},
    run: async (_file, args, o) => {
      assert.deepEqual(o.allowExitCodes, [0]);
      return {
        exitCode: 0,
        stdout: args[2] === 'info' ? dockerInfo('arm64') : JSON.stringify([{
          Id: imageId,
          Architecture: 'arm64',
          Os: 'linux',
          Config: {
            Labels: {
              'dvaia.registry.package': digest
            }
          }
        }])
      };
    },
    build: async input => {
      builds++;
      assert.equal(input.args.at(-1), '-');
      assert.equal(input.files.length, 20);
      assert(!input.args.includes(process.cwd()));
      assert(input.args.includes('linux/arm64'));
    },
    provision: async input => {
      provisions++;
      assert.equal(input.imageId, imageId);
      return {
        ready: true,
        activationEnabled: false
      };
    }
  };
  try {
    assert.equal((await setupOwnedMcpRegistry(options)).activationEnabled, false);
    await setupOwnedMcpRegistry(options);
    assert.equal(builds, 1);
    assert.equal(provisions, 2);
    const file = path.join(home, '.dvaia', workspaceId(process.cwd()), 'secureshop-owned-mcp-registry-build.json');
    const before = JSON.parse(await fs.readFile(file));
    assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
    await fs.writeFile(file, JSON.stringify({
      ...before,
      packageDigest: '0'.repeat(64)
    }));
    await assert.rejects(setupOwnedMcpRegistry(options), {
      code: 'REGISTRY_BUILD_UPGRADE_REQUIRES_REVIEW'
    });
    assert.equal(builds, 1);
  } finally {
    await fs.rm(home, {
      recursive: true,
      force: true
    });
  }
});
test('unsupported daemon fails before capture/build/provision', async () => {
  let built = false;
  await assert.rejects(setupOwnedMcpRegistry({
    platform: 'linux',
    environment: {},
    run: async () => ({
      exitCode: 0,
      stdout: dockerInfo('x86_64')
    }),
    build: async () => {
      built = true;
    }
  }), {
    code: 'REGISTRY_BUILD_AMD64_UNQUALIFIED'
  });
  assert.equal(built, false);
});
test('daemon replacement after first preflight stops before image build', async () => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-daemon-drift-'));
  let probes=0, builds=0;
  try {
    await assert.rejects(setupOwnedMcpRegistry({root:process.cwd(),homeDirectory:home,platform:'linux',environment:{},
      run:async(_file,args)=>({exitCode:0,stdout:args[2]==='info'
        ? dockerInfo('arm64',++probes===1?'original-daemon':'replacement-daemon') : '[]'}),
      build:async()=>{builds++;}}),{code:'REGISTRY_BUILD_DOCKER_AUTHORITY_MISMATCH'});
    assert.equal(probes,2);
    assert.equal(builds,0);
  } finally {
    await fs.rm(home,{recursive:true});
  }
});
test('registry architecture preflight inspects only the selected Docker host and rejects authority drift before inspection', async () => {
  const calls=[];
  const options={root:process.cwd(),platform:'linux',environment:{},
    run:async(file,args,limits)=>{calls.push({file,args,limits});return{exitCode:0,stdout:dockerInfo('arm64')};}};
  assert.deepEqual(await preflightOwnedMcpRegistryArchitecture(options),{
    architecture:'arm64',dockerHost:'unix:///var/run/docker.sock',daemonId:'fixture-daemon'
  });
  assert.equal(calls.length,1);
  assert.equal(calls[0].file,'docker');
  assert.deepEqual(calls[0].args,['--host','unix:///var/run/docker.sock','info','--format','{{json .ID}}|{{json .Architecture}}']);
  assert.deepEqual(calls[0].limits,{timeoutMs:30000,maxOutputBytes:1048576,allowExitCodes:[0]});
  const colima=await preflightOwnedMcpRegistryArchitecture({...options,platform:'darwin',
    homeDirectory:'/controlled/home',colimaProfile:'colima-dvaia'});
  assert.equal(colima.dockerHost,'unix:///controlled/home/.colima/dvaia/docker.sock');
  assert.deepEqual(calls[1].args.slice(0,3),['--host',colima.dockerHost,'info']);
  await assert.rejects(preflightOwnedMcpRegistryArchitecture({...options,
    dockerAuthority:{host:'unix:///another-daemon.sock'}}),{code:'REGISTRY_BUILD_DOCKER_AUTHORITY_MISMATCH'});
  assert.equal(calls.length,2);
  await assert.rejects(preflightOwnedMcpRegistryArchitecture({...options,
    dockerAuthority:{host:'unix:///var/run/docker.sock',daemonId:'other-daemon'}}),{code:'REGISTRY_BUILD_DOCKER_AUTHORITY_MISMATCH'});
  await assert.rejects(preflightOwnedMcpRegistryArchitecture({...options,
    environment:{DOCKER_HOST:'unix:///another-daemon.sock'}}),{code:'MCP_INSTALL_DOCKER_AUTHORITY_CONFLICT'});
  assert.equal(calls.length,3);
  for(const stdout of [dockerInfo('x86_64'),dockerInfo('amd64')]){
    await assert.rejects(preflightOwnedMcpRegistryArchitecture({...options,
      run:async()=>({exitCode:0,stdout})}),{code:'REGISTRY_BUILD_AMD64_UNQUALIFIED'});
  }
  for(const stdout of ['not-json','null','{"architecture":"arm64"}',dockerInfo('arm64','')]){
    await assert.rejects(preflightOwnedMcpRegistryArchitecture({...options,
      run:async()=>({exitCode:0,stdout})}),{code:'REGISTRY_BUILD_ARCHITECTURE_INVALID'});
  }
});
test('existing install without build authority is never rebuilt or silently adopted', async () => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'registry-adoption-control-')),
    directory = path.join(home, '.dvaia', workspaceId(process.cwd()));
  await fs.mkdir(directory, {
    recursive: true,
    mode: 0o700
  });
  const imageId = 'sha256:' + 'b'.repeat(64);
  await fs.writeFile(path.join(directory, 'secureshop-owned-mcp-registry-install.json'), JSON.stringify({
    imageId
  }), {
    mode: 0o600
  });
  let builds = 0,
    provisions = 0,
    label;
  const options = {
    homeDirectory: home,
    platform: 'linux',
    environment: {},
    run: async (_f, args) => ({
      exitCode: 0,
      stdout: args[2] === 'info' ? dockerInfo('arm64') : JSON.stringify([{
        Id: imageId,
        Architecture: 'arm64',
        Os: 'linux',
        Config: {
          Labels: label === undefined ? {} : {
            'dvaia.registry.package': label
          }
        }
      }])
    }),
    build: async () => {
      builds++;
    },
    provision: async () => {
      provisions++;
      return {
        ready: true,
        activationEnabled: false
      };
    }
  };
  try {
    await assert.rejects(setupOwnedMcpRegistry(options), {
      code: 'REGISTRY_BUILD_EXISTING_IMAGE_REQUIRES_ADOPTION'
    });
    assert.equal(builds, 0);
    await fs.writeFile(path.join(directory, 'secureshop-owned-mcp-registry-build.json'), JSON.stringify({
      version: 1,
      packageDigest: i.packageDigest(),
      dockerHost: 'unix:///var/run/docker.sock',
      imageId
    }), {
      mode: 0o600
    });
    await setupOwnedMcpRegistry(options);
    assert.equal(provisions, 1);
    assert.equal(builds, 0);
    label = '0'.repeat(64);
    await assert.rejects(setupOwnedMcpRegistry(options), {
      code: 'REGISTRY_BUILD_IMAGE_CONFLICT'
    });
  } finally {
    await fs.rm(home, {
      recursive: true,
      force: true
    });
  }
});

test('activation is explicit and private publication preserves credentials on readiness failure',async()=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'registry-activation-control-'));
 const root=process.cwd(),file=path.join(home,'config.json');
 const previous={version:1,workspace:workspaceId(root),enabled:false,baseURL:'http://127.0.0.1:8095',token:'a'.repeat(43),runtimeDigest:'b'.repeat(64),mode:'vuln'};
 try{
  await fs.writeFile(file,JSON.stringify(previous),{mode:0o600});const before=await fs.readFile(file);
  await assert.rejects(i.publishActivation({root,configFile:file,previous,readiness:async()=>{throw Error('denied');}}));assert.deepEqual(await fs.readFile(file),before);
  await assert.rejects(i.publishActivation({root,configFile:file,previous,readiness:async()=>false}));assert.deepEqual(await fs.readFile(file),before);
  await i.publishActivation({root,configFile:file,previous,readiness:async({configuration})=>{assert.deepEqual(configuration,previous);return true;}});
  assert.deepEqual(JSON.parse(await fs.readFile(file)),{...previous,enabled:true});assert.equal((await fs.stat(file)).mode&0o777,0o600);
  await assert.rejects(i.publishActivation({root,configFile:file,previous,readiness:async()=>true}),{code:'REGISTRY_PRIVATE_STATE_CHANGED'});
 }finally{await fs.rm(home,{recursive:true,force:true});}
 assert.deepEqual(await setupOwnedMcpRegistry({requested:false,run:()=>{throw Error('must not provision');}}),{requested:false,activationEnabled:false});
});

test('activation readiness checks canonical bound/persona/registry authority and drains exactly owned pools',async()=>{
 const env={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
 for(const prefix of ['IDENTITY','SECURESHOP_AGENTS','SECURESHOP_REVIEW','SECURESHOP'])for(const suffix of ['DATABASE_URL','MIGRATION_DATABASE_URL'])env[prefix+'_'+suffix]='postgresql://owned@127.0.0.1/'+prefix.toLowerCase();
 for(const failure of [null,'bound','persona','registry','health','registration','close','identity']){
  const calls=[],pools=[];
  const check=name=>async()=>{calls.push(name);if(failure===name)throw Error('controlled');};
  const run=()=>i.assertActivationReadiness({applicationEnvironment:env,configuration:{baseURL:'http://127.0.0.1:8095',token:'private',runtimeDigest:'b'.repeat(64)},createPool:(_env,key)=>{const p={ended:false,query:async()=>({rows:[{database:failure==='identity'?'foreign':'identity'}]}),end:async()=>{p.ended=true;if(failure==='close')throw Error('close');}};pools.push(p);return p;},assertBound:check('bound'),assertPersona:async x=>{assert.equal(x.pool,pools[2]);assert.equal(x.expectedDatabase,'secureshop_agents');await check('persona')();},assertRegistry:check('registry'),createClient:()=>({health:check('health'),registrationHealth:check('registration')})});
  if(failure)await assert.rejects(run());else{assert.equal(await run(),true);assert.deepEqual(calls,['bound','persona','registry','health','registration']);}
  assert.equal(pools.length,8);assert(pools.every(p=>p.ended));
 }
});

test('requested setup preserves disabled existing state unless explicit; fresh activates only qualified readiness',async()=>{
 for(const existing of [false,true])for(const explicitActivation of [false,true]){
  const home=await fs.mkdtemp(path.join(os.tmpdir(),'registry-policy-control-')),root=process.cwd(),directory=path.join(home,'.dvaia',workspaceId(root)),file=path.join(directory,'secureshop-owned-mcp-registry.json');
  const imageId='sha256:'+'a'.repeat(64),configuration={version:1,workspace:workspaceId(root),enabled:false,baseURL:'http://127.0.0.1:8095',token:'a'.repeat(43),runtimeDigest:'b'.repeat(64),mode:'vuln'};
  await fs.mkdir(directory,{recursive:true,mode:0o700});if(existing)await fs.writeFile(file,JSON.stringify(configuration),{mode:0o600});let probes=0;
  const options={root,homeDirectory:home,platform:'linux',environment:{},requested:true,explicitActivation,productionQualified:true,readiness:async()=>{probes++;return true;},run:async(_cmd,args)=>({exitCode:0,stdout:args[2]==='info'?dockerInfo('arm64'):JSON.stringify([{Id:imageId,Architecture:'arm64',Os:'linux',Config:{Labels:{'dvaia.registry.package':i.packageDigest()}}}])}),build:async()=>{},provision:async()=>{if(!existing)await fs.writeFile(file,JSON.stringify(configuration),{mode:0o600});return{ready:true,architecture:'arm64',imageId,runtimeDigest:configuration.runtimeDigest,activationEnabled:false};}};
  try{const result=await setupOwnedMcpRegistry(options),enabled=!existing||explicitActivation;assert.equal(result.activationEnabled,enabled);assert.equal(probes,Number(enabled));assert.deepEqual(JSON.parse(await fs.readFile(file)),{...configuration,enabled});}
  finally{await fs.rm(home,{recursive:true,force:true});}
 }
});

test('packaged control-plane execution bytes are part of authenticated runtime assets',()=>{
 const {ASSETS}=require('../sidecars/sandbox-runner/owned-mcp-registry/executor');
 for(const name of ['executor.js','http-handler.js','http-listener.js','invoke-protocol.js'])assert.equal(ASSETS.filter(p=>p==='/app/sidecars/sandbox-runner/owned-mcp-registry/'+name).length,1);
 assert.equal(new Set(ASSETS).size,ASSETS.length);
});
test('changed package requires explicit upgrade and authentic maintenance before building', async()=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'registry-upgrade-admission-'));
 const directory=path.join(home,'.dvaia',workspaceId(process.cwd()));await fs.mkdir(directory,{recursive:true,mode:0o700});
 const installer=require('../scripts/install/secureshop-owned-mcp-registry');
 await installer._internals.writePrivate(path.join(directory,'secureshop-owned-mcp-registry-build.json'),{version:1,packageDigest:previousPackageDigest,imageId:'sha256:'+'a'.repeat(64),dockerHost:'unix:///var/run/docker.sock'},null);
 await installer._internals.writePrivate(path.join(directory,'secureshop-owned-mcp-registry-install.json'),{imageId:'sha256:'+'a'.repeat(64)},null);
 await installer._internals.writePrivate(path.join(directory,'secureshop-owned-mcp-registry.json'),{enabled:true},null);
 const privateFiles=['secureshop-owned-mcp-registry-build.json','secureshop-owned-mcp-registry-install.json','secureshop-owned-mcp-registry.json'];
 const before=await Promise.all(privateFiles.map(name=>fs.readFile(path.join(directory,name))));
 let builds=0;const options={homeDirectory:home,platform:'linux',environment:{},run:async()=>({exitCode:0,stdout:dockerInfo('arm64')}),build:async()=>{builds++;}};
 try {
  await assert.rejects(setupOwnedMcpRegistry(options),{code:'REGISTRY_BUILD_UPGRADE_REQUIRES_REVIEW'});
  await assert.rejects(setupOwnedMcpRegistry({...options,upgrade:true,maintenanceScope:{assertHeld(){}}}),{code:'APPLICATION_MAINTENANCE_SCOPE_INVALID'});
  assert.equal(builds,0);
  assert.deepEqual(await Promise.all(privateFiles.map(name=>fs.readFile(path.join(directory,name)))),before);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
