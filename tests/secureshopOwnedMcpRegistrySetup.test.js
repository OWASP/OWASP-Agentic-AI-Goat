'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs/promises'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto');
const {
  setupOwnedMcpRegistry,
  _internals: i
} = require('../scripts/install/secureshop-owned-mcp-registry-setup');
const {
  workspaceId
} = require('../server/services/mcp/ownedManagedConfiguration');
const authority = require('../scripts/install/manifests/secureshop-owned-mcp-registry-build.json');
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
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
  assert.equal(i.packageDigest(), 'd9bdfa1f22d8678a455d5bebb1225b1221b9c9a1fb70d31d04c8b19f7e9cfd50');
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
        stdout: args[2] === 'info' ? '"arm64"' : JSON.stringify([{
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
      stdout: '"x86_64"'
    }),
    build: async () => {
      built = true;
    }
  }), {
    code: 'REGISTRY_BUILD_AMD64_UNQUALIFIED'
  });
  assert.equal(built, false);
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
      stdout: args[2] === 'info' ? '"arm64"' : JSON.stringify([{
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
 for(const failure of [null,'bound','persona','registry','health','close','identity']){
  const calls=[],pools=[];
  const check=name=>async()=>{calls.push(name);if(failure===name)throw Error('controlled');};
  const run=()=>i.assertActivationReadiness({applicationEnvironment:env,configuration:{baseURL:'http://127.0.0.1:8095',token:'private',runtimeDigest:'b'.repeat(64)},createPool:(_env,key)=>{const p={ended:false,query:async()=>({rows:[{database:failure==='identity'?'foreign':'identity'}]}),end:async()=>{p.ended=true;if(failure==='close')throw Error('close');}};pools.push(p);return p;},assertBound:check('bound'),assertPersona:async x=>{assert.equal(x.pool,pools[2]);assert.equal(x.expectedDatabase,'secureshop_agents');await check('persona')();},assertRegistry:check('registry'),createClient:()=>({health:check('health')})});
  if(failure)await assert.rejects(run());else{assert.equal(await run(),true);assert.deepEqual(calls,['bound','persona','registry','health']);}
  assert.equal(pools.length,8);assert(pools.every(p=>p.ended));
 }
});

test('requested setup preserves disabled existing state unless explicit; fresh activates only qualified readiness',async()=>{
 for(const existing of [false,true])for(const explicitActivation of [false,true]){
  const home=await fs.mkdtemp(path.join(os.tmpdir(),'registry-policy-control-')),root=process.cwd(),directory=path.join(home,'.dvaia',workspaceId(root)),file=path.join(directory,'secureshop-owned-mcp-registry.json');
  const imageId='sha256:'+'a'.repeat(64),configuration={version:1,workspace:workspaceId(root),enabled:false,baseURL:'http://127.0.0.1:8095',token:'a'.repeat(43),runtimeDigest:'b'.repeat(64),mode:'vuln'};
  await fs.mkdir(directory,{recursive:true,mode:0o700});if(existing)await fs.writeFile(file,JSON.stringify(configuration),{mode:0o600});let probes=0;
  const options={root,homeDirectory:home,platform:'linux',environment:{},requested:true,explicitActivation,productionQualified:true,readiness:async()=>{probes++;return true;},run:async(_cmd,args)=>({exitCode:0,stdout:args[2]==='info'?'"arm64"':JSON.stringify([{Id:imageId,Architecture:'arm64',Os:'linux',Config:{Labels:{'dvaia.registry.package':i.packageDigest()}}}])}),build:async()=>{},provision:async()=>{if(!existing)await fs.writeFile(file,JSON.stringify(configuration),{mode:0o600});return{ready:true,architecture:'arm64',imageId,runtimeDigest:configuration.runtimeDigest,activationEnabled:false};}};
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
 let builds=0;const options={homeDirectory:home,platform:'linux',environment:{},run:async()=>({exitCode:0,stdout:'"arm64"'}),build:async()=>{builds++;}};
 try {
  await assert.rejects(setupOwnedMcpRegistry(options),{code:'REGISTRY_BUILD_UPGRADE_REQUIRES_REVIEW'});
  await assert.rejects(setupOwnedMcpRegistry({...options,upgrade:true,maintenanceScope:{assertHeld(){}}}),{code:'APPLICATION_MAINTENANCE_SCOPE_INVALID'});
  assert.equal(builds,0);
  assert.deepEqual(await Promise.all(privateFiles.map(name=>fs.readFile(path.join(directory,name)))),before);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
