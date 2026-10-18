'use strict';
// Controlled guest Docker/Compose/forward/readiness providers, not native proof.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs/promises'), path = require('node:path'), crypto = require('node:crypto');
const { createWindowsBaseLabServices, provisionWindowsBaseLabServices } = require('../scripts/install/windows-base-lab-services');
const { workspaceId } = require('../server/services/mcp/ownedManagedConfiguration');
const { MAILPIT_IMAGE } = require('../scripts/local-mailpit');
const root = path.resolve(__dirname,'..'), hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const services = ['mcp-sandbox','mailpit','ssrf-target','rogue-mcp'];
const images = ['mcp-sandbox-runner:dev',MAILPIT_IMAGE,'mcp-ssrf-target:dev','mcp-rogue:dev'];
function fixture() {
  const calls = [], actualHashes = {}, stagedHashes = {}; let created = false, unsafe = false, missing = false, healthy = true, clock = 0;
  const binding = { workspaceId:workspaceId(root),daemonId:'owned-daemon',bindingSha256:'b'.repeat(64) };
  const ownLabChild = async()=>{};
  const ids = services.map((_,index)=>(index+1).toString().repeat(64));
  const session = {
    async assertCurrent(){calls.push(['assert']);},
    async stageReviewedBundle(files){
      calls.push(['stage',files]); const compose=files.find(file=>file.path==='docker-compose.yml').bytes.toString();
      for(const name of services.filter(name=>name!=='mailpit'))stagedHashes[name]=compose.match(new RegExp('  '+name+':\\n[\\s\\S]*?org\\.dvaia\\.reviewed-source: "([a-f0-9]{64})"'))[1];
      return '/var/lib/dvaia/owned/bundles/'+hash(Buffer.from(compose));
    },
    async executeDocker(args,options){
      calls.push(['docker',args,options]);
      if(args[0]==='compose'&&args.includes('up')){created=true;Object.assign(actualHashes,stagedHashes);return '';}
      if(args[0]==='compose'&&args.includes('ps'))return created?ids[services.indexOf(args.at(-1))]:'';
      if(args[0]==='image'){
        if(!created||missing)throw Object.assign(Error('private-password'),{code:1});
        const index=images.indexOf(args.at(-1)),name=services[index];
        return JSON.stringify({Id:'sha256:'+ids[index],RepoDigests:name==='mailpit'?[MAILPIT_IMAGE]:[],Config:{Labels:{'org.dvaia.reviewed-source':actualHashes[name]}}});
      }
      if(args[0]==='inspect'){
        const index=ids.indexOf(args.at(-1)),name=services[index],ports=name==='mailpit'?[1025,8025]:[index===0?8090:index===2?9099:8091];
        return JSON.stringify({Id:ids[index],Image:'sha256:'+ids[index],Config:{Image:images[index],Labels:{'com.docker.compose.project':'dvaia-'+binding.workspaceId,'com.docker.compose.service':unsafe?'foreign':name}},
          HostConfig:{Privileged:false,NetworkMode:'dvaia_'+binding.workspaceId+'_mcplab',PortBindings:Object.fromEntries(ports.map(port=>[port+'/tcp',[{HostIp:'127.0.0.1',HostPort:String(port)}]]))},Mounts:[],State:{Running:true}});
      }
      throw Error('unexpected controlled command');
    },
    async openLoopbackForwards(ports,options){calls.push(['forward',ports,options]);assert.equal(options.ownChild,ownLabChild);return{bindingSha256:binding.bindingSha256};},
  };
  const factory = createWindowsBaseLabServices({describeSession:value=>{if(value!==session)throw Error('fake');return binding;},
    collectRunnerBundle:async()=>{
      const names=['docker-compose.yml','sidecars/sandbox-runner/Dockerfile','sidecars/sandbox-runner/index.js'];
      return Promise.all(names.map(async relative=>{const bytes=await fs.readFile(path.join(root,relative));return{path:relative,bytes,sha256:hash(bytes)};}));
    },fetch:async url=>{calls.push(['fetch',url]);return{ok:healthy,text:async()=>JSON.stringify(url.includes('/api/v1/info')?{Version:'controlled'}:{status:'ok'})};},now:()=>clock,delay:async ms=>{clock+=ms;},
  });
  return{factory,session,calls,ownLabChild,options:{session,root,ownLabChild},foreign(){unsafe=true;},missing(){missing=true;},unhealthy(){healthy=false;},corruptImage(){actualHashes['mcp-sandbox']='f'.repeat(64);}};
}
test('base bundle includes exact ordinary Dockerfile COPY inputs, guest loopback ports and preserved teaching sinks',async()=>{
  // Existing runner collector has separate COPY-closure controls. Its labfs
  // synthetic credentials are intentionally denied by this unit read guard.
  const result=await fixture().factory.reviewedBaseBundle(root);
  const names=result.files.map(file=>file.path);
  for(const context of ['rogue-mcp','ssrf-target'])for(const name of ['Dockerfile','index.js'])assert(names.includes('sidecars/'+context+'/'+name));
  assert(!names.some(name=>name==='.env'||name.includes('administrator')||name.includes('node_modules')||name.startsWith('server/')));
  const compose=result.files.find(file=>file.path==='docker-compose.yml');assert.equal(compose.sha256,hash(compose.bytes));
  const text=compose.bytes.toString();for(const port of [8090,8091,9099])assert(text.includes('"127.0.0.1:'+port+':'+port+'"'));
  assert(text.includes('apparmor:unconfined'));assert(text.includes('mcp-owned-targets:/sandbox/owned-targets'));
});
test('fresh base services build through branded guest stable project then forward before localhost readiness',async()=>{
  const f=fixture(),result=await f.factory.provisionWindowsBaseLabServices(f.options);
  assert.equal(result.project,'dvaia-'+workspaceId(root));assert.deepEqual(Object.keys(result.containers),services);
  const up=f.calls.find(call=>call[0]==='docker'&&call[1].includes('up'));
  assert(up[1].includes('--build'));assert(up[1].includes('--wait'));assert.deepEqual(up[1].slice(-4),services);
  assert(up[2].bundlePath.startsWith('/var/lib/dvaia/owned/bundles/'));assert.equal(up[2].scope,'provision');
  assert.equal(up[2].timeoutMs,600000);
  assert(f.calls.filter(call=>call[0]==='docker'&&call!==up).every(call=>!Object.hasOwn(call[2],'timeoutMs')));
  assert(f.calls.findIndex(call=>call[0]==='forward')<f.calls.findIndex(call=>call[0]==='fetch'));
  assert.deepEqual(result.ports.map(port=>port.local).sort((a,b)=>a-b),[1025,8025,8090,8091,9099]);
});
test('start verifies existing source-labelled images and owned containers, never builds/pulls/recreates',async()=>{
  const f=fixture();await f.factory.provisionWindowsBaseLabServices(f.options);f.calls.length=0;
  await f.factory.provisionWindowsBaseLabServices({...f.options,mode:'start'});
  const up=f.calls.find(call=>call[0]==='docker'&&call[1].includes('up'));
  assert(up[1].includes('--no-recreate'));assert(up[1].includes('--no-build'));assert(up[1].includes('--pull'));assert(up[1].includes('never'));assert(!up[1].includes('--build'));
  assert(!Object.hasOwn(up[2],'timeoutMs'));
  assert(f.calls.findIndex(call=>call[0]==='docker'&&call[1][0]==='inspect')<f.calls.indexOf(up));
});
test('start fails closed before up for missing/changed images and foreign Compose identity',async()=>{
  for(const change of [f=>f.missing(),f=>f.corruptImage(),f=>f.foreign()]){
    const f=fixture();await f.factory.provisionWindowsBaseLabServices(f.options);f.calls.length=0;change(f);
    await assert.rejects(f.factory.provisionWindowsBaseLabServices({...f.options,mode:'start'}),{code:'WINDOWS_BASE_LAB_SERVICES_DENIED'});
    assert(!f.calls.some(call=>call[0]==='docker'&&call[1].includes('up')));assert(!f.calls.some(call=>call[0]==='forward'));
  }
});
test('failure readiness is bounded and redacted without teardown or mutation of sibling services',async()=>{
  const f=fixture();f.unhealthy();await assert.rejects(f.factory.provisionWindowsBaseLabServices({...f.options,healthTimeoutMs:200}),error=>error.code==='WINDOWS_BASE_LAB_SERVICES_DENIED'&&!error.message.includes('private-password'));
  assert(!f.calls.some(call=>call[0]==='docker'&&call[1].some(arg=>['down','rm','prune','reset'].includes(arg))));
});
test('default opaque brand rejects fake sessions and unsupported modes before guest operations',async()=>{
  await assert.rejects(provisionWindowsBaseLabServices({session:{},root,ownLabChild:async()=>{}}),{code:'WINDOWS_BASE_LAB_SERVICES_DENIED'});
  const f=fixture();await assert.rejects(f.factory.provisionWindowsBaseLabServices({...f.options,mode:'reset'}));assert.equal(f.calls.length,0);
});
