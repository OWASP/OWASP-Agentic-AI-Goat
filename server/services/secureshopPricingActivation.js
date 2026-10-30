'use strict';
const path=require('node:path');
const managed=require('./secureshopPricingManagedConfiguration');
const {capturePricingPackage}=require('./secureshopPricingPackage');
const {verifyDockerAuthority,executeBoundDocker}=require('../../scripts/local-docker-authority');
const {createPricingHttpClient}=require('./secureshopPricingHttpClient');
const FLAG='SS_BOUND_PRICING_ENABLED';
const fail=()=>Object.assign(Error('Owned Pricing activation unavailable'),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
function activationPolicy(env=process.env){
 if(env[FLAG]!==undefined&&!['true','false'].includes(env[FLAG]))throw fail();
 if(env[FLAG]!=='true')return Object.freeze({requested:false});
 if(env.SS_ENABLE!=='true'||env.SS_BOUND_REVIEWS_ENABLED!=='true'||env.PLATFORM_DATABASE_ENGINE!=='postgres'||env.WORKSHOP_DATABASE_ENGINE!=='postgres')throw fail();
 if(env.SS_PRICING_BASE_URL!==undefined||env.SS_PRICING_TOKEN!==undefined)throw fail();
 return Object.freeze({requested:true});
}
const stagedProofs=new WeakMap();
async function inspectPricingClient({env=process.env,root=path.resolve(__dirname,'../..'),home,fetchImpl=fetch,execute,onDiagnostic,portCandidate}={},enabled,readiness=true){
 let phase='managed-record';
 try{
  const record=managed.load({root,home});if(!record||record.config.enabled!==enabled)throw fail();let c=record.config;
  // A read-only candidate inspection does not activate or replace authority.
  // Only the disabled legacy collision may inspect its exact successor profile.
  if(portCandidate){if(enabled||readiness||c.port!==8093||portCandidate.port!==8096||!/^[a-f0-9]{64}$/.test(portCandidate.containerId))throw fail();c=managed.validate({...c,...portCandidate},{root});}
  if(capturePricingPackage(root).sha256!==c.packageSha256)throw fail();
  phase='docker-authority';await verifyDockerAuthority({authority:record.authority,execute,environment:env});
  const inspect=async args=>JSON.parse((await executeBoundDocker({authority:record.authority,execute,environment:env,args,options:{timeout:10000,maxBuffer:1024*1024}})).stdout)[0];
  phase='resource-inspection';const image=await inspect(['image','inspect',c.imageId]),container=await inspect(['inspect',c.containerId]);
  const h=container.HostConfig,labels=container.Config.Labels||{};
  const expectedEntrypoint=['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'];
  const expectedEnv=[...(image.Config.Env||[]),'SECURESHOP_PRICING_ENABLED=true','SECURESHOP_PRICING_TOKEN='+c.token,'SECURESHOP_PRICING_PROFILE='+c.profile,'SECURESHOP_PRICING_HOST=0.0.0.0','SECURESHOP_PRICING_PORT=8093'].sort();
  // A failed first start can detach the configured bridge without executing.
  // The real bridge identity is still checked below; live readiness stays strict.
  const networks=container.NetworkSettings.Networks;
  const unattachedNeverStarted=!enabled&&!readiness&&networks&&typeof networks==='object'&&!Array.isArray(networks)&&Object.keys(networks).length===0
   &&container.State.Status==='created'&&container.State.Running===false&&container.State.StartedAt==='0001-01-01T00:00:00Z'
   &&container.State.FinishedAt==='0001-01-01T00:00:00Z'&&container.RestartCount===0;
  if(JSON.stringify(image.Config.Entrypoint)!==JSON.stringify(expectedEntrypoint)||JSON.stringify(container.Config.Entrypoint)!==JSON.stringify(expectedEntrypoint)||JSON.stringify(container.Config.Cmd)!==JSON.stringify(image.Config.Cmd)||JSON.stringify([...(container.Config.Env||[])].sort())!==JSON.stringify(expectedEnv)||(!unattachedNeverStarted&&JSON.stringify(Object.keys(networks||{}))!==JSON.stringify(['owasp-ai-goat-pricing-'+c.workspaceId+'-network']))||h.Binds?.length||h.Devices?.length||h.DeviceRequests?.length||h.PidMode||h.IpcMode==='host'||h.UsernsMode==='host')throw fail();
  if(image.Id!==c.imageId||image.Architecture!=='arm64'||image.Config.Labels?.['owasp-ai-goat.pricing.package']!==c.packageSha256||container.Id!==c.containerId||container.Name!=='/'+c.containerName||container.Image!==c.imageId||(readiness&&!container.State.Running)||labels['owasp-ai-goat.pricing.owner']!==c.ownerId||labels['owasp-ai-goat.pricing.workspace']!==c.workspaceId||labels['owasp-ai-goat.pricing.package']!==c.packageSha256||container.Config.User!=='10001:10001'||container.Mounts.length||h.Privileged||h.CapAdd?.length||JSON.stringify(h.CapDrop)!=='["ALL"]'||!h.ReadonlyRootfs||h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128||JSON.stringify(h.PortBindings)!==JSON.stringify({'8093/tcp':[{HostIp:'127.0.0.1',HostPort:String(c.port)}]})||(container.State.Running&&JSON.stringify(container.NetworkSettings.Ports)!==JSON.stringify({'8093/tcp':[{HostIp:'127.0.0.1',HostPort:String(c.port)}]}))||h.NetworkMode!=='owasp-ai-goat-pricing-'+c.workspaceId+'-network'||JSON.stringify(h.Tmpfs)!==JSON.stringify({'/tmp':'rw,nosuid,nodev,size=134217728'})||h.SecurityOpt.length!==2||!h.SecurityOpt.includes('apparmor='+c.profile)||!h.SecurityOpt.includes('seccomp=unconfined'))throw fail();
  phase='network-inspection';const network=await inspect(['network','inspect',h.NetworkMode]);
  if(network.Name!==h.NetworkMode||network.Labels?.['owasp-ai-goat.pricing.owner']!==c.ownerId||network.Labels?.['owasp-ai-goat.pricing.workspace']!==c.workspaceId||network.Driver!=='bridge')throw fail();
  const config=Object.fromEntries(container.Config.Env.map(row=>{const at=row.indexOf('=');return[row.slice(0,at),row.slice(at+1)];}));
  if(config.SECURESHOP_PRICING_ENABLED!=='true'||config.SECURESHOP_PRICING_TOKEN!==c.token||config.SECURESHOP_PRICING_PROFILE!==c.profile)throw fail();
  phase='authenticated-readiness';const client=createPricingHttpClient({baseURL:`http://127.0.0.1:${c.port}`,token:c.token,fetchImpl});if(readiness){const deadline=Date.now()+3000;for(;;){try{await client.assertReady();break;}catch(error){if(Date.now()>=deadline)throw error;await new Promise(resolve=>setTimeout(resolve,100));}}}
  phase='record-recapture';const current=managed.load({root,home});if(capturePricingPackage(root).sha256!==c.packageSha256||current?.sha256!==record.sha256||current.identity.ino!==record.identity.ino||current.identity.dev!==record.identity.dev)throw fail();
  return {client,record,root,home};
 }catch{if(typeof onDiagnostic==='function')onDiagnostic(Object.freeze({phase}));throw fail();}
}
async function preparePricingClient(options={}){if(!activationPolicy(options.env||process.env).requested)return undefined;return(await inspectPricingClient(options,true)).client;}
async function verifyStagedPricing(options={}){
 if(!activationPolicy(options.env||process.env).requested)throw fail();
 const verified=await inspectPricingClient(options,false),proof=Object.freeze({ready:true});stagedProofs.set(proof,{...verified,verifiedAt:require('node:perf_hooks').performance.now()});return proof;
}
function activateStagedPricing(proof){
 const verified=stagedProofs.get(proof);if(!verified)throw fail();stagedProofs.delete(proof);
 if(require('node:perf_hooks').performance.now()-verified.verifiedAt>5000)throw fail();
 if(capturePricingPackage(verified.root).sha256!==verified.record.config.packageSha256)throw fail();
 return managed.compareAndSwap({root:verified.root,home:verified.home,expected:verified.record,enabled:true});
}
async function inspectPricingBeforeStart(options={}){const record=managed.load(options);if(!record)throw fail();const verified=await inspectPricingClient(options,record.config.enabled,false);return Object.freeze({containerId:verified.record.config.containerId});}
async function inspectPricingPortCandidate(options={}){await inspectPricingClient(options,false,false);return Object.freeze({verified:true});}
module.exports={activationPolicy,preparePricingClient,verifyStagedPricing,activateStagedPricing,inspectPricingBeforeStart,inspectPricingPortCandidate};
