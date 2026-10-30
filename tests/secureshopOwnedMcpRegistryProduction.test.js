'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {workspaceId}=require('../server/services/mcp/ownedManagedConfiguration');
const production=require('../server/services/secureshopOwnedMcpRegistryProduction');
const config=()=>({version:1,workspace:workspaceId(process.cwd()),enabled:true,baseURL:'http://127.0.0.1:8099',token:'a'.repeat(43),runtimeDigest:'b'.repeat(64),mode:'vuln'});
test('private production configuration requires an exact runtime pin and closed local authority',()=>{
 assert.equal(production.PRODUCTION_QUALIFIED,true);
 assert.equal(production.validateConfiguration(config()).mode,'vuln');
 for(const patch of [{runtimeDigest:undefined},{runtimeDigest:'latest'},{workspace:'other'},{baseURL:'http://example.com:8099'},{mode:'browser'},{extra:true}])assert.throws(()=>production.validateConfiguration({...config(),...patch}));
});
test('production forwards exact pin, immutable mode, and drains full admitted mutation on shutdown',async()=>{
 let received,mode,release,entered;const ready=new Promise(r=>entered=r),held=new Promise(r=>release=r);
 const runtime=await production.createOwnedMcpRegistryProduction({configuration:config(),createClient:args=>{received=args;return{health:async()=>{}};},createComposition:async args=>{
  mode=await args.readMode();return{capability:'test',router:()=>{},service:args.wrapService({async mutate(_args,{signal}){entered();await held;assert.equal(signal.aborted,true);return{state:'unknown'};},async read(){return{};}})};
 }});
 assert.equal(received.expectedRuntimeDigest,config().runtimeDigest);assert.equal(mode,'vuln');
 const request=runtime.service.mutate({});await ready;let closed=false;const closing=runtime.close().then(()=>closed=true);await Promise.resolve();assert.equal(closed,false);
 await assert.rejects(runtime.service.read({}),{code:'MCP_REGISTRY_NOT_READY'});release();assert.deepEqual(await request,{state:'unknown'});await closing;assert.equal(closed,true);
});
test('disabled serving does not construct executor transport',async()=>{const runtime=await production.createOwnedMcpRegistryProduction({configuration:{enabled:false},createClient(){throw Error('must not call');}});assert.equal(runtime.ready,false);await runtime.close();});
test('executor health rejects a different well formed digest',async()=>{
 const {createOwnedMcpRegistryClient}=require('../server/services/secureshopOwnedMcpRegistryClient');
 const {MCP_REGISTRY_CAPABILITY}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
 const client=createOwnedMcpRegistryClient({...config(),expectedRuntimeDigest:'b'.repeat(64),fetchImpl:async()=>Response.json({version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:MCP_REGISTRY_CAPABILITY,runtimeDigest:'c'.repeat(64)})});
 await assert.rejects(client.health(),{code:'MCP_REGISTRY_EXECUTOR_UNAVAILABLE'});
});
test('wrapper preserves synchronous request snapshot and same-tick shutdown tracking',async()=>{
 const {createOwnedMcpRegistry}=require('../server/services/secureshopOwnedMcpRegistry');
 let prepared,release;const held=new Promise(r=>release=r);
 const repository={prepare(raw){prepared=structuredClone(raw);return prepared;},async beginPrepared(p){await held;return{newlyAdmitted:false,operation:p};},async activeEntries(){},async publish(){},async finish(){},async read(){}};
 const runtime=await production.createOwnedMcpRegistryProduction({configuration:config(),createClient:()=>({health:async()=>{}}),createComposition:async args=>({service:args.wrapService(createOwnedMcpRegistry({repository,executor:{async execute(){}},readMode:args.readMode})),router:()=>{}})});
 const input={request:{name:'original'}};const request=runtime.service.mutate(input);input.request.name='changed';assert.equal(prepared.request.name,'original');
 let closed=false;const closing=runtime.close().then(()=>closed=true);await Promise.resolve();assert.equal(closed,false);release();assert.equal((await request).request.name,'original');await closing;
});
test('general registry reads survive only explicit trust-disabled status, not arbitrary outages',async()=>{
 const {createOwnedMcpRegistryAdminReadOverlay}=require('../server/services/secureshopOwnedMcpRegistryAdminReadOverlay');
 let code='BOUND_MCP_DISABLED';const deny=async()=>{throw Object.assign(Error('closed'),{code});};
 const overlay=createOwnedMcpRegistryAdminReadOverlay({enabled:true,base:{mcpServers:deny,mcpHistory:deny,mcpTools:deny},repository:{head:async()=>'0',servers:async()=>[{name:'owned'}],history:async()=>[],tools:async()=>null}});
 assert.equal((await overlay.mcpServers({launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:7,platformSessionId:11})).servers[0].name,'owned');assert.deepEqual((await overlay.mcpHistory({})).history,[]);
 code='BOUND_MCP_UNAVAILABLE';await assert.rejects(overlay.mcpServers({launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:7,platformSessionId:11}),{code});
});
test('absent private configuration disables; malformed present configuration fails even before activation',async t=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');const home=await fs.mkdtemp(path.join(os.tmpdir(),'owned-mcp-config-'));t.after(()=>fs.rm(home,{recursive:true,force:true}));
 assert.equal(await production.readConfiguration({home}),null);
 const dir=path.join(home,'.owasp-ai-goat',workspaceId(process.cwd()));await fs.mkdir(dir,{recursive:true});const file=path.join(dir,'secureshop-owned-mcp-registry.json');
 await fs.writeFile(file,'{}',{mode:0o600});await assert.rejects(production.readConfiguration({home}),{code:'MCP_REGISTRY_NOT_READY'});
 await fs.writeFile(file,JSON.stringify({...config(),enabled:false}));assert.equal((await production.readConfiguration({home})).enabled,false);
 await fs.chmod(file,0o644);await assert.rejects(production.readConfiguration({home}),{code:'MCP_REGISTRY_NOT_READY'});
});
