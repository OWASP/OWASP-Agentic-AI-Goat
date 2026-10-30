'use strict';
// Explicit owned mac-host/Colima Linux-VM qualification. Never use app stores.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),net=require('node:net'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');
const {provision,plan}=require('../../scripts/install/mcp-owned-http');
const {createCommandRunner}=require('../../scripts/install/mcp-owned-provision');
const config=require('../../server/services/mcp/ownedHttpManagedConfiguration');
const {createOwnedHttpServiceClient}=require('../../server/services/mcp/ownedHttpServiceClient');
const docker='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker';
const env={...process.env};delete env.DOCKER_HOST;delete env.DOCKER_CONTEXT;
const exec=createCommandRunner({cwd:root,env});
const run=(file,args,options)=>exec(file==='docker'?docker:file,args,options);
const checked=async(file,args)=>{const r=await run(file,args,{timeoutMs:30000,maxOutputBytes:1024*1024});assert.equal(r.exitCode,0);return r.stdout;};
(async()=>{
 const scratch=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-http-installer-native-'));
 const listener=net.createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));const port=listener.address().port;await new Promise(resolve=>listener.close(resolve));
 const opts={root:scratch,home:os.homedir(),platform:'darwin',colimaProfile:'colima-owasp-ai-goat-pg-verify',port,commandEnv:env,run};const p=plan(opts);
 const D=args=>checked('docker',['--host',p.dockerHost,...args]);
 const S=args=>checked('ssh',['-F',p.sshConfig,p.sshHost,args.join(' ')]);
 const evidence={scope:'macOS arm64 host invoking application installer against existing isolated Colima Linux arm64 VM',profile:p.profile,port,actualInstaller:true,defaultActivated:false};
 try{
  assert.equal((await D(['ps','-aq','--filter',`name=^/${p.container}$`])).trim(),'');
  await fs.mkdir(path.join(scratch,'sidecars'),{recursive:true});await fs.cp(path.join(root,'sidecars/sandbox-runner'),path.join(scratch,'sidecars/sandbox-runner'),{recursive:true});
  evidence.first=await provision(opts);const firstConfig=await fs.readFile(p.managedPath),first=JSON.parse(await D(['inspect',p.container]))[0];
  evidence.repeat=await provision(opts);const second=JSON.parse(await D(['inspect',p.container]))[0];
  assert.equal(first.Id,second.Id);assert.deepEqual(await fs.readFile(p.managedPath),firstConfig);evidence.repeatPreservesContainerAndConfig=true;
  const cfg=config.load({file:p.managedPath}),client=createOwnedHttpServiceClient({baseUrl:cfg.url,token:cfg.token});
  const scope={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:11,generation:0};
  const admitted=await client.admit(scope);const request={url:'http://169.254.169.254/latest/?installer=%2f',mode:'vuln',runId:crypto.randomUUID(),operationId:crypto.randomUUID(),invocationId:crypto.randomUUID(),mcpSessionId:'mcp_7'};
  const receipt=await client.request('/owned-http/execute',{capability:admitted.capability,request});assert.equal(receipt.result.status,'completed');evidence.actualSocket=true;
  // Restart the exact owned service and verify journal persistence using a new
  // process-local capability, with no second network request.
  await D(['restart',p.container]);await provision(opts);const readmitted=await client.admit(scope);
  const replay=await client.request('/owned-http/execute',{capability:readmitted.capability,request});assert.deepEqual(replay,receipt);evidence.persistentReceiptReplay=true;
  const operationId=crypto.randomUUID();await client.retire({...scope,operationId});assert.equal((await client.readRetirement({...scope,operationId})).status,'completed');evidence.retirement=true;
  await D(['rm','-f',p.container]);
  await D(['run','--detach','--name',p.container,'--label','owasp-ai-goat.http.owner=controlled-conflict','--network','none','--entrypoint','sleep',cfg.image,'300']);
  await assert.rejects(provision(opts),/MCP_HTTP_CONTAINER_CONFLICT/);evidence.ownershipConflictRejected=true;
  evidence.image=cfg.image;evidence.profileSha256=crypto.createHash('sha256').update(await S(['sudo','cat',p.destination])).digest('hex');
  evidence.status='passed';
 }catch(error){evidence.status='failed';evidence.error=error.code||error.message;process.exitCode=1;}
 finally{
  await D(['rm','-f',p.container]).catch(()=>{});
  evidence.containerAbsent=!(await D(['ps','-aq','--filter',`name=^/${p.container}$`])).trim();
  if(evidence.containerAbsent){await D(['volume','rm',p.volume]).catch(()=>{});await S(['sudo','apparmor_parser','-R',p.destination]).catch(()=>{});await S(['sudo','rm','-f',p.destination]);}
  const profiles=await S(['sudo','cat','/sys/kernel/security/apparmor/profiles']);evidence.profileAbsent=!profiles.split('\n').some(x=>x.startsWith(p.profile+' ')||x.startsWith(p.profile+'//'));
  evidence.volumeAbsent=!(await D(['volume','ls','-q','--filter',`name=^${p.volume}$`])).trim();
  if(evidence.profileAbsent&&evidence.containerAbsent&&evidence.volumeAbsent){await fs.rm(path.dirname(p.managedPath),{recursive:true,force:true});await fs.rm(scratch,{recursive:true,force:true});await D(['image','rm',`${p.container}:local`]).catch(()=>{});}
  evidence.sourceHashes={};for(const file of ['scripts/install/mcp-owned-http.js','scripts/install/mcp-owned-provision.js','server/services/mcp/ownedHttpManagedConfiguration.js','tests/fixtures/mcpOwnedHttpInstaller.native.cjs'])evidence.sourceHashes[file]=crypto.createHash('sha256').update(await fs.readFile(path.join(root,file))).digest('hex');
  await fs.writeFile(path.join(root,'tasks/mcp-owned-http-installer-native-2026-09-19.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify(evidence));
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
