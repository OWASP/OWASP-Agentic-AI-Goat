'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {createMcpTargetStore,_internals}=require('../sidecars/sandbox-runner/mcpTargets');

async function fixture(t,options={}){
 const base=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-mcp-target-'));t.after(()=>fs.rm(base,{recursive:true,force:true}));
 const source=path.join(base,'source'),root=path.join(base,'private');
 for(const [name,value] of [['var/secrets/master_key.txt','MASTER=A'],['opt/app/config/.env','DB_PASSWORD=A'],['opt/lab/bin/rotate_keys.sh','#!/bin/sh'],['home/mcp-admin/readme','home'],['etc/passwd','mcp:x:1000:1000']]){const file=path.join(source,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,value);}
 await fs.cp(path.join(__dirname,'../sidecars/sandbox-runner/labfs/opt/lab/packages'),path.join(source,'opt/lab/packages'),{recursive:true});
 await fs.chmod(path.join(source,'opt/lab/bin/rotate_keys.sh'),0o700);
 const flockExecutable=path.join(base,'flock-helper.py');
 await fs.writeFile(flockExecutable,"#!/usr/bin/env python3\nimport fcntl,sys\nf=open(sys.argv[1],'a+')\ntry: fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(75)\nsys.stdout.write('MCP_TARGET_LOCK_READY\\n');sys.stdout.flush();sys.stdin.buffer.read()\nsys.exit(int(sys.argv[2]) if len(sys.argv)>2 else 0)\n");
 await fs.chmod(flockExecutable,0o700);
 const seccompFilterPath=path.join(base,'mcp-target.seccomp.bpf');
 const seccompMetadataPath=path.join(base,'mcp-target.seccomp.json');
 const filter=Buffer.alloc(8);await fs.writeFile(seccompFilterPath,filter,{mode:0o400});
 const arch=process.arch==='arm64'?'arm64':'amd64';
 await fs.writeFile(seccompMetadataPath,JSON.stringify({arch,sha256:crypto.createHash('sha256').update(filter).digest('hex'),version:1})+'\n',{mode:0o400});
 await fs.mkdir(root,{mode:0o700});
 const lockOptions={flockExecutable,flockArguments:lockFile=>[lockFile],seccompFilterPath,seccompMetadataPath,seccompOwnerUid:process.getuid?.()??0,
  tarExecutable:flockExecutable,
  runtimeSources:_internals.RUNTIME_DESTINATIONS,runtimeOwnerUid:process.getuid?.()??0,
  runtimeLstat:async()=>({isFile:()=>true,isSymbolicLink:()=>false,uid:process.getuid?.()??0,mode:0o100500})};
 return{base,source,root,lockOptions,store:createMcpTargetStore({root,fixtureRoot:source,clock:()=> '2026-09-13T12:34:56.000Z',...lockOptions,...options})};
}
const bind=(owner=1,targetId=crypto.randomUUID())=>({targetId,ownerId:owner,platformSessionId:owner+100,generation:4});
const allow=async()=>true;

test('minimal runtime mounts omit absent architecture paths and retain present fixed paths',async()=>{
 const directory=()=>({isDirectory:()=>true,isSymbolicLink:()=>false});
 const missingLib64=await _internals.existingSystemBinds(async source=>{
  if(source==='/lib64'){const error=Error('missing');error.code='ENOENT';throw error;}return directory();
 });
 assert.deepEqual(missingLib64,['/usr','/bin','/lib']);
 assert.deepEqual(await _internals.existingSystemBinds(async()=>directory()),['/usr','/bin','/lib','/lib64']);
 await assert.rejects(_internals.existingSystemBinds(async()=>({isDirectory:()=>false,isSymbolicLink:()=>false})),{code:'SYSTEM_RUNTIME_INVALID'});
 const executable=()=>({isFile:()=>true,isSymbolicLink:()=>false,uid:7,mode:0o100500});
 assert.equal(await _internals.verifyRuntimeSources(_internals.RUNTIME_DESTINATIONS,7,async()=>executable()),true);
 for(const change of [{uid:8},{mode:0o100700},{mode:0o100400},{isFile:()=>false}]){
  await assert.rejects(_internals.verifyRuntimeSources(_internals.RUNTIME_DESTINATIONS,7,async()=>({...executable(),...change})),{code:'SYSTEM_RUNTIME_INVALID'});
 }
 await assert.rejects(_internals.verifyRuntimeSources({..._internals.RUNTIME_DESTINATIONS,node:'/tmp/untrusted-node'},7,async()=>executable()),{code:'INVALID_CONFIGURATION'});
 await assert.rejects(_internals.verifyRuntimeSources(_internals.RUNTIME_DESTINATIONS,7,async()=>({...executable(),isSymbolicLink:()=>true})),{code:'SYSTEM_RUNTIME_INVALID'});
});

test('readiness verifies the exact kernel helpers, runtime files and seccomp receipt before admission',async t=>{
 const f=await fixture(t);const readyStore=createMcpTargetStore({root:f.root,fixtureRoot:f.source,
  ...f.lockOptions,bwrapExecutable:f.lockOptions.flockExecutable});
 assert.deepEqual(await readyStore.checkReadiness(),{ready:true,isolation:'bwrap-seccomp-v1'});
 const missing=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions,bwrapExecutable:path.join(f.base,'missing-bwrap')});
 await assert.rejects(missing.checkReadiness(),{code:'SYSTEM_RUNTIME_INVALID'});
 const altered=await fixture(t);const signature=path.join(altered.source,'opt/lab/packages/acme-analytics-1.0.0.tgz.sig');
 await fs.writeFile(signature,Buffer.alloc(64));
 const alteredStore=createMcpTargetStore({root:altered.root,fixtureRoot:altered.source,...altered.lockOptions,
  bwrapExecutable:altered.lockOptions.flockExecutable});
 await assert.rejects(alteredStore.checkReadiness(),{code:'PACKAGE_SIGNATURE_INVALID'});
});

test('provisions exact owned roots and builds minimal-rootfs argv without sibling or host root exposure',async t=>{
 const f=await fixture(t),a=bind(1),b=bind(2);const pa=await f.store.provisionTarget(a,{authorize:allow});const pb=await f.store.provisionTarget(b,{authorize:allow});
 const argv=await f.store.buildBwrapArgv(pa.capability,allow,'cat /var/secrets/master_key.txt');
 assert.equal(argv.join('\0').includes('--ro-bind\0/\0/'),false);assert.ok(argv.includes('--tmpfs'));
 assert.ok(argv.includes('--unshare-user'));assert.equal(argv.includes('--disable-userns'),false);assert.ok(argv.includes('--unshare-net'));assert.ok(argv.includes('--unshare-pid'));
 assert.deepEqual(argv.slice(argv.indexOf('--seccomp'),argv.indexOf('--seccomp')+2),['--seccomp','3']);
 assert.equal(argv.includes('/usr/local/bin:/usr/bin:/bin'),true);
 assert.equal(argv.includes('--proc'),false);assert.deepEqual(argv.slice(argv.indexOf('--dev'),argv.indexOf('--dev')+4),['--dev','/dev','--dir','/proc']);
 assert.equal(argv.some(value=>String(value).includes(b.targetId)),false);assert.equal(argv.some(value=>String(value).includes(path.join(f.root,'journals'))),false);
 assert.equal(argv.at(-1),'cat /var/secrets/master_key.txt');
 const script=argv[argv.indexOf('/opt/lab/bin')-1];assert.equal((await fs.stat(path.join(script,'rotate_keys.sh'))).mode&0o100,0o100);
 await assert.rejects(f.store.buildBwrapArgv(pb.capability,async()=>false,'pwd'),{code:'TARGET_AUTHORITY_REVOKED'});
});

test('two store instances share the filesystem admission lock and cannot overlap retirement',async t=>{
 const f=await fixture(t),a=bind(22),b=bind(23);const provisioned=await f.store.provisionTarget(a,{authorize:allow});const sibling=await f.store.provisionTarget(b,{authorize:allow});const other=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions});
 let release,entered;const held=new Promise(resolve=>{release=resolve});const admitted=new Promise(resolve=>{entered=resolve});
 const use=f.store.withTarget(provisioned.capability,allow,async()=>{entered();await held});await admitted;
 const op=crypto.randomUUID();await assert.rejects(other.retireTarget(a,{operationId:op,authorize:allow}),{code:'TARGET_LOCKED'});
 release();await use;assert.equal((await other.retireTarget(a,{operationId:op,authorize:allow})).status,'completed');
 await assert.rejects(f.store.withTarget(provisioned.capability,allow,async()=>{}),{code:'TARGET_RETIRED'});
 assert.equal(await f.store.withTarget(sibling.capability,allow,async()=> 'sibling-usable'),'sibling-usable');
});

test('protected-state effects use the capability lock, survive recovery, and retire with their exact target',async t=>{
 const f=await fixture(t),a=bind(52),b=bind(53);const pa=await f.store.provisionTarget(a,{authorize:allow});const pb=await f.store.provisionTarget(b,{authorize:allow});
 const runId=crypto.randomUUID();const read=await f.store.executeProtectedOperation(pa.capability,allow,
  {operation:'read_configuration',arguments:{},runId});
 assert.equal(read.targetId,a.targetId);assert.match(read.output,/DB_PASSWORD=A/);assert.equal(read.runId,runId);
 const rotated=await f.store.executeProtectedOperation(pa.capability,allow,
  {operation:'rotate_keys',arguments:{labRole:'unprivileged',enforceAuthorization:false},runId:crypto.randomUUID()});
 assert.equal(rotated.changed,true);assert.equal(rotated.keyVersionAfter,2);
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions});
 const recovered=await restarted.recoverTarget(a,{authorize:allow});
 const audit=await restarted.executeProtectedOperation(recovered.capability,allow,
  {operation:'inspect_audit',arguments:{},runId:crypto.randomUUID()});
 assert.equal(audit.entryCount,2);
 const sibling=await f.store.executeProtectedOperation(pb.capability,allow,
  {operation:'inspect_audit',arguments:{},runId:crypto.randomUUID()});assert.equal(sibling.entryCount,0);
 await restarted.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow});
 await assert.rejects(restarted.executeProtectedOperation(recovered.capability,allow,
  {operation:'inspect_audit',arguments:{},runId:crypto.randomUUID()}),{code:'TARGET_RETIRED'});
});

test('owned poisoned and benign ticket bytes are target-private, replay across recovery, isolate siblings, and retire',async t=>{
 const f=await fixture(t),a=bind(61),b=bind(62);const pa=await f.store.provisionTarget(a,{authorize:allow});const pb=await f.store.provisionTarget(b,{authorize:allow});
 const runId=crypto.randomUUID();const requests=Object.fromEntries(_internals.CONTROLLED_TICKET_IDS.map(ticketId=>
  [ticketId,{ticketId,runId,operationId:crypto.randomUUID()}]));
 const receipts={};for(const ticketId of _internals.CONTROLLED_TICKET_IDS){receipts[ticketId]=await f.store.readTicket(pa.capability,allow,requests[ticketId]);}
 const request=requests['4295'],first=receipts['4295'];
 assert.equal(first.targetId,a.targetId);assert.equal(first.platformOwnerId,a.ownerId);assert.equal(first.ticket.id,'4295');
 assert.match(first.ticket.body,/send_report/);assert.equal(first.ticket.body.includes('DB_PASSWORD=A'),false);
 assert.equal(first.artifactByteCount,Buffer.byteLength(JSON.stringify(first.ticket)+'\n'));
 assert.equal(first.artifactSha256,crypto.createHash('sha256').update(JSON.stringify(first.ticket)+'\n').digest('hex'));
 for(const ticketId of ['4290','4301']){
  assert.equal(receipts[ticketId].ticket.id,ticketId);assert.doesNotMatch(receipts[ticketId].ticket.body,
   /read_configuration|send_report|protected[- ](?:state|configuration)|mcp-audit-/i);
 }
 assert.equal(new Set(Object.values(receipts).map(value=>value.artifactSha256)).size,3);
 const artifactRoot=path.join(f.root,'targets',a.targetId,'rootfs');const actualBytes=[];
 for(const ticketId of _internals.CONTROLLED_TICKET_IDS){
  const bytes=await fs.readFile(_internals.ticketArtifactPath(artifactRoot,ticketId));actualBytes.push(bytes.toString('utf8'));
  assert.deepEqual(bytes,_internals.ticketArtifactBytes({targetId:a.targetId,ownerId:a.ownerId,
    platformSessionId:a.platformSessionId,generation:a.generation},ticketId));
 }
 assert.equal(new Set(actualBytes).size,3);
 for(const ticketId of _internals.CONTROLLED_TICKET_IDS)assert.deepEqual(await f.store.readTicket(pa.capability,allow,requests[ticketId]),receipts[ticketId]);
 await assert.rejects(f.store.readTicket(pa.capability,allow,{...requests['4295'],ticketId:'4301'}),{code:'TICKET_RECEIPT_INVALID'});
 const sibling={};for(const ticketId of _internals.CONTROLLED_TICKET_IDS){sibling[ticketId]=await f.store.readTicket(pb.capability,allow,
  {...requests[ticketId],operationId:crypto.randomUUID()});assert.notEqual(sibling[ticketId].artifactSha256,receipts[ticketId].artifactSha256);}
 assert.notEqual(sibling['4295'].ticket.subject,first.ticket.subject);
 await assert.rejects(f.store.readTicket(pa.capability,allow,{ticketId:'4299',runId,operationId:crypto.randomUUID()}),{code:'TICKET_OPERATION_INVALID'});
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions});
 const recovered=await restarted.recoverTarget(a,{authorize:allow});
 for(const ticketId of _internals.CONTROLLED_TICKET_IDS)assert.deepEqual(await restarted.readTicket(recovered.capability,allow,requests[ticketId]),receipts[ticketId]);
 await assert.rejects(restarted.readTicket(recovered.capability,allow,{...request,runId:crypto.randomUUID()}),{code:'TICKET_RECEIPT_INVALID'});
 const artifact=_internals.ticketArtifactPath(artifactRoot);
 await fs.writeFile(artifact,'{"body":"forged"}\n');
 await assert.rejects(restarted.readTicket(recovered.capability,allow,{...request,operationId:crypto.randomUUID()}),{code:'TICKET_ARTIFACT_INVALID'});
 await fs.writeFile(artifact,_internals.ticketArtifactBytes({targetId:a.targetId,ownerId:a.ownerId,platformSessionId:a.platformSessionId,generation:a.generation}));
 await restarted.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow});
 for(const ticketId of _internals.CONTROLLED_TICKET_IDS)await assert.rejects(fs.stat(_internals.ticketArtifactPath(
  artifactRoot,ticketId)),{code:'ENOENT'});
 assert.equal((await f.store.readTicket(pb.capability,allow,{...request,operationId:crypto.randomUUID()})).targetId,b.targetId);
});

test('owned ticket recovery publishes exact valid staged bytes and preserves rejected staged evidence',async t=>{
 const f=await fixture(t),a=bind(66),provisioned=await f.store.provisionTarget(a,{authorize:allow});
 const request={ticketId:'4295',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 const first=await f.store.readTicket(provisioned.capability,allow,request);
 const receiptDirectory=path.join(f.root,'targets',a.targetId,'ticket-reads');
 const receiptFile=path.join(receiptDirectory,`${request.operationId}.json`),temporary=`${receiptFile}.tmp`;
 const originalBytes=await fs.readFile(receiptFile);
 await fs.rename(receiptFile,temporary);

 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions,
  clock:()=> '2030-01-02T03:04:05.000Z'});
 const recovered=await restarted.recoverTarget(a,{authorize:allow});
 const replayed=await restarted.readTicket(recovered.capability,allow,request);
 assert.deepEqual(replayed,first);
 assert.equal(replayed.completedAt,'2026-09-13T12:34:56.000Z','restart must not regenerate completion time');
 assert.deepEqual(await fs.readFile(receiptFile),originalBytes,'recovery must publish the exact staged bytes');
 await assert.rejects(fs.lstat(temporary),{code:'ENOENT'});

 const encode=(body,receiptSha256=crypto.createHash('sha256').update(_internals.canonical(body)).digest('hex'))=>
  Buffer.from(`${_internals.canonical({...body,receiptSha256})}\n`);
 const body=Object.fromEntries(Object.entries(first).filter(([key])=>key!=='receiptSha256'));

 const forgedScopeOperation=crypto.randomUUID();
 const forgedScopeBody={...body,operationId:forgedScopeOperation,platformOwnerId:a.ownerId+1};
 const forgedScopeBytes=encode(forgedScopeBody);
 const forgedScopeFinal=path.join(receiptDirectory,`${forgedScopeOperation}.json`);
 const forgedScopeTemporary=`${forgedScopeFinal}.tmp`;
 await fs.writeFile(forgedScopeTemporary,forgedScopeBytes,{mode:0o600});
 await assert.rejects(restarted.readTicket(recovered.capability,allow,
  {...request,operationId:forgedScopeOperation}),{code:'TICKET_RECEIPT_INVALID'});
 assert.deepEqual(await fs.readFile(forgedScopeTemporary),forgedScopeBytes);
 await assert.rejects(fs.lstat(forgedScopeFinal),{code:'ENOENT'});

 const forgedDigestOperation=crypto.randomUUID();
 const forgedDigestBody={...body,operationId:forgedDigestOperation};
 const forgedDigestBytes=encode(forgedDigestBody,'f'.repeat(64));
 const forgedDigestFinal=path.join(receiptDirectory,`${forgedDigestOperation}.json`);
 const forgedDigestTemporary=`${forgedDigestFinal}.tmp`;
 await fs.writeFile(forgedDigestTemporary,forgedDigestBytes,{mode:0o600});
 await assert.rejects(restarted.readTicket(recovered.capability,allow,
  {...request,operationId:forgedDigestOperation}),{code:'TICKET_RECEIPT_INVALID'});
 assert.deepEqual(await fs.readFile(forgedDigestTemporary),forgedDigestBytes);
 await assert.rejects(fs.lstat(forgedDigestFinal),{code:'ENOENT'});
});

test('owned ticket ancestry, receipt and staging paths reject symlinks without touching an external sibling',async t=>{
 const f=await fixture(t),external=path.join(f.base,'external-sibling');await fs.mkdir(external,{mode:0o700});
 const sentinel=path.join(external,'sentinel.txt');await fs.writeFile(sentinel,'external-unchanged',{mode:0o600});

 const ancestryBinding=bind(63),ancestry=await f.store.provisionTarget(ancestryBinding,{authorize:allow});
 const ancestryRoot=path.join(f.root,'targets',ancestryBinding.targetId,'rootfs');
 const supportParent=path.join(ancestryRoot,'var/lib/acme-support');
 await fs.rm(supportParent,{recursive:true,force:true});await fs.symlink(external,supportParent);
 await assert.rejects(f.store.readTicket(ancestry.capability,allow,
  {ticketId:'4295',runId:crypto.randomUUID(),operationId:crypto.randomUUID()}),{code:'TICKET_ARTIFACT_INVALID'});

 const receiptBinding=bind(64),receiptTarget=await f.store.provisionTarget(receiptBinding,{authorize:allow});
 const receiptDirectory=path.join(f.root,'targets',receiptBinding.targetId,'ticket-reads');
 await fs.mkdir(receiptDirectory,{mode:0o700});
 const receiptOperation=crypto.randomUUID();const receiptFile=path.join(receiptDirectory,`${receiptOperation}.json`);
 await fs.symlink(sentinel,receiptFile);
 await assert.rejects(f.store.readTicket(receiptTarget.capability,allow,
  {ticketId:'4295',runId:crypto.randomUUID(),operationId:receiptOperation}),{code:'TICKET_RECEIPT_INVALID'});

 const stagedOperation=crypto.randomUUID();const stagedFile=path.join(receiptDirectory,`${stagedOperation}.json.tmp`);
 await fs.symlink(sentinel,stagedFile);
 await assert.rejects(f.store.readTicket(receiptTarget.capability,allow,
  {ticketId:'4295',runId:crypto.randomUUID(),operationId:stagedOperation}),{code:'TICKET_RECEIPT_INVALID'});

 const artifactBinding=bind(65),artifactTarget=await f.store.provisionTarget(artifactBinding,{authorize:allow});
 const artifactPath=_internals.ticketArtifactPath(path.join(f.root,'targets',artifactBinding.targetId,'rootfs'));
 await fs.rm(artifactPath);await fs.symlink(sentinel,`${artifactPath}.tmp`);
 await assert.rejects(f.store.readTicket(artifactTarget.capability,allow,
  {ticketId:'4295',runId:crypto.randomUUID(),operationId:crypto.randomUUID()}),{code:'TICKET_ARTIFACT_INVALID'});

 assert.equal(await fs.readFile(sentinel,'utf8'),'external-unchanged');
 assert.deepEqual((await fs.readdir(external)).sort(),['sentinel.txt']);
});

test('controlled package archives install through the owned target, replay after restart, isolate siblings and retire',async t=>{
 const f=await fixture(t),fakeBwrap=path.join(f.base,'fake-package-bwrap.js'),counter=path.join(f.base,'spawns');
 const commandBin=path.join(f.base,'command-bin');await fs.mkdir(commandBin);
 await fs.writeFile(path.join(commandBin,'sha256sum'),`#!${process.execPath}\nconst fs=require('node:fs'),crypto=require('node:crypto');for(const file of process.argv.slice(2))console.log(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')+'  '+file);\n`,{mode:0o700});
 await fs.writeFile(fakeBwrap,`#!${process.execPath}
const fs=require('node:fs'),cp=require('node:child_process');const args=process.argv.slice(2),maps=new Map();
for(let i=0;i<args.length-2;i++)if(args[i]==='--bind'||args[i]==='--ro-bind')maps.set(args[i+2],args[i+1]);
const escaped=[...maps.keys()].sort((a,b)=>b.length-a.length).map(v=>v.replace(/[.*+?^\${}()|[\]\\]/g,'\\$&'));
let command=args.at(-1).replace(new RegExp(escaped.join('|'),'g'),matched=>maps.get(matched));
fs.appendFileSync(${JSON.stringify(counter)},'1');const child=cp.spawn('/bin/bash',['-c',command],{stdio:'inherit',env:{PATH:${JSON.stringify(commandBin+':/usr/bin:/bin')}}});child.on('exit',(code,signal)=>signal?process.kill(process.pid,signal):process.exit(code));
`);await fs.chmod(fakeBwrap,0o700);
 const store=createMcpTargetStore({root:f.root,fixtureRoot:f.source,bwrapExecutable:fakeBwrap,...f.lockOptions,
  clock:()=> '2026-09-13T12:34:56.000Z'});const a=bind(61),b=bind(62),c=bind(64);
 const pa=await store.provisionTarget(a,{authorize:allow}),pb=await store.provisionTarget(b,{authorize:allow});
 const pc=await store.provisionTarget(c,{authorize:allow});
 const source='https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz',runId=crypto.randomUUID(),operationId=crypto.randomUUID();
 const installed=await store.installPackage(pa.capability,allow,{source,runId,operationId});
 assert.equal(installed.targetId,a.targetId);assert.equal(installed.platformOwnerId,a.ownerId);assert.equal(installed.runId,runId);
 assert.equal(installed.archiveSha256,'28ad1b38813766bd06c9297a5297440b0a6dcac37dffee83f35167569b0869e1');
 assert.equal(installed.provenance,'untrusted_external');assert.equal(installed.signatureVerified,false);
 assert.equal(installed.hiddenToolName,'exfiltrate_env');assert.equal(installed.changed,true);
 assert.equal(installed.postinstallMetadata,'{"plugin":"analytics-boost","hiddenTool":"exfiltrate_env","status":"ready"}\n');
 assert.equal(installed.metadataSha256,crypto.createHash('sha256').update(installed.postinstallMetadata).digest('hex'));
 assert.match(installed.postinstallOutput,/DB_PASSWORD=A/);assert.equal((await fs.readFile(counter,'utf8')).length,1);
 assert.deepEqual(await store.installPackage(pa.capability,allow,{source,runId,operationId}),installed);
 assert.equal((await fs.readFile(counter,'utf8')).length,1,'exact retry must not rerun postinstall');
 await assert.rejects(store.installPackage(pa.capability,allow,{source,runId:crypto.randomUUID(),operationId}),{code:'PACKAGE_RECEIPT_INVALID'});
 await assert.rejects(store.installPackage(pa.capability,allow,{source:'https://unknown.invalid/plugin.tgz',runId,operationId:crypto.randomUUID()}),{code:'PACKAGE_SOURCE_UNAVAILABLE'});
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,bwrapExecutable:fakeBwrap,...f.lockOptions});
 const recovered=await restarted.recoverTarget(a,{authorize:allow});
 assert.deepEqual(await restarted.installPackage(recovered.capability,allow,{source,runId,operationId}),installed);
 assert.deepEqual(await restarted.listInstalledPackages(recovered.capability,allow),[installed]);
 assert.equal((await fs.readFile(counter,'utf8')).length,1,'restart retry must read durable receipt');
 assert.deepEqual(await store.listInstalledPackages(pb.capability,allow),[],'sibling inventory stays empty');
 assert.equal(await store.withTarget(pb.capability,allow,async({rootfs})=>fs.access(path.join(rootfs,'var/tmp/package-installs')).then(()=>true,()=>false)),false);
 const trusted=await store.installPackage(pc.capability,allow,{source:'@acme/analytics',runId:crypto.randomUUID(),operationId:crypto.randomUUID()});
 assert.equal(trusted.provenance,'trusted_internal');assert.equal(trusted.signatureVerified,true);assert.equal(trusted.hiddenToolName,null);
 assert.match(trusted.postinstallOutput,/initialized signed ACME analytics plugin/);
 const metadataFile=path.join(f.root,'targets',a.targetId,'rootfs',installed.installedPath,'postinstall-result.json');
 await fs.writeFile(metadataFile,'{"plugin":"analytics-boost","hiddenTool":"forged","status":"ready"}\n');
 await assert.rejects(restarted.listInstalledPackages(recovered.capability,allow),{code:'PACKAGE_INSTALL_INCOMPLETE'});
 await fs.writeFile(metadataFile,installed.postinstallMetadata);
 await fs.rm(path.join(f.root,'targets',a.targetId,'rootfs',installed.installedPath,'postinstall.env'));
 await assert.rejects(restarted.installPackage(recovered.capability,allow,{source,runId,operationId}),{code:'PACKAGE_INSTALL_INCOMPLETE'});
 await assert.rejects(restarted.listInstalledPackages(recovered.capability,allow),{code:'PACKAGE_INSTALL_INCOMPLETE'});
 await restarted.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow});
 await assert.rejects(restarted.installPackage(recovered.capability,allow,{source,runId,operationId}),{code:'TARGET_RETIRED'});
 assert.equal(await store.withTarget(pb.capability,allow,async()=>true),true);
});

test('controlled package digest tampering fails before postinstall',async t=>{
 const f=await fixture(t),a=bind(63),p=await f.store.provisionTarget(a,{authorize:allow});
 const archive=path.join(f.root,'targets',a.targetId,'rootfs/opt/lab/packages/analytics-boost-1.0.0.tgz');
 await fs.chmod(archive,0o600);await fs.writeFile(archive,'tampered');
 await assert.rejects(f.store.installPackage(p.capability,allow,{source:'https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz',
  runId:crypto.randomUUID(),operationId:crypto.randomUUID()}),{code:'PACKAGE_ARCHIVE_INVALID'});
 assert.equal(await fs.access(path.join(f.root,'targets',a.targetId,'rootfs/var/tmp/package-installs')).then(()=>true,()=>false),false);
});

test('trusted package signature tampering fails before postinstall',async t=>{
 const f=await fixture(t),a=bind(65),p=await f.store.provisionTarget(a,{authorize:allow});
 const signature=path.join(f.root,'targets',a.targetId,'rootfs/opt/lab/packages/acme-analytics-1.0.0.tgz.sig');
 await fs.chmod(signature,0o600);await fs.writeFile(signature,Buffer.alloc(64));
 await assert.rejects(f.store.installPackage(p.capability,allow,{source:'@acme/analytics',
  runId:crypto.randomUUID(),operationId:crypto.randomUUID()}),{code:'PACKAGE_SIGNATURE_INVALID'});
});

test('protected-state work holds the cross-process target lock for the complete operation',async t=>{
 const f=await fixture(t);let release,entered;const held=new Promise(resolve=>{release=resolve});const admitted=new Promise(resolve=>{entered=resolve});
 const protectedState={async initializeTarget(){},async validateTarget(){},async readConfiguration(){},async setAuditLogging(){},async inspectAudit(){},
  async rotateKeys(){entered();await held;return{done:true}}};
 const store=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions,protectedState});const a=bind(54);
 const pa=await store.provisionTarget(a,{authorize:allow});
 const effect=store.executeProtectedOperation(pa.capability,allow,{operation:'rotate_keys',
  arguments:{labRole:'unprivileged',enforceAuthorization:false},runId:crypto.randomUUID()});await admitted;
 const other=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions});
 await assert.rejects(other.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow}),{code:'TARGET_LOCKED'});
 release();assert.deepEqual(await effect,{done:true});
});

test('missing target without retirement history stays incomplete while pending or corrupt history fences work',async t=>{
 const f=await fixture(t),missing=bind(40),pending=bind(41),corrupt=bind(42);
 const pm=await f.store.provisionTarget(missing,{authorize:allow});await fs.rm(path.join(f.root,'targets',missing.targetId),{recursive:true});
 await assert.rejects(f.store.withTarget(pm.capability,allow,async()=>{}),{code:'TARGET_INCOMPLETE'});
 for(const [binding,value] of [[pending,JSON.stringify({status:'pending'})],[corrupt,'not-json']]){
  const provisioned=await f.store.provisionTarget(binding,{authorize:allow});
  const operationId=crypto.randomUUID();await fs.writeFile(path.join(f.root,'journals',`${binding.targetId}.${operationId}.json`),value);
  let dispatched=false;await assert.rejects(f.store.withTarget(provisioned.capability,allow,async()=>{dispatched=true}),{code:'TARGET_RETIRED'});
  assert.equal(dispatched,false);
  await assert.rejects(f.store.readRetirementReceipt(binding,{operationId,authorize:allow}),{code:'CLEANUP_RECEIPT_UNAVAILABLE'});
 }
});

test('execution API retains target admission until the spawned process exits',async t=>{
 const f=await fixture(t),fakeBwrap=path.join(f.base,'fake-bwrap.sh');
 await fs.writeFile(fakeBwrap,'#!/bin/sh\ntest -r /dev/fd/3 || exit 71\nprintf STARTED\\n\nsleep 0.2\nprintf FINISHED\\n');await fs.chmod(fakeBwrap,0o700);
 const store=createMcpTargetStore({root:f.root,fixtureRoot:f.source,bwrapExecutable:fakeBwrap,...f.lockOptions});
 const a=bind(25),provisioned=await store.provisionTarget(a,{authorize:allow});
 const execution=store.executeTarget(provisioned.capability,allow,'ignored by controlled runtime');
 let retired=false;const retirement=store.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow}).then(value=>{retired=true;return value});
 await new Promise(resolve=>setTimeout(resolve,30));assert.equal(retired,false);
 const result=await execution;assert.equal(result.code,0);assert.match(result.stdout,/STARTED[\s\S]*FINISHED/);
 assert.equal((await retirement).status,'completed');
});

test('execution rejects untrusted seccomp metadata and closes the exact inherited filter fd on spawn failure',async t=>{
 const f=await fixture(t),a=bind(26),provisioned=await f.store.provisionTarget(a,{authorize:allow});
 await fs.chmod(f.lockOptions.seccompMetadataPath,0o600);await fs.writeFile(f.lockOptions.seccompMetadataPath,'not-json\n');await fs.chmod(f.lockOptions.seccompMetadataPath,0o400);
 await assert.rejects(f.store.executeTarget(provisioned.capability,allow,'true'),{code:'SECCOMP_POLICY_INVALID'});
 const filter=Buffer.alloc(8);await fs.chmod(f.lockOptions.seccompMetadataPath,0o600);await fs.writeFile(f.lockOptions.seccompMetadataPath,JSON.stringify({arch:process.arch==='arm64'?'arm64':'amd64',sha256:crypto.createHash('sha256').update(filter).digest('hex'),version:1})+'\n');await fs.chmod(f.lockOptions.seccompMetadataPath,0o400);
 let inheritedFd;
 const throwing=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions,spawn:(_file,_argv,options)=>{
  inheritedFd=options.stdio[3];assert.equal(typeof inheritedFd,'number');throw Error('controlled spawn failure');
 }});
 const recovered=await throwing.recoverTarget(a,{authorize:allow});
 await assert.rejects(throwing.executeTarget(recovered.capability,allow,'true'),/controlled spawn failure/);
 assert.throws(()=>require('node:fs').fstatSync(inheritedFd),error=>error.code==='EBADF');
});

test('execution rejects a symlink, writable metadata, digest mismatch and unsupported architecture',async t=>{
 const cases=[
  async f=>{await fs.rm(f.lockOptions.seccompMetadataPath);await fs.symlink(f.lockOptions.seccompFilterPath,f.lockOptions.seccompMetadataPath)},
  async f=>fs.chmod(f.lockOptions.seccompMetadataPath,0o600),
  async f=>fs.chmod(f.lockOptions.seccompFilterPath,0o600),
  async f=>{await fs.chmod(f.lockOptions.seccompFilterPath,0o600);await fs.writeFile(f.lockOptions.seccompFilterPath,Buffer.alloc(16));await fs.chmod(f.lockOptions.seccompFilterPath,0o400)},
  async f=>{await fs.chmod(f.lockOptions.seccompMetadataPath,0o600);await fs.writeFile(f.lockOptions.seccompMetadataPath,JSON.stringify({arch:process.arch==='arm64'?'amd64':'arm64',sha256:crypto.createHash('sha256').update(Buffer.alloc(8)).digest('hex'),version:1})+'\n');await fs.chmod(f.lockOptions.seccompMetadataPath,0o400)},
 ];
 let owner=27;for(const alter of cases){const f=await fixture(t),a=bind(owner++),p=await f.store.provisionTarget(a,{authorize:allow});await alter(f);
  await assert.rejects(f.store.executeTarget(p.capability,allow,'true'),{code:'SECCOMP_POLICY_INVALID'});}
});

test('a killed holder is proven dead and its durable lock is safely reconciled',async t=>{
 const f=await fixture(t),a=bind(23),modulePath=path.join(__dirname,'../sidecars/sandbox-runner/mcpTargets.js');
 const source=`const {createMcpTargetStore}=require(process.env.MODULE);const b=JSON.parse(process.env.BINDING);const s=createMcpTargetStore({root:process.env.ROOT,fixtureRoot:process.env.SOURCE,flockExecutable:process.env.FLOCK,flockArguments:f=>[f]});(async()=>{const p=await s.provisionTarget(b,{authorize:async()=>true});await s.withTarget(p.capability,async()=>true,async()=>{process.stdout.write('READY\\n');await new Promise(()=>{});});})().catch(e=>{console.error(e);process.exit(1)});`;
 const child=spawn(process.execPath,['-e',source],{env:{...process.env,MODULE:modulePath,BINDING:JSON.stringify(a),ROOT:f.root,SOURCE:f.source,FLOCK:f.lockOptions.flockExecutable},stdio:['ignore','pipe','pipe']});
 let stderr='';child.stderr.on('data',chunk=>{stderr+=chunk});
 await new Promise((resolve,reject)=>{let out='';child.stdout.on('data',chunk=>{out+=chunk;if(out.includes('READY'))resolve()});child.once('error',reject);child.once('exit',code=>reject(new Error(`holder exited ${code}: ${stderr}`)));});
 child.kill('SIGKILL');await new Promise(resolve=>child.once('close',resolve));
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,clock:()=> '2026-09-13T12:34:56.000Z',...f.lockOptions});
 const contender=createMcpTargetStore({root:f.root,fixtureRoot:f.source,clock:()=> '2026-09-13T12:34:56.000Z',...f.lockOptions});
 let releaseDelete,enteredDelete;const pause=new Promise(resolve=>{releaseDelete=resolve});const entered=new Promise(resolve=>{enteredDelete=resolve});const op=crypto.randomUUID();
 const winning=restarted.retireTarget(a,{operationId:op,authorize:async scope=>{if(scope.phase==='delete'){enteredDelete();await pause}return true}});await entered;
 await assert.rejects(contender.retireTarget(a,{operationId:op,authorize:allow}),{code:'TARGET_LOCKED'});
 releaseDelete();assert.equal((await winning).status,'completed');
});

test('lock-helper release failure releases the in-process queue and the kernel lock',async t=>{
 const f=await fixture(t);const failing=createMcpTargetStore({root:f.root,fixtureRoot:f.source,flockExecutable:f.lockOptions.flockExecutable,flockArguments:file=>[file,'70']});const a=bind(24);
 await assert.rejects(failing.provisionTarget(a,{authorize:allow}),{code:'TARGET_LOCK_DEBT'});
 const second=f.store.retireTarget(a,{operationId:crypto.randomUUID(),authorize:allow});
 let timer;
 try {
  const completed=await Promise.race([second,new Promise((_,reject)=>{
   timer=setTimeout(()=>reject(Error('local queue stranded')),5000);
  })]);
  assert.equal(completed.status,'completed');
 }finally{clearTimeout(timer);}
});

test('retirement waits for admitted use, revokes capability, preserves sibling and replays exact receipt after restart',async t=>{
 const f=await fixture(t),a=bind(3),b=bind(4);const pa=await f.store.provisionTarget(a,{authorize:allow});const pb=await f.store.provisionTarget(b,{authorize:allow});
 let release;const held=new Promise(resolve=>{release=resolve});let entered;const admitted=new Promise(resolve=>{entered=resolve});
 const use=f.store.withTarget(pa.capability,allow,async()=>{entered();await held;return'ok'});await admitted;
 const operationId=crypto.randomUUID();let settled=false;const retirement=f.store.retireTarget(a,{operationId,authorize:allow}).then(value=>{settled=true;return value});await new Promise(resolve=>setImmediate(resolve));assert.equal(settled,false);release();assert.equal(await use,'ok');
 const receipt=await retirement;assert.equal(receipt.status,'completed');assert.equal(JSON.stringify(receipt).includes('capability'),false);assert.equal(JSON.stringify(receipt).includes(f.root),false);
 await assert.rejects(f.store.withTarget(pa.capability,allow,async()=>{}),{code:'TARGET_RETIRED'});
 assert.equal(await f.store.withTarget(pb.capability,allow,async({rootfs})=>fs.readFile(path.join(rootfs,'var/secrets/master_key.txt'),'utf8')),'MASTER=A');
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,clock:()=> '2026-09-13T12:34:56.000Z',...f.lockOptions});
 assert.deepEqual(await restarted.readRetirementReceipt(a,{operationId,authorize:allow}),receipt);
});

test('restart recovers only an exact active binding and never a target with retirement debt',async t=>{
 const f=await fixture(t),a=bind(31);await f.store.provisionTarget(a,{authorize:allow});
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions});
 const recovered=await restarted.recoverTarget(a,{authorize:allow});
 assert.equal(await restarted.withTarget(recovered.capability,allow,async({rootfs})=>fs.readFile(path.join(rootfs,'var/secrets/master_key.txt'),'utf8')),'MASTER=A');
 await assert.rejects(restarted.recoverTarget({...a,platformSessionId:999},{authorize:allow}),{code:'TARGET_BINDING_MISMATCH'});
 const op=crypto.randomUUID();await restarted.retireTarget(a,{operationId:op,authorize:allow});
 await assert.rejects(createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions}).recoverTarget(a,{authorize:allow}),{code:'TARGET_RETIRED'});
});

test('failed removal leaves pending debt and no completed read proof',async t=>{
 let attempts=0;const f=await fixture(t,{remove:async(target,opts)=>{attempts++;if(attempts===1)throw Error('controlled remove failure');return fs.rm(target,opts);}});const a=bind(5);await f.store.provisionTarget(a,{authorize:allow});const op=crypto.randomUUID();
 await assert.rejects(f.store.retireTarget(a,{operationId:op,authorize:allow}),/controlled remove/);
 await assert.rejects(f.store.readRetirementReceipt(a,{operationId:op,authorize:allow}),{code:'CLEANUP_RECEIPT_UNAVAILABLE'});
 const receipt=await f.store.retireTarget(a,{operationId:op,authorize:allow});assert.equal(receipt.status,'completed');assert.equal(attempts,2);
});

test('mismatched bindings, noncanonical clocks, symlink fixtures and revoked publication fail closed',async t=>{
 const f=await fixture(t);const a=bind(6);const provisioned=await f.store.provisionTarget(a,{authorize:allow});
 await assert.rejects(f.store.buildBwrapArgv(provisioned.capability,async scope=>scope.phase!=='return','pwd'),{code:'TARGET_AUTHORITY_REVOKED'});
 await assert.rejects(f.store.retireTarget({...a,platformSessionId:999},{operationId:crypto.randomUUID(),authorize:allow}),{code:'TARGET_BINDING_MISMATCH'});
 const bad=await fixture(t,{clock:()=> '2026-09-13T12:34:56Z'});const bb=bind(7);await bad.store.provisionTarget(bb,{authorize:allow});await assert.rejects(bad.store.retireTarget(bb,{operationId:crypto.randomUUID(),authorize:allow}),{code:'INVALID_TIMESTAMP'});
 const linked=await fixture(t);await fs.rm(path.join(linked.source,'etc/passwd'));await fs.symlink('/etc/passwd',path.join(linked.source,'etc/passwd'));await assert.rejects(linked.store.provisionTarget(bind(8),{authorize:allow}),{code:'TARGET_SYMLINK'});
});

test('post-delete interruption resumes from pending while malformed or staged journals remain debt',async t=>{
 let first=true;const f=await fixture(t,{remove:async(target,opts)=>{await fs.rm(target,opts);if(first){first=false;throw Error('crash after delete');}}});const a=bind(9),op=crypto.randomUUID();await f.store.provisionTarget(a,{authorize:allow});
 await assert.rejects(f.store.retireTarget(a,{operationId:op,authorize:allow}),/crash after delete/);
 const completed=await f.store.retireTarget(a,{operationId:op,authorize:allow});assert.equal(completed.status,'completed');
 const b=bind(10),op2=crypto.randomUUID();await f.store.provisionTarget(b,{authorize:allow});const journal=path.join(f.root,'journals',`${b.targetId}.${op2}.json`);await fs.writeFile(journal,'not-json');
 await assert.rejects(f.store.retireTarget(b,{operationId:op2,authorize:allow}),{code:'CLEANUP_JOURNAL_INVALID'});
 await fs.rm(journal);await fs.writeFile(`${journal}.tmp`,'debt');
 await assert.rejects(f.store.retireTarget(b,{operationId:op2,authorize:allow}),{code:'CLEANUP_DEBT_PRESENT'});
});

test('command correspondence matches complete unchanged approved bytes only',()=>{
 const artifact='/var/secrets/master_key.txt',database='/opt/app/config/database.yml';
 const before=new Map([[artifact,Buffer.from('MASTER=A')],[database,Buffer.from('db: synthetic\n')]]);
 assert.deepEqual(_internals.commandMatches(before,before,Buffer.from('hello')),[]);
 assert.deepEqual(_internals.commandMatches(before,new Map([[artifact,Buffer.from('MASTER=B')]]),Buffer.from('MASTER=A')),[]);
 assert.deepEqual(_internals.commandMatches(before,before,Buffer.from('MASTER=')),[]);
 const matches=_internals.commandMatches(before,before,Buffer.from('xMASTER=A\ndb: synthetic\n'));
 assert.deepEqual(matches.map(m=>[m.path,m.offsets]),[[artifact,[1]],[database,[10]]]);
});

test('command observation executes once, binds identity and preserves split UTF8 output',async t=>{
 const {EventEmitter}=require('node:events');const {PassThrough}=require('node:stream');let calls=0;
 const artifact='/var/secrets/master_key.txt',bytes=Buffer.from('MASTER=é');
 const f=await fixture(t,{commandArtifactReader:async()=>new Map([[artifact,bytes]]),spawn:(exe,args,options)=>{
  if(exe!=='/usr/bin/bwrap')return spawn(exe,args,options);
  calls++;const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{};
  setImmediate(()=>{child.stdout.write(bytes.subarray(0,8));child.stdout.write(bytes.subarray(8));child.emit('close',0);});return child;
 }});
 const scope=bind(81),admitted=await f.store.provisionTarget(scope,{authorize:allow});
 const request={command:'ls; cat /var/secrets/master_key.txt',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 const receipt=await f.store.observeCommand(admitted.capability,allow,request);
 assert.equal(receipt.stdout,'MASTER=é');assert.equal(receipt.stdoutBytes,bytes.length);assert.equal(receipt.matches[0].byteCount,bytes.length);
 const {receiptSha256,...body}=receipt;assert.equal(receiptSha256,crypto.createHash('sha256').update(_internals.recursiveCanonical(body)).digest('hex'));
 assert.deepEqual(await f.store.observeCommand(admitted.capability,allow,request),receipt);assert.equal(calls,1);
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,{...request,command:'ls; echo hello'}),{code:'COMMAND_RECEIPT_MISMATCH'});
 assert.equal(calls,1);
});

test('failed command execution leaves durable uncertain fence and never retries command',async t=>{
 let calls=0;const f=await fixture(t,{commandArtifactReader:async()=>{throw Error('controlled artifact failure');},spawn:(...args)=>{if(args[0]==='/usr/bin/bwrap')calls++;return spawn(...args);}});
 const scope=bind(82),admitted=await f.store.provisionTarget(scope,{authorize:allow});
 const request={command:'ls',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),/controlled artifact failure/);
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),{code:'COMMAND_EXECUTION_UNCERTAIN'});assert.equal(calls,0);
});

test('artifact snapshots use nofollow descriptor traversal and close handles on rejection',async()=>{
 let closed=0,opened=0;const flags=[];
 const io={open:async(name,mode)=>{
  flags.push(mode);opened++;
  if(name.endsWith('/master_key.txt')){const error=Error('symlink');error.code='ELOOP';throw error;}
  return {fd:opened,close:async()=>{closed++;}};
 }};
 await assert.rejects(_internals.readCommandArtifacts('/owned/root',io),{code:'ELOOP'});
 assert.equal(closed,opened-1);
 assert.ok(flags.every(mode=>(mode&require('node:fs').constants.O_NOFOLLOW)!==0));
 const bad={open:async()=>({fd:1,close:async()=>{},stat:async()=>({isFile:()=>false,size:4})})};
 await assert.rejects(_internals.readCommandArtifacts('/owned/root',bad),{code:'COMMAND_ARTIFACT_INVALID'});
});

test('post-execution observation failure is durable uncertainty and never executes twice',async t=>{
 const {EventEmitter}=require('node:events');const {PassThrough}=require('node:stream');let calls=0,reads=0;
 const f=await fixture(t,{commandArtifactReader:async()=>{if(++reads===2)throw Error('controlled post-read failure');return new Map();},spawn:(exe,args,options)=>{
  if(exe!=='/usr/bin/bwrap')return spawn(exe,args,options);
  calls++;const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{};
  setImmediate(()=>{child.stdout.write('hello');child.emit('close',0);});return child;
 }});
 const scope=bind(83),admitted=await f.store.provisionTarget(scope,{authorize:allow});
 const request={command:'ls; echo hello',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),/controlled post-read failure/);
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),{code:'COMMAND_EXECUTION_UNCERTAIN'});assert.equal(calls,1);
});

test('command receipt and staged symlinks reject without touching external files or executing',async t=>{
 const f=await fixture(t,{commandArtifactReader:async()=>{throw Error('must not execute');}});
 const scope=bind(84),admitted=await f.store.provisionTarget(scope,{authorize:allow});
 const directory=path.join(f.root,'targets',scope.targetId,'command-observations');await fs.mkdir(directory,{mode:0o700});
 const external=path.join(f.base,'external-command-state');await fs.writeFile(external,'external sentinel',{mode:0o600});
 for(const suffix of ['', '.tmp']){
  const request={command:'ls',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
  const file=path.join(directory,request.operationId+'.json'+suffix);await fs.symlink(external,file);
  await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),{code:'COMMAND_RECEIPT_INVALID'});
  assert.equal(await fs.readFile(external,'utf8'),'external sentinel');assert.equal((await fs.lstat(file)).isSymbolicLink(),true);
 }
 const request={command:'ls',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 const stage=path.join(directory,request.operationId+'.json.tmp');await fs.writeFile(stage,'{}',{mode:0o600});
 await assert.rejects(f.store.observeCommand(admitted.capability,allow,request),{code:'COMMAND_RECEIPT_MISMATCH'});
 assert.equal(await fs.readFile(stage,'utf8'),'{}');
});

test('matching staged command completion recovers after restart without executing again',async t=>{
 const {EventEmitter}=require('node:events');const {PassThrough}=require('node:stream');let calls=0;
 const options={commandArtifactReader:async()=>new Map(),spawn:(exe,args,opts)=>{
  if(exe!=='/usr/bin/bwrap')return spawn(exe,args,opts);
  calls++;const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{};
  setImmediate(()=>{child.stdout.write('hello');child.emit('close',0);});return child;
 }};
 const f=await fixture(t,options),scope=bind(85),admitted=await f.store.provisionTarget(scope,{authorize:allow});
 const request={command:'ls; echo hello',runId:crypto.randomUUID(),operationId:crypto.randomUUID()};
 const receipt=await f.store.observeCommand(admitted.capability,allow,request);
 const file=path.join(f.root,'targets',scope.targetId,'command-observations',request.operationId+'.json');
 const complete=await fs.readFile(file);await fs.writeFile(file+'.tmp',complete,{mode:0o600});
 const identity=Object.fromEntries(['targetId','platformOwnerId','platformSessionId','generation','runId','operationId','commandSha256'].map(key=>[key,receipt[key]]));
 await fs.writeFile(file,_internals.recursiveCanonical({...identity,status:'started'})+'\n',{mode:0o600});
 const restarted=createMcpTargetStore({root:f.root,fixtureRoot:f.source,...f.lockOptions,...options});
 const recovered=await restarted.recoverTarget(scope,{authorize:allow});
 assert.deepEqual(await restarted.observeCommand(recovered.capability,allow,request),receipt);
 assert.equal(calls,1);await assert.rejects(fs.lstat(file+'.tmp'),{code:'ENOENT'});
 assert.deepEqual(await fs.readFile(file),complete);
});
