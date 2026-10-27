'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const policy=require('./postgres/ownedPricingEgressPolicy'),bounded=require('./postgres/ownedPricingBoundedDerivation');
const root=path.resolve(__dirname,'..'),runId='a'.repeat(32);
function packet(){const rows={};for(const mode of ['adapter','connector'])rows[mode]={kind:'transport-audit',variant:'metadata-idle-barrier-v4',runId,mode,sequence:2,trigger:'checkpoint',counts:{dnsSubprocesses:0,externalConnectAttempts:0,unixConnectAttempts:0,peerChecks:0,peerDenied:0},activeWorkers:0,deniedAuthorities:{hosts:{},unclassified:0,overflow:0},admission:{workerLimitRejected:7,connectionLimitRejected:0,saturated:false},pricingBudget:{version:1,policy:policy.VERSION,sourceSha256:policy.RELAY_SHA,limit:68,connections:14}};return{version:1,runId,variant:'metadata-idle-barrier-v4',rows};}
function artifacts(n){return Array.from({length:n},(_,i)=>({kind:'deb',algorithm:'sha256',digest:i.toString(16).padStart(64,'0'),bytes:123,urls:[`https://deb.debian.org/debian/pool/main/f/fixture/fixture${i}_1_arm64.deb`],stages:['build']}));}
function python(source){const r=spawnSync('python3',['-B','-c',source],{encoding:'utf8',timeout:5000,maxBuffer:65536});assert.equal(r.status,0,r.stderr||r.error?.message);return r.stdout;}
test('fixed Pricing policy has no caller-selectable limits; exact authenticated artifact boundary is36',()=>{
 assert.deepEqual(policy.LIMITS,{connections:68,overheadConnections:32,artifacts:36});assert(Object.isFrozen(policy.LIMITS));
 assert.equal(policy.validatePricingArtifactCensus(artifacts(36)).artifacts,36);
 for(const rows of [artifacts(37),[],[...artifacts(1),...artifacts(1)],artifacts(1).map(r=>({...r,kind:'npm'})),artifacts(1).map(r=>({...r,urls:[...r.urls,r.urls[0]+'x']})),artifacts(1).map(r=>({...r,stages:['foreign']}))])assert.throws(()=>policy.validatePricingArtifactCensus(rows));
});
test('actual admitted connection witness rejects excess, stale, malformed and nonquiescent overhead',()=>{
 const p=packet();p.rows.adapter.pricingBudget.connections=32;assert.equal(policy.validateOverheadCheckpoint(p,{runId}).connections.adapter,32);
 for(const change of [p=>p.runId='b'.repeat(32),p=>delete p.rows.connector,p=>p.rows.adapter.pricingBudget.connections=33,p=>delete p.rows.adapter.pricingBudget,p=>p.rows.adapter.pricingBudget.limit=192,p=>p.rows.adapter.pricingBudget.sourceSha256='f'.repeat(64),p=>p.rows.adapter.pricingBudget.policy='foreign',p=>p.rows.adapter.activeWorkers=1,p=>p.rows.adapter.mode='connector',p=>p.rows.adapter.trigger='terminal',p=>p.rows.adapter.sequence=0,p=>p.rows.adapter.counts.peerChecks=15,p=>p.rows.adapter.admission.connectionLimitRejected=1,p=>p.rows.adapter.extra=true]){const value=packet();change(value);assert.throws(()=>policy.validateOverheadCheckpoint(value,{runId}),{code:'PRICING_EGRESS_OVERHEAD'});}
 // Attempt counters can be lower than admission counts (malformed headers).
 const malformed=packet();malformed.rows.adapter.pricingBudget.connections=33;assert.equal(malformed.rows.adapter.counts.unixConnectAttempts,0);assert.throws(()=>policy.validateOverheadCheckpoint(malformed,{runId}));
});
test('actual emitted Python enforces68/69 without resetting byte accounts; shared default remains32/33',async()=>{
 const shared=fs.readFileSync(path.join(root,'tests/postgres/ownedMcpPrivateEgress.js'));
 const plan=await bounded.loadPricingBounded().pricingMetadataQualificationPlan(root,runId);
 const match=/^CHILDREN=json\.loads\((.*)\)$/m.exec(plan.phases.relayStart);assert(match);
 const children=JSON.parse(JSON.parse(match[1]));
 for(const [name,source]of [...Object.entries(children),['default',require('./postgres/ownedMcpPrivateEgress')._internals.program]]){
  const max=name==='default'?32:68,body=source.slice(source.indexOf('class Budget:'),source.indexOf('def header('));
  const stdout=python(`import threading,json\nclass Denied(Exception): pass\nHOST_LIMITS={'deb.debian.org':138412032}\nTOTAL=273678336\n${body}\nb=Budget()\nfor _ in range(${max}): b.admit()\ntry: b.admit(); raise AssertionError('extra admission')\nexcept Denied: pass\nb.charge('deb.debian.org',138412032)\ntry: b.charge('deb.debian.org',1); raise AssertionError('byte reset')\nexcept Denied: pass\nprint(json.dumps({'connections':b.connections,'observed':globals().get('PRICING_ADMITTED_CONNECTIONS'),'bytes':b.total}))`);
  assert.deepEqual(JSON.parse(stdout),{connections:max,observed:name==='default'?null:68,bytes:138412032});
  if(name!=='default'){
   for(const exact of ['TOTAL=273678336','threading.BoundedSemaphore(4)','validate_deadline(deadline)','reject','production.cloudfront.docker.com'])if(exact!=='reject')assert(source.includes(exact),exact);
   assert(!source.includes('registry.npmjs.org'));assert(source.includes("sourceSha256='"+policy.RELAY_SHA+"'"));
   assert.throws(()=>policy._internals.deriveChild(source),/ANCHOR/);
  }
 }
 assert.deepEqual(fs.readFileSync(path.join(root,'tests/postgres/ownedMcpPrivateEgress.js')),shared);
});
test('actual emitted checkpoint reports Budget admissions, not attempt counters',async()=>{
 const plan=await bounded.loadPricingBounded().pricingMetadataQualificationPlan(root,runId);
 const child=JSON.parse(JSON.parse(/^CHILDREN=json\.loads\((.*)\)$/m.exec(plan.phases.relayStart)[1])).adapter;
 const output=python(`import ast,json,sys,time,threading\nsource=${JSON.stringify(child)}\ntree=ast.parse(source)\nkeep=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in ('Denied','Budget','transport_snapshot')]\nexec(compile(ast.Module(body=keep,type_ignores=[]),'emitted-relay','exec'))\nHOST_LIMITS={'deb.debian.org':138412032};TOTAL=273678336\nTRANSPORT_SEQUENCE=0;TRANSPORT_RUN='${runId}';TRANSPORT_MODE='adapter'\nTRANSPORT_COUNTS=dict(dnsSubprocesses=0,externalConnectAttempts=0,unixConnectAttempts=0,peerChecks=0,peerDenied=0)\nMETADATA_ADMISSION=dict(workerLimitRejected=0,connectionLimitRejected=0,saturated=False)\nmetadata_denied_snapshot=lambda:dict(hosts={},unclassified=0,overflow=0)\nsys.argv=['controlled',str(time.monotonic()+300)]\nb=Budget()\nfor _ in range(32): b.admit()\ntransport_snapshot('checkpoint')`);
 const p=packet();p.rows.adapter=JSON.parse(output);assert.equal(policy.validateOverheadCheckpoint(p,{runId}).connections.adapter,32);
});
