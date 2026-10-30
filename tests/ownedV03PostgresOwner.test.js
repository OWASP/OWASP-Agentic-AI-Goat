'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03PostgresOwner'),'utf8');
const core=new Function('crypto','handles','path',source.slice(source.indexOf('const COMMAND_PYTHON='),source.indexOf('async function createPostgresOwner('))+';return {ownerFor,inspected,absent,transport};')(crypto,new WeakMap(),require('node:path'));
function fixture(){
 let now=1000;const owner={binding:()=>({runId:'a'.repeat(32),planSha256:'b'.repeat(64)}),wrapperWindow:()=>({deadlineMs:1801000}),
  nowMs:()=>now,isRevoked:()=>false};
 const writes=[],calls=[],id='c'.repeat(64),image='sha256:'+'d'.repeat(64);let present=false,wrong=false,late=false;
 const name='owasp-ai-goat-merchant-listing-image-optimize-v03-browser-'+crypto.createHash('sha256').update('a'.repeat(32)+':v03-postgres').digest('hex').slice(0,12);
 const row=()=>({Id:wrong?'f'.repeat(64):id,Name:'/'+name,Image:image,Config:{Labels:{'owasp-ai-goat.owner':'a'.repeat(32),
  'owasp-ai-goat.cohort':'secureshop-merchant-listing-image-optimize-v03-browser-current-main-v1'}},Mounts:[],
  HostConfig:{Tmpfs:{'/var/lib/postgresql':'rw,size=268435456'},Memory:536870912,NanoCpus:2000000000,PidsLimit:256},
  NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:'54321'}]}}});
 const commands={clean:()=>true,command:async(parts,timeout,end)=>{
  calls.push({parts,timeout,end});
  if(parts[0]==='info')return {code:0,signal:null,stdout:'daemon\n',stderr:''};
  if(parts[0]==='rm'){present=false;return {code:0,signal:null,stdout:id,stderr:''};}
  if(!present)return {code:1,signal:null,stdout:'',stderr:'Error: No such object: '+parts.at(-1)+'\n'};
  return {code:0,signal:null,stdout:JSON.stringify([row()]),stderr:''};
 }};
 const publish=async(name,value,end)=>{writes.push({name,value,end});if(late&&name==='pg-retirement-result.json')now=end;return {file:name,sha256:'e'.repeat(64)};};
 const post={pgDeadline:()=>1000000,publicationDeadline:()=>1000000,retireAfterMain:async()=>({workTerminalSucceeded:true,
  mainProof:{groupAbsent:true},producerProof:{cleanupVerified:true,diagnosticAbsent:true,listingsAbsent:true}})};
 const pg=core.ownerFor(owner,{image,daemonId:'daemon'},commands,publish,(candidate,actual)=>{assert.equal(candidate,post);assert.equal(actual,owner);});
 return {pg,post,commands,writes,calls,id,row,create:()=>{present=true;},wrong:()=>{wrong=true;},late:()=>{late=true;},setNow:n=>{now=n;}};
}
test('durable parent intent precedes create acknowledgement and actual captured binding precedes effects',async()=>{
 const f=fixture();assert.throws(()=>f.pg.requireBound());
 const intent=await f.pg.createIntent();assert.equal(f.writes.at(-1).name,'pg-create-intent.json');
 assert.equal(intent.intent.labels['owasp-ai-goat.owner'],'a'.repeat(32));assert.equal(f.pg.status().attempted,true);
 f.create();await f.pg.bind(f.id);assert.equal(f.pg.requireBound(),true);
 assert.equal(f.writes.at(-1).name,'pg-captured-binding.json');
 await assert.rejects(f.pg.createIntent(),{code:'V03_PG_INTENT_ONCE'});
});
test('exact six original cleanup commands follow private post-work authority and do not qualify',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();await f.pg.bind(f.id);f.calls.length=0;
 const receipt=await f.pg.retire(f.post);
 assert.deepEqual(f.calls.map(c=>c.parts[0]),['info','inspect','rm','inspect','inspect','inspect']);
 assert.deepEqual(f.calls.map(c=>c.timeout),[30000,30000,30000,30000,10000,10000]);
 assert.deepEqual(f.calls[2].parts,['rm','--force','--volumes',f.id]);
 assert.equal(receipt.absent,true);assert.equal(receipt.retrospective,false);assert.equal(receipt.qualificationComplete,false);
});
test('lost captured-ID acknowledgement retains attempted intent and labels retrospective binding honestly',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();const receipt=await f.pg.retire(f.post);
 assert.equal(receipt.retrospective,true);
 assert.equal(f.writes.find(x=>x.name==='pg-retirement-binding.json').value.originalCapturedId,null);
});
test('lost creation outcome with no observable ID stays unknown rather than becoming full absence',async()=>{
 const f=fixture();await f.pg.createIntent();
 await assert.rejects(f.pg.retire(f.post),e=>e.code==='V03_PG_CAPTURED_ID_UNPROVEN'&&e.cleanupDebt);
 assert.equal(f.pg.status().capturedId,null);assert.equal(f.calls.some(x=>x.parts[0]==='rm'),false);
});
test('replacement ID cannot be removed after actual captured binding',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();await f.pg.bind(f.id);f.wrong();f.calls.length=0;
 await assert.rejects(f.pg.retire(f.post),{code:'V03_PG_OWNERSHIP_LAYOUT'});
 assert.equal(f.calls.some(x=>x.parts[0]==='rm'),false);
});
test('insufficient full command/join reserve denies before any destructive command',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();await f.pg.bind(f.id);f.setNow(800000);f.calls.length=0;
 await assert.rejects(f.pg.retire(f.post),{code:'V03_PG_FINALIZATION_RESERVE'});
 assert.deepEqual(f.calls,[]);
});
test('late result publication cannot create successful cleanup authority',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();await f.pg.bind(f.id);f.late();
 await assert.rejects(f.pg.retire(f.post),e=>['V03_PG_PUBLICATION_LATE','V03_PG_DEADLINE'].includes(e.code)&&e.cleanupDebt);
 assert.equal(f.pg.status().state,'debt');assert.equal(f.writes.at(-1).value.qualificationComplete,false);
});
test('preexisting command debt denies further commands and deletion',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();f.commands.clean=()=>false;f.calls.length=0;
 await assert.rejects(f.pg.retire(f.post),{code:'V03_PG_COMMAND_DEBT'});assert.deepEqual(f.calls,[]);
});
test('public factory remains closed and JSON cannot mint PG ownership',async()=>{
 const api=require('./postgres/ownedV03PostgresOwner');await assert.rejects(api.createPostgresOwner(),{code:'V03_PG_OPTIONS'});
 const filename=require.resolve('./postgres/ownedV03PostgresOwner'),m={exports:{}};
 assert.equal(source.split('const LIVE_ENABLED=true,handles=').length,2);
 const closed=source.replace('const LIVE_ENABLED=true,handles=','const LIVE_ENABLED=false,handles=');
 new Function('require','module','exports','__dirname',closed)(require('node:module').createRequire(filename),m,m.exports,require('node:path').dirname(filename));
 await assert.rejects(m.exports.createPostgresOwner(),{code:'V03_PG_NOT_ADMITTED'});
 assert.throws(()=>api.assertPostgresOwner({},{}),{code:'V03_PG_OWNER_REQUIRED'});
});
test('final publication uses actual post-work and PG proofs but always requires independent FULL',async()=>{
 const f=fixture();await f.pg.createIntent();f.create();await f.pg.bind(f.id);
 const result=await f.pg.finalize(f.post);
 assert.equal(result.publicationVerified,true);assert.equal(result.qualificationComplete,false);
 const saved=f.writes.at(-1);assert.equal(saved.name,'parent-post-work-candidate.json');
 assert.equal(saved.value.publicationVerified,false);assert.equal(saved.value.independentFullRequired,true);
});
test('actual fixed transport retains each outcome and requires exact birth plus group closure',async()=>{
 const {EventEmitter}=require('node:events');let child,argv;const records=[];
 const config={root:'/repo',docker:'/repo/docker',host:'unix:///repo/docker.sock'};
 const observer={status:()=>({pending:0,debts:0}),observe:async req=>{
  if(req.op==='inspect'){
   child.stdin.end=()=>{child.stdout.emit('data',Buffer.from('daemon\n'));child.emit('close',0,null);};
   return {observed:{identity:{pid:123},argv}};
  }return {groupAbsent:true};
 }};
 const launch=(file,args)=>{argv=[file,...args];child=new EventEmitter();child.pid=123;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();return child;};
 const t=core.transport({nowMs:()=>0},config,observer,async(name,row)=>{records.push({name,row:{...row}});},launch);
 assert.equal((await t.command(['info','--format','{{.ID}}'],30000,50000)).stdout,'daemon\n');
 assert.equal(t.clean(),true);assert.equal(records.at(-1).row.groupAbsent,true);
});
test('transport unknown birth retains live-child debt and never signals it',async()=>{
 const {EventEmitter}=require('node:events');let observations=0;
 const observer={status:()=>({pending:0,debts:0}),observe:async()=>{observations++;throw Error('birth unavailable');}};
 const launch=()=>{const child=new EventEmitter();child.pid=123;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();return child;};
 const t=core.transport({nowMs:()=>0},{root:'/repo',docker:'/repo/docker',host:'unix:///repo/sock'},observer,async()=>{},launch);
 await assert.rejects(t.command(['info','--format','{{.ID}}'],30000,50000),e=>e.cleanupDebt);
 assert.equal(observations,1);assert.equal(t.clean(),false);assert.equal(t.records()[0].closed,false);
});
test('publication timeout retains pending write debt; late completion never restores cleanup authority',async()=>{
 const f=fixture();let resolveWrite;const write=new Promise(resolve=>{resolveWrite=resolve;});
 const owner={binding:()=>({runId:'a'.repeat(32),planSha256:'b'.repeat(64)}),wrapperWindow:()=>({deadlineMs:1800000}),
  nowMs:()=>0,isRevoked:()=>false};
 const pg=core.ownerFor(owner,{image:'sha256:'+'d'.repeat(64),daemonId:'daemon'},f.commands,()=>write,()=>{},
  async operation=>{void operation();await Promise.resolve();throw Object.assign(Error('timeout'),{code:'V03_PG_DEADLINE'});});
 await assert.rejects(pg.createIntent(),e=>e.cleanupDebt&&e.code==='V03_PG_DEADLINE');
 assert.equal(pg.status().pendingPublications,1);assert.equal(pg.status().publicationDebt,true);
 await assert.rejects(pg.retire(f.post),{code:'V03_PG_PUBLICATION_UNJOINED'});
 resolveWrite({file:'late'});await new Promise(resolve=>setImmediate(resolve));
 assert.equal(pg.status().pendingPublications,0);assert.equal(pg.status().publicationDebt,true);
 await assert.rejects(pg.finalize(f.post),{code:'V03_PG_PUBLICATION_UNJOINED'});
});
test('actual ten-second command charges positive async intent latency without renewing its window',async()=>{
 const {EventEmitter}=require('node:events');let now=0,child,argv;const publications=[];
 const owner={nowMs:()=>now},config={root:'/repo',docker:'/repo/docker',host:'unix:///repo/socket'};
 const observer={status:()=>({pending:0,debts:0}),observe:async request=>{
  if(request.op==='inspect'){now+=5;child.stdin.end=()=>{child.stderr.emit('data',Buffer.from('Error: No such object: exact\n'));child.emit('close',1,null);};
   return {observed:{identity:{pid:123},argv}};}
  return {groupAbsent:true};
 }};
 const publish=async(name,record)=>{await Promise.resolve();if(name.endsWith('-intent.json'))now+=7;publications.push({...record});};
 const launch=(file,args)=>{argv=[file,...args];child=new EventEmitter();child.pid=123;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.stdin=new EventEmitter();return child;};
 const t=core.transport(owner,config,observer,publish,launch);
 const result=await t.command(['inspect','--type','container','exact'],10000,30000);
 assert.equal(result.code,1);assert.equal(t.clean(),true);assert.equal(publications[0].commandEnd,10000);
 assert.equal(t.records()[0].commandEnd,10000);assert.equal(now,12);
});
test('intent publication exhausting the original ten-second window cannot spawn',async()=>{
 let now=0,spawned=false;
 const observer={status:()=>({pending:0,debts:0}),observe:async()=>{throw Error('must not inspect');}};
 const t=core.transport({nowMs:()=>now},{root:'/repo',docker:'/repo/docker',host:'unix:///repo/socket'},observer,
  async name=>{await Promise.resolve();if(name.endsWith('-intent.json'))now=10000;},()=>{spawned=true;throw Error('must not spawn');});
 await assert.rejects(t.command(['inspect','--type','container','exact'],10000,30000),e=>e.cleanupDebt);
 assert.equal(spawned,false);assert.equal(t.clean(),false);assert.equal(t.records()[0].pid,null);
});
