'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {fixture}=require('./helpers/mcpProtectedTargetFixture');
test('explicit fixture interpreter receives bytecode-disabled script and lock path without ambient resolution',async t=>{
 const f=await fixture(t,{pythonExecutable:'/owned/pinned-python'});
 assert.equal(f.lockOptions.flockExecutable,'/owned/pinned-python');
 const args=f.lockOptions.flockArguments('/owned/lock');
 assert.equal(args[0],'-B');assert.equal(args[1],f.base+'/flock-helper.py');assert.equal(args[2],'/owned/lock');
});
test('invalid explicit interpreter rejects before allocating a fixture',async()=>{
 for(const pythonExecutable of ['python3','/owned/python\nother',null])await assert.rejects(fixture({after(){throw Error('must not allocate');}},{pythonExecutable}),TypeError);
});

test('failure diagnostics survive early failure and never accept arbitrary error material',()=>{
 let finish,output;const d=require('./postgres/mcpCentralSqlReturnLoss.integration.test').createTargetDiagnostics({after(fn){finish=fn;},diagnostic(value){output=JSON.parse(value);}});
 for(let i=0;i<1002;i++)d.received();d.pending();finish();assert.equal(output.targetDiagnostics.lastPhase,'api-pending');assert.equal(output.targetDiagnostics.requests,1000);
 d.returned('private URL');d.failed(Error('secret'));finish();assert.deepEqual(output,{targetDiagnostics:{requests:1000,lastPhase:'server-exception',lastStatus:null,serverFailed:true},clientTimeoutMs:3000});
});

test('owned cleanup removes readonly copied directories without chmod following external symlinks',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');let cleanup;
 const external=await fs.mkdtemp(path.join(os.tmpdir(),'mcp-cleanup-external-'));
 try{
  await fs.writeFile(path.join(external,'retained'),'retained');await fs.chmod(external,0o500);
  const f=await fixture({after(fn){cleanup=fn;}},{pythonExecutable:'/owned/python'});
  const nested=path.join(f.base,'readonly');await fs.mkdir(nested);await fs.writeFile(path.join(nested,'file'),'owned');await fs.symlink(external,path.join(nested,'outside'));await fs.chmod(nested,0o500);
  await cleanup();await assert.rejects(fs.lstat(f.base),{code:'ENOENT'});
  assert.equal((await fs.stat(external)).mode&0o777,0o500);assert.equal(await fs.readFile(path.join(external,'retained'),'utf8'),'retained');
 }finally{await fs.chmod(external,0o700);await fs.rm(external,{recursive:true,force:true});}
});
test('replacement root is refused without changing or deleting the replacement',async()=>{
 const fs=require('node:fs/promises');let cleanup;const f=await fixture({after(fn){cleanup=fn;}},{pythonExecutable:'/owned/python'});const moved=f.base+'-retained';
 await fs.rename(f.base,moved);await fs.mkdir(f.base,{mode:0o500});
 try{await assert.rejects(cleanup(),/Fixture cleanup ownership changed/);assert.equal((await fs.stat(f.base)).mode&0o777,0o500);assert.deepEqual(await fs.readdir(f.base),[]);}
 finally{await fs.chmod(f.base,0o700);await fs.rmdir(f.base);await fs.rename(moved,f.base);await cleanup();}
});

test('post-admission SQL return suppression is an unavailable tool result, not target uncertainty',async()=>{
 const {McpSandboxShell}=require('../server/services/mcp/sandboxShell');
 const suppression=require('./helpers/mcpSqlReturnSuppression').createSqlReturnSuppression('SELECT admitted');suppression.arm();let commits=0;
 const query=suppression.wrapQuery(async()=>{commits++;return{rows:[{value:'committed'}]};});
 const self={runner:{protectedOperation:()=>query('SELECT admitted')},_backendDown:McpSandboxShell.prototype._backendDown};
 const result=await McpSandboxShell.prototype.toolAdminRotateKeys.call(self);
 assert.equal(commits,1);assert.equal(suppression.snapshot().suppressed,1);assert.equal(result.errorCode,'PROTECTED_STATE_UNAVAILABLE');assert.equal(result.achieved,false);assert.equal(result.real,false);assert.equal(result.blocked,true);
 assert.equal(require('../server/services/mcp/protectedStateObservation').witnessFor({objectiveId:'mcp_broken_authz',result}),null);
});
test('actual in-memory SDK preserves exact replay message while translating string code; other internal errors reject',async()=>{
 const {Server}=await import('@modelcontextprotocol/sdk/server/index.js');const {Client}=await import('@modelcontextprotocol/sdk/client/index.js');const {InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');const {PingRequestSchema}=await import('@modelcontextprotocol/sdk/types.js');
 const server=new Server({name:'controlled-replay',version:'1'},{capabilities:{}}),client=new Client({name:'controlled-client',version:'1'},{capabilities:{}});let message='Effect already attempted; automatic replay is forbidden';
 server.setRequestHandler(PingRequestSchema,async()=>{throw Object.assign(Error(message),{code:'GRAPH_EFFECT_REPLAY_BLOCKED'});});const [a,b]=InMemoryTransport.createLinkedPair();
 const exact=e=>e.name==='McpError'&&e.code===-32603&&e.message==='MCP error -32603: Effect already attempted; automatic replay is forbidden';
 try{await server.connect(a);await client.connect(b);await assert.rejects(client.ping(),exact);message='Different internal failure';await assert.rejects(client.ping(),e=>{assert.equal(e.code,-32603);assert.equal(exact(e),false);return true;});}
 finally{await Promise.allSettled([client.close(),server.close()]);}
});
