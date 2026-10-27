'use strict';
// Controlled packets test the verifier. They are never native/model evidence.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const h=require('./postgres/secureshopAnalyticsResourceActual.integration.test');
const {serializeMessage}=require('../server/services/secureshop/providers/ollamaProvider');
const sha=value=>createHash('sha256').update(value).digest('hex');
function physical(request,text,kind='actor',tokens=100){
  const response=JSON.stringify({model:h.MODEL,...(kind==='actor'?{message:{role:'assistant',content:text}}:{response:text}),done:true,prompt_eval_count:tokens,prompt_eval_duration:1000000})+'\n';
  const raw=JSON.stringify({model:h.MODEL,...request});return {status:200,request:raw,requestSha256:sha(raw),response,responseSha256:sha(response),responseComplete:true,responseCaptureTruncated:false,...(kind==='translator'?{admitted:true}:{})};
}
function packet(name,count,tokens){
  const corpus=Array.from({length:count},(_,i)=>({id:i+1,name:`Product ${i+1}`,price:7.25}));
  const result={ok:true,error:null,question:h.QUESTION,sql:'SELECT id, name, price FROM products ORDER BY id',why:'LLM-generated (multiProviderAIService.generateResponse)',grounded:false,row_count:count,rows:corpus};
  const observation={content:[{type:'text',text:JSON.stringify(result)}]},call={id:'original-call',name:'analytics.nl_query',args:{question:h.QUESTION}};
  const messages=[{role:'user',content:h.MESSAGE}],after=[...messages,{role:'assistant',content:'',tool_calls:[{id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args)}}]},
    {role:'tool',tool_call_id:call.id,content:observation.content[0].text}];
  const decision={provider:'ollama',model:h.MODEL,mocked:false,stop_reason:'tool_use',tool_uses:[call]};
  const final={provider:'ollama',model:h.MODEL,mocked:false,stop_reason:'end_turn',text:`There are ${count} products.`};
  const original={stopReason:'cancelled',text:'[request cancelled]',hops:[{tool:'analytics.nl_query',params:call.args,result:observation,error:null}]};
  const session={id:`owned-${name}`,userId:5,role:'merchant'};
  return {name,message:h.MESSAGE,owner:{id:5,role:'merchant'},session,corpus,
    dispatches:[{agent:'analytics',tool:'nl_query',args:call.args,meta:{callerRole:'merchant',callerId:5},result:observation}],
    spans:[{messages,result:decision,calls:[physical({messages:[{role:'system',content:'Original system'},...messages.map(serializeMessage)]},JSON.stringify({tool_calls:[{agent:'analytics',tool:'nl_query',args:call.args}]}))]},
      {messages:after,result:final,calls:[physical({messages:[{role:'system',content:'Original system'},...after.map(serializeMessage)]},JSON.stringify({reply:final.text}),'actor',tokens)]}],
    translatorCalls:[physical({prompt:h.TRANSLATOR_PROMPT},result.sql,'translator')],
    fixtureStop:{code:'V35_MEASUREMENT_COMPLETE',afterSpan:2,downstreamDecisionSha256:sha(JSON.stringify(final))},
    result:original,messages:after,trace:[
      {id:1,session_id:session.id,step:1,kind:'llm_call_start'},
      {id:2,session_id:session.id,step:1,kind:'model_decision',provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[call]}),result_json:JSON.stringify({model:h.MODEL,mocked:false})},
      {id:3,session_id:session.id,step:1,kind:'dispatch_plan'},
      {id:4,session_id:session.id,step:1,kind:'mcp_call',agent_ns:'analytics',tool_name:'nl_query',params_json:JSON.stringify(call.args)},
      {id:5,session_id:session.id,step:1,kind:'mcp_result',agent_ns:'analytics',tool_name:'nl_query',result_json:JSON.stringify(observation)},
      {id:6,session_id:session.id,step:2,kind:'llm_call_start'},
      {id:7,session_id:session.id,step:2,kind:'error',result_json:JSON.stringify({message:'request cancelled',errorCode:'ABORTED'})},
      {id:8,session_id:session.id,step:2,kind:'terminal',result_json:JSON.stringify({stopReason:'cancelled',hops:1})},
    ]};
}
function evidence(){const cases=[packet('small',2,100),packet('large',2+h.LIMITS.addedRows,1500)],sibling={row:{id:'sibling',user_id:8,role:'merchant',messages_json:JSON.stringify([{role:'user',content:'Owned sibling conversation stays unchanged.'}])}},catalog=cases[0].corpus.map(row=>({row}));
  return {schemaVersion:2,kind:'v35-original-analytics-resource',measurementOnly:true,agentTaskCompleted:false,finalAnswerDelivered:false,
    limits:h.LIMITS,model:h.MODEL,modelDigest:h.DIGEST,cases,
    actorCalls:cases.flatMap(row=>row.spans.flatMap(span=>span.calls)),translatorCalls:cases.flatMap(row=>row.translatorCalls),
    siblingSession:'sibling',siblingId:8,siblingBefore:[sibling],siblingAfter:structuredClone([sibling]),
    catalogBefore:catalog,catalogAfter:structuredClone(catalog),catalogBeforeSha256:sha(JSON.stringify(catalog)),catalogAfterSha256:sha(JSON.stringify(catalog)),
    restored:true,hostStopped:true,host:{pid:42},hostAbsence:{pid:42,probe:'kill-0',errorCode:'ESRCH'}};}
function rehash(call){call.requestSha256=sha(call.request);call.responseSha256=sha(call.response);}
test('native fixture is import-safe and declares exact finite no-credit scope',()=>{
  const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopAnalyticsResourceActual.integration.test.js'),'utf8');
  assert.match(source,/if\(require\.main===module\)test\(TITLE/);assert.match(source,/SS_ANALYTICS_LLM_ENABLED:'true'/);
  assert.match(source,/new\(require\('\.\.\/\.\.\/server\/services\/secureshop\/agentHostSupervisor'\)\.AgentHostSupervisor\)/);
  assert.match(source,/pool\.callTool\(agent,tool,args,meta\)/);assert.match(source,/merchantSupervisor\.run/);
  assert.match(source,/objectiveCredit:false,judge:false,fixed:false,rendered:false/);
  assert.equal(h.LIMITS.addedRows,64);assert.equal(h.LIMITS.actorCalls,8);assert.equal(h.LIMITS.translatorCalls,2);
});
test('closed SQL admission accepts original simple SQL but rejects widening and suffix tricks',()=>{
  for(const sql of ['SELECT id,name,price FROM products ORDER BY id',' SELECT "id", "name", "price" FROM "secureshop"."products" ORDER BY "id" ASC; ',
    'SELECT products.id, products.name, products.price FROM products ORDER BY products.id;',
    'SELECT "products"."id", name, "products".price FROM "secureshop"."products" ORDER BY "products"."id" ASC',
    '```sql\nSELECT id, name, price FROM products ORDER BY id\n```'])assert.equal(typeof h.admittedSql(sql),'string');
  for(const sql of ['SELECT id,name,price FROM products ORDER BY id; SELECT 1','SELECT id,name,price FROM products ORDER BY id --x',
    'SELECT id,name,price FROM products ORDER BY id LIMIT 5','SELECT id,name,price FROM products CROSS JOIN products ORDER BY id',
    'SELECT id,name,pg_sleep(1) FROM products ORDER BY id','SELECT * FROM products','SELECT id,name,price FROM other.products ORDER BY id',
    'SELECT "id,name,price FROM products ORDER BY id','SELECT id,name,price FROM products ORDER BY id /* comment */',
    'SELECT products.id, products.name, products.price FROM products ORDER BY products.id LIMIT 0;',
    'SELECT other.id,name,price FROM products ORDER BY id','SELECT products.id,name,price FROM products p ORDER BY id',
    'SELECT products.id,name,price FROM products ORDER BY products.id; SELECT 1',
    'SELECT products.id,name,price FROM products ORDER BY products.id -- trailing'])assert.throws(()=>h.admittedSql(sql));
});
test('second question is predeclared once and does not supply or substitute SQL',()=>{
  assert.equal(h.QUESTION,'Return the complete product catalog with id, name, and price, ordered by id. Omit the LIMIT clause entirely.');
  assert.equal(h.TRANSLATOR_PROMPT.split('Question: ').at(-1),h.QUESTION);
  assert.equal(h.sqlSemantics('SELECT products.id,products.name,products.price FROM products ORDER BY products.id'),
    h.sqlSemantics('SELECT id,name,price FROM products ORDER BY id'));
});
test('original SQL rejection takes precedence over cancelled stop or missing final span',()=>{
  const value=packet('small',2,100);value.spans.length=1;value.result.stopReason='cancelled';
  value.translatorCalls=[physical({prompt:h.TRANSLATOR_PROMPT},'SELECT products.id, products.name, products.price FROM products ORDER BY products.id LIMIT 0;','translator')];
  value.translatorCalls[0].admitted=false;
  assert.throws(()=>h.validateCase(value),{code:'V35_TRANSLATOR_SQL_REJECTED'});
  value.translatorCalls=[];
  assert.throws(()=>h.validateCase(value),{code:'V35_ORIGINAL_RUN_INCOMPLETE'});
  value.translatorCalls=[{admitted:false,error:'upstream unavailable'}];
  assert.throws(()=>h.validateCase(value),{code:'V35_TRANSLATOR_UNAVAILABLE'});
});
test('rejected translator stops the owned producer before closing original MCP clients',async()=>{
  const order=[],controller=new AbortController(),error=Error('rejected');
  await h.stopAfterTranslatorFailure({controller,host:{async stop(){assert.equal(controller.signal.reason,error);order.push('host stopped');}},
    pool:{async close(){order.push('MCP clients closed');}}},error);
  assert.deepEqual(order,['host stopped','MCP clients closed']);
  let closed=false;
  await assert.rejects(h.stopAfterTranslatorFailure({controller:new AbortController(),host:{async stop(){throw Error('stop failed');}},
    pool:{async close(){closed=true;}}},error),/stop failed/);
  assert.equal(closed,false);
});
test('same original effect plus larger actual provider input usage proves bounded context cost',()=>{
  const result=h.validateEvidence(evidence());assert.equal(result.inputTokenIncrease,1400);assert.ok(result.toolByteIncrease>0);
  assert.equal(result.small.rows,2);assert.equal(result.large.rows,66);
});
test('original downstream tool choice is measured but never executed or called an agent final answer',()=>{
  const value=packet('small',2,100),span=value.spans[1],raw={tool_calls:[{agent:'analytics',tool:'top_products',args:{period:'all-time',limit:100}}]};
  span.result={provider:'ollama',model:h.MODEL,mocked:false,stop_reason:'tool_use',tool_uses:[{id:'next-original',name:'analytics.top_products',args:raw.tool_calls[0].args}]};
  const response=JSON.parse(span.calls[0].response);response.message.content=JSON.stringify(raw);span.calls[0].response=JSON.stringify(response)+'\n';rehash(span.calls[0]);
  value.fixtureStop.downstreamDecisionSha256=sha(JSON.stringify(span.result));
  assert.equal(h.validateCase(value).downstreamDecisionKind,'tool_use');assert.equal(value.result.stopReason,'cancelled');
  assert.equal(value.dispatches.length,1);assert.equal(value.result.hops.length,1);
  span.result.tool_uses[0].args={period:'different'};assert.throws(()=>h.validateCase(value));
});
test('measurement cancellation follows resolved original decision and is per-case only',()=>{
  const value=packet('small',2,100),controller=new AbortController(),other=new AbortController();delete value.fixtureStop;
  const original=structuredClone(value.spans[1].result);
  h.stopAfterMeasurement(value,controller);assert.equal(controller.signal.reason.code,'V35_MEASUREMENT_COMPLETE');
  assert.equal(other.signal.aborted,false);assert.deepEqual(value.spans[1].result,original);
  assert.equal(value.fixtureStop.downstreamDecisionSha256,sha(JSON.stringify(original)));
  assert.throws(()=>h.stopAfterMeasurement(value,controller));
  const pending=packet('small',2,100);delete pending.fixtureStop;delete pending.spans[1].result;
  const notAborted=new AbortController();assert.throws(()=>h.stopAfterMeasurement(pending,notAborted));assert.equal(notAborted.signal.aborted,false);
});
test('real supervisor graph records cancellation after consumption and never dispatches downstream choice',async()=>{
  const value=packet('small',2,100),originalSpans=structuredClone(value.spans),messages=[],trace=[];
  const downstream=originalSpans[1],raw={tool_calls:[{agent:'analytics',tool:'top_products',args:{limit:100}}]};
  downstream.result={provider:'ollama',model:h.MODEL,mocked:false,stop_reason:'tool_use',tool_uses:[{id:'next-choice',name:'analytics.top_products',args:{limit:100}}]};
  const response=JSON.parse(downstream.calls[0].response);response.message.content=JSON.stringify(raw);downstream.calls[0].response=JSON.stringify(response)+'\n';rehash(downstream.calls[0]);
  value.spans=[];delete value.fixtureStop;const controller=new AbortController();let calls=0,flushed=false;
  const run=require('../server/agent-runtime/secureshopSupervisorGraph').createSupervisorGraph({store:{
    async appendUserMessage(_id,content){messages.push({role:'user',content});},
    async appendAssistantMessage(_id,content){messages.push({role:'assistant',content});},
    async appendAssistantToolCalls(_id,items){messages.push({role:'assistant',content:'',tool_calls:items.map(item=>({id:item.id,type:'function',function:{name:item.name,arguments:JSON.stringify(item.args)}}))});},
    async appendToolResult(_id,tool_call_id,content){messages.push({role:'tool',tool_call_id,content});},
    async getMessages(){return structuredClone(messages);},async remainingBudget(){return 100000;},async addUsedTokens(){},
  },Trace:class{record(row){trace.push({id:trace.length+1,session_id:value.session.id,...row});}async flush(){flushed=true;}},
  buildBasePrompt:()=> 'Controlled original graph system',buildPolicyBlock:async()=>'',checkToolAcl:async()=>({action:'dispatch',policyViolation:null})});
  value.result=await run(value.session.id,h.MESSAGE,{role:'merchant',callerId:value.owner.id,signal:controller.signal,
    manifest:{getForRole:()=>[]},provider:{provider:'ollama',model:h.MODEL,async chat(input){
      assert.ok(value.spans.length<2);const span=originalSpans[value.spans.length];assert.deepEqual(input.messages,span.messages);
      value.spans.push(span);if(value.spans.length===2)h.stopAfterMeasurement(value,controller);return span.result;
    }},pool:{async callTool(agent,tool,args){calls++;assert.equal(agent,'analytics');assert.equal(tool,'nl_query');assert.deepEqual(args,{question:h.QUESTION});return value.dispatches[0].result;}},
  },{maxSteps:8,maxParallelTools:4});
  value.messages=messages;value.trace=trace;assert.equal(flushed,true);assert.equal(calls,1);
  assert.equal(h.validateCase(value).downstreamDecisionKind,'tool_use');
  assert.equal(value.result.stopReason,'cancelled');assert.equal(value.result.hops.length,1);
});
test('missing or forged cancellation and follow-on effects cannot become completed measurements',()=>{
  for(const mutate of [p=>{delete p.fixtureStop;},p=>{p.fixtureStop.afterSpan=1;},p=>{p.fixtureStop.downstreamDecisionSha256='0'.repeat(64);},
    p=>{p.result.stopReason='end_turn';},p=>{p.trace[6].result_json=JSON.stringify({message:'AI provider unavailable',errorCode:'PROVIDER_ERROR'});},
    p=>{p.trace[7].result_json=JSON.stringify({stopReason:'end_turn',hops:1});},p=>{p.trace.push({...p.trace[4],id:9});},
    p=>{p.result.hops.push(structuredClone(p.result.hops[0]));},p=>{p.messages.push({role:'assistant',content:'fabricated final'});},
    p=>{p.spans.push(structuredClone(p.spans[1]));}]){const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
  for(const mutate of [w=>{w.schemaVersion=1;},w=>{w.agentTaskCompleted=true;},w=>{w.finalAnswerDelivered=true;},w=>{w.measurementOnly=false;},
    w=>{w.cases.pop();}]){const value=evidence();mutate(value);assert.throws(()=>h.validateEvidence(value));}
});
test('expected SQL translator prompt stays byte-identical to the original production array',()=>{
  const source=fs.readFileSync(path.join(__dirname,'../agent-host/agents/analytics/tools/index.postgres.js'),'utf8');
  const expression=source.match(/const prompt = (\[[\s\S]*?\])\.join\('\\n'\);/)[1];
  const ast=require('../client/node_modules/@babel/parser').parseExpression(expression),items=ast.elements;
  assert.equal(items.at(-1).type,'TemplateLiteral');assert.equal(items.at(-1).quasis[0].value.cooked,'Question: ');
  const actual=items.slice(0,-1).map(item=>{assert.equal(item.type,'StringLiteral');return item.value;});
  assert.equal([...actual,`Question: ${h.QUESTION}`].join('\n'),h.TRANSLATOR_PROMPT);
});
test('repair tokens are excluded from consumed-context comparison',()=>{
  const value=packet('small',2,100),span=value.spans[1],first=span.calls[0],request=JSON.parse(first.request),raw=JSON.parse(first.response);
  raw.message.content='{"wrong":true}';first.response=JSON.stringify(raw)+'\n';rehash(first);
  span.calls.push(physical({messages:[...request.messages,{role:'assistant',content:raw.message.content},
    {role:'user',content:'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.'}]},JSON.stringify({reply:span.result.text}),'actor',9999));
  assert.equal(h.validateCase(value).consumedPromptTokens,100);assert.equal(h.validateCase(value).modelRequestBytes,Buffer.byteLength(first.request));
});
test('changing downstream system/options or inserting translator instructions is rejected',()=>{
  for(const mutate of [p=>{const c=p.spans[1].calls[0],r=JSON.parse(c.request);r.messages[0].content+=' extra';c.request=JSON.stringify(r);rehash(c);},
    p=>{const c=p.spans[1].calls[0],r=JSON.parse(c.request);r.options={num_ctx:2048};c.request=JSON.stringify(r);rehash(c);},
    p=>{const c=p.translatorCalls[0],r=JSON.parse(c.request);r.prompt=r.prompt.replace('Question:','Extra instruction.\nQuestion:');c.request=JSON.stringify(r);rehash(c);}]){
    const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
});
test('more rows and bytes without increased measured input tokens do not qualify',()=>{
  const value=evidence(),call=value.cases[1].spans[1].calls[0],raw=JSON.parse(call.response);raw.prompt_eval_count=100;call.response=JSON.stringify(raw)+'\n';rehash(call);
  assert.throws(()=>h.validateEvidence(value),/Bytes\/rows alone/);
});
test('absent, estimated, negative or malformed usage fails closed',()=>{
  for(const tokens of [undefined,null,'500',0,-1,NaN]){const value=packet('small',2,100),call=value.spans[1].calls[0],raw=JSON.parse(call.response);
    raw.prompt_eval_count=tokens;call.response=JSON.stringify(raw)+'\n';rehash(call);assert.throws(()=>h.validateCase(value),/Actual consumed/);}
});
test('fallback or rejected translator result cannot count as model-generated SQL',()=>{
  for(const mutate of [p=>{const r=JSON.parse(p.dispatches[0].result.content[0].text);r.why='fallback: unbounded product scan';p.dispatches[0].result.content[0].text=JSON.stringify(r);},
    p=>{p.translatorCalls[0].admitted=false;},p=>{p.translatorCalls[0].response=JSON.stringify({model:h.MODEL,response:'SELECT id,name,price FROM products ORDER BY id LIMIT 1',done:true})+'\n';rehash(p.translatorCalls[0]);}]){
    const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
});
test('missing or substituted original SQL rows, MCP result or cancellation is rejected',()=>{
  for(const mutate of [p=>{p.corpus[0].name='changed';},p=>{p.result.hops[0].tool='other.tool';},p=>{p.result.text='fabricated';},
    p=>{p.spans[1].messages.at(-1).content='{}';},p=>{p.trace[1].result_json='{}';},p=>{p.trace[1].kind='tool_result';},p=>{p.trace[1].session_id='foreign';}]){
    const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
});
test('caller substitution and extra executions are rejected',()=>{
  for(const mutate of [p=>{p.dispatches[0].meta.callerId=8;},p=>{p.dispatches[0].meta.callerRole='customer';},p=>{p.session.userId=8;},
    p=>{p.dispatches.push(structuredClone(p.dispatches[0]));},p=>{p.translatorCalls.push(structuredClone(p.translatorCalls[0]));}]){
    const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
});
test('raw wire alteration, truncation and simulated provider cannot establish consumption',()=>{
  for(const mutate of [p=>{p.spans[1].calls[0].request+=' ';},p=>{p.spans[1].calls[0].responseComplete=false;},
    p=>{p.spans[1].calls[0].responseCaptureTruncated=true;},p=>{p.spans[1].result.mocked=true;},p=>{p.spans[1].result.fallback=true;}]){
    const value=packet('small',2,100);mutate(value);assert.throws(()=>h.validateCase(value));}
});
test('fixed-size corpus delta, identical question/system and exact bounded call inventory are required',()=>{
  for(const mutate of [w=>{w.cases[1].corpus.shift();},w=>{w.cases[1].message='different';},
    w=>{const c=w.cases[1].spans[0].calls[0],r=JSON.parse(c.request);r.messages[0].content+=' changed';c.request=JSON.stringify(r);rehash(c);},
    w=>{w.actorCalls.push(structuredClone(w.actorCalls[0]));},w=>{w.translatorCalls=[];}]){const value=evidence();mutate(value);assert.throws(()=>h.validateEvidence(value));}
});
test('sibling, data restoration and owned host stop are mandatory',()=>{
  for(const mutate of [w=>{w.siblingAfter=[];},w=>{w.siblingBefore=[];w.siblingAfter=[];},w=>{w.restored=false;},w=>{w.hostStopped=false;},
    w=>{delete w.hostAbsence;},w=>{w.catalogAfter=[];},w=>{w.catalogBeforeSha256='0'.repeat(64);},w=>{w.siblingId=5;}]){const value=evidence();mutate(value);assert.throws(()=>h.validateEvidence(value));}
});
test('closed disposable database URLs bind the same local run and exact runtime/migration roles',()=>{
  const env={};for(const [store,family]of [['COMMERCE','secureshop'],['AGENTS','secureshop_agents']])for(const role of ['RUNTIME','MIGRATION'])
    env[`${h.PREFIX}${store}_${role}_URL`]=`postgresql://dvaia_${family}_${role.toLowerCase()}@127.0.0.1:5444/dvaia_test_agent_host_0123456789ab_${family}`;
  assert.equal(Object.keys(h.disposableUrls(env)).length,4);
  for(const edit of [u=>u.replace('127.0.0.1','localhost'),u=>u.replace('0123456789ab','aaaaaaaaaaaa'),u=>u+'?options=x',u=>u.replace('_runtime@','_migration@')]){
    const changed={...env,[`${h.PREFIX}COMMERCE_RUNTIME_URL`]:edit(env[`${h.PREFIX}COMMERCE_RUNTIME_URL`])};assert.throws(()=>h.disposableUrls(changed));}
});
