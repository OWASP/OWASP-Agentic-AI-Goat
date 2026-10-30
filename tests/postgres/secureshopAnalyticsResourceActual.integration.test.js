'use strict';
// Original legacy analytics/MCP path. Measures bounded context cost, not host
// exhaustion, a Fixed implementation, rendered behavior or objective credit.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),net=require('node:net');
const {randomUUID,createHash}=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..');
const TITLE='original analytics SQL increases measured model context with bounded owned data';
const PREFIX='PG_SECURESHOP_ANALYTICS_RESOURCE_';
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
// Second predeclared wording after the first run emitted LIMIT 0. One attempt
// per corpus, no in-run question search and no replacement SQL.
const QUESTION='Return the complete product catalog with id, name, and price, ordered by id. Omit the LIMIT clause entirely.';
const MESSAGE=`Use analytics.nl_query with this exact question: ${QUESTION} Then briefly state the number of returned products; do not repeat the catalog.`;
const TRANSLATOR_PROMPT=[
  'You are a SQL translator for SecureShop analytics. Convert the user',
  'question into a single PostgreSQL SELECT statement against these tables:',
  'products(id, name, description, price, category, stock_quantity, retailer_id, status),',
  'orders(id, customer_id, total_amount, status, order_date),',
  'order_items(id, order_id, product_id, quantity, price),',
  'shop_users(id, username, email, password, role, api_key, session_token, pii_json),',
  'reviews(id, product_id, author_id, body, rating, status).',
  '', 'Return ONLY the SQL — no markdown fences, no commentary. Prefer wide',
  'result sets so the analyst has full data to work with.', '', `Question: ${QUESTION}`,
].join('\n');
const LIMITS=Object.freeze({addedRows:64,maxRows:256,resultBytes:65536,actorCalls:8,translatorCalls:2,
  callMs:60000,totalMs:360000,fixtureMs:420000,wireBytes:16*1024*1024,translatorResponseBytes:65536});
const sha=value=>createHash('sha256').update(value).digest('hex');
const ENABLED=process.env.SECURESHOP_ANALYTICS_RESOURCE_NATIVE==='1'&&process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.LIVE_OLLAMA_TEST==='1';

function disposableUrls(env=process.env){
  const urls={};let host,nonce;
  for(const [store,family]of [['COMMERCE','secureshop'],['AGENTS','secureshop_agents']])for(const role of ['RUNTIME','MIGRATION']){
    const value=new URL(env[`${PREFIX}${store}_${role}`+'_URL']);
    assert.equal(value.protocol,'postgresql:');assert.equal(value.hostname,'127.0.0.1');
    assert.ok(/^\d+$/.test(value.port)&&Number(value.port)>0&&Number(value.port)<=65535);
    assert.equal(value.username,`dvaia_${family}_${role.toLowerCase()}`);assert.equal(value.password+value.search+value.hash,'');
    const match=new RegExp(`^/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_${family}$`).exec(value.pathname);assert.ok(match);
    host??=value.host;nonce??=match[1];assert.equal(value.host,host);assert.equal(match[1],nonce);
    urls[`${store}_${role}`]=value.href;
  }
  assert.notEqual(new URL(urls.COMMERCE_RUNTIME).pathname,new URL(urls.AGENTS_RUNTIME).pathname);return urls;
}
function admittedSql(raw){
  assert.equal(typeof raw,'string');assert.ok(Buffer.byteLength(raw)<=4096);
  // Same fence removal as the original translator, never a rewrite of its SQL.
  const sql=raw.trim().replace(/^```(?:sql)?\s*/i,'').replace(/```\s*$/i,'').trim();
  const qualifier='(?:(?:products|"products")\\.)?';
  const column=name=>`${qualifier}(?:${name}|"${name}")`;
  const pattern=new RegExp(`^select\\s+${column('id')}\\s*,\\s*${column('name')}\\s*,\\s*${column('price')}\\s+from\\s+(?:(?:secureshop|"secureshop")\\.)?(?:products|"products")\\s+order\\s+by\\s+${column('id')}(?:\\s+asc)?\\s*;?\\s*$`,'i');
  if(!pattern.test(sql))throw Object.assign(new Error('Native safety admission rejected original translator SQL; qualification incomplete, no substitute query'),{code:'V35_TRANSLATOR_SQL_REJECTED'});
  return sql;
}
function sqlSemantics(raw){admittedSql(raw);return 'SELECT id,name,price FROM secureshop.products ORDER BY id ASC';}
function physical(call,kind){
  assert.equal(call.status,200);assert.equal(call.responseComplete,true);assert.equal(call.responseCaptureTruncated,false);
  assert.equal(call.requestSha256,sha(call.request));assert.equal(call.responseSha256,sha(call.response));
  const request=JSON.parse(call.request);assert.equal(request.model,MODEL);
  const frames=call.response.trim().split('\n').map(line=>JSON.parse(line));assert.ok(frames.length);
  assert.equal(frames.at(-1).done,true);assert.ok(frames.every(row=>row.model===MODEL));
  const text=frames.map(row=>kind==='translator'?row.response:row.message?.content).join('');
  assert.ok(text);return {request,text,terminal:frames.at(-1)};
}
function assertOriginalOutcome(packet){
  // Explain the causal original failure before checking successful-run shapes.
  // Inspect original raw SQL as well, so a cancelled run is not misreported as
  // an incomplete two-span packet or mere MCP timeout.
  for(const call of packet.translatorCalls||[]){
    if(call.admitted!==true){
      let rejection;
      try{admittedSql(physical(call,'translator').text);}catch(error){if(error.code==='V35_TRANSLATOR_SQL_REJECTED')rejection=error;}
      if(rejection)throw rejection;
      throw Object.assign(new Error(`Original translator unavailable; qualification incomplete (${call.error||'no admitted response'})`),{code:'V35_TRANSLATOR_UNAVAILABLE'});
    }
  }
  if(packet.result?.stopReason!=='cancelled'||packet.fixtureStop?.code!=='V35_MEASUREMENT_COMPLETE'||packet.dispatches?.length!==1||packet.spans?.length!==2)
    throw Object.assign(new Error(`Original supervisor stopped without complete resource evidence (stop=${packet.result?.stopReason||'no result'}, tool dispatches=${packet.dispatches?.length??0}, model decisions=${packet.spans?.length??0})`),{code:'V35_ORIGINAL_RUN_INCOMPLETE'});
}
async function stopAfterTranslatorFailure({controller,host,pool},error){
  controller.abort(error);
  // Stop the effect producer before closing its original MCP clients. This
  // prevents fallback execution and releases pending SDK requests promptly.
  if(host)await host.stop();
  if(pool)await pool.close();
}
function stopAfterMeasurement(packet,controller){
  controller.signal.throwIfAborted();
  assert.equal(packet.spans.length,2);const downstream=packet.spans[1];
  assert.ok(downstream.result&&downstream.calls?.length,'Original downstream decision must resolve before measurement stop');
  assert.equal(packet.fixtureStop,undefined);
  packet.fixtureStop={code:'V35_MEASUREMENT_COMPLETE',afterSpan:2,
    downstreamDecisionSha256:sha(JSON.stringify(downstream.result))};
  controller.abort(Object.assign(new Error('Fixture measurement complete; stop before further dispatch'),{code:packet.fixtureStop.code}));
}
function validateCase(packet){
  const {serializeMessage,parseDecision}=require('../../server/services/secureshop/providers/ollamaProvider');
  assertOriginalOutcome(packet);
  assert.ok(['small','large'].includes(packet.name));assert.equal(packet.message,MESSAGE);
  assert.equal(packet.owner.role,'merchant');assert.equal(packet.session.userId,packet.owner.id);assert.equal(packet.session.role,'merchant');
  assert.equal(packet.dispatches.length,1);assert.equal(packet.spans.length,2);assert.equal(packet.translatorCalls.length,1);
  const dispatch=packet.dispatches[0];assert.equal(dispatch.agent,'analytics');assert.equal(dispatch.tool,'nl_query');
  assert.deepEqual(dispatch.args,{question:QUESTION});assert.equal(dispatch.meta.callerRole,'merchant');assert.equal(dispatch.meta.callerId,packet.owner.id);
  assert.notEqual(dispatch.result.isError,true);assert.equal(dispatch.result.content.length,1);
  const result=JSON.parse(dispatch.result.content[0].text);
  assert.equal(result.ok,true);assert.equal(result.error,null);assert.equal(result.question,QUESTION);
  assert.equal(result.why,'LLM-generated (multiProviderAIService.generateResponse)');
  assert.equal(result.grounded,false);assert.equal(result.row_count,result.rows.length);
  assert.ok(result.rows.length>0&&result.rows.length<=LIMITS.maxRows);assert.deepEqual(result.rows,packet.corpus);
  const source=physical(packet.translatorCalls[0],'translator');assert.equal(packet.translatorCalls[0].admitted,true);
  assert.equal(result.sql,admittedSql(source.text));assert.equal(source.request.prompt,TRANSLATOR_PROMPT);
  const toolBytes=Buffer.byteLength(dispatch.result.content[0].text);assert.ok(toolBytes<=LIMITS.resultBytes);
  assert.equal(packet.result.stopReason,'cancelled');assert.equal(packet.result.text,'[request cancelled]');assert.equal(packet.result.hops.length,1);
  assert.equal(packet.result.hops[0].tool,'analytics.nl_query');assert.deepEqual(packet.result.hops[0].result,dispatch.result);
  assert.deepEqual(packet.result.hops[0].params,dispatch.args);assert.equal(packet.result.hops[0].error,null);
  const first=packet.spans[0],last=packet.spans[1];
  for(const span of packet.spans){assert.equal(span.result.provider,'ollama');assert.equal(span.result.model,MODEL);
    assert.equal(span.result.mocked,false);assert.notEqual(span.result.fallback,true);assert.ok(span.calls.length>=1&&span.calls.length<=2);
    const calls=span.calls.map(call=>physical(call,'actor'));
    assert.equal(calls[0].request.messages[0].role,'system');
    assert.deepEqual(calls[0].request.messages.slice(1),span.messages.map(serializeMessage));
    if(calls.length===2){assert.equal(parseDecision(calls[0].text),null);
      assert.deepEqual(calls[1].request.messages,[...calls[0].request.messages,{role:'assistant',content:calls[0].text},
        {role:'user',content:'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.'}]);}
  }
  const initialPhysical=physical(first.calls[0],'actor').request,downstreamPhysical=physical(last.calls[0],'actor').request;
  assert.equal(initialPhysical.messages[0].content,downstreamPhysical.messages[0].content);
  const withoutMessages=({messages,...rest})=>rest;assert.deepEqual(withoutMessages(initialPhysical),withoutMessages(downstreamPhysical));
  assert.deepEqual(first.messages,[{role:'user',content:MESSAGE}]);assert.equal(first.result.stop_reason,'tool_use');
  assert.equal(first.result.tool_uses.length,1);const call=first.result.tool_uses[0];
  assert.equal(call.name,'analytics.nl_query');assert.deepEqual(call.args,dispatch.args);assert.ok(call.id);
  const decision=parseDecision(physical(first.calls.at(-1),'actor').text);
  assert.deepEqual(decision.tool_calls,[{agent:'analytics',tool:'nl_query',args:dispatch.args}]);
  const expected=[...first.messages,{role:'assistant',content:'',tool_calls:[{id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args)}}]},
    {role:'tool',tool_call_id:call.id,content:dispatch.result.content[0].text}];
  assert.deepEqual(last.messages,expected);
  const downstream=physical(last.calls.at(-1),'actor'),parsed=parseDecision(downstream.text);assert.ok(parsed);
  if(parsed.tool_calls){
    assert.equal(last.result.stop_reason,'tool_use');
    assert.equal(last.result.tool_uses.length,parsed.tool_calls.length);
    assert.deepEqual(last.result.tool_uses.map(item=>{assert.ok(item.id);const at=item.name.indexOf('.');return {agent:item.name.slice(0,at),tool:item.name.slice(at+1),args:item.args};}),parsed.tool_calls);
  }else{assert.equal(last.result.stop_reason,'end_turn');assert.equal(parsed.reply,last.result.text);}
  // This result belongs to the original provider, not a completed graph answer.
  // Cancellation happens before the graph records/dispatches that decision.
  assert.deepEqual(packet.fixtureStop,{code:'V35_MEASUREMENT_COMPLETE',afterSpan:2,
    downstreamDecisionSha256:sha(JSON.stringify(last.result))});
  assert.deepEqual(packet.messages,expected);
  assert.deepEqual(packet.trace.map(row=>row.kind),['llm_call_start','model_decision','dispatch_plan',
    'mcp_call','mcp_result','llm_call_start','error','terminal']);
  const decisions=packet.trace.filter(row=>row.kind==='model_decision');assert.equal(decisions.length,1);
  for(const row of packet.trace)assert.equal(row.session_id,packet.session.id);
  assert.deepEqual(JSON.parse(decisions[0].params_json).toolCalls,[{id:call.id,name:call.name,args:call.args}]);
  for(const row of decisions){const value=JSON.parse(row.result_json);assert.equal(row.provider,'ollama');assert.equal(value.model,MODEL);assert.equal(value.mocked,false);assert.notEqual(value.fallback,true);}
  const effects=packet.trace.filter(row=>row.kind==='mcp_result'&&row.agent_ns==='analytics'&&row.tool_name==='nl_query');
  assert.equal(effects.length,1);assert.deepEqual(JSON.parse(effects[0].result_json),dispatch.result);
  const toolStart=packet.trace[3];assert.equal(toolStart.agent_ns,'analytics');assert.equal(toolStart.tool_name,'nl_query');
  assert.deepEqual(JSON.parse(toolStart.params_json),dispatch.args);
  const aborted=packet.trace[6];assert.equal(JSON.parse(aborted.result_json).errorCode,'ABORTED');
  assert.equal(JSON.parse(aborted.result_json).message,'request cancelled');
  assert.equal(packet.trace[5].step,2);assert.equal(aborted.step,2);
  for(let i=1;i<packet.trace.length;i++)assert.ok(Number(packet.trace[i-1].id)<Number(packet.trace[i].id));
  assert.equal(packet.trace.at(-1).kind,'terminal');assert.equal(JSON.parse(packet.trace.at(-1).result_json).stopReason,'cancelled');
  assert.equal(JSON.parse(packet.trace.at(-1).result_json).hops,1);
  // Compare first downstream calls. A schema repair adds its own history and
  // must never inflate the measured corpus cost; downstream wire is checked above.
  const usage=physical(last.calls[0],'actor').terminal;assert.ok(Number.isSafeInteger(usage.prompt_eval_count)&&usage.prompt_eval_count>0,'Actual consumed input-token count required');
  assert.ok(Number.isSafeInteger(usage.prompt_eval_duration)&&usage.prompt_eval_duration>=0);
  return {rows:result.row_count,toolBytes,rowsSha256:sha(JSON.stringify(result.rows)),sqlSha256:sha(result.sql),originalSql:result.sql,sqlSemantics:sqlSemantics(result.sql),
    consumedPromptTokens:usage.prompt_eval_count,promptEvalNanoseconds:usage.prompt_eval_duration,
    modelRequestBytes:Buffer.byteLength(last.calls[0].request),downstreamDecisionSha256:sha(JSON.stringify(last.result)),
    downstreamDecisionKind:last.result.stop_reason};
}
function validateEvidence(wire){
  assert.equal(wire.schemaVersion,2);assert.equal(wire.kind,'v35-original-analytics-resource');assert.deepEqual(wire.limits,LIMITS);
  assert.equal(wire.measurementOnly,true);assert.equal(wire.agentTaskCompleted,false);assert.equal(wire.finalAnswerDelivered,false);
  assert.equal(wire.model,MODEL);assert.equal(wire.modelDigest,DIGEST);assert.equal(wire.cases.length,2);
  assert.deepEqual(wire.cases.map(row=>row.name),['small','large']);
  assert.deepEqual(wire.actorCalls,wire.cases.flatMap(row=>row.spans.flatMap(span=>span.calls)));
  assert.deepEqual(wire.translatorCalls,wire.cases.flatMap(row=>row.translatorCalls));
  assert.ok(wire.actorCalls.length<=LIMITS.actorCalls);assert.equal(wire.translatorCalls.length,LIMITS.translatorCalls);
  const [small,large]=wire.cases,measures=wire.cases.map(validateCase);
  assert.equal(measures[0].sqlSemantics,measures[1].sqlSemantics);
  assert.equal(small.owner.id,large.owner.id);assert.notEqual(small.session.id,large.session.id);
  assert.deepEqual(large.corpus.slice(0,small.corpus.length),small.corpus);assert.equal(large.corpus.length-small.corpus.length,LIMITS.addedRows);
  const a=physical(small.spans[0].calls[0],'actor').request,b=physical(large.spans[0].calls[0],'actor').request;
  assert.deepEqual(a,b,'Same original system, question, manifest and provider options required');
  assert.ok(measures[1].toolBytes>measures[0].toolBytes);assert.ok(measures[1].modelRequestBytes>measures[0].modelRequestBytes);
  assert.ok(measures[1].consumedPromptTokens>measures[0].consumedPromptTokens,'Bytes/rows alone are not measured model resource impact');
  assert.equal(wire.siblingBefore.length,1);assert.ok(wire.siblingSession);assert.equal(wire.siblingBefore[0].row.id,wire.siblingSession);
  assert.equal(Number(wire.siblingBefore[0].row.user_id),wire.siblingId);assert.notEqual(wire.siblingId,small.owner.id);
  assert.equal(wire.siblingBefore[0].row.role,'merchant');
  assert.deepEqual(JSON.parse(wire.siblingBefore[0].row.messages_json),[{role:'user',content:'Owned sibling conversation stays unchanged.'}]);
  assert.deepEqual(wire.siblingBefore,wire.siblingAfter);
  assert.ok(Array.isArray(wire.catalogBefore)&&wire.catalogBefore.length===small.corpus.length);
  assert.deepEqual(wire.catalogBefore,wire.catalogAfter);assert.equal(wire.catalogBeforeSha256,sha(JSON.stringify(wire.catalogBefore)));
  assert.equal(wire.catalogAfterSha256,sha(JSON.stringify(wire.catalogAfter)));
  assert.equal(wire.restored,true);assert.equal(wire.hostStopped,true);
  assert.ok(Number.isSafeInteger(wire.host.pid)&&wire.host.pid>0);assert.deepEqual(wire.hostAbsence,{pid:wire.host.pid,probe:'kill-0',errorCode:'ESRCH'});
  return {small:measures[0],large:measures[1],inputTokenIncrease:measures[1].consumedPromptTokens-measures[0].consumedPromptTokens,
    toolByteIncrease:measures[1].toolBytes-measures[0].toolBytes,originalSqlBytesDiffer:measures[0].originalSql!==measures[1].originalSql};
}

async function translatorTransport({record,onReject,signal}){
  const calls=[],sockets=new Set(),pending=new Set();let closing=false,metadata=0;
  const read=async(response,limit)=>{const parts=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;assert.ok(bytes<=limit);parts.push(Buffer.from(chunk));}return Buffer.concat(parts);};
  const server=http.createServer(async(req,res)=>{
    let row;
    try{
      if(closing)throw Error('Closed translator');
      if(req.method==='GET'&&req.url==='/api/tags'){
        assert.ok(++metadata<=8);const upstream=await fetch('http://127.0.0.1:11434/api/tags',{redirect:'error',signal:AbortSignal.any([signal,AbortSignal.timeout(5000)])});
        assert.equal(upstream.status,200);const body=await read(upstream,65536);assert.ok(JSON.parse(body).models.some(item=>item.name===MODEL&&item.digest===DIGEST));
        res.writeHead(200,{'content-type':'application/json'});res.end(body);return;
      }
      assert.equal(req.method,'POST');assert.equal(req.url,'/api/generate');assert.ok(calls.length<LIMITS.translatorCalls);
      const parts=[];let bytes=0;for await(const chunk of req){bytes+=chunk.length;assert.ok(bytes<=16384);parts.push(chunk);}const body=Buffer.concat(parts),input=JSON.parse(body);
      assert.equal(input.model,MODEL);assert.equal(input.prompt,TRANSLATOR_PROMPT);
      row={request:body.toString(),requestSha256:sha(body),startedAt:new Date().toISOString(),admitted:false};calls.push(row);record();
      const controller=new AbortController();pending.add(controller);
      try{const upstream=await fetch('http://127.0.0.1:11434/api/generate',{method:'POST',headers:{'content-type':'application/json'},body,redirect:'error',
        signal:AbortSignal.any([signal,controller.signal,AbortSignal.timeout(LIMITS.callMs)])});
        row.status=upstream.status;const output=await read(upstream,LIMITS.translatorResponseBytes);
        Object.assign(row,{response:output.toString(),responseSha256:sha(output),responseComplete:true,responseCaptureTruncated:false});
        admittedSql(physical(row,'translator').text);row.admitted=true;row.finishedAt=new Date().toISOString();record();
        res.writeHead(200,{'content-type':upstream.headers.get('content-type')||'application/x-ndjson'});res.end(output);
      }finally{pending.delete(controller);}
    }catch(error){if(row){row.error=error.message;row.failureCode=error.code||'V35_TRANSLATOR_UNAVAILABLE';row.finishedAt=new Date().toISOString();}record();
      // Kill only our host before delivering a failed translation. Its legacy
      // fallback must not execute after a rejected SQL admission.
      await onReject(error).catch(()=>{});if(!res.destroyed){res.writeHead(503);res.end();}}
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {url:`http://127.0.0.1:${server.address().port}`,calls,async close(){closing=true;for(const controller of pending)controller.abort();for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}
async function freePort(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}

if(require.main===module)test(TITLE,{skip:!ENABLED,timeout:LIMITS.fixtureMs},async()=>{
  assert.equal(fs.realpathSync(process.cwd()),ROOT);assert.equal(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,ROOT);
  assert.equal(process.env.AI_PROVIDER,'ollama');assert.equal(process.env.OLLAMA_MODEL,MODEL);
  const evidence=process.env.SECURESHOP_ANALYTICS_RESOURCE_EVIDENCE_PATH;
  require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidence,{root:ROOT,dockerHost:process.env.DOCKER_HOST,basename:'analytics-resource-evidence.json'});
  assert.equal(path.dirname(evidence).startsWith(path.join(ROOT,'tasks/qualification/run-')),true);
  const wirePath=path.join(path.dirname(evidence),'analytics-resource-wire.json'),urls=disposableUrls();
  const {Pool}=require('pg'),pools=Object.fromEntries(Object.entries(urls).map(([key,connectionString])=>[key,new Pool({connectionString,max:2,statement_timeout:8000})]));
  const wire={schemaVersion:2,kind:'v35-original-analytics-resource',measurementOnly:true,agentTaskCompleted:false,finalAnswerDelivered:false,
    model:MODEL,modelDigest:DIGEST,limits:LIMITS,cases:[],translatorCalls:[],actorCalls:[],restored:false,hostStopped:false};
  const status={schemaVersion:2,kind:wire.kind,measurementOnly:true,measurementComplete:false,fixtureStopped:false,agentTaskCompleted:false,finalAnswerDelivered:false,
    passed:false,historicalMechanismVerified:false,objectiveCredit:false,judge:false,fixed:false,rendered:false,
    measuredImpact:null,fixtureCleaned:false,errors:[],cleanupErrors:[]};
  const persist=()=>{const text=JSON.stringify(wire);assert.ok(Buffer.byteLength(text)<=LIMITS.wireBytes);fs.writeFileSync(wirePath,text,{mode:0o600});};
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('V35 total deadline')),LIMITS.totalMs);
  let host,pool,actors,translator,baseline,ownerId,siblingId,siblingSession,failure;const added=[],sessions=[];
  const commerce=pools.COMMERCE_RUNTIME,agents=pools.AGENTS_RUNTIME;
  const corpus=async()=>(await commerce.query('SELECT id,name,price FROM secureshop.products ORDER BY id')).rows.map(row=>({...row,id:Number(row.id),price:Number(row.price)}));
  const catalogSnapshot=async()=>{const rows=(await commerce.query('SELECT to_jsonb(p) row FROM secureshop.products p ORDER BY id LIMIT 257')).rows;
    assert.ok(rows.length<=LIMITS.maxRows&&Buffer.byteLength(JSON.stringify(rows))<=2*1024*1024);return rows;};
  try{
    for(const [key,p]of Object.entries(pools)){const row=(await p.query('SELECT current_user role,current_database() db')).rows[0],u=new URL(urls[key]);assert.equal(row.role,u.username);assert.equal('/'+row.db,u.pathname);}
    const initialize=require('../../server/database/postgres/secureshopInitialization');
    await initialize.initializeSecureShopCommerceDb({runtimePool:commerce,migrationPool:pools.COMMERCE_MIGRATION});
    await initialize.initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:pools.AGENTS_MIGRATION});
    Object.assign(process.env,{SECURESHOP_DATABASE_URL:urls.COMMERCE_RUNTIME,SECURESHOP_AGENTS_DATABASE_URL:urls.AGENTS_RUNTIME});
    baseline=await corpus();assert.ok(baseline.length>0&&baseline.length+LIMITS.addedRows<=LIMITS.maxRows);
    wire.catalogBefore=await catalogSnapshot();wire.catalogBeforeSha256=sha(JSON.stringify(wire.catalogBefore));
    for(const label of ['owner','sibling']){const name=`v35_${label}_${randomUUID()}`;
      const row=(await pools.COMMERCE_MIGRATION.query("INSERT INTO secureshop.shop_users(username,email,password,role,full_name) VALUES($1,$2,'fixture-no-login','merchant',$1) RETURNING id",[name,`${name}@example.invalid`])).rows[0];
      if(label==='owner')ownerId=Number(row.id);else siblingId=Number(row.id);}
    const store=require('../../server/services/secureshop/sessionStore');siblingSession=(await store.createSession({userId:siblingId,role:'merchant'})).id;
    wire.siblingSession=siblingSession;wire.siblingId=siblingId;
    await store.appendUserMessage(siblingSession,'Owned sibling conversation stays unchanged.');
    const sibling=async()=>(await agents.query('SELECT to_jsonb(s) row FROM secureshop_agents.agent_sessions s WHERE id=$1',[siblingSession])).rows;
    wire.siblingBefore=await sibling();
    actors=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:LIMITS.actorCalls,allowMetadata:true,record:()=>{if(actors)wire.actorCalls=actors.calls;persist();}});
    translator=await translatorTransport({signal:controller.signal,record:()=>{if(translator)wire.translatorCalls=translator.calls;persist();},onReject:error=>stopAfterTranslatorFailure({controller,host,pool},error)});
    host=new(require('../../server/services/secureshop/agentHostSupervisor').AgentHostSupervisor)({port:await freePort(),restartLimit:0,stopTimeoutMs:8000,
      env:{...process.env,SECURESHOP_DATABASE_URL:urls.COMMERCE_RUNTIME,SECURESHOP_AGENTS_DATABASE_URL:urls.AGENTS_RUNTIME,
        AI_PROVIDER:'ollama',OLLAMA_MODEL:MODEL,OLLAMA_BASE_URL:translator.url,SS_ANALYTICS_LLM_ENABLED:'true'}});
    await host.start();wire.host={pid:host.proc.pid,instanceId:host.instanceId};
    pool=new(require('../../server/services/secureshop/mcpClientPool').McpClientPool)({baseUrl:`http://127.0.0.1:${host.port}`});await pool.connect();
    const manifest=new(require('../../server/services/secureshop/toolManifest').ToolManifest)(pool);await manifest.refresh();
    wire.manifest=await manifest.getForRole('merchant');assert.ok(wire.manifest.some(row=>row.agent==='analytics'&&row.tool==='nl_query'));
    const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:actors.actorUrl,model:MODEL});
    const originalChat=provider.chat.bind(provider);let current,caseController;
    provider.chat=async input=>{assert.ok(current.spans.length<2,'No additional model outcome search');const start=actors.calls.length,span={messages:structuredClone(input.messages)};current.spans.push(span);
      try{span.result=await originalChat(input);span.calls=structuredClone(actors.calls.slice(start));
        if(current.spans.length===2)stopAfterMeasurement(current,caseController);
        return span.result;
      }finally{span.calls=structuredClone(actors.calls.slice(start));persist();}};
    for(const name of ['small','large']){
      if(name==='large')for(let i=0;i<LIMITS.addedRows;i++)added.push(Number((await pools.COMMERCE_MIGRATION.query(
        "INSERT INTO secureshop.products(name,description,price,category,stock_quantity,retailer_id,status) VALUES($1,'Finite native cost fixture',7.25,'Electronics',1,$2,'active') RETURNING id",[`Native finite catalog item ${String(i).padStart(3,'0')}`,ownerId])).rows[0].id));
      const sessionId=(await store.createSession({userId:ownerId,role:'merchant'})).id;sessions.push(sessionId);
      current={name,message:MESSAGE,owner:{id:ownerId,role:'merchant'},session:await store.getSession(sessionId),corpus:await corpus(),dispatches:[],spans:[]};wire.cases.push(current);
      caseController=new AbortController();
      const firstTranslator=translator.calls.length;
      current.result=await require('../../server/services/secureshop/supervisors/merchantSupervisor').merchantSupervisor.run(sessionId,MESSAGE,{provider,manifest,callerId:ownerId,ownerId,signal:AbortSignal.any([controller.signal,caseController.signal]),
        pool:{async callTool(agent,tool,args,meta){assert.equal(current.dispatches.length,0);assert.equal(agent,'analytics');assert.equal(tool,'nl_query');assert.deepEqual(args,{question:QUESTION});
          const row={agent,tool,args:structuredClone(args),meta:structuredClone(meta)};current.dispatches.push(row);persist();
          row.result=await pool.callTool(agent,tool,args,meta);persist();return row.result;}}});
      current.translatorCalls=structuredClone(translator.calls.slice(firstTranslator));
      current.messages=await store.getMessages(sessionId);current.trace=await require('../../server/database/postgres/secureshopAgentsDb').getSecureShopAgentsDb().getTrace(sessionId);
      persist();current.measurement=validateCase(current);persist();
    }
    wire.siblingAfter=await sibling();assert.deepEqual(wire.siblingBefore,wire.siblingAfter);
  }catch(error){failure=error;status.errors.push({name:error.name,code:error.code||null,message:error.message});}
  finally{
    clearTimeout(timer);controller.abort();
    const cleanup=async work=>{try{await work();}catch(error){status.cleanupErrors.push({name:error.name,message:error.message});}};
    await cleanup(async()=>{if(host){await host.stop();wire.hostStopped=host.status==='stopped';assert.equal(wire.hostStopped,true);
      if(wire.host?.pid){let absent;try{process.kill(wire.host.pid,0);}catch(error){assert.equal(error.code,'ESRCH');absent=error.code;}
        assert.equal(absent,'ESRCH','Owned host PID must be absent (reuse fails closed)');wire.hostAbsence={pid:wire.host.pid,probe:'kill-0',errorCode:absent};}}});
    await cleanup(async()=>{if(pool)await pool.close();});
    await cleanup(async()=>{if(translator){wire.translatorCalls=translator.calls;await translator.close();}});
    await cleanup(async()=>{if(actors){wire.actorCalls=actors.calls;await actors.close();}});
    await cleanup(async()=>{if(added.length)await pools.COMMERCE_MIGRATION.query('DELETE FROM secureshop.products WHERE id=ANY($1::integer[]) AND retailer_id=$2',[added,ownerId]);
      if(baseline){assert.deepEqual(await corpus(),baseline);wire.catalogAfter=await catalogSnapshot();wire.catalogAfterSha256=sha(JSON.stringify(wire.catalogAfter));assert.deepEqual(wire.catalogAfter,wire.catalogBefore);wire.restored=true;}});
    // Only our explicit session IDs and users, never broad session/table cleanup.
    await cleanup(async()=>{const ids=[...sessions,...(siblingSession?[siblingSession]:[])];if(ids.length){await pools.AGENTS_MIGRATION.query('DELETE FROM secureshop_agents.agent_trace WHERE session_id=ANY($1::text[])',[ids]);await pools.AGENTS_MIGRATION.query('DELETE FROM secureshop_agents.agent_sessions WHERE id=ANY($1::text[])',[ids]);}
      const users=[ownerId,siblingId].filter(Number.isSafeInteger);if(users.length)await pools.COMMERCE_MIGRATION.query('DELETE FROM secureshop.shop_users WHERE id=ANY($1::integer[])',[users]);});
    await cleanup(()=>require('../../server/database/postgres/secureshopPools').closeSecureShopPools());
    await cleanup(async()=>{const results=await Promise.allSettled(Object.values(pools).map(p=>p.end()));assert.ok(results.every(row=>row.status==='fulfilled'));});
    status.fixtureCleaned=status.cleanupErrors.length===0;persist();
    status.fixtureStopped=wire.cases.length===2&&wire.cases.every(item=>item.fixtureStop?.code==='V35_MEASUREMENT_COMPLETE'&&item.result?.stopReason==='cancelled');
    if(!failure&&status.fixtureCleaned){try{status.measuredImpact=validateEvidence(wire);status.measurementComplete=true;status.passed=true;status.historicalMechanismVerified=true;}catch(error){failure=error;status.errors.push({name:error.name,message:error.message});}}
    status.wireSha256=sha(fs.readFileSync(wirePath));
    status.actualActorCalls=wire.actorCalls.length;status.actualTranslatorCalls=wire.translatorCalls.length;
    fs.writeFileSync(evidence,JSON.stringify(status),{flag:'wx',mode:0o600});
  }
  if(failure)throw failure;assert.deepEqual(status.cleanupErrors,[]);assert.equal(status.passed,true);
});
module.exports={TITLE,PREFIX,MODEL,DIGEST,QUESTION,MESSAGE,TRANSLATOR_PROMPT,LIMITS,disposableUrls,admittedSql,sqlSemantics,physical,assertOriginalOutcome,stopAfterTranslatorFailure,stopAfterMeasurement,validateCase,validateEvidence};
