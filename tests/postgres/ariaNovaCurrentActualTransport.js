'use strict';
const assert=require('node:assert/strict'),http=require('node:http'),path=require('node:path'),fs=require('node:fs');
const {performance}=require('node:perf_hooks'),{AsyncLocalStorage}=require('node:async_hooks'),{createHash}=require('node:crypto');
const {saveBounded}=require('../fixtures/boundedJsonArtifact');
const {createResponseCapture}=require('./secureshopMailActualTransport');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha=x=>createHash('sha256').update(x).digest('hex');
const upstreamContext=new AsyncLocalStorage(),upstreamToken=Object.freeze({});
const allowsUpstream=()=>upstreamContext.getStore()===upstreamToken;
const {profileFor}=require('../fixtures/ariaNovaCurrentProfiles');
function budget(profile='current'){
 const profileLimits=profileFor(profile);
 const counts={external:0,incoming:0,metadata:0,tags:0,version:0,generate:0,chat:0};
 return {counts,incoming(){assert(counts.incoming<profileLimits.external);counts.incoming++;},reserve(kind){
  assert(['tags','version','generate','chat'].includes(kind));assert(counts.external<profileLimits.external);
  if(kind==='tags')assert(counts.tags<1);if(kind==='version')assert(counts.version<0);
  if(kind==='generate')assert(counts.generate<profileLimits.generate);if(kind==='chat')assert(counts.chat<profileLimits.chat);
  if(['tags','version'].includes(kind))assert(counts.metadata<1);else assert(counts.generate+counts.chat<profileLimits.external-1);
  counts.external++;counts[kind]++;if(['tags','version'].includes(kind))counts.metadata++;
 }};
}
function validateRequest(method,url,body){
 if(method==='GET'&&['/api/tags','/api/version'].includes(url)){assert.equal(body.length,0);return url==='/api/tags'?'tags':'version';}
 assert.equal(method,'POST');assert(['/api/generate','/api/chat'].includes(url));assert(body.length>0&&body.length<=262144);const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));
 const keys=['model','stream','options','format',...(url==='/api/chat'?['messages','tools']:['prompt','system','template','raw','keep_alive'])];assert(Object.keys(v).every(k=>keys.includes(k)));assert(v.options&&typeof v.options==='object'&&!Array.isArray(v.options));const o=v.options;assert(Object.keys(o).every(k=>['temperature','num_predict','num_ctx','top_p','top_k','stop'].includes(k)));if(url==='/api/generate'){assert((o.temperature===0&&o.num_predict===300&&o.num_ctx===8192&&(v.format==='json'||v.format&&typeof v.format==='object'))||(o.temperature===0.7&&o.num_predict===1500&&o.num_ctx===undefined&&v.format===undefined));}else{assert.equal(o.temperature,0);assert.equal(o.num_predict,900);assert.equal(o.num_ctx,32768);assert(v.format&&typeof v.format==='object');assert(!v.tools||v.tools.length===0);}if(o.top_p!==undefined)assert(Number.isFinite(o.top_p)&&o.top_p>=0&&o.top_p<=1);if(o.top_k!==undefined)assert(Number.isInteger(o.top_k)&&o.top_k>=0&&o.top_k<=100);if(o.stop!==undefined)assert(Array.isArray(o.stop)&&o.stop.length<=8&&o.stop.every(x=>typeof x==='string'&&Buffer.byteLength(x)<=128));
 if(url==='/api/chat')assert(Array.isArray(v.messages)&&v.messages.length);else assert.equal(typeof v.prompt,'string');
 return url==='/api/chat'?'chat':'generate';
}
function classifyRequest(row) {
 const body=Buffer.from(row.request);assert.equal(sha(body),row.requestSha256);assert.equal(validateRequest(row.method,row.path,body),row.kind);
 if(row.kind==='chat')return 'judge';
 const request=JSON.parse(row.request);return request.options.temperature===0?'decision':'formatter';
}
function validateResponse(row) {
  assert.equal(row.status, 200); assert.equal(row.responseComplete, true); assert.equal(row.responseCaptureTruncated, false);
  assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);
  if (row.kind === 'version') {
    const v=JSON.parse(row.response);assert(v&&typeof v.version==='string'&&/^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$/.test(v.version));
  } else if (row.kind === 'tags') {
    assert.ok(JSON.parse(row.response).models?.some(value => (value.name === MODEL || value.model === MODEL) && value.digest === DIGEST));
  } else {
    const frames = row.response.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(frames.length); assert.equal(frames.at(-1).done, true); const role=classifyRequest(row),reason=frames.at(-1).done_reason;assert(reason==='stop'||(role==='formatter'&&reason==='length'));
    row.requestRole=role;row.terminationReason=reason;if(role==='formatter'){row.formatterComplete=reason==='stop';row.formatterOutcome=reason==='length'?'output-limit':'complete';}
    assert.ok(frames.every(frame => !frame.error && frame.model === MODEL && !frame.tool_calls && !frame.message?.tool_calls));
    if(row.kind==='generate')assert(frames.every(f=>typeof f.response==='string'));else assert(frames.every(f=>f.message&&typeof f.message.content==='string'));
    assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);
  }
}
function validateTimedResponse(row, deadline, now = () => performance.now()) {
  assert.ok(now() < deadline, 'Absolute wire deadline');
  validateResponse(row);
  assert.ok(now() < deadline, 'Absolute wire deadline after parsing');
}
async function closeOwned(resources, servers, timeoutMs = 5000) {
  const waiting = resources.map(resource => new Promise(resolve => resource.once('close', resolve)));
  for (const resource of resources) resource.destroy();
  waiting.push(...servers.map(server => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
  let timer; try {
    await Promise.race([Promise.all(waiting), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Physical close deadline')), timeoutMs); })]);
  } finally { clearTimeout(timer); }
}
function assertDispatchDeadline(deadline,now=()=>performance.now()){assert(now()<deadline,'Absolute deadline before upstream dispatch');}
function serializedBytes(value){
 if(value===null||typeof value!=='object')return Buffer.byteLength(JSON.stringify(value));
 if(Array.isArray(value))return 2+Math.max(0,value.length-1)+value.reduce((n,x)=>n+serializedBytes(x),0);
 const entries=Object.entries(value);return 2+Math.max(0,entries.length-1)+entries.reduce((n,[k,v])=>n+Buffer.byteLength(JSON.stringify(k))+1+serializedBytes(v),0);
}
function saveWire(file,value){const next=serializedBytes(value)+1,old=fs.existsSync(file)?fs.statSync(file).size:0;assert(old+next<=64*1024*1024,'Aggregate wire and atomic temporary ceiling');saveBounded(file,value);}
function admissionDiagnostic({index,caseId,method,url,body}) {
 assert(Buffer.isBuffer(body));assert(body.length<=262144);
 return {index,caseId,method:String(method).slice(0,16),path:String(url).slice(0,256),requestBytes:body.length,requestSha256:sha(body),request:body.toString('utf8'),stage:'request-validation',outcome:'pending'};
}
async function createTransport({ evidence, profile='current' }) {
  const profileLimits=profileFor(profile);
  const calls = [], ingress = [], failures = [], sockets = new Set(), upstreams = new Set(), servers = [];
  const limits = budget(profile); let closing = false, activeCase = null, caseDeadline = null, caseCounts = null; const overallDeadline = performance.now() + profileLimits.deadlineMs;
  function checkpoint() { saveWire(path.join(evidence, 'actual-model-wire.json'), { version: 'aria-nova-current-wire-v1', profile, model: MODEL, digest: DIGEST, counts: limits.counts, calls, ingress, failures, physicalPending: sockets.size + upstreams.size, closed: closing && !sockets.size && !upstreams.size }); }
  function forward(kind, method, pathname, body, downstream) {
    assert.equal(failures.length,0,'Previous transport failure');
    if(!['tags','version'].includes(kind)){assert(caseCounts);assert(caseCounts[kind] < (kind==='generate'?9:profileLimits.chats[profileLimits.cases.indexOf(activeCase)]));caseCounts[kind]++;}
    limits.reserve(kind); if(!['tags','version'].includes(kind)) assert.ok(activeCase && performance.now() < caseDeadline && performance.now() < overallDeadline, 'Case admission deadline');
    const row = { index: calls.length, kind, caseId: activeCase, method, path: pathname, requestBytes: body.length, requestSha256: sha(body), request: body.toString(), terminal: 'pending' };
    const deadline = Math.min(overallDeadline, ['tags','version'].includes(kind) ? performance.now()+5000 : Math.min(caseDeadline,performance.now()+90000));
    calls.push(row); checkpoint();
    return new Promise((resolve, reject) => {
      let timer, settled = false;
      const capture = createResponseCapture(row);
      const finish = (error) => { if (settled) return; settled = true; if (error) { row.terminal = 'incomplete'; failures.push({ index: row.index, code: 'WIRE_INCOMPLETE' }); } else row.terminal = 'returned'; checkpoint(); error ? reject(error) : resolve(row); };
      try { assertDispatchDeadline(deadline); } catch(error) { finish(error); return; }
      const upstream = upstreamContext.run(upstreamToken, () => http.request({ hostname: '127.0.0.1', port: 11434, path: pathname, method, headers: { 'content-type': 'application/json', 'content-length': body.length } }, response => {
        capture.headers(response.statusCode);
        downstream?.writeHead(response.statusCode, { 'content-type': response.headers['content-type'] || 'application/json' });
        response.on('data', chunk => { if (!capture.data(chunk)) { upstream.destroy(Error('Bounded response')); return; } downstream?.write(chunk); });
        response.on('end', () => { capture.finish(true, 'end'); try { validateTimedResponse(row, deadline); downstream?.end(); finish(); } catch (error) { upstream.destroy(error); downstream?.destroy(); finish(error); } });
        response.on('aborted', () => { capture.finish(false, 'aborted'); finish(Error('Aborted response')); });
        response.on('error', error => { capture.finish(false, 'error'); finish(error); });
      }));
      upstreams.add(upstream);
      timer = setTimeout(() => upstream.destroy(Error('Wire deadline')), Math.max(1,deadline-performance.now()));
      upstream.once('close', () => { clearTimeout(timer); upstreams.delete(upstream); capture.finish(false, 'closed'); if (!settled) finish(Error('Incomplete close')); });
      upstream.once('error', error => { capture.finish(false, 'error'); downstream?.destroy(); finish(error); });
      downstream?.once('close', () => { if (!downstream.writableFinished) upstream.destroy(Error('Consumer closed')); });
      upstream.end(body);
    });
  }
  async function listen(kind) {
    const server = http.createServer(async (req, res) => {
      let timer, diagnostic, stage='ingress'; try {
        limits.incoming(); assert.ok(!closing); stage='body-read'; timer = setTimeout(() => req.destroy(), 5000);
        const chunks = []; let bytes = 0;
        for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 262144); chunks.push(chunk); }
        clearTimeout(timer); const body = Buffer.concat(chunks);
        diagnostic=admissionDiagnostic({index:ingress.length,caseId:activeCase,method:req.method,url:req.url,body});ingress.push(diagnostic);stage='request-validation';checkpoint();
        const requested = validateRequest(req.method, req.url, body);
        stage='dispatch';diagnostic.stage=stage;checkpoint();
        await forward(requested, req.method, req.url, body, res);diagnostic.outcome='returned';checkpoint();
      } catch(error) { if(diagnostic){diagnostic.outcome='denied-or-incomplete';diagnostic.stage=stage;} failures.push({ code: 'REQUEST_DENIED_OR_INCOMPLETE',stage,ingressIndex:diagnostic?.index??null,errorCode:error?.code==='ERR_ASSERTION'?'ERR_ASSERTION':'REQUEST_ERROR' }); if (!res.headersSent) res.writeHead(503); res.end(); checkpoint(); }
      finally { clearTimeout(timer); }
    });
    server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
    servers.push(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    return `http://127.0.0.1:${server.address().port}`;
  }
  async function close() {
    closing = true;
    try {
      await closeOwned([...upstreams, ...sockets], servers);
      assert.equal(upstreams.size + sockets.size, 0);
    } finally { checkpoint(); }
  }

  try {
    await forward('tags', 'GET', '/api/tags', Buffer.alloc(0));
    const actorUrl = await listen('generate');
    const used = new Set();
    return { actorUrl, judgeUrl: actorUrl, close, beginCase(id) { assert.equal(activeCase,null); assert.equal(id,profileLimits.cases[used.size]); assert.ok(!used.has(id)); used.add(id); activeCase=id; caseCounts={generate:0,chat:0}; caseDeadline=Math.min(overallDeadline,performance.now()+120000); }, endCase(){ assert.ok(activeCase); assert.ok(performance.now()<caseDeadline); activeCase=null; caseDeadline=null; caseCounts=null; }, snapshot(){return {counts:{...limits.counts},calls:structuredClone(calls),failures:structuredClone(failures)};}, assertComplete() { assert.equal(failures.length, 0); assert.equal(activeCase,null); assert.equal(used.size,profileLimits.cases.length); for (const row of calls) validateResponse(row); } };
  } catch (error) { try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], 'Transport setup/cleanup failed'); } throw error; }
}
module.exports={classifyRequest,admissionDiagnostic,createTransport,allowsUpstream,validateRequest,validateResponse,validateTimedResponse,budget,assertDispatchDeadline,serializedBytes,closeOwned,MODEL,DIGEST};
