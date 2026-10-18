'use strict';
const assert=require('node:assert/strict'),http=require('node:http'),path=require('node:path'),fs=require('node:fs');
const {performance}=require('node:perf_hooks'),{AsyncLocalStorage}=require('node:async_hooks'),{createHash}=require('node:crypto');
const {saveBounded}=require('../fixtures/boundedJsonArtifact');
const {createResponseCapture}=require('./secureshopMailActualTransport');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha=x=>createHash('sha256').update(x).digest('hex');
const upstreamContext=new AsyncLocalStorage(),upstreamToken=Object.freeze({});
const allowsUpstream=()=>upstreamContext.getStore()===upstreamToken;
function budget(){const counts={external:0,incoming:0,metadata:0,generate:0,chat:0};return{counts,incoming(){assert(counts.incoming<20);counts.incoming++;},reserve(kind){assert(['metadata','generate','chat'].includes(kind));assert(counts.external<20);counts.external++;counts[kind]++;}};}
function validateRequest(method,url,body){
 if(method==='GET'&&url==='/api/tags'){assert.equal(body.length,0);return 'metadata';}
 assert.equal(method,'POST');assert(['/api/generate','/api/chat'].includes(url));assert(body.length>0&&body.length<=262144);const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));
 const keys=['model','stream','options','format',...(url==='/api/chat'?['messages','tools']:['prompt','system','template','raw','keep_alive'])];assert(Object.keys(v).every(k=>keys.includes(k)));assert(v.options&&typeof v.options==='object'&&!Array.isArray(v.options));const o=v.options;assert(Object.keys(o).every(k=>['temperature','num_predict','num_ctx','top_p','top_k','stop'].includes(k)));assert(Number.isFinite(o.temperature)&&o.temperature>=0&&o.temperature<=0.7);assert(Number.isInteger(o.num_predict)&&o.num_predict>0&&o.num_predict<=1000);if(o.num_ctx!==undefined)assert(Number.isInteger(o.num_ctx)&&o.num_ctx>0&&o.num_ctx<=32768);if(o.top_p!==undefined)assert(Number.isFinite(o.top_p)&&o.top_p>=0&&o.top_p<=1);if(o.top_k!==undefined)assert(Number.isInteger(o.top_k)&&o.top_k>=0&&o.top_k<=100);if(o.stop!==undefined)assert(Array.isArray(o.stop)&&o.stop.length<=8&&o.stop.every(x=>typeof x==='string'&&Buffer.byteLength(x)<=128));
 if(url==='/api/chat')assert(Array.isArray(v.messages)&&v.messages.length);else assert.equal(typeof v.prompt,'string');
 return url==='/api/chat'?'chat':'generate';
}
function validateResponse(row) {
  assert.equal(row.status, 200); assert.equal(row.responseComplete, true); assert.equal(row.responseCaptureTruncated, false);
  if (row.kind === 'metadata') {
    assert.ok(JSON.parse(row.response).models?.some(value => (value.name === MODEL || value.model === MODEL) && value.digest === DIGEST));
  } else {
    const frames = row.response.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(frames.length); assert.equal(frames.at(-1).done, true); assert.equal(frames.at(-1).done_reason, 'stop');
    assert.ok(frames.every(frame => !frame.error && frame.model === MODEL));
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
function saveWire(file,value){const next=serializedBytes(value)+1,old=fs.existsSync(file)?fs.statSync(file).size:0;assert(old+next<=126*1024*1024,'Aggregate wire and atomic temporary ceiling');saveBounded(file,value);}
async function createTransport({ evidence }) {
  const calls = [], failures = [], sockets = new Set(), upstreams = new Set(), servers = [];
  const limits = budget(); let closing = false, activeCase = null, caseDeadline = null; const overallDeadline = performance.now() + 480000;
  function checkpoint() { saveWire(path.join(evidence, 'actual-model-wire.json'), { version: 'ctf-stage9-actual-wire-v1', model: MODEL, digest: DIGEST, counts: limits.counts, calls, failures, physicalPending: sockets.size + upstreams.size, closed: closing && !sockets.size && !upstreams.size }); }
  function forward(kind, method, pathname, body, downstream) {
    limits.reserve(kind); if(kind !== 'metadata') assert.ok(activeCase && performance.now() < caseDeadline && performance.now() < overallDeadline, 'Case admission deadline');
    const row = { index: calls.length, kind, caseId: activeCase, method, path: pathname, requestBytes: body.length, requestSha256: sha(body), request: body.toString(), terminal: 'pending' };
    const deadline = Math.min(overallDeadline, kind === 'metadata' ? performance.now()+5000 : Math.min(caseDeadline,performance.now()+120000));
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
      let timer; try {
        limits.incoming(); assert.ok(!closing); timer = setTimeout(() => req.destroy(), 5000);
        const chunks = []; let bytes = 0;
        for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 262144); chunks.push(chunk); }
        clearTimeout(timer); const body = Buffer.concat(chunks);
        const requested = validateRequest(req.method, req.url, body);
        await forward(requested, req.method, req.url, body, res);
      } catch { failures.push({ code: 'REQUEST_DENIED_OR_INCOMPLETE' }); if (!res.headersSent) res.writeHead(503); res.end(); checkpoint(); }
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
    await forward('metadata', 'GET', '/api/tags', Buffer.alloc(0));
    const actorUrl = await listen('generate');
    const used = new Set();
    return { actorUrl, judgeUrl: actorUrl, close, beginCase(id) { assert.equal(activeCase,null); assert.ok(['benign','instructor-candidate'].includes(id)&&!used.has(id)); used.add(id); activeCase=id; caseDeadline=Math.min(overallDeadline,performance.now()+240000); }, endCase(){ assert.ok(activeCase); assert.ok(performance.now()<caseDeadline); activeCase=null; caseDeadline=null; }, snapshot(){return {counts:{...limits.counts},calls:structuredClone(calls),failures:structuredClone(failures)};}, assertComplete() { assert.equal(failures.length, 0); assert.equal(activeCase,null); assert.equal(used.size,2); for (const row of calls) validateResponse(row); } };
  } catch (error) { try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], 'Transport setup/cleanup failed'); } throw error; }
}
module.exports={createTransport,allowsUpstream,validateRequest,validateResponse,validateTimedResponse,budget,assertDispatchDeadline,serializedBytes,closeOwned,MODEL,DIGEST};
