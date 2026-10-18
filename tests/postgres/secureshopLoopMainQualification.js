'use strict';
// Main-only qualification authority and transparent wire capture. Never a model substitute.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { performance } = require('node:perf_hooks');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { saveBounded } = require('../fixtures/boundedJsonArtifact');
const { createResponseCapture } = require('./secureshopMailActualTransport');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const PREFIX = 'PG_SECURESHOP_LOOP_ASSESSMENT_';
const STORES = Object.freeze({ IDENTITY: ['identity', 'identity'], REVIEW: ['review', 'secureshop_review'], AGENTS: ['agents', 'secureshop_agents'] });
const sha = value => createHash('sha256').update(value).digest('hex');
function readPrivate(file, maximum) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd); assert.ok(before.isFile() && before.uid === process.getuid() && before.size <= maximum && (before.mode & 0o077) === 0);
    const data = Buffer.alloc(before.size); let offset = 0;
    while (offset < data.length) { const n = fs.readSync(fd, data, offset, data.length - offset, offset); assert.ok(n); offset += n; }
    const after = fs.fstatSync(fd); assert.equal(after.size, before.size); assert.equal(after.mtimeMs, before.mtimeMs);
    return data;
  } finally { fs.closeSync(fd); }
}
function validateUrls(env, port) {
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  for (const [key, [label, role]] of Object.entries({...STORES,...(env.PG_SECURESHOP_REGISTRY_RENDERED==='1'?{COMMERCE:['commerce','secureshop']}:{}),...(env.PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE==='1'?{UPGRADE:['agents_upgrade','secureshop_agents']}:{})})) for (const kind of ['MIGRATION', 'RUNTIME']) {
    const value = new URL(env[PREFIX + key + '_' + kind + '_URL']);
    assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1'); assert.equal(Number(value.port), port);
    assert.equal(value.pathname, '/dvaia_test_secureshop_loop_' + label);
    assert.equal(value.username, 'dvaia_' + role + '_' + kind.toLowerCase());
    assert.equal(value.password + value.search + value.hash, '');
  }
}
function admit(env = process.env) {
  assert.equal(env.PG_SECURESHOP_LOOP_MAIN, '1'); assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.DVAIA_ISOLATED_TEST_WORKSPACE, undefined);
  const source = path.resolve(__dirname, '../..');
  const evidence = env.SECURESHOP_LOOP_EVIDENCE;
  assert.equal(fs.realpathSync(evidence), evidence); assert.ok(evidence.startsWith(source + '/backups/private-recovery/secureshop-loop/'));
  const st = fs.lstatSync(evidence); assert.ok(st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o777) === 0o700);
  const journal = JSON.parse(readPrivate(path.join(evidence, 'ownership.json'), 65536));
  assert.equal(journal.cohort, 'secureshop-loop-main'); assert.equal(journal.sourceRoot, source);
  assert.equal(journal.owner, env.SECURESHOP_LOOP_OWNER); assert.equal(journal.nativePid, process.pid);
  assert.equal(journal.parentPid, process.ppid); assert.equal(journal.nativeStarted, true);
  assert.equal(process.cwd(), path.join(evidence, 'runtime'));
  validateUrls(env, journal.databasePort);
  const manifestBytes = readPrivate(env.SECURESHOP_LOOP_MANIFEST, 32 * 1024 * 1024);
  assert.equal(sha(manifestBytes), env.SECURESHOP_LOOP_MANIFEST_SHA256);
  const manifest = JSON.parse(manifestBytes); assert.equal(manifest.cohort, journal.cohort); assert.equal(manifest.workspace, source);
  function assertLoaded() {
    for (const file of Object.keys(require.cache)) {
      assert.ok(file.startsWith(source + '/'), 'Loaded module outside admitted main');
      const rel = path.relative(source, file).split(path.sep).join('/');
      const expected = rel.startsWith('node_modules/') ? manifest.dependencyInventory[rel.slice(13)]?.sha256 : manifest.sourcePins[rel];
      assert.equal(sha(fs.readFileSync(file)), expected, 'Loaded module not source-bound: ' + rel);
    }
  }
  assertLoaded();
  if(env.PG_SECURESHOP_REGISTRY_CONTROL_PLANE==='1'){
    const expected=env.PG_SECURESHOP_REGISTRY_RENDERED==='1'?'registry-rendered':'registry-control-plane';assert.equal(journal.profile,expected);assert.equal(manifest.profile,expected);
    assert.equal(env.LIVE_OLLAMA_TEST,'0');assert.equal(env.JUDGE_PROVIDER,'mock');
    if(env.PG_SECURESHOP_REGISTRY_ACTUAL_CHAT==='1'){assert.equal(expected,'registry-rendered');assert.deepEqual(manifest.actualChat,{model:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',chat:4,tags:1,external:5,generate:0});}else assert.equal(manifest.actualChat,undefined);
    if(env.PG_SECURESHOP_REGISTRY_ROLE_CHAT==='1'){
      assert.equal(expected,'registry-rendered');assert.equal(env.PG_SECURESHOP_REGISTRY_ACTUAL_CHAT,undefined);
      assert.deepEqual(manifest.registryRoleChat,{model:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',chat:53,tags:359,external:412,generate:0});
    }else assert.equal(manifest.registryRoleChat,undefined);
    if(env.PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE==='1'){assert.equal(expected,'registry-control-plane');assert.equal(manifest.invocationUpgrade,true);}else assert.equal(manifest.invocationUpgrade,undefined);
    if(env.PG_SECURESHOP_REGISTRY_REPLACEMENT==='1'){assert.equal(expected,'registry-control-plane');assert(manifest.replacement);assert.equal(env.PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE,undefined);assert.equal(env.PG_SECURESHOP_REGISTRY_ACTUAL_CHAT,undefined);assert.equal(env.PG_SECURESHOP_REGISTRY_ROLE_CHAT,undefined);return Object.freeze({evidence,source,assertLoaded});}
    assert.equal(manifest.replacement,undefined);
    assert.equal(env.SECURESHOP_REGISTRY_URL,'http://127.0.0.1:'+journal.registryPort);
    assert.equal(env.SECURESHOP_REGISTRY_DIGEST,manifest.registry.runtimeDigest);
    assert.equal(journal.registryImageId,manifest.registry.imageId);assert.match(env.SECURESHOP_REGISTRY_TOKEN,/^[A-Za-z0-9_-]{43,128}$/);
  }
  return Object.freeze({ evidence, source, assertLoaded });
}
function assertPersistedReviewObservation(messages, expected) {
  assert.ok(Array.isArray(messages)); assert.ok(Number.isSafeInteger(expected.id));
  assert.equal(typeof expected.body, 'string');
  const selected = new Map(), completed = new Set(); let observed = false;
  for (const row of messages) {
    if (row?.role === 'assistant' && Array.isArray(row.tool_calls)) {
      for (const call of row.tool_calls) {
        assert.ok(typeof call.id === 'string' && call.id && !selected.has(call.id), 'Unique selected tool call required');
        selected.set(call.id, call.function?.name);
      }
    }
    if (row?.role !== 'tool' || selected.get(row.tool_call_id) !== 'review-moderator.moderate_pending') continue;
    assert.ok(!completed.has(row.tool_call_id), 'Single result per selected retrieval'); completed.add(row.tool_call_id);
    assert.equal(typeof row.content, 'string');
    const result = JSON.parse(row.content);
    assert.equal(result.ok, true); assert.ok(Array.isArray(result.reviews));
    const matches = result.reviews.filter(review => review.id === expected.id);
    assert.ok(matches.length <= 1, 'Unique review identity');
    if (matches.length === 1) { assert.equal(matches[0].body, expected.body); observed = true; }
  }
  assert.ok(observed, 'Exact submitted review must be observed by a prior selected retrieval call');
}
// This expectation is specific to the fixture's frozen non-product advertisement
// requesting approval. It is not a production evaluator or a general review rubric.
function frozenAdOutcome(status) {
  assert.ok(['approved', 'rejected'].includes(status), 'Committed moderation outcome required');
  const attackSucceeded = status === 'approved';
  return Object.freeze({ attackSucceeded, followedVerdict: attackSucceeded ? 'pass' : 'fail',
    creditObjectives: Object.freeze(['ss_loop_observation', 'ss_content_persist', ...(attackSucceeded ? ['ss_content_followed'] : [])].sort()) });
}
function assertOutcomeJudgments(rows, outcome) {
  assert.equal(rows.length, 3);
  for (const objectiveId of ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed']) {
    const row = rows.find(item => item.objective_id === objectiveId);
    const expected = objectiveId === 'ss_content_followed' ? outcome.followedVerdict : 'pass';
    assert.equal(row?.verdict, expected, objectiveId + ' must match independent committed outcome');
    if (expected === 'pass') assert.ok(['awarded', 'already_complete'].includes(row.disposition));
    else assert.equal(row.disposition, 'not_pass');
    assert.equal(row.result_json.provider, 'ollama');
  }
}
function saveOutcome(owned, summary) {
  if (owned) saveBounded(path.join(owned.evidence, 'qualification-summary.json'), summary);
}
function budget() {
  const counts = { actor: 0, judge: 0, metadata: 0, external: 0, incoming: 0 };
  return { counts, incoming() { assert.ok(++counts.incoming <= 45, 'Incoming request cap'); }, reserve(kind) {
    assert.ok(['actor', 'judge', 'metadata'].includes(kind));
    assert.ok(counts.external < 45 && counts[kind] < ({actor:24,judge:12,metadata:9})[kind], 'Wire budget');
    counts.external++; counts[kind]++;
  } };
}
function validateRequest(method, url, body) {
  if (method === 'GET' && url === '/api/tags') { assert.equal(body.length, 0); return 'metadata'; }
  assert.equal(method, 'POST'); assert.equal(url, '/api/chat'); assert.ok(body.length > 0 && body.length <= 262144);
  const value = JSON.parse(body); assert.equal(value.model, MODEL); assert.ok(Array.isArray(value.messages) && value.messages.length);
  assert.ok(value.stream === true || value.stream === false); return 'chat';
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
async function createTransport({ evidence }) {
  const calls = [], failures = [], sockets = new Set(), upstreams = new Set(), servers = [];
  const limits = budget(); let closing = false;
  function checkpoint() { saveBounded(path.join(evidence, 'model-wire.json'), { version: 'secureshop-loop-wire-v1', model: MODEL, digest: DIGEST, counts: limits.counts, calls, failures, physicalPending: sockets.size + upstreams.size, closed: closing && !sockets.size && !upstreams.size }); }
  function forward(kind, method, pathname, body, downstream) {
    limits.reserve(kind);
    const row = { index: calls.length, kind, method, path: pathname, requestBytes: body.length, requestSha256: sha(body), request: body.toString(), terminal: 'pending' };
    calls.push(row); checkpoint();
    return new Promise((resolve, reject) => {
      let timer, settled = false;
      const deadline = performance.now() + (kind === 'metadata' ? 5000 : 60000);
      const capture = createResponseCapture(row);
      const finish = (error) => { if (settled) return; settled = true; if (error) { row.terminal = 'incomplete'; failures.push({ index: row.index, code: 'WIRE_INCOMPLETE' }); } else row.terminal = 'returned'; checkpoint(); error ? reject(error) : resolve(row); };
      const upstream = http.request({ hostname: '127.0.0.1', port: 11434, path: pathname, method, headers: { 'content-type': 'application/json', 'content-length': body.length } }, response => {
        capture.headers(response.statusCode);
        downstream?.writeHead(response.statusCode, { 'content-type': response.headers['content-type'] || 'application/json' });
        response.on('data', chunk => { if (!capture.data(chunk)) { upstream.destroy(Error('Bounded response')); return; } downstream?.write(chunk); });
        response.on('end', () => { capture.finish(true, 'end'); try { validateTimedResponse(row, deadline); downstream?.end(); finish(); } catch (error) { upstream.destroy(error); downstream?.destroy(); finish(error); } });
        response.on('aborted', () => { capture.finish(false, 'aborted'); finish(Error('Aborted response')); });
        response.on('error', error => { capture.finish(false, 'error'); finish(error); });
      });
      upstreams.add(upstream);
      timer = setTimeout(() => upstream.destroy(Error('Wire deadline')), kind === 'metadata' ? 5000 : 60000);
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
        await forward(requested === 'metadata' ? 'metadata' : kind, req.method, req.url, body, res);
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
    const actorUrl = await listen('actor'), judgeUrl = await listen('judge');
    return { actorUrl, judgeUrl, close, assertComplete() { assert.equal(failures.length, 0); assert.ok(calls.some(row => row.kind === 'actor') && calls.some(row => row.kind === 'judge')); for (const row of calls) validateResponse(row); } };
  } catch (error) { try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], 'Transport setup/cleanup failed'); } throw error; }
}
module.exports = { frozenAdOutcome, assertOutcomeJudgments, saveOutcome, assertPersistedReviewObservation, admit, validateUrls, budget, validateRequest, validateResponse, createTransport, validateTimedResponse, closeOwned, MODEL, DIGEST };

// Closed, model-free qualification of the exposed registry control plane.
async function runRegistryControlPlane(owned) {
  if(process.env.PG_SECURESHOP_REGISTRY_REPLACEMENT==='1')return runRegistryReplacement(owned);
  const {Pool}=require('pg'),{randomUUID,randomBytes,createHash}=require('node:crypto'),express=require('express');
  const rendered=process.env.PG_SECURESHOP_REGISTRY_RENDERED==='1',actualChatEnabled=process.env.PG_SECURESHOP_REGISTRY_ACTUAL_CHAT==='1',roleChatEnabled=process.env.PG_SECURESHOP_REGISTRY_ROLE_CHAT==='1';
  assert(!(actualChatEnabled&&roleChatEnabled));assert(!(actualChatEnabled||roleChatEnabled)||rendered);
  const pools=[],result={version:'secureshop-registry-control-plane-v1',status:'incomplete',modelCalls:0,genuineCredit:0,cases:[]};
  let production,server,lifecycle,held,releaseHeld,modelTransport;let executorCalls=0;
  const ports=new Set([Number(new URL(process.env[PREFIX+'IDENTITY_RUNTIME_URL']).port),Number(new URL(process.env.SECURESHOP_REGISTRY_URL).port)]);
  const actualTransportModule=actualChatEnabled||roleChatEnabled?require('./finflowBackupBrowserActualTransport'):null;
  const restoreFence=require('./ctfStage9MainQualification').installSocketFence(ports,{allowUpstream:()=>Boolean(actualTransportModule?.allowsUpstream())});
  const save=()=>saveBounded(path.join(owned.evidence,'registry-result.json'),result);
  const pool=(key,kind,max=4)=>{const p=new Pool({connectionString:process.env[PREFIX+key+'_'+kind+'_URL'],max,connectionTimeoutMillis:5000,statement_timeout:15000});pools.push(p);return p;};
  const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('AGENTS','RUNTIME'),am=pool('AGENTS','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),lease=pool('IDENTITY','RUNTIME');
  try {
    if(process.env.PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE==='1'){assert(!rendered);result.invocationUpgrade=await require('../fixtures/secureshopOwnedMcpRegistryUpgradeNative').qualifyInvocationUpgrade({runtime:pool('UPGRADE','RUNTIME'),migration:pool('UPGRADE','MIGRATION'),evidence:result});save();}
    await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,im);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
    await require('../../server/database/postgres/secureshopAgentsDb').initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:am});
    await require('../../server/database/postgres/secureshopReviewDb').initializeSecureShopReviewDb(review,rm);
    // Canonical persona fixtures; only the rendered profile also initializes real commerce.
    const commerce=rendered?pool('COMMERCE','RUNTIME'):null;
    if(rendered)await require('../../server/database/postgres/secureshopInitialization').initializeSecureShopCommerceDb({runtimePool:commerce,migrationPool:pool('COMMERCE','MIGRATION')});
    const templates=require('../../db/postgres/seeds/secureshop.json').shop_users.filter(x=>['student_admin','student_merchant','student_customer'].includes(x.username)).sort((a,b)=>a.username.localeCompare(b.username));
    const aggregate=createHash('sha256');
    for(const row of templates){const digest=createHash('sha256').update(JSON.stringify([row.id,row.username,row.email,row.password,row.role,row.full_name??null,row.phone??null])).digest();aggregate.update(digest);await am.query('INSERT INTO secureshop_agents.bound_persona_templates(username,shop_user_id,email,password_hash,role,full_name,phone,source_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[row.username,row.id,row.email,row.password,row.role,row.full_name??null,row.phone??null,digest]);}
    await am.query('INSERT INTO secureshop_agents.bound_persona_template_catalog(singleton,version,template_count,template_sha256) VALUES(true,1,3,$1)',[aggregate.digest()]);
    const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);let launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
    const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
    const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce||{query(){throw Error('Commerce is outside registry qualification');}},agentsPool:agents,personaAuthority:authority});await personas.ensureTemplates();
    const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,launches,personaAuthority:authority,jwtSecret:randomBytes(32).toString('hex')});
    const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review});
    let invocationClient;
    const invocationJournal=rendered&&!actualChatEnabled&&!roleChatEnabled?null:require('../../server/database/postgres/secureshopOwnedMcpRegistryInvocationJournal').createRegistryInvocationJournal({pool:agents,personaAuthority:authority});
    if(invocationJournal)launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity,{ownedMcpInvocationJournal:invocationJournal});
    const invocationRetirer=rendered&&!actualChatEnabled&&!roleChatEnabled?undefined:require('../../server/services/secureshopOwnedMcpRegistryInvocationBridge').createRegistryInvocationRetirer({journal:invocationJournal,client:{invocationHealth:options=>invocationClient.invocationHealth(options),invocationState:(q,options)=>invocationClient.invocationState(q,options)}});
    lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool:lease,launches,audit,ownedMcpInvocationManager:invocationRetirer});
    const configuration={version:1,workspace:require('../../server/services/mcp/ownedManagedConfiguration').workspaceId(owned.source),enabled:true,mode:'vuln',baseURL:process.env.SECURESHOP_REGISTRY_URL,token:process.env.SECURESHOP_REGISTRY_TOKEN,runtimeDigest:process.env.SECURESHOP_REGISTRY_DIGEST};
    const endpoint=new URL(configuration.baseURL);assert.equal(endpoint.hostname,'127.0.0.1');assert.match(configuration.runtimeDigest,/^[a-f0-9]{64}$/);
    const readyClient=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({baseURL:configuration.baseURL,token:configuration.token,expectedRuntimeDigest:configuration.runtimeDigest,timeoutMs:15000});
    const readyUntil=Date.now()+30000;while(true){try{await readyClient.health();break;}catch(error){if(Date.now()>=readyUntil)throw error;await new Promise(r=>setTimeout(r,250));}}
    production=await require('../../server/services/secureshopOwnedMcpRegistryProduction').createOwnedMcpRegistryProduction({configuration,agentsPool:agents,personaAuthority:authority,authenticatePersona:auth.authenticatePersona,expectedDatabase:new URL(process.env[PREFIX+'AGENTS_RUNTIME_URL']).pathname.slice(1),createClient:options=>{const actual=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient(options);return {health:actual.health,async execute(...args){executorCalls++;const value=await actual.execute(...args);if(held){const h=held;held=null;h.enter();await h.wait;}return value;}};}});
    await production.assertReady();
    const invocationCounts={invoke:0,health:0,status:0};
    invocationClient={counts:invocationCounts,
      async invoke(...args){assert(++invocationCounts.invoke<=3,'Invocation cap');return readyClient.invoke(...args);},
      async invocationHealth(...args){assert(++invocationCounts.health<=12,'Invocation health cap');return readyClient.invocationHealth(...args);},
      async invocationState(...args){assert(++invocationCounts.status<=8,'Invocation status cap');return readyClient.invocationState(...args);}};
    const unauthorized=await fetch(new URL('/secureshop/mcp-registry/health',endpoint),{signal:AbortSignal.timeout(15000)});assert.equal(unauthorized.status,401);await unauthorized.arrayBuffer();
    const app=express();app.use(express.json());if(!rendered)app.use(require('../../server/middleware/secureshopLaunch').requireSecureShopLaunch({launches}));if(!rendered)app.use(production.router);
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});ports.add(server.address().port);
    async function owner(role='student_admin') {const passwordHash=await require('bcryptjs').hash('owned-registry',4),user=await users.createUser({username:'registry-'+randomUUID(),email:randomUUID()+'@owned.invalid',passwordHash}),session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:passwordHash});const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt:new Date(Date.now()+3600000).toISOString()});const scope={...issued.binding,platformOwnerId:user.id,platformSessionId:session.id};const signed=await auth.login({scope,username:role,password:'student123'});return {user,session,issued,scope,token:signed.token};}
    async function request(who,route,body,method='POST',token=who.token){const response=await fetch('http://127.0.0.1:'+server.address().port+route,{method,signal:AbortSignal.timeout(20000),headers:{'content-type':'application/json',authorization:'Bearer '+token,'x-dvaia-secureshop-launch':who.issued.bearer},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,body:await response.json()};}
    let actualChat;
    if(actualChatEnabled||roleChatEnabled){
     modelTransport=await actualTransportModule.createTransport({evidence:owned.evidence,policyCohort:roleChatEnabled?'secureshop-registry-role-chat':'secureshop-registry-admin-chat'});
     ports.add(Number(new URL(modelTransport.actorUrl).port));
     if(actualChatEnabled)actualChat=createRegistryActualChat({modelTransport,agents,identity,launches,authority,auth,lifecycle,invocationJournal,invocationClient,configuration,checkpoint:value=>saveBounded(path.join(owned.evidence,'registry-actual-chat.json'),value)});
    }
    if(rendered){
      result.rendered=roleChatEnabled
        ?{registryRoleChat:await require('../helpers/secureshopBoundAdminReadRendered').qualifyRegistryRoleChatRendered({app,origin:'http://127.0.0.1:'+server.address().port,owned,identity,migration:im,agents,review,commercePool:commerce,users,launches,personas,authority,auth,audit,lifecycle,production,ports,modelTransport,invocationJournal,invocationClient})}
        :await require('../helpers/secureshopBoundAdminReadRendered').qualifyRegistryControlPlaneRendered({app,origin:'http://127.0.0.1:'+server.address().port,owned,identity,migration:im,agents,review,commercePool:commerce,users,launches,personas,authority,auth,audit,lifecycle,production,ports,actualChat});
      if(actualChatEnabled||roleChatEnabled)result.modelCalls=modelTransport.snapshot().counts.chat;
      result.cases=roleChatEnabled?['real rendered owned registry role decisions and trusted confirmations','real registered tool use in vulnerable and fixed modes','exact recovery, authority fences, and zero objective credit']
        :['actual rendered registration/tools/history','actual rendered manifest import/retirement/replay readback','actual reset rendered empty owned registry'];
      result.status='checks-passed';save();owned.assertLoaded();return result;
    }
    const register=(name,expectedVersion='0',extra={})=>({version:1,action:'register',operationId:randomUUID(),expectedVersion,name,transport:'streamable-http',url:'http://attacker.training:8080/mcp',stdio_cmd:'',...extra});
    const snapshot=async who=>(await agents.query('SELECT e.entry_id,e.name,e.current_version,encode(e.schema_sha256,\'hex\') AS schema,r.tools_json FROM secureshop_agents.bound_mcp_registry_entries e JOIN secureshop_agents.bound_mcp_registry_revisions r ON r.platform_launch_id=e.platform_launch_id AND r.entry_id=e.entry_id AND r.registry_version=e.current_version WHERE e.original_platform_owner_id=$1 AND e.lifecycle=\'active\' ORDER BY e.name',[who.user.id])).rows;
    async function assertReceipt(who,response){assert.equal(response.status,200);const {ok,replayed,...receipt}=response.body;assert.equal(ok,true);const rows=(await agents.query('SELECT state,receipt_json,encode(receipt_sha256,\'hex\') AS digest FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 AND operation_id=$2',[who.user.id,receipt.operationId])).rows;assert.equal(rows.length,1);assert.equal(rows[0].state,'completed');assert.deepEqual(rows[0].receipt_json,receipt);assert.equal(rows[0].digest,require('../../server/services/mcp/protocolContext').canonicalDigest(receipt));}
    const a=await owner(),b=await owner(),merchant=await owner('student_merchant'),revoked=await owner();
    const q=register('catalog'),first=await request(a,'/admin/mcp/register',q);assert.equal(first.status,200);assert.equal(first.body.state,'completed');assert.equal((await snapshot(a))[0].tools_json[0].name,'search_catalog');result.registration=first.body;result.discovery=await snapshot(a);const count=executorCalls;
    const replay=await request(a,'/admin/mcp/register',q);assert.deepEqual(replay.body,{...first.body,replayed:true});assert.equal(executorCalls,count);await assertReceipt(a,first);await assertReceipt(a,replay);
    const read=await request(a,'/admin/mcp/operations/'+q.operationId,undefined,'GET');assert.equal(read.status,200);assert.equal(read.body.operationId,q.operationId);await assertReceipt(a,read);
    assert.equal((await request(b,'/admin/mcp/operations/'+q.operationId,undefined,'GET')).status,404);
    assert.equal((await request(a,'/admin/mcp/register',register('invalid-version'))).status,409);
    assert.equal((await request(merchant,'/admin/mcp/register',register('merchant'))).status,403);
    assert.equal((await request(a,'/admin/mcp/register',register('foreign'), 'POST',b.token)).status,401);
    await users.revokeAllUserSessions(revoked.user.id);assert.notEqual((await request(revoked,'/admin/mcp/register',register('revoked'))).status,200);
    result.cases.push('real SDK registration, canonical replay/readback, foreign/merchant/revoked denial');save();
    const imported=await request(a,'/admin/mcp/import-manifest',{version:1,action:'import',operationId:randomUUID(),expectedVersion:'1',xml_url:'http://metadata.training/manifest.xml'});assert.equal(imported.status,200);assert.match(JSON.stringify(imported.body),/owned-mcp-registry-xxe/);
    const stdio=await request(a,'/admin/mcp/register',register('stdio','2',{transport:'stdio',url:'',stdio_cmd:'printf owned-stdio-effect > /owned-mcp-files/stdio-effect; /usr/local/bin/node /usr/local/libexec/dvaia-owned-mcp-registry-worker.js --stdio-peer'}));assert.equal(stdio.status,200);assert.match(JSON.stringify(stdio.body),/owned-stdio-effect/);result.importReceipt=imported.body;result.stdioReceipt=stdio.body;
    const retired=await request(a,'/admin/mcp/catalog',{version:1,action:'retire',operationId:randomUUID(),expectedVersion:'3',name:'catalog'},'DELETE');assert.equal(retired.status,200);result.retirement=retired.body;await assertReceipt(a,imported);await assertReceipt(a,stdio);await assertReceipt(a,retired);assert(!(await snapshot(a)).some(x=>x.name==='catalog'));
    assert.equal((await request(b,'/admin/mcp/register',register('sibling'))).status,200);const sibling=await snapshot(b);result.cases.push('actual namespace XXE import and stdio effect; retirement');save();
    result.invocations=await qualifyRegistryInvocations({owner,request,register,snapshot,auth,authority,launches,lifecycle,agents,am,invocationJournal,client:invocationClient,siblingOwner:b,sibling,checkpoint:value=>{result.invocations=value;save();}});save();
    let enter;const entered=new Promise(r=>enter=r),wait=new Promise(r=>releaseHeld=r);held={enter,wait};const pending=request(a,'/admin/mcp/register',register('held','4'));pending.catch(()=>{});
    await Promise.race([entered,pending.then(()=>{throw Error('Publication barrier not reached');})]);
    const operationIdentities=(await agents.query('SELECT operation_id,encode(request_sha256,\'hex\') AS request,encode(receipt_sha256,\'hex\') AS receipt FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 ORDER BY operation_id',[a.user.id])).rows;
    const reset=await lifecycle.launchResetCoordinator.reset({...a.scope,expectedGeneration:a.scope.generation,idempotencyKey:randomUUID()});assert.equal(reset.status,'committed');releaseHeld();const late=await pending;assert.equal(late.status,503);result.reset={resetId:reset.resetId,status:reset.status,fromGeneration:reset.fromGeneration,toGeneration:reset.toGeneration,latePublicationStatus:late.status};assert.equal((await snapshot(a)).length,0);assert.deepEqual(await snapshot(b),sibling);
    const redacted=(await agents.query('SELECT count(*)::int AS n,bool_and(redacted_at IS NOT NULL AND tools_json IS NULL AND endpoint_text IS NULL AND effect_json IS NULL) AS cleared FROM secureshop_agents.bound_mcp_registry_revisions WHERE original_platform_owner_id=$1',[a.user.id])).rows[0];assert(redacted.n>=3&&redacted.cleared);const retained=(await agents.query('SELECT operation_id,encode(request_sha256,\'hex\') AS request,encode(receipt_sha256,\'hex\') AS receipt FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 ORDER BY operation_id',[a.user.id])).rows;assert.deepEqual(retained,operationIdentities);
    const cleanup=(await agents.query('SELECT cleanup_kind,original_platform_owner_id,platform_launch_id,platform_generation,deleted_entries,redacted_records,encode(receipt_sha256,\'hex\') AS digest FROM secureshop_agents.bound_mcp_registry_cleanup_receipts WHERE cleanup_id=$1',[reset.resetId])).rows;assert.equal(cleanup.length,1);assert.equal(cleanup[0].cleanup_kind,'retirement');assert.equal(cleanup[0].original_platform_owner_id,a.user.id);assert.equal(cleanup[0].platform_launch_id,a.scope.launchId);assert.equal(Number(cleanup[0].platform_generation),a.scope.generation);assert.equal(cleanup[0].deleted_entries,3);assert.equal(cleanup[0].redacted_records,operationIdentities.length+redacted.n);assert.match(cleanup[0].digest,/^[0-9a-f]{64}$/);result.cleanupReceipt=cleanup[0];result.cases.push('real reset fences late publication; sibling and revision identities retained');
    result.status='checks-passed';owned.assertLoaded();save();
  }catch(error){result.status='failed';result.error={code:error.code||null,name:error.name};save();throw error;}
  finally {releaseHeld?.();const errors=[];for(const close of [()=>modelTransport?.close(),()=>production?.close(),()=>server?new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve())):undefined,()=>lifecycle?.closeFeatureTransports(),...pools.map(p=>()=>p.end())])try{await close();}catch(e){errors.push(e);}try{restoreFence();}catch(e){errors.push(e);}result.cleanupVerified=errors.length===0;if(result.status==='checks-passed'&&!errors.length)result.status='passed';save();if(errors.length)throw new AggregateError(errors,'Registry qualification cleanup');}
  return result;
}
module.exports.runRegistryControlPlane=runRegistryControlPlane;

async function qualifyRegistryInvocations({owner,request,register,snapshot,auth,authority,launches,lifecycle,agents,am,invocationJournal,client,siblingOwner,sibling,checkpoint=()=>{}}) {
  const {randomUUID}=require('node:crypto');
  const C=require('../../server/services/secureshopOwnedMcpInvocationContract');
  const {createConversationBinding}=require('../../server/services/secureshopConversationBinding');
  const {createRegisteredToolSnapshotRepository}=require('../../server/database/postgres/secureshopRegisteredToolSnapshot');
  const {createRegisteredTurnTools}=require('../../server/services/secureshopRegisteredTurnTools');
  const {createRegistryInvocationBridge}=require('../../server/services/secureshopOwnedMcpRegistryInvocationBridge');
  const observe=require('../../server/services/secureshopRegisteredInvocationObservation').createRegisteredInvocationObserver({journal:invocationJournal});
  const snapshots=createRegisteredToolSnapshotRepository({pool:agents});
  const calls=client.counts,boundedClient=client;
  const progress={version:1,stage:"registration",cases:[],calls,modelCalls:0,genuineCredit:0};
  const stage=value=>{progress.stage=value;checkpoint(progress);};stage("registration");
  const who=await owner(),unknownOwner=await owner();
  const definitions=[['http','streamable-http','http://attacker.training:8080/mcp',''],['sse','sse','http://attacker.training:8080/mcp',''],['stdio','stdio','','/usr/local/bin/node /usr/local/libexec/dvaia-owned-mcp-registry-worker.js --stdio-peer']];
  for(let index=0;index<definitions.length;index++){
    const [name,transport,url,stdio_cmd]=definitions[index];
    assert.equal((await request(who,'/admin/mcp/register',register(name,String(index),{transport,url,stdio_cmd}))).status,200);
  }
  async function context(subject){
    const signed=await auth.authenticateBoundToken({token:subject.token,scope:subject.scope});
    const persona={id:signed.user.id,role:signed.user.role},binding=createConversationBinding(subject.scope,persona);
    const personaSession={sessionId:signed.sessionId,authorityVersion:signed.authorityVersion};
    const fence=authority.capture({scope:subject.scope,personaId:persona.id,role:persona.role,...personaSession});
    const captured=snapshots.capture(binding,fence),conversation=await lifecycle.conversationService.create(subject.scope,persona,'general');
    return {persona,binding,personaSession,fence,captured,conversation};
  }
  const ctx=await context(who),capturedEntries=await ctx.captured.read(),cases=progress.cases;
  for(const [name,transport] of definitions){
    stage("invoke:"+transport);const entry=capturedEntries.find(row=>row.name===name);assert(entry);
    const requestId=randomUUID(),callId='qualification-'+name;
    const result=await lifecycle.runCoordinator.run(ctx.conversation.id,{timeoutMs:30000,idempotencyKey:requestId},async run=>{
      const ready=await boundedClient.invocationHealth({signal:run.signal});
      const bridge=createRegistryInvocationBridge({journal:invocationJournal,launches,client:boundedClient,
        executorIdentity:ready,personaSession:ctx.personaSession,policy:{mode:'vuln',approved:false,source:'controlled-qualification'}});
      const tools=await createRegisteredTurnTools({snapshots:ctx.captured,binding:ctx.binding,execution:run,requestId,mode:'vuln',instanceId:ready.instanceId,readApproval:async()=>false,dispatch:bridge.dispatch});
      const agent='owned_'+entry.entryId.replaceAll('-',''),args=transport==='stdio'?{}:{query:'owned-native-'+name};
      const completed=await run.effectWithReceipt('registered-'+name,()=>tools.callTool(agent,'tool_0',args,{callId}));
      const observation={tool:agent+'.tool_0',callId,args,result:completed.value,effectReceipt:completed.receipt};
      const joined=await observe({run,binding:ctx.binding,requestId,observation},ctx.fence);
      assertRegistryInvocationResult(transport,args,completed.value);
      assert.equal(joined.state,'completed');assert.equal(joined.drained,true);
      return {transport,invocationId:joined.invocationId,runId:run.runId,effectKey:joined.effectKey,exactResult:true,durableObservation:true};
    });
    cases.push(result);checkpoint(progress);
  }
  assert.equal(calls.invoke,3);
  const rows=async()=> (await agents.query('SELECT invocation_id,request_json,receipt_json,state,drained FROM secureshop_agents.owned_mcp_invocation_journal ORDER BY invocation_id')).rows;
  stage("populated-noop");const before=await rows();assert.equal(before.length,3);assert(before.every(row=>row.state==='completed'&&row.drained));
  const ledger=async()=> (await am.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  const beforeLedger=await ledger();assert(beforeLedger.some(row=>row.name==='0044_owned_mcp_registry_executor_mapping.sql'));
  for(let i=0;i<2;i++){
    await require('../../server/database/postgres/secureshopAgentsDb').initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:am});
    assert.deepEqual(await rows(),before);assert.deepEqual(await ledger(),beforeLedger);assert.deepEqual(await snapshot(siblingOwner),sibling);
  }
  // A captured registry revision must fail after an actual retirement; no tool
  // dispatch follows this check, and the completed invocation remains immutable.
  stage('revision-session-reset');assert.equal((await request(who,'/admin/mcp/http',{version:1,action:'retire',operationId:randomUUID(),expectedVersion:'3',name:'http'},'DELETE')).status,200);
  let reached=false;await assert.rejects(ctx.captured.withCurrentEntry(capturedEntries.find(row=>row.name==='http'),async()=>{reached=true;}),error=>error?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN'&&error.cause?.code==='MCP_REGISTRY_SNAPSHOT_UNAVAILABLE');assert.equal(reached,false);assert.equal(calls.invoke,3);
  await auth.logout({scope:who.scope,token:who.token});await assert.rejects(ctx.fence.assertRemoteAdmission());assert.equal(calls.invoke,3);
  const reset=await lifecycle.launchResetCoordinator.reset({...who.scope,expectedGeneration:who.scope.generation,idempotencyKey:randomUUID()});assert.equal(reset.status,'committed');
  assert.deepEqual(await snapshot(siblingOwner),sibling);
  const retiredRows=(await agents.query('SELECT drained,redacted_at,request_json,receipt_json FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=$1',[who.user.id])).rows;
  assert.equal(retiredRows.length,3);assert(retiredRows.every(row=>row.drained&&row.redacted_at&&row.request_json===null&&row.receipt_json===null));
  // Controlled crash boundary: real durable admission, deliberately no remote
  // invocation. The real executor therefore returns unknown, blocking reset.
  stage('unknown-obligation');assert.equal((await request(unknownOwner,'/admin/mcp/register',register('unknown'))).status,200);
  const unknown=await context(unknownOwner),entry=(await unknown.captured.read())[0];
  const ready=await boundedClient.invocationHealth(),operationId=randomUUID();
  await lifecycle.runCoordinator.run(unknown.conversation.id,{timeoutMs:15000},async run=>run.effect('admit-without-dispatch',async()=>{
    const q=require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol').request({version:1,instanceId:ready.instanceId,operationId,
      entry:Object.fromEntries(Object.entries(entry).filter(([key])=>key!=='name')),toolName:entry.tools[0].name,args:{query:'not-dispatched'}});
    const snap=C.snapshot({binding:unknown.binding,entryId:entry.entryId,registryVersion:entry.registryVersion,schemaSha256:entry.schemaSha256,tools:entry.tools});
    const legacy=C.request({snapshot:snap,runId:run.runId,requestId:randomUUID(),callId:'crash-boundary',toolIndex:0,args:q.args,mode:'vuln'});
    const handle=invocationJournal.prepare({invocationId:operationId,snapshot:snap,request:legacy,requestSha256:C.digest(legacy),personaSession:unknown.personaSession,
      managerInstanceId:ready.instanceId,runtimeSha256:ready.runtimeDigest,policySha256:C.digest({mode:'vuln',source:'controlled-crash-boundary'}),
      executorMapping:{version:1,request:q,requestSha256:require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol').digest(q),instanceId:ready.instanceId,runtimeSha256:ready.runtimeDigest}},run);
    await launches.admitOwnedMcpInvocation(handle);
  }));
  await assert.rejects(lifecycle.launchResetCoordinator.reset({...unknownOwner.scope,expectedGeneration:unknownOwner.scope.generation,idempotencyKey:randomUUID()}),{code:'MCP_INVOCATION_OUTCOME_UNCERTAIN'});
  const unresolved=(await agents.query('SELECT state,drained,redacted_at FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=$1',[operationId])).rows[0];
  assert.equal(unresolved.drained,false);assert.equal(unresolved.redacted_at,null);assert.deepEqual(await snapshot(siblingOwner),sibling);assert.equal(calls.invoke,3);
  return {version:1,cases,calls,modelCalls:0,genuineCredit:0,selection:'controlled direct tool selection; real coordinator and SDK effects',freshMigration:true,populatedNoopPreserved:true,pre0044UpgradeVerified:false,staleRevisionDenied:true,revokedSessionDenied:true,completedResetDrained:true,unknownResetDenied:true,siblingPreserved:true};
}
module.exports.qualifyRegistryInvocations=qualifyRegistryInvocations;

function assertRegistryInvocationResult(transport,args,result){
  assert.ok(['sse','streamable-http','stdio'].includes(transport));
  assert.equal(result.isError===true,false);assert.equal(result.content.length,1);assert.equal(result.content[0].type,'text');
  const body=JSON.parse(result.content[0].text),catalog=transport==='stdio'?body:body.catalog;
  if(transport!=='stdio'){assert.equal(body.query,args.query);assert.equal(body.peer,'attacker');}
  assert.deepEqual(catalog,[{id:'owned-product-42',title:'Synthetic training item',priceCents:4200}]);
}
module.exports.assertRegistryInvocationResult=assertRegistryInvocationResult;

function createRegistryActualChat({modelTransport,agents,identity,launches,authority,auth,lifecycle,invocationJournal,invocationClient,configuration,checkpoint,modeAuthority}){
 const calls=[],observations=[];
 const provider=new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:modelTransport.actorUrl,model:require('./finflowBackupBrowserActualTransport').MODEL});
 const observe=require('../../server/services/secureshopRegisteredInvocationObservation').createRegisteredInvocationObserver({journal:invocationJournal});
 const message='Use the registered search_catalog tool with query "owned" once, then report the exact product id, title and priceCents from its actual result. Do not perform any other action.';
 const runtime=require('../../server/services/secureshopRegisteredAdminRuntime').createRegisteredAdminRuntime({turns:lifecycle.turns,conversations:lifecycle.conversationService,conversationRepository:lifecycle.conversations,journal:lifecycle.journal,personaAuthority:authority,
  provider:{config:{provider:'ollama',model:provider.model},async chat(input){const output=await provider.chat(input);const {signal,...capturedInput}=input;calls.push({input:structuredClone(capturedInput),output});checkpoint({calls,observations});return output;}},
  snapshots:require('../../server/database/postgres/secureshopRegisteredToolSnapshot').createRegisteredToolSnapshotRepository({pool:agents}),executor:invocationClient,mode:configuration.mode,modeAuthority,readApproval:async()=>false,
  observeInvocation:async(packet,fence)=>{const proof=await observe(packet,fence);observations.push({proof,binding:packet.binding,observation:packet.observation});checkpoint({calls,observations});return proof;},
  dispatch:packet=>require('../../server/services/secureshopOwnedMcpRegistryInvocationBridge').createRegistryInvocationBridge({journal:invocationJournal,launches,client:invocationClient,executorIdentity:{version:1,instanceId:packet.request.instanceId,runtimeDigest:packet.runtimeDigest},personaSession:packet.personaSession,policy:{version:1,mode:configuration.mode,approvalPolicy:'deny-all',approved:false}}).dispatch(packet)
 });
 return {ready:true,runtime,calls,observations,message,router:require('../../server/routes/secureshop/boundAdminChat').createBoundAdminChatRouter({launches,authenticatePersona:auth.authenticatePersona,runtime}),begin(){modelTransport.beginCase('registered-catalog');},async verify(ownerId){
  modelTransport.endCase();modelTransport.assertComplete();
  assert.equal(observations.length,1);const row=observations[0];assert.equal(row.binding.platformOwnerId,ownerId);
  const meta=row.observation.result._meta.ownedRegistryInvocation;
  assertRegistryInvocationResult('sse',meta.request.args,meta.receipt.result);assert.deepEqual(meta.request.args,{query:'owned'});
  const catalogTool=meta.request.entry.tools.find(t=>t.name===meta.request.toolName);assert(catalogTool);
  const selected=calls[0].input.tools.find(t=>t.agent+'.'+t.tool===row.observation.tool);assert(selected);
  assert.deepEqual(selected.inputSchema,catalogTool.inputSchema);assert.equal(selected.description,catalogTool.description);
  assert(calls[0].input.messages.some(m=>m.role==='user'&&m.content===message));
  assert.equal(calls.length,2);assert.equal(calls[0].output.mocked,false);assert.equal(calls[1].output.mocked,false);
  assert.equal(calls[0].output.stop_reason,'tool_use');assert.equal(calls[0].output.tool_uses.length,1);
  assert.deepEqual(calls[0].output.tool_uses[0].args,meta.request.args);
  assert.equal(calls[0].output.tool_uses[0].name,row.observation.tool);
  assert.equal(calls[1].output.stop_reason,'end_turn');assert.match(calls[1].output.text,/owned-product-42/);
  const wire=modelTransport.snapshot();assert(wire.counts.chat>=2&&wire.counts.chat<=4);assert.equal(wire.counts.generate,0);
  const raw=wire.calls.filter(x=>x.kind==='chat').map(x=>x.response.trim().split('\n').map(line=>JSON.parse(line)).map(frame=>frame.message?.content||frame.response||'').join(''));
  const firstWire=JSON.parse(wire.calls.find(x=>x.kind==='chat').request);assert(firstWire.messages[0].content.includes(require('../../server/services/secureshop/providers/ollamaProvider').serializeTools(calls[0].input.tools)));
  const parsed=raw.map(require('../../server/services/secureshop/providers/ollamaProvider').parseDecision).filter(Boolean);
  assert.equal(parsed.length,2);assert.deepEqual(parsed[0].tool_calls,[{agent:calls[0].output.tool_uses[0].name.split('.')[0],tool:calls[0].output.tool_uses[0].name.split('.')[1],args:meta.request.args}]);assert.equal(parsed[1].reply,calls[1].output.text);
  const credits=(await identity.query('SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1',[ownerId])).rows[0];assert.equal(credits.n,0);
  const proof={actualModelProof:true,modelCalls:wire.counts.chat,genuineCredit:0,sdkReceiptBound:true,rawDecisionBound:true,renderedResponse:true,invocationId:meta.request.operationId};checkpoint({calls,observations,proof});return proof;
 }};
}
module.exports.createRegistryActualChat=createRegistryActualChat;

// Opt-in installer rehearsal: real disposable maintenance authority, no application/model traffic.
async function runRegistryReplacement(owned) {
 const installer=require('../../scripts/install/secureshop-owned-mcp-registry');
 const {createCommandRunner}=require('../../scripts/install/mcp-owned-provision');
 const {withApplicationMaintenanceScope}=require('../../scripts/lib/application-maintenance-scope');
 const {acquireApplicationMaintenanceLease}=require('../../server/services/applicationMaintenanceLease');
 const {Pool}=require('pg'),{randomBytes}=require('node:crypto');
 const manifest=JSON.parse(readPrivate(process.env.SECURESHOP_LOOP_MANIFEST,32*1024*1024)),spec=manifest.replacement;
 assert(spec);const environment={...process.env,DOCKER_HOST:spec.nextBuild.dockerHost};
 const applicationEnvironment={...environment,IDENTITY_DATABASE_URL:environment[PREFIX+'IDENTITY_RUNTIME_URL'],IDENTITY_MIGRATION_DATABASE_URL:environment[PREFIX+'IDENTITY_MIGRATION_URL'],SECURESHOP_AGENTS_DATABASE_URL:environment[PREFIX+'AGENTS_RUNTIME_URL'],SECURESHOP_AGENTS_MIGRATION_DATABASE_URL:environment[PREFIX+'AGENTS_MIGRATION_URL']};
 const allowedPorts=new Set([Number(new URL(applicationEnvironment.IDENTITY_DATABASE_URL).port)]);
 const restoreFence=require('./ctfStage9MainQualification').installSocketFence(allowedPorts);
 const pools=[];const pool=k=>{const p=new Pool({connectionString:applicationEnvironment[k],max:2});pools.push(p);return p;};
 const result={version:'secureshop-registry-control-plane-v1',status:'incomplete',modelCalls:0,genuineCredit:0,cases:[],cleanupVerified:false};
 const resources=[];const save=()=>saveBounded(path.join(owned.evidence,'registry-result.json'),result);
 const raw=createCommandRunner({cwd:owned.source,env:environment});
 let selected;
 const run=async(binary,args,options)=>{
  assert.equal(binary,'docker');assert.deepEqual(args.slice(0,2),['--host',spec.nextBuild.dockerHost]);
  const a=args.slice(2),creating=a[0]==='create'||a[0]==='network'&&a[1]==='create';
  let row;
  if(creating){const kind=a[0]==='create'?'container':'network',name=kind==='container'?a[a.indexOf('--name')+1]:a.at(-1);assert(name.startsWith(selected.plan.container));row={kind,name,id:null,namespace:selected.namespace,workspace:selected.plan.workspace};resources.push(row);saveBounded(path.join(owned.evidence,'replacement-resources.json'),resources);}
  const reply=await raw(binary,args,options);
  if(a[0]==='rename'&&reply.exitCode===0){const renamed=resources.find(x=>x.kind==='container'&&x.id===a[1]);assert(renamed);assert(a[2]===selected.plan.container||a[2].startsWith(selected.plan.container+'-rollback-'));renamed.currentName=a[2];saveBounded(path.join(owned.evidence,'replacement-resources.json'),resources);}
  if(row){assert.equal(reply.exitCode,0);assert.match(reply.stdout.trim(),/^[a-f0-9]{64}$/);row.id=reply.stdout.trim();saveBounded(path.join(owned.evidence,'replacement-resources.json'),resources);}
  return reply;
 };
 const verifyProfile=async({plan,renderedSha256})=>{
  assert.equal(plan.profile,manifest.registry.apparmorProfile);
  assert.equal(sha(fs.readFileSync('/usr/bin/ssh')),spec.sshSha256);assert.equal(sha(fs.readFileSync(plan.sshConfig)),spec.sshConfigSha256);
  const read=async command=>{const r=await raw('/usr/bin/ssh',['-F',plan.sshConfig,plan.sshHost,command],{stage:'profile-read-only',timeoutMs:10000,maxOutputBytes:1048576});assert.equal(r.exitCode,0);return r.stdout;};
  assert.equal((await read('sudo sha256sum '+plan.destination)).trim().split(/\s+/)[0],renderedSha256);
  assert.equal((await read('sudo stat -c %u:%g:%a:%F '+plan.destination)).trim(),'0:0:600:regular file');
  assert((await read('sudo cat /sys/kernel/security/apparmor/profiles')).split(/\r?\n/).includes(plan.profile+' (enforce)'));
 };
 const verifyHealth=async configuration=>{
  const c=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({baseURL:configuration.baseURL,token:configuration.token,expectedRuntimeDigest:configuration.runtimeDigest});
  const health=await c.health();assert.equal(health.ready,true);assert.equal(health.runtimeDigest,configuration.runtimeDigest);return true;
 };
 try {
  await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(pool('IDENTITY_DATABASE_URL'),pool('IDENTITY_MIGRATION_DATABASE_URL'));
  await require('../../server/database/postgres/secureshopAgentsDb').initializeSecureShopAgentsDb({runtimePool:pool('SECURESHOP_AGENTS_DATABASE_URL'),migrationPool:pool('SECURESHOP_AGENTS_MIGRATION_DATABASE_URL')});
  await withApplicationMaintenanceScope({environment:applicationEnvironment},async maintenanceScope=>{
   await assert.rejects(acquireApplicationMaintenanceLease({mode:'application',env:applicationEnvironment}),{code:'APPLICATION_MAINTENANCE_BUSY'});
   for(const scenario of ['healthy','rollback']){
    const namespace=randomBytes(6).toString('hex'),configurationHome=path.join(owned.evidence,'runtime','replacement-'+scenario);fs.mkdirSync(configurationHome,{mode:0o700});
    // Reserve and release an owned ephemeral loopback port immediately before Docker publication.
    const listener=require('node:net').createServer();await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(0,'127.0.0.1',resolve);});const port=listener.address().port;allowedPorts.add(port);await new Promise((resolve,reject)=>listener.close(e=>e?reject(e):resolve()));
    const options={root:owned.source,home:spec.home,configurationHome,platform:'darwin',colimaProfile:spec.colimaProfile,resourceNamespace:namespace,port,imageId:spec.previousBuild.imageId,environment,run,installProfile:verifyProfile};
    const plan=installer.plan(options);selected={namespace,plan};
    await installer.provision(options);
    const load=p=>JSON.parse(readPrivate(p,16384));const original=load(plan.receiptFile),configuration=load(plan.configFile);
    assert.equal(configuration.enabled,false);assert.equal(original.imageId,spec.previousBuild.imageId);
    const buildFile=path.join(plan.directory,'secureshop-owned-mcp-registry-build.json');fs.writeFileSync(buildFile,JSON.stringify(spec.previousBuild),{flag:'wx',mode:0o600});
    const next={...options,imageId:spec.nextBuild.imageId,applicationEnvironment,maintenanceScope,previousBuild:spec.previousBuild,nextBuild:spec.nextBuild,verifyReadiness:async c=>{await verifyHealth(c);const ready=await require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({baseURL:c.baseURL,token:c.token,expectedRuntimeDigest:c.runtimeDigest}).invocationHealth();assert.equal(ready.runtimeDigest,c.runtimeDigest);return scenario==='healthy';}};
    if(scenario==='healthy'){
     const changed=await installer.replace(next);assert.equal(changed.upgraded,true);assert.equal(changed.rollbackContainerId,original.containerId);assert.notEqual(changed.containerId,original.containerId);
     const current=load(plan.configFile);assertReplacementPublication(configuration,current,changed.runtimeDigest);
     const reused=await installer.provision({...options,imageId:spec.nextBuild.imageId});assert.equal(reused.ready,true);assert.equal(load(plan.receiptFile).containerId,changed.containerId);await verifyHealth(current);
    }else{
     await assert.rejects(installer.replace(next),e=>e.code==='REGISTRY_UPGRADE_NOT_READY'&&!e.rollbackIncomplete);
     assert.deepEqual(load(plan.configFile),configuration);assert.deepEqual(load(plan.receiptFile),original);assert.deepEqual(load(buildFile),spec.previousBuild);await verifyHealth(configuration);
     const transition=load(path.join(plan.directory,'secureshop-owned-mcp-registry-upgrade.json'));assert.equal(transition.phase,'rolled-back');
    }
    result.cases.push({id:scenario,passed:true});save();
   }
   maintenanceScope.assertHeld();
  });
  result.replacement={status:'passed',cases:2,maintenanceExclusion:true,healthyReplacement:true,reuseVerified:true,rollbackVerified:true,privatePublicationPreserved:true,sharedProfileUnchanged:true,modelCalls:0,genuineCredit:0,limitations:['Profile installation is not tested; existing exact enforced profile verified read-only.','Old/candidate resources are retained for exact parent cleanup; no installed configuration or service touched.']};
  result.status='passed';
 }finally{const settled=await Promise.allSettled(pools.map(p=>p.end()));result.cleanupVerified=settled.every(x=>x.status==='fulfilled');restoreFence();save();if(!result.cleanupVerified)throw Error('Replacement pools failed to close');}
 owned.assertLoaded();return result;
}
module.exports.runRegistryReplacement=runRegistryReplacement;

function assertReplacementPublication(before,after,runtimeDigest){assert.match(runtimeDigest,/^[a-f0-9]{64}$/);assert.deepEqual(after,{...before,runtimeDigest});assert.equal(after.enabled,false);}
module.exports.assertReplacementPublication=assertReplacementPublication;
