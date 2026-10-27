'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildAuditModelChain, verifyAuditModelChain } = require('../server/services/secureshopAuditModelChain');
const { consumeSecureShopAuditEvidence } = require('../server/services/secureshopAuditVerifiedEvidence');

const runId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestedCount = 4;
const summary = '• Suspicious instruction in an audit event.';
const digest = value => createHash('sha256').update(value).digest('hex');
test('final framing trace requires exact trusted task, observation, ordering and unique marker; history remains readable',()=>{
 const {createAuditFinalFraming,auditFinalFramingFromTraces}=require('../server/services/secureshopAuditModelChain');
 const final={kind:'model_decision',step:2},effect={kind:'local_tool_result',step:1};
 const payload=createAuditFinalFraming(4,'complete original observation');
 const marker={kind:'audit_final_framing',actor:'supervisor',step:2,result_json:JSON.stringify(payload)};
 const rows=[effect,marker,final];
 assert.deepEqual(auditFinalFramingFromTraces(rows,4,final,payload.observationSha256),payload);
 assert.equal(auditFinalFramingFromTraces([effect,final],4,final,payload.observationSha256),undefined);
 for(const mutate of [r=>r.splice(1,0,marker),r=>r.reverse(),r=>{r[1].step=1;},
  r=>{r[1].result_json=JSON.stringify({...payload,version:2});},
  r=>{r[1].result_json=JSON.stringify({...payload,taskSha256:'0'.repeat(64)});},
  r=>{r[1].result_json=JSON.stringify({...payload,observationSha256:'0'.repeat(64)});}]){
  const changed=structuredClone(rows);mutate(changed);
  assert.throws(()=>auditFinalFramingFromTraces(changed,4,changed.find(r=>r.kind==='model_decision'),payload.observationSha256));
 }
});
const observation = Object.freeze({ ok: true, requested_count: requestedCount, row_count: 1,
  prompt: 'audit prompt', log_text: 'event log', source_manifest: { logSha256: digest('event log'), sourcesSha256: 's'.repeat(64) } });

function fixture(overrides = {}) {
  const original = overrides.observation || observation;
  const exact = JSON.stringify(original);
  const decision = { step: 1, actor: 'supervisor', kind: 'model_decision', provider: 'ollama',
    params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: 'call-1', name: 'audit.summarize_anomalies', args: overrides.args||{ limit: requestedCount } }] }),
    result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) };
  const final = { step: 2, actor: 'supervisor', kind: 'model_decision', provider: 'ollama',
    result_json: JSON.stringify({ decision: 'final', stopReason: 'end_turn', text: summary, model: 'llama3.1:8b', mocked: false }) };
  const terminal = { step: 2, actor: 'supervisor', kind: 'terminal', provider: 'ollama',
    result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2, hops: 1, model: 'llama3.1:8b', mocked: false }) };
  const traces = [decision,
    { step: 1, actor: 'supervisor→task', kind: 'local_tool_call', agent_ns: 'audit', tool_name: 'summarize_anomalies', params_json: JSON.stringify(overrides.args||{ limit: requestedCount }) },
    { step: 1, actor: 'task→supervisor', kind: 'local_tool_result', agent_ns: 'audit', tool_name: 'summarize_anomalies',
      result_json: JSON.stringify({ isError: false, content: [{ type: 'text', text: exact }] }) }, final, terminal];
  const messages = [{ role: 'user', content: 'summarize audit' },
    { role: 'assistant', content: '', tool_calls: [{ id: 'call-1', type: 'function' }] },
    { role: 'tool', tool_call_id: 'call-1', content: exact }, { role: 'assistant', content: summary }];
  const manifest = { version: 1, runId, requestedCount, rowCount: original.row_count,
    logSha256: digest(original.log_text), sourcesSha256: original.source_manifest.sourcesSha256 };
  const effects = [{ status: 'completed', workerLocal: true, effectKey: JSON.stringify([1, 'call-1', 'audit.summarize_anomalies']) }];
  const input = { manifest, messages, traces, effects, observation,
    result: { summary, provider: 'ollama', model: 'llama3.1:8b' }, qualifyModel: () => true, ...overrides };
  return { input, manifest, messages, traces, effects };
}

function evidenceFixture() {
  const f = fixture();
  const chain = buildAuditModelChain(f.input);
  const data = {
    log: Buffer.from('event log'), sources: Buffer.from('sources'), messages: Buffer.from('messages'),
    traces: Buffer.from('traces'), effects: Buffer.from(JSON.stringify([f.effects[0], chain])),
  };
  const reads = [];
  const evidence = { runId, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount, rowCount: 1,
    artifacts: Object.fromEntries(Object.entries(data).map(([name, value]) => [name, { bytes: value.length,
      sha256: name === 'effects' ? digest(value) : name === 'log' ? f.manifest.logSha256 : name === 'sources' ? f.manifest.sourcesSha256 : chain[`${name}Sha256`] }])),
    async *readArtifact(name) { reads.push(name); yield data[name]; },
  };
  return { f, chain, data, reads, evidence };
}

test('builds and verifies a compact chain bound to the exact observation and summary', () => {
  const f = fixture();
  const chain = buildAuditModelChain(f.input);
  assert.equal(chain.kind, 'audit_model_chain');
  assert.equal(chain.version, 1);
  assert.equal(chain.requestedCount, requestedCount);
  assert.equal(chain.decision.params_json.includes(`"limit":${requestedCount}`), true);
  assert.equal(chain.final.result_json.includes(summary), true);
  assert.equal(verifyAuditModelChain(chain, { runId, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount, rowCount: 1,
    qualifyModel: () => true, artifacts: { messages: { sha256: chain.messagesSha256 }, traces: { sha256: chain.tracesSha256 },
      log: { sha256: f.manifest.logSha256 }, sources: { sha256: f.manifest.sourcesSha256 } } }), true);
});

test('v2 chain binds original one-copy bytes, while explicit unknown or malformed versions fail closed', () => {
  const value = require('../server/services/secureshopAuditSummaryObservation')
    .createAuditSummaryObservationV2({ logText: 'original event log', requestedCount,
      rowCount: 1, logSha256: digest('original event log'), sourcesSha256: digest('sources') });
  const f = fixture({ observation: value }), chain = buildAuditModelChain(f.input);
  assert.equal(chain.version, 2);
  assert.equal(chain.observationSha256, digest(JSON.stringify(value)));
  assert.equal(chain.logSha256, digest(value.log_text));
  const expected = { runId, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount,
    rowCount: 1, qualifyModel: () => true,
    artifacts: { messages: { sha256: chain.messagesSha256 }, traces: { sha256: chain.tracesSha256 },
      log: { sha256: chain.logSha256 }, sources: { sha256: chain.sourcesSha256 } } };
  assert.equal(verifyAuditModelChain(chain, expected), true);
  assert.throws(() => verifyAuditModelChain({ ...chain, version: 3 }, expected), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  for (const observation of [
    { ...value, version: 1 }, { ...value, version: 3 },
    { ...value, prompt: `${value.prompt}\n${value.log_text}` },
    { ...value, log_text: `${value.log_text}!` },
    { ...value, source_manifest: { ...value.source_manifest, rowCount: 2 } },
  ]) assert.throws(() => buildAuditModelChain(fixture({ observation }).input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  const changed = fixture({ observation: value });
  changed.messages[2].content = JSON.stringify(observation);
  assert.throws(() => buildAuditModelChain(changed.input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
});

test('reordered or missing tool result cannot produce a chain', () => {
  const reordered = fixture();
  [reordered.input.traces[1], reordered.input.traces[2]] = [reordered.input.traces[2], reordered.input.traces[1]];
  assert.throws(() => buildAuditModelChain(reordered.input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  const missing = fixture();
  missing.input.traces.splice(2, 1);
  assert.throws(() => buildAuditModelChain(missing.input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
});

test('wrong count, mock/fallback provenance, and modified summary are rejected', () => {
  const wrongCount = fixture();
  wrongCount.input.traces[0].params_json = JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: 'call-1', name: 'audit.summarize_anomalies', args: { limit: 3 } }] });
  assert.throws(() => buildAuditModelChain(wrongCount.input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  for (const field of ['mocked', 'fallback']) {
    const bad = fixture();
    const meta = JSON.parse(bad.input.traces[0].result_json); meta[field] = true;
    bad.input.traces[0].result_json = JSON.stringify(meta);
    assert.throws(() => buildAuditModelChain(bad.input), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  }
  const chain = buildAuditModelChain(fixture().input);
  const f = fixture();
  assert.throws(() => verifyAuditModelChain(chain, { runId, summary: `${summary}!`, provider: 'ollama', model: 'llama3.1:8b', requestedCount, rowCount: 1,
    qualifyModel: () => true, artifacts: { messages: { sha256: chain.messagesSha256 }, traces: { sha256: chain.tracesSha256 },
      log: { sha256: f.manifest.logSha256 }, sources: { sha256: f.manifest.sourcesSha256 } } }), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
});

test('source, artifact, and effect bindings are fail-closed', () => {
  const f = fixture();
  const chain = buildAuditModelChain(f.input);
  const base = { runId, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount, rowCount: 1, qualifyModel: () => true,
    artifacts: { messages: { sha256: chain.messagesSha256 }, traces: { sha256: chain.tracesSha256 },
      log: { sha256: chain.logSha256 }, sources: { sha256: chain.sourcesSha256 } } };
  for (const [field, value] of [['logSha256', 'x'.repeat(64)], ['sourcesSha256', 'x'.repeat(64)],
    ['messagesSha256', 'x'.repeat(64)], ['tracesSha256', 'x'.repeat(64)], ['localEffectKey', 'wrong-effect']]) {
    assert.throws(() => verifyAuditModelChain({ ...chain, [field]: value }, base), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
  }
  assert.throws(() => verifyAuditModelChain(chain, { ...base, model: 'other-model' }), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
});

test('consumer verifies effects projection and drains every artifact stream', async () => {
  const f = evidenceFixture(); let checks = 0;
  const result = await consumeSecureShopAuditEvidence(f.evidence, { qualifyModel: () => true, check: async () => { checks++; } });
  assert.equal(result.modelChainVerified, true);
  assert.equal(result.objectiveCredit, false);
  assert.deepEqual(result.trace,[
    {step:1,phase:'decision',provider:'ollama',model:'llama3.1:8b',tool:'audit.summarize_anomalies'},
    {step:2,phase:'final',provider:'ollama',model:'llama3.1:8b',tool:null},
  ]);
  assert.equal(JSON.stringify(result.trace).includes('audit prompt'),false);
  assert.equal(JSON.stringify(result.trace).includes(summary),false);
  assert.deepEqual(new Set(f.reads), new Set(['effects', 'log', 'sources', 'messages', 'traces']));
  assert.ok(checks > 0);
});

test('consumer rejects corrupted projection and truncated effect stream', async () => {
  const bad = evidenceFixture();
  const corrupted = { ...bad.chain, summarySha256: 'f'.repeat(64) };
  bad.data.effects = Buffer.from(JSON.stringify([bad.f.effects[0], corrupted]));
  bad.evidence.artifacts.effects.bytes = bad.data.effects.length;
  bad.evidence.artifacts.effects.sha256 = digest(bad.data.effects);
  await assert.rejects(consumeSecureShopAuditEvidence(bad.evidence, { qualifyModel: () => true, check: async () => {} }), { code: 'AUDIT_MODEL_CHAIN_INVALID' });

  const truncated = evidenceFixture();
  const original = truncated.evidence.readArtifact;
  truncated.evidence.readArtifact = async function * (name) {
    if (name === 'effects') { const value = truncated.data.effects; yield value.subarray(0, value.length - 1); return; }
    yield * original.call(this, name);
  };
  await assert.rejects(consumeSecureShopAuditEvidence(truncated.evidence, { qualifyModel: () => true, check: async () => {} }), { code: 'AUDIT_MODEL_CHAIN_INVALID' });
});

test('v3 binds the model selected literal action and exact immutable matches without replacing full source',()=>{
 const {createAuditSummaryObservationV3,validateAuditSummaryObservation}=require('../server/services/secureshopAuditSummaryObservation');
 const line='[2026-10-16T00:00:00.000000Z] actor=merchant action=listing_update target=7 params={"note":"original"}';
 const logText=line+'\n'+line.replace('action=listing_update','action=listing_update_other');
 const value=createAuditSummaryObservationV3({logText,requestedCount,rowCount:2,logSha256:digest(logText),sourcesSha256:digest('sources'),focusAction:'listing_update'});
 assert.equal(validateAuditSummaryObservation(value),3);assert.equal(value.log_text,logText);
 assert.deepEqual(value.focus.matches,[{lineIndex:0,text:line,sha256:digest(line)}]);
 const f=fixture({observation:value,args:{focus_action:'listing_update',limit:requestedCount}}),chain=buildAuditModelChain(f.input);
 assert.equal(chain.version,3);assert.equal(chain.focusAction,'listing_update');assert.equal(chain.focusSelectionSha256,digest(JSON.stringify(value.focus)));
 assert.equal(chain.observationSha256,digest(JSON.stringify(value)));assert.equal(f.effects.length,1);
 const expected={runId,summary,provider:'ollama',model:'llama3.1:8b',requestedCount,rowCount:2,qualifyModel:()=>true,observation:value,
  artifacts:{messages:{sha256:chain.messagesSha256},traces:{sha256:chain.tracesSha256},log:{sha256:chain.logSha256},sources:{sha256:chain.sourcesSha256}}};
 assert.equal(verifyAuditModelChain(chain,expected),true);
 assert.throws(()=>verifyAuditModelChain({...chain,focusSelectionSha256:digest('well-formed substitution')},expected),{code:'AUDIT_MODEL_CHAIN_INVALID'});
 assert.throws(()=>verifyAuditModelChain(chain,{...expected,observation:undefined}),{code:'AUDIT_MODEL_CHAIN_INVALID'});
 assert.throws(()=>verifyAuditModelChain({...chain,focusAction:'other'},expected),{code:'AUDIT_MODEL_CHAIN_INVALID'});
 const wrong=fixture({observation:value,args:{limit:requestedCount,focus_action:'other'}});assert.throws(()=>buildAuditModelChain(wrong.input),{code:'AUDIT_MODEL_CHAIN_INVALID'});
 for(const edit of [o=>{o.focus.matches[0].text+=' forged';},o=>{o.focus.matches[0].lineIndex=1;},
  o=>{o.focus.matches[0].sha256=digest('different');},o=>{o.focus.matches=[];},
  o=>{o.focus.matches.push({...o.focus.matches[0]});},o=>{o.focus.logSha256=digest('different');}]){
  const bad=structuredClone(value);edit(bad);assert.throws(()=>validateAuditSummaryObservation(bad));
 }
});

test('retained v3 consumer joins focus to one exact persisted observation before accepting provenance',async()=>{
 const {createAuditSummaryObservationV3}=require('../server/services/secureshopAuditSummaryObservation');
 const line='[2026-10-16T00:00:00.000000Z] actor=admin action=owned_event target=1 params={}';
 const value=createAuditSummaryObservationV3({logText:line,requestedCount,rowCount:1,logSha256:digest(line),sourcesSha256:digest('sources'),focusAction:'owned_event'});
 function retained(){const f=fixture({observation:value,args:{limit:requestedCount,focus_action:'owned_event'}}),chain=structuredClone(buildAuditModelChain(f.input));
  const data={log:Buffer.from(line),sources:Buffer.from('sources'),messages:Buffer.from(JSON.stringify(f.messages)),
   traces:Buffer.from(JSON.stringify(f.traces)),effects:Buffer.from(JSON.stringify([f.effects[0],chain]))},reads=[];
  const evidence={runId,summary,provider:'ollama',model:'llama3.1:8b',requestedCount,rowCount:1,
   artifacts:Object.fromEntries(Object.entries(data).map(([k,v])=>[k,{bytes:v.length,sha256:digest(v)}])),
   async*readArtifact(name){reads.push(name);yield data[name];}};
  return {f,chain,data,evidence,reads};}
 const original=retained(),check=async()=>{};
 assert.equal((await consumeSecureShopAuditEvidence(original.evidence,{qualifyModel:()=>true,check})).observationVersion,3);
 const reused=retained();await consumeSecureShopAuditEvidence(reused.evidence,{qualifyModel:()=>true,check,observation:value});
 assert.equal(reused.reads.filter(n=>n==='messages').length,1,'checked observation avoids a second full parse');
 for(const edit of [f=>{f.chain.focusSelectionSha256=digest('different');},
  f=>{const rows=JSON.parse(f.data.messages),o=JSON.parse(rows[2].content);o.focus.matches=[];rows[2].content=JSON.stringify(o);f.data.messages=Buffer.from(JSON.stringify(rows));},
  f=>{const rows=JSON.parse(f.data.messages);rows.push({...rows[2]});f.data.messages=Buffer.from(JSON.stringify(rows));},
  f=>{f.evidence.artifacts.messages.sha256=digest('different');},
  f=>{f.evidence.artifacts.messages.bytes=128*1024*1024+1;}]){
  const bad=retained();edit(bad);bad.data.effects=Buffer.from(JSON.stringify([bad.f.effects[0],bad.chain]));
  bad.evidence.artifacts.effects={bytes:bad.data.effects.length,sha256:digest(bad.data.effects)};
  await assert.rejects(consumeSecureShopAuditEvidence(bad.evidence,{qualifyModel:()=>true,check}),{code:'AUDIT_MODEL_CHAIN_INVALID'});
  if(bad.evidence.artifacts.messages.bytes>128*1024*1024)assert.equal(bad.reads.includes('messages'),false);
 }
});

test('literal focus has honest empty results, excludes parameter text and cannot clip overflowing originals',()=>{
 const {createAuditActionFocus}=require('../server/services/secureshopAuditSummaryObservation');
 const line='[2026-10-16T00:00:00.000000Z] actor=admin action=session_create target=7 params={"note":"action=listing_update"}';
 assert.deepEqual(createAuditActionFocus(line,'listing_update').matches,[]);
 assert.equal(createAuditActionFocus(line,'session_create').matches[0].text,line);
 for(const action of ['*','.*','x y','',null,123])assert.throws(()=>createAuditActionFocus(line,action));
 assert.throws(()=>createAuditActionFocus(Array(33).fill(line).join('\n'),'session_create'),{code:'AUDIT_FOCUS_RESOURCE_LIMIT'});
 assert.throws(()=>createAuditActionFocus(line+'x'.repeat(16385),'session_create'),{code:'AUDIT_FOCUS_RESOURCE_LIMIT'});
});
