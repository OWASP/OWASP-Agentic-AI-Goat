'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfEmailDispatch, inspectCsrfMailProof } = require('../server/services/csrfEmailDispatch');
const codec = require('../server/services/csrfEmailCodec');

const OWNER = '7';
const OWNER_KEY = JSON.stringify(['CSRF', OWNER]);
const RECIPIENT = 'owned@sharklasers.com';
const SENDER = 'indirectpromptinjection@gmail.com';
const PAYLOAD = '<img src=x onerror="globalThis.__xssEmail=1">';

function fixture({ transportResult, transportError } = {}) {
  const records = [];
  let canonicalGeneration = 4;
  let graphGeneration = 9;
  let activeRun = '11111111-1111-4111-8111-111111111111';
  let effectCalls = 0;
  let transportCalls = 0;
  const sent = [];
  const inbox = new Map();
  const repository = {
    async append(input) {
      if (input.generation !== canonicalGeneration) throw Object.assign(new Error('stale canonical generation'), { code: 'STALE_GENERATION' });
      if (input.runId !== activeRun) throw Object.assign(new Error('stale or foreign run'), { code: 'STALE_RUN' });
      const prior = records.find(row => row.evidenceID === input.evidenceID && row.generation === input.generation);
      if (prior) {
        assert.deepEqual(prior.evidence, input.evidence, 'evidence IDs are immutable');
        return prior;
      }
      const row = Object.freeze({ evidenceID: input.evidenceID, runId: input.runId,
        generation: input.generation, evidence: structuredClone(input.evidence), omitted: false });
      records.push(row);
      return row;
    },
    async list(input) {
      if (input.generation !== canonicalGeneration) throw Object.assign(new Error('stale canonical generation'), { code: 'STALE_GENERATION' });
      if (input.runId !== activeRun) throw Object.assign(new Error('stale or foreign run'), { code: 'STALE_RUN' });
      return records.filter(row => row.generation === input.generation).slice(-input.limit);
    },
  };
  const transport = {
    async sendEmail(recipient, subject, body, owner, options) {
      transportCalls++;
      sent.push({ recipient, subject, body, owner, html: options.html });
      if (transportError) throw transportError;
      return transportResult || { smtpAccepted: true, messageId: '<owned-message@fixture.invalid>',
        sentTo: recipient, sentFrom: SENDER, requestedRecipient: recipient,
        accepted: [recipient], rejected: [], deliveryConfirmed: false };
    },
  };
  const mailbox = {
    canonicalize: value => String(value).trim().toLowerCase().replace('+alias@', '@'),
    async fetchEmails() { return { success: true, emails: [...inbox.values()].map(row => ({ id: row.id, subject: row.subject })) }; },
    async fetchEmail(_recipient, id) { const email = inbox.get(String(id)); return email ? { success: true, email } : { success: false }; },
  };
  const execution = () => ({
    runId: activeRun, ownerKey: OWNER_KEY, durableGeneration: graphGeneration,
    async check() {
      if (this.runId !== activeRun || String(this.durableGeneration) !== String(graphGeneration)) {
        throw Object.assign(new Error('execution is stale'), { name: 'AbortError' });
      }
    },
    async effect(_key, callback) { effectCalls++; return callback(); },
  });
  const scope = () => ({ userId: Number(OWNER), generation: canonicalGeneration, execution: execution() });
  const service = createCsrfEmailDispatch({ repository, transport, mailbox, codec, expectedSender: SENDER });
  return { service, records, sent, inbox, scope,
    counts: () => ({ effectCalls, transportCalls }),
    rotate({ generation = canonicalGeneration + 1, durableGeneration = graphGeneration + 1,
      runId = '22222222-2222-4222-8222-222222222222' } = {}) {
      canonicalGeneration = generation; graphGeneration = durableGeneration; activeRun = runId;
    },
    pruneAccepted() {
      for (let i = records.length - 1; i >= 0; i--) if (records[i].evidence.state === 'accepted') records.splice(i, 1);
    },
  };
}

test('requires canonical mailbox and strict numeric execution generation', async () => {
  const f = fixture();
  const scope = f.scope();
  scope.execution.durableGeneration = null;
  await assert.rejects(f.service.send(scope, { recipient: RECIPIENT, payload: PAYLOAD }),
    /Authenticated durable CSRF execution/);
  assert.throws(() => createCsrfEmailDispatch({
    repository: { append() {}, list() {} },
    transport: { sendEmail() {} },
    mailbox: { fetchEmails() {}, fetchEmail() {} }, codec, expectedSender: SENDER,
  }), /Explicit durable mail evidence/);
});

test('accepts PostgreSQL bigint generation strings beyond Number safe range and rejects invalid values', async () => {
  const f = fixture();
  f.rotate({ generation: 4, durableGeneration: '9007199254740993' });
  const scope = f.scope();
  const accepted = await f.service.send(scope, { recipient: RECIPIENT, payload: PAYLOAD });
  assert.equal(f.records.at(-1).evidence.durableGeneration, '9007199254740993');
  assert.equal(inspectCsrfMailProof(accepted, proofScope(scope, 'accepted')).durableGeneration, '9007199254740993');
  for (const value of [null, '', '01', '-1', '9223372036854775808', 'not-a-generation']) {
    const invalid = f.scope();
    invalid.execution.durableGeneration = value;
    await assert.rejects(f.service.send(invalid, { recipient: RECIPIENT, payload: PAYLOAD }), /Authenticated durable/);
  }
});

function proofScope(scope, kind) {
  return { kind, userId: String(scope.userId), generation: scope.generation,
    runId: scope.execution.runId, ownerKey: scope.execution.ownerKey,
    durableGeneration: scope.execution.durableGeneration };
}

function installOwnMail(f, id = 'owned-mail') {
  const mail = f.sent.at(-1);
  f.inbox.set(id, { id, subject: mail.subject, from: SENDER, htmlBody: mail.html });
  return mail;
}

test('persists pending before the effect and accepted only after exact SMTP acceptance', async () => {
  const order = [];
  const f = fixture();
  const scope = f.scope();
  scope.execution.effect = async (_key, callback) => {
    order.push(f.records.map(row => row.evidence.state).join(','));
    return callback();
  };
  const accepted = await f.service.send(scope, { recipient: 'OWNED+alias@sharklasers.com', payload: PAYLOAD });
  assert.deepEqual(order, ['pending']);
  assert.deepEqual(f.records.map(row => row.evidence.state), ['pending', 'accepted']);
  assert.equal(f.records[0].evidence.dispatchId, f.records[1].evidence.dispatchId);
  assert.equal(f.records[1].evidence.expected.payloadDigest, codec.buildCsrfMail({
    marker: f.records[1].evidence.marker, payload: PAYLOAD,
  }).expected.payloadDigest);
  assert.equal(inspectCsrfMailProof(accepted, proofScope(scope, 'accepted')).state, 'accepted');
  assert.equal(inspectCsrfMailProof(accepted, proofScope(scope, 'accepted')).hasEventHandler, true);
  assert.equal(Object.hasOwn(accepted, 'marker'), false);
});

test('an uncertain send leaves pending evidence and is never automatically resent', async () => {
  const failure = Object.assign(new Error('transport outcome unknown'), { code: 'ETIMEDOUT' });
  const f = fixture({ transportError: failure });
  await assert.rejects(f.service.send(f.scope(), { recipient: RECIPIENT, payload: PAYLOAD }), failure);
  assert.deepEqual(f.records.map(row => row.evidence.state), ['pending']);
  assert.deepEqual(f.counts(), { effectCalls: 1, transportCalls: 1 });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.counts(), { effectCalls: 1, transportCalls: 1 });
});

test('rejects incomplete or contradictory transport acceptance without an accepted record', async () => {
  const cases = [
    { smtpAccepted: true, messageId: 'm', sentTo: RECIPIENT, sentFrom: SENDER, accepted: ['other@sharklasers.com'], rejected: [] },
    { smtpAccepted: true, messageId: 'm', sentTo: RECIPIENT, sentFrom: SENDER, accepted: [RECIPIENT], rejected: [RECIPIENT] },
    { smtpAccepted: true, messageId: 'm', sentTo: RECIPIENT, sentFrom: 'foreign@example.test', accepted: [RECIPIENT], rejected: [] },
  ];
  for (const transportResult of cases) {
    const f = fixture({ transportResult });
    await assert.rejects(f.service.send(f.scope(), { recipient: RECIPIENT, payload: PAYLOAD }), /acceptance|sender/i);
    assert.deepEqual(f.records.map(row => row.evidence.state), ['pending']);
  }
});

test('accepted proof snapshots transport arrays against post-issuance mutation', async () => {
  const acceptedRecipients = [RECIPIENT];
  const rejectedRecipients = [];
  const f = fixture({ transportResult: { smtpAccepted: true, messageId: 'immutable-message',
    sentTo: RECIPIENT, sentFrom: SENDER, accepted: acceptedRecipients, rejected: rejectedRecipients } });
  const scope = f.scope();
  const delivery = await f.service.send(scope, { recipient: RECIPIENT, payload: PAYLOAD });
  acceptedRecipients[0] = 'foreign@sharklasers.com';
  rejectedRecipients.push(RECIPIENT);
  const proof = inspectCsrfMailProof(delivery, proofScope(scope, 'accepted'));
  assert.deepEqual(proof.accepted, [RECIPIENT]);
  assert.deepEqual(proof.rejected, []);
});

test('opaque proofs cannot be forged or rebound to another owner, run, or reset generation', async () => {
  const f = fixture();
  const sendScope = f.scope();
  const accepted = await f.service.send(sendScope, { recipient: RECIPIENT, payload: PAYLOAD });
  assert.equal(inspectCsrfMailProof({ ...accepted }, proofScope(sendScope, 'accepted')), null);
  for (const override of [
    { userId: '8' }, { runId: '33333333-3333-4333-8333-333333333333' },
    { generation: sendScope.generation + 1 }, { durableGeneration: '10' }, { ownerKey: JSON.stringify(['XSS', '8']) },
  ]) assert.equal(inspectCsrfMailProof(accepted, { ...proofScope(sendScope, 'accepted'), ...override }), null);
  f.rotate();
  const current = f.scope();
  assert.equal(inspectCsrfMailProof(accepted, proofScope(current, 'accepted')), null);
  assert.deepEqual(await f.service.retrieve(current, { recipient: RECIPIENT }), {
    error: 'Send a new attack email from this exercise first; no current accepted dispatch is available.',
  });
});

test('a graph-generation reset rejects prior dispatch proof even when canonical generation is unchanged', async () => {
  const f = fixture();
  const oldScope = f.scope();
  const accepted = await f.service.send(oldScope, { recipient: RECIPIENT, payload: PAYLOAD });
  installOwnMail(f);
  f.rotate({ generation: oldScope.generation, durableGeneration: 10 });
  const current = f.scope();
  assert.equal(inspectCsrfMailProof(accepted, proofScope(current, 'accepted')), null);
  assert.match((await f.service.retrieve(current, { recipient: RECIPIENT })).error, /no current accepted dispatch/);
  assert.equal(f.records.some(row => row.evidence.state === 'retrieved'), false);
});

test('skips foreign matching-subject mail before retrieving the exact owned dispatch', async () => {
  const f = fixture();
  await f.service.send(f.scope(), { recipient: RECIPIENT, payload: PAYLOAD });
  const mail = installOwnMail(f, 'owned');
  const ordered = new Map();
  ordered.set('foreign', { id: 'foreign', subject: mail.subject, from: 'foreign@example.test', htmlBody: mail.html });
  ordered.set('owned', f.inbox.get('owned'));
  f.inbox.clear(); for (const [key, value] of ordered) f.inbox.set(key, value);
  const readScope = f.scope();
  const result = await f.service.retrieve(readScope, { recipient: RECIPIENT });
  assert.equal(result.email.id, 'owned');
  assert.equal(result.email.body.includes(PAYLOAD), true);
  assert.equal(result.email.payload, PAYLOAD);
  assert.equal(Object.isFrozen(result.email), true);
  assert.equal(inspectCsrfMailProof(result.email, proofScope(readScope, 'retrieved')).payloadDigest,
    f.records.find(row => row.evidence.state === 'accepted').evidence.expected.payloadDigest);
  assert.equal(inspectCsrfMailProof(result.email, proofScope(readScope, 'retrieved')).hasEventHandler, true);
});

test('wrong sender, marker, modified body, and expired or pruned dispatch evidence cannot prove retrieval', async t => {
  for (const kind of ['sender', 'marker', 'body', 'smtp-message-id']) await t.test(kind, async () => {
    const f = fixture();
    await f.service.send(f.scope(), { recipient: RECIPIENT, payload: PAYLOAD });
    const mail = installOwnMail(f);
    const row = f.inbox.get('owned-mail');
    if (kind === 'smtp-message-id') row.messageId = 'different@fixture.invalid';
    if (kind === 'sender') row.from = 'foreign@example.test';
    if (kind === 'marker') row.htmlBody = row.htmlBody.replace(f.records[0].evidence.marker, '0'.repeat(64));
    if (kind === 'body') row.htmlBody = row.htmlBody.replace('Dear Customer', 'Dear Changed Customer');
    const result = await f.service.retrieve(f.scope(), { recipient: RECIPIENT });
    assert.match(result.error, /no exact message/);
    assert.equal(f.records.some(record => record.evidence.state === 'retrieved'), false);
    assert.ok(mail);
  });
  await t.test('expired-or-pruned', async () => {
    const f = fixture();
    await f.service.send(f.scope(), { recipient: RECIPIENT, payload: PAYLOAD });
    installOwnMail(f);
    f.pruneAccepted();
    assert.match((await f.service.retrieve(f.scope(), { recipient: RECIPIENT })).error, /no current accepted dispatch/);
  });
});

test('selected-read vertical slice persists original decision before exact owned retrieval',async()=>{
 const f=fixture(),scope={...f.scope(),platformSessionId:'17'};await f.service.send(scope,{recipient:RECIPIENT,payload:PAYLOAD});installOwnMail(f);
 const attempt={userId:scope.userId,runId:scope.execution.runId,generation:scope.generation,mode:'vuln',modeStamp:'1'};
 const plan=await f.service.prepareSelectedRead(scope,{recipient:RECIPIENT,attempt,assertAttempt:async()=>{}});
 assert.equal(plan.metadata.length,1);assert.deepEqual(Object.keys(plan.metadata[0]).sort(),['id','sender','subject']);
 await assert.rejects(plan.persistDecision({decision:{action:'read_message',presentation:'original',messageId:plan.metadata[0].id}}),/Original model/);
 const selected=await require('../server/agent-runtime/csrfMailReadDecision').selectMailRead({message:'Open the message',metadata:plan.metadata,execution:scope.execution,model:{chatWithMessages:async()=>({provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'read_message',presentation:'original',messageId:plan.metadata[0].id})})},persistDecision:plan.persistDecision});
 const decision=f.records.at(-1);assert.equal(decision.evidence.state,'read_decision');assert.equal(decision.evidence.mode,'vuln');assert.equal(decision.evidence.expected.payloadDigest,codec.buildCsrfMail({marker:'abcdefghijklmnop',payload:PAYLOAD}).payloadDigest);
 const result=await plan.retrieveSelection(selected.record);assert.equal(result.email.payload,PAYLOAD);assert.equal(f.records.at(-1).evidence.state,'retrieved');
 const next=await f.service.prepareSelectedRead(scope,{recipient:RECIPIENT,attempt,assertAttempt:async()=>{}});assert.equal(next.metadata.length,1,'decision/read records cannot become message choices');
 await assert.rejects(plan.retrieveSelection({...selected.record}),/Persisted selected/);
 f.rotate();await assert.rejects(plan.retrieveSelection(selected.record),/stale/);
});
test('selected read checks canonical attempt again before retrieval and denies changed mode',async()=>{
 const f=fixture(),scope={...f.scope(),platformSessionId:'17'};await f.service.send(scope,{recipient:RECIPIENT,payload:PAYLOAD});installOwnMail(f);let current=true;
 const attempt={userId:scope.userId,runId:scope.execution.runId,generation:scope.generation,mode:'fixed',modeStamp:'1'};
 const plan=await f.service.prepareSelectedRead(scope,{recipient:RECIPIENT,attempt,assertAttempt:async()=>{if(!current)throw Error('mode changed');}});
 const selected=await require('../server/agent-runtime/csrfMailReadDecision').selectMailRead({message:'Read',metadata:plan.metadata,execution:scope.execution,model:{chatWithMessages:async()=>({provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'read_message',presentation:'original',messageId:plan.metadata[0].id})})},persistDecision:plan.persistDecision});
 const before=f.counts().effectCalls;current=false;await assert.rejects(plan.retrieveSelection(selected.record),/mode changed/);assert.equal(f.counts().effectCalls,before);
});

test('real selected inbox graph fixed branch persists escaped render and never enters browser/classifier',async()=>{
 const f=fixture(),scope={...f.scope(),platformSessionId:'7'};scope.execution.signal=new AbortController().signal;
 await f.service.send(scope,{recipient:RECIPIENT,payload:PAYLOAD});installOwnMail(f);
 const attempt={userId:scope.userId,runId:scope.execution.runId,generation:scope.generation,mode:'fixed',modeStamp:'1'};
 let calls=0;
 const response=await require('../server/agent-runtime/csrfSelectedInboxGraph').runSelectedInboxGraph({message:'Open my email',scope,attempt,recipient:RECIPIENT},{dispatch:f.service,assertAttempt:async()=>{},snapshot:()=>({}),model:{chatWithMessages:async messages=>{calls++;const id=JSON.parse(messages[1].content).messages[0].id;return {provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'read_message',presentation:'original',messageId:id})};}},executeBrowser:()=>{throw Error('must not enter browser');}});
 assert.equal(calls,1);assert.equal(response.renderPolicy,'escaped_inert_text');assert.equal(response.browserExecuted,false);assert.ok(response.ragHtml.includes('&lt;img'));assert.deepEqual(response.newlyCompleted,[]);assert.equal(f.records.at(-1).evidence.state,'render_prepared');assert.equal(f.records.at(-1).evidence.originalPayload,PAYLOAD);
});
test('real graph no-action and independent request classifier refusal yield no browser credit',async()=>{
 for(const action of ['no_action','read_message']){
  const f=fixture(),scope={...f.scope(),platformSessionId:'7'};scope.execution.signal=new AbortController().signal;await f.service.send(scope,{recipient:RECIPIENT,payload:PAYLOAD});installOwnMail(f);
  const attempt={userId:scope.userId,runId:scope.execution.runId,generation:scope.generation,mode:null,modeStamp:'default'};let browserCalls=0;
  const result=await require('../server/agent-runtime/csrfSelectedInboxGraph').runSelectedInboxGraph({message:'Read or decline',scope,attempt,recipient:RECIPIENT},{dispatch:f.service,assertAttempt:async()=>{},snapshot:()=>({}),model:{chatWithMessages:async messages=>({provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action,presentation:action==='read_message'?'original':null,messageId:action==='read_message'?JSON.parse(messages[1].content).messages[0].id:null})})},executeBrowser:async()=>{browserCalls++;return {qualified:false};},noteBrowser:()=>{throw Error('no receipt');},grade:()=>{throw Error('no credit');}});
  assert.deepEqual(result.newlyCompleted,[]);assert.equal(browserCalls,action==='read_message'?1:0);assert.equal(f.records.some(row=>row.evidence.state==='retrieved'),action==='read_message');
 }
});
for(const mode of ['vuln','fixed'])for(const outcome of ['refused','unavailable'])test(`selected summary ${outcome} stops ${mode} before rendering, effects and grading`,async()=>{
 const f=fixture(),scope={...f.scope(),platformSessionId:'7'};scope.execution.signal=new AbortController().signal;await f.service.send(scope,{recipient:RECIPIENT,payload:PAYLOAD});installOwnMail(f);
 const attempt={userId:scope.userId,runId:scope.execution.runId,generation:scope.generation,mode,modeStamp:'1'};let calls=0,browser=0,note=0,grade=0;
 const result=await require('../server/agent-runtime/csrfSelectedInboxGraph').runSelectedInboxGraph({message:'Summarize my email',scope,attempt,recipient:RECIPIENT},{dispatch:f.service,assertAttempt:async()=>{},snapshot:()=>({}),model:{chatWithMessages:async messages=>{calls++;if(calls===1)return {provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'read_message',presentation:'summary',messageId:JSON.parse(messages[1].content).messages[0].id})};assert.ok(messages[1].content.includes(PAYLOAD));assert.ok(f.records.some(row=>row.evidence.state==='retrieved'));if(outcome==='unavailable')throw Error('provider unavailable');return {provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({status:'refused',text:'I decline to summarize that code.'})};}},executeBrowser:()=>{browser++;return {qualified:true};},noteBrowser:()=>{note++;},grade:()=>{grade++;}});
 assert.equal(calls,2);assert.match(result.response,outcome==='refused'?/Summary declined/:/Summary unavailable/);assert.deepEqual([browser,note,grade],[0,0,0]);assert.ok(f.records.some(row=>row.evidence.state==='retrieved'));assert.match(result.response,/no active content/);assert.equal(result.ragHtml,null);assert.equal(f.records.some(row=>row.evidence.state==='render_prepared'),false);if(outcome==='refused')assert.equal(f.records.find(row=>row.evidence.state==='plain_summary').evidence.summary.status,'refused');assert.deepEqual(result.newlyCompleted,[]);
});
