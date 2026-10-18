'use strict';

const { randomBytes, randomUUID } = require('node:crypto');
const { canonicalDurableGeneration } = require('../agent-runtime/durableGeneration');
const proofs = new WeakMap();
const selectedReads = new WeakMap();
async function inspectSelectedMailRead(proof,{execution,retrievedMail}={}){
 const authority=selectedReads.get(proof);if(!authority||authority.execution!==execution||authority.email!==retrievedMail)return null;
 await authority.fence();return authority.renderingRecord?freezeRecord({...authority.record,rendering:authority.renderingRecord}):null;
}
const WORKSHOP = 'csrf_workshop';
const SCENARIO = 'csrf_email_dispatch';
const EVENT_HANDLER = /on(?:error|load|focus|toggle|mouseover|click)\s*=/i;
function freezeRecord(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freezeRecord);
    Object.freeze(value);
  }
  return value;
}

function inspectCsrfMailProof(value, scope) {
  const proof = value && typeof value === 'object' ? proofs.get(value) : null;
  let proofGeneration;
  let expectedGeneration;
  try {
    proofGeneration = canonicalDurableGeneration(proof?.durableGeneration);
    expectedGeneration = canonicalDurableGeneration(scope?.durableGeneration);
  } catch {
    return null;
  }
  if (!proof || proof.kind !== scope.kind || proof.userId !== String(scope.userId)
    || proof.generation !== scope.generation || proof.runId !== scope.runId
    || proof.ownerKey !== scope.ownerKey || proofGeneration !== expectedGeneration) return null;
  return proof;
}

function createCsrfEmailDispatch({ repository, transport, mailbox, codec, expectedSender = transport?.getStatus?.().targetEmail }) {
  if (!repository?.append || !repository?.list || !transport?.sendEmail || !mailbox?.fetchEmails
    || !mailbox?.fetchEmail || !mailbox?.canonicalize || !codec?.buildCsrfMail || !codec?.validateRetrievedMail) {
    throw new TypeError('Explicit durable mail evidence, transport, mailbox and codec are required');
  }
  if (typeof expectedSender !== 'string' || !/^[^\s@<>]+@[^\s@<>]+$/.test(expectedSender)) throw new TypeError('Configured SMTP sender required');
  expectedSender = expectedSender.toLowerCase();
  async function check(scope) {
    const { execution, userId, generation } = scope;
    let durableGeneration;
    try { durableGeneration = canonicalDurableGeneration(execution?.durableGeneration); } catch {}
    if (!Number.isSafeInteger(Number(userId)) || Number(userId) <= 0
      || !Number.isInteger(generation) || generation < 0 || !execution?.runId
      || execution.ownerKey !== JSON.stringify(['CSRF', String(userId)])
      || durableGeneration === undefined
      || typeof execution.check !== 'function' || typeof execution.effect !== 'function') {
      throw new Error('Authenticated durable CSRF execution is required');
    }
    await execution.check();
    return durableGeneration;
  }
  const repositoryScope = scope => ({ userId: scope.userId, workshopKey: WORKSHOP,
    scenario: SCENARIO, generation: scope.generation, runId: scope.execution.runId });
  async function append(scope, evidenceID, evidence) {
    await check(scope);
    const row = await repository.append({ ...repositoryScope(scope), evidenceID, evidence });
    await check(scope);
    if (!row || row.omitted || !row.evidence) throw new Error('Mail provenance could not be persisted');
    return row;
  }
  function prove(value, kind, scope, evidence) {
    const durableGeneration = canonicalDurableGeneration(scope.execution.durableGeneration);
    proofs.set(value, freezeRecord({ ...JSON.parse(JSON.stringify(evidence)), kind, userId: String(scope.userId),
      generation: scope.generation, runId: scope.execution.runId, ownerKey: scope.execution.ownerKey,
      durableGeneration }));
    return Object.freeze(value);
  }
  async function acceptedDispatches(scope, recipient) {
    const durableGeneration=await check(scope),canonicalRecipient=mailbox.canonicalize(recipient);
    const rows=await repository.list({...repositoryScope(scope),limit:100});await check(scope);
    const dispatches=rows.filter(row=>!row.omitted&&row.generation===scope.generation
      &&row.evidence?.state==='accepted'&&row.evidence.recipient===canonicalRecipient
      &&row.evidence.ownerKey===scope.execution.ownerKey&&row.runId===row.evidence.dispatchRunId
      &&(()=>{try{return canonicalDurableGeneration(row.evidence.durableGeneration)===durableGeneration;}catch{return false;}})()).map(row=>row.evidence).reverse();
    return {canonicalRecipient,dispatches};
  }
  const thisService = {
    async prepareSelectedRead(scope,{recipient,attempt,assertAttempt}) {
      if(typeof scope.platformSessionId!=='string'||!/^[1-9][0-9]{0,18}$/.test(scope.platformSessionId)||typeof assertAttempt!=='function'||!attempt||![null,'vuln','fixed'].includes(attempt.mode)||attempt.modeStamp==null||String(attempt.userId)!==String(scope.userId)||attempt.runId!==scope.execution.runId||attempt.generation!==scope.generation)throw Error('Canonical mail attempt required');
      const admittedSession=scope.platformSessionId,admittedExecution=scope.execution,admittedRun=scope.execution.runId,admittedOwner=scope.execution.ownerKey,admittedGeneration=scope.generation;
      const fence=async()=>{if(scope.platformSessionId!==admittedSession||scope.execution!==admittedExecution||scope.execution.runId!==admittedRun||scope.execution.ownerKey!==admittedOwner||scope.generation!==admittedGeneration)throw Error('Admitted mail scope changed');await check(scope);await assertAttempt(attempt);await check(scope);};
      await fence();const {canonicalRecipient,dispatches}=await acceptedDispatches(scope,recipient);await fence();
      const selected=new Map();for(const row of dispatches){if(!selected.has(row.dispatchId))selected.set(row.dispatchId,row);}
      if(selected.size>8)throw Error('Owned mail selection exceeds eight current dispatches');
      const metadata=freezeRecord([...selected.values()].map(row=>({id:row.dispatchId,subject:row.subject,sender:row.sender})));
      let admitted,observedMail,observedAuthority;
      return Object.freeze({metadata,
        async persistDecision(record){
          await fence();if(!require('../agent-runtime/csrfMailReadDecision').inspectDecision(record,scope.execution))throw Error('Original model decision required');
          const row=record.decision.action==='read_message'?selected.get(record.decision.messageId):null;
          if(record.decision.action==='read_message'&&!row)throw Error('Foreign mail selection');
          const evidence={version:2,state:'read_decision',...record,ownerKey:scope.execution.ownerKey,durableGeneration:canonicalDurableGeneration(scope.execution.durableGeneration),mode:attempt.mode,modeStamp:attempt.modeStamp,platformSessionId:scope.platformSessionId,dispatchId:row?.dispatchId||null,expected:row?.expected||null};
          if(Buffer.byteLength(JSON.stringify(evidence))>15000)throw Error('Mail decision evidence exceeds bound');
          const receipt=await append(scope,'decision_'+randomUUID(),evidence);await fence();
          admitted={record,row,receipt};return freezeRecord({evidenceID:receipt.evidenceID,dispatchId:row?.dispatchId||null});
        },
        async persistSummary(record,summary){
          await fence();if(!admitted||record!==admitted.record||record.decision.presentation!=='summary'||!observedMail
            ||!require('../agent-runtime/csrfMailPlainSummary').isCapturedSummary(summary)
            ||summary.sourceSha256!==require('node:crypto').createHash('sha256').update(observedMail.body).digest('hex'))throw Error('Original selected summary required');
          const evidence={version:2,state:'plain_summary',decisionEvidenceID:admitted.receipt.evidenceID,dispatchId:admitted.row.dispatchId,platformSessionId:scope.platformSessionId,mode:attempt.mode,modeStamp:attempt.modeStamp,summary};
          if(Buffer.byteLength(JSON.stringify(evidence))>15000)throw Error('Mail summary evidence exceeds bound');
          const row=await append(scope,'summary_'+randomUUID(),evidence);await fence();return {evidenceID:row.evidenceID};
        },
        async recordRendering(record,rendering){
          await fence();if(!admitted||record!==admitted.record||!observedMail||!require('./csrfMailRendering').validateRendering(rendering,{body:observedMail.payload,mode:attempt.mode??'vuln'}))throw Error('Original owned rendering required');
          const evidence={version:2,state:'render_prepared',decisionEvidenceID:admitted.receipt.evidenceID,
            dispatchId:admitted.row.dispatchId,platformSessionId:scope.platformSessionId,mode:attempt.mode,modeStamp:attempt.modeStamp,
            sourceField:'payload',originalPayload:observedMail.payload,rendering};
          if(Buffer.byteLength(JSON.stringify(evidence))>15000)throw Error('Mail rendering evidence exceeds bound');
          const row=await append(scope,'render_'+randomUUID(),evidence);await fence();observedAuthority.renderingRecord=freezeRecord({evidenceID:row.evidenceID,sourceField:'payload',version:rendering.version,mode:attempt.mode,policy:rendering.policy,originalSha256:rendering.originalSha256,renderedSha256:rendering.renderedSha256});return Object.freeze({evidenceID:row.evidenceID,policy:rendering.policy});
        },
        async retrieveSelection(record){
          await fence();if(!admitted||admitted.record!==record||!admitted.row||record.decision.action!=='read_message')throw Error('Persisted selected read required');
          const current=await acceptedDispatches(scope,canonicalRecipient);await fence();
          const row=current.dispatches.find(row=>row.dispatchId===admitted.row.dispatchId);
          if(!row||JSON.stringify(row)!==JSON.stringify(admitted.row))throw Error('Selected delivery changed');
          const result=await scope.execution.effect('email_selected_read_'+scope.execution.runId+'_'+admitted.row.dispatchId,()=>thisService.retrieve(scope,{recipient:canonicalRecipient,dispatchId:admitted.row.dispatchId}));
          await fence();
          if(!result?.email)return result;
          observedMail=result.email;
          const proof=Object.freeze(Object.create(null));
          const capturedRecord=freezeRecord({version:2,selection:admitted.record,decisionEvidenceID:admitted.receipt.evidenceID,
            dispatchId:admitted.row.dispatchId,expected:admitted.row.expected,mode:attempt.mode,modeStamp:attempt.modeStamp,
            platformSessionId:scope.platformSessionId,runId:scope.execution.runId,ownerKey:scope.execution.ownerKey,generation:scope.generation,
            durableGeneration:canonicalDurableGeneration(scope.execution.durableGeneration)});
          observedAuthority={execution:scope.execution,email:result.email,fence,record:capturedRecord,renderingRecord:null};
          selectedReads.set(proof,observedAuthority);
          return Object.freeze({...result,selectedRead:proof});
        }
      });
    },
    async send(scope, { recipient, payload }) {
      const durableGeneration = await check(scope);
      const canonicalRecipient = mailbox.canonicalize(recipient);
      const dispatchId = randomUUID();
      const marker = randomBytes(32).toString('hex');
      const mail = codec.buildCsrfMail({ marker, payload });
      const pending = { version: 1, dispatchId, state: 'pending', marker,
        recipient: canonicalRecipient, sender: expectedSender, ownerKey: scope.execution.ownerKey,
        durableGeneration, dispatchRunId: scope.execution.runId,
        expected: mail.expected, subject: mail.subject, hasEventHandler: EVENT_HANDLER.test(payload) };
      await append(scope, `mail_${dispatchId}_pending`, pending);
      // A started effect is never automatically repeated after a timeout or crash.
      // If acceptance cannot be durably recorded, pending means outcome unknown.
      const result = await scope.execution.effect(`email_dispatch_${dispatchId}`, () =>
        transport.sendEmail(canonicalRecipient, mail.subject, mail.body, String(scope.userId), { html: mail.html }));
      await check(scope);
      if (result?.smtpAccepted !== true || typeof result.messageId !== 'string' || !result.messageId.trim()
        || result.sentTo !== canonicalRecipient || String(result.sentFrom || '').toLowerCase() !== expectedSender
        || !Array.isArray(result.accepted) || result.accepted.length !== 1 || result.accepted[0] !== canonicalRecipient
        || !Array.isArray(result.rejected) || result.rejected.length !== 0) {
        throw new Error('SMTP acceptance evidence is missing; delivery is unconfirmed');
      }
      const accepted = { ...pending, state: 'accepted', providerMessageId: result.messageId,
        sender: result.sentFrom, accepted: result.accepted, rejected: result.rejected };
      await append(scope, `mail_${dispatchId}_accepted`, accepted);
      return prove({ success: true, canonicalRecipient, configuredRecipient: canonicalRecipient,
        payload, providerReceipt: result.messageId, smtpAccepted: true }, 'accepted', scope, accepted);
    },
    async retrieve(scope, { recipient, dispatchId }) {
      const durableGeneration = await check(scope);
      const canonicalRecipient = mailbox.canonicalize(recipient);
      const rows = await repository.list({ ...repositoryScope(scope), limit: 100 });
      await check(scope);
      const dispatches = rows.filter(row => !row.omitted && row.generation === scope.generation
        && row.evidence?.state === 'accepted' && row.evidence.recipient === canonicalRecipient
        && row.evidence.ownerKey === scope.execution.ownerKey
        && (() => { try { return canonicalDurableGeneration(row.evidence.durableGeneration) === durableGeneration; } catch { return false; } })()
        && row.runId === row.evidence.dispatchRunId).map(row => row.evidence).reverse();
      if (!dispatches.length) return { error: 'Send a new attack email from this exercise first; no current accepted dispatch is available.' };
      const listing = await mailbox.fetchEmails(canonicalRecipient, false);
      await check(scope);
      if (listing?.success !== true || !Array.isArray(listing.emails)) throw new Error('Inbox query failed');
      for (const dispatch of dispatches.filter(row=>dispatchId===undefined||row.dispatchId===dispatchId)) {
        const candidates = listing.emails.filter(email => email.subject === dispatch.subject);
        for (const candidate of candidates.slice(0, 20)) {
          const fetched = await mailbox.fetchEmail(canonicalRecipient, candidate.id);
          await check(scope);
          if (fetched?.success !== true || !fetched.email) continue;
          const email = fetched.email;
          if (String(email.id) !== String(candidate.id) || email.subject !== dispatch.subject
            || String(email.from || '').trim().toLowerCase() !== String(dispatch.sender).trim().toLowerCase()) continue;
          // Mailpit exposes the original SMTP Message-ID separately from its
          // internal inbox ID. Bind it when available; external APIs may omit it.
          const normalizeMessageId = value => String(value || '').trim().replace(/^<(.*)>$/, '$1');
          if (Object.hasOwn(email, 'messageId')
            && normalizeMessageId(email.messageId) !== normalizeMessageId(dispatch.providerMessageId)) continue;
          const decoded = codec.validateRetrievedMail({ htmlBody: email.htmlBody, expected: dispatch.expected });
          if (!decoded.valid) continue;
          const observation = { version: 1, state: 'retrieved', dispatchId: dispatch.dispatchId,
            dispatchRunId: dispatch.dispatchRunId, providerMessageId: dispatch.providerMessageId,
            inboxMessageId: String(email.id), recipient: canonicalRecipient, sender: dispatch.sender,
            expected: dispatch.expected, hasEventHandler: dispatch.hasEventHandler === true, ...decoded.evidence };
          await append(scope, `read_${randomUUID()}`, observation);
          return { email: prove({ id: email.id, subject: email.subject, from: email.from,
            sender: email.from, body: decoded.body, payload: decoded.payload },
            'retrieved', scope, observation) };
        }
      }
      return { error: 'The inbox has no exact message matching your current exercise dispatch. Delivery may still be pending.' };
    },
  };
  return thisService;
}

let configured;
function getCsrfEmailDispatch() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw new Error('Authenticated email grading requires the PostgreSQL platform');
  if (!configured) configured = createCsrfEmailDispatch({
    repository: require('../database/postgres/objectiveEvidenceRepository').createObjectiveEvidenceRepository(
      require('./postgresPlatformStores').getPostgresPlatformStores().pool,
      { maxEntries: 100, maxBytes: 16000, retentionSeconds: 2592000 }),
    ...require('./xssMailProvider').getXssMailProvider(),
    codec: require('./csrfEmailCodec'),
  });
  return configured;
}

module.exports = { createCsrfEmailDispatch, getCsrfEmailDispatch, inspectCsrfMailProof, inspectSelectedMailRead };
