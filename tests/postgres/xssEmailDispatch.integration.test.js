'use strict';
const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request)) {
    throw new Error(`Working/SQLite database import forbidden: ${request}`);
  }
  return originalLoad.call(this, request, parent, isMain);
};

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createPool } = require('../../server/database/postgres');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const { createObjectiveEvidenceRepository } = require('../../server/database/postgres/objectiveEvidenceRepository');
const { createObjectiveJudgmentRepository } = require('../../server/database/postgres/objectiveJudgmentRepository');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { JUDGE_VERSION, prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
const { getObjectiveRubric } = require('../../server/config/objectiveRubrics');
const { createXssEmailDispatch, inspectXssMailProof } = require('../../server/services/xssEmailDispatch');
const codec = require('../../server/services/xssEmailCodec');

const runtimeUrl = process.env.PG_XSS_EMAIL_DISPATCH_RUNTIME_URL;
const migrationUrl = process.env.PG_XSS_EMAIL_DISPATCH_MIGRATION_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && runtimeUrl && migrationUrl;
const recipient = 'shared-owned@sharklasers.com';
const sender = 'indirectpromptinjection@gmail.com';

function assertOwnedUrl(value) {
  const url = new URL(value);
  assert.match(url.pathname, /^\/dvaia_test_xss_email_dispatch_identity$/);
  assert.equal(url.hostname, '127.0.0.1');
}

function acceptedResult(to, id) {
  return { smtpAccepted: true, messageId: id, sentTo: to, sentFrom: sender,
    requestedRecipient: to, accepted: [to], rejected: [], deliveryConfirmed: false };
}

function scopeFor(userId, generation, execution) { return { userId, generation, execution }; }
function proofScope(kind, userId, generation, execution) {
  return { kind, userId: String(userId), generation, runId: execution.runId,
    ownerKey: execution.ownerKey, durableGeneration: execution.durableGeneration };
}

function mailboxFixture(sent) {
  const messages = new Map();
  return {
    messages,
    canonicalize: value => String(value).trim().toLowerCase(),
    async fetchEmails() { return { success: true, emails: [...messages.values()].map(row => ({ id: row.id, subject: row.subject })) }; },
    async fetchEmail(_recipient, id) { const email = messages.get(String(id)); return email ? { success: true, email } : { success: false }; },
    installOwn(index, id) {
      const mail = sent[index];
      messages.set(id, { id, subject: mail.subject, from: sender, htmlBody: mail.html });
      return mail;
    },
  };
}

test('native XSS dispatch evidence binds accepted mail and retrieval to owner/run/generations and fences reset',
  { skip: !enabled }, async () => {
    assertOwnedUrl(runtimeUrl); assertOwnedUrl(migrationUrl);
    const pool = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_RUNTIME_URL');
    const migration = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_MIGRATION_URL');
    const leaseA = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_RUNTIME_URL');
    const leaseB = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_RUNTIME_URL');
    leaseA.options.max = 2; leaseB.options.max = 2;
    try {
      await initializeIdentityRepository(pool, migration);
      await seedWorkshopPlatform(migration);
      const identities = createIdentityRepository(pool);
      const passwordHash = await require('bcryptjs').hash('OwnedFixture@123', 4);
      const ownerA = await identities.createUser({ username: 'xss-mail-owner-a', email: 'xss-mail-a@fixture.invalid', passwordHash });
      const ownerB = await identities.createUser({ username: 'xss-mail-owner-b', email: 'xss-mail-b@fixture.invalid', passwordHash });
      const raceOwner = await identities.createUser({ username: 'xss-mail-race', email: 'xss-mail-race@fixture.invalid', passwordHash });
      const oldPacketOwner = await identities.createUser({ username: 'xss-mail-old-packet', email: 'xss-mail-old-packet@fixture.invalid', passwordHash });
      const progress = createWorkshopProgressRepository(pool);
      const judgments = createObjectiveJudgmentRepository(pool);
      const repository = createObjectiveEvidenceRepository(pool,
        { maxEntries: 100, maxBytes: 16000, retentionSeconds: 2592000 });
      const sent = [];
      const mailbox = mailboxFixture(sent);
      const transport = {
        async sendEmail(to, subject, body, owner, options) {
          sent.push({ to, subject, body, owner, html: options.html });
          return acceptedResult(to, `<accepted-${owner}-${sent.length}@fixture.invalid>`);
        },
      };
      const dispatch = createXssEmailDispatch({ repository, transport, mailbox, codec, expectedSender: sender });
      const coordinatorA = createRunCoordinator({ family: 'XSS', ledger: createPostgresRunLedger(pool, { leasePool: leaseA }) });
      const coordinatorB = createRunCoordinator({ family: 'XSS', ledger: createPostgresRunLedger(pool, { leasePool: leaseB }) });

      for (const oldJudgeVersion of ['2026-09-13.grounded-v12', '2026-09-13.grounded-v14', '2026-09-13.grounded-v15', '2026-09-13.grounded-v16', '2026-09-13.grounded-v17', '2026-09-13.grounded-v18']) {
      let oldUnavailable;
      await coordinatorA.run(oldPacketOwner.id, {}, async execution => {
        const rubric = getObjectiveRubric('xss_workshop', 'xss_e2', 'vuln');
        const prepared = prepareJudgeInput({ rubric, evidence: [{ id: 'old-valid-facts', source: 'server_observation', content: {
          objective_signal_detected: true, vulnerable_mode: true, server_receipt_valid: true,
        } }] });
        const evaluationId = randomUUID();
        const input = {
          userId: oldPacketOwner.id, evaluationId, workshopKey: 'xss_workshop', objectiveId: rubric.objectiveId,
          family: rubric.family, scenario: rubric.scenario, rubricVersion: rubric.version,
          evidenceDigest: prepared.evidenceDigest, runId: execution.runId, mode: rubric.mode,
          recovery: { packet: prepared.packet, judgeVersion: oldJudgeVersion,
            ownerKey: execution.ownerKey, ownerGeneration: execution.durableGeneration },
        };
        await judgments.beginEvaluation(input);
        await judgments.recordVerdict({ ...input, result: {
          family: rubric.family, scenario: rubric.scenario, objectiveId: rubric.objectiveId,
          rubricVersion: rubric.version, evidenceDigest: prepared.evidenceDigest, runId: execution.runId,
          mode: rubric.mode, verdict: 'unavailable', criteria: [], explanation: 'Fixture judge transport unavailable.',
          provider: null, model: null, judgeVersion: oldJudgeVersion, errorCode: 'JUDGE_TRANSPORT',
        } });
        oldUnavailable = { evaluationId, ownerGeneration: execution.durableGeneration };
      });
      assert.notEqual(JUDGE_VERSION, oldJudgeVersion, 'Historical packets must remain version-fenced');
      assert.equal((await judgments.listRecoverable({ userId: oldPacketOwner.id, judgeVersion: JUDGE_VERSION }))
        .find(row => row.evaluationId === oldUnavailable.evaluationId)?.canRetry, false);
      await assert.rejects(judgments.beginRetry({ userId: oldPacketOwner.id,
        evaluationId: oldUnavailable.evaluationId, judgeVersion: JUDGE_VERSION,
        ownerGeneration: oldUnavailable.ownerGeneration }), { code: 'JUDGE_VERSION_CHANGED' });
      const oldRecovery = await judgments.getRecovery({ userId: oldPacketOwner.id,
        evaluationId: oldUnavailable.evaluationId });
      assert.equal(oldRecovery.child_evaluation_id, null, 'A version-fenced retry creates no child evaluation');
      assert.equal((await pool.query(`SELECT count(*)::int n FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='xss_workshop'`, [oldPacketOwner.id])).rows[0].n, 0);
      }

      const accepted = new Map();
      for (const user of [ownerA, ownerB]) {
        await coordinatorA.run(user.id, {}, async execution => {
          const generation = await progress.getGeneration(user.id, 'xss_workshop');
          const value = await dispatch.send(scopeFor(user.id, generation, execution), {
            recipient, payload: `<img src=x onerror="globalThis.owner=${user.id}">`,
          });
          assert.equal(inspectXssMailProof(value, proofScope('accepted', user.id, generation, execution)).state, 'accepted');
          accepted.set(user.id, { value, execution: { ...execution }, generation });
        });
      }
      const rows = await pool.query(`SELECT e.evidence_id,e.run_id,e.generation,e.evidence_json,r.owner_key,r.generation AS graph_generation
        FROM workshop_platform.objective_evidence e JOIN graph_runtime.runs r ON r.run_id=e.run_id
        WHERE e.workshop_key='xss_workshop' AND e.scenario='xss_email_dispatch' ORDER BY e.id`);
      assert.equal(rows.rowCount, 4);
      for (const user of [ownerA, ownerB]) {
        const owned = rows.rows.filter(row => row.owner_key === JSON.stringify(['XSS', String(user.id)]));
        assert.deepEqual(owned.map(row => row.evidence_json.state), ['pending', 'accepted']);
        assert.equal(new Set(owned.map(row => row.run_id)).size, 1);
        assert.equal(new Set(owned.map(row => String(row.graph_generation))).size, 1);
        assert.equal(owned[0].evidence_json.dispatchId, owned[1].evidence_json.dispatchId);
      }

      // A foreign message with the exact opaque subject is examined first, but
      // sender/body validation skips it and reaches this owner's real message.
      const ownerAMail = mailbox.installOwn(0, 'owner-a-mail');
      mailbox.messages.clear();
      mailbox.messages.set('foreign-first', { id: 'foreign-first', subject: ownerAMail.subject,
        from: 'foreign@example.invalid', htmlBody: ownerAMail.html });
      mailbox.messages.set('owner-a-mail', { id: 'owner-a-mail', subject: ownerAMail.subject,
        from: sender, htmlBody: ownerAMail.html });
      await coordinatorA.run(ownerA.id, {}, async execution => {
        const generation = await progress.getGeneration(ownerA.id, 'xss_workshop');
        const result = await dispatch.retrieve(scopeFor(ownerA.id, generation, execution), { recipient });
        assert.equal(result.email.id, 'owner-a-mail');
        const proof = inspectXssMailProof(result.email, proofScope('retrieved', ownerA.id, generation, execution));
        assert.equal(proof.dispatchRunId, accepted.get(ownerA.id).execution.runId);
        assert.equal(proof.payloadDigest, rows.rows.find(row => row.owner_key === JSON.stringify(['XSS', String(ownerA.id)])
          && row.evidence_json.state === 'accepted').evidence_json.expected.payloadDigest);
      });
      assert.equal((await pool.query("SELECT count(*)::int n FROM workshop_platform.objective_evidence WHERE evidence_json->>'state'='retrieved'")).rows[0].n, 1);

      let releaseTransport;
      let reportTransport;
      const transportEntered = new Promise(resolve => { reportTransport = resolve; });
      const transportRelease = new Promise(resolve => { releaseTransport = resolve; });
      let raceSends = 0;
      const raceDispatch = createXssEmailDispatch({ repository, mailbox, codec, expectedSender: sender, transport: {
        async sendEmail(to) { raceSends++; reportTransport(); await transportRelease; return acceptedResult(to, '<race@fixture.invalid>'); },
      } });
      const raceRun = coordinatorA.run(raceOwner.id, {}, async execution => {
        const generation = await progress.getGeneration(raceOwner.id, 'xss_workshop');
        return raceDispatch.send(scopeFor(raceOwner.id, generation, execution), { recipient, payload: '<svg onload="globalThis.race=1">' });
      });
      await transportEntered;
      const reset = coordinatorB.reset(raceOwner.id, async () => {
        await progress.resetWorkshopProgress(raceOwner.id, 'xss_workshop');
      });
      const ownerKey = JSON.stringify(['XSS', String(raceOwner.id)]);
      for (let i = 0; i < 100; i++) {
        if (Number((await pool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [ownerKey])).rows[0]?.generation) === 1) break;
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      releaseTransport();
      await assert.rejects(raceRun, { name: 'AbortError' });
      await reset;
      assert.equal(raceSends, 1, 'the uncertain/reset path never resends automatically');
      const raceRows = await pool.query(`SELECT evidence_json->>'state' AS state FROM workshop_platform.objective_evidence
        WHERE user_id=$1 ORDER BY id`, [raceOwner.id]);
      assert.deepEqual(raceRows.rows.map(row => row.state), ['pending']);
      await coordinatorA.run(raceOwner.id, {}, async execution => {
        const generation = await progress.getGeneration(raceOwner.id, 'xss_workshop');
        assert.equal(generation, 1);
        const result = await raceDispatch.retrieve(scopeFor(raceOwner.id, generation, execution), { recipient });
        assert.match(result.error, /no current accepted dispatch/);
      });
      assert.equal((await pool.query(`SELECT count(*)::int n FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='xss_workshop'`, [raceOwner.id])).rows[0].n, 0);
      assert.equal((await pool.query(`SELECT count(*)::int n FROM workshop_platform.objective_evidence
        WHERE user_id=$1`, [raceOwner.id])).rows[0].n, 0, 'fresh-generation read prunes stale pending evidence');
    } finally {
      await Promise.allSettled([pool.end(), migration.end(), leaseA.end(), leaseB.end()]).then(results => {
        const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (failures.length) throw new AggregateError(failures, 'Native XSS dispatch pool cleanup failed');
      });
    }
  });

test('native dispatch uses owned Mailpit for two isolated owner inboxes and reset fences stale evidence', {
  skip: !enabled || process.env.XSS_EMAIL_DISPATCH_MAILPIT !== 'yes',
  timeout: 60000,
}, async () => {
  assertOwnedUrl(runtimeUrl); assertOwnedUrl(migrationUrl);
  assert.equal(process.env.MAILPIT_SMTP_HOST, '127.0.0.1');
  const smtpPort = Number(process.env.MAILPIT_SMTP_PORT);
  assert.ok(Number.isSafeInteger(smtpPort) && smtpPort > 0 && smtpPort <= 65535);
  const apiUrl = new URL(process.env.MAILPIT_API_URL);
  assert.equal(apiUrl.hostname, '127.0.0.1');
  assert.ok(Number.isSafeInteger(Number(apiUrl.port)) && Number(apiUrl.port) > 0);
  assert.equal(apiUrl.username, ''); assert.equal(apiUrl.password, '');
  assert.equal(apiUrl.protocol, 'http:');

  const pool = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_RUNTIME_URL');
  const migration = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_MIGRATION_URL');
  const lease = createPool(process.env, 'PG_XSS_EMAIL_DISPATCH_RUNTIME_URL');
  lease.options.max = 2;
  let mailbox;
  try {
    await initializeIdentityRepository(pool, migration);
    await seedWorkshopPlatform(migration);
    const identities = createIdentityRepository(pool);
    const passwordHash = await require('bcryptjs').hash('OwnedMailpitFixture@123', 4);
    const owners = await Promise.all(['a', 'b'].map(label => identities.createUser({
      username: `xss-mailpit-owner-${label}`, email: `xss-mailpit-${label}@fixture.invalid`, passwordHash,
    })));
    const progress = createWorkshopProgressRepository(pool);
    const repository = createObjectiveEvidenceRepository(pool,
      { maxEntries: 100, maxBytes: 16000, retentionSeconds: 2592000 });
    mailbox = require('../../server/services/xssLocalMail').createXssLocalMail({
      smtpHost: process.env.MAILPIT_SMTP_HOST, smtpPort,
      apiUrl: apiUrl.toString(), timeoutMs: 5000,
    });
    const dispatch = createXssEmailDispatch({ repository, transport: mailbox, mailbox, codec,
      expectedSender: mailbox.getStatus().targetEmail });
    const coordinator = createRunCoordinator({ family: 'XSS', ledger: createPostgresRunLedger(pool, { leasePool: lease }) });
    const sent = new Map();
    for (const owner of owners) {
      const address = `xss-${owner.id}@dvaia.invalid`;
      const payload = `<img src=x onerror="globalThis.mailpitOwner=${owner.id}">`;
      await coordinator.run(owner.id, {}, async execution => {
        const generation = await progress.getGeneration(owner.id, 'xss_workshop');
        const accepted = await dispatch.send(scopeFor(owner.id, generation, execution), { recipient: address, payload });
        const proof = inspectXssMailProof(accepted, proofScope('accepted', owner.id, generation, execution));
        assert.equal(proof.state, 'accepted');
        assert.equal(accepted.canonicalRecipient, address);
        sent.set(owner.id, { address, payload, providerMessageId: accepted.providerReceipt });
      });
    }
    assert.notEqual(sent.get(owners[0].id).providerMessageId, sent.get(owners[1].id).providerMessageId);

    for (const owner of owners) {
      const expected = sent.get(owner.id);
      await coordinator.run(owner.id, {}, async execution => {
        const generation = await progress.getGeneration(owner.id, 'xss_workshop');
        let retrieved;
        for (let attempt = 0; attempt < 20; attempt += 1) {
          retrieved = await dispatch.retrieve(scopeFor(owner.id, generation, execution), { recipient: expected.address });
          if (retrieved.email) break;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert.ok(retrieved?.email, retrieved?.error || 'owned message was not retrieved');
        assert.ok(retrieved.email.body.includes(expected.payload));
        const other = sent.get(owners.find(candidate => candidate.id !== owner.id).id);
        assert.equal(retrieved.email.body.includes(other.payload), false);
        const proof = inspectXssMailProof(retrieved.email,
          proofScope('retrieved', owner.id, generation, execution));
        assert.equal(proof.providerMessageId.replace(/[<>]/g, ''), expected.providerMessageId.replace(/[<>]/g, ''));
        assert.notEqual(proof.inboxMessageId, proof.providerMessageId,
          'Mailpit internal ID remains distinct from SMTP Message-ID');
      });
    }

    const resetOwner = owners[0];
    await coordinator.reset(resetOwner.id, async () => {
      await progress.resetWorkshopProgress(resetOwner.id, 'xss_workshop');
    });
    await coordinator.run(resetOwner.id, {}, async execution => {
      const generation = await progress.getGeneration(resetOwner.id, 'xss_workshop');
      assert.equal(generation, 1);
      const stale = await dispatch.retrieve(scopeFor(resetOwner.id, generation, execution), {
        recipient: sent.get(resetOwner.id).address,
      });
      assert.match(stale.error, /no current accepted dispatch/);
    });
    for (const owner of owners) {
      assert.equal((await pool.query(`SELECT count(*)::int n FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='xss_workshop'`, [owner.id])).rows[0].n, 0,
      'dispatch and retrieval evidence alone never grants objective credit');
    }
    const evidence = await pool.query(`SELECT user_id,evidence_json->>'state' state
      FROM workshop_platform.objective_evidence WHERE scenario='xss_email_dispatch'
      AND user_id=ANY($1::bigint[]) ORDER BY user_id,id`, [owners.map(owner => owner.id)]);
    assert.deepEqual(evidence.rows.filter(row => Number(row.user_id) === owners[0].id).map(row => row.state), [],
      'fresh-generation retrieval prunes the reset owner evidence');
    assert.deepEqual(evidence.rows.filter(row => Number(row.user_id) === owners[1].id).map(row => row.state),
      ['pending', 'accepted', 'retrieved']);
  } finally {
    await mailbox?.close?.();
    const results = await Promise.allSettled([pool.end(), migration.end(), lease.end()]);
    const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new AggregateError(failures, 'Native Mailpit dispatch cleanup failed');
  }
});
