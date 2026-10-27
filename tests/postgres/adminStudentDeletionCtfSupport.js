'use strict';
// Test-only, import-inert composition. Launcher owns stores; the canonical
// production singleton owns its dedicated delivery pool and shutdown.
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { canonicalCtfJson } = require('../../server/services/ctfLifecycleCommands');
const { validateCtfProjectionResult } = require('../../server/services/ctfProjectionResults');
const deletion = require('../../server/services/ctfDeletionContract');
const sha = value => createHash('sha256').update(value).digest('hex');
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHARED_TEXT = 'owned student deletion shared payload preservation fixture';
const SHARED_HASH = sha(SHARED_TEXT);
const MAX_ROWS = 256, MAX_BYTES = 1024 * 1024;
const MUTABLE = Object.freeze({ participants: ['ctf_participants', 'id'],
  judgments: ['ctf_judgments', 'participant_id'], attempts: ['ctf_attempts', 'participant_id'],
  progress: ['ctf_progress', 'participant_id'], techniques: ['ctf_technique_blocklist', 'participant_id'],
  leaderboard: ['ctf_leaderboard', 'participant_id'], events: ['ctf_events', 'participant_id'],
  sessions: ['ctf_sessions', 'participant_id'], bans: ['ctf_bans', 'user_id'] });
// Read-only equivalent of 0008 refresh_authorized_leaderboard's source SELECT.
// Never invokes the refresher; rankings include retained inactive leaderboard
// entries because the production rank UPDATE covers those entries too.
const LEADERBOARD_SELECT = `WITH scored AS (
 SELECT p.id AS participant_id,p.username,p.team_name,COALESCE(x.cnt,0)::integer AS total_stages_completed,
 COALESCE(x.elapsed,0)::bigint AS total_completion_time,COALESCE(x.average,0)::double precision AS average_stage_time,
 COALESCE(a.attempts,0)::integer AS total_attempts,
 CASE WHEN COALESCE(a.attempts,0)>0 THEN a.successes::double precision/a.attempts*100 ELSE 0 END AS success_rate,
 COALESCE(x.score,0)::integer AS total_score
 FROM ctf.ctf_participants p LEFT JOIN
 (SELECT pr.participant_id,COUNT(*) cnt,SUM(pr.completion_time) elapsed,AVG(pr.completion_time) average,
 SUM(GREATEST(0,(CASE WHEN pr.authorized_decision_id IS NULL THEN s.level_score ELSE pr.authorized_level_score END)-COALESCE(pr.hint_penalty_total,0))) score
 FROM ctf.ctf_progress pr JOIN ctf.ctf_stages s ON s.id=pr.stage_id WHERE pr.status='completed' GROUP BY pr.participant_id) x ON x.participant_id=p.id
 LEFT JOIN (SELECT participant_id,SUM(attempts_count) attempts,SUM(successful_attempts) successes FROM ctf.ctf_progress GROUP BY participant_id) a ON a.participant_id=p.id WHERE p.is_active=1
 ), ranked_source AS (
 SELECT * FROM scored UNION ALL
 SELECT l.participant_id,l.username,l.team_name,l.total_stages_completed,l.total_completion_time,l.average_stage_time,l.total_attempts,l.success_rate,l.total_score
 FROM ctf.ctf_leaderboard l WHERE NOT EXISTS(SELECT 1 FROM scored s WHERE s.participant_id=l.participant_id)
 ), ranked AS (SELECT *,rank() OVER(ORDER BY total_stages_completed DESC,total_score DESC,total_completion_time ASC)::integer AS rank_position FROM ranked_source)
 SELECT to_jsonb(r) AS row FROM ranked r WHERE participant_id=$1 ORDER BY participant_id LIMIT 257`;
function positive(value) { assert.match(String(value), /^[1-9][0-9]*$/); assert(BigInt(value) <= 2147483647n); return String(value); }
function pool(value) { assert.equal(typeof value?.query, 'function'); assert.equal(typeof value?.connect, 'function'); }
async function assertCtfPoolBindings(pools, env) {
  for (const [name, key] of [['identityRuntime', 'IDENTITY_DATABASE_URL'], ['identityMigration', 'IDENTITY_MIGRATION_DATABASE_URL'],
    ['ctfRuntime', 'CTF_DATABASE_URL'], ['ctfMigration', 'CTF_MIGRATION_DATABASE_URL']]) {
    pool(pools[name]); const expected = new URL(env[key]);
    const rows = (await pools[name].query('SELECT current_database() AS database,current_user AS role,session_user AS login')).rows;
    assert.equal(rows.length, 1); assert.deepEqual(rows[0], { database: decodeURIComponent(expected.pathname.slice(1)),
      role: decodeURIComponent(expected.username), login: decodeURIComponent(expected.username) });
  }
}
function admitCtfDelivery(env = process.env) {
  assert.equal(env, process.env, 'Singleton CTF composition requires the actual process environment');
  require('./adminStudentDeletionRenderedSupport').admitStores(env);
  const runtime = new URL(env.CTF_DATABASE_URL), delivery = new URL(env.CTF_DELIVERY_DATABASE_URL);
  assert.equal(delivery.protocol, 'postgresql:'); assert.equal(delivery.host, runtime.host);
  assert.equal(delivery.pathname, runtime.pathname); assert.equal(delivery.search, ''); assert.equal(delivery.hash, '');
  assert.equal(decodeURIComponent(delivery.username), 'dvaia_ctf_delivery');
  return true;
}
async function initializeDeletionCtf({ identityRuntime, identityMigration, ctfRuntime, ctfMigration,
  adapter, coordinator, env = process.env, signal }) {
  admitCtfDelivery(env);
  for (const value of [identityRuntime, identityMigration, ctfRuntime, ctfMigration]) pool(value);
  assert.equal(new Set([identityRuntime, identityMigration, ctfRuntime, ctfMigration]).size, 4);
  assert.equal(typeof adapter?.validateSession, 'function'); assert.equal(typeof coordinator?.run, 'function');
  const ownedSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000);
  ownedSignal.throwIfAborted();
  await assertCtfPoolBindings({ identityRuntime, identityMigration, ctfRuntime, ctfMigration }, env);
  const ctf = require('../../server/database/postgres/ctfDb').createCtfDb(ctfRuntime);
  // The launcher has already migrated all stores. Do not run initialization
  // or migration-role seed work again once a bootstrap fence exists.
  const control = (await ctfRuntime.query('SELECT state FROM ctf.bootstrap_control WHERE singleton')).rows[0];
  assert(control);
  if (control.state === 'open') {
    await ctf.initialize(ctfMigration);
    // All direct seed writes precede the real bootstrap fence. Never reopen it.
    const seed = require('../../server/database/postgres/ctfDb').createCtfDb(ctfMigration);
    for (const key of ['ctf_enabled', 'ctf_visible_to_students', 'ctf_registration_open']) await seed.updateConfig(key, 'true');
    await ctfMigration.query(`INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id)
      SELECT id,$1,$2,NULL FROM ctf.ctf_stages WHERE stage_number=9
      ON CONFLICT(stage_id,payload_hash) DO NOTHING`, [SHARED_HASH, SHARED_TEXT]);
    const repository = require('../../server/database/postgres/ctfAuthorityBootstrapRepository')
      .createCtfAuthorityBootstrapRepository({ identityPool: identityMigration, ctfPool: ctfMigration });
    const operationId = randomUUID();
    await require('../../server/services/ctfAuthorityBootstrap').createCtfAuthorityBootstrap({ repository })
      .prepare({ operationId, signal: ownedSignal });
    const operator = require('../../server/database/postgres/ctfDeliveryActivationOperator')
      .createCtfDeliveryActivationOperator({ identityMigrationPool: identityMigration, ctfMigrationPool: ctfMigration });
    const activationId = randomUUID();
    let result;
    for (let page = 0; page < 4; page++) {
      ownedSignal.throwIfAborted();
      result = await operator.activate({ activationId, bootstrapOperationId: operationId, pageBudget: 16 }, { signal: ownedSignal });
      if (!result.staged) break;
    }
    assert(result?.activation && result.trafficStarted === false, 'Bounded canonical activation must finish');
  } else assert.equal(control.state, 'prepared', 'Incomplete bootstrap is not repaired or replayed implicitly');
  // Prepared/active stores are verified, never re-seeded or re-activated.
  const activation = await require('../../server/database/postgres/ctfDeliveryActivation')
    .createCtfDeliveryActivation({ identityPool: identityRuntime, ctfPool: ctfRuntime }).loadCurrent({ signal: ownedSignal });
  const shared = (await ctfRuntime.query('SELECT normalized_snippet FROM ctf.ctf_payload_blocklist WHERE payload_hash=$1', [SHARED_HASH])).rows;
  assert.equal(shared.length, 1); assert.equal(shared[0].normalized_snippet, SHARED_TEXT);
  const production = require('../../server/services/ctfAuthorityProduction');
  try {
    const application = await production.initializeProductionCtfAuthority({ identityPool: identityRuntime,
      ctfPool: ctfRuntime, validateSession: adapter.validateSession.bind(adapter), coordinator, env, signal });
    assert.equal((await application.runtime.readiness({ signal: ownedSignal })).runtimeReady, true);
    return Object.freeze({ application, runtime: application.runtime, activation,
      close: production.closeProductionCtfAuthority, nativeVerified: false, canonicalCredit: false });
  } catch (error) {
    try { await production.closeProductionCtfAuthority(); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], 'CTF fixture initialization and owned shutdown failed'); }
    throw error;
  }
}
function identity(req) {
  assert.match(req?.headers?.authorization || '', /^Bearer [^\s]+$/);
  return { ownerId: positive(req.user?.id), sessionId: positive(req.identitySession?.id) };
}
async function registerDeletionCtfOwner({ runtime, req, signal }) {
  const binding = identity(req);
  const deadline = AbortSignal.timeout(15000), owned = signal ? AbortSignal.any([signal, deadline]) : deadline;
  owned.throwIfAborted();
  const wait = async work => {
    owned.throwIfAborted(); let onAbort;
    const aborted = new Promise((_, reject) => { onAbort = () => reject(owned.reason); owned.addEventListener('abort', onAbort, { once: true }); });
    try { return await Promise.race([work(), aborted]); }
    finally { owned.removeEventListener('abort', onAbort); }
  };
  let result = await wait(() => runtime.mutate({ req, kind: 'register', input: {}, signal: owned }));
  let operationId = null, recoveryReads = 0;
  while (result.status === 202 && recoveryReads < 4) {
    assert.match(result.body?.operationId || '', UUID);
    if (operationId !== null) assert.equal(result.body.operationId, operationId);
    operationId = result.body.operationId; owned.throwIfAborted(); recoveryReads++;
    result = await wait(() => runtime.recoverOperation({ req, operationId, signal: owned }));
  }
  assert.equal(result.status, 200, 'Registration unresolved; never submit a second registration');
  const participantId = positive(result.body?.participantId);
  assert.equal(typeof result.body.sessionToken, 'string'); assert(result.body.sessionToken.length > 0);
  // Do not retain bearer or teaching session tokens in fixture evidence.
  return Object.freeze({ ...binding, participantId, operationId, recoveryReads, mutationCalls: 1 });
}
async function boundedRows(pool, sql, args) {
  const result = (await pool.query(sql, args)).rows;
  assert(result.length <= MAX_ROWS && Buffer.byteLength(JSON.stringify(result)) <= MAX_BYTES, 'CTF evidence exceeds bound');
  return result;
}
async function readDeletionCtfOwner({ identityPool, ctfPool, registration }) {
  const ownerId = positive(registration.ownerId), participantId = positive(registration.participantId);
  positive(registration.sessionId);
  const read = (p, table, where, args) => boundedRows(p,
    `SELECT to_jsonb(t) AS row FROM ${table} t WHERE ${where} ORDER BY to_jsonb(t)::text LIMIT 257`, args);
  const mutable = {};
  for (const [key, [table, column]] of Object.entries(MUTABLE)) mutable[key] = await read(ctfPool,
    `ctf.${table}`, `${column}=$1`, [key === 'bans' ? ownerId : participantId]);
  const outbox = await read(identityPool, 'identity.ctf_outbox',
    "command->'scope'->>'ownerId'=$1 OR command->>'subjectId'=$1", [ownerId]);
  const operations = outbox.map(r => r.row.operation_id);
  const snapshot = { registration: structuredClone(registration), mutable, outbox,
    projections: await read(ctfPool, 'ctf.projection_receipts', 'operation_id=ANY($1::uuid[])', [operations]),
    binding: await read(identityPool, 'identity.ctf_participant_bindings', 'owner_id=$1', [ownerId]),
    reservations: await read(identityPool, 'identity.ctf_registration_reservations', 'owner_id=$1', [ownerId]),
    authority: await read(identityPool, 'identity.ctf_authority', 'scope_key=$1', ['owner:' + ownerId]),
    deletionCommands: await read(identityPool, 'identity.ctf_deletion_commands', 'subject_id=$1', [ownerId]),
    decisions: await read(identityPool, 'identity.ctf_decisions', 'owner_id=$1', [ownerId]),
    payload: await read(ctfPool, 'ctf.ctf_payload_blocklist', 'true', []),
    identityPayload: await read(identityPool, 'identity.ctf_adaptive_memory', "kind='payload'", []) };
  snapshot.leaderboardProjection = await boundedRows(ctfPool, LEADERBOARD_SELECT, [participantId]);
  assert(Buffer.byteLength(JSON.stringify(snapshot)) <= MAX_BYTES, 'Aggregate CTF snapshot exceeds bound');
  return snapshot;
}
function eventFor(row) {
  assert.equal(row.state, 'applied'); assert.equal(sha(row.canonical_command), row.command_hash);
  assert.deepEqual(JSON.parse(row.canonical_command), row.command);
  return { command: JSON.parse(row.canonical_command), canonicalCommand: row.canonical_command,
    commandHash: row.command_hash, sequence: String(row.sequence) };
}
function assertRegistration(snapshot) {
  const { ownerId, sessionId, participantId, operationId } = snapshot.registration;
  const matches = snapshot.outbox.filter(x => x.row.kind === 'register'); assert.equal(matches.length, 1);
  const row = matches[0].row, event = eventFor(row);
  assert.equal(event.command.scope.ownerId, ownerId); assert.equal(event.command.actorId, ownerId);
  assert.equal(String(row.session_id), sessionId); assert.equal(String(row.actor_id), ownerId);
  assert.equal(event.command.operationId, row.operation_id);
  if (operationId !== null) assert.equal(row.operation_id, operationId);
  const receipt = validateCtfProjectionResult({ ...event.command, commandHash: row.command_hash }, event.sequence, row.canonical_result, row.result_hash);
  assert.equal(receipt.value.data.participantId, participantId); assert.equal(receipt.value.data.active, true);
  const projections = snapshot.projections.filter(x => x.row.operation_id === row.operation_id);
  assert.equal(projections.length, 1);
  for (const key of ['kind', 'sequence', 'command_hash', 'canonical_result', 'result_hash'])
    assert.deepEqual(projections[0].row[key], row[key]);
  assert.equal(snapshot.reservations.length, 1);
  const reservation = snapshot.reservations[0].row;
  assert.equal(reservation.operation_id, row.operation_id); assert.equal(String(reservation.sequence), event.sequence);
  assert.equal(String(reservation.owner_id), ownerId); assert.equal(reservation.state, 'applied');
  assert(reservation.resolved_at);
  return row;
}
function assertDeletionCtf(before, after, siblingBefore, siblingAfter, { jobId }) {
  assert.match(jobId, UUID); assert.deepEqual(after.registration, before.registration);
  const { ownerId, participantId } = before.registration;
  assert.notEqual(ownerId, siblingBefore.registration.ownerId);
  assert.notEqual(participantId, siblingBefore.registration.participantId);
  const registrationRow = assertRegistration(before);
  assertRegistration(after); assertRegistration(siblingBefore);
  const { payload: siblingPayloadBefore, identityPayload: siblingIdentityBefore, leaderboardProjection: ignoredBefore, ...siblingRowsBefore } = structuredClone(siblingBefore);
  const { payload: siblingPayloadAfter, identityPayload: siblingIdentityAfter, leaderboardProjection: ignoredAfter, ...siblingRowsAfter } = structuredClone(siblingAfter);
  delete siblingRowsBefore.mutable.leaderboard; delete siblingRowsAfter.mutable.leaderboard;
  assert.deepEqual(siblingRowsAfter, siblingRowsBefore, 'Sibling CTF rows and receipts must be byte-equivalent');
  assert.deepEqual(siblingPayloadBefore, before.payload); assert.deepEqual(siblingPayloadAfter, after.payload);
  assert.deepEqual(siblingIdentityBefore, before.identityPayload); assert.deepEqual(siblingIdentityAfter, after.identityPayload);
  assert.equal(before.mutable.participants.length, 1);
  assert.equal(String(before.mutable.participants[0].row.id), participantId);
  assert.equal(String(before.mutable.participants[0].row.user_id), ownerId);
  assert(before.mutable.sessions.some(({ row }) => String(row.participant_id) === participantId
    && row.session_token === registrationRow.command.body.teachingSessionToken), 'Original registration must have its real teaching session');
  assert(before.mutable.events.some(({ row }) => String(row.participant_id) === participantId
    && row.event_type === 'new_participant'), 'Original registration event required');
  for (const key of Object.keys(MUTABLE)) assert.deepEqual(after.mutable[key], []);
  assert.deepEqual(after.decisions, before.decisions);
  assert.deepEqual(after.reservations, before.reservations);
  assert.deepEqual(before.deletionCommands, []); assert.equal(after.deletionCommands.length, 1);
  const commandLink = after.deletionCommands[0].row;
  assert.equal(commandLink.job_id, jobId); assert.equal(commandLink.operation_id, jobId);
  assert.equal(String(commandLink.subject_id), ownerId);
  const added = after.outbox.filter(x => !before.outbox.some(y => y.row.operation_id === x.row.operation_id));
  assert.equal(added.length, 1); const row = added[0].row, event = eventFor(row);
  deletion.validateEvent(event); assert.equal(row.operation_id, jobId); assert.equal(row.kind, 'student_delete');
  assert.equal(String(commandLink.sequence), event.sequence);
  assert.equal(event.command.jobId, jobId); assert.equal(event.command.subjectId, ownerId);
  assert.equal(event.command.participantId, participantId);
  assert.deepEqual(after.leaderboardProjection, [], 'Deleted target cannot remain in the derived ranking');
  assertSiblingLeaderboard(siblingBefore, siblingAfter, event.command.occurredAt);
  const receipt = deletion.validateReceipt(event, row.canonical_result, row.result_hash);
  for (const key of Object.keys(MUTABLE)) assert.equal(receipt.value.data.removed[key], before.mutable[key].length);
  for (const key of ['outbox', 'projections']) {
    assert.equal(after[key].length, before[key].length + 1);
    assert.deepEqual(after[key].filter(x => x.row.operation_id !== jobId), before[key]);
  }
  const projected = after.projections.find(x => x.row.operation_id === jobId)?.row; assert(projected);
  for (const key of ['kind', 'sequence', 'command_hash', 'canonical_result', 'result_hash']) assert.deepEqual(projected[key], row[key]);
  assert.equal(before.binding.length, 1); assert.equal(after.binding.length, 1);
  assert.equal(before.binding[0].row.active, true); assert.equal(before.binding[0].row.banned, false);
  assert.equal(String(before.binding[0].row.owner_id), ownerId);
  assert.equal(String(before.binding[0].row.participant_id), participantId);
  assert.deepEqual(after.binding[0].row, { ...before.binding[0].row, active: false, banned: true,
    applied_sequence: row.sequence, applied_operation_id: jobId });
  assert.equal(before.authority.length, 1); assert.equal(after.authority.length, 1);
  assert.equal(before.authority[0].row.scope_key, 'owner:' + ownerId);
  assert.equal(before.authority[0].row.lifecycle_state, 'ready');
  assert.equal(String(before.authority[0].row.owner_generation), event.command.generationBefore);
  assert.equal(String(after.authority[0].row.owner_generation), event.command.generationAfter);
  assert.deepEqual(after.authority[0].row, { ...before.authority[0].row,
    owner_generation: after.authority[0].row.owner_generation, lifecycle_state: 'blocked', pending_operation_id: null,
    blocked_operation_id: jobId, banned: true, failure_code: 'student_deleted' });
  assert(before.payload.length > 0 && before.identityPayload.length > 0, 'Shared payload witnesses must be populated');
  assert.deepEqual(after.identityPayload, before.identityPayload);
  assert.deepEqual(after.payload, before.payload.map(({ row: payload }) => ({ row: {
    ...payload, first_winner_participant_id: String(payload.first_winner_participant_id) === participantId
      ? null : payload.first_winner_participant_id } })));
  return { canonicalCredit: false, modelCalls: 0, nativeVerified: false, fullStoreCoverage: false,
    registeredThroughAuthority: true, targetDeleted: true, immutableRegistrationRetained: true,
    deletionReceiptValidated: true, siblingBusinessAndEvidenceUnchanged: true,
    siblingLeaderboardRecomputed: true, sharedPayloadContentPreserved: true };
}
function timestampMicros(value) {
  assert.equal(typeof value, 'string');
  const match = /^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  assert(match, 'Canonical timestamp required');
  const milliseconds = Date.parse(match[1] + '.000' + match[3]); assert(Number.isFinite(milliseconds));
  return BigInt(milliseconds) * 1000n + BigInt((match[2] || '').padEnd(6, '0'));
}
function assertSiblingLeaderboard(before, after, occurredAt) {
  const prior = before.mutable.leaderboard, current = after.mutable.leaderboard;
  assert(prior.length <= 1); assert.equal(current.length, 1); assert.equal(after.leaderboardProjection.length, 1);
  const actual = current[0].row, expected = after.leaderboardProjection[0].row;
  assert.equal(String(expected.participant_id), before.registration.participantId);
  const baseline = prior[0]?.row || { id: actual.id, fastest_stage_time: 0,
    slowest_stage_time: 0, is_completed: 0, completion_timestamp: null };
  positive(actual.id);
  const oldTime = prior.length ? timestampMicros(prior[0].row.last_updated) : -1n;
  const deletionTime = timestampMicros(occurredAt);
  assert.equal(timestampMicros(actual.last_updated), oldTime > deletionTime ? oldTime : deletionTime);
  assert.deepEqual(actual, { ...baseline, ...expected, last_updated: actual.last_updated });
}
module.exports = { initializeDeletionCtf, admitCtfDelivery, registerDeletionCtfOwner,
  readDeletionCtfOwner, assertDeletionCtf, assertCtfPoolBindings, assertSiblingLeaderboard,
  MUTABLE, LEADERBOARD_SELECT, SHARED_HASH, SHARED_TEXT };
