'use strict';

const crypto = require('node:crypto');
const { withTransaction } = require('./index');
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const mailScene = require('../../services/secureshopMailSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = Object.freeze(['customer', 'merchant', 'admin']);
const FIXTURE_KEYS = Object.freeze(['customer-note', 'merchant-note', 'admin-note']);
const MODES = new Set(['advisory', 'enforced']);
const MAX_EVENTS = 4096;

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function plain(value) { return value && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function positive(value, label, max = 2147483647) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function text(value, label, max) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > max) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function digest(value) { return crypto.createHash('sha256').update(value, 'utf8').digest(); }
function scope(input) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'trusted persona inbox scope is invalid');
  const launch = createLaunchScope(input);
  return mailScene.copy(input,{ targetId: uuid(input.targetId, 'targetId'), ...launch });
}
function values(value) { return [value.targetId, value.launchId, value.scenarioId, value.generation,
  value.platformOwnerId, value.platformSessionId]; }
function persona(input) {
  if (!plain(input) || Object.keys(input).length !== 2 || !Object.hasOwn(input,'id') || !Object.hasOwn(input,'role')) {
    throw failure('INVALID_ARGUMENT', 'trusted shop persona is invalid');
  }
  try { return createConversationBinding({ launchId: '00000000-0000-4000-8000-000000000000',
    scenarioId: '00000000-0000-4000-8000-000000000001', generation: 1,
    platformOwnerId: 1, platformSessionId: 1 }, input); }
  catch { throw failure('INVALID_ARGUMENT', 'trusted shop persona is invalid'); }
}
function normalizePersona(input) { const bound = persona(input); return Object.freeze({ id: bound.shopUserId, role: bound.role }); }
function normalizeFixtures(input) {
  if (!Array.isArray(input) || input.length !== 3 || Object.keys(input).length !== 3) {
    throw failure('INVALID_ARGUMENT', 'persona inbox fixtures are invalid');
  }
  const rows = input.map(row => {
    if (!plain(row) || Object.keys(row).some(key => !['fixtureKey','owner','subject','body'].includes(key))) {
      throw failure('INVALID_ARGUMENT', 'persona inbox fixture is invalid');
    }
    return Object.freeze({ fixtureKey: text(row.fixtureKey, 'fixtureKey', 32), owner: normalizePersona(row.owner),
      subject: text(row.subject, 'subject', 256), body: text(row.body, 'body', 4096) });
  }).sort((a, b) => FIXTURE_KEYS.indexOf(a.fixtureKey) - FIXTURE_KEYS.indexOf(b.fixtureKey));
  if (rows.some((row, index) => row.fixtureKey !== FIXTURE_KEYS[index])
      || new Set(rows.map(row => row.owner.id)).size !== 3
      || new Set(rows.map(row => row.owner.role)).size !== 3
      || !ROLES.every(role => rows.some(row => row.owner.role === role))) {
    throw failure('INVALID_ARGUMENT', 'persona inbox fixtures are invalid');
  }
  const canonical = rows.map(row => [row.fixtureKey,row.owner.id,row.owner.role,row.subject,row.body]);
  return Object.freeze({ rows, seedSha256: digest(JSON.stringify(canonical)) });
}
function policyDigest(version, mode) { return digest(JSON.stringify(['persona-inbox-acl',1,version,mode])); }
function requestDigest(target, caller, messageId, operationId) {
  const scene=mailScene.productScene(target);
  if(scene){const e=mailScene.current(target);return digest(JSON.stringify(['persona-inbox-read',2,
    ...values(target),...values({...e,targetId:target.targetId}),scene.scene.sceneId,
    scene.scene.sceneGeneration,scene.scene.grantId,caller.id,caller.role,messageId,operationId]));}
  return digest(JSON.stringify(['persona-inbox-read',1,...values(target),caller.id,caller.role,messageId,operationId]));
}
function buffer32(value) { return Buffer.isBuffer(value) && value.length === 32; }
function hex(value) { if (!buffer32(value)) throw failure('PERSONA_INBOX_INTEGRITY', 'persona inbox digest is invalid'); return value.toString('hex'); }
function receiptDigest(row) {
  return digest(['persona-inbox-cleanup-v1',row.operation_id,row.target_id,row.launch_id,row.scenario_id,
    String(row.generation),String(row.original_platform_owner_id),String(row.original_platform_session_id),
    String(row.deleted_message_count),String(row.deleted_acl_version_count),String(row.deleted_access_event_count),
    hex(row.seed_sha256)].join('\x1f'));
}
function publicCleanup(row) {
  return Object.freeze({ version: 1, operationId: row.operation_id, targetId: row.target_id,
    launchId: row.launch_id, scenarioId: row.scenario_id, generation: Number(row.generation),
    platformOwnerId: Number(row.original_platform_owner_id), platformSessionId: Number(row.original_platform_session_id),
    deletedMessageCount: Number(row.deleted_message_count), deletedAclVersionCount: Number(row.deleted_acl_version_count),
    deletedAccessEventCount: Number(row.deleted_access_event_count), seedSha256: hex(row.seed_sha256),
    receiptSha256: hex(row.receipt_sha256), completedAt: row.completed_at });
}

function createSecureShopPersonaInboxRepository(pool, dependencies = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof dependencies.checkCurrent !== 'function'
      || typeof dependencies.checkAclTransition !== 'function'
      || typeof dependencies.checkCleanup !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'persona inbox repository dependencies are invalid');
  }
  const { checkCurrent, checkAclTransition, checkCleanup, auditStore } = dependencies;
  if (auditStore !== undefined && typeof auditStore?.append !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'persona inbox audit store is invalid');
  }

  async function verifyCleanup(target, operationId) {
    const rows = (await pool.query(`SELECT r.*,t.lifecycle,t.seed_sha256 AS target_seed_sha256,
      (SELECT count(*)::integer FROM secureshop_agents.persona_inbox_messages m WHERE m.target_id=t.target_id) AS messages,
      (SELECT count(*)::integer FROM secureshop_agents.persona_inbox_acl_versions a WHERE a.target_id=t.target_id) AS policies,
      (SELECT count(*)::integer FROM secureshop_agents.persona_inbox_access_events e WHERE e.target_id=t.target_id) AS events
      FROM secureshop_agents.persona_inbox_cleanup_receipts r
      JOIN secureshop_agents.persona_inbox_targets t USING(target_id)
      WHERE r.operation_id=$1 OR r.target_id=$2`, [operationId, target.targetId])).rows;
    const row = rows[0];
    if (rows.length !== 1 || !row || row.operation_id !== operationId || row.target_id !== target.targetId
        || row.launch_id !== target.launchId || row.scenario_id !== target.scenarioId
        || Number(row.generation) !== target.generation || Number(row.original_platform_owner_id) !== target.platformOwnerId
        || Number(row.original_platform_session_id) !== target.platformSessionId || row.lifecycle !== 'retired'
        || Number(row.messages) !== 0 || Number(row.policies) !== 0 || Number(row.events) !== 0
        || Number(row.deleted_message_count) !== 3 || Number(row.deleted_acl_version_count) < 1
        || Number(row.deleted_acl_version_count) > 1024 || Number(row.deleted_access_event_count) < 0
        || Number(row.deleted_access_event_count) > MAX_EVENTS || !buffer32(row.target_seed_sha256)
        || !buffer32(row.seed_sha256) || !row.target_seed_sha256.equals(row.seed_sha256)
        || !buffer32(row.receipt_sha256) || !crypto.timingSafeEqual(row.receipt_sha256, receiptDigest(row))) {
      throw failure('PERSONA_INBOX_CLEANUP_MISMATCH', 'persona inbox cleanup receipt is invalid');
    }
    return publicCleanup(row);
  }

  async function lockEffect(client,target){const current=mailScene.current(target);await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-bound-audit-owner:${current.platformOwnerId}`]);await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-conversation-admission:${current.launchId}`]);}
      async function advanceUsing(client,inputScope,{expectedVersion,mode}={},inputPersona) {
      const target = scope(inputScope); const expected = positive(expectedVersion, 'expectedVersion', 1023);
      if (mode !== 'enforced') throw failure('INVALID_ARGUMENT', 'persona inbox ACL transition must enforce policy');
      const caller = auditStore ? normalizePersona(inputPersona) : null;
      if (caller && caller.role !== 'merchant') throw failure('OWNER_MISMATCH', 'Merchant persona required');
      await checkAclTransition(Object.freeze({ ...target, expectedVersion: expected, mode }));
      await checkCurrent(target);

      await lockEffect(client,target);await mailScene.assertGrant(client,target);
      const scene=mailScene.productScene(target),current=mailScene.current(target);
      const next = Number((await client.query(`SELECT secureshop_agents.advance_persona_inbox_acl
        ($1,$2,$3,$4,$5,$6,$7,$8,$9${scene?',$10::uuid':''}) AS version`,
        [...values({...current,targetId:target.targetId}),expected,mode,policyDigest(expected+1,mode),
          ...(scene?[scene.scene.grantId]:[])])).rows[0]?.version);
      await mailScene.assertGrant(client,target);
      await checkCurrent(target);
      if (next !== expected + 1) throw failure('PERSONA_INBOX_ACL_MISMATCH', 'persona inbox ACL transition failed');
      if (auditStore) await auditStore.append(client, {
        eventId: crypto.randomUUID(), scope: current, persona: caller, actor: caller.role,
        action: 'inbox_acl_enforce', target: `inbox:${target.targetId}`,
        paramsJson: JSON.stringify({ previousVersion: expected, version: next, mode,
          policySha256: policyDigest(next,mode).toString('hex'),
          ...(scene?{sceneId:scene.scene.sceneId,grantId:scene.scene.grantId,birthTargetId:target.targetId}:{}) }),
        outcome: 'completed', sourceKind: 'persona_inbox_acl_version', sourceId: `${target.targetId}:${next}`,
      });
      await checkCurrent(target);
      return Object.freeze({ version: next, mode, policySha256: policyDigest(next,mode).toString('hex') });
  }
  async function readUsing(client,inputScope,inputPersona,{messageId,operationId,personaSession}={}) {
      const target = scope(inputScope); const caller = normalizePersona(inputPersona);
      const id = positive(messageId, 'messageId', Number.MAX_SAFE_INTEGER); const operation = uuid(operationId, 'operationId');
      const requestSha256 = requestDigest(target,caller,id,operation);
      await checkCurrent(target);
      await lockEffect(client,target);await mailScene.assertGrant(client,target);
      const scene=mailScene.productScene(target),current=mailScene.current(target);
      const session=personaSession;
      if(scene&&(!session||typeof session.sessionId!=='string'||!UUID.test(session.sessionId)
        ||typeof session.authorityVersion!=='string'||!/^\d+$/.test(session.authorityVersion)))
        throw failure('SHOP_AUTH_INVALID','Persona inbox scene session unavailable');
      const row = (await client.query(`SELECT * FROM secureshop_agents.read_persona_inbox_message
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11${scene?',$12::uuid,$13::uuid,$14::bigint':''})`,
        [...values({...current,targetId:target.targetId}),caller.id,caller.role,id,operation,requestSha256,
          ...(scene?[scene.scene.grantId,session.sessionId,session.authorityVersion]:[])])).rows[0];
      await mailScene.assertGrant(client,target);
      await checkCurrent(target);
      if (!row || row.event_id !== operation || Number(row.message_id) !== id
          || !ROLES.includes(row.owner_shop_role) || !MODES.has(row.acl_mode)
          || !['allow','deny'].includes(row.acl_decision) || typeof row.cross_persona !== 'boolean'
          || typeof row.disclosed !== 'boolean' || row.cross_persona !== (caller.id !== Number(row.owner_shop_user_id))
          || row.disclosed !== (row.acl_decision === 'allow' || row.acl_mode === 'advisory')
          || (row.disclosed && (typeof row.body !== 'string' || !buffer32(row.body_sha256)
            || !crypto.timingSafeEqual(row.body_sha256,digest(row.body))))
          || (!row.disclosed && (row.body !== null || row.body_sha256 !== null))) {
        throw failure('PERSONA_INBOX_INTEGRITY', 'persona inbox read receipt is invalid');
      }
      if (auditStore) await auditStore.append(client, {
        eventId: operation, scope: current, persona: caller,
        actor: caller.role, action: 'inbox_read', target: `inbox-message:${id}`,
        paramsJson: JSON.stringify({ messageId: id, aclVersion: Number(row.acl_version),
          aclMode: row.acl_mode, aclDecision: row.acl_decision, crossPersona: row.cross_persona,
          disclosed: row.disclosed, requestSha256: requestSha256.toString('hex'),
          ...(scene?{sceneId:scene.scene.sceneId,sceneGeneration:scene.scene.sceneGeneration,
            grantId:scene.scene.grantId,birthTargetId:target.targetId}:{} ) }),
        outcome: row.disclosed ? 'completed' : 'denied',
        sourceKind: 'persona_inbox_access_event', sourceId: operation,
      });
      await checkCurrent(target);
  return Object.freeze({ version: 1, eventId: row.event_id, operationId: operation, messageId: id,
        callerShopUserId: caller.id, callerShopRole: caller.role,
        ownerShopUserId: Number(row.owner_shop_user_id), ownerShopRole: row.owner_shop_role,
        subject: row.subject, body: row.body, bodySha256: row.body_sha256 ? row.body_sha256.toString('hex') : null,
        aclVersion: Number(row.acl_version), aclMode: row.acl_mode, aclDecision: row.acl_decision,
        crossPersona: row.cross_persona, disclosed: row.disclosed, requestSha256: requestSha256.toString('hex'),
        createdAt: row.created_at });
  }
  return Object.freeze({
    async provision(inputScope, { fixtures, mode = 'advisory' } = {}) {
      const target = scope(inputScope); const seed = normalizeFixtures(fixtures);
      if (mode !== 'advisory') throw failure('INVALID_ARGUMENT', 'persona inbox must begin in advisory mode');
      await checkCurrent(target);
      return withTransaction(pool, async client => {
        const inserted = await client.query(`INSERT INTO secureshop_agents.persona_inbox_targets
          (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,seed_count,seed_sha256)
          VALUES($1,$2,$3,$4,$5,$6,3,$7) ON CONFLICT(target_id) DO NOTHING`, [...values(target),seed.seedSha256]);
        const stored = (await client.query(`SELECT * FROM secureshop_agents.persona_inbox_targets
          WHERE target_id=$1`, [target.targetId])).rows[0];
        if (!stored || stored.launch_id !== target.launchId || stored.scenario_id !== target.scenarioId
            || Number(stored.generation) !== target.generation
            || Number(stored.original_platform_owner_id) !== target.platformOwnerId
            || Number(stored.original_platform_session_id) !== target.platformSessionId
            || stored.lifecycle !== 'active' || Number(stored.seed_count) !== 3
            || !buffer32(stored.seed_sha256) || !crypto.timingSafeEqual(stored.seed_sha256, seed.seedSha256)) {
          throw failure('PERSONA_INBOX_TARGET_MISMATCH', 'persona inbox target does not match');
        }
        if (inserted.rowCount === 1) {
          await client.query(`INSERT INTO secureshop_agents.persona_inbox_acl_versions
            (target_id,version,mode,policy_sha256) VALUES($1,1,$2,$3)`, [target.targetId,mode,policyDigest(1,mode)]);
          for (const row of seed.rows) await client.query(`INSERT INTO secureshop_agents.persona_inbox_messages
            (target_id,fixture_key,owner_shop_user_id,owner_shop_role,subject,body,body_sha256)
            VALUES($1,$2,$3,$4,$5,$6,$7)`, [target.targetId,row.fixtureKey,row.owner.id,row.owner.role,
            row.subject,row.body,digest(row.body)]);
        } else {
          const rows = (await client.query(`SELECT fixture_key,owner_shop_user_id,owner_shop_role,subject,body,body_sha256
            FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1
            ORDER BY CASE fixture_key WHEN 'customer-note' THEN 1 WHEN 'merchant-note' THEN 2 WHEN 'admin-note' THEN 3 END`,
          [target.targetId])).rows;
          const acl = (await client.query(`SELECT version,mode,policy_sha256 FROM secureshop_agents.persona_inbox_acl_versions
            WHERE target_id=$1 AND version=1`, [target.targetId])).rows[0];
          if (rows.length !== 3 || rows.some((row,index) => row.fixture_key !== seed.rows[index].fixtureKey
              || Number(row.owner_shop_user_id) !== seed.rows[index].owner.id || row.owner_shop_role !== seed.rows[index].owner.role
              || row.subject !== seed.rows[index].subject || row.body !== seed.rows[index].body
              || !buffer32(row.body_sha256) || !crypto.timingSafeEqual(row.body_sha256,digest(row.body)))
              || !acl || Number(acl.version) !== 1 || acl.mode !== mode || !buffer32(acl.policy_sha256)
              || !crypto.timingSafeEqual(acl.policy_sha256,policyDigest(1,mode))) {
            throw failure('PERSONA_INBOX_TARGET_PARTIAL', 'persona inbox target is incomplete');
          }
        }
        await checkCurrent(target);
        return Object.freeze({ ...target, seedCount: 3, seedSha256: seed.seedSha256.toString('hex') });
      });
    },

    async list(inputScope) {
      const target = scope(inputScope); await checkCurrent(target);
      const scene=mailScene.productScene(target),current=mailScene.current(target);
      const read=async client=>{await mailScene.assertGrant(client,target);
        const rows=(await client.query(`SELECT * FROM secureshop_agents.list_persona_inbox_messages($1,$2,$3,$4,$5,$6${scene?',$7::uuid':''})`,
          [...values({...current,targetId:target.targetId}),...(scene?[scene.scene.grantId]:[])])).rows;
        await mailScene.assertGrant(client,target);return rows;};
      const rows=scene?await mailScene.withLease(target,()=>withTransaction(pool,read)):await read(pool);
      await checkCurrent(target);
      if (rows.length !== 3) throw failure('PERSONA_INBOX_TARGET_PARTIAL', 'persona inbox target is incomplete');
      return Object.freeze(rows.map(row => Object.freeze({ messageId: Number(row.message_id),
        ownerShopUserId: Number(row.owner_shop_user_id), ownerShopRole: row.owner_shop_role, subject: row.subject })));
    },

    async readAcl(inputScope) {
      const target = scope(inputScope); await checkCurrent(target);
      const scene=mailScene.productScene(target);
      const read=async client=>{await mailScene.assertGrant(client,target);
        const rows=(await client.query(`SELECT version,mode,policy_sha256
          FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=$1
          ORDER BY version DESC LIMIT 2`, [target.targetId])).rows;
        await mailScene.assertGrant(client,target);return rows;};
      const rows=scene?await mailScene.withLease(target,()=>withTransaction(pool,read)):await read(pool);
      await checkCurrent(target);
      const row = rows[0];
      if (!row || rows.length > 2 || !Number.isSafeInteger(Number(row.version))
          || Number(row.version) < 1 || Number(row.version) > 1024 || !MODES.has(row.mode)
          || !buffer32(row.policy_sha256)
          || !crypto.timingSafeEqual(row.policy_sha256, policyDigest(Number(row.version), row.mode))) {
        throw failure('PERSONA_INBOX_INTEGRITY', 'persona inbox ACL is invalid');
      }
      return Object.freeze({ version: Number(row.version), mode: row.mode,
        policySha256: row.policy_sha256.toString('hex') });
    },

    async read(inputScope,inputPersona,args={}){const target=scope(inputScope);normalizePersona(inputPersona);positive(args.messageId,'messageId',Number.MAX_SAFE_INTEGER);uuid(args.operationId,'operationId');return mailScene.withLease(target,()=>withTransaction(pool,client=>readUsing(client,target,inputPersona,args)));},
    async readWithClient(client,inputScope,inputPersona,args){if(typeof client?.query!=='function')throw failure('INVALID_ARGUMENT','Transaction client required');return readUsing(client,inputScope,inputPersona,args);},

    async readAccessEvent(inputScope, eventId) {
      const target = scope(inputScope); const event = uuid(eventId, 'eventId'); await checkCurrent(target);
      const scene=mailScene.productScene(target),current=mailScene.current(target);
      const read=async client=>{await mailScene.assertGrant(client,target);
       const row=(await client.query(`SELECT e.*,m.subject,m.body,m.body_sha256 AS current_body_sha256,t.lifecycle,
        t.launch_id AS target_launch_id,t.scenario_id AS target_scenario_id,t.generation AS target_generation,
        t.original_platform_owner_id AS target_owner_id,t.original_platform_session_id AS target_session_id,
        p.grant_id AS scene_grant_id,p.scene_id AS scene_id,p.scene_generation AS scene_generation,
        p.launch_id AS execution_launch_id,p.scenario_id AS execution_scenario_id,
        p.generation AS execution_generation,p.original_platform_owner_id AS execution_owner_id,
        p.original_platform_session_id AS execution_session_id
        FROM secureshop_agents.persona_inbox_access_events e
        JOIN secureshop_agents.persona_inbox_targets t USING(target_id)
        JOIN secureshop_agents.persona_inbox_messages m USING(target_id,message_id)
        LEFT JOIN secureshop_agents.persona_inbox_scene_access_provenance p ON p.event_id=e.event_id
        WHERE e.event_id=$1 AND e.target_id=$2`, [event,target.targetId])).rows[0];
       await mailScene.assertGrant(client,target);return row;};
      const row=scene?await mailScene.withLease(target,()=>withTransaction(pool,read)):await read(pool);
      await checkCurrent(target);
      if (!row || row.lifecycle !== 'active' || row.target_launch_id !== target.launchId
          || row.target_scenario_id !== target.scenarioId || Number(row.target_generation) !== target.generation
          || Number(row.target_owner_id) !== target.platformOwnerId || Number(row.target_session_id) !== target.platformSessionId
          || (scene ? row.scene_grant_id!==scene.scene.grantId
            || row.scene_id!==scene.scene.sceneId || Number(row.scene_generation)!==scene.scene.sceneGeneration
            || row.execution_launch_id!==current.launchId || row.execution_scenario_id!==current.scenarioId
            || Number(row.execution_generation)!==current.generation
            || Number(row.execution_owner_id)!==current.platformOwnerId
            || Number(row.execution_session_id)!==current.platformSessionId : row.scene_grant_id!==null)
          || !buffer32(row.request_sha256) || !buffer32(row.current_body_sha256)
          || row.disclosed !== (row.acl_decision === 'allow' || row.acl_mode === 'advisory')
          || (row.disclosed && (!buffer32(row.body_sha256) || !row.body_sha256.equals(row.current_body_sha256)))
          || (!row.disclosed && row.body_sha256 !== null)) return null;
      return Object.freeze({ version: scene?2:1, ...current,targetId:target.targetId,
        ...(scene?{sceneId:scene.scene.sceneId,sceneGeneration:scene.scene.sceneGeneration,
          grantId:scene.scene.grantId,birth:mailScene.birth(target)}:{}),
        eventId: row.event_id, operationId: row.operation_id,
        messageId: Number(row.message_id), callerShopUserId: Number(row.caller_shop_user_id),
        callerShopRole: row.caller_shop_role, ownerShopUserId: Number(row.resource_owner_shop_user_id),
        ownerShopRole: row.resource_owner_shop_role, subject: row.subject, body: row.disclosed ? row.body : null,
        bodySha256: row.body_sha256 ? row.body_sha256.toString('hex') : null,
        currentBodySha256: row.current_body_sha256.toString('hex'), aclVersion: Number(row.acl_version),
        aclMode: row.acl_mode, aclDecision: row.acl_decision, crossPersona: row.cross_persona,
        disclosed: row.disclosed, requestSha256: row.request_sha256.toString('hex'), createdAt: row.created_at });
    },

    async advanceAcl(inputScope,args={},inputPersona){const target=scope(inputScope);positive(args.expectedVersion,'expectedVersion',1023);if(args.mode!=='enforced')throw failure('INVALID_ARGUMENT','persona inbox ACL transition must enforce policy');return mailScene.withLease(target,()=>withTransaction(pool,client=>advanceUsing(client,target,args,inputPersona)));},
    async advanceAclWithClient(client,inputScope,args,inputPersona){if(typeof client?.query!=='function')throw failure('INVALID_ARGUMENT','Transaction client required');return advanceUsing(client,inputScope,args,inputPersona);},

    async cleanup(inputScope, { operationId } = {}) {
      const target = scope(inputScope); const operation = uuid(operationId, 'operationId');
      await checkCleanup(Object.freeze({ ...target, operationId: operation }));
      await pool.query(`SELECT * FROM secureshop_agents.retire_persona_inbox_target
        ($1,$2,$3,$4,$5,$6,$7)`, [operation,...values(target)]);
      return verifyCleanup(target, operation);
    },

    async readCleanupReceipt(inputScope, { operationId } = {}) {
      const target = scope(inputScope); const operation = uuid(operationId, 'operationId');
      await checkCleanup(Object.freeze({ ...target, operationId: operation }));
      return verifyCleanup(target, operation);
    },
  });
}

module.exports = { createSecureShopPersonaInboxRepository, policyDigest, requestDigest, receiptDigest };
