'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Module, createRequire } = require('node:module');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const PREFIX = 'PG_SECURESHOP_MAIL_';
const KEYS = ['IDENTITY_RUNTIME_URL', 'IDENTITY_MIGRATION_URL',
  'AGENTS_RUNTIME_URL', 'AGENTS_MIGRATION_URL',
  'COMMERCE_RUNTIME_URL', 'COMMERCE_MIGRATION_URL',
  'REVIEW_RUNTIME_URL', 'REVIEW_MIGRATION_URL'];
const ENABLED = process.env.SECURESHOP_STANDALONE_MAIL_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && KEYS.every(key => process.env[PREFIX + key]);
const IDENTITY_DIRECTORY = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const AGENTS_DIRECTORY = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents');
const REVIEW_DIRECTORY = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const COMMERCE_DIRECTORY = path.resolve(__dirname, '../../db/postgres/workshop-migrations/secureshop');

function disposableUrl(key) {
  const url = new URL(process.env[PREFIX + key]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
  return url.href;
}
function historicalMigrator(directory, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory
      ? names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
        || Number(name.slice(0, 4)) <= ceiling) : names;
  } };
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? virtual : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}
async function count(pool, sql, args = []) {
  return Number((await pool.query(sql, args)).rows[0].n);
}
async function receipt(file, value) {
  await fsp.writeFile(file, JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 });
  assert.equal((await fsp.stat(file)).mode & 0o777, 0o600);
}

test('standalone shop mail actors preserve legacy evidence and fence tenant mail',
  { skip: !ENABLED, timeout: 220000 }, async t => {
    assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/'), process.cwd());
    const evidencePath = process.env.SECURESHOP_STANDALONE_MAIL_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidencePath));
    assert.ok(!path.resolve(evidencePath).startsWith(`${process.cwd()}${path.sep}`));
    const im = new Pool({ connectionString: disposableUrl('IDENTITY_MIGRATION_URL'), max: 2 });
    const identity = new Pool({ connectionString: disposableUrl('IDENTITY_RUNTIME_URL'), max: 6 });
    const am = new Pool({ connectionString: disposableUrl('AGENTS_MIGRATION_URL'), max: 2 });
    const agents = new Pool({ connectionString: disposableUrl('AGENTS_RUNTIME_URL'), max: 6 });
    const cm = new Pool({ connectionString: disposableUrl('COMMERCE_MIGRATION_URL'), max: 2 });
    const commerce = new Pool({ connectionString: disposableUrl('COMMERCE_RUNTIME_URL'), max: 3 });
    const rm = new Pool({ connectionString: disposableUrl('REVIEW_MIGRATION_URL'), max: 2 });
    const review = new Pool({ connectionString: disposableUrl('REVIEW_RUNTIME_URL'), max: 6 });
    t.after(async () => {
      const settled = await Promise.allSettled([im, identity, am, agents, cm, commerce, rm, review].map(pool => pool.end()));
      assert.equal(settled.filter(row => row.status === 'rejected').length, 0);
    });
    const status = { scope: 'controlled native tenant mail storage and authority; no actual model or browser proof',
      passed: false, freshPopulatedNoop: false, legacyMailPreserved: false,
      registeredDelivery: false, replayStable: false, foreignTenantDenied: false,
      vulnerableIdorRetained: false, fixedModeFenced: false, siblingPreserved: false,
      mailUncertainResolutionFenced: false, mailSceneSharedRelogin: false,
      mailSceneLegacyAdoption: false, mailSceneGrantFenced: false, mailSceneCanonicalCleanup: false,
      savedSendMigration: false, savedSendExactProjection: false,
      savedSendAuthorityFenced: false, savedSendTamperDenied: false };
    await migrate(im, IDENTITY_DIRECTORY);
    await historicalMigrator(AGENTS_DIRECTORY, 46)(am, AGENTS_DIRECTORY);
    await migrate(cm, COMMERCE_DIRECTORY);
    await migrate(rm, REVIEW_DIRECTORY);
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
    const preview = await am.connect();
    try {
      await preview.query('BEGIN');
      await preview.query(await fsp.readFile(path.join(AGENTS_DIRECTORY,
        '0047_bound_mail_tenant_actors.sql'), 'utf8'));
      await preview.query(await fsp.readFile(path.join(AGENTS_DIRECTORY,
        '0050_bound_mail_uncertain_resolution.sql'), 'utf8'));
      assert.equal(await count(preview,
        'SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages'), 0);
      assert.equal(await count(preview,
        'SELECT count(*)::int n FROM secureshop_agents.bound_mail_thread_attempts'), 0);
      await preview.query('ROLLBACK');
    } catch (error) { await preview.query('ROLLBACK').catch(() => {}); throw error; }
    finally { preview.release(); }

    const suffix = randomUUID().slice(0, 8);
    const users = require('../../server/database/postgres/identityRepository')
      .createIdentityRepository(identity);
    const passwordHash = await require('bcryptjs').hash('disposable-mail-history', 4);
    const oldUser = await users.createUser({ username: `mail_${suffix}`,
      email: `mail_${suffix}@example.invalid`, passwordHash });
    const oldToken = randomUUID();
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const oldSession = await users.createSession({ userId: oldUser.id,
      token: oldToken, expiresAt, expectedPasswordHash: passwordHash });
    const launches = require('../../server/database/postgres/secureshopLaunchRepository')
      .createSecureShopLaunchRepository(identity);
    const oldLaunch = await launches.issueOrRenew({ platformOwnerId: oldUser.id,
      platformSessionId: oldSession.id, expiresAt });
    const launchScope = value => require('../../server/services/secureshopConversationBinding')
      .createLaunchScope(value.binding);
    const oldScope = launchScope(oldLaunch);
    const authority = require('../../server/database/postgres/secureshopBoundPersonaAuthority')
      .createSecureShopBoundPersonaAuthority({ pool: agents,
        checkCurrent: scope => launches.assertCurrent(scope) });
    const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository')
      .createSecureShopBoundPersonaRepository({ commercePool: commerce, agentsPool: agents,
        personaAuthority: authority });
    await personas.ensureTemplates();
    const bound = require('../../server/services/secureshopBoundPersonaAuth')
      .createSecureShopBoundPersonaAuth({ repository: personas, personaAuthority: authority,
        launches, jwtSecret: 'disposable-standalone-mail-fixture-secret-at-least-32-bytes' });
    const oldLogin = await bound.login({ scope: oldScope, username: 'student_merchant',
      password: 'student123' });
    const oldVerified = await bound.authenticateBoundToken({ scope: oldScope, token: oldLogin.token });
    const template = (await personas.listPersonas()).find(row => row.role === 'customer');
    const inbox = require('../../server/database/postgres/secureshopPersonaInboxRepository')
      .createSecureShopPersonaInboxRepository(agents, {
        checkCurrent: scope => launches.assertCurrent(scope),
        checkAclTransition: async () => {}, checkCleanup: async () => {},
      });
    const fixtures = require('../../server/services/secureshopPersonaInboxComposition')
      .mapPersonaInboxFixtures(await personas.listPersonas());
    async function target(scope) {
      const reserved = await launches.reservePersonaInboxTarget({ ...scope,
        expectedGeneration: scope.generation });
      const result = { ...scope, targetId: reserved.targetId };
      await inbox.provision(result, { fixtures, mode: 'advisory' });
      return result;
    }
    const oldTarget = await target(oldScope);
    const mail = require('../../server/database/postgres/secureshopBoundMailRepository')
      .createBoundMailRepository({ pool: agents, personaAuthority: authority,
        checkCleanup: async () => {} });
    const oldBinding = { scope: oldScope, targetId: oldTarget.targetId,
      persona: { id: oldLogin.user.id, role: 'merchant' },
      personaSession: { sessionId: oldVerified.sessionId,
        authorityVersion: oldVerified.authorityVersion }, mode: 'vuln', operationId: randomUUID() };
    const oldMessage = { from: oldLogin.user.email, to: template.email,
      subject: 'Retained template mail', body_markdown: 'Historical message' };
    const oldSent = await mail.send(oldBinding, oldMessage);
    const oldReadBinding = { ...oldBinding, operationId: randomUUID() };
    const oldRead = await mail.read(oldReadBinding, template.id);
    assert.equal(oldRead.emails.length, 1);
    const oldRows = {
      messages: (await am.query(`SELECT * FROM secureshop_agents.lab_mail_messages
        WHERE target_id=$1 ORDER BY message_id`, [oldTarget.targetId])).rows,
      operations: (await am.query(`SELECT * FROM secureshop_agents.lab_mail_operation_receipts
        WHERE target_id=$1 ORDER BY operation_id`, [oldTarget.targetId])).rows,
      inbox: (await am.query(`SELECT * FROM secureshop_agents.persona_inbox_messages
        WHERE target_id=$1 ORDER BY message_id`, [oldTarget.targetId])).rows,
    };
    assert.deepEqual(await historicalMigrator(AGENTS_DIRECTORY,49)(am, AGENTS_DIRECTORY), [
      '0047_bound_mail_tenant_actors.sql','0048_bound_tool_registered_actor_admission.sql',
      '0049_bound_prompt_registered_actor_admission.sql']);
    const beforeUncertainty = (await am.query(`SELECT * FROM secureshop_agents.turn_requests
      ORDER BY session_id,request_id`)).rows;
    const uncertainPreview=await am.connect();
    try{
      await uncertainPreview.query('BEGIN');
      await uncertainPreview.query(await fsp.readFile(path.join(AGENTS_DIRECTORY,
        '0050_bound_mail_uncertain_resolution.sql'),'utf8'));
      assert.equal(await count(uncertainPreview,
        'SELECT count(*)::int n FROM secureshop_agents.bound_mail_preexecution_rejections'),0);
      await uncertainPreview.query('ROLLBACK');
    }catch(error){await uncertainPreview.query('ROLLBACK').catch(()=>{});throw error;}
    finally{uncertainPreview.release();}
    assert.deepEqual(await historicalMigrator(AGENTS_DIRECTORY,50)(am, AGENTS_DIRECTORY), ['0050_bound_mail_uncertain_resolution.sql']);
    assert.deepEqual(await historicalMigrator(AGENTS_DIRECTORY,50)(am, AGENTS_DIRECTORY), []);
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.turn_requests
      ORDER BY session_id,request_id`)).rows,beforeUncertainty);
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.lab_mail_messages
      WHERE target_id=$1 ORDER BY message_id`, [oldTarget.targetId])).rows, oldRows.messages);
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.lab_mail_operation_receipts
      WHERE target_id=$1 ORDER BY operation_id`, [oldTarget.targetId])).rows, oldRows.operations);
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.persona_inbox_messages
      WHERE target_id=$1 ORDER BY message_id`, [oldTarget.targetId])).rows, oldRows.inbox);
    const oldReplay = await mail.read(oldReadBinding, template.id);
    assert.equal(oldReplay.replayed, true);
    assert.equal(oldReplay.emails.length, 1);
    status.freshPopulatedNoop = true;
    status.legacyMailPreserved = true;

    const standalone = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(im);
    const merchantAuth = await standalone.register({ username: `sender_${suffix}`,
      email: `sender_${suffix}@example.invalid`, password: 'disposable-mail-password', role: 'merchant' });
    const customerAuth = await standalone.register({ username: `target_${suffix}`,
      email: `target_${suffix}@example.invalid`, password: 'disposable-mail-password', role: 'customer' });
    const merchant = await standalone.establishTenantContext(merchantAuth.context);
    const customer = await standalone.establishTenantContext(customerAuth.context);
    assert.equal(merchant.tenantId, customer.tenantId);
    const merchantLaunch = await launches.issueOrRenew({ platformOwnerId: merchant.ownerId,
      platformSessionId: merchant.sessionId, expiresAt, shopPrincipal: merchant });
    const merchantScope = launchScope(merchantLaunch);
    const merchantBound = await bound.establishSession({ scope: merchantScope,
      shopPrincipal: merchant });
    const customerLaunch = await launches.issueOrRenew({ platformOwnerId: customer.ownerId,
      platformSessionId: customer.sessionId, expiresAt, shopPrincipal: customer });
    const customerScope = launchScope(customerLaunch);
    const customerBound=await bound.establishSession({ scope: customerScope, shopPrincipal: customer });
    const merchantVerified = await bound.authenticateBoundToken({ scope: merchantScope,
      token: merchantBound.token });
    const directory = await personas.listMailActors(merchantScope);
    assert.equal(directory.find(row => row.id === merchant.shopUserId)?.email, merchant.email);
    assert.equal(directory.find(row => row.id === customer.shopUserId)?.email, customer.email);
    assert.equal(directory.find(row => row.id === merchant.shopUserId)?.role, 'merchant');
    assert.equal(directory.find(row => row.id === customer.shopUserId)?.role, 'customer');
    const registeredTarget = await target(merchantScope);
    const owned = { scope: merchantScope, targetId: registeredTarget.targetId,
      persona: { id: merchant.shopUserId, role: 'merchant' },
      personaSession: { sessionId: merchantVerified.sessionId,
        authorityVersion: merchantVerified.authorityVersion }, mode: 'vuln', operationId: randomUUID() };
    const message = { from: merchant.email, to: customer.email, subject: 'Registered receipt',
      body_markdown: '<img src=x onerror="owned()">' };
    const delivered = await mail.send(owned, message);
    assert.equal(delivered.receipt.senderId, merchant.shopUserId);
    assert.equal(delivered.receipt.recipientId, customer.shopUserId);
    assert.equal((await mail.read({ ...owned, operationId: randomUUID() }, customer.shopUserId)).emails.length, 1);
    status.registeredDelivery = true;
    const replay = await mail.send(owned, message);
    assert.equal(replay.replayed, true);
    assert.equal(replay.email_id, delivered.email_id);
    assert.equal(await count(am, `SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages
      WHERE target_id=$1 AND message_id=$2`, [registeredTarget.targetId, delivered.email_id]), 1);
    status.replayStable = true;

    const foreignId = randomUUID(), foreignTenantId = randomUUID();
    const foreign = (await im.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'customer')
      RETURNING owner_id,shop_user_id`, [foreignId, `foreign_${suffix}`,
      `foreign_${suffix}@example.invalid`, await require('bcryptjs').hash('foreign-disposable', 4)])).rows[0];
    const foreignTenant = (await im.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2) RETURNING owner_id`, [foreignTenantId, `isolated_${suffix}`])).rows[0];
    await im.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
    [foreignTenantId, foreignId, foreign.shop_user_id]);
    await am.query(`INSERT INTO secureshop_agents.bound_actor_identities
      (shop_user_id,username,email,base_role,principal_id,original_platform_owner_id)
      VALUES($1,$2,$3,'customer',$4,$5)`, [foreign.shop_user_id, `foreign_${suffix}`,
      `foreign_${suffix}@example.invalid`, foreignId, foreign.owner_id]);
    await am.query(`INSERT INTO secureshop_agents.bound_actor_tenant_memberships
      (tenant_owner_id,tenant_id,shop_user_id,principal_id,principal_owner_id,membership_version,role)
      VALUES($1,$2,$3,$4,$5,1,'customer')`,
    [foreignTenant.owner_id, foreignTenantId, foreign.shop_user_id, foreignId, foreign.owner_id]);
    assert.equal((await agents.query(`SELECT secureshop_agents.bound_actor_in_owner($1,$2) AS owned`,
      [foreign.shop_user_id, merchant.ownerId])).rows[0].owned, false);
    assert.equal((await agents.query(`SELECT secureshop_agents.bound_actor_in_owner($1,$2) AS owned`,
      [foreign.shop_user_id, foreignTenant.owner_id])).rows[0].owned, true);
    assert.equal((await personas.listMailActors(merchantScope))
      .some(row => row.id === foreign.shop_user_id), false);
    await assert.rejects(mail.send({ ...owned, operationId: randomUUID() },
      { ...message, to: `foreign_${suffix}@example.invalid` }));
    await assert.rejects(mail.read({ ...owned, operationId: randomUUID() },
      foreign.shop_user_id));
    assert.equal(await count(am, `SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages
      WHERE target_id=$1`, [registeredTarget.targetId]), 1);
    status.foreignTenantDenied = true;

    const disclosed = await mail.read({ ...owned, operationId: randomUUID() }, customer.shopUserId);
    assert.equal(disclosed.emails[0].id, delivered.email_id);
    assert.equal(disclosed.emails[0].body_html, message.body_markdown);
    status.vulnerableIdorRetained = true;
    const fixed = { ...owned, mode: 'fixed', operationId: randomUUID() };
    await assert.rejects(mail.read(fixed, customer.shopUserId));
    await assert.rejects(mail.send({ ...fixed, operationId: randomUUID() },
      { ...message, subject: 'safe\r\nBcc: owned@example.invalid' }));
    const fixedSent = await mail.send({ ...fixed, operationId: randomUUID() },
      { ...message, subject: 'Safe owned mail' });
    const fixedHtml = (await am.query(`SELECT body_html FROM secureshop_agents.lab_mail_messages
      WHERE message_id=$1`, [fixedSent.email_id])).rows[0].body_html;
    assert.match(fixedHtml, /&lt;img/);
    assert.ok(!fixedHtml.includes('<img'));
    status.fixedModeFenced = true;
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.lab_mail_messages
      WHERE target_id=$1 ORDER BY message_id`, [oldTarget.targetId])).rows, oldRows.messages);
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.lab_mail_operation_receipts
      WHERE target_id=$1 ORDER BY operation_id`, [oldTarget.targetId])).rows, oldRows.operations);
    assert.equal((await mail.read(oldReadBinding, template.id)).replayed, true);
    status.siblingPreserved = true;
    const conversationsRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository')
      .createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
    const conversations=require('../../server/services/secureshopBoundConversation')
      .createBoundConversationService({conversations:conversationsRepository,launches});
    const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository')
      .createTurnRequestsRepository({pool:agents});
    const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({
      family:'SecureShopBoundConversation',ledger:require('../../server/agent-runtime/postgresRunLedger')
        .createPostgresRunLedger(identity,{leasePool:identity})});
    const uncertain=require('../../server/database/postgres/secureshopMailUncertainRepository')
      .createMailUncertainRepository({pool:agents,personaAuthority:authority});
    const purpose=require('../../server/services/secureshopConversationPurpose')
      .SECURESHOP_CONVERSATION_PURPOSES.mailReply;
    const conversation=await conversations.create(merchantScope,owned.persona,purpose);
    const binding=require('../../server/services/secureshopConversationBinding')
      .createConversationBinding(merchantScope,owned.persona);
    const oldRequest={...owned,operationId:randomUUID()};
    const historicalTurnMessage=JSON.stringify({version:1,targetId:owned.targetId,threadId:delivered.thread_id,
      mode:'vuln',operationId:oldRequest.operationId,personaSession:owned.personaSession});
    const claimed=await journal.claim({sessionId:conversation.id,requestId:oldRequest.operationId,
      binding,message:historicalTurnMessage});
    assert.equal(claimed.status,'claimed');
    assert.equal(await journal.markUncertain({sessionId:conversation.id,
      requestId:oldRequest.operationId,binding,claimId:claimed.claimId}),true);
    const oldTurn=(await am.query(`SELECT * FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`,[conversation.id,oldRequest.operationId])).rows[0];
    const forgedRequestId=randomUUID();
    const forgedMessage=JSON.stringify({version:1,targetId:owned.targetId,
      threadId:delivered.thread_id,mode:'vuln',operationId:forgedRequestId,
      personaSession:owned.personaSession});
    const forgedClaim=await journal.claim({sessionId:conversation.id,requestId:forgedRequestId,
      binding,message:forgedMessage});
    const forgedHash=require('../../server/services/secureshopTurnRequest').createTurnRequest({
      sessionId:conversation.id,requestId:forgedRequestId,binding,message:forgedMessage}).hash;
    const forgedArgs=[conversation.id,forgedRequestId,forgedClaim.claimId,forgedHash,
      randomUUID(),owned.targetId,owned.persona.id,owned.personaSession.sessionId,
      owned.personaSession.authorityVersion,delivered.thread_id,'vuln',false];
    const directAttempt=`INSERT INTO secureshop_agents.bound_mail_thread_attempts
      (session_id,request_id,claim_id,request_hash,run_id,target_id,persona_id,
       persona_session_id,authority_version,thread_id,mode,blocked)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`;
    for(const [index,value] of [[7,randomUUID()],
      [8,String(Number(owned.personaSession.authorityVersion)+1)],
      [6,customer.shopUserId]]){
      const args=[...forgedArgs];args[index]=value;
      await assert.rejects(agents.query(directAttempt,args),{code:'55000'});
    }
    assert.equal(await count(am,`SELECT count(*)::int n
      FROM secureshop_agents.bound_mail_thread_attempts WHERE request_id=$1`,
    [forgedRequestId]),0);
    assert.equal(await journal.markUncertain({sessionId:conversation.id,
      requestId:forgedRequestId,binding,claimId:forgedClaim.claimId}),true);
    assert.equal(await uncertain.readRejected(oldRequest),null,
      'A historical uncertain turn has no affirmative preexecution receipt');
    await assert.rejects(uncertain.keepUnresolved(oldRequest,delivered.thread_id+1));
    await assert.rejects(uncertain.keepUnresolved({...oldRequest,mode:'fixed'},delivered.thread_id));
    await assert.rejects(uncertain.keepUnresolved({...oldRequest,
      persona:{id:customer.shopUserId,role:'customer'}},delivered.thread_id));
    assert.deepEqual(await uncertain.keepUnresolved(oldRequest,delivered.thread_id),
      {requestId:oldRequest.operationId,threadId:delivered.thread_id});
    assert.deepEqual(await uncertain.keepUnresolved(oldRequest,delivered.thread_id),
      {requestId:oldRequest.operationId,threadId:delivered.thread_id});
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`,[conversation.id,oldRequest.operationId])).rows[0],oldTurn);
    await assert.rejects(uncertain.admitThread({...owned,operationId:randomUUID()},
      delivered.thread_id,Object.freeze({})),{name:'TypeError'});
    let modelCalls=0,policyCalls=0;
    const actor={async chat(){modelCalls++;throw Error('Model must not run');},
      async finalResponse(){modelCalls++;throw Error('Model must not run');}};
    const graph=require('../../server/services/secureshopBoundMailGraph').createBoundMailGraph({
      launches,personaAuthority:authority,conversationRepository:conversationsRepository,
      journal,coordinator,provider:actor,mailRepository:mail,
      listPersonas:scope=>personas.listMailActors(scope),uncertainRepository:uncertain,
      promptPolicyRepository:{async admitRunSnapshot(){policyCalls++;throw Error('Controlled pre-model admission rejection');}}});
    const same={...owned,operationId:randomUUID()};
    await assert.rejects(graph.run({...same,threadId:delivered.thread_id}));
    assert.equal(policyCalls,0);assert.equal(modelCalls,0);
    const sameReceipt=await uncertain.readRejected(same);
    assert.deepEqual(sameReceipt,{threadId:delivered.thread_id,stage:'thread_admission'});
    const separate=await mail.send({...owned,operationId:randomUUID()},
      {...message,subject:'Independent thread'});
    const different={...owned,operationId:randomUUID()};
    await assert.rejects(graph.run({...different,threadId:separate.thread_id}));
    assert.equal(policyCalls,1);assert.equal(modelCalls,0);
    assert.deepEqual(await uncertain.readRejected(different),
      {threadId:separate.thread_id,stage:'prompt_policy_admission'});
    assert.equal(await count(am,`SELECT count(*)::int n
      FROM secureshop_agents.bound_mail_preexecution_rejections
      WHERE request_id=ANY($1::uuid[])`,[[same.operationId,different.operationId]]),2);
    await assert.rejects(am.query(`UPDATE secureshop_agents.bound_mail_preexecution_rejections
      SET stage='thread_admission' WHERE request_id=$1`,[different.operationId]));
    assert.deepEqual((await am.query(`SELECT * FROM secureshop_agents.turn_requests
      WHERE session_id=$1 AND request_id=$2`,[conversation.id,oldRequest.operationId])).rows[0],oldTurn);
    status.mailUncertainResolutionFenced = true;
    // Apply the scene migration over actual retained mail and uncertainty
    // evidence. Preview rolls back; ledger application and a second run follow.
    const retainedMessages=(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[owned.targetId])).rows;
    const retainedOperations=(await am.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[owned.targetId])).rows;
    const retainedRejections=(await am.query('SELECT * FROM secureshop_agents.bound_mail_preexecution_rejections ORDER BY request_id')).rows;
    const scenePreview=await am.connect();
    try{
      await scenePreview.query('BEGIN');
      await scenePreview.query(await fsp.readFile(path.join(AGENTS_DIRECTORY,'0051_mail_scene_execution.sql'),'utf8'));
      await scenePreview.query('ROLLBACK');
    }catch(error){await scenePreview.query('ROLLBACK').catch(()=>{});throw error;}finally{scenePreview.release();}
    const sceneApplied=await historicalMigrator(AGENTS_DIRECTORY,53)(am,AGENTS_DIRECTORY);
    assert.ok(sceneApplied.includes('0051_mail_scene_execution.sql'));
    const savedProjectionSql=await fsp.readFile(path.join(AGENTS_DIRECTORY,
      '0054_bound_mail_exact_sent_projection.sql'),'utf8');
    const savedPreview=await am.connect();
    try{
      await savedPreview.query('BEGIN');
      await savedPreview.query(savedProjectionSql);
      assert.equal(await count(savedPreview,`SELECT count(*)::int n FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='secureshop_agents'
        AND p.proname='project_bound_lab_mail_send'`),1);
      await savedPreview.query('ROLLBACK');
    }catch(error){await savedPreview.query('ROLLBACK').catch(()=>{});throw error;}
    finally{savedPreview.release();}
    assert.deepEqual(await historicalMigrator(AGENTS_DIRECTORY,54)(am,AGENTS_DIRECTORY),['0054_bound_mail_exact_sent_projection.sql']);
    assert.deepEqual(await historicalMigrator(AGENTS_DIRECTORY,54)(am,AGENTS_DIRECTORY),[]);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[owned.targetId])).rows,retainedMessages);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[owned.targetId])).rows,retainedOperations);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.bound_mail_preexecution_rejections ORDER BY request_id')).rows,retainedRejections);
    status.savedSendMigration=true;
    const currentTail=(await require('../../db/postgres/migrate').readMigrations(AGENTS_DIRECTORY))
      .filter(row=>Number(row.name.slice(0,4))>54).map(row=>row.name);
    assert.deepEqual(await migrate(am,AGENTS_DIRECTORY),currentTail);
    assert.deepEqual(await migrate(am,AGENTS_DIRECTORY),[]);
    const sceneBinding=require('../../server/services/secureshopMailSceneBinding');
    const cleanupAuthority=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository')
      .createSecureShopResetCleanupAuthorityRepository(identity);
    const sceneInbox=require('../../server/database/postgres/secureshopPersonaInboxRepository')
      .createSecureShopPersonaInboxRepository(agents,{checkCurrent:value=>launches.assertCurrent(sceneBinding.current(value)),
        checkAclTransition:async()=>{throw Error('ACL transition not requested');},
        checkCleanup:value=>cleanupAuthority.checkTarget({...value,targetKind:'persona_inbox',fromGeneration:value.generation})});
    const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository:require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches}),
      reviewPool:review,launches});
    const products=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{
      checkCurrent:scope=>launches.assertCurrent(scope),checkCleanup:async()=>{throw Error('Product cleanup not requested');}});
    const catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({
      sourcePool:commerce,repository:products,scenes,personaAuthority:authority,
      checkCurrent:scope=>launches.assertCurrent(scope),
      resolveTarget:scope=>launches.reserveProductsTarget({...scope,expectedGeneration:scope.generation})});
    const mailScenes=require('../../server/services/secureshopMailScenes').createMailScenes({
      repository:require('../../server/database/postgres/secureshopMailSceneRepository').createMailSceneRepository({pool:identity,launches}),
      scenes,catalog,agentsPool:agents,launches,inboxRepository:sceneInbox,resolveFixtures:async()=>fixtures,personaAuthority:authority});
    const customerVerified=await bound.authenticateBoundToken({scope:customerScope,token:customerBound.token});
    const customerContext={scope:customerScope,persona:{id:customerVerified.user.id,role:customerVerified.user.role},
      personaSession:{sessionId:customerVerified.sessionId,authorityVersion:customerVerified.authorityVersion}};
    const merchantContext={scope:merchantScope,persona:{id:merchantVerified.user.id,role:merchantVerified.user.role},personaSession:owned.personaSession};
    assert.equal(await scenes.readExisting(customerScope),null,'mail is the first product-scene visitor');
    const customerTarget=await mailScenes.resolve(customerContext);
    const merchantTarget=await mailScenes.resolve(merchantContext);
    assert.equal(customerTarget.targetId,registeredTarget.targetId);
    assert.equal(merchantTarget.targetId,customerTarget.targetId);
    assert.deepEqual(sceneBinding.birth(customerTarget),registeredTarget);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[owned.targetId])).rows,retainedMessages);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.bound_mail_preexecution_rejections ORDER BY request_id')).rows,retainedRejections);
    assert.equal((await identity.query('SELECT adoption_kind FROM identity.secureshop_mail_scenes WHERE target_id=$1',[owned.targetId])).rows[0].adoption_kind,'unique_owner');
    status.mailSceneLegacyAdoption=true;
    const mailInput=(context,target)=>({...context,target,targetId:target.targetId,mode:'vuln',operationId:randomUUID()});
    const savedStartInput=mailInput(merchantContext,merchantTarget);
    const savedStartBody={from:merchant.email,to:customer.email,
      subject:'Exact sent projection',body_markdown:'Persisted new thread only'};
    const savedStart=await mail.send(savedStartInput,savedStartBody);
    assert.deepEqual(await mail.readSavedSend(savedStartInput),{
      recipientId:customer.shopUserId,to:customer.email,
      subject:savedStartBody.subject,body_markdown:savedStartBody.body_markdown});
    const savedReplyInput=mailInput(merchantContext,merchantTarget);
    const savedReplyBody={from:merchant.email,to:customer.email,
      subject:'Re: Exact sent projection',body_markdown:'Persisted reply only',
      threadId:savedStart.thread_id};
    const savedReply=await mail.send(savedReplyInput,savedReplyBody);
    assert.deepEqual(await mail.readSavedSend(savedReplyInput),{
      recipientId:customer.shopUserId,to:customer.email,
      subject:savedReplyBody.subject,body_markdown:savedReplyBody.body_markdown});
    assert.equal((await mail.readSavedSend({...savedReplyInput,operationId:randomUUID()})),null);
    assert.equal((await agents.query(`SELECT has_function_privilege(
      'secureshop_agents.project_bound_lab_mail_send(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid)',
      'EXECUTE') AS allowed`)).rows[0].allowed,true);
    await assert.rejects(agents.query('SELECT body_markdown FROM secureshop_agents.lab_mail_messages LIMIT 1'),{code:'42501'});
    status.savedSendExactProjection=true;
    const directSaved=(input,caller,grant,operation)=>{
      const s=input.scope;
      return agents.query(`SELECT secureshop_agents.project_bound_lab_mail_send(
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS saved`,[
        input.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,
        s.platformSessionId,caller,input.personaSession.sessionId,input.persona.role,
        input.personaSession.authorityVersion,input.mode,operation,grant]);
    };
    await assert.rejects(directSaved(savedReplyInput,customer.shopUserId,
      sceneBinding.productScene(merchantTarget).scene.grantId,savedReplyInput.operationId),{code:'42501'});
    await assert.rejects(directSaved(savedReplyInput,merchant.shopUserId,
      randomUUID(),savedReplyInput.operationId),{code:'42501'});
    assert.equal((await directSaved(savedReplyInput,merchant.shopUserId,
      sceneBinding.productScene(merchantTarget).scene.grantId,randomUUID())).rows[0].saved,null);
    status.savedSendAuthorityFenced=true;
    await am.query(`UPDATE secureshop_agents.lab_mail_messages SET body_markdown='tampered'
      WHERE target_id=$1 AND message_id=$2`,[merchantTarget.targetId,savedReply.email_id]);
    await assert.rejects(mail.readSavedSend(savedReplyInput),{code:'55000'});
    await am.query(`UPDATE secureshop_agents.lab_mail_messages SET body_markdown=$3
      WHERE target_id=$1 AND message_id=$2`,[merchantTarget.targetId,savedReply.email_id,
      savedReplyBody.body_markdown]);
    assert.equal((await mail.readSavedSend(savedReplyInput)).body_markdown,savedReplyBody.body_markdown);
    status.savedSendTamperDenied=true;
    // Q49 uses the real repository effect transaction. Synthetic incoming mail
    // is admitted by the existing SQL function, never inserted as a receipt.
    const q49Snapshot=async()=>({
      messages:(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[merchantTarget.targetId])).rows,
      receipts:(await am.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id',[merchantTarget.targetId])).rows,
    });
    const q49SourceInput=mailInput(customerContext,customerTarget);
    const q49Source=await mail.send(q49SourceInput,{from:customer.email,to:merchant.email,
      subject:'Q49 exact selected source',body_markdown:'Immutable selected native source.'});
    const expectedSource={threadId:q49Source.thread_id,messageId:q49Source.email_id,
      sha256:q49Source.receipt.contentSha256};
    const sourceRead=await mail.browse(mailInput(merchantContext,merchantTarget),merchant.shopUserId);
    assert.deepEqual(sourceRead.receipt.messages.find(row=>row.id===expectedSource.messageId),
      {id:expectedSource.messageId,sha256:expectedSource.sha256});
    const featureModes=require('../../server/services/secureshopFeatureModeAuthority');
    const q49ModeRepository=require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const q49ModeAuthority=featureModes.createFeatureModeAuthority({launches,
      progress:q49ModeRepository});
    const q49Context={...merchantContext,target:await scenes.readExisting(merchantScope)};
    // Native service assembly checks real transport schema, authority and mode;
    // the retained reply graph remains unavailable here and is never inferred.
    const q49Application=require('../../server/services/secureshopMailApplication').createMailApplication({
      mode:'vuln',modeAuthority:q49ModeAuthority,mailRepository:mail,graph,
      recoveryRepository:require('../../server/database/postgres/secureshopMailRecoveryRepository')
        .createMailRecoveryRepository({personaAuthority:authority}),
      resolveTarget:context=>mailScenes.resolve(context),
      readExistingTarget:scope=>mailScenes.readRetained(scope),
      readReadiness:async context=>{
        await require('../../server/services/secureshopMailProduction').assertMailSchema(agents);
        await launches.assertCurrent(context.scope);
        await authority.capture({scope:context.scope,personaId:context.persona.id,
          role:context.persona.role,...context.personaSession}).assertRemoteAdmission();
        const token=await featureModes.captureFeatureMode(q49ModeAuthority,context.scope,'mail');
        await token.assertCurrent();return {ready:true,modeCapability:featureModes.projectFeatureMode(token)};
      }});
    const q49Reads=require('../../server/services/secureshopRoleMailRead').createBoundMailChat({
      mailApplication:q49Application,listMailActors:scope=>personas.listMailActors(scope),modeAuthority:q49ModeAuthority});
    const q49Actions=require('../../server/services/secureshopRoleMailActions').createBoundMailActions({
      mailApplication:q49Application,listMailActors:scope=>personas.listMailActors(scope),modeAuthority:q49ModeAuthority});
    const q49Digest=require('../../server/services/mcp/protocolContext').canonicalDigest;
    const outerMode=featureModes.projectFeatureMode(await featureModes.captureFeatureMode(q49ModeAuthority,merchantScope,'merchant_assistant'));
    const recipientsPacket=await q49Reads.recipients({context:q49Context,search:customer.username});
    assert.equal(recipientsPacket.recipients.find(row=>row.id===customer.shopUserId)?.email,customer.email);
    const selected=(packet,kind,sourceId)=>({version:1,kind,choiceId:randomUUID(),sourceId,
      snapshotSha256:q49Digest(packet),snapshot:packet,card:{title:'Controlled native selection'}});
    // A genuinely new merchant has a catalog scene but has never visited mail.
    // Existing customer delivery seeded the retained target; no grant is deleted.
    const freshMerchant=async label=>{
      const registration=await standalone.register({username:`first_mail_${label}_${suffix}`,
        email:`first_mail_${label}_${suffix}@example.invalid`,password:'disposable-mail-password',role:'merchant'});
      const principal=await standalone.establishTenantContext(registration.context);
      const issued=await launches.issueOrRenew({platformOwnerId:principal.ownerId,
        platformSessionId:principal.sessionId,expiresAt,shopPrincipal:principal});
      const scope=launchScope(issued),login=await bound.establishSession({scope,shopPrincipal:principal});
      const verified=await bound.authenticateBoundToken({scope,token:login.token});
      const context={scope,persona:{id:verified.user.id,role:verified.user.role},
        personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};
      const fence=authority.capture({scope,personaId:context.persona.id,role:context.persona.role,...context.personaSession});
      const target=await catalog.prepareTarget({...context,
        personaEffect:require('../../server/services/secureshopPersonaProductEffect').createPersonaProductEffect(fence)});
      return {...context,target};
    };
    const allMailGrants=()=>am.query('SELECT * FROM secureshop_agents.mail_scene_execution_grants ORDER BY grant_id').then(result=>result.rows);
    const allMailEffects=async()=>({
      messages:(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages ORDER BY message_id')).rows,
      receipts:(await am.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts ORDER BY operation_id')).rows,
    });
    const freshContext=await freshMerchant('ready');
    assert.equal(freshContext.scope.platformOwnerId,merchantScope.platformOwnerId);
    assert.equal(freshContext.target.scene.sceneId,q49Context.target.scene.sceneId);
    assert.ok((await allMailGrants()).some(row=>row.launch_id===customerScope.launchId),
      'the actual customer seed already admitted its own mail grant');
    assert.equal((await allMailGrants()).filter(row=>row.launch_id===freshContext.scope.launchId).length,0);
    const freshBefore=await allMailEffects(),grantsBefore=await allMailGrants();
    await assert.rejects(q49Application.readRetainedTarget(freshContext),{code:'MAIL_SCENE_STALE'});
    assert.deepEqual(await allMailGrants(),grantsBefore,'saved readback cannot create a missing caller grant');
    const freshRecipients=await q49Reads.recipients({context:freshContext,search:customer.username});
    const freshConversation=await conversations.create(freshContext.scope,freshContext.persona,
      require('../../server/services/secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.merchantAssistant);
    const freshPreparation={context:freshContext,source:{sessionId:freshConversation.id,requestId:randomUUID()},
      origin:{step:1,callId:'native-first-mail-prepare'},
      selected:selected(freshRecipients,'merchant_mail_recipient',customer.shopUserId),action:'send',
      input:{subject:'First-use native proposal',body_markdown:'No send before confirmation.'},
      modeCapability:featureModes.projectFeatureMode(await featureModes.captureFeatureMode(q49ModeAuthority,freshContext.scope,'merchant_assistant'))};
    const firstProposal=await q49Actions.prepare(freshPreparation);
    const firstGrants=await allMailGrants();
    const createdGrants=firstGrants.filter(row=>!grantsBefore.some(prior=>prior.grant_id===row.grant_id));
    assert.equal(createdGrants.length,1);assert.equal(createdGrants[0].launch_id,freshContext.scope.launchId);
    assert.equal(createdGrants[0].original_platform_owner_id,freshContext.scope.platformOwnerId);
    assert.equal(createdGrants[0].original_platform_session_id,freshContext.scope.platformSessionId);
    assert.equal(createdGrants[0].target_id,merchantTarget.targetId);
    assert.equal(createdGrants[0].scene_id,freshContext.target.scene.sceneId);
    assert.deepEqual(await allMailEffects(),freshBefore,'first-use preparation records no mail send or read receipt');
    assert.deepEqual(await q49Actions.prepare(freshPreparation),firstProposal);
    assert.deepEqual(await allMailGrants(),firstGrants,'second preparation adds no grant');
    assert.deepEqual(await allMailEffects(),freshBefore);
    const staleContext=await freshMerchant('stale');
    const foreignOuter=await catalog.prepareTarget({scope:oldScope,persona:oldBinding.persona,
      personaSession:oldBinding.personaSession});
    assert.notEqual(foreignOuter.scene.sceneId,staleContext.target.scene.sceneId);
    const staleGrantsBefore=await allMailGrants(),staleEffectsBefore=await allMailEffects();
    const staleRecipients=await q49Reads.recipients({context:staleContext,search:customer.username});
    await assert.rejects(q49Actions.prepare({...freshPreparation,
      context:{...staleContext,target:foreignOuter},
      source:{sessionId:freshConversation.id,requestId:randomUUID()},
      selected:selected(staleRecipients,'merchant_mail_recipient',customer.shopUserId),
      modeCapability:featureModes.projectFeatureMode(await featureModes.captureFeatureMode(q49ModeAuthority,staleContext.scope,'merchant_assistant'))}),
    {code:'MAIL_SCENE_STALE'});
    assert.deepEqual(await allMailGrants(),staleGrantsBefore,'stale foreign outer scene cannot grant any mail rights');
    assert.deepEqual(await allMailEffects(),staleEffectsBefore);
    assert.equal((await allMailGrants()).filter(row=>row.launch_id===staleContext.scope.launchId).length,0);
    const q49SourceRef={sessionId:conversation.id,requestId:randomUUID()},q49Origin={step:1,callId:'native-mail-prepare'};
    const sendPreparation={context:q49Context,source:q49SourceRef,origin:q49Origin,
      selected:selected(recipientsPacket,'merchant_mail_recipient',customer.shopUserId),
      action:'send',input:{subject:'Frozen native send proposal',body_markdown:'Literal <b>native</b> send bytes.'},modeCapability:outerMode};
    const prepareBefore=await q49Snapshot();
    const sendProposal=await q49Actions.prepare(sendPreparation);
    assert.deepEqual(await q49Actions.prepare(sendPreparation),sendProposal,'proposal ID and digest are deterministic');
    assert.deepEqual(await q49Snapshot(),prepareBefore,'two prepare calls have no send or operation effect');
    const sourcePacket=await q49Reads.list({context:q49Context,requestId:randomUUID()});
    const replyPrepareBefore=await q49Snapshot();
    const replyProposal=await q49Actions.prepare({context:q49Context,
      source:{...q49SourceRef,requestId:randomUUID()},origin:q49Origin,
      selected:selected(sourcePacket,'merchant_mail_message',q49Source.email_id),action:'reply',input:{},modeCapability:outerMode});
    assert.deepEqual(replyProposal.expectedSource,expectedSource);
    assert.equal(replyProposal.send,null,'reply preparation cannot preapprove a generated body');
    assert.deepEqual(await q49Snapshot(),replyPrepareBefore);
    const confirmedSend=await q49Actions.confirm({context:q49Context,proposal:sendProposal});
    assert.equal(confirmedSend.status,'saved');assert.equal(confirmedSend.sendOperationId,sendProposal.proposalId);
    assert.deepEqual(confirmedSend.savedSend,{recipientId:customer.shopUserId,to:customer.email,...sendPreparation.input});
    const confirmedBefore=await q49Snapshot();
    assert.equal(confirmedBefore.messages.length,replyPrepareBefore.messages.length+1);
    assert.deepEqual(await q49Actions.recover({context:q49Context,proposal:sendProposal}),confirmedSend);
    assert.deepEqual(await q49Actions.confirm({context:q49Context,proposal:sendProposal}),confirmedSend);
    assert.deepEqual(await q49Snapshot(),confirmedBefore,'confirmation replay and saved recovery have no new effect');
    await assert.rejects(q49Actions.confirm({context:q49Context,
      proposal:{...sendProposal,send:{...sendProposal.send,body_markdown:'Changed draft'}}}),{code:'ROLE_MAIL_PROPOSAL_MISMATCH'});
    assert.deepEqual(await q49Snapshot(),confirmedBefore);
    const preemptProposal=await q49Actions.prepare({...sendPreparation,
      source:{...q49SourceRef,requestId:randomUUID()}});
    const actualPreemptBody={...preemptProposal.send,body_markdown:'Actual direct operation bytes, not the proposed draft.'};
    const actualPreempt=await mail.send({...mailInput(merchantContext,merchantTarget),
      operationId:preemptProposal.proposalId},actualPreemptBody);
    const adapterPreemptBefore=await q49Snapshot();
    const actualPreemptRecovered=await q49Actions.recover({context:q49Context,proposal:preemptProposal});
    assert.equal(actualPreemptRecovered.status,'saved_unattributed');
    assert.equal(actualPreemptRecovered.canRetrySameId,false);
    assert.equal(actualPreemptRecovered.emailId,actualPreempt.email_id);
    assert.deepEqual(actualPreemptRecovered.savedSend,{recipientId:customer.shopUserId,
      to:customer.email,subject:actualPreemptBody.subject,body_markdown:actualPreemptBody.body_markdown});
    await assert.rejects(q49Actions.confirm({context:q49Context,proposal:preemptProposal}),{code:'23505'});
    assert.deepEqual(await q49Snapshot(),adapterPreemptBefore);
    // The four public saved fields alone cannot prove a matching send request:
    // vulnerable mode permits an owned From header suffix without changing them.
    const headerProposal=await q49Actions.prepare({...sendPreparation,
      source:{...q49SourceRef,requestId:randomUUID()}});
    const headerInput={...mailInput(merchantContext,merchantTarget),operationId:headerProposal.proposalId};
    const headerBody={...headerProposal.send,from:merchant.email+'\r\nX-Native: permitted owned header'};
    const headerSent=await mail.send(headerInput,headerBody);
    const headerBefore=await q49Snapshot();
    const headerOperation=await q49Actions.recover({context:q49Context,proposal:headerProposal});
    assert.equal(headerOperation.status,'saved_unattributed');assert.equal(headerOperation.canRetrySameId,false);
    assert.equal(headerOperation.emailId,headerSent.email_id);
    assert.equal(headerOperation.sendOperationId,headerProposal.proposalId);
    assert.deepEqual(headerOperation.savedSend,confirmedSend.savedSend,
      'identical public saved bytes must not hide a different full request');
    const headerReceipt=await mail.recover(headerInput);
    const expectedHash=await mail.hashSendRequest(headerInput,headerProposal.send);
    const actualHash=await mail.hashSendRequest(headerInput,headerBody);
    const independentHash=(await agents.query(`SELECT encode(sha256(convert_to(
      jsonb_build_array('send',$1::jsonb)::text,'UTF8')),'hex') AS digest`,[
      JSON.stringify(require('../../server/database/postgres/secureshopBoundMailRepository').prepareSend(headerProposal.send))])).rows[0].digest;
    assert.equal(expectedHash,independentHash,'PostgreSQL JSONB text defines the request digest');
    assert.equal(actualHash,headerReceipt.requestSha256);assert.notEqual(expectedHash,actualHash);
    const storedHeader=headerBefore.messages.find(row=>Number(row.message_id)===headerSent.email_id);
    assert.equal(storedHeader.from_addr,headerBody.from);assert.match(storedHeader.headers_raw,/X-Native: permitted owned header/);
    assert.deepEqual(await q49Snapshot(),headerBefore,'full-hash recovery is read only');
    await assert.rejects(q49Actions.confirm({context:q49Context,proposal:headerProposal}),{code:'23505'});
    assert.deepEqual(await q49Snapshot(),headerBefore);
    // A send at the reply's derived ID has an honest receipt but no completed
    // Q49 reply graph/source proof. Missing terminal provenance cannot be saved.
    const directReplyOperationId=require('../../server/services/secureshopBoundMailGraph')
      .operationId(replyProposal.proposalId,'reply');
    const directReplyBody={from:merchant.email,to:customer.email,threadId:expectedSource.threadId,
      subject:'Direct preempted reply',body_markdown:'Direct receipt without a terminal reply graph.'};
    const directReply=await mail.send({...mailInput(merchantContext,merchantTarget),
      operationId:directReplyOperationId},directReplyBody);
    const directReplyBefore=await q49Snapshot();
    const missingTerminal=await q49Actions.recover({context:q49Context,proposal:replyProposal});
    assert.equal(missingTerminal.status,'saved_unattributed');assert.equal(missingTerminal.canRetrySameId,false);
    assert.equal(missingTerminal.sendOperationId,directReplyOperationId);
    assert.equal(missingTerminal.emailId,directReply.email_id);assert.equal(missingTerminal.threadId,expectedSource.threadId);
    assert.deepEqual(missingTerminal.savedSend,{recipientId:customer.shopUserId,
      to:customer.email,subject:directReplyBody.subject,body_markdown:directReplyBody.body_markdown});
    assert.equal(await count(am,'SELECT count(*)::int n FROM secureshop_agents.turn_requests WHERE request_id=$1',[replyProposal.proposalId]),0);
    assert.deepEqual(await q49Snapshot(),directReplyBefore);
    const q49ReplyInput=mailInput(merchantContext,merchantTarget);
    const q49ReplyBody={from:merchant.email,to:customer.email,threadId:expectedSource.threadId,
      subject:'Re: Q49 exact selected source',body_markdown:'Exact frozen native reply.'};
    const deniedBefore=await q49Snapshot();
    for(const invalid of [{...expectedSource,sha256:'0'.repeat(64)},
      {...expectedSource,threadId:expectedSource.threadId+100000},
      {...expectedSource,messageId:expectedSource.messageId+100000}]){
      await assert.rejects(mail.send({...q49ReplyInput,operationId:randomUUID()},
        {...q49ReplyBody,threadId:invalid.threadId},
        {expectedSource:invalid}),{code:'MAIL_SOURCE_STALE'});
      assert.deepEqual(await q49Snapshot(),deniedBefore,'source denial rolls back browse and send receipts');
    }
    await assert.rejects(mail.send({...q49ReplyInput,operationId:randomUUID()},
      {...q49ReplyBody,threadId:expectedSource.threadId+1},{expectedSource}),{code:'INVALID_ARGUMENT'});
    assert.deepEqual(await q49Snapshot(),deniedBefore);
    const q49Reply=await mail.send(q49ReplyInput,q49ReplyBody,{expectedSource});
    assert.equal(q49Reply.replayed,false);
    assert.equal(q49Reply.receipt.senderId,merchant.shopUserId);
    assert.equal(q49Reply.receipt.recipientId,customer.shopUserId);
    assert.equal(q49Reply.thread_id,expectedSource.threadId);
    assert.deepEqual(await mail.readSavedSend(q49ReplyInput),{recipientId:customer.shopUserId,
      to:customer.email,subject:q49ReplyBody.subject,body_markdown:q49ReplyBody.body_markdown});
    const q49AfterReply=await q49Snapshot();
    assert.equal(q49AfterReply.messages.length,deniedBefore.messages.length+1);
    assert.equal(q49AfterReply.receipts.filter(row=>row.operation_id===q49ReplyInput.operationId).length,1);
    // A later incoming source cannot invalidate an already completed operation.
    const newer=await mail.send(mailInput(customerContext,customerTarget),{from:customer.email,
      to:merchant.email,threadId:expectedSource.threadId,subject:'New incoming native source',
      body_markdown:'Committed after the selected source.'});
    const replayBefore=await q49Snapshot();
    const q49Replay=await mail.send(q49ReplyInput,q49ReplyBody,{expectedSource});
    assert.equal(q49Replay.replayed,true);assert.deepEqual(q49Replay.receipt,q49Reply.receipt);
    assert.deepEqual(await q49Snapshot(),replayBefore);
    await assert.rejects(mail.send(q49ReplyInput,{...q49ReplyBody,body_markdown:'Conflicting replay'},
      {expectedSource}),{code:'23505'});
    assert.deepEqual(await q49Snapshot(),replayBefore);
    // A direct same-principal send may preempt an operation UUID. Its actual
    // stored bytes are authoritative; checked recovery must not invent a draft.
    const preemptInput=mailInput(merchantContext,merchantTarget);
    const preemptBody={...q49ReplyBody,body_markdown:'Direct native send won the same operation.'};
    const preempted=await mail.send(preemptInput,preemptBody);
    const preemptBefore=await q49Snapshot();
    await assert.rejects(mail.send(preemptInput,q49ReplyBody,{expectedSource}),{code:'23505'});
    assert.equal((await mail.recover(preemptInput)).receipt.email_id,preempted.email_id);
    assert.equal((await mail.readSavedSend(preemptInput)).body_markdown,preemptBody.body_markdown);
    assert.deepEqual(await q49Snapshot(),preemptBefore);
    const raceSource={threadId:newer.thread_id,messageId:newer.email_id,sha256:newer.receipt.contentSha256};
    const racingInput=mailInput(merchantContext,merchantTarget);
    const raceIncoming=mailInput(customerContext,customerTarget);
    const barrier=await am.connect();let pending,blocking,incoming;
    const settle=promise=>promise.then(value=>({status:'fulfilled',value}),
      error=>({status:'rejected',code:error.code,message:error.message}));
    try{
      await barrier.query('BEGIN');
      await barrier.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||$1::text,0))",[racingInput.scope.platformOwnerId]);
      for(const launchId of [...new Set([racingInput.scope.launchId,raceIncoming.scope.launchId])].sort())
        await barrier.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||$1::text,0))",[launchId]);
      await barrier.query('SELECT target_id FROM secureshop_agents.persona_inbox_targets WHERE target_id=$1 FOR UPDATE',[merchantTarget.targetId]);
      const holder=Number((await barrier.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
      pending=settle(mail.send(racingInput,q49ReplyBody,{expectedSource:raceSource}));
      const deadline=Date.now()+2000;
      do{
        const rows=(await am.query("SELECT pid,usename,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND usename='dvaia_secureshop_agents_runtime'",[holder])).rows;
        if(rows.length){blocking={holder,waiter:Number(rows[0].pid),blockers:rows[0].blockers};break;}
        await new Promise(resolve=>setTimeout(resolve,10));
      }while(Date.now()<deadline);
      assert.ok(blocking,'real runtime send must wait on the canonical owner/launch/target transaction');
      const s=raceIncoming.scope;
      const payload=require('../../server/database/postgres/secureshopBoundMailRepository').prepareSend({
        from:customer.email,to:merchant.email,threadId:raceSource.threadId,
        subject:'Incoming source wins held transaction',body_markdown:'Atomic native incoming source.'});
      incoming=(await barrier.query(`SELECT secureshop_agents.bound_lab_mail(
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::uuid) AS result`,[
        raceIncoming.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,
        raceIncoming.persona.id,raceIncoming.personaSession.sessionId,raceIncoming.persona.role,
        raceIncoming.personaSession.authorityVersion,raceIncoming.mode,raceIncoming.operationId,
        'send',JSON.stringify(payload),sceneBinding.productScene(customerTarget).scene.grantId])).rows[0].result;
      await barrier.query('COMMIT');
    }catch(error){await barrier.query('ROLLBACK').catch(()=>{});throw error;}
    finally{barrier.release();if(pending)await pending;}
    const raceOutcome=await pending;
    assert.equal(raceOutcome.status,'rejected');assert.equal(raceOutcome.code,'MAIL_SOURCE_STALE');
    assert.equal((await mail.recover(racingInput)).found,false);
    assert.equal((await mail.recover(raceIncoming)).receipt.email_id,incoming.email_id);
    assert.equal(await count(am,'SELECT count(*)::int n FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=$1',[racingInput.operationId]),0);
    const latestSource={threadId:incoming.thread_id,messageId:incoming.email_id,
      sha256:incoming.receipt.contentSha256};
    const validAfterRace=mailInput(merchantContext,merchantTarget),validBefore=await q49Snapshot();
    const validAfter=await mail.send(validAfterRace,q49ReplyBody,{expectedSource:latestSource});
    assert.equal(validAfter.replayed,false);
    assert.equal(validAfter.receipt.senderId,merchant.shopUserId);
    assert.equal(validAfter.receipt.recipientId,customer.shopUserId);
    assert.equal((await q49Snapshot()).messages.length,validBefore.messages.length+1);
    const authorityBefore=await q49Snapshot();
    for(const invalid of [
      {...validAfterRace,operationId:randomUUID(),personaSession:{...validAfterRace.personaSession,sessionId:randomUUID()}},
      {...validAfterRace,operationId:randomUUID(),persona:{id:foreign.shop_user_id,role:'customer'}},
      {...validAfterRace,operationId:randomUUID(),scope:{...validAfterRace.scope,platformOwnerId:foreignTenant.owner_id}},
    ]){
      await assert.rejects(mail.send(invalid,q49ReplyBody,{expectedSource:latestSource}));
      assert.deepEqual(await q49Snapshot(),authorityBefore);
    }
    const q49OperationIds=[sendProposal.proposalId,preemptProposal.proposalId,headerProposal.proposalId,
      directReplyOperationId,q49SourceInput.operationId,q49ReplyInput.operationId,
      preemptInput.operationId,raceIncoming.operationId,validAfterRace.operationId];
    const q49Immutable=()=>am.query('SELECT * FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=ANY($1::uuid[]) ORDER BY operation_id',[q49OperationIds]).then(result=>result.rows);
    const q49ReceiptsBeforeReset=await q49Immutable();
    assert.equal(q49ReceiptsBeforeReset.length,q49OperationIds.length);
    const q49Evidence={expectedSource,raceSource,blocking,raceOutcome,
      firstUsePrepare:{grant:createdGrants[0],proposalId:firstProposal.proposalId,
        idempotent:true,zeroMailEffect:true,retainedReadNoProvision:true,staleForeignSceneNoGrant:true},
      proposalId:sendProposal.proposalId,confirmedSend,replyProposalId:replyProposal.proposalId,
      adapterPreemptOperation:actualPreemptRecovered,
      headerPreemptOperation:headerOperation,headerRequestHashes:{expectedHash,actualHash},
      missingTerminalOperation:missingTerminal,
      sourceOperationId:q49SourceInput.operationId,replyOperationId:q49ReplyInput.operationId,
      replyReceipt:q49Reply.receipt,preemptOperationId:preemptInput.operationId,
      preemptReceipt:preempted.receipt,incomingReceipt:incoming.receipt,
      validAfterRaceReceipt:validAfter.receipt};
    const sentByCustomer=await mail.send(mailInput(customerContext,customerTarget),{
      from:customer.email,to:merchant.email,subject:'Shared scene reply',body_markdown:'Customer to merchant'});
    assert.ok((await mail.read(mailInput(merchantContext,merchantTarget),merchant.shopUserId)).emails.some(row=>row.id===sentByCustomer.email_id));
    const relogged=await standalone.login({username:customer.username,password:'disposable-mail-password'});
    const nextCustomer=await standalone.establishTenantContext(relogged.context);
    const nextLaunch=await launches.issueOrRenew({platformOwnerId:nextCustomer.ownerId,platformSessionId:nextCustomer.sessionId,expiresAt,shopPrincipal:nextCustomer});
    const nextScope=launchScope(nextLaunch),nextBound=await bound.establishSession({scope:nextScope,shopPrincipal:nextCustomer});
    const nextActor=await bound.authenticateBoundToken({scope:nextScope,token:nextBound.token});
    const nextContext={scope:nextScope,persona:{id:nextActor.user.id,role:nextActor.user.role},personaSession:{sessionId:nextActor.sessionId,authorityVersion:nextActor.authorityVersion}};
    const nextTarget=await mailScenes.resolve(nextContext);
    assert.equal(nextTarget.targetId,owned.targetId);
    assert.ok((await mail.read(mailInput(nextContext,nextTarget),customer.shopUserId)).emails.some(row=>row.id===delivered.email_id));
    assert.deepEqual(await uncertain.readRejected({...different,target:merchantTarget}),{threadId:separate.thread_id,stage:'prompt_policy_admission'});
    const notes=await sceneInbox.list(nextTarget);
    const noteFence=authority.capture({scope:nextScope,personaId:nextContext.persona.id,role:nextContext.persona.role,...nextContext.personaSession});
    const noteEffect=require('../../server/services/secureshopPersonaInboxEffect').createPersonaInboxEffect({fence:noteFence,repository:sceneInbox});
    const note=await noteEffect.read(nextTarget,nextContext.persona,{messageId:notes[0].messageId,operationId:randomUUID()});
    assert.equal(note.disclosed,true,'advisory cross-persona lesson remains inside shared scene');
    const access=await sceneInbox.readAccessEvent(nextTarget,note.eventId);
    assert.equal(access.version,2);assert.equal(access.launchId,nextScope.launchId);
    assert.equal(access.birth.launchId,merchantScope.launchId);
    status.mailSceneSharedRelogin=true;
    // A mapped birth-session caller must not bypass the current scene grant.
    await assert.rejects(agents.query(`SELECT secureshop_agents.bound_lab_mail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)`,
      [owned.targetId,merchantScope.launchId,merchantScope.scenarioId,merchantScope.generation,merchantScope.platformOwnerId,merchantScope.platformSessionId,
        merchant.shopUserId,owned.personaSession.sessionId,'merchant',owned.personaSession.authorityVersion,'vuln',randomUUID(),'read',JSON.stringify({userId:merchant.shopUserId})]),{code:'42501'});
    await assert.rejects(mail.send({...mailInput(nextContext,nextTarget),persona:{id:foreign.shop_user_id,role:'customer'}},message));
    const provenance=(await am.query('SELECT * FROM secureshop_agents.mail_scene_operation_provenance WHERE operation_id=$1',[sentByCustomer.operationId])).rows[0];
    assert.equal(provenance.launch_id,customerScope.launchId);
    assert.equal(provenance.target_id,registeredTarget.targetId);
    status.mailSceneGrantFenced=true;
    // The new customer's reset retires the shared scene, whose inbox was born
    // in the original merchant launch. Only that first reset may clean it.
    const firstReset=await launches.beginReset({...nextScope,expectedGeneration:nextScope.generation,idempotencyKey:randomUUID()});
    const secondReset=await launches.beginReset({...merchantScope,expectedGeneration:merchantScope.generation,idempotencyKey:randomUUID()});
    const firstTargets=await cleanupAuthority.listTargets(firstReset.resetId);
    assert.deepEqual(firstTargets.targets.map(item=>item.targetKind).sort(),['persona_inbox','products']);
    const claimedInbox=firstTargets.targets.find(item=>item.targetKind==='persona_inbox');
    assert.equal(claimedInbox.targetId,registeredTarget.targetId);
    assert.equal(claimedInbox.launchId,merchantScope.launchId);
    assert.equal((await cleanupAuthority.listTargets(secondReset.resetId)).targets.length,0);
    await assert.rejects(cleanupAuthority.assertResolved(secondReset.resetId),{code:'CLEANUP_REQUIRED'});
    await assert.rejects(mail.read(mailInput(customerContext,customerTarget),customer.shopUserId));
    await assert.rejects(mail.read(mailInput(nextContext,nextTarget),customer.shopUserId));
    const cleanup=require('../../server/services/secureshopMailCleanup');
    const verifiedInbox=cleanup.withMailCleanup(sceneInbox,cleanup.createDurableMailCleanupVerifier(agents));
    const verifiedProducts=require('../../server/database/postgres/secureshopBoundProductRepository')
      .createSecureShopBoundProductRepository(review,{checkCurrent:scope=>launches.assertCurrent(scope),
        checkCleanup:value=>cleanupAuthority.checkTarget({...value,targetKind:'products',
          fromGeneration:value.generation})});
    const reconciler=require('../../server/database/postgres/secureshopTargetReconciliationRepository')
      .createSecureShopTargetReconciliationRepository(identity,{checkAuthority:cleanupAuthority.checkTarget,
        // Mail scene provisioning also created a product target. Reconcile
        // both exact private receipts under the canonical scene claimant.
        readCleanupReceipt:value=>(value.targetKind==='products'
          ?verifiedProducts.readCleanupReceipt({...value,generation:value.fromGeneration},
            {operationId:value.operationId})
          :verifiedInbox.readCleanupReceipt({...value,generation:value.fromGeneration},
            {operationId:value.operationId}))
          .then(privateReceipt=>Object.freeze({...privateReceipt,kind:value.targetKind}))});
    const resetCoordinator=require('../../server/services/secureshopReviewResetCoordinator').createSecureShopReviewResetCoordinator({
      launches,cleanupAuthority,reconciler,personaInboxCleanup:verifiedInbox,productCleanup:verifiedProducts,
      reviewRepository:{cleanup:async()=>{throw Error('Review cleanup not requested');}}});
    assert.equal((await resetCoordinator.recover(firstReset.resetId)).resolved,true);
    assert.equal((await resetCoordinator.recover(firstReset.resetId)).resolved,true);
    assert.equal((await resetCoordinator.recover(secondReset.resetId)).resolved,true);
    const history=(await identity.query('SELECT * FROM identity.secureshop_target_cleanup_history WHERE target_id=$1',[owned.targetId])).rows;
    assert.equal(history.length,1);assert.equal(history[0].operation_id,firstReset.resetId);
    assert.equal(history[0].launch_id,merchantScope.launchId);
    assert.equal(await count(am,'SELECT count(*)::int n FROM secureshop_agents.lab_mail_messages WHERE target_id=$1',[owned.targetId]),0);
    assert.equal(await count(am,'SELECT count(*)::int n FROM secureshop_agents.persona_inbox_scene_access_provenance WHERE event_id=$1',[note.eventId]),1);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.bound_mail_preexecution_rejections ORDER BY request_id')).rows,retainedRejections);
    assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 ORDER BY message_id',[oldTarget.targetId])).rows,oldRows.messages);
    await assert.rejects(mail.send(validAfterRace,q49ReplyBody,{expectedSource:latestSource}));
    await assert.rejects(mail.recover(q49ReplyInput));
    await assert.rejects(q49Actions.recover({context:q49Context,proposal:sendProposal}));
    assert.deepEqual(await q49Immutable(),q49ReceiptsBeforeReset,
      'reset retires exact source/reply messages while immutable operation receipts remain unchanged');
    await receipt(evidencePath.replace(/\.json$/,'')+'-q49-native.json',{
      scope:'controlled native Q49 expected-source transaction and immutable receipt checks; no model/browser',
      passed:true,exactCheckedReply:true,sourceDenialZeroEffect:true,atomicIncomingSourceRace:true,
      zeroEffectPrepare:true,deterministicProposal:true,exactSendConfirmation:true,proposalTamperDenied:true,
      completedReplayBeforeFreshness:true,conflictingReplayDenied:true,directPreemptionHonest:true,
      ownerSessionDenied:true,resetFenced:true,separateLearnerPreserved:true,
      immutableReceiptsPreserved:true,...q49Evidence});
    status.mailSceneCanonicalCleanup=true;
    assert.equal(oldSent.receipt.recipientId, template.id);
    status.passed = true;
    await receipt(evidencePath, status);
    t.diagnostic(status.scope);
  });
