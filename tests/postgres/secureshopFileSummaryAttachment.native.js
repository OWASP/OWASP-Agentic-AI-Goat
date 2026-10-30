'use strict';
require('./secureshopFilesPrincipalMigration.native');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');

test('file summary attachment uses one real persona lease without re-entering its PostgreSQL locks',
  { skip: process.env.PG_TEST_DISPOSABLE !== 'yes', timeout: 60000 }, async t => {
    assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
    const sourceRoot = await fs.realpath(path.resolve(__dirname, '../..'));
    const isolatedWorkspace = await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
    assert.equal(await fs.realpath(process.cwd()), sourceRoot);
    assert.notEqual(isolatedWorkspace, sourceRoot);
    const pools = [];
    const pool = (store, role) => {
      const url = new URL(process.env[`V19_ATTACHMENT_${store}_${role}_URL`]);
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/owasp_ai_goat_test_persona_(identity|agents|commerce|review)_[a-f0-9]{12}$/);
      const value = new Pool({ connectionString: url.href, max: 4, statement_timeout: 3000,
        connectionTimeoutMillis: 3000 });
      pools.push(value); return value;
    };
    t.after(() => Promise.all(pools.map(value => value.end())));
    const identity = pool('IDENTITY', 'RUNTIME'), identityMigration = pool('IDENTITY', 'MIGRATION');
    const sceneProvision = pool('IDENTITY', 'RUNTIME'), sceneLease = pool('IDENTITY', 'RUNTIME');
    const cleanupLease = pool('IDENTITY', 'RUNTIME');
    const agents = pool('AGENTS', 'RUNTIME'), agentsMigration = pool('AGENTS', 'MIGRATION');
    const commerce = pool('COMMERCE', 'RUNTIME'), commerceMigration = pool('COMMERCE', 'MIGRATION');
    const review = pool('REVIEW', 'RUNTIME'), reviewMigration = pool('REVIEW', 'MIGRATION');
    const { migrate } = require('../../db/postgres/migrate');
    await migrate(identityMigration, 'db/postgres/identity-migrations');
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    await migrate(agentsMigration, 'db/postgres/workshop-migrations/secureshop_agents');
    await migrate(commerceMigration, 'db/postgres/workshop-migrations/secureshop');
    await migrate(reviewMigration, 'db/postgres/workshop-migrations/secureshop_review');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);
    await require('../../server/database/postgres/secureshopStandaloneSeed')
      .seedSecureShopStandaloneDefaults(identityMigration);
    const identities = require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
    const passwordHash = await require('bcryptjs').hash('owned-v19-attachment', 4);
    const user = await identities.createUser({ username: `v19-attachment-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const expiresAt = new Date(Date.now() + 600000);
    const platformSession = await identities.createSession({ userId: user.id, token: randomUUID(), expiresAt,
      expectedPasswordHash: passwordHash });
    const launches = require('../../server/database/postgres/secureshopLaunchRepository')
      .createSecureShopLaunchRepository(identity);
    const scope = require('../../server/services/secureshopConversationBinding').createLaunchScope(
      (await launches.issueOrRenew({ platformOwnerId: user.id,
        platformSessionId: platformSession.id, expiresAt })).binding);
    const checkCurrent = input => launches.assertCurrent(input);
    const personaAuthority = require('../../server/database/postgres/secureshopBoundPersonaAuthority')
      .createSecureShopBoundPersonaAuthority({ pool: agents, checkCurrent });
    const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository')
      .createSecureShopBoundPersonaRepository({ commercePool: commerce, agentsPool: agents, personaAuthority,
        auditStore: require('../../server/database/postgres/secureshopBoundAuditRepository')
          .createBoundAuditStore({ store: 'agents', pool: agents }) });
    await personas.ensureTemplates();
    const personaAuth = require('../../server/services/secureshopBoundPersonaAuth')
      .createSecureShopBoundPersonaAuth({ repository: personas, launches, personaAuthority,
        jwtSecret: 'v19-native-shop-principal-partition-at-least-32-bytes' });
    const defaultAuth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({
        repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }),
      });
    const defaultBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches, personaAuth, authService: defaultAuth });
    const persona = (await personas.listPersonas()).find(value => value.role === 'customer');
    assert.ok(persona);
    const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
    await personas.createSession({ scope, sessionId: personaSession.sessionId, jti: randomUUID(), persona,
      authorityVersion: personaSession.authorityVersion,
      expiresAt: new Date(Date.now() + 600000).toISOString() });
    const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-v19-attachment-native-')));
    t.after(() => fs.rm(root, { recursive: true, force: true }));
    const priorUploadRoot = process.env.SECURESHOP_UPLOAD_ROOT;
    process.env.SECURESHOP_UPLOAD_ROOT = path.join(root, 'uploads');
    await fs.mkdir(process.env.SECURESHOP_UPLOAD_ROOT, { recursive: true, mode: 0o700 });
    t.after(() => { if (priorUploadRoot === undefined) delete process.env.SECURESHOP_UPLOAD_ROOT;
      else process.env.SECURESHOP_UPLOAD_ROOT = priorUploadRoot; });
    const files = require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({ root });
    const audit = require('../../server/database/postgres/secureshopBoundAuditRepository')
      .createBoundAuditStore({ store: 'review', pool: review });
    const products = require('../../server/database/postgres/secureshopBoundProductRepository')
      .createSecureShopBoundProductRepository(review, { checkCurrent, auditStore: audit,
        checkCleanup: async () => { throw new Error('cleanup outside attachment fixture'); } });
    const cleanup = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool: cleanupLease, launches, files, personaInboxFactory: false });
    t.after(async () => { await cleanup.closeFeatureTransports(); await cleanup.auditLedger?.close?.(); });
    const productTarget = await launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation });
    await products.provision({ ...scope, targetId: productTarget.targetId }, { ownMerchantId: 12, products: [{
      id: 7, sourceRetailerId: 1, retailerId: 12, name: 'Owned attachment scene',
      description: 'Disposable native fixture', descriptionHtml: '<p>Disposable native fixture</p>',
      price: 12.5, category: 'fixture', imageUrl: null, images: [], stockQuantity: 4,
      status: 'active', templateSource: '{{source}}', createdAt: null, updatedAt: null }] });
    const sceneRepository = require('../../server/database/postgres/secureshopSceneRepository')
      .createSecureShopProductionSceneRepository({ pool: identity, provisionPool: sceneProvision,
        leasePool: sceneLease, launches });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
      repository: sceneRepository, reviewPool: review, launches });
    const scene = await scenes.resolve(scope);
    assert.ok(scene?.scene);
    const modeStamp = createHash('sha256').update('vuln').digest('hex');
    const modeAuthority = { async capture() { return { snapshot: { version: 1, featureId: 'file_summary',
      policyVersion: 'file-summary-data-only-v1', scope, generation: 1, mode: 'vuln', modeStamp },
    assertCurrent: () => checkCurrent(scope), assertCurrentAtEffect: () => checkCurrent(scope) }; },
    assertToken: value => value };
    const attachment = require('../../server/services/secureshopFileSummaryAttachment')
      .createFileSummaryAttachment({ launches, files, personaAuthority,
        scenes, modeAuthority });
    const input = { scope, persona: { id: persona.id, role: 'customer' }, personaSession,
      sessionId: randomUUID(), requestId: randomUUID(), filename: 'sibling-control.txt',
      mime: 'text/plain', bytes: Buffer.from('Owned native attachment lease regression.\n') };
    const { SUMMARY_TOOL, createFileSummaryExecutionConfig } = require('../../server/services/secureshopFileSummaryExecutionConfig');
    const config = createFileSummaryExecutionConfig({ mode: 'vuln', byteCount: input.bytes.length });
    const messages = [], observations = [], claims = new Map();
    let tokens = 0, providerCalls = 0, saved, execution, toolFailure;
    const runner = require('../../server/services/secureshopBoundAgentRunner').createBoundAgentRunner({ ...config,
      turns: { async run(_id, _binding, _persona, _options, work) {
        const identity = { runId: 'v19-native-run', ownerKey: 'v19-native-owner', generation: 1, durableGeneration: '1' };
        return work({ identity, signal: AbortSignal.timeout(5000), check: () => checkCurrent(scope),
          async effect(_key, callback) { return callback(); }, async effectWithReceipt(key, callback) {
            return { value: await callback(), receipt: { version: 1, runId: identity.runId,
              ownerKey: identity.ownerKey, generation: '1', effectKey: `${input.requestId}:${key}`, status: 'completed' } };
          }, async trace() {} });
      } },
      conversations: { async assertOwned() { await checkCurrent(scope); },
        async getMessages() { return messages.map(value => structuredClone(value)); } },
      repository: { async appendMessage(_id, _binding, message) { messages.push(structuredClone(message)); },
        async getTokens() { return tokens; }, async addTokens(_id, _binding, count) { tokens += count; },
        async appendTraces() {} },
      journal: { async claim({ requestId }) { if (claims.has(requestId)) return structuredClone(claims.get(requestId));
        const value = { status: 'claimed', claimId: requestId }; claims.set(requestId, value); return value; },
      async complete({ requestId, result }) { claims.set(requestId, { status: 'completed', claimId: requestId,
        result: structuredClone(result) }); }, async markUncertain() {} },
      provider: { async chat() { providerCalls++; return providerCalls === 1
        ? { provider: 'native-controlled', model: 'native-controlled', mocked: false, stop_reason: 'tool_use',
          tool_uses: [{ id: 'read', name: SUMMARY_TOOL, args: {} }] }
        : { provider: 'native-controlled', model: 'native-controlled', mocked: false,
          stop_reason: 'end_turn', text: 'Controlled native summary.' }; } },
      pool: { async callTool() { throw Error('External dispatch forbidden'); } },
      createLocalTools: async (_binding, _context, _supplied, actualExecution) => {
        execution = actualExecution;
        return new Map([[SUMMARY_TOOL, async args => { assert.deepEqual(args, {});
          try { saved = await attachment.writeAndReadBack(input, actualExecution); }
          catch (error) { toolFailure = { name: error?.name, code: error?.code, message: error?.message,
            cause: error?.cause && { name: error.cause.name, code: error.cause.code, message: error.cause.message } };
            throw error; }
          return { content: [{ type: 'text', text: JSON.stringify({ body: saved.data.toString('utf8') }) }] };
        }]]);
      }, observeLocalTool: async value => { observations.push(structuredClone(value)); },
      capturePersonaAuthority: ({ binding, personaSession: actual }) => personaAuthority.capture({
        scope: binding, personaId: persona.id, role: 'customer', ...actual }),
      personaLocalToolModes: { [SUMMARY_TOOL]: 'remote_admission' },
      limits: { maxSteps: 2, maxParallelTools: 1 } });
    const started = Date.now();
    const result = await runner.run({ ...input, message: 'Summarize the owned attachment.',
      localToolAuthority: Object.freeze({ source: 'native' }) });
    assert.equal(result.text, 'Controlled native summary.'); assert.equal(providerCalls, 2);
    assert.ok(saved && execution && typeof execution.checkAtEffect === 'function',
      JSON.stringify({ toolFailure, observations }));
    assert.ok(Date.now() - started < 5000);
    assert.deepEqual(saved.data, input.bytes);
    assert.deepEqual((await attachment.readRetained(Object.fromEntries(Object.entries(input)
      .filter(([key]) => !['filename', 'mime', 'bytes'].includes(key))), saved.receipt,
    execution)).data, input.bytes);
    assert.equal((await agentsMigration.query("SELECT count(*)::int n FROM pg_locks WHERE locktype='advisory' AND NOT granted")).rows[0].n, 0);

    const launchScope = packet => require('../../server/services/secureshopConversationBinding')
      .createLaunchScope(packet);
    const fileBinding = (trusted, target) => ({ targetId: target.targetId, launchId: trusted.launchId,
      scenarioId: trusted.scenarioId, generation: trusted.generation,
      ownerId: String(trusted.platformOwnerId) });
    async function reserveAndWrite(trusted, name, data) {
      const reserved = await launches.reserveFilesTarget({ ...trusted, expectedGeneration: trusted.generation });
      const binding = fileBinding(trusted, reserved);
      const provisioned = await files.provisionReservedTarget(binding);
      await files.writeFile(provisioned.capability, `/uploads/${name}`, data,
        { expectedGeneration: trusted.generation, createOnly: true, createParents: true });
      return { reserved, binding, provisioned, name, data };
    }
    async function assertStored(entry) {
      assert.deepEqual((await files.readFile(entry.provisioned.capability, `/uploads/${entry.name}`,
        { expectedGeneration: entry.binding.generation })).data, entry.data);
    }
    async function bootstrap(authService, bootstrapService, login) {
      const packet = await bootstrapService(login.context);
      const trusted = launchScope(await launches.resolveCapability(packet.bearer));
      const actor = await personaAuth.authenticateBoundToken({ scope: trusted, token: packet.persona.token });
      return { packet, trusted, actor };
    }

    // The public reservation signature stays unchanged, but shop launches are
    // partitioned by their immutable tenant execution principal. Two distinct
    // customers in the default tenant can each hold one live files target.
    const principalA = await bootstrap(defaultAuth, defaultBootstrap,
      await defaultAuth.login({ username: 'student_customer', password: 'student123' }));
    const suffix = randomUUID().slice(0, 8), secondUsername = `v19_native_peer_${suffix}`;
    const secondLogin = await defaultAuth.register({ username: secondUsername,
      email: `${secondUsername}@example.invalid`, password: 'v19-native-peer-password', role: 'customer' });
    const principalB = await bootstrap(defaultAuth, defaultBootstrap, secondLogin);
    assert.equal(principalA.trusted.platformOwnerId, principalB.trusted.platformOwnerId);
    assert.notEqual(principalA.actor.user.id, principalB.actor.user.id);
    const executionRows = (await identity.query(`SELECT s.id AS authority_session_id,
        e.tenant_id,e.principal_id,e.session_id AS execution_session_id
      FROM identity.secureshop_authority_sessions s
      JOIN secureshop_auth.execution_sessions e ON e.session_id=s.shop_execution_session_id
      WHERE s.id=ANY($1::int[]) ORDER BY s.id`,
    [[principalA.trusted.platformSessionId, principalB.trusted.platformSessionId]])).rows;
    assert.equal(executionRows.length, 2);
    assert.equal(executionRows[0].tenant_id, executionRows[1].tenant_id);
    assert.notEqual(executionRows[0].principal_id, executionRows[1].principal_id);
    const principalABytes = Buffer.from('Default tenant principal A bytes.\n');
    const principalBBytes = Buffer.from('Default tenant principal B bytes.\n');
    const principalAFile = await reserveAndWrite(principalA.trusted, 'principal-a.txt', principalABytes);
    const principalBFile = await reserveAndWrite(principalB.trusted, 'principal-b.txt', principalBBytes);
    assert.equal((await launches.reserveFilesTarget({ ...principalA.trusted,
      expectedGeneration: principalA.trusted.generation })).targetId, principalAFile.reserved.targetId);
    await assertStored(principalAFile); await assertStored(principalBFile);

    const principalANext = await bootstrap(defaultAuth, defaultBootstrap,
      await defaultAuth.login({ username: 'student_customer', password: 'student123' }));
    assert.equal(principalANext.trusted.platformOwnerId, principalA.trusted.platformOwnerId);
    assert.equal(principalANext.actor.user.id, principalA.actor.user.id);
    assert.notEqual(principalANext.trusted.launchId, principalA.trusted.launchId);
    await assert.rejects(launches.reserveFilesTarget({ ...principalANext.trusted,
      expectedGeneration: principalANext.trusted.generation }), { code: 'CLEANUP_REQUIRED' });
    const principalAReset = await cleanup.launchResetCoordinator.reset({ ...principalA.trusted,
      expectedGeneration: principalA.trusted.generation, idempotencyKey: randomUUID() });
    assert.equal(principalAReset.status, 'committed');
    await assert.rejects(files.openExistingReservedTarget(principalAFile.binding), { code: 'TARGET_RETIRED' });
    await assertStored(principalBFile);
    const principalARefreshed = await bootstrap(defaultAuth, defaultBootstrap,
      await defaultAuth.login({ username: 'student_customer', password: 'student123' }));
    assert.equal(principalARefreshed.actor.user.id, principalA.actor.user.id);
    const principalAAfterCleanup = await reserveAndWrite(principalARefreshed.trusted,
      'principal-a-after-cleanup.txt', Buffer.from('Principal A admitted after its own cleanup.\n'));
    await assertStored(principalAAfterCleanup);

    // Exercise the exact supported peer-tenant bootstrap used by rendered V19:
    // membership, seed merchant, login/bootstrap, catalog target, and physical
    // file storage all bind to the peer tenant's distinct platform owner.
    const merchant = (await identityMigration.query(`SELECT principal_id,shop_user_id
      FROM secureshop_auth.principals
      WHERE username='student_merchant' AND role='merchant'`)).rows;
    assert.equal(merchant.length, 1);
    const peerTenantId = randomUUID(), peerSlug = `v19_native_tenant_${suffix}`;
    const peerTenant = (await identityMigration.query(`INSERT INTO secureshop_auth.tenants(tenant_id,slug)
      VALUES($1,$2) RETURNING owner_id,seed_merchant_id`, [peerTenantId, peerSlug])).rows[0];
    assert.equal(peerTenant.seed_merchant_id, null);
    await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
    [peerTenantId, merchant[0].principal_id, merchant[0].shop_user_id]);
    const peerSeed = (await identityMigration.query(`UPDATE secureshop_auth.tenants
      SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL
      RETURNING seed_merchant_id`, [peerTenantId, merchant[0].shop_user_id])).rows[0];
    assert.equal(peerSeed.seed_merchant_id, merchant[0].shop_user_id);
    const peerAuth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({
        repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity, executionTenantSlug: peerSlug }),
      });
    const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches, personaAuth, authService: peerAuth });
    const peer = await bootstrap(peerAuth, peerBootstrap,
      await peerAuth.login({ username: 'student_merchant', password: 'student123' }));
    assert.notEqual(peer.trusted.platformOwnerId, principalA.trusted.platformOwnerId);
    assert.equal(peer.actor.user.role, 'merchant');
    const peerExecution = (await identity.query(`SELECT e.tenant_id,e.principal_id
      FROM identity.secureshop_authority_sessions s
      JOIN secureshop_auth.execution_sessions e ON e.session_id=s.shop_execution_session_id
      WHERE s.id=$1`, [peer.trusted.platformSessionId])).rows;
    assert.deepEqual(peerExecution, [{ tenant_id: peerTenantId, principal_id: merchant[0].principal_id }]);
    const catalog = require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({
      sourcePool: commerce, repository: products, scenes, personaAuthority,
      resolveTarget: trusted => launches.reserveProductsTarget({ ...trusted,
        expectedGeneration: trusted.generation }), checkCurrent });
    const peerProductTarget = await catalog.prepareTarget({ scope: peer.trusted, persona: peer.actor.user });
    assert.ok(peerProductTarget.targetId);
    assert.equal((await review.query(`SELECT count(*)::int n
      FROM secureshop_review.product_target_products WHERE target_id=$1`,
    [peerProductTarget.targetId])).rows[0].n > 0, true);
    const peerFile = await reserveAndWrite(peer.trusted, 'peer-tenant.txt',
      Buffer.from('Peer tenant catalog and file setup completed.\n'));
    await assertStored(peerFile);

    async function additionalLaunch(owner = user) {
      const session = await identities.createSession({ userId: owner.id, token: randomUUID(), expiresAt,
        expectedPasswordHash: passwordHash });
      return require('../../server/services/secureshopConversationBinding').createLaunchScope(
        (await launches.issueOrRenew({ platformOwnerId: owner.id,
          platformSessionId: session.id, expiresAt })).binding);
    }
    const sameOwnerNext = await additionalLaunch();
    await assert.rejects(launches.reserveFilesTarget({ ...sameOwnerNext,
      expectedGeneration: sameOwnerNext.generation }), { code: 'CLEANUP_REQUIRED' });
    const foreignUser = await identities.createUser({ username: `v19-attachment-foreign-${randomUUID().slice(0, 8)}`,
      email: `${randomUUID()}@example.invalid`, passwordHash });
    const foreignScope = await additionalLaunch(foreignUser);
    const foreignTarget = await launches.reserveFilesTarget({ ...foreignScope,
      expectedGeneration: foreignScope.generation });
    const foreignBinding = { targetId: foreignTarget.targetId, launchId: foreignScope.launchId,
      scenarioId: foreignScope.scenarioId, generation: foreignScope.generation,
      ownerId: String(foreignScope.platformOwnerId) };
    const foreignProvisioned = await files.provisionReservedTarget(foreignBinding);
    const foreignBytes = Buffer.from('Independent owner remains unchanged.\n');
    await files.writeFile(foreignProvisioned.capability, '/uploads/foreign.txt', foreignBytes,
      { expectedGeneration: foreignScope.generation, createOnly: true, createParents: true });
    const reset = await cleanup.launchResetCoordinator.reset({ ...scope,
      expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
    assert.equal(reset.status, 'committed');
    assert.equal(reset.fromGeneration, scope.generation);
    assert.equal(reset.toGeneration, scope.generation + 1);
    await assert.rejects(attachment.readRetained(Object.fromEntries(Object.entries(input)
      .filter(([key]) => !['filename', 'mime', 'bytes'].includes(key))), saved.receipt,
    execution), { code: 'STALE_LAUNCH' });
    const { virtualPath, ...retainedBinding } = saved.receipt.file;
    await assert.rejects(files.openExistingReservedTarget(retainedBinding), { code: 'TARGET_RETIRED' });
    assert.deepEqual((await files.readFile(foreignProvisioned.capability, '/uploads/foreign.txt',
      { expectedGeneration: foreignScope.generation })).data, foreignBytes);
    const admittedAfterCleanup = await launches.reserveFilesTarget({ ...sameOwnerNext,
      expectedGeneration: sameOwnerNext.generation });
    const admittedBinding = { targetId: admittedAfterCleanup.targetId, launchId: sameOwnerNext.launchId,
      scenarioId: sameOwnerNext.scenarioId, generation: sameOwnerNext.generation,
      ownerId: String(sameOwnerNext.platformOwnerId) };
    const admittedFiles = await files.provisionReservedTarget(admittedBinding);
    const admittedBytes = Buffer.from('Same owner admitted only after canonical cleanup.\n');
    await files.writeFile(admittedFiles.capability, '/uploads/after-cleanup.txt', admittedBytes,
      { expectedGeneration: sameOwnerNext.generation, createOnly: true, createParents: true });
    assert.deepEqual((await files.readFile(admittedFiles.capability, '/uploads/after-cleanup.txt',
      { expectedGeneration: sameOwnerNext.generation })).data, admittedBytes);
    assert.equal((await identityMigration.query(`SELECT count(*)::int n
      FROM identity.secureshop_target_cleanup_history
      WHERE target_id=$1 AND target_kind='files' AND operation_id=$2`,
    [retainedBinding.targetId, reset.resetId])).rows[0].n, 1);
    t.diagnostic('Real PostgreSQL persona/scene authority and canonical reset preserve the owner-wide cleanup-debt fence: same-owner denial before cleanup, physical retirement, independent-owner bytes unchanged, then a new reservation. No model, browser, Judge, or credit.');
  });
