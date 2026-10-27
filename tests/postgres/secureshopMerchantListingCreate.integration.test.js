'use strict';

// Owned native service proof; actual model/rendered create and fresh full-chain
// qualification remain separate from these populated 0043 -> 0044 -> 0047 transitions.
// The empty-table 0047 DDL check rolls back; it is not a separate fresh installation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const PREFIX = 'PG_SECURESHOP_MERCHANT_LISTING_CREATE_';
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'];
const FAMILIES = { IDENTITY: 'identity', AGENTS: 'secureshop_agents', REVIEW: 'secureshop_review', COMMERCE: 'secureshop' };
const enabled = process.env.SECURESHOP_MERCHANT_LISTING_CREATE_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && STORES.every(store => ['RUNTIME', 'MIGRATION'].every(role => process.env[PREFIX + store + '_' + role + '_URL']));
function urls() {
  const result = {}; let nonce; let port;
  for (const store of STORES) for (const role of ['RUNTIME', 'MIGRATION']) {
    const key = store + '_' + role, value = new URL(process.env[PREFIX + key + '_URL']);
    assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
    assert.equal(value.username, 'dvaia_' + FAMILIES[store] + '_' + role.toLowerCase());
    assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
    const match = new RegExp('^/dvaia_test_agent_host_([a-f0-9]{12})_' + FAMILIES[store] + '$').exec(value.pathname);
    assert.ok(match); nonce ??= match[1]; port ??= value.port;
    assert.equal(match[1], nonce); assert.equal(value.port, port); result[key] = value.href;
  }
  return result;
}
function throughReview(directory, version) {
  const filename = require.resolve('../../db/postgres/migrate'), local = createRequire(filename);
  const original = require('node:fs/promises');
  const virtual = { ...original, async readdir(target, ...args) {
    const names = await original.readdir(target, ...args);
    return path.resolve(target) === directory ? names.filter(name => !/^\d{4}_.*\.sql$/.test(name)
      || Number(name.slice(0, 4)) <= version) : names;
  } };
  const loaded = new Module(filename, module); loaded.filename = filename;
  loaded.require = name => ['node:fs/promises', 'fs/promises'].includes(name) ? virtual : local(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename); return loaded.exports.migrate;
}
async function retainedRows(pool) {
  const queries = {
    targets: 'SELECT * FROM secureshop_review.product_targets ORDER BY target_id',
    products: 'SELECT * FROM secureshop_review.product_target_products ORDER BY target_id,product_id',
    overlays: 'SELECT * FROM secureshop_review.product_target_listing_overlays ORDER BY target_id,product_id',
    owners: 'SELECT * FROM secureshop_review.product_target_merchant_listings ORDER BY target_id,product_id',
    history: 'SELECT * FROM secureshop_review.product_target_price_history ORDER BY observation_id',
    revisions: 'SELECT * FROM secureshop_review.owned_listing_catalog_revisions ORDER BY target_id',
    edits: 'SELECT * FROM secureshop_review.owned_merchant_listing_edit_receipts ORDER BY operation_id',
    audits: 'SELECT * FROM secureshop_review.bound_audit_events ORDER BY event_id',
  };
  const result = {}; for (const [key, query] of Object.entries(queries)) result[key] = (await pool.query(query)).rows;
  return result;
}

test('merchant listing create preserves populated history, previews without effects, commits one owned listing, and fences replay conflicts or retired authority',
  { skip: !enabled, timeout: 120000 }, async () => {
    const workspace = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(workspace, process.cwd(), 'current checkout only; no source copy');
    const connections = urls();
    const pools = Object.fromEntries(Object.entries(connections).map(([key, connectionString]) =>
      [key, new Pool({ connectionString, max: 6 })]));
    const leasePool = new Pool({ connectionString: connections.IDENTITY_RUNTIME, max: 3 });
    let reset;
    try {
      const reviewDirectory = path.join(workspace, 'db/postgres/workshop-migrations/secureshop_review');
      for (const store of ['IDENTITY', 'AGENTS', 'COMMERCE']) await migrate(pools[store + '_MIGRATION'],
        path.join(workspace, 'db/postgres', store === 'IDENTITY' ? 'identity-migrations' : 'workshop-migrations/' + FAMILIES[store]));
      await throughReview(reviewDirectory, 43)(pools.REVIEW_MIGRATION, reviewDirectory);
      await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seed = await pools.COMMERCE_MIGRATION.connect();
      try { await seed.query('BEGIN'); await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed); await seed.query('COMMIT'); }
      catch (error) { await seed.query('ROLLBACK'); throw error; } finally { seed.release(); }
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME, review = pools.REVIEW_RUNTIME;
      const audit = require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review });
      reset = require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({ identityPool: identity,
        agentsPool: agents, reviewPool: review, leasePool, audit });
      const authority = require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({
        pool: agents, checkCurrent: scope => reset.launches.assertCurrent(scope) });
      const personas = require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({
        commercePool: pools.COMMERCE_RUNTIME, agentsPool: agents, personaAuthority: authority, auditStore: audit.agents });
      await personas.ensureTemplates();
      const personaAuth = require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({ repository: personas,
        personaAuthority: authority, launches: reset.launches, jwtSecret: 'native-owned-listing-create-secret-at-least-32-bytes' });
      const auth = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
        launches: reset.launches, personaAuth, authService: auth });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({ repository:
        require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
        reviewPool: review, launches: reset.launches });
      const catalog = require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({ sourcePool: pools.COMMERCE_RUNTIME,
        repository: reset.products, personaAuthority: authority, scenes, modeAuthority: reset.modeAuthority, checkCurrent: scope => reset.launches.assertCurrent(scope),
        resolveTarget: scope => reset.launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation }) });
      const suffix = randomUUID().slice(0, 8);
      async function merchant(label, isolated = false) {
        const registered = await auth.register({ username: label + suffix, email: label + suffix + '@example.invalid',
          password: 'disposable-listing-create-password', role: 'merchant' });
        let selectedAuth = auth, rawPrincipal = registered.context;
        if (isolated) {
          const tenantId = randomUUID(), slug = label + suffix;
          await pools.IDENTITY_MIGRATION.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)', [tenantId, slug]);
          await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
            (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
          [tenantId, rawPrincipal.principalId, rawPrincipal.shopUserId]);
          await pools.IDENTITY_MIGRATION.query('UPDATE secureshop_auth.tenants SET seed_merchant_id=$2 WHERE tenant_id=$1',
            [tenantId, rawPrincipal.shopUserId]);
          selectedAuth = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({ repository:
            require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({
              pool: identity, executionTenantSlug: slug }) });
          rawPrincipal = (await selectedAuth.login({ username: label + suffix, password: 'disposable-listing-create-password' })).context;
        }
        const selectedBootstrap = isolated ? require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
          launches: reset.launches, personaAuth, authService: selectedAuth }) : bootstrap;
        const boot = await selectedBootstrap(rawPrincipal), scope = await reset.launches.resolveCapability(boot.bearer);
        const actor = await personaAuth.authenticateBoundToken({ scope, token: boot.persona.token });
        const context = { scope, persona: { id: actor.user.id, role: 'merchant' },
          personaSession: { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion } };
        return { context, execution: await selectedAuth.establishTenantContext(rawPrincipal), target: await catalog.prepareTarget(context) };
      }
      const owner = await merchant('create_owner_'), sibling = await merchant('create_peer_', true);
      assert.notEqual(owner.target.targetId, sibling.target.targetId);
      const oldProduct = await catalog.createMerchantProduct({ ...owner.context, listing: { name: 'Retained pre0044 listing',
        description: 'Actual owned historical listing', price: 8.25, category: 'fixture', templateSource: null, images: [] } });
      const oldPreview = await catalog.previewMerchantListingEdit({ ...owner.context, productId: oldProduct.productId,
        patch: { description: 'Retained confirmed0043 edit' } });
      const oldOperation = randomUUID(), oldReceipt = await catalog.confirmMerchantListingEdit({ ...owner.context,
        operationId: oldOperation, preview: oldPreview });
      const beforeMigration = await retainedRows(review), ledgerBefore = (await pools.REVIEW_MIGRATION.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.equal(beforeMigration.edits.length, 1); assert.equal(beforeMigration.edits[0].operation_id, oldOperation);
      const migration = '0044_owned_merchant_listing_creates.sql';
      assert.deepEqual(await throughReview(reviewDirectory, 44)(pools.REVIEW_MIGRATION, reviewDirectory), [migration]);
      assert.deepEqual(await retainedRows(review), beforeMigration);
      const ledgerAfter = (await pools.REVIEW_MIGRATION.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(ledgerAfter.slice(0, -1), ledgerBefore); assert.equal(ledgerAfter.at(-1).name, migration);
      assert.equal(ledgerAfter.at(-1).checksum, createHash('sha256').update(fs.readFileSync(path.join(reviewDirectory, migration))).digest('hex'));
      assert.deepEqual(await throughReview(reviewDirectory, 44)(pools.REVIEW_MIGRATION, reviewDirectory), []);
      assert.deepEqual(await retainedRows(review), beforeMigration);
      assert.deepEqual(await catalog.readMerchantListingEdit({ ...owner.context, operationId: oldOperation }), { ...oldReceipt, replayed: true });
      const creationRows = () => review.query('SELECT * FROM secureshop_review.owned_merchant_listing_create_receipts ORDER BY operation_id').then(result => result.rows);
      assert.deepEqual(await creationRows(), []);
      const privileges = (await review.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS read,
        has_table_privilege(current_user,$1,'INSERT') AS insert,has_table_privilege(current_user,$1,'UPDATE') AS update,
        has_table_privilege(current_user,$1,'DELETE') AS remove`, ['secureshop_review.owned_merchant_listing_create_receipts'])).rows[0];
      assert.deepEqual(privileges, { read: true, insert: true, update: false, remove: false });
      // Exact 0047 DDL against an empty receipt table, transactionally rolled back.
      // Populated application and migration-ledger qualification follows below.
      const rawMigration = '0047_owned_listing_create_html_source.sql';
      const emptyDdl = await pools.REVIEW_MIGRATION.connect();
      try {
        await emptyDdl.query('BEGIN');
        await emptyDdl.query(fs.readFileSync(path.join(reviewDirectory, rawMigration), 'utf8'));
        const columns = (await emptyDdl.query(`SELECT column_name,column_default,is_nullable FROM information_schema.columns
          WHERE table_schema='secureshop_review' AND table_name='owned_merchant_listing_create_receipts'
          AND column_name IN ('receipt_version','source_document') ORDER BY column_name`)).rows;
        assert.equal(columns.length, 2); assert.equal(columns[0].column_name, 'receipt_version');
        assert.equal(columns[0].column_default, '1'); assert.equal(columns[0].is_nullable, 'NO');
        assert.equal((await emptyDdl.query('SELECT count(*)::integer AS n FROM secureshop_review.owned_merchant_listing_create_receipts')).rows[0].n, 0);
      } finally { await emptyDdl.query('ROLLBACK'); emptyDdl.release(); }
      assert.equal((await pools.REVIEW_MIGRATION.query(`SELECT count(*)::integer AS n FROM information_schema.columns
        WHERE table_schema='secureshop_review' AND table_name='owned_merchant_listing_create_receipts'
        AND column_name='source_document'`)).rows[0].n, 0);
      const preview = await catalog.previewMerchantListingCreate({ ...owner.context, listing: { name: 'Explicit practice listing', price: 12.5 } });
      assert.deepEqual(preview.listing, { name: 'Explicit practice listing', description: null, category: null, price: 12.5 });
      assert.equal(preview.version, 1); assert.equal(preview.currency, 'USD'); assert.equal(preview.initialStock, 0); assert.equal(preview.status, 'active');
      assert.match(preview.scopeKey, /^[a-f0-9]{64}$/); assert.match(preview.requestSha256, /^[a-f0-9]{64}$/);
      assert.deepEqual(await retainedRows(review), beforeMigration); assert.deepEqual(await creationRows(), []);
      const operationId = randomUUID();
      const receipt = await catalog.confirmMerchantListingCreate({ ...owner.context, operationId, preview });
      assert.deepEqual(Object.keys(receipt).sort(), ['version', 'operationId', 'status', 'productId', 'scopeKey', 'requestSha256', 'sourceSha256', 'receiptSha256', 'replayed'].sort());
      assert.equal(receipt.version, 1); assert.equal(receipt.operationId, operationId); assert.equal(receipt.status, 'completed');
      assert.equal(receipt.scopeKey, preview.scopeKey); assert.equal(receipt.requestSha256, preview.requestSha256); assert.equal(receipt.replayed, false);
      const committed = await retainedRows(review), creations = await creationRows();
      assert.equal(committed.products.length, beforeMigration.products.length + 1);
      assert.equal(committed.owners.length, beforeMigration.owners.length + 1);
      assert.equal(committed.audits.length, beforeMigration.audits.length + 1); assert.equal(creations.length, 1);
      const product = committed.products.find(row => row.target_id === owner.target.targetId && Number(row.product_id) === receipt.productId);
      assert.ok(product); assert.equal(Number(product.retailer_id), owner.context.persona.id);
      assert.equal(product.name, preview.listing.name); assert.equal(product.description, null); assert.equal(product.category, null);
      assert.equal(Number(product.price), 12.5); assert.equal(product.stock_quantity, 0); assert.equal(product.status, 'active');
      assert.equal(product.template_source, null); assert.deepEqual(product.images, []);
      assert.equal(product.source_product_sha256.toString('hex'), receipt.sourceSha256);
      assert.equal(creations[0].receipt_sha256.toString('hex'), receipt.receiptSha256);
      const auditRow = committed.audits.find(row => !beforeMigration.audits.some(old => old.event_id === row.event_id));
      assert.equal(auditRow.shop_user_id, owner.context.persona.id); assert.equal(auditRow.target, String(receipt.productId));
      assert.equal(auditRow.launch_id, owner.context.scope.launchId);
      assert.equal(auditRow.action, 'listing_create_confirm'); assert.equal(auditRow.outcome, 'completed');
      assert.deepEqual(JSON.parse(auditRow.params_json), { operationId, requestSha256: preview.requestSha256,
        sourceSha256: receipt.sourceSha256, storage: { targetId: owner.target.targetId,
          sceneId: owner.target.scene.sceneId, birthLaunchId: owner.target.launchId,
          birthGeneration: owner.target.generation } });
      assert.deepEqual(await catalog.confirmMerchantListingCreate({ ...owner.context, operationId, preview }), { ...receipt, replayed: true });
      assert.deepEqual(await catalog.readMerchantListingCreate({ ...owner.context, operationId }), { ...receipt, replayed: true });
      assert.deepEqual(await retainedRows(review), committed); assert.deepEqual(await creationRows(), creations);
      const different = await catalog.previewMerchantListingCreate({ ...owner.context, listing: { name: 'Different immutable intent', price: 12.5 } });
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...owner.context, operationId, preview: different }),
        error => error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause?.code === 'LISTING_CREATE_RECEIPT_INVALID');
      assert.deepEqual(await catalog.readMerchantListingCreate({ ...owner.context, operationId }), { ...receipt, replayed: true });
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...sibling.context, operationId, preview }), { code: 'SHOP_AUTH_INVALID' });
      const foreignRead = await catalog.readMerchantListingCreate({ ...sibling.context, operationId });
      assert.equal(foreignRead.status, 'not_found'); assert.equal(foreignRead.operationId, operationId);
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...owner.context, personaSession: { ...owner.context.personaSession,
        authorityVersion: String(Number(owner.context.personaSession.authorityVersion) + 1) }, operationId: randomUUID(), preview }));
      assert.deepEqual(await retainedRows(review), committed); assert.deepEqual(await creationRows(), creations);
      await assert.rejects(review.query('UPDATE secureshop_review.owned_merchant_listing_create_receipts SET receipt_sha256=$1', [Buffer.alloc(32)]), { code: '42501' });
      await assert.rejects(review.query('DELETE FROM secureshop_review.owned_merchant_listing_create_receipts'), { code: '42501' });
      await assert.rejects(pools.REVIEW_MIGRATION.query('UPDATE secureshop_review.owned_merchant_listing_create_receipts SET receipt_sha256=$1', [Buffer.alloc(32)]), { code: '55000' });
      // Upgrade a genuine populated v1 receipt without changing a single prior hash/data field.
      assert.deepEqual(await throughReview(reviewDirectory, 46)(pools.REVIEW_MIGRATION, reviewDirectory),
        ['0045_customer_address_receipts.sql', '0046_customer_profile_receipts.sql']);
      assert.deepEqual(await retainedRows(review), committed); assert.deepEqual(await creationRows(), creations);
      assert.deepEqual(await throughReview(reviewDirectory, 47)(pools.REVIEW_MIGRATION, reviewDirectory), [rawMigration]);
      const upgraded = await creationRows();
      assert.deepEqual(upgraded.map(({ receipt_version, source_document, ...row }) => {
        assert.equal(receipt_version, 1); assert.equal(source_document, null); return row;
      }), creations);
      assert.deepEqual(await retainedRows(review), committed);
      assert.deepEqual(await catalog.readMerchantListingCreate({ ...owner.context, operationId }), { ...receipt, replayed: true });
      assert.deepEqual(await throughReview(reviewDirectory, 47)(pools.REVIEW_MIGRATION, reviewDirectory), []);
      assert.deepEqual(await creationRows(), upgraded); assert.deepEqual(await retainedRows(review), committed);
      const rawLedger = (await pools.REVIEW_MIGRATION.query('SELECT * FROM dvaia_migrations.ledger WHERE name=$1', [rawMigration])).rows;
      assert.equal(rawLedger.length, 1);
      assert.equal(rawLedger[0].checksum, createHash('sha256').update(fs.readFileSync(path.join(reviewDirectory, rawMigration))).digest('hex'));
      const modes = require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
      async function mode(value) {
        const current = await modes.getPrincipalMode(owner.execution);
        if (current.mode !== value) await modes.setPrincipalMode(owner.execution, { mode: value, expectedRevision: current.revision });
      }
      await mode('vuln');
      const rawHtml = '<img src=x onerror="window.__ownedRaw=1">\r\n café & exact';
      const rawInput = { ...owner.context, listing: { name: 'Authored raw listing', price: 6.25, description: rawHtml, presentation: 'html' },
        preparation: { sessionId: randomUUID(), requestId: randomUUID(), step: 1, callId: 'controlled-native-prepare',
          message: 'Create the owned listing using exactly this HTML: ' + rawHtml } };
      const rawPreview = await catalog.previewMerchantListingCreate(rawInput), rawOperation = randomUUID();
      assert.equal(rawPreview.version, 2); assert.equal(rawPreview.source.execution.mode, 'vuln');
      assert.deepEqual(await creationRows(), upgraded, 'preview has no durable effect');
      const rawReceipt = await catalog.confirmMerchantListingCreate({ ...owner.context, operationId: rawOperation, preview: rawPreview });
      assert.equal(rawReceipt.version, 2); assert.equal(rawReceipt.source.authoredHtml, rawHtml); assert.equal(rawReceipt.source.storedHtml, rawHtml);
      const rawRows = await creationRows(), rawSql = rawRows.find(row => row.operation_id === rawOperation);
      assert.equal(rawSql.receipt_version, 2); assert.deepEqual(rawSql.source_document, rawReceipt.source);
      assert.equal(rawSql.receipt_sha256.toString('hex'), rawReceipt.receiptSha256);
      const source = await catalog.readMerchantListingCreateSource({ ...owner.context, operationId: rawOperation });
      assert.equal(source.product.descriptionHtml, rawHtml); assert.equal(source.product.sourceSha256, rawReceipt.sourceSha256);
      assert.deepEqual(source.receipt, { ...rawReceipt, replayed: true });
      const afterRaw = await retainedRows(review);
      assert.deepEqual(await catalog.confirmMerchantListingCreate({ ...owner.context, operationId: rawOperation, preview: rawPreview }),
        { ...rawReceipt, replayed: true });
      assert.deepEqual(await retainedRows(review), afterRaw); assert.deepEqual(await creationRows(), rawRows);
      assert.equal((await catalog.readMerchantListingCreate({ ...sibling.context, operationId: rawOperation })).status, 'not_found');
      await assert.rejects(catalog.readMerchantListingCreateSource({ ...sibling.context, operationId: rawOperation }), { code: 'LISTING_CREATE_SOURCE_UNAVAILABLE' });
      await mode('fixed');
      assert.deepEqual(await catalog.confirmMerchantListingCreate({ ...owner.context, operationId: rawOperation, preview: rawPreview }),
        { ...rawReceipt, replayed: true }, 'mode change cannot rerender immutable completed source');
      const fixedPreview = await catalog.previewMerchantListingCreate(rawInput), fixedOperation = randomUUID();
      const fixedReceipt = await catalog.confirmMerchantListingCreate({ ...owner.context, operationId: fixedOperation, preview: fixedPreview });
      const escaped = require('../../server/services/secureshopListingCreateContract').escapeListingHtml(rawHtml);
      assert.equal(fixedReceipt.source.storedHtml, escaped); assert.equal(fixedReceipt.source.authoredHtml, rawHtml);
      assert.equal((await catalog.readMerchantListingCreateSource({ ...owner.context, operationId: fixedOperation })).product.descriptionHtml, escaped);
      await mode('vuln'); const stalePreview = await catalog.previewMerchantListingCreate(rawInput);
      await mode('fixed'); await mode('vuln');
      const beforeStale = await retainedRows(review), receiptsBeforeStale = await creationRows();
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...owner.context, operationId: randomUUID(), preview: stalePreview }),
        error => error.code === 'LISTING_CREATE_MODE_INVALID' || error.cause?.code === 'LISTING_CREATE_MODE_INVALID');
      assert.deepEqual(await retainedRows(review), beforeStale); assert.deepEqual(await creationRows(), receiptsBeforeStale);
      await assert.rejects(pools.REVIEW_MIGRATION.query(`UPDATE secureshop_review.owned_merchant_listing_create_receipts
        SET source_document=source_document WHERE operation_id=$1`, [rawOperation]), { code: '55000' });
      // Manual business operations: controlled PostgreSQL durability/trigger proof only.
      // No assistant preparation, model invocation, assessment, or credit is synthesized.
      const beforeCurrentUpgrade = await retainedRows(review), receiptsBeforeCurrentUpgrade = await creationRows();
      assert.deepEqual(await migrate(pools.REVIEW_MIGRATION, reviewDirectory), [
        '0048_owned_idor_lesson_receipts.sql', '0049_bound_support_ticket_receipts.sql',
        '0050_product_embedding_revision_preimages.sql', '0051_bound_system_restart_full_receipts.sql',
        '0052_bound_upload_journal.sql', '0053_bound_upload_reconciliation_aliases.sql',
        '0054_owned_listing_image_optimize.sql',
        '0055_private_manual_original_preimages.sql',
      ]);
      assert.deepEqual(await retainedRows(review), beforeCurrentUpgrade);
      assert.deepEqual(await creationRows(), receiptsBeforeCurrentUpgrade);
      assert.deepEqual(await migrate(pools.REVIEW_MIGRATION, reviewDirectory), []);
      const manualItem = { name: 'Manual owned listing', description: 'Full manual fields', price: 14.25,
        category: 'manual fixture', images: ['/owned-first.png', '/owned-second.png'], templateSource: '{{ name }}' };
      const manualReady = await catalog.manualListingReadiness(owner.context);
      const beforeManual = await retainedRows(review), receiptsBeforeManual = await creationRows();
      const manualPreview = await catalog.previewManualMerchantListingCreate({ ...owner.context, listing: manualItem });
      assert.equal(manualPreview.scopeKey, manualReady.createScopeKey);
      assert.deepEqual(await retainedRows(review), beforeManual); assert.deepEqual(await creationRows(), receiptsBeforeManual);
      const manualOperation = randomUUID(), manualArgs = { ...owner.context, operationId: manualOperation, preview: manualPreview };
      // Concurrent identical submissions serialize on the owned target: exactly one effect.
      const concurrent = await Promise.all([catalog.confirmManualMerchantListingCreate(manualArgs),
        catalog.confirmManualMerchantListingCreate(manualArgs)]);
      assert.deepEqual(concurrent.map(row => row.replayed).sort(), [false, true]);
      const manualReceipt = concurrent.find(row => !row.replayed);
      assert.deepEqual(concurrent.find(row => row.replayed), { ...manualReceipt, replayed: true });
      // Discarding the confirm response models a lost client acknowledgement; authoritative GET is sufficient.
      assert.deepEqual(await catalog.readManualMerchantListingCreate({ ...owner.context, operationId: manualOperation }),
        { ...manualReceipt, replayed: true });
      const manualCommitted = await retainedRows(review), manualRows = await creationRows();
      assert.equal(manualCommitted.products.length, beforeManual.products.length + 1);
      assert.equal(manualCommitted.owners.length, beforeManual.owners.length + 1);
      assert.equal(manualCommitted.audits.length, beforeManual.audits.length + 1);
      assert.equal(manualRows.length, receiptsBeforeManual.length + 1);
      const manualRow = manualRows.find(row => row.operation_id === manualOperation);
      assert.equal(manualRow.receipt_version, 1); assert.equal(manualRow.source_document, null);
      const manualProduct = manualCommitted.products.find(row => row.target_id === owner.target.targetId && row.product_id === manualReceipt.productId);
      assert.deepEqual(manualProduct.images, manualItem.images); assert.equal(manualProduct.image_url, manualItem.images[0]);
      assert.equal(manualProduct.template_source, manualItem.templateSource); assert.equal(manualProduct.description_html, null);
      assert.equal((await catalog.readMerchantListingCreate({ ...owner.context, operationId: manualOperation })).status, 'not_found');
      assert.equal((await catalog.readManualMerchantListingCreate({ ...owner.context, operationId })).status, 'not_found');
      await assert.rejects(catalog.readMerchantListingCreateSource({ ...owner.context, operationId: manualOperation }), { code: 'LISTING_CREATE_SOURCE_UNAVAILABLE' });
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...owner.context, operationId: manualOperation, preview }));
      await assert.rejects(catalog.confirmManualMerchantListingCreate({ ...owner.context, operationId, preview: manualPreview }));
      const changedManual = await catalog.previewManualMerchantListingCreate({ ...owner.context, listing: { ...manualItem, images: [] } });
      await assert.rejects(catalog.confirmManualMerchantListingCreate({ ...manualArgs, preview: changedManual }));
      await assert.rejects(catalog.confirmManualMerchantListingCreate({ ...manualArgs, ...sibling.context }), { code: 'SHOP_AUTH_INVALID' });
      assert.equal((await catalog.readManualMerchantListingCreate({ ...sibling.context, operationId: manualOperation })).status, 'not_found');
      await assert.rejects(catalog.confirmManualMerchantListingCreate({ ...manualArgs,
        personaSession: { ...owner.context.personaSession, authorityVersion: '999999' } }));
      assert.deepEqual(await retainedRows(review), manualCommitted); assert.deepEqual(await creationRows(), manualRows);
      // Controlled provenance row exercises the real existing invalidation trigger, not model evidence.
      const generatedHtml = 'Controlled generated presentation';
      // Seed only the mutable presentation overlay, as rewrite publication does.
      // The product birth snapshot must remain immutable, even for migration roles.
      await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_listing_overlays
        (target_id,product_id,shop_user_id,name,description,description_html,price,category,
         image_url,images,stock_quantity,status,template_source)
        SELECT target_id,product_id,retailer_id,name,description,$3,price,category,
          image_url,images,stock_quantity,status,template_source
        FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=$2`,
      [owner.target.targetId, manualReceipt.productId, generatedHtml]);
      await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.owned_listing_generated_products
        (target_id,product_id,rewrite_operation_id,source_name,source_description,source_sha256,html_sha256)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [owner.target.targetId, manualReceipt.productId, randomUUID(),
        manualItem.name, manualItem.description, createHash('sha256').update('controlled fixture source').digest('hex'),
        createHash('sha256').update(generatedHtml).digest('hex')]);
      const editedItem = { ...manualItem, name: 'Manual updated listing', images: ['/replacement.png', '/retained-second.png'], templateSource: '{{ description }}' };
      const manualEditPreview = await catalog.previewManualMerchantListingEdit({ ...owner.context,
        productId: manualReceipt.productId, listing: editedItem });
      assert.equal(manualEditPreview.scopeKey, manualReady.editScopeKey);
      assert.equal(manualEditPreview.invalidatesGeneratedHtml, true); assert.equal(manualEditPreview.after.descriptionHtml, null);
      const manualEditOperation = randomUUID(), beforeManualEdit = await retainedRows(review);
      const manualEditArgs = { ...owner.context, operationId: manualEditOperation, preview: manualEditPreview };
      const editReceipts = await Promise.all([catalog.confirmManualMerchantListingEdit(manualEditArgs), catalog.confirmManualMerchantListingEdit(manualEditArgs)]);
      assert.deepEqual(editReceipts.map(row => row.replayed).sort(), [false, true]);
      const manualEditReceipt = editReceipts.find(row => !row.replayed), afterManualEdit = await retainedRows(review);
      assert.equal(afterManualEdit.edits.length, beforeManualEdit.edits.length + 1);
      assert.equal(afterManualEdit.audits.length, beforeManualEdit.audits.length + 1);
      const manualOverlay = afterManualEdit.overlays.find(row => row.target_id === owner.target.targetId && row.product_id === manualReceipt.productId);
      assert.deepEqual(manualOverlay.images, editedItem.images); assert.equal(manualOverlay.image_url, editedItem.images[0]);
      assert.equal(manualOverlay.template_source, editedItem.templateSource); assert.equal(manualOverlay.description_html, null);
      assert.equal((await review.query(`SELECT count(*)::integer AS n FROM secureshop_review.owned_listing_generated_products
        WHERE target_id=$1 AND product_id=$2`, [owner.target.targetId, manualReceipt.productId])).rows[0].n, 0);
      assert.deepEqual(await catalog.readManualMerchantListingEdit({ ...owner.context, operationId: manualEditOperation }), { ...manualEditReceipt, replayed: true });
      assert.equal((await catalog.readMerchantListingEdit({ ...owner.context, operationId: manualEditOperation })).status, 'not_found');
      assert.equal((await catalog.readManualMerchantListingEdit({ ...owner.context, operationId: oldOperation })).status, 'not_found');
      await assert.rejects(catalog.confirmManualMerchantListingEdit({ ...manualEditArgs, operationId: randomUUID() }));
      assert.deepEqual(await retainedRows(review), afterManualEdit, 'stale CAS cannot append overlay, audit or receipt');
      const peerPreview = await catalog.previewMerchantListingCreate({ ...sibling.context, listing: { name: 'Independent sibling listing', price: 4 } });
      const peerOperation = randomUUID(), peerReceipt = await catalog.confirmMerchantListingCreate({ ...sibling.context, operationId: peerOperation, preview: peerPreview });
      const finalRows = await retainedRows(review), finalReceipts = await creationRows();
      await reset.launches.beginReset({ ...owner.context.scope, expectedGeneration: owner.context.scope.generation,
        idempotencyKey: 'q31-create-reset-admission' });
      await assert.rejects(catalog.confirmMerchantListingCreate({ ...owner.context, operationId: randomUUID(), preview }));
      await assert.rejects(catalog.readMerchantListingCreate({ ...owner.context, operationId }));
      await assert.rejects(catalog.manualListingReadiness(owner.context));
      await assert.rejects(catalog.confirmManualMerchantListingCreate(manualArgs));
      await assert.rejects(catalog.readManualMerchantListingCreate({ ...owner.context, operationId: manualOperation }));
      await assert.rejects(catalog.readManualMerchantListingEdit({ ...owner.context, operationId: manualEditOperation }));
      assert.deepEqual(await retainedRows(review), finalRows, 'reset admission/denied create preserves birth data and historical audits');
      assert.deepEqual(await creationRows(), finalReceipts, 'reset admission preserves both immutable receipt versions');
      await assert.rejects(catalog.readMerchantListingCreateSource({ ...owner.context, operationId: rawOperation }));
      assert.deepEqual(await catalog.readMerchantListingCreate({ ...sibling.context, operationId: peerOperation }), { ...peerReceipt, replayed: true });
      assert.equal((await catalog.getOwnedMerchantProduct({ ...sibling.context, productId: peerReceipt.productId })).product.name,
        'Independent sibling listing');
      assert.deepEqual(await creationRows(), finalReceipts);
    } finally {
      await reset?.closeFeatureTransports?.();
      await Promise.all([...Object.values(pools), leasePool].map(pool => pool.end()));
    }
  });
