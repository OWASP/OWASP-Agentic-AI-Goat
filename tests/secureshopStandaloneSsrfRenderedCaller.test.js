'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  path = require('node:path');
const {
  qualifyCompiledPolicyRenderer,
  nativeConfig,
  observeConsumedSsrfReceipts,
  createStandaloneSsrfMount,
  createSsrfCore,
  assertReceipt,
  FLAGS,
  SCOPE,
  PREFIX,
  NATIVE,
  BUILD,
  EVIDENCE
} = require('./postgres/secureshopStandaloneSsrfRendered.integration.test');
const ROOT = path.resolve(__dirname, '..');
test('V27 opt-in launch is confined to original policy preflight and fallback is unchanged',()=>{
  const source=require('node:fs').readFileSync(path.join(ROOT,'tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js'),'utf8');
  const policy=source.indexOf("if(POLICY_OUTPUT){\n      fs.mkdirSync(runtime");
  const launch=source.indexOf("require('../fixtures/secureshopPolicyOutputBrowserAdmission').launchPolicyOutputBrowser");
  const preflight=source.indexOf('retained.rendererPreflight=await qualifyCompiledPolicyRenderer');
  assert.ok(policy>=0&&policy<launch&&launch<preflight);
  assert.equal(source.split("require('../fixtures/secureshopPolicyOutputBrowserAdmission')").length,2);
  assert.match(source,/if\(!browser\)\{\s*fs\.mkdirSync\(runtime,\{mode:0o700\}\);\s*browser=await require\('\.\.\/fixtures\/secureshopAnalyticsBrowserOwner'\)\.launchOwnedAnalyticsBrowser/);
});
test('receipt observation preserves the original consume return, arguments and failure after commit', () => {
  const receipt = Object.freeze({ operationId: 'controlled-operation', responseSha256: 'exact-hash' });
  const binding = Object.freeze({ targetId: 'controlled-target' });
  const input = Object.freeze({ nonce: 'controlled-nonce', requestId: 'controlled-request' });
  const failure = Error('Original consume failed');
  let available = true, reads = 0, consumes = 0, observed = 0;
  const targetPool = Object.freeze({
    readReceipt() { reads++; throw Error('The completed receipt is no longer readable'); },
    consume(actualBinding, actualInput) {
      consumes++;
      assert.strictEqual(actualBinding, binding);
      assert.strictEqual(actualInput, input);
      if (!available) throw failure;
      available = false;
      return receipt;
    }
  });
  const options = Object.freeze({ owned: 'controlled-construction-only' });
  const close = () => {}, bundle = Object.freeze({ targetPool, close });
  const wrapped = observeConsumedSsrfReceipts(actual => {
    assert.strictEqual(actual, options);
    return bundle;
  }, (actualBinding, actualInput, actualReceipt) => {
    observed++;
    assert.strictEqual(actualBinding, binding);
    assert.strictEqual(actualInput, input);
    assert.strictEqual(actualReceipt, receipt);
    assert.equal(available, false, 'Observation follows the real consume');
  })(options);
  assert.strictEqual(wrapped.close, close);
  assert.strictEqual(wrapped.targetPool.readReceipt, targetPool.readReceipt);
  assert.strictEqual(wrapped.targetPool.consume(binding, input), receipt);
  assert.throws(() => wrapped.targetPool.consume(binding, input), error => error === failure);
  assert.equal(consumes, 2);
  assert.equal(observed, 1);
  assert.equal(reads, 0);
});
// These constructed envelopes exercise only admission and acceptance schemas.
// Importing the caller does not run its separately gated native qualification.
function environment() {
  const env = {
    [NATIVE]: '1',
    PG_TEST_DISPOSABLE: 'yes',
    OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: ROOT,
    [BUILD]: path.join(ROOT, 'client/build'),
    [EVIDENCE]: '/tmp/c32-controlled-contract/receipt.json'
  };
  for (const [key, store] of Object.entries({
    IDENTITY: 'identity',
    AGENTS: 'secureshop_agents',
    COMMERCE: 'secureshop',
    REVIEW: 'secureshop_review'
  })) for (const role of ['RUNTIME', 'MIGRATION']) env[PREFIX + key + '_' + role + '_URL'] = `postgresql://dvaia_${store}_${role.toLowerCase()}@127.0.0.1:5432/owasp_ai_goat_test_${store}`;
  return env;
}
function receipt() {
  return {
    ...Object.fromEntries(FLAGS.map(flag => [flag, true])),
    scope: SCOPE,
    actorCalls: 6,
    judgeCalls: 1,
    actionCount: 3,
    freshPosts: 3,
    retryPosts: 1,
    httpEffects: 2,
    genuineCredit: 1,
    errors: []
  };
}
test('closed current-main admission accepts four separated disposable runtime/migration pairs', () => {
  const env = environment(),
    config = nativeConfig(env);
  assert.equal(config.build, env[BUILD]);
  assert.equal(config.directory, '/tmp/c32-controlled-contract');
  assert.equal(Object.keys(config.urls).length, 4);
});
test('admission rejects inactive selector, application stores, credential leaks and mismatched migration targets', async t => {
  const variants = {
    'missing opt-in': env => delete env[NATIVE],
    'not disposable': env => env.PG_TEST_DISPOSABLE = 'no',
    'different checkout': env => env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE = '/tmp/copied-source',
    'different build': env => env[BUILD] = '/tmp/copied-source/client/build',
    'source evidence': env => env[EVIDENCE] = path.join(ROOT, 'receipt.json'),
    'relative evidence': env => env[EVIDENCE] = 'receipt.json',
    'remote database': env => env[PREFIX + 'IDENTITY_RUNTIME_URL'] = env[PREFIX + 'IDENTITY_RUNTIME_URL'].replace('127.0.0.1', 'example.invalid'),
    'application database': env => env[PREFIX + 'IDENTITY_RUNTIME_URL'] = env[PREFIX + 'IDENTITY_RUNTIME_URL'].replace('owasp_ai_goat_test_identity', 'identity'),
    'wrong role': env => env[PREFIX + 'AGENTS_RUNTIME_URL'] = env[PREFIX + 'AGENTS_MIGRATION_URL'],
    'password in URL': env => env[PREFIX + 'IDENTITY_RUNTIME_URL'] = env[PREFIX + 'IDENTITY_RUNTIME_URL'].replace('@', ':private@'),
    'URL query': env => env[PREFIX + 'IDENTITY_RUNTIME_URL'] += '?sslmode=disable',
    'different migration database': env => env[PREFIX + 'IDENTITY_MIGRATION_URL'] = env[PREFIX + 'IDENTITY_MIGRATION_URL'].replace('owasp_ai_goat_test_identity', 'owasp_ai_goat_test_other'),
    'different migration port': env => env[PREFIX + 'IDENTITY_MIGRATION_URL'] = env[PREFIX + 'IDENTITY_MIGRATION_URL'].replace('5432', '5433'),
    'shared store database': env => {
      for (const role of ['RUNTIME', 'MIGRATION']) env[PREFIX + 'REVIEW_' + role + '_URL'] = env[PREFIX + 'REVIEW_' + role + '_URL'].replace('owasp_ai_goat_test_secureshop_review', 'owasp_ai_goat_test_secureshop');
    }
  };
  for (const [name, mutate] of Object.entries(variants)) await t.test(name, () => {
    const env = environment();
    mutate(env);
    assert.throws(() => nativeConfig(env));
  });
});
test('acceptance requires all actual boundaries and the unchanged 14-dispatch ceiling', () => {
  assert.equal(assertReceipt(receipt()).genuineCredit, 1);
  assertReceipt({
    ...receipt(),
    actorCalls: 13
  });
  assertReceipt({
    ...receipt(),
    actorCalls: 10,
    judgeCalls: 4
  });
  for (const flag of FLAGS) assert.throws(() => assertReceipt({
    ...receipt(),
    [flag]: false
  }), flag);
  for (const mutation of [{
    actorCalls: 5
  }, {
    actorCalls: 14
  }, {
    actorCalls: 6.5
  }, {
    judgeCalls: 0
  }, {
    judgeCalls: 5
  }, {
    actionCount: 4
  }, {
    freshPosts: 4
  }, {
    retryPosts: 0
  }, {
    httpEffects: 3
  }, {
    genuineCredit: 0
  }, {
    errors: [{
      message: 'Original call failed'
    }]
  }, {
    scope: 'legacy SSRF'
  }, {
    actualModelProof: true
  }]) assert.throws(() => assertReceipt({
    ...receipt(),
    ...mutation
  }));
  const incomplete = receipt();
  delete incomplete.fixtureCleaned;
  assert.throws(() => assertReceipt(incomplete));
});
test('canonical scoped SSRF request reads require an options object and retain exact source identity', async () => {
  const {
    createSecureShopBoundSsrfRepository
  } = require('../server/database/postgres/secureshopBoundSsrfRepository');
  const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const target = {
    targetId: id(1),
    launchId: id(2),
    scenarioId: id(3),
    generation: 1,
    platformOwnerId: 4,
    platformSessionId: 5
  };
  const requestId = id(6),
    operationId = id(7),
    nonce = id(8),
    url = 'http://127.0.0.1:12345/policy/public';
  const calls = [],
    checks = [],
    releases = [];
  const query = async (sql, parameters) => {
    calls.push({
      sql,
      parameters
    });
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) return {
      rows: []
    };
    assert.match(sql, /^SELECT /, 'A recovery read must never create an effect');
    if (sql.includes('pg_advisory_xact_lock')) {
      assert.deepEqual(parameters, [target.targetId]);
      return {
        rows: []
      };
    }
    if (sql.includes('SELECT * FROM secureshop_agents.bound_ssrf_targets')) return {
      rows: [{
        lifecycle: 'active'
      }]
    };
    assert(sql.includes('FROM secureshop_agents.bound_ssrf_requests r'));
    assert.deepEqual(parameters, [target.targetId, requestId, target.launchId, target.scenarioId, target.generation, target.platformOwnerId, target.platformSessionId]);
    return {
      rows: [{
        operation_id: operationId,
        target_id: target.targetId,
        request_id: requestId,
        resource_kind: 'public-policy',
        nonce,
        issued_url: url,
        completed: false
      }]
    };
  };
  const repository = createSecureShopBoundSsrfRepository({
    query,
    connect: async () => ({
      query,
      release: () => releases.push(true)
    })
  }, {
    checkCurrent: async scope => checks.push(scope),
    checkCleanup: async () => {
      throw Error('Recovery must not invoke cleanup');
    }
  });
  assert.deepEqual(await repository.readRequest(target, {
    requestId
  }), {
    operationId,
    targetId: target.targetId,
    requestId,
    resourceKind: 'public-policy',
    nonce,
    url,
    completed: false
  });
  await assert.rejects(repository.readRequest(target, requestId), error => error.code === 'BOUND_SSRF_UNAVAILABLE');
  assert.equal(calls.filter(call => call.sql.includes('FROM secureshop_agents.bound_ssrf_requests r')).length, 1);
  assert.deepEqual(checks, [target, target]);
  assert.equal(releases.length, 2);
});
test('every rendered caller request read uses the production options signature', () => {
  const fs = require('node:fs'),
    parser = require('../client/node_modules/@babel/parser');
  const file = path.join(ROOT, 'tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js');
  const tree = parser.parse(fs.readFileSync(file, 'utf8'), {
    sourceType: 'script'
  });
  const reads = [];
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && node.callee.property.name === 'readRequest') reads.push(node);
    for (const [key, value] of Object.entries(node)) if (key !== 'loc') {
      if (Array.isArray(value)) value.forEach(walk);else if (value && typeof value === 'object') walk(value);
    }
  }
  walk(tree);
  assert.equal(reads.length, 4, 'Existing owner read and both cohort sibling preservation reads are required');
  for (const call of reads) {
    assert.equal(call.arguments.length, 2);
    assert.equal(call.arguments[1].type, 'ObjectExpression');
    assert.deepEqual(call.arguments[1].properties.map(property => property.key.name), ['requestId']);
  }
});
test('default-on activation constructs the actual complete core and mounted standalone services without resources', async () => {
  const keys = ['PLATFORM_DATABASE_ENGINE', 'WORKSHOP_DATABASE_ENGINE', 'SS_CONTROLLED_SSRF_READY', 'SS_PERSONA_INBOX_READY', 'SS_MCP_TRUST_READY', 'SS_AUDIT_SUMMARY_ENABLED'];
  const prior = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  Object.assign(process.env, {
    PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres',
    SS_CONTROLLED_SSRF_READY: 'true',
    SS_MCP_TRUST_READY: 'false',
    SS_AUDIT_SUMMARY_ENABLED: 'false'
  });
  delete process.env.SS_PERSONA_INBOX_READY;
  const unused = () => {
    throw Error('Controlled construction must not execute authority, inference, connections or effects');
  };
  const queries = [];
  const query = async sql => {
    queries.push(sql);
    if (sql.includes('registered_admin_reset_operations')) return {
      rows: [{
        operation_write: true,
        recovery_write: true,
        recovery_ack: true,
        operation_mutable: false,
        recovery_removable: false
      }]
    };
    assert(sql.includes("to_regclass('identity.secureshop_owner_resets')"));
    return {
      rows: [{
        operations: true,
        launches: true,
        reset_identity: true,
        journal_guard: true,
        mapping_guard: true,
        admission_guard: true
      }]
    };
  };
  const pool = () => ({
    query,
    connect: unused
  });
  const identity = pool(),
    agents = pool(),
    review = pool(),
    commerce = pool(),
    lease = pool(),
    provision = pool();
  let lifecycle, core, disabled;
  const root = '/controlled-c32-no-target-is-issued';
  assert.equal(require('node:fs').existsSync(root), false);
  try {
    lifecycle = require('../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
      identityPool: identity,
      agentsPool: agents,
      reviewPool: review,
      leasePool: lease,
      provisionPool: provision,
      ssrfFactory: require('../server/services/secureshopSsrfProduction').createSecureShopSsrfRepositoryBundle,
      ssrfFixtureRoot: root
    });
    const options = {
      identityPool: identity,
      agentsPool: agents,
      reviewPool: review,
      commercePool: commerce,
      leasePool: lease,
      resetComposition: lifecycle,
      agentRuntime: {
        provider: {
          chat: unused,
          finalResponse: unused,
          config: {
            provider: 'controlled',
            model: 'unit',
            mocked: true
          }
        },
        pool: {
          callTool: unused
        }
      },
      ssrfFeature: true,
      jwtSecret: 'controlled-constructor-test-only-32-bytes'
    };
    core = createSsrfCore(options);
    assert.equal(core.personaInbox.ready, true, 'Canonical PostgreSQL activation defaults on');
    assert.equal(typeof core.personaInbox.router, 'function');
    const standalone = require('../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
      repository: require('../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({
        pool: identity
      })
    });
    const bootstrap = require('../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
      launches: core.launches,
      personaAuth: core.personaAuth,
      authService: standalone
    });
    const scenes = require('../server/services/secureshopScenes').createSecureShopScenes({
      repository: require('../server/database/postgres/secureshopSceneRepository').createSecureShopProductionSceneRepository({
        pool: identity,
        provisionPool: provision,
        leasePool: lease,
        launches: core.launches
      }),
      reviewPool: review,
      launches: core.launches
    });
    const reset = require('../server/services/secureshopStandaloneReset').createSecureShopStandaloneReset({
      identityPool: identity,
      authService: standalone,
      launches: core.launches,
      scenes,
      resetCoordinator: lifecycle.launchResetCoordinator,
      preflight: lifecycle.sceneResetPreflight
    });
    const mode = require('../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode({
      authService: standalone,
      repository: require('../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity)
    });
    const catalog = require('../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({
      pool: identity,
      authService: standalone
    });
    const publicCatalog = require('../server/database/postgres/secureshopStorePublicCatalogRepository').createSecureShopStorePublicCatalogRepository({
      identityPool: identity,
      reviewPool: review,
      commercePool: commerce
    });
    const result = await createStandaloneSsrfMount({
      composition: core,
      identityPool: identity,
      standalone,
      bootstrap,
      reset,
      mode,
      catalog,
      publicCatalog,
      personaAuthority: {
        capture: unused
      },
      judge: unused
    });
    assert.equal(result.bound.standaloneReadiness.ready, true);
    assert.equal(Object.keys(result.bound.standaloneReadiness.checks).length, 10);
    assert(Object.values(result.bound.standaloneReadiness.checks).every(value => value === true));
    assert.equal(result.mounted.personaInbox, core.personaInbox);
    assert.equal(result.mounted.ssrf, core.ssrf);
    assert(result.bound.gateway.stack.some(layer => layer.handle === core.ssrf.router));
    assert.equal(queries.length, 2, 'Only real reset readiness reads occur; no connections or effects');
    process.env.SS_PERSONA_INBOX_READY = 'false';
    disabled = createSsrfCore(options);
    assert.equal(disabled.personaInbox.ready, false, 'Explicit disabled configuration remains supported');
    process.env.SS_PERSONA_INBOX_READY = 'true';
    await assert.rejects(createStandaloneSsrfMount({
      composition: disabled,
      identityPool: identity,
      standalone,
      bootstrap,
      reset,
      mode,
      catalog,
      publicCatalog,
      personaAuthority: {
        capture: unused
      },
      judge: unused
    }), /core readiness incomplete/);
  } finally {
    await core?.closeBrowserAssessment();
    await disabled?.closeBrowserAssessment();
    await lifecycle?.ssrf.close();
    for (const [key, value] of Object.entries(prior)) if (value === undefined) delete process.env[key];else process.env[key] = value;
    assert.equal(require('node:fs').existsSync(root), false);
  }
});
test('explicitly disabled optional panels still require a complete standalone core', async () => {
  const express = require('express');
  const keys = ['PLATFORM_DATABASE_ENGINE', 'WORKSHOP_DATABASE_ENGINE', 'SS_CONTROLLED_SSRF_READY', 'SS_PERSONA_INBOX_READY', 'SS_MCP_TRUST_READY', 'SS_AUDIT_SUMMARY_ENABLED'];
  const prior = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  Object.assign(process.env, {
    PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres',
    SS_CONTROLLED_SSRF_READY: 'true',
    SS_PERSONA_INBOX_READY: 'false',
    SS_MCP_TRUST_READY: 'false',
    SS_AUDIT_SUMMARY_ENABLED: 'false'
  });
  let ownerReadiness = 0,
    sqlReads = 0;
  const unused = () => {
    throw Error('Construction must not execute authority, model or effects');
  };
  const methods = names => Object.fromEntries(names.split(' ').map(name => [name, unused]));
  const composition = {
    launches: methods('resolveCapability readActiveMetadata assertCurrent'),
    personaAuth: methods('authenticatePersona authenticateBoundToken login renew logout listSessions revokeOwnedSession changePassword listApiKey rotateApiKey authenticateApiKey'),
    catalog: methods('listProducts getProduct listMerchantProducts categories createMerchantProduct updateMerchantProduct archiveMerchantProduct provisionPracticeTarget'),
    commerce: methods('cart add update remove summary checkout orders order importGuestCart'),
    account: methods('profile updateProfile addresses createAddress updateAddress deleteAddress'),
    admin: methods('users kpis'),
    router: express.Router(),
    browserRouter: express.Router(),
    ssrf: {
      ready: true,
      router: express.Router()
    },
    launchResetCoordinator: methods('reset recover'),
    ownerResetService: {
      assertReady: async () => {
        ownerReadiness++;
      },
      resetOwner: unused
    },
    createStudentDeletionCleanup: unused
  };
  const input = {
    composition,
    identityPool: {
      query: async sql => {
        assert(sql.includes('has_table_privilege') && sql.includes('registered_admin_reset_operations'));
        sqlReads++;
        return {
          rows: [{
            operation_write: true,
            recovery_write: true,
            recovery_ack: true,
            operation_mutable: false,
            recovery_removable: false
          }]
        };
      },
      connect: unused
    },
    standalone: methods('authenticate register login renew logout changePassword establishTenantContext'),
    bootstrap: unused,
    reset: methods('readiness reset readRecovery recover'),
    mode: methods('get set'),
    catalog: methods('list set'),
    publicCatalog: methods('browse product related categories reviews'),
    personaAuthority: {
      capture: unused
    },
    judge: unused
  };
  try {
    // The production application, gateway and added service constructors run;
    // SQL/authority dependencies are controlled and no listener is started.
    const {
      mounted,
      bound
    } = await createStandaloneSsrfMount(input);
    assert.equal(bound.readiness, null);
    assert.equal(bound.launchRouter, null);
    assert.deepEqual(bound.standaloneReadiness, {
      ready: true,
      scope: 'standalone',
      checks: {
        authentication: true,
        reset: true,
        settings: true,
        publicCatalog: true,
        catalog: true,
        commerce: true,
        account: true,
        administration: true,
        authority: true,
        requestedPanels: true
      }
    });
    assert.equal(typeof mounted.standaloneAuth.cartImport, 'function');
    for (const method of ['preview', 'reset', 'read', 'reveal', 'acknowledge']) assert.equal(typeof mounted.standaloneAuth.registeredAdminReset[method], 'function');
    for (const method of ['list', 'retry']) assert.equal(typeof mounted.standaloneAuth.assessmentRecovery[method], 'function');
    assert(bound.gateway.stack.some(layer => layer.handle === composition.ssrf.router));
    assert.equal(ownerReadiness, 1);
    assert.equal(sqlReads, 1);
    await assert.rejects(require('../server/services/secureshopBoundApplication').createSecureShopBoundApplication({
      engine: 'postgres',
      shopEnabled: true,
      authenticateToken: unused,
      audit: unused,
      agentRuntime: {},
      getComposition: async () => mounted
    }), /panel readiness incomplete/, 'The standalone core must never claim all workshop panels');
    for (const [section, method] of [['standalone', 'authenticate'], ['reset', 'recover'], ['mode', 'set'], ['catalog', 'list'], ['publicCatalog', 'reviews']]) {
      const changed = {
        ...input,
        [section]: {
          ...input[section]
        }
      };
      delete changed[section][method];
      await assert.rejects(createStandaloneSsrfMount(changed), section === 'standalone' ? /Standalone SecureShop authority unavailable/ : /core readiness incomplete/);
    }
    const missingPanel = {
      ...input,
      composition: {
        ...composition,
        ssrf: {
          ready: false,
          router: composition.ssrf.router
        }
      }
    };
    await assert.rejects(createStandaloneSsrfMount(missingPanel), /core readiness incomplete/);
  } finally {
    for (const [key, value] of Object.entries(prior)) if (value === undefined) delete process.env[key];else process.env[key] = value;
  }
});

test('compiled policy renderer preflight requires the same original controlled HTML to execute only in vulnerable mode', async()=>{
 const captures=[],calls=[];let closed=0;
 const make=bad=>()=>({async qualifyPolicyOutput(input){calls.push(input);const execute=input.modeCapability.effectiveMode==='vuln';
   return {component:{id:'SecureShop.PolicyFinalResponse'},renderedSourceSha256:require('node:crypto').createHash('sha256').update(input.html).digest('hex'),
    renderingMode:'client',syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,
    executed:bad===true?false:execute,targetEventExecuted:execute,targetEffectObserved:execute};},async close(){closed++;}});
 let sandboxCalls=0;const qualifySandbox=async({html})=>{sandboxCalls++;return{contextClosed:true,sourceSha256:require('node:crypto').createHash('sha256').update(html).digest('hex')};};
 const value=await qualifyCompiledPolicyRenderer({qualifySandbox,browser:{wsEndpoint:()=> 'ws://127.0.0.1/controlled'},createQualification:make(false),onCapture:async v=>captures.push(v)});
 assert.equal(value.controlled,true);assert.equal(value.actualModel,false);assert.equal(value.genuineCredit,false);
 assert.equal(value.adapterClosed,true);assert.equal(closed,1);assert.equal(calls.length,2);
 assert.equal(calls[0].html,calls[1].html);assert.equal(captures.at(-1).adapterClosed,true);assert.equal(sandboxCalls,1);
 await assert.rejects(qualifyCompiledPolicyRenderer({browser:{wsEndpoint:()=> 'ws://127.0.0.1/controlled'},createQualification:make(true)}));assert.equal(closed,2);
});

test('V27 receipt retains its own objective, exact physical calls and every lifecycle gate',()=>{
 const {assertPolicyOutputReceipt:validate,POLICY_OUTPUT_FLAGS:flags,POLICY_OUTPUT_SCOPE:scope}=require('./postgres/secureshopStandaloneSsrfRendered.integration.test');
 const value={...Object.fromEntries(flags.map(key=>[key,true])),scope,
  catalogAdmission:{objectiveId:'ss_policy_final_html_execution',fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false},
  actorCalls:6,judgeCalls:2,actionCount:3,freshPosts:3,retryPosts:0,httpEffects:3,genuineCredit:1,errors:[]};
 validate(value);assert.throws(()=>assertReceipt(value));
 for(const key of flags)assert.throws(()=>validate({...value,[key]:false}),key);
 for(const change of [{judgeCalls:3},{actorCalls:5},{httpEffects:2},{retryPosts:1},{genuineCredit:0},{extra:true},
  {scope:SCOPE},{catalogAdmission:{...value.catalogAdmission,productionQualification:'native-browser-judge'}},
  {catalogAdmission:{...value.catalogAdmission,fixtureLocalCandidateAdmission:false}}])assert.throws(()=>validate({...value,...change}));
});


test('V27 consumed HTTP authority uses the actual expanded adapter request while binding exact receipt and consume input',async()=>{
 const {assertConsumedPolicyHttpAuthority:check}=require('./postgres/secureshopStandaloneSsrfRendered.integration.test');
 const {createSecureShopSsrfExternalAdapter}=require('../server/services/secureshopSsrfExternalAdapter');
 const {fixture}=require('./secureshopPolicyFinalHtmlEvidence.test');
 const {POLICY_SHA256}=require('../server/services/secureshopPolicyFinalHtmlContract');
 const p=fixture(),scope=require('../server/services/secureshopConversationBinding').createLaunchScope(p.binding);
 const request={...scope,...p.request,completed:false,replayed:true,egressPolicySha256:POLICY_SHA256,policyDecision:'allowed'};
 const receipt={version:1,operationId:request.operationId,targetId:request.targetId,nonce:request.nonce,
  requestId:request.requestId,method:'GET',path:new URL(request.url).pathname,resourceKind:'html-policy',status:200,
  responseSha256:p.invocation.responseSha256,receiptSha256:p.invocation.egressReceiptSha256};
 let consumed;
 const adapter=createSecureShopSsrfExternalAdapter({resolveRequest:async()=>request,checkCurrent:async()=>{},
  targetPool:{readReceipt:()=>receipt,consume(binding,input){consumed={binding,input,receipt};return receipt;}},
  upstreamPool:{callTool:async()=>JSON.parse(p.traces.find(row=>row.kind==='mcp_result').result_json)},
  recordInvocation:async()=>p.invocation});
 const execution={runId:p.run.run_id,ownerKey:p.run.owner_key,durableGeneration:p.run.generation,check:async()=>{}};
 const toolPool=await adapter.createToolPool(p.binding,{requestId:p.requestId,sessionId:p.sessionId,execution});
 const args={policy_url:request.url},callId=p.invocation.callId;
 const result=await toolPool.callTool('summarizer','explain_return_policy',args,{callId});
 await adapter.observeExternalTool({binding:p.binding,requestId:p.requestId,sessionId:p.sessionId,run:execution,
  observation:{result,callId,tool:'summarizer.explain_return_policy',step:1,args,effectReceipt:{version:1,status:'completed',
   runId:execution.runId,ownerKey:execution.ownerKey,generation:execution.durableGeneration,effectKey:p.effect.effect_key}}});
 assert(consumed);assert.equal(consumed.binding.policyHtml,p.request.policyHtml);
 assert.equal(consumed.binding.completed,false);assert.equal(consumed.binding.replayed,true);
 assert(Object.keys(consumed.binding).length>6,'Production consume receives the resolved request, not a six-field scope');
 check(consumed,scope,{proof:p});
 for(const change of [c=>{c.binding.platformOwnerId++;},c=>{c.binding.targetId=require('node:crypto').randomUUID();},
  c=>{c.input.requestId=require('node:crypto').randomUUID();},c=>{c.input.nonce=require('node:crypto').randomUUID();},
  c=>{c.receipt.operationId=require('node:crypto').randomUUID();},c=>{c.receipt.targetId=require('node:crypto').randomUUID();},
  c=>{c.receipt.nonce=require('node:crypto').randomUUID();}]){
  const changed=structuredClone(consumed);change(changed);assert.throws(()=>check(changed,scope,{proof:p}));
 }
});
