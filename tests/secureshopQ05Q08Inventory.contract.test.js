'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { inventory, verify, REQUIRED_RECEIPT_FIELDS } = require('../scripts/verify-secureshop-q05-q08-inventory');
const outside = require('../scripts/lib/q05q08NonSecureShopInventory');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');

test('Q05/Q08 source inventory spans direct panels, RoleChat, MCP tools and intentional exceptions without promoting credit', () => {
  const value = inventory();
  const counts = verify(value);
  assert.deepEqual(value.qualification, { Q05: 'deferred_unverified', Q08: 'deferred_unverified' });
  assert.ok(counts.routeMutations > counts.confirmTerminals, 'non-confirmation mutations must remain visible');
  assert.ok(counts.clientFetches > counts.roleTools, 'direct panel actions must remain visible');
  assert.ok(counts.mcpTools > 17, 'all task agents must contribute tool descriptions');
  assert.ok(counts.intentionalExceptions > 0, 'annotated teaching exceptions must remain visible');
  assert.ok(REQUIRED_RECEIPT_FIELDS.includes('actorDecisionId'));
  assert.ok(REQUIRED_RECEIPT_FIELDS.includes('observedEffect'));
  assert.ok(REQUIRED_RECEIPT_FIELDS.includes('judgeDecisionId'));
  for (const rows of Object.values(value.surfaces))
    assert.ok(rows.every(row => row.status === 'source_discovered_runtime_unverified'));
});

test('discovery exposes top-level confirmation authority and bridge modules without claiming reachability', () => {
  const value = inventory();
  assert.equal(value.scope.denominatorComplete, false);
  assert.equal(value.scope.actionDiscovery, 'secureshop_and_nonsecureshop_static_source_callsite_discovery_not_a_supported_action_manifest');
  for (const module of ['secureshopCouponAgentConfirmation.js', 'secureshopTicketAgentConfirmation.js',
    'secureshopBoundMailGraph.js', 'secureshopBoundReviewComposition.js']) {
    assert.ok(value.surfaces.authorityModules.some(row => row.value === module), module);
  }
  assert.ok(value.surfaces.confirmationBindings.some(row =>
    row.file.endsWith('/secureshopCouponAgentConfirmation.js') && row.value === 'confirm'));
  assert.ok(value.surfaces.bridgeModules.some(row => row.value === 'assessmentPanelIntent.mjs'));
  assert.ok(value.surfaces.bridgeModules.some(row => row.value === 'fetchAdapter.mjs'));
  assert.ok(value.surfaces.bridgeModules.every(row => !row.file.includes('.test.')));
});

test('coupon composition callsite is found despite stale unmounted module comments', () => {
  const value = inventory();
  const reference = value.surfaces.compositionMountReferences.find(row =>
    row.target === 'server/routes/secureshop/boundCouponAgentConfirm.js');
  assert.ok(reference);
  assert.equal(reference.file, 'server/services/secureshopBoundReviewComposition.js');
  assert.equal(reference.factory, 'createBoundCouponAgentConfirmRouter');
  assert.equal(reference.referenceKind, 'inline_router_use_factory_callsite');
  assert.equal(reference.runtimeReachability, 'conditional_transitive_mount_unverified');
  assert.equal(reference.status, 'source_discovered_runtime_unverified');
});

test('all current canonical workshop IDs and separate CTF stages remain visible, not a complete action denominator', () => {
  const value = inventory();
  const expected = Object.entries(WORKSHOP_OBJECTIVES).flatMap(([family, objectives]) =>
    objectives.map(objective => `${family}.${objective.id}`));
  assert.deepEqual(value.surfaces.catalogObjectives.map(row => row.value).sort(), expected.sort());
  for (const family of ['sql_injection_workshop', 'nosql_injection_workshop',
    'sensitive_info_disclosure', 'excessive_agency', 'csrf_workshop', 'supply_chain_rce',
    'direct_prompt_injection', 'indirect_prompt_injection', 'xss_workshop',
    'xss_email_builder', 'legacy_sensitive_file_ssi']) {
    assert.ok(value.surfaces.catalogObjectives.some(row => row.family === family), family);
  }
  assert.deepEqual(value.surfaces.ctfStages.map(row => row.stageNumber), [1,2,3,4,5,6,7,8,9,10]);
  assert.ok(value.surfaces.catalogObjectives.every(row => row.applicability === 'unresolved'));
  assert.throws(() => verify({ ...value, scope: { ...value.scope, denominatorComplete: true } }),
    /cannot establish a complete/);
  assert.deepEqual(value.qualification, { Q05: 'deferred_unverified', Q08: 'deferred_unverified' });
});

test('non-SecureShop source discovery ties concrete app and React mounts to route and UI callsites without promoting reachability',()=>{
  const value=inventory(),rows=value.nonSecureShop;
  assert.equal(value.schemaVersion,5);
  assert.equal(value.scope.denominatorComplete,false);
  const sql=rows.applicationMounts.find(row=>row.base==='/api/workshop/sql');
  assert.equal(sql.target,'server/routes/sqlWorkshop.js');
  assert.equal(sql.resolution,'module_reference_source_only');
  assert.ok(rows.routeRegistrations.some(row=>row.file===sql.target
    && row.verb==='post'&&row.path==='/chat'));
  assert.ok(rows.reactRoutes.some(row=>row.route==='/workshop/sql'
    && row.modules.includes('./pages/workshops/SQLWorkshop')));
  assert.ok(rows.uiRequests.some(row=>row.file==='client/src/pages/workshops/SQLWorkshop.js'
    && row.url==='/api/workshop/sql/chat'));
  assert.ok(rows.uiRequestRelations.some(row=>row.file==='client/src/pages/challenges/CSRFWorkshop.js'
    && row.url==='/api/workshop/csrf/mode'
    && row.resolution==='static_ui_event_to_exact_route_candidate_runtime_unverified'));
  assert.ok(rows.routeRegistrations.some(row=>row.file==='server/routes/ctfAuthorityRouter.js'
    && row.path==='/admin/reset'));
  assert.ok(rows.reactRoutes.some(row=>row.route==='/ctf/challenge'
    && row.modules.includes('./pages/CTFChallenge')));
  assert.equal(rows.applicationMounts.find(row=>row.base==='/api/ctf').target,null,
    'deferred CTF production mount must not be mistaken for the legacy ctf.js router');
  assert.deepEqual(rows.deferredProductionChains[0].files,[
    'server/applicationServer.js','server/services/ctfAuthorityProduction.js',
    'server/services/ctfAuthorityApplication.js','server/routes/ctfAuthorityRouter.js']);
  assert.ok(rows.uiRequests.every(row=>!row.file.includes('.test.')));
  assert.ok(rows.routeRegistrations.every(row=>!row.file.includes('.test.')));
  assert.ok(rows.uiRequestRelations.every(row=>!row.resolution.includes('qualified')));
});

test('reviewed CTF admin partition remains connected without completing the global denominator',()=>{
  const value=inventory();
  assert.equal(value.reviewedPartitions.ctfAdmin.actions.length,13);
  assert.equal(verify(value)['reviewedPartitions.ctfAdmin.actions'],13);
  assert.deepEqual(value.reviewedPartitions.ctfAdmin.unresolvedActions.map(row=>row.id),[
    'ctf.participant.register','ctf.participant.start','ctf.participant.hint',
    'ctf.participant.attempt','ctf.participant.practice',
  ]);
  assert.equal(value.reviewedPartitions.ctfAdmin.routeOnly.length,2);
  assert.equal(value.scope.denominatorComplete,false);
  assert.deepEqual(value.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
  const altered=JSON.parse(JSON.stringify(value));
  altered.reviewedPartitions.ctfAdmin.actions[0].request.path='/api/ctf/legacy-reset';
  assert.throws(()=>verify(altered),/source-validated manifest/);
});

test('participant partition connects all five prior admin exclusions without claiming qualification',()=>{
  const value=inventory();
  const participant=value.reviewedPartitions.ctfParticipant;
  assert.deepEqual(participant.actions.map(row=>row.id),
    value.reviewedPartitions.ctfAdmin.unresolvedActions.map(row=>row.id));
  assert.equal(verify(value)['reviewedPartitions.ctfParticipant.actions'],5);
  assert.equal(value.scope.denominatorComplete,false);
  assert.deepEqual(value.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
  assert.match(participant.qualification,/unverified/);
  const altered=JSON.parse(JSON.stringify(value));
  altered.reviewedPartitions.ctfParticipant.actions[0].request.path='/api/ctf/legacy-register';
  assert.throws(()=>verify(altered),/participant partition differs/);
  const missing=JSON.parse(JSON.stringify(value));
  delete missing.reviewedPartitions.ctfParticipant;
  assert.throws(()=>verify(missing),/participant partition differs/);
});

test('AST discovery excludes comments/examples and refuses unrelated event or duplicate/absent route joins',()=>{
  const route=outside.inspectRoutes(`// router.post('/fake', cb)\nconst sample="router.post('/string', cb)";
    router.post('/real', cb); router.post('/real', another); router[verb]('/computed', cb);`,
    'server/routes/example.js');
  assert.deepEqual(route.registrations.map(row=>row.path),['/real','/real']);
  assert.equal(route.computed.length,1);
  assert.equal(route.computed[0].resolution,'computed_router_verb_unresolved');
  const ui=outside.inspectUiSource(`function Panel(){
    const send=()=>axios.post('/api/workshop/example/real',{});
    const unrelated=()=>{};
    return <button onClick={unrelated}>Example axios.post('/fake')</button>;
  }`, 'client/src/pages/Example.js');
  assert.equal(ui.requests.length,1);
  assert.equal(ui.events.length,1);
  assert.equal(ui.links.length,0,'an unrelated onClick cannot establish request intent');
  const deferred=outside.inspectUiSource(`function Panel(){
    const click=()=>{ const later=()=>axios.post('/api/workshop/example/real',{}); return later; };
    return <button onClick={click}>Do not count an uncalled nested function</button>;
  }`, 'client/src/pages/Deferred.js');
  assert.equal(deferred.requests.length,1);
  assert.equal(deferred.links.length,0,'a nested uncalled callback is not the clicked request');
  const base={applicationMounts:[{base:'/api/workshop/example',verb:'use',
    target:'server/routes/example.js'}],reactRoutes:[{modules:['./pages/Example']}],
    routeRegistrations:route.registrations,uiRequests:ui.requests,uiEventRequestLinks:ui.links};
  assert.equal(outside.joinRequests(base)[0].resolution,'no_unique_exact_mounted_route_unresolved');
  assert.equal(outside.joinRequests({...base,routeRegistrations:[]})[0].resolution,
    'no_unique_exact_mounted_route_unresolved');
  assert.equal(outside.joinRequests({...base,routeRegistrations:route.registrations.slice(0,1)})[0].resolution,
    'exact_mounted_route_event_relation_unresolved');
  const alias=outside.inspectApplication(`const reused=require('./routes/first');
    function shadow(){const reused=require('./routes/second');return reused;}
    app.use('/api/workshop/example',reused);`, 'server/applicationServer.js');
  assert.equal(alias[0].target,null,'ambiguous aliases may not be admitted as exact mount targets');
  assert.throws(()=>outside.inspectCtfProductionSources([
    "// app.use('/api/ctf',ctfRoutes); initializeProductionCtfAuthority(); ctfAuthorityRouter=authority.router; require('./services/ctfAuthorityProduction');",
    "// createCtfAuthorityApplication(); require('./ctfAuthorityApplication')",
    "// createCtfAuthorityRouter(); require('../routes/ctfAuthorityRouter')",
    '// router.post(\'/stage/:stageId/attempt\', handler)',
  ]),/source chain changed/);
});
