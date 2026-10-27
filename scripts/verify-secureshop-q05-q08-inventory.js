'use strict';

// A source inventory, not a release qualification. In particular, finding a
// tool, route, or annotation never substitutes for an original actor decision,
// durable effect, independent Judge decision, or a vulnerable/fixed comparison.
const fs = require('node:fs');
const path = require('node:path');
const {inventory: nonSecureShopInventory} = require('./lib/q05q08NonSecureShopInventory');
const {loadAndValidate: ctfAdminPartition} = require('./lib/ctfSupportedAdminActionManifest');
const {loadAndValidate: ctfParticipantPartition} = require('./lib/ctfSupportedParticipantActionManifest');

const root = path.resolve(__dirname, '..');
const SOURCE_STATUS = 'source_discovered_runtime_unverified';
const REQUIRED_RECEIPT_FIELDS = Object.freeze([
  'advertisedAction', 'originalUserRequest', 'actorProvider', 'actorModel',
  'actorDecisionId', 'selectedTool', 'validatedArguments', 'boundOwner',
  'boundSession', 'resetGeneration', 'effectiveMode', 'toolInvocationId',
  'observedEffect', 'effectReadback', 'judgeProvider', 'judgeModel',
  'judgeDecisionId', 'canonicalCreditDecision',
]);

function files(directory, accept) {
  const base = path.join(root, directory);
  const result = [];
  function visit(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'build' || entry.name === 'dist') continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (accept(full)) result.push(full);
    }
  }
  visit(base);
  return result.sort();
}

function at(file, source, offset, value) {
  const line = source.slice(0, offset).split('\n').length;
  return Object.freeze({ file: path.relative(root, file).split(path.sep).join('/'), line, value, status: SOURCE_STATUS });
}

function scan(file, expression, capture = 0) {
  const source = fs.readFileSync(file, 'utf8');
  return [...source.matchAll(expression)].map(match => at(file, source, match.index, match[capture]));
}

function inventory() {
  const roleFile = path.join(root, 'server/services/secureshopBoundRoleChat.js');
  const roleSource = fs.readFileSync(roleFile, 'utf8');
  const descriptors = roleSource.slice(roleSource.indexOf('const tools=Object.freeze({'), roleSource.indexOf('\nconst exact='));
  if (!descriptors.startsWith('const tools=Object.freeze({') || !descriptors.includes('admin:Object.freeze([')) {
    throw new Error('RoleChat descriptor boundary changed; inspect inventory parser');
  }
  const roleTools = [...descriptors.matchAll(/\{agent:'(merchant|admin)',tool:'([^']+)'/g)]
    .map(match => at(roleFile, roleSource, roleSource.indexOf(descriptors) + match.index, `${match[1]}.${match[2]}`));

  const agentFiles = files('agent-host/agents', file => /\/server\.js$/.test(file) && !file.includes('/_template/'));
  const mcpTools = agentFiles.flatMap(file => {
    const source = fs.readFileSync(file, 'utf8');
    const start = source.indexOf('const TOOLS = [');
    const end = start < 0 ? -1 : source.indexOf('\n];', start);
    if (start < 0 || end < 0) throw new Error(`MCP TOOLS block changed: ${file}`);
    const block = source.slice(start, end);
    const agent = path.basename(path.dirname(file));
    return [...block.matchAll(/\bname:\s*['"]([^'"]+)['"]/g)]
      .map(match => at(file, source, start + match.index, `${agent}.${match[1]}`));
  });

  const routeFiles = files('server/routes/secureshop', file => file.endsWith('.js'));
  const routeMutations = routeFiles.flatMap(file => scan(file,
    /\brouter\.(post|put|patch|delete)\s*\(\s*([^,\n]+)/g, 0));
  // Several production routers register a verb selected from a finite loop.
  // Keep those callsites visible; their expanded paths need runtime review.
  const dynamicRouteRegistrations = routeFiles.flatMap(file => scan(file,
    /\brouter\[(?:method|verb)\]\s*\(/g, 0));
  const confirmTerminals = routeFiles.flatMap(file => scan(file,
    /\brouter\.(post|put|patch|delete)\s*\(\s*([^,\n]*\/confirm(?:\b|\$|`|['"]))/g, 0));

  const clientFiles = files('client/src/pages/secureshop', file => /\.(?:js|jsx|mjs)$/.test(file)
    && !/\.test\.|\/bridge\/|\/__tests__\//.test(file));
  const clientFetches = clientFiles.flatMap(file => scan(file, /\b(?:fetch|secureShopFetch)\s*\(\s*([^,\n]+)/g, 0));

  // Supported authority is largely in top-level services, not only the older
  // services/secureshop subtree. File discovery deliberately does not infer
  // that every exported handler is mounted or used by a supported lesson.
  const authorityFiles = files('server/services', file => file.endsWith('.js')
    && path.dirname(file) === path.join(root, 'server/services')
    && path.basename(file).startsWith('secureshop'));
  const authorityModules = authorityFiles.map(file => at(file, '', 0, path.basename(file)));
  const confirmationBindings = authorityFiles.flatMap(file => scan(file,
    /\b(confirm[A-Z][A-Za-z0-9_]*|confirm)\s*(?:\(|:)/g, 1));
  const bridgeFiles = files('client/src/pages/secureshop/bridge', file => /\.(?:js|jsx|mjs)$/.test(file)
    && !/\.test\.|\/__tests__\//.test(file));
  const bridgeModules = bridgeFiles.map(file => at(file, '', 0, path.basename(file)));
  const bridgeFetches = bridgeFiles.flatMap(file => scan(file,
    /\b(?:fetch|secureShopFetch)\s*\(\s*([^,\n]+)/g, 0));

  // These are concrete inline composition callsites, not claims inferred from
  // module comments. Conditional/transitive mounting still requires resolution.
  // Other forms (imported identifiers, aliases, computed paths) stay unresolved.
  const compositionMountReferences = authorityFiles.flatMap(file => {
    const source = fs.readFileSync(file, 'utf8');
    return [...source.matchAll(/\brouter\.use\s*\(\s*require\(\s*['"](\.\.\/routes\/secureshop\/[^'"]+)['"]\s*\)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g)]
      .map(match => {
        const target = path.resolve(path.dirname(file), `${match[1]}.js`);
        if (!fs.statSync(target).isFile()) throw new Error('Missing inline composition route target');
        return Object.freeze({ ...at(file, source, match.index, `${match[1]}.${match[2]}`),
          target: path.relative(root, target).split(path.sep).join('/'), factory: match[2],
          referenceKind: 'inline_router_use_factory_callsite',
          runtimeReachability: 'conditional_transitive_mount_unverified' });
      });
  });

  // Pure catalog modules supply the current canonical IDs, including generated
  // IDs and family curriculum imports. CTF has a separate progression catalog.
  // Catalog membership is not a complete advertised-action denominator: manual
  // actions, ungraded teaching surfaces and runtime configuration also matter.
  const catalogFile = path.join(root, 'server/config/workshopCatalog.js');
  const catalogSource = fs.readFileSync(catalogFile, 'utf8');
  const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
  const catalogObjectives = Object.entries(WORKSHOP_OBJECTIVES).flatMap(([family, objectives]) => {
    const offset = catalogSource.indexOf(`  ${family}:`);
    if (offset < 0) throw new Error(`Catalog family source location unavailable: ${family}`);
    return objectives.map(objective => Object.freeze({
      ...at(catalogFile, catalogSource, offset, `${family}.${objective.id}`),
      family, objectiveId: objective.id, applicability: 'unresolved' }));
  });
  const ctfFile = path.join(root, 'server/data/ctfDefaults.js');
  const ctfStages = scan(ctfFile, /\bstage_number:\s*([0-9]+)\s*,/g, 1)
    .map(row => Object.freeze({ ...row, value: `ctf.stage_${row.value}`,
      family: 'ctf', stageNumber: Number(row.value), applicability: 'unresolved' }));

  const sinkFiles = [
    ...files('server/routes/secureshop', file => file.endsWith('.js')),
    ...files('server/services/secureshop', file => file.endsWith('.js')),
    ...files('agent-host/agents', file => file.endsWith('.js') && !file.includes('/_template/')),
    ...authorityFiles,
  ];
  const exceptions = sinkFiles.flatMap(file => scan(file,
    /@intentional-vulnerability\s+([a-zA-Z0-9_-]+)/g, 1));
  const nonSecureShop = nonSecureShopInventory(root);

  return Object.freeze({
    schemaVersion: 5,
    qualification: Object.freeze({ Q05: 'deferred_unverified', Q08: 'deferred_unverified' }),
    scope: Object.freeze({ denominatorComplete: false,
      catalogDiscovery: 'all_canonical_workshop_families_and_separate_ctf_stages',
      actionDiscovery: 'secureshop_and_nonsecureshop_static_source_callsite_discovery_not_a_supported_action_manifest',
      unresolved: Object.freeze([
        'Original acceptance scope must be reconciled; the SecureShop script name does not exclude other supported lessons.',
        'Non-SecureShop and CTF application/React mounts, route callsites and UI requests/events are discovered, but nested imports, dynamic requests and exact support/confirmation/effect joins remain unresolved.',
        'Resolve aliases, conditional/transitive mounts, runtime availability and manual/read-only/ungraded applicability per action.',
        'Catalog rows are not all advertised actions; source callsites are not necessarily reachable supported actions.',
      ]) }),
    requiredReceiptFields: REQUIRED_RECEIPT_FIELDS,
    surfaces: Object.freeze({ roleTools, mcpTools, routeMutations, dynamicRouteRegistrations,
      confirmTerminals, clientFetches, intentionalExceptions: exceptions,
      authorityModules, confirmationBindings, bridgeModules, bridgeFetches,
      compositionMountReferences, catalogObjectives, ctfStages }),
    nonSecureShop,
    reviewedPartitions: Object.freeze({ ctfAdmin: ctfAdminPartition({root}),
      ctfParticipant: ctfParticipantPartition({root}) }),
    limitations: Object.freeze([
      'Source discovery includes direct panels, bound RoleChat and task-agent MCP descriptors, but cannot establish reachability or consequence completeness.',
      'Route and fetch callsites require human resolution of dynamic paths, methods, aliases, and intentional exceptions. Dynamic router verb registrations are listed separately.',
      'No source-discovered row is original actor, tool, effect or Judge provenance; no objective credit follows from this inventory.',
      'Inline composition references locate real router.use factory callsites but do not prove conditional/transitive runtime mounting; comments are not mounting authority.',
      'Non-SecureShop AST rows locate concrete application/React mounts, route registrations and UI request/event callsites, but nested modules and conditional production readiness remain unresolved.',
      'Only a unique literal method/path match and a same-component handler directly calling that exact request form a candidate join; even that does not prove a rendered action, effect or supported denominator.',
    ]),
  });
}

function verify(value = inventory()) {
  const surfaces = value.surfaces;
  const outside = value.nonSecureShop;
  const required = ['roleTools', 'mcpTools', 'routeMutations', 'dynamicRouteRegistrations',
    'confirmTerminals', 'clientFetches', 'intentionalExceptions', 'authorityModules',
    'confirmationBindings', 'bridgeModules', 'bridgeFetches', 'compositionMountReferences',
    'catalogObjectives', 'ctfStages'];
  if (value.scope?.denominatorComplete !== false)
    throw new Error('Discovery cannot establish a complete supported-action denominator');
  if (JSON.stringify(value.reviewedPartitions?.ctfAdmin) !== JSON.stringify(ctfAdminPartition({root})))
    throw new Error('CTF administrator partition differs from its source-validated manifest');
  if (JSON.stringify(value.reviewedPartitions?.ctfParticipant) !== JSON.stringify(ctfParticipantPartition({root})))
    throw new Error('CTF participant partition differs from its source-validated manifest');
  for (const key of required) {
    // Typed bridges may dispatch operations without making literal fetch calls.
    // An empty fetch search is honest; bridge module discovery remains required.
    if (!Array.isArray(surfaces[key]) || (key !== 'bridgeFetches' && surfaces[key].length === 0))
      throw new Error(`Empty Q05/Q08 source surface: ${key}`);
    for (const item of surfaces[key]) {
      if (item.status !== SOURCE_STATUS || !item.file || !Number.isInteger(item.line) || item.line < 1 || !item.value)
        throw new Error(`Unlocated or promoted source row in ${key}`);
    }
  }
  if (new Set(surfaces.roleTools.map(row => row.value)).size !== surfaces.roleTools.length)
    throw new Error('Duplicate bound RoleChat tool descriptor');
  if (new Set(surfaces.mcpTools.map(row => row.value)).size !== surfaces.mcpTools.length)
    throw new Error('Duplicate MCP tool descriptor');
  if (!surfaces.confirmTerminals.some(row => row.value.includes('/mail/confirm'))
    || !surfaces.confirmTerminals.some(row => row.value.includes('/policies/confirm')))
    throw new Error('Known confirmation terminal missing from Q05 discovery');
  if (!surfaces.clientFetches.some(row => row.file.endsWith('/merchant/Listings.jsx'))
    || !surfaces.clientFetches.some(row => row.file.endsWith('/Account.jsx')))
    throw new Error('Direct merchant/account panel missing from Q08 discovery');
  if (!surfaces.mcpTools.some(row => row.value === 'inventory.set_stock'))
    throw new Error('Known consequence-producing MCP tool missing from Q08 discovery');
  for (const key of ['catalogObjectives', 'ctfStages']) {
    if (new Set(surfaces[key].map(row => row.value)).size !== surfaces[key].length)
      throw new Error(`Duplicate canonical discovery identity: ${key}`);
  }
  if (!surfaces.compositionMountReferences.some(row => row.target ===
      'server/routes/secureshop/boundCouponAgentConfirm.js'
      && row.factory === 'createBoundCouponAgentConfirmRouter'))
    throw new Error('Known coupon composition mount reference missing');
  const outsideRequired=['applicationMounts','reactRoutes','routeRegistrations','nestedRoutes',
    'computedRouteRegistrations',
    'uiRequests','uiEvents','uiEventRequestLinks','uiRequestRelations','deferredProductionChains'];
  for(const key of outsideRequired){
    if(!Array.isArray(outside?.[key])||(key!=='computedRouteRegistrations'&&outside[key].length===0))
      throw new Error(`Empty non-SecureShop source surface: ${key}`);
    if(outside[key].some(row=>row.status!==SOURCE_STATUS||!row.file
      ||!Number.isInteger(row.line)||row.line<1||!row.value))
      throw new Error(`Unlocated or promoted non-SecureShop source row: ${key}`);
  }
  if(!outside.applicationMounts.some(row=>row.base==='/api/workshop/sql'
    && row.target==='server/routes/sqlWorkshop.js'))
    throw new Error('Canonical SQL app mount missing');
  if(!outside.reactRoutes.some(row=>row.route==='/ctf/challenge'
    && row.modules.includes('./pages/CTFChallenge')))
    throw new Error('CTF React mount missing');
  if(!outside.deferredProductionChains.some(row=>row.files.includes('server/routes/ctfAuthorityRouter.js')))
    throw new Error('Supported CTF production router chain missing');
  return Object.freeze({...Object.fromEntries(required.map(key => [key, surfaces[key].length])),
    'reviewedPartitions.ctfAdmin.actions': value.reviewedPartitions.ctfAdmin.actions.length,
    'reviewedPartitions.ctfParticipant.actions': value.reviewedPartitions.ctfParticipant.actions.length,
    ...Object.fromEntries(outsideRequired.map(key=>[`nonSecureShop.${key}`,outside[key].length]))});
}

if (require.main === module) {
  try {
    const value = inventory();
    const counts = verify(value);
    if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
    else process.stdout.write(`${JSON.stringify({ qualification: value.qualification, scope: value.scope, counts,
      missingRuntimeQualification: value.requiredReceiptFields, limitations: value.limitations }, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Q05/Q08 inventory failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = Object.freeze({ inventory, verify, REQUIRED_RECEIPT_FIELDS });
