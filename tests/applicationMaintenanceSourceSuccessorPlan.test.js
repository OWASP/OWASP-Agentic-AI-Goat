'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { planSuccessor, sqlInventory, virtualAdmission, staticallyReachableMissing, directMissingFromChanged } = require('../scripts/plan-application-maintenance-source-successor');

const root = path.resolve(__dirname, '..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('source review finds extensionless JSX imports and imports inside new JSX components', () => {
  const component = 'client/src/pages/secureshop/components/MerchantMailConfirmation.jsx';
  const discovered = directMissingFromChanged(root,
    ['client/src/pages/secureshop/components/BoundRoleAssistant.jsx'], {});
  assert(discovered.includes(component), 'new rendered JSX must be visible to admission review');
  const dependencies = directMissingFromChanged(root, [component], {});
  assert(dependencies.includes('client/src/pages/secureshop/utils/merchantMailAction.mjs'));
  assert(dependencies.includes('client/src/pages/secureshop/utils/merchantMailReference.mjs'));
});

test('successor plan is read-only and keeps historical source admission immutable', () => {
  const admissionPath = path.join(root, 'server/services/applicationMaintenanceInprocessAdmission.js');
  const admissionBytes = fs.readFileSync(admissionPath);
  const activeVersions = [...admissionBytes.toString('utf8').matchAll(/applicationMaintenanceInprocessSources-v([1-9][0-9]*)\.json/g)]
    .map(match => Number(match[1]));
  assert.equal(activeVersions.length, 2);
  assert.equal(activeVersions[0], activeVersions[1]);
  const predecessorVersion = activeVersions[0];
  const nextVersion = predecessorVersion + 1;
  const priorPath = path.join(root, `server/services/applicationMaintenanceInprocessSources-v${predecessorVersion}.json`);
  const priorBytes = fs.readFileSync(priorPath);
  const plan = planSuccessor({ root });
  assert.equal(plan.predecessor, `server/services/applicationMaintenanceInprocessSources-v${predecessorVersion}.json`);
  assert.equal(plan.nextVersion, nextVersion);
  assert.equal(plan.requiresReview, true);
  assert.equal(plan.predecessorSha256, sha(priorBytes));
  assert.equal(sha(fs.readFileSync(priorPath)), sha(priorBytes));
  assert.equal(sha(fs.readFileSync(admissionPath)), sha(admissionBytes));
  assert.equal(plan.candidate.files['server/services/applicationMaintenanceInprocessAdmission.js'],
    sha(virtualAdmission(admissionBytes, predecessorVersion, nextVersion)));
  const plannedManifest = `server/services/applicationMaintenanceInprocessSources-v${nextVersion}.json`;
  const reachable = staticallyReachableMissing(root, plan.candidate.files, {
    sourceOverrides: new Map([['server/services/applicationMaintenanceInprocessAdmission.js', virtualAdmission(admissionBytes, predecessorVersion, nextVersion)]]),
    planned: new Set([plannedManifest]),
  });
  assert.equal(reachable.missing.includes('server/services/applicationMaintenanceInprocessSources-v246.json'), false);
  assert.equal(reachable.missing.includes(plannedManifest), false);
  assert.equal(reachable.unresolved.some(name => name.includes('applicationMaintenanceInprocessSources-v234.json')), false);
  assert.equal(plan.staticImportReview.missingCount, reachable.missing.length);
  assert.equal(plan.provisionalManifestSha256, sha(Buffer.from(JSON.stringify(plan.candidate))));
  assert.equal(fs.existsSync(path.join(root, 'server/services/applicationMaintenanceInprocessSources-v235.json')), true);
});

test('successor plan includes all newly added SQL and preserves exact sorted recovery inventory', () => {
  const prior = require('../server/services/applicationMaintenanceInprocessSources-v264.json');
  const inherited = require('../server/services/applicationMaintenanceInprocessSources-v263.json');
  const v264Added = Object.keys(prior.files).filter(name => !Object.hasOwn(inherited.files, name)).sort();
  assert.deepEqual(v264Added, ['client/src/pages/secureshop/components/CustomerAvatarUploadLesson.jsx',
    'client/src/pages/secureshop/hooks/useCustomerAvatarUploadLesson.js',
    'client/src/pages/secureshop/utils/customerAvatarUploadReference.mjs',
    'server/agent-runtime/mcpDescriptionRangePersistenceV6.js',
    'server/agent-runtime/mcpDescriptionRangeRelationsV6.js']);
  assert.deepEqual(prior.recoveryFiles, [...new Set([...inherited.recoveryFiles, ...v264Added])].sort());
  const older = require('../server/services/applicationMaintenanceInprocessSources-v262.json');
  const v263Sql = ['db/postgres/workshop-migrations/secureshop_agents/0102_avatar_upload_conversation_purpose.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0103_avatar_upload_registry_successor.sql'];
  const v263Added = Object.keys(inherited.files).filter(name => !Object.hasOwn(older.files, name)).sort();
  assert.equal(v263Added.length, 19);
  assert.deepEqual(v263Added.slice(0, 2), v263Sql);
  assert.deepEqual(inherited.recoveryFiles, [...new Set([...older.recoveryFiles, ...v263Added])].sort());
  const v265 = require('../server/services/applicationMaintenanceInprocessSources-v265.json');
  const added265 = Object.keys(v265.files).filter(name => !Object.hasOwn(prior.files,name)).sort();
  assert.deepEqual(added265, ['db/postgres/workshop-migrations/secureshop_agents/0104_avatar_upload_registry_guard_repair.sql']);
  assert.deepEqual(v265.recoveryFiles, [...new Set([...prior.recoveryFiles,...added265])].sort());
  const v266 = require('../server/services/applicationMaintenanceInprocessSources-v266.json');
  const added266=Object.keys(v266.files).filter(name=>!Object.hasOwn(v265.files,name)).sort();
  assert.deepEqual(added266,["client/src/pages/secureshop/utils/customerAvatarUploadAssessmentReference.mjs","server/database/postgres/secureshopV06UploadTurnReader.js","server/services/secureshopV06UploadAssessment.js","server/services/secureshopV06UploadEvidence.js","server/services/secureshopV06UploadSourceReader.js"]);
  assert.deepEqual(v266.recoveryFiles,[...new Set([...v265.recoveryFiles,...added266])].sort());
  const v267 = require('../server/services/applicationMaintenanceInprocessSources-v267.json');
  assert.deepEqual(Object.keys(v267.files),Object.keys(v266.files));
  assert.deepEqual(v267.recoveryFiles,v266.recoveryFiles);
  const v268 = require('../server/services/applicationMaintenanceInprocessSources-v268.json');
  const added268=Object.keys(v268.files).filter(name=>!Object.hasOwn(v267.files,name)).sort();
  assert.deepEqual(added268,["client/src/pages/secureshop/bridge/compiler.mjs","client/src/pages/secureshop/bridge/guestRead.mjs","client/src/pages/secureshop/bridge/handshake.mjs","client/src/pages/secureshop/bridge/seededStateStore.mjs","client/src/pages/secureshop/bridge/transport.mjs","client/src/pages/secureshop/components/UploadZone.jsx","db/postgres/workshop-migrations/secureshop_agents/0105_listing_optimize_conversation_purpose.sql","db/postgres/workshop-migrations/secureshop_agents/0106_listing_optimize_registry_successor.sql","db/postgres/workshop-migrations/secureshop_review/0054_owned_listing_image_optimize.sql","server/services/secureshopListingOptimizeEvidence.js","server/services/secureshopListingOptimizeExecutor.js","server/services/secureshopListingOptimizeJudgeGuard.js","server/services/secureshopRoleListingOptimizeSetup.js"]);
  assert.deepEqual(v268.recoveryFiles,[...new Set([...v267.recoveryFiles,...added268])].sort());
  const v269=require('../server/services/applicationMaintenanceInprocessSources-v269.json');
  assert.deepEqual(Object.keys(v269.files),Object.keys(v268.files));
  assert.deepEqual(v269.recoveryFiles,v268.recoveryFiles);
  const v270=require('../server/services/applicationMaintenanceInprocessSources-v270.json');
  const added270=Object.keys(v270.files).filter(name=>!Object.hasOwn(v269.files,name)).sort();
  assert.deepEqual(added270,['scripts/lib/setup-upload-asset-environment.js','server/middleware/applicationCors.js']);
  assert.deepEqual(v270.recoveryFiles,[...new Set([...v269.recoveryFiles,...added270])].sort());
  const admitted=require('../server/services/applicationMaintenanceInprocessSources-v304.json');
  const added275=["db/postgres/workshop-migrations/secureshop_agents/0107_file_summary_conversation_purpose.sql", "db/postgres/workshop-migrations/secureshop_agents/0108_file_summary_registry_successor.sql", "server/services/secureshopBoundFileSummaryGraph.js", "server/services/secureshopFileSummaryAttachment.js", "server/services/secureshopFileSummaryComposition.js", "server/services/secureshopFileSummaryExecutionConfig.js", "server/services/secureshopSvgAssetBrowserQualification.js", "server/services/secureshopV08SvgAssessment.js", "server/services/secureshopV08SvgEvidence.js", "server/services/secureshopV08SvgSourceReader.js"];
  added275.push(...["client/src/pages/secureshop/components/CustomerFileSummaryLesson.jsx","client/src/pages/secureshop/hooks/useCustomerFileSummaryLesson.js","client/src/pages/secureshop/utils/customerFileSummaryReference.mjs","server/database/postgres/secureshopV19FileSummaryTurnReader.js","server/routes/secureshop/boundFileSummary.js","server/services/secureshopFileSummaryApplication.js","server/services/secureshopV19FileSummaryAssessment.js","server/services/secureshopV19FileSummaryEvidence.js","server/services/secureshopV19FileSummarySavedTurn.js","server/services/secureshopV19FileSummarySourceReader.js"]);added275.push(...["client/src/pages/secureshop/components/MerchantMailHtmlAssessment.jsx","client/src/pages/secureshop/components/mailMessageClientRenderer.jsx","client/src/pages/secureshop/utils/merchantMailHtmlAssessmentReference.mjs","client/vite.mail-renderer.config.mjs","server/services/secureshopMailHtmlInjectionAssessment.js","server/services/secureshopMailHtmlInjectionEvidence.js","server/services/secureshopMailHtmlInjectionOriginalReader.js","server/services/secureshopMailboxContent.js"]);added275.push(...["client/src/pages/secureshop/components/V11MailReadAssessment.jsx","client/src/pages/secureshop/utils/merchantMailReadAssessmentReference.mjs","db/postgres/identity-migrations/0151_secureshop_files_principal_admission.sql","server/services/secureshopMailAgentReadAssessment.js","server/services/secureshopMailAgentReadEvidence.js","server/services/secureshopMailAgentReadOriginalReader.js"]);added275.push(...["server/services/secureshopAnalyticsNlSqlAssessment.js","server/services/secureshopAnalyticsNlSqlEvidence.js","server/services/secureshopAnalyticsNlSqlRetained.js"]);added275.push(...["db/postgres/identity-migrations/0152_secureshop_scene_assessment_cleanup.sql"]);added275.push(...[]);added275.push(...[]);added275.push(...[]);added275.push(...[]);added275.push(...[]);added275.push(...[]);added275.push(...["server/services/secureshopAuditSummaryTaskPrompt.js"]);added275.push(...[]);added275.push(...[]);added275.push(...[]);added275.push(...["agent-host/agents/uploads/tools/index.js","agent-host/shared/vectorStore.js","client/src/pages/secureshop/components/CustomerAvatarTraversalLesson.jsx","client/src/pages/secureshop/hooks/useCustomerAvatarTraversalLesson.js","client/src/pages/secureshop/hooks/useProductSummary.js","client/src/pages/secureshop/utils/customerAvatarTraversalReference.mjs","client/src/pages/secureshop/utils/productSummaryReference.mjs","server/database/postgres/secureshopV46TraversalRepository.js","server/routes/secureshop/boundProductSummaryAssessment.js","server/services/secureshopProductSummaryAssessment.js","server/services/secureshopProductSummaryEvidence.js","server/services/secureshopProductSummarySourceContract.js","server/services/secureshopProductSummarySourceReader.js","server/services/secureshopV46TraversalApplication.js","server/services/secureshopV46TraversalAssessment.js","server/services/secureshopV46TraversalAssetReader.js","server/services/secureshopV46TraversalDestination.js","server/services/secureshopV46TraversalEvidence.js","server/services/secureshopV46TraversalSourceReader.js","server/services/secureshopV46TraversalWriter.js"]);added275.sort();
  assert.deepEqual(Object.keys(admitted.files).filter(name=>!Object.hasOwn(v270.files,name)).sort(),added275);
  assert.deepEqual(admitted.recoveryFiles,[...new Set([...v270.recoveryFiles,...added275])].sort());
  const plan = planSuccessor({ root });
  const activePredecessor = JSON.parse(fs.readFileSync(path.join(root, plan.predecessor)));
  const expected = sqlInventory(root).filter(name => !Object.hasOwn(activePredecessor.files, name));
  assert.deepEqual(plan.addedSql, expected);
  assert.deepEqual(Object.keys(plan.candidate.files).filter(name => name.startsWith('db/postgres/') && name.endsWith('.sql')).sort(), sqlInventory(root));
  assert.deepEqual(plan.candidate.recoveryFiles, [...new Set([...activePredecessor.recoveryFiles, ...expected])].sort());
  assert(plan.changedPinned.includes('server/services/applicationMaintenanceInprocessAdmission.js'));
  assert(plan.staticImportReview.visited > 0);
  assert(plan.directMissingFromChanged.every(name => !Object.hasOwn(plan.candidate.files, name)));
});

test('virtual pointer requires two exact references and does not modify source bytes', () => {
  const original = Buffer.from("require('./applicationMaintenanceInprocessSources-v87.json');require('./applicationMaintenanceInprocessSources-v87.json');");
  const changed = virtualAdmission(original, 87, 88);
  assert.equal(changed.toString('utf8').includes('Sources-v87.json'), false);
  assert.equal(original.toString('utf8').includes('Sources-v87.json'), true);
  assert.throws(() => virtualAdmission(Buffer.from("require('./applicationMaintenanceInprocessSources-v87.json')"), 87, 88), /two active admission references/);
});
