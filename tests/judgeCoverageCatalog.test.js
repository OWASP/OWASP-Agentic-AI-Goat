'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const load = Module._load;
Module._load = function (name, parent, main) {
  if (/(?:^|\/)authDb(?:\.js)?$/.test(name)) throw Error('Coverage inspection must not initialize user databases');
  return load.call(this, name, parent, main);
};
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
const { getObjectiveRubric } = require('../server/config/objectiveRubrics');
const { rubricSchema } = require('../server/agent-runtime/objectiveJudge');
const secureShopCurriculum = require('../server/config/secureshopCurriculum');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');

test('canonical objectives have exact qualified adapter coverage or explicit pending readiness', () => {
  // Read rubric exports consumed by the actual assessment paths, not catalog IDs.
  const listings = require('../server/services/secureshopListingsAssessment');
  const addedRubrics = [
    require('../server/services/secureshopInventoryAssessment').INVENTORY_RUBRIC,
    ...Object.values(listings.LISTINGS_IMPORT_RUBRICS), listings.GENERATED_BROWSER_RUBRIC,
    require('../server/services/secureshopMailHeaderEvidence').MAIL_HEADER_RUBRIC,
    require('../server/services/secureshopMailReplyAssessment').MAIL_REPLY_RUBRIC,
    require('../server/services/secureshopMailDisclosureEvidence').MAIL_DISCLOSURE_RUBRIC,
    require('../server/services/secureshopMailBrowserEvidence').MAIL_BROWSER_RUBRIC,
  ];
  assert.equal(addedRubrics.length, 9);
  const establishedSecureShopRubrics = [
    require('../server/services/secureshopListingRawBrowserAssessment').RAW_LISTING_BROWSER_RUBRIC,
    require('../server/services/secureshopListingTemplateAssessment').RUBRIC,
    require('../server/services/secureshopMcpImpersonationEvidence').RUBRIC,
    require('../server/services/secureshopPolicyInstructionEvidence').RUBRIC,
    require('../server/services/secureshopPolicyTemplateEvidence').RUBRIC,
    require('../server/services/secureshopSystemConfigEvidence').RUBRIC,
    require('../server/services/secureshopCouponAgentEvidence').RUBRIC,
  ];
  assert.equal(establishedSecureShopRubrics.length, 7);
  for (const rubric of [...addedRubrics, ...establishedSecureShopRubrics]) {
    rubricSchema.parse({...rubric, mode:'vuln'});
    assert.equal(rubric.family, 'SecureShop');
    assert.ok(rubric.requiredFacts.length > 0);
  }
  // Explicit current production adapters; never infer coverage from catalog membership.
  const currentSecureShopRubrics = [
    require('../server/services/secureshopAuditUnboundedEvidence').auditUnboundedRubric(),
    require('../server/services/secureshopV01AuditEvidence').V01_AUDIT_RUBRIC,
    require('../server/services/secureshopAgencyRoleEvidence').RUBRIC,
    require('../server/services/secureshopV44FilePathTraversalEvidence').FILE_PATH_RUBRIC,
    listings.LISTINGS_OPTIMIZE_RUBRIC,
    require('../server/services/secureshopMailAgentReadEvidence').RUBRIC,
    require('../server/services/secureshopMailHtmlInjectionEvidence').MAIL_HTML_INJECTION_RUBRIC,
    require('../server/services/secureshopMailInlineEvidence').RUBRIC,
    require('../server/services/secureshopMcpManifestEvidence').RUBRIC,
    require('../server/services/secureshopMcpRegistrySsrfEvidence').RUBRIC,
    require('../server/services/secureshopSearchEchoBrowserEvidence').RUBRIC,
    require('../server/services/secureshopCouponBlindEvidence').RUBRIC,
    require('../server/services/secureshopOrderStatusErrorEvidence').RUBRIC,
    require('../server/services/secureshopAnalyticsNlSqlEvidence').RUBRIC,
    require('../server/services/secureshopProductUnionEvidence').RUBRIC,
    require('../server/services/secureshopSystemCredentialEvidence').RUBRIC,
    require('../server/services/secureshopSystemDiagnosticEvidence').RUBRIC,
    require('../server/services/secureshopSystemRestartInjectionEvidence').RUBRIC,
    require('../server/services/secureshopTicketBrowserEvidence').RUBRIC,
    require('../server/services/secureshopV06UploadEvidence').UPLOAD_RUBRIC,
    require('../server/services/secureshopV46TraversalEvidence').TRAVERSAL_RUBRIC,
    require('../server/services/secureshopV07UploadEvidence').RUBRIC,
    require('../server/services/secureshopV08SvgEvidence').RUBRIC,
  ];
  assert.equal(currentSecureShopRubrics.length,23);
  for(const rubric of currentSecureShopRubrics){
    rubricSchema.parse({...rubric,mode:'vuln'});
    assert.equal(rubric.family,'SecureShop');assert.ok(rubric.requiredFacts.length>0);
  }
  const idor=require('../server/services/secureshopIdorLessonEvidence');
  const pendingOrder=idor.idorLessonRubric('order_status',idor.IDOR_LESSON_ORDER_VERSION);
  rubricSchema.parse({...pendingOrder,mode:'vuln'});
  assert.equal(pendingOrder.objectiveId,'ss_idor_order_status_disclosure');
  assert.equal(secureShopCurriculum.isQualifiedObjective(pendingOrder.objectiveId),false);
  assert.equal(secureShopCurriculum.isAssessmentReleaseAllowed(pendingOrder.objectiveId),false);
  const builderGrader = require('../server/services/xssEmailObjectiveGrader');
  const builderIds = Object.keys(builderGrader.LEVELS).map(level => {
    const rubric = builderGrader.rubricFor(Number(level));
    rubricSchema.parse(rubric);
    assert.equal(rubric.family, 'xss_email_builder');
    assert.equal(rubric.objectiveId, `level_${level}`);
    assert.ok(rubric.requiredFacts.length > 0);
    return require('../server/config/xssEmailBuilderCurriculum').objectiveId(Number(level));
  });
  assert.equal(builderIds.length, 4);
  const competitorRubric = require('../server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_competitor_disclosure;
  rubricSchema.parse({...competitorRubric, mode:'vuln'});
  const definitions = {
    xss_email_builder: builderIds,
    legacy_sensitive_file_ssi: [...require('../server/services/legacySensitiveObjectiveGrader').OBJECTIVES],
    direct_prompt_injection: Object.values(require('../server/services/promptInjectionWorkshop').OBJECTIVE_IDS),
    indirect_prompt_injection: Object.keys(require('../server/agent-runtime/indirectObjectiveJudge').RUBRICS),
    excessive_agency: Object.keys(require('../server/agent-runtime/excessiveAgencyJudge').DESCRIPTIONS).map(id => `objective_${id}`),
    sensitive_info_disclosure: Object.keys(require('../server/services/sensitiveInfoWorkshopAgent').FINFLOW_RUBRICS),
    supply_chain_rce: Object.keys(require('../server/agent-runtime/codeBotJudge').CRITERIA),
    csrf_workshop: Object.keys(require('../server/services/csrfObjectiveGrader').CRITERIA),
    secureshop_agent_security: [
      ...addedRubrics.map(rubric => rubric.objectiveId),
      ...currentSecureShopRubrics.map(rubric=>rubric.objectiveId),
      require('../server/services/secureshopOwnedAuditTimingAssessment').OBJECTIVE,
      ...establishedSecureShopRubrics.map(rubric => rubric.objectiveId),
      require('../server/services/secureshopAnalyticsDisclosureAssessment').OBJECTIVE,
      competitorRubric.objectiveId,
      require('../server/services/secureshopLoopAssessment').OBJECTIVE,
      require('../server/services/secureshopOwnedAuditAssessment').OBJECTIVE,
      require('../server/services/secureshopAuditJudgePacket').auditInstructionRubric().objectiveId,
      ...Object.values(require('../server/services/secureshopReviewContentAssessment').OBJECTIVES),
      ...(releasePhase().generated
        ? Object.values(require('../server/services/secureshopPersonaInboxAssessment').OBJECTIVES) : []),
      ...Object.keys(require('../server/services/secureshopMcpTrustAssessment').MCP_TRUST_RUBRICS),
      require('../server/services/secureshopStoredBrowserAssessment').OBJECTIVE,
      require('../server/services/secureshopSsrfAssessment').SECURESHOP_SSRF_RUBRIC.objectiveId,
      idor.IDOR_LESSON_OBJECTIVES.cart_remove,
    ],
  };
  const nativeFamilies = { ARIA: 'sql_injection_workshop', NOVA: 'nosql_injection_workshop', MCP: 'mcp_workshop', XSS: 'xss_workshop' };
  for (const rubric of require('../server/config/objectiveRubrics').listObjectiveRubrics()) {
    rubricSchema.parse(rubric);
    const key = nativeFamilies[rubric.family];
    assert.ok(key, `Unmapped grading family ${rubric.family}`);
    (definitions[key] ||= []).push(rubric.objectiveId);
    assert.equal(getObjectiveRubric(key, rubric.objectiveId, 'vuln'), rubric);
  }
  assert.deepEqual(Object.keys(definitions).sort(), Object.keys(WORKSHOP_OBJECTIVES).sort());
  let count = 0;
  for (const [key, objectives] of Object.entries(WORKSHOP_OBJECTIVES)) {
    const expected = key === secureShopCurriculum.WORKSHOP_KEY
      ? secureShopCurriculum.QUALIFIED_OBJECTIVE_IDS
      : objectives.map(o => o.id);
    assert.deepEqual(definitions[key].sort(), [...expected].sort(), `${key}: rubric/catalog drift`);
    assert.equal(new Set(definitions[key]).size, definitions[key].length, `${key}: duplicate rubric`);
    count += objectives.length;
  }
  assert.equal(Object.keys(definitions).length, 13);
  assert.equal(count, 179, 'Catalog changes require explicit judge qualification updates');
  assert.deepEqual(secureShopCurriculum.PENDING_OBJECTIVE_IDS,
    WORKSHOP_OBJECTIVES.secureshop_agent_security.filter(row => row.qualification === 'pending').map(row => row.id));
  assert.deepEqual(secureShopCurriculum.PENDING_OBJECTIVE_IDS, [
    'ss_file_upload_instruction_adoption','ss_pricing_false_grounding','ss_pricing_manual_injection',
    'ss_manual_rag_instruction_adoption','ss_product_description_instruction_adoption',
    'ss_idor_order_status_disclosure','ss_mcp_description_instruction_adoption',
    'ss_policy_final_html_execution','ss_user_lookup_sensitive_disclosure',
  ]);
  assert.ok(WORKSHOP_OBJECTIVES.secureshop_agent_security.every(row => row.defaultEnabled === false));
});
