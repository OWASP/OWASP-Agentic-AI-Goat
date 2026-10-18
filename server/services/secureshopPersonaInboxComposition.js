'use strict';
const {createBoundToolPolicyAdmission}=require('./secureshopBoundToolPolicyAdmission');
const {resolveObjectiveGradingDependencies}=require('./objectiveGradingCore');

const { createSecureShopPersonaInboxRepository } = require('../database/postgres/secureshopPersonaInboxRepository');
const { createObjectiveJudgmentRepository } = require('../database/postgres/objectiveJudgmentRepository');
const { createWorkshopProgressRepository } = require('../database/postgres/workshopProgressRepository');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createSecureShopPersonaInboxTools } = require('./secureshopPersonaInboxTools');
const { captureFeatureMode, guardFeatureFence, featureModeForFence } = require('./secureshopFeatureModeAuthority');
const { createSecureShopPersonaInboxExecutionConfig } = require('./secureshopPersonaInboxExecutionConfig');
const { createSecureShopPersonaInboxAssessment, OBJECTIVES } = require('./secureshopPersonaInboxAssessment');
const { createSecureShopPersonaInboxPriorAdvisoryReader } = require('./secureshopPersonaInboxPriorAdvisoryReader');
const { createSecureShopModelQualifier } = require('./secureshopModelQualification');
const { createSecureShopPersonaInboxApplication } = require('./secureshopPersonaInboxApplication');
const { createSecureShopPersonaInboxRequestAuthority } = require('./secureshopPersonaInboxRequestAuthority');
const { createSecureShopPersonaInboxFinalResponseGate } = require('./secureshopPersonaInboxFinalResponseGate');
const { createBoundPersonaInboxRouter } = require('../routes/secureshop/boundPersonaInbox');
const { createSecureShopPersonaInboxAvailability } = require('./secureshopPersonaInboxAvailability');
const { createLaunchScope } = require('./secureshopConversationBinding');

const FIXTURES = Object.freeze([
  Object.freeze({ fixtureKey: 'customer-note', ownerRole: 'customer',
    subject: 'Delivery preference', body: 'Please leave the package with the front desk after 4 PM.' }),
  Object.freeze({ fixtureKey: 'merchant-note', ownerRole: 'merchant',
    subject: 'Inventory handoff', body: 'The blue headphone shipment is assigned to aisle C for tomorrow.' }),
  Object.freeze({ fixtureKey: 'admin-note', ownerRole: 'admin',
    subject: 'Support rotation', body: 'The weekend support rotation begins Saturday at 09:00.' }),
]);
function unavailable(message = 'SecureShop persona inbox runtime is unavailable') {
  return Object.assign(new Error(message), { code: 'SECURESHOP_PERSONA_INBOX_UNAVAILABLE' });
}
function key(value) { return `${value.targetId}:${value.launchId}:${value.scenarioId}:${value.generation}:${value.platformOwnerId}:${value.platformSessionId}:${value.expectedVersion}:${value.mode}`; }
function mapPersonaInboxFixtures(personas, fixtures = FIXTURES) {
  if (!Array.isArray(personas) || personas.length !== 3 || !Array.isArray(fixtures) || fixtures.length !== 3) {
    throw unavailable('Persona templates are unavailable');
  }
  return Object.freeze(fixtures.map(row => {
    const owner = personas.find(persona => persona.role === row.ownerRole);
    if (!owner || !Number.isSafeInteger(owner.id) || owner.id < 1) throw unavailable('Persona templates are unavailable');
    return Object.freeze({ fixtureKey: row.fixtureKey, owner: Object.freeze({ id: owner.id, role: owner.role }),
      subject: row.subject, body: row.body });
  }));
}

function createSecureShopPersonaInboxRepositoryBundle({ agentsPool, launches, cleanupAuthority, auditStore, mailCleanup } = {}) {
  if (typeof agentsPool?.query !== 'function' || typeof agentsPool?.connect !== 'function'
      || typeof launches?.assertCurrent !== 'function' || typeof cleanupAuthority?.checkTarget !== 'function') {
    throw unavailable();
  }
  const authorized = new Map();
  const baseRepository = createSecureShopPersonaInboxRepository(agentsPool, {
    auditStore,
    checkCurrent: value => launches.assertCurrent(require('./secureshopMailSceneBinding').current(value)),
    async checkAclTransition(value) {
      if (!authorized.has(key(value))) throw Object.assign(new Error('Persona inbox ACL transition unavailable'), {
        code: 'ACL_TRANSITION_UNAVAILABLE',
      });
    },
    checkCleanup: input => cleanupAuthority.checkTarget({ ...input, targetKind: 'persona_inbox',
      fromGeneration: input.generation }),
  });
  const { withMailCleanup, createDurableMailCleanupVerifier } = require('./secureshopMailCleanup');
  const repository = withMailCleanup(baseRepository, createDurableMailCleanupVerifier(agentsPool, mailCleanup));
  return Object.freeze({ repository, async authorizeAclTransition(value) {
    const grant = key(value); authorized.set(grant, (authorized.get(grant) || 0) + 1);
    let revoked = false;
    return () => { if (revoked) return; revoked = true; const count = authorized.get(grant) || 0;
      if (count <= 1) authorized.delete(grant); else authorized.set(grant, count - 1); };
  } });
}

function createSecureShopPersonaInboxComposition({ enabled = false, identityPool, provider, judge,
  authenticatePersona, personaRepository, resetComposition, personaAuthority, modeAuthority, personaBindings, gradingCore, toolPolicyRepository,promptPolicyRepository,mailScenes,
  fixtures = FIXTURES } = {}) {
  const grading=gradingCore===undefined?undefined:resolveObjectiveGradingDependencies(gradingCore,{identityPool,...(Object.hasOwn(arguments[0]||{},'personaBindings')?{personaBindings}:{})});
  if(grading)personaBindings=grading.personaBindings;
  if (typeof enabled !== 'boolean') throw unavailable('Persona inbox readiness must be boolean');
  if (!enabled) return Object.freeze({ ready: false });
  const promptPolicyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority);
  if(toolPolicyRepository!==undefined&&(typeof toolPolicyRepository?.admitTool!=='function'||typeof personaAuthority?.capture!=='function'))throw unavailable();
  const bundle = resetComposition?.personaInbox;
  const launches = resetComposition?.launches;
  const conversations = resetComposition?.conversationService;
  const turns = resetComposition?.turns;
  if (!bundle || typeof bundle.repository?.readAccessEvent !== 'function'
      || typeof bundle.authorizeAclTransition !== 'function'
      || typeof launches?.assertCurrent !== 'function'
      || typeof launches?.reservePersonaInboxTarget !== 'function'
      || typeof conversations?.create !== 'function' || typeof turns?.run !== 'function'
      || typeof resetComposition?.journal?.claim !== 'function'
      || typeof resetComposition?.conversations?.appendTraces !== 'function'
      || typeof provider?.chat !== 'function' || typeof authenticatePersona !== 'function'
      || typeof personaRepository?.listPersonas !== 'function'
      || typeof identityPool?.query !== 'function') throw unavailable();
  if (!Array.isArray(fixtures) || fixtures.length !== 3) throw unavailable();
  const personaBound=personaBindings!==undefined;
  if(personaBound&&(!personaAuthority||typeof personaAuthority.capture!=='function'))throw unavailable();
  const resolveFixtures = async () => {
    const personas = await personaRepository.listPersonas();
    return mapPersonaInboxFixtures(personas, fixtures);
  };
  const receipts = grading?.receipts || createObjectiveJudgmentRepository(identityPool,personaBound?{personaBindings}:{});
  const progress = grading?.progress || createWorkshopProgressRepository(identityPool);
  const availability = createSecureShopPersonaInboxAvailability(identityPool);
  const qualifyModel = createSecureShopModelQualifier(provider);
  let application;
  const resolveTarget = binding => mailScenes ? mailScenes.readExisting(createLaunchScope(binding)) : application.resolveTarget(binding);
  const resolveAssessmentTarget=async(binding,targetId)=>{
    const scope=createLaunchScope(binding);
    if(typeof targetId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(targetId))throw unavailable();
    await launches.assertCurrent(scope);
    if(mailScenes){const target=await mailScenes.readExisting(scope);if(target.targetId!==targetId.toLowerCase())throw unavailable();return target;}
    return Object.freeze({...scope,targetId:targetId.toLowerCase()});
  };
  const prior = createSecureShopPersonaInboxPriorAdvisoryReader({ pool: identityPool,
    checkCurrent: value => launches.assertCurrent(value) });
  const assessment = createSecureShopPersonaInboxAssessment({ receipts, progress, qualifyModel,
    resolveTarget:resolveAssessmentTarget, readAccessEvent: async (binding, eventId, targetId) => {
      const target = await resolveAssessmentTarget(binding,targetId);
      return bundle.repository.readAccessEvent(target,eventId);
    }, readPriorAdvisoryReceipt: prior, ...(judge ? { judge } : {}),
    ...(personaBound?{personaBindings}:{}) });
  const config = createSecureShopPersonaInboxExecutionConfig();
  const toolPolicyAdmission=toolPolicyRepository===undefined?undefined:createBoundToolPolicyAdmission({repository:toolPolicyRepository,workflow:'inbox',declaredTools:config.manifest.getForRole('customer')});
  const requestAuthority = createSecureShopPersonaInboxRequestAuthority();
  const assessmentFactory = (context,personaFence) => {
    const allowed = requestAuthority.resolve(context.localToolAuthority, context);
    const input=Object.freeze({ ...context,requestedMessageId:allowed.messageId,requestedTargetId:allowed.targetId });
    return personaBound?assessment.assessmentFactory(input,personaFence):assessment.assessmentFactory(input);
  };
  const enterFinalResponseAfterLocalTool = createSecureShopPersonaInboxFinalResponseGate({
    requestAuthority, resolveTarget,
    readAccessEvent: (target, eventId) => bundle.repository.readAccessEvent(target, eventId),
    checkCurrent: value => launches.assertCurrent(require('./secureshopMailSceneBinding').current(value)),
  });
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw unavailable();
  const capturePersonaAuthority=personaAuthority?async({binding,personaSession})=>{
    const mode = await captureFeatureMode(modeAuthority,binding,'persona_inbox','vuln');
    const fence = await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    return guardFeatureFence(fence,mode);
  }:undefined;
  const runner = createBoundAgentRunner({ turns, conversations,...promptPolicyOptions,
    ...(toolPolicyAdmission?{toolPolicyAdmission}:{}),
    ...(capturePersonaAuthority?{capturePersonaAuthority,personaLocalToolModes:{'persona-inbox.list_messages':'remote_admission','persona-inbox.read_message':'remote_admission'}}:{}),
    repository: resetComposition.conversations, journal: resetComposition.journal,
    provider, manifest: config.manifest, buildBasePrompt: config.buildBasePrompt,
    buildPolicyBlock: config.buildPolicyBlock, checkToolAcl: config.checkToolAcl,
    assessmentFactory, enterFinalResponseAfterLocalTool, limits: { maxSteps: 8, maxParallelTools: 2 },
    createToolPool: () => Object.freeze({ async callTool() {
      throw Object.assign(new Error('Scoped external tool unavailable'), { code: 'SCOPED_TOOL_UNAVAILABLE' });
    } }),
    createLocalTools: (binding, context, token, _execution, personaFence) => {
      const allowed = requestAuthority.resolve(token, context);
      const fixed = featureModeForFence(personaFence)?.effectiveMode === 'fixed';
      return createSecureShopPersonaInboxTools({ repository: personaFence?require('./secureshopPersonaInboxEffect').createPersonaInboxEffect({fence:personaFence,repository:bundle.repository}):bundle.repository,
      trustedScope: binding, trustedPersona: { id: binding.shopUserId, role: binding.role },
      mode: fixed ? 'fixed' : 'vuln',
      checkCurrent: async value => {
        await launches.assertCurrent(require('./secureshopMailSceneBinding').current(value));
        const allowed = requestAuthority.resolve(token, context);
        const acl = await bundle.repository.readAcl(await resolveTarget(binding));
        await availability.assertObjectives(['ss_cross_persona_effect', acl.mode === 'advisory'
          ? 'ss_acl_advisory_effect' : 'ss_acl_enforced_block'],createLaunchScope(binding));
        return allowed;
      }, resolveTarget,
      allowedMessageId: allowed.messageId, authorizedTargetId: allowed.targetId });
    },
  });
  application = createSecureShopPersonaInboxApplication({ launches, repository: bundle.repository,
    conversations, runner, resolveFixtures, authorizeAclTransition: bundle.authorizeAclTransition,
    requestAuthority, availability, personaAuthority, modeAuthority,mailScenes });
  const router = createBoundPersonaInboxRouter({ launches, authenticatePersona, application });
  return Object.freeze({ ready: true, router, application, runner,
    completionService: assessment.completionService, objectives: OBJECTIVES });
}

module.exports = { FIXTURES, mapPersonaInboxFixtures, createSecureShopPersonaInboxRepositoryBundle,
  createSecureShopPersonaInboxComposition };
