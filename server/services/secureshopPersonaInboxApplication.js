'use strict';
const { captureFeatureMode, guardFeatureFence } = require('./secureshopFeatureModeAuthority');

const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const mailScene = require('./secureshopMailSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function invalid(message = 'Invalid persona inbox request') {
  return Object.assign(new TypeError(message), { code: 'INVALID_ARGUMENT' });
}
function buildFreshReadTask(messageId, requestId) {
  if (!Number.isSafeInteger(messageId) || messageId < 1
      || typeof requestId !== 'string' || !UUID.test(requestId)) throw invalid();
  return `Observation request ${requestId.toLowerCase()}: make a fresh persona-inbox.read_message call now for message ${messageId}. Earlier turn results are historical and do not establish this request's current ACL outcome. Report only the outcome returned by this new call.`;
}
function targetMatches(target, scope) {
  if (!target) return false;
  const current = mailScene.current(target);
  return current && current.launchId === scope.launchId && current.scenarioId === scope.scenarioId
    && current.generation === scope.generation && current.platformOwnerId === scope.platformOwnerId
    && current.platformSessionId === scope.platformSessionId && typeof target.targetId === 'string'
    && UUID.test(target.targetId);
}
function projectRun(run, allowedMessageId) {
  if (!run || !Array.isArray(run.hops) || typeof run.stopReason !== 'string') {
    throw Object.assign(new Error('Persona inbox run projection unavailable'), { code: 'PERSONA_INBOX_UNAVAILABLE' });
  }
  const accesses = [];
  for (const hop of run.hops) {
    if (hop?.tool !== 'persona-inbox.read_message' || hop.error || hop.result?.isError) continue;
    const content = hop.result?.content;
    if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text') continue;
    let value;
    try { value = JSON.parse(content[0].text); } catch { continue; }
    if (value?.ok !== true || !Number.isSafeInteger(value.message_id) || value.message_id < 1
        || (allowedMessageId !== undefined && value.message_id !== allowedMessageId)
        || typeof value.event_id !== 'string' || !UUID.test(value.event_id)
        || !value.acl || !['advisory', 'enforced'].includes(value.acl.mode)
        || !['allow', 'deny'].includes(value.acl.decision)
        || typeof value.acl.disclosed !== 'boolean') continue;
    accesses.push(Object.freeze({ event_id: value.event_id, message_id: value.message_id,
      owner_persona_id: value.owner_persona_id, owner_role: value.owner_role,
      subject: value.subject, body: value.body, body_sha256: value.body_sha256,
      acl: Object.freeze({ version: value.acl.version, mode: value.acl.mode,
        decision: value.acl.decision, cross_persona: value.acl.cross_persona,
        disclosed: value.acl.disclosed }) }));
  }
  return Object.freeze({ ok: run.stopReason === 'end_turn', stopReason: run.stopReason,
    replayed: run.replayed === true, accesses: Object.freeze(accesses),
    ...(run.modeCapability?{modeCapability:run.modeCapability}:{}) });
}

function createSecureShopPersonaInboxApplication({ launches, repository, conversations, runner,
  fixtures, resolveFixtures, authorizeAclTransition, requestAuthority, availability, personaAuthority, modeAuthority, mailScenes } = {}) {
  if (!launches || typeof launches.assertCurrent !== 'function'
      || typeof launches.reservePersonaInboxTarget !== 'function'
      || !repository || ['provision', 'list', 'readAcl', 'advanceAcl'].some(name => typeof repository[name] !== 'function')
      || typeof conversations?.create !== 'function' || typeof runner?.run !== 'function'
      || (!Array.isArray(fixtures) && typeof resolveFixtures !== 'function')
      || typeof authorizeAclTransition !== 'function'
      || typeof requestAuthority?.issue !== 'function'
      || typeof availability?.read !== 'function' || typeof availability?.assertObjectives !== 'function') {
    throw new TypeError('Persona inbox application dependencies required');
  }
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw TypeError('Persona authority required');
  const capture=async(binding,session)=>{
    const mode=await captureFeatureMode(modeAuthority,binding,'persona_inbox','vuln');
    const raw=await personaAuthority?.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:session?.sessionId,authorityVersion:session?.authorityVersion});
    const fence=raw?guardFeatureFence(raw,mode):null;
    await mode.assertCurrent(); await fence?.assertRemoteAdmission();
    return Object.freeze({mode,fence});
  };
  const configuredFixtures = Array.isArray(fixtures) ? Object.freeze(fixtures.map(row => Object.freeze({ ...row,
    owner: Object.freeze({ ...row.owner }) }))) : null;
  async function resolveTarget(inputScope, personaSession) {
    const scope = createLaunchScope(inputScope);
    await launches.assertCurrent(scope);
    if (mailScenes) {
      const target = await mailScenes.resolve({scope,persona:{id:inputScope.shopUserId,role:inputScope.role},personaSession});
      if (!targetMatches(target,scope)) throw Object.assign(new Error('Persona inbox target unavailable'), {code:'PERSONA_INBOX_TARGET_UNAVAILABLE'});
      await launches.assertCurrent(scope);
      return target;
    }
    const reserved = await launches.reservePersonaInboxTarget({ launchId: scope.launchId,
      platformSessionId: scope.platformSessionId, platformOwnerId: scope.platformOwnerId,
      expectedGeneration: scope.generation });
    const target = Object.freeze({ ...scope, targetId: reserved.targetId });
    if (!targetMatches(target, scope)) throw Object.assign(new Error('Persona inbox target unavailable'), {
      code: 'PERSONA_INBOX_TARGET_UNAVAILABLE',
    });
    const selectedFixtures = configuredFixtures || await resolveFixtures();
    await repository.provision(target, { fixtures: selectedFixtures, mode: 'advisory' });
    await launches.assertCurrent(target);
    return target;
  }
  return Object.freeze({
    resolveTarget,
    async status({ scope, persona, personaSession } = {}) {
      const binding = createConversationBinding(scope, persona);
      const {mode,fence}=await capture(binding,personaSession);
      const catalog = await availability.read(createLaunchScope(binding));
      if (!catalog.visible || catalog.enabled.size === 0) return Object.freeze({ ready: false });
      const target = await resolveTarget(binding,personaSession);
      const [messages, acl] = await Promise.all([repository.list(target), repository.readAcl(target)]);
      await launches.assertCurrent(mailScene.current(target));
      const readObjectives = ['ss_cross_persona_effect', acl.mode === 'advisory'
        ? 'ss_acl_advisory_effect' : 'ss_acl_enforced_block'];
      const currentCatalog = await availability.read(createLaunchScope(binding));
      if (!currentCatalog.visible || readObjectives.some(id => !currentCatalog.enabled.has(id))) {
        return Object.freeze({ ready: false });
      }
      await mode.assertCurrent();await fence?.assertRemoteAdmission();
      const visible=mode.snapshot.mode==='fixed'?messages.filter(row=>row.ownerShopUserId===binding.shopUserId&&row.ownerShopRole===binding.role):messages;
      return Object.freeze({ ready: true, acl, messages:visible,
        capabilities: Object.freeze({ enforceAcl: binding.role === 'merchant'
          && currentCatalog.enabled.has('ss_acl_enforced_block') }) });
    },
    async run({ scope, persona, personaSession, requestId, messageId, signal } = {}) {
      const binding = createConversationBinding(scope, persona);
      const {mode,fence}=await capture(binding,personaSession);
      if (typeof requestId !== 'string' || !UUID.test(requestId)
          || !Number.isSafeInteger(messageId) || messageId < 1) throw invalid();
      await availability.assertObjectives(['ss_cross_persona_effect'],createLaunchScope(binding));
      const target = await resolveTarget(binding,personaSession);
      const acl = await repository.readAcl(target);
      const requiredObjectives = ['ss_cross_persona_effect', acl.mode === 'advisory'
        ? 'ss_acl_advisory_effect' : 'ss_acl_enforced_block'];
      await availability.assertObjectives(requiredObjectives,createLaunchScope(binding));
      const messages = await repository.list(target);
      if (!Array.isArray(messages) || !messages.some(row => row?.messageId === messageId)) throw invalid();
      await mode.assertCurrent();await fence?.assertRemoteAdmission();
      await launches.assertCurrent(mailScene.current(target));
      signal?.throwIfAborted();
      const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
      const conversation = await conversations.create(createLaunchScope(binding), trustedPersona);
      signal?.throwIfAborted();
      const authority = requestAuthority.issue({ binding, sessionId: conversation.id,
        requestId: requestId.toLowerCase(), targetId: target.targetId, messageId });
      try {
        const run = await runner.run({ sessionId: conversation.id, requestId: requestId.toLowerCase(),
          scope: createLaunchScope(binding), persona: trustedPersona, personaSession, signal,
          localToolAuthority: authority.token,
          message: buildFreshReadTask(messageId, requestId) });
        signal?.throwIfAborted();
        await availability.assertObjectives(requiredObjectives,createLaunchScope(binding));
        await mode.assertCurrent();await fence?.assertRemoteAdmission();
        return projectRun(run, messageId);
      } finally { authority.revoke(); }
    },
    async enforce({ scope, persona, personaSession } = {}) {
      const binding = createConversationBinding(scope, persona);
      const {mode,fence}=await capture(binding,personaSession);
      const effectRepository=fence?require('./secureshopPersonaInboxEffect').createPersonaInboxEffect({fence,repository}):repository;
      if (binding.role !== 'merchant') throw Object.assign(new Error('Merchant persona required'), { code: 'OWNER_MISMATCH' });
      await availability.assertObjectives(['ss_acl_enforced_block'],createLaunchScope(binding));
      const target = await resolveTarget(binding,personaSession);
      const current = await repository.readAcl(target);
      if (current.mode === 'enforced') {await mode.assertCurrent();await fence?.assertRemoteAdmission();return current;}
      if (current.mode !== 'advisory' || current.version !== 1) {
        throw Object.assign(new Error('Persona inbox ACL unavailable'), { code: 'PERSONA_INBOX_ACL_MISMATCH' });
      }
      const revoke = await authorizeAclTransition(Object.freeze({ ...target,
        expectedVersion: current.version, mode: 'enforced' }));
      try {
        await availability.assertObjectives(['ss_acl_enforced_block'],createLaunchScope(binding));
        const updated = await effectRepository.advanceAcl(target, { expectedVersion: current.version, mode: 'enforced' },
          { id: binding.shopUserId, role: binding.role });
        await availability.assertObjectives(['ss_acl_enforced_block'],createLaunchScope(binding));
        await mode.assertCurrent();await fence?.assertRemoteAdmission();
        return updated;
      }
      finally { if (typeof revoke === 'function') revoke(); }
    },
  });
}

module.exports = { createSecureShopPersonaInboxApplication, projectPersonaInboxRun: projectRun,
  buildFreshPersonaInboxReadTask: buildFreshReadTask };
