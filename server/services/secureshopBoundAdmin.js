'use strict';

const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const ROLES = new Set(['customer', 'merchant', 'admin']);
function fail(code = 'INVALID_ARGUMENT') {
  throw Object.assign(new Error('Bound admin request unavailable'), { code });
}

// Administer the personas of this launch, never the platform's user directory.
// Credentials and the deliberately vulnerable lookup tool are separate surfaces.
function createSecureShopBoundAdmin({ launches, personas, account, catalog, commerceRepository, conversations, auditRepository, readAdapter,
  personaAuthority, accountRepository, administrationRepository } = {}) {
  if (typeof launches?.assertCurrent !== 'function' || typeof personas?.listPersonas !== 'function'
      || typeof account?.profile !== 'function') throw new TypeError('Bound admin dependencies required');
  const protectedDirectory = personaAuthority !== undefined || accountRepository !== undefined
    || administrationRepository !== undefined;
  if (protectedDirectory && (typeof personaAuthority?.capture !== 'function'
      || typeof accountRepository?.readProfile !== 'function'
      || typeof administrationRepository?.readEffectivePersona !== 'function'
      || typeof catalog?.prepareTarget !== 'function')) {
    throw new TypeError('Bound admin directory authority required');
  }
  function snapshot(input = {}) {
    const scope = createLaunchScope(input.scope);
    if (input.persona?.role !== 'admin' || !Number.isSafeInteger(input.persona.id)
        || input.persona.id < 1) fail('OWNER_MISMATCH');
    return Object.freeze({ scope, persona: Object.freeze({ id: input.persona.id, role: 'admin' }),
      ...(input.personaSession ? { personaSession: Object.freeze({
        sessionId: input.personaSession.sessionId,
        authorityVersion: input.personaSession.authorityVersion,
      }) } : {}),
      query: input.query === undefined ? undefined : structuredClone(input.query),
      limit: input.limit, name: typeof input.name === 'string' ? input.name : undefined,
      provenance: input.provenance });
  }
  async function capture(input, scope) {
    if (!protectedDirectory) return null;
    const session = input?.personaSession;
    if (typeof session?.sessionId !== 'string'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(session.sessionId)
        || typeof session?.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(session.authorityVersion)) fail('SHOP_AUTH_INVALID');
    const credential = Object.freeze({ sessionId: session.sessionId.toLowerCase(),
      authorityVersion: session.authorityVersion });
    const fence = await personaAuthority.capture({ scope, personaId: input.persona.id,
      role: input.persona.role, ...credential });
    const binding = fence?.binding;
    if (typeof fence?.assertRemoteAdmission !== 'function'
        || typeof fence?.withCrossStoreEffect !== 'function' || !binding
        || Object.keys(scope).some(key => scope[key] !== binding[key])
        || binding.personaId !== input.persona.id || binding.role !== input.persona.role
        || binding.sessionId !== credential.sessionId
        || binding.authorityVersion !== credential.authorityVersion) fail('SHOP_AUTH_INVALID');
    await fence.assertRemoteAdmission();
    return fence;
  }
  const actors = scope => typeof personas.listActors === 'function'
    ? personas.listActors(scope) : personas.listPersonas();
  async function readUsers(rawInput = {}, exactTargetId) {
      const input = snapshot(rawInput);
      const { scope, persona, personaSession } = input;
      const query = input.query || {};
      const { page = 1, pageSize = 25, search = '', role = '', banned = '' } = query;
      if (!Number.isSafeInteger(page) || page < 1 || page > 2147483647
          || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100
          || typeof search !== 'string' || Buffer.byteLength(search, 'utf8') > 256
          || !['', ...ROLES, 'banned'].includes(role) || !['', 'true', 'false'].includes(banned)) fail();
      await launches.assertCurrent(scope);
      const fence = await capture({ persona, personaSession }, scope);
      const templates = await actors(scope);
      if (!templates.some(row => row.id === persona.id && (fence || row.role === 'admin'))) fail('OWNER_MISMATCH');
      const selectedTemplates = exactTargetId === undefined ? templates : templates.filter(row => row.id === exactTargetId);
      if (exactTargetId !== undefined && selectedTemplates.length !== 1) fail('PERSONA_UNAVAILABLE');
      let target;
      if (fence) {
        const personaEffect = require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence);
        target = await catalog.prepareTarget({ scope, persona, personaEffect });
        await fence.assertRemoteAdmission();
      }
      const users = [];
      for (const template of selectedTemplates) {
        if (!ROLES.has(template.role) || !Number.isSafeInteger(template.id)) fail();
        const identityKind = typeof personas.listActors === 'function'
          ? template.identity_kind : 'teaching_persona';
        if (!['teaching_persona','registered_account'].includes(identityKind)) fail('OWNER_MISMATCH');
        const state = fence
          ? await administrationRepository.readEffectivePersona({ scope, shopUserId: template.id })
          : null;
        const overlay = fence ? await accountRepository.readProfile(target, template.id) : null;
        const profile = fence ? { id: template.id, username: template.username,
          email: overlay ? overlay.email : template.email,
          full_name: overlay ? overlay.full_name : template.full_name,
          phone: overlay ? overlay.phone : template.phone, role: state.role,
          banned_at: state.banned_at, authority_version: state.version }
          : await account.profile({ scope, persona: { id: template.id, role: template.role } });
        if (profile.id !== template.id || !ROLES.has(profile.role)) fail('OWNER_MISMATCH');
        // The protected projection combines immutable template identity with
        // the current effective role/ban state and the target's profile overlay.
        users.push({ id: profile.id, username: profile.username, email: profile.email,
          role: profile.role, full_name: profile.full_name, phone: profile.phone,
          identity_kind: identityKind,
          banned_at: profile.banned_at ?? null,
          ...(fence ? { authority_version: profile.authority_version } : {}) });
      }
      await fence?.assertRemoteAdmission();
      await launches.assertCurrent(scope);
      const needle = search.trim().toLowerCase();
      const filtered = users.filter(row => (!role || (role === 'banned' ? row.banned_at !== null : row.role === role))
        && (!banned || (banned === 'true') === (row.banned_at !== null))
        && (!needle || [row.username, row.email, row.full_name]
          .some(value => String(value || '').toLowerCase().includes(needle))))
        .sort((a, b) => a.id - b.id);
      return Object.freeze({ users: filtered.slice((page - 1) * pageSize, page * pageSize),
        total: filtered.length, count: filtered.length, page, pageSize,
        pages: Math.max(1, Math.ceil(filtered.length / pageSize)) });
  }
  const service = {
    users: rawInput => readUsers(rawInput),
    async user(rawInput = {}) {
      const targetId = rawInput.targetId;
      if (!Number.isSafeInteger(targetId) || targetId < 1 || targetId > 2147483647) fail();
      // Internal exact owned actor lookup. Select before projection and pagination;
      // a username search is not a reliable identity lookup.
      const result = await readUsers({ ...rawInput, query: { page: 1, pageSize: 1 } }, targetId);
      const row = result.users[0];
      return { id: row.id, username: row.username, email: row.email, role: row.role,
        identity_kind: row.identity_kind, banned_at: row.banned_at instanceof Date ? row.banned_at.toISOString() : row.banned_at,
        authority_version: row.authority_version };
    },
  };
  if (catalog && commerceRepository && typeof personas.countActiveSessions === 'function') {
    service.kpis = async rawInput => {
      const input = snapshot(rawInput);
      const directory = await service.users({ ...input, query: {} });
      const scope = createLaunchScope(input.scope);
      let fence = await capture(input, scope);
      const target = await catalog.prepareTarget({ scope, persona: input.persona,
        ...(fence ? { personaEffect: require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence) } : {}) });
      const [commerce, activeSessions] = await Promise.all([
        commerceRepository.adminSummary(target), personas.countActiveSessions({ scope }),
      ]);
      await fence?.assertRemoteAdmission();
      await launches.assertCurrent(scope);
      return Object.freeze({ ...commerce, total_users: directory.total,
        admin_count: directory.users.filter(row => row.role === 'admin').length,
        banned_count: directory.users.filter(row => row.banned_at !== null).length,
        active_sessions: activeSessions });
    };
  }
  async function observed(input, read) {
    input = snapshot(input);
    const scope = input.scope;
    await launches.assertCurrent(scope);
    const fence = await capture(input, scope);
    const templates = await actors(scope);
    if (!templates.some(row => row.id === input.persona.id && (fence || row.role === 'admin'))) fail('OWNER_MISMATCH');
    const result = await read(scope, input);
    await fence?.assertRemoteAdmission();
    await launches.assertCurrent(scope);
    return result;
  }
  if (typeof conversations?.latestObservedProviders === 'function'
      && typeof conversations?.adminLatestTrace === 'function') {
    service.providers = input => observed(input, scope => conversations.latestObservedProviders(scope));
    service.latestTrace = input => observed(input, (scope, captured) =>
      conversations.adminLatestTrace(createConversationBinding(scope, captured.persona), captured.limit));
  }
  if (typeof auditRepository?.recent === 'function') {
    service.audit = input => observed(input, (scope, captured) => auditRepository.recent(scope, captured.query));
  }
  for (const name of ['runtimeHealth','mcpServers','mcpHistory','dbSizes']) {
    if (typeof readAdapter?.[name] === 'function') service[name] = input => observed(input, scope => readAdapter[name](scope));
  }
  if(typeof readAdapter?.mcpTools==='function')service.mcpTools=input=>observed(input,(scope,captured)=>readAdapter.mcpTools(scope,captured.name,captured.provenance));
  return Object.freeze(service);
}
module.exports = { createSecureShopBoundAdmin };
