'use strict';

function failure(code, message) { return Object.assign(new Error(message), { code }); }

function createSecureShopBoundAccount({ repository, personaRepository, catalog, personaAuthority } = {}) {
  if (['readProfile', 'updateProfile', 'listAddresses', 'saveAddress', 'deleteAddress']
    .some(name => typeof repository?.[name] !== 'function')
    || typeof personaRepository?.readPersona !== 'function'
    || typeof catalog?.prepareTarget !== 'function') {
    throw new TypeError('Bound account dependencies required');
  }
  if (personaAuthority !== undefined && typeof personaAuthority?.capture !== 'function') throw new TypeError('Account persona authority required');
  async function prepared(raw) {
    const input = personaAuthority ? {...structuredClone({...raw,apiAuthority:undefined}),...(raw?.apiAuthority?{apiAuthority:raw.apiAuthority}:{})} : raw;
    let fence;
    if (personaAuthority) {
      const scope = require('./secureshopConversationBinding').createLaunchScope(input.scope);
      if(input.apiAuthority!==undefined){fence=require('./secureshopBoundPersonaAuth').resolveBoundApiKeyAuthority(input.apiAuthority,{scope,persona:input.persona});await fence.assertRemoteAdmission();input.scope=scope;}else{
      const session = input.personaSession;
      if (typeof session?.sessionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(session.sessionId)
          || typeof session.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(session.authorityVersion)) throw failure('SHOP_AUTH_INVALID','Account authority unavailable');
      const credential = {sessionId:session.sessionId.toLowerCase(),authorityVersion:session.authorityVersion};
      fence = await personaAuthority.capture({scope,personaId:input.persona?.id,role:input.persona?.role,...credential});
      if (typeof fence?.assertRemoteAdmission !== 'function' || typeof fence?.withCrossStoreEffect !== 'function'
          || !fence.binding || Object.keys(scope).some(key=>scope[key]!==fence.binding[key])
          || fence.binding.personaId!==input.persona?.id || fence.binding.role!==input.persona?.role
          || fence.binding.sessionId!==credential.sessionId || fence.binding.authorityVersion!==credential.authorityVersion) throw failure('SHOP_AUTH_INVALID','Account authority unavailable');
      await fence.assertRemoteAdmission();
      input.scope=scope;
      input.personaEffect=require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence);
      }
    }
    if (!input?.persona || !Number.isSafeInteger(input.persona.id)
        || !['customer', 'merchant', 'admin'].includes(input.persona.role)) {
      throw failure('OWNER_MISMATCH', 'shop persona required');
    }
    const canonical = await personaRepository.readPersona(input.persona.id, input.scope);
    if (!canonical || Number(canonical.id) !== input.persona.id || (!personaAuthority && canonical.role !== input.persona.role)) {
      throw failure('OWNER_MISMATCH', 'shop persona unavailable');
    }
    await fence?.assertRemoteAdmission();
    if(input.apiAuthority)throw failure('SHOP_API_KEY_INVALID','Account API target initialization requires an effect credential');
    const target = await catalog.prepareTarget(input);
    await fence?.assertRemoteAdmission();
    return { target, input, fence, canonical: Object.freeze({ id: Number(canonical.id), username: canonical.username,
      email: canonical.email, role: personaAuthority ? input.persona.role : canonical.role, full_name: canonical.full_name ?? null,
      phone: canonical.phone ?? null }) };
  }
  async function profile(input) {
    const { target, canonical, fence } = await prepared(input);
    const overlay = await repository.readProfile(target, canonical.id);
    await fence?.assertRemoteAdmission();
    return Object.freeze({ ...canonical, ...(overlay ? { email: overlay.email,
      full_name: overlay.full_name, phone: overlay.phone } : {}) });
  }
  async function run(raw, work, mutation=false) {
    const preparedInput=await prepared(raw),{fence}=preparedInput;
    await fence?.assertRemoteAdmission();
    const result=fence&&mutation?await fence.withCrossStoreEffect(()=>work(preparedInput)):await work(preparedInput);
    try { await fence?.assertRemoteAdmission(); }
    catch(cause) {
      if(!mutation)throw cause;
      const error=Object.assign(new Error('Account effect requires authoritative readback'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});
      Object.defineProperty(error,'cause',{value:cause});throw error;
    }
    return result;
  }
  return Object.freeze({
    profile,
    updateProfile(input) { return run(input,async({target,canonical,input})=>{
      const overlay=await repository.updateProfile(target,canonical.id,{fullName:input.fullName,email:input.email,phone:input.phone},canonical);
      return Object.freeze({...canonical,email:overlay.email,full_name:overlay.full_name,phone:overlay.phone});
    },true); },
    addresses(input) { return run(input,({target,canonical})=>repository.listAddresses(target,canonical.id)); },
    createAddress(input) { return run(input,({target,canonical,input})=>repository.saveAddress(target,canonical.id,null,input.address,canonical),true); },
    updateAddress(input) { return run(input,({target,canonical,input})=>repository.saveAddress(target,canonical.id,input.addressId,input.address,canonical),true); },
    deleteAddress(input) { return run(input,({target,canonical,input})=>repository.deleteAddress(target,canonical.id,input.addressId,canonical),true); },
  });
}

module.exports = { createSecureShopBoundAccount };
