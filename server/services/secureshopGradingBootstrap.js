'use strict';
const preparedBootstraps = new WeakMap();

// Prepared required-persona composition only. Startup owns installation and
// publication; this module never discovers stores or installs a singleton.
async function createSecureShopGradingBootstrap({ identityPool, agentsPool, progress,
  resetComposition, assertAuthorityReady, expectedIdentityDatabase, expectedAgentsDatabase,
  judge, coordinatorFactory, assessmentReleaseAdmission } = {}, factories = {}) {
  const releaseAdmission = require('./secureshopAssessmentReleaseAdmission')
    .resolveAssessmentReleaseAdmission(assessmentReleaseAdmission, { identityPool, agentsPool });
  await releaseAdmission.assertCurrent();
  const explicitStoreNames = typeof expectedIdentityDatabase === 'string' && expectedIdentityDatabase.length > 0
    && typeof expectedAgentsDatabase === 'string' && expectedAgentsDatabase.length > 0
    && expectedIdentityDatabase !== expectedAgentsDatabase;
  if (typeof identityPool?.query !== 'function' || typeof identityPool?.connect !== 'function'
      || typeof agentsPool?.query !== 'function' || typeof agentsPool?.connect !== 'function'
      || identityPool === agentsPool || typeof progress?.getGeneration !== 'function'
      || typeof resetComposition?.launches?.assertCurrent !== 'function'
      || (assertAuthorityReady !== undefined && typeof assertAuthorityReady !== 'function')
      || (assertAuthorityReady === undefined && !explicitStoreNames)) {
    throw new TypeError('Explicit initialized grading stores and authority readiness required');
  }
  // Expected database names come from the startup's validated store manifest.
  // Never infer the expected identity from the database being checked.
  const readiness = assertAuthorityReady || (async () => {
    const row = (await identityPool.query('SELECT current_database() AS database')).rows[0];
    if (row?.database !== expectedIdentityDatabase) throw new Error('Identity grading store mismatch');
    await require('../database/postgres/secureshopBoundPersonaAuthority').assertAuthorityReady({
      pool: agentsPool, expectedDatabase: expectedAgentsDatabase });
  });
  // A missing or failed check must never fall back to unbound grading.
  if (await readiness({ identityPool, agentsPool, resetComposition }) === false) {
    throw new Error('Persona authority readiness rejected');
  }
  const createAuthority = factories.createAuthority
    || require('../database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority;
  const createBindings = factories.createBindings
    || require('../database/postgres/personaObjectiveJudgmentBindings').createPersonaObjectiveJudgmentBindings;
  const createCore = factories.createCore || require('./objectiveGradingCore').createObjectiveGradingCore;
  const launches = resetComposition.launches;
  const personaAuthority = createAuthority({ pool: agentsPool,
    checkCurrent: scope => launches.assertCurrent(scope) });
  if (typeof personaAuthority?.capture !== 'function') throw new TypeError('Persona authority required');
  const legacyBindings = createBindings({ pool: identityPool, personaAuthority });
  if (typeof legacyBindings?.assertReady !== 'function'
      || ['capture', 'initial', 'inherit', 'commit', 'check', 'projectRecoverable']
        .some(method => typeof legacyBindings[method] !== 'function')) {
    throw new TypeError('Complete persona grading adapter required');
  }
  if (await legacyBindings.assertReady() === false) throw new Error('Persona grading readiness rejected');
  const subjects=require('./secureshopAssessmentSubject').createSecureShopAssessmentSubjects({identityPool,launches,personaAuthority});
  const personaBindings=Object.freeze({...legacyBindings,async resolveStores(input,execution){
    const subject=await subjects.capture(input,execution);
    return subject===null?null:require('../database/postgres/secureshopAssessmentStore').createSecureShopAssessmentStore({pool:identityPool,subject,assessmentReleaseAdmission});
  }});
  const gradingCore = createCore({ identityPool, progress, personaBindings,
    ...(judge === undefined ? {} : { judge }),
    ...(coordinatorFactory === undefined ? {} : { coordinatorFactory }) });
  const assessmentDependencies = require('./objectiveGradingCore')
    .resolveObjectiveGradingDependencies(gradingCore, { identityPool, personaBindings });
  const prepared = Object.freeze({ gradingCore, assessmentDependencies, personaAuthority, personaBindings, resetComposition });
  preparedBootstraps.set(prepared, { identityPool, agentsPool, resetComposition, assessmentReleaseAdmission });
  return prepared;
}

function resolveSecureShopGradingBootstrap(prepared, { identityPool, agentsPool, resetComposition, assessmentReleaseAdmission } = {}) {
  const metadata = preparedBootstraps.get(prepared);
  if (!metadata || metadata.identityPool !== identityPool || metadata.agentsPool !== agentsPool
      || metadata.resetComposition !== resetComposition || prepared.resetComposition !== resetComposition
      || metadata.assessmentReleaseAdmission !== assessmentReleaseAdmission) {
    throw new TypeError('Matching prepared SecureShop grading bootstrap required');
  }
  require('./objectiveGradingCore').resolveObjectiveGradingDependencies(prepared.gradingCore,
    { identityPool, personaBindings: prepared.personaBindings });
  return prepared;
}

module.exports = { createSecureShopGradingBootstrap, resolveSecureShopGradingBootstrap };
