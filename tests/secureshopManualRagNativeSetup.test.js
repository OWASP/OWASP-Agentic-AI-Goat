'use strict';
// Controlled constructor wiring/readiness only; never native-store evidence.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const file=path.join(__dirname,'postgres/secureshopManualRagNativeSetup.js');
const real=require('node:module').createRequire(file);
const {standaloneReadiness}=require('../server/routes/secureshopRuntimeReadiness');
const methods=names=>Object.fromEntries(names.split(' ').map(name=>[name,()=>{}]));
async function exercise(flag,{dropPanel=false}={}){
  const env={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',...(flag===undefined?{}:{SS_PERSONA_INBOX_READY:flag})};
  let seen,checked=false;
  const composition={
    catalog:methods('listProducts getProduct listMerchantProducts categories createMerchantProduct updateMerchantProduct archiveMerchantProduct'),
    commerce:methods('cart add update remove summary checkout orders order'),
    account:methods('profile updateProfile addresses createAddress updateAddress deleteAddress'),admin:methods('users kpis'),
    personaAuth:methods('authenticatePersona'),router(){},browserRouter(){},launches:{},productAssist:methods('runSimilar'),
    repositories:{personas:methods('ensureTemplates')},
  };
  const special={
    '../../server/services/secureshopBoundReviewComposition':{createSecureShopBoundReviewComposition(options){
      seen=options;composition.personaInbox={ready:options.personaInboxFeature&&!dropPanel,router(){}};return composition;}},
    '../../server/services/secureshopStandaloneBootstrap':{createSecureShopStandaloneBootstrap:()=>()=>{}},
    '../../server/services/secureshopStandaloneReset':{createSecureShopStandaloneReset:()=>methods('readiness reset readRecovery recover')},
    '../../server/database/postgres/secureshopRegisteredAdminResetRepository':{createRegisteredAdminResetRepository:()=>methods('checkReadiness')},
    '../../server/services/secureshopRegisteredAdminReset':{createRegisteredAdminResetService:()=>methods('preview reset read reveal acknowledge')},
    '../../server/services/secureshopStandaloneMode':{createSecureShopStandaloneMode:()=>methods('get set')},
    '../../server/services/secureshopAssessmentCatalog':{createSecureShopAssessmentCatalog:()=>methods('list set')},
    '../../server/services/secureshopAssessmentRecovery':{createSecureShopAssessmentRecovery:()=>methods('list retry')},
    '../../server/services/secureshopStandaloneCartImport':{createSecureShopStandaloneCartImport:()=>()=>{}},
    '../../server/database/postgres/secureshopStorePublicCatalogRepository':{createSecureShopStorePublicCatalogRepository:()=>methods('browse product related categories reviews')},
    '../../server/services/secureshopBoundApplication':{async createSecureShopBoundApplication(options){
      const value=await options.getComposition();
      const requested=real('../../server/services/secureshopPersonaInboxActivationPolicy').activationPolicy(env).requested;
      checked=true;return{standaloneReadiness:standaloneReadiness(value,{personaInboxFeature:requested})};}},
  };
  const module={exports:{}};
  vm.compileFunction(fs.readFileSync(file,'utf8'),['require','module','__dirname','process'],{filename:file})(name=>{
    if(name in special)return special[name];
    if(name.startsWith('node:')||name.endsWith('secureshopPersonaInboxActivationPolicy'))return real(name);
    return new Proxy({},{get:()=>()=>({})});
  },module,path.dirname(file),{env});
  const lifecycle={modeAuthority:{},personaInbox:{repository:{}}};
  const result=await module.exports.createManualRagApplication({pools:{IDENTITY_RUNTIME:{},AGENTS_RUNTIME:{},REVIEW_RUNTIME:{},COMMERCE_RUNTIME:{}},
    lifecycle,grading:{personaAuthority:{}},scenes:{},auth:methods('authenticate register login renew logout changePassword establishTenantContext'),provider:{},judge:()=>{},audit:{agents:{}}});
  assert.equal(seen.resetComposition,lifecycle);assert.equal(checked,true);
  assert.equal(result.bound.standaloneReadiness.ready,true);return seen;
}
for(const [flag,expected]of [[undefined,true],['false',false],['true',true]])
  test(`shared setup preserves PostgreSQL persona inbox policy ${String(flag)}`,async()=>{
    const seen=await exercise(flag);assert.equal(seen.personaInboxFeature,expected);
    assert.equal('mcpTrustFeature'in seen,false);assert.equal('ssrfFeature'in seen,false);
  });
test('real standalone readiness rejects missing requested panel despite otherwise complete controlled composition',async()=>{
  await assert.rejects(exercise(undefined,{dropPanel:true}),/core readiness incomplete/);
  await assert.rejects(exercise('invalid'),/SS_PERSONA_INBOX_READY/);
});
