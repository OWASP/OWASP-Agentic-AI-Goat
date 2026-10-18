'use strict';
async function createSecureShopSystemRebuildComposition({reviewPool,launches,products,personaAuthority,audit,authenticatePersona,policyRepository,scenes}={},factories={}){
 if(typeof reviewPool?.query!=='function'||typeof reviewPool?.connect!=='function'||typeof launches?.assertCurrent!=='function'||typeof launches?.readExistingProductsTarget!=='function'||typeof products?.open!=='function'||typeof personaAuthority?.capture!=='function'||typeof audit?.append!=='function'||typeof authenticatePersona!=='function')throw new TypeError('Bound System rebuild composition dependencies required');
 const createEmbedder=factories.createEmbedder||require('./secureshopProductEmbedder').createSecureShopProductEmbedder;
 const embedder=createEmbedder();
 const checkCurrent=value=>launches.assertCurrent(value);
 const revisions=(factories.createRevisionRepository||require('../database/postgres/secureshopEmbeddingRevisionRepository').createSecureShopEmbeddingRevisionRepository)(reviewPool,{checkCurrent,getRuntimeFingerprint:()=>embedder.getRuntimeFingerprint()?.fingerprint});
 if(policyRepository!==undefined&&typeof policyRepository?.list!=='function')throw new TypeError('Bound System policy repository required');
 const policyRebuildEnabled=policyRepository!==undefined;
 const journal=(factories.createJournal||require('../database/postgres/secureshopSystemRebuildRepository').createSecureShopSystemRebuildRepository)({pool:reviewPool,revisions,auditStore:audit,policyRebuildEnabled});
 const readiness=factories.assertReadiness||require('../database/postgres/secureshopSystemRebuildReadiness').assertSystemRebuildReadiness;
 await readiness(reviewPool,{policyRebuildEnabled});
 const fingerprint=embedder.getRuntimeFingerprint?.()?.fingerprint;
 if(typeof fingerprint!=='string'||!/^[a-f0-9]{64}$/.test(fingerprint))throw Object.assign(new Error('Bound System rebuild embedding runtime unavailable'),{code:'SYSTEM_REBUILD_NOT_READY'});
 const resolveTarget=(factories.createTargetResolver||require('./secureshopSystemRebuildTarget').createSystemRebuildTargetResolver)({launches,products,personaAuthority,...(scenes?{scenes}:{})});
 const policySource=policyRebuildEnabled?(factories.createPolicySource||require('./secureshopPolicyCorpusSource').createSecureShopPolicyCorpusSource)({policyRepository}):null;
 const service=(factories.createService||require('./secureshopSystemRebuildService').createSecureShopSystemRebuildService)({resolveTarget,journal,revisionRepository:revisions,embedder,checkCurrent,policySource});
 const router=(factories.createRouter||require('../routes/secureshop/boundSystemRebuild').createBoundSystemRebuildRouter)({service,authenticatePersona});
 if(typeof service?.administration!=='function'||typeof service?.execute!=='function'||typeof service?.read!=='function'||typeof router!=='function')throw new TypeError('Bound System rebuild composition unavailable');
 return Object.freeze({ready:true,service,router,journal,revisions});
}
module.exports={createSecureShopSystemRebuildComposition};
