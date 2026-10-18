'use strict';
// Optional source composition only. Runtime never creates or repairs a key.
async function preparePasswordResetRepository({filePath,pool,auditStore},dependencies={}){
 if(filePath===undefined||filePath==='')return undefined;
 if(typeof filePath!=='string')throw TypeError('Private reset key path required');
 const stat=dependencies.stat||require('node:fs').lstatSync;
 try{stat(filePath);}catch(error){if(error?.code==='ENOENT')return undefined;throw error;}
 const load=dependencies.load||require('./secureshopPasswordResetKeys').loadPasswordResetKeys;
 const createEnvelope=dependencies.createEnvelope||require('./secureshopPasswordResetEnvelope').createPasswordResetEnvelope;
 const createRepository=dependencies.createRepository||require('../database/postgres/secureshopBoundPasswordResetRepository').createBoundPasswordResetRepository;
 const envelope=createEnvelope(load({filePath}));
 const repository=createRepository({pool,auditStore,envelope});
 await repository.checkReadiness();
 return repository;
}
async function prepareRegisteredAdminResetService({filePath,pool},dependencies={}){
 const repository=await preparePasswordResetRepository({filePath,pool},{
  ...dependencies,
  createEnvelope:dependencies.createEnvelope||require('./secureshopRegisteredAdminResetEnvelope').createRegisteredAdminResetEnvelope,
  createRepository:dependencies.createRepository||require('../database/postgres/secureshopRegisteredAdminResetRepository').createRegisteredAdminResetRepository,
 });
 if(repository===undefined)return undefined;
 const createService=dependencies.createService||require('./secureshopRegisteredAdminReset').createRegisteredAdminResetService;
 return createService({repository});
}
module.exports={preparePasswordResetRepository,prepareRegisteredAdminResetService};
