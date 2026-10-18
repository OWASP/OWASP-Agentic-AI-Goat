'use strict';

const path=require('node:path');
const {createFinflowDurableResourceRepository}=require('../database/postgres/finflowDurableResourceRepository');
const {createFinflowLogOverlayRepository}=require('../database/postgres/finflowLogOverlayRepository');
const {createFinflowBackupFileStore,createFinflowDurableResources}=require('./finflowDurableResources');
const {createFinflowOwnerResourceDeletion}=require('./finflowOwnerResourceDeletion');
const {initialFinflowCustomerDataset}=require('./finflowCustomerDataset');

function controlledRoots({appDataRoot,env=process.env}={}){
  const supplied=appDataRoot===undefined?env.DVAIA_APP_DATA_ROOT:appDataRoot;
  if(typeof supplied!=='string'||!path.isAbsolute(supplied)){
    throw new TypeError('Explicit absolute DVAIA application data root required');
  }
  const root=path.resolve(supplied);
  const traversalRoot=path.resolve(env.FINFLOW_TRAVERSAL_TARGET_ROOT||path.join(root,'finflow-traversal-targets'));
  const backupRoot=path.resolve(env.FINFLOW_BACKUP_ROOT||path.join(root,'finflow-backups'));
  for(const value of [traversalRoot,backupRoot]){
    if(path.dirname(value)!==root)throw new TypeError('FinFlow resource roots must be direct application-data children');
  }
  if(traversalRoot===backupRoot)throw new TypeError('FinFlow resource roots must be distinct');
  return Object.freeze({appDataRoot:root,traversalRoot,backupRoot});
}

async function createFinflowDurableResourceLifecycle({pool,appDataRoot,env=process.env,fileSystem,
  initialRecords=initialFinflowCustomerDataset()}={}){
  const roots=controlledRoots({appDataRoot,env});
  const repository=createFinflowDurableResourceRepository(pool);
  const logRepository=createFinflowLogOverlayRepository(pool);
  await repository.assertReady();
  await logRepository.assertReady();
  const files=createFinflowBackupFileStore({root:roots.backupRoot,
    ...(fileSystem===undefined?{}:{fileSystem})});
  await files.assertReady();
  const resources=createFinflowDurableResources({repository,logRepository,files,initialRecords});
  return Object.freeze({roots,repository,logRepository,files,resources,
    cleanupOwner:createFinflowOwnerResourceDeletion({repository,files})});
}

module.exports={controlledRoots,createFinflowDurableResourceLifecycle};
