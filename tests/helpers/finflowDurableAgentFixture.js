'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createFinflowDurableResources, createFinflowBackupFileStore } = require('../../server/services/finflowDurableResources');
const { initialFinflowCustomerDataset } = require('../../server/services/finflowCustomerDataset');

const clone = value => value == null ? value : structuredClone(value);
const key = value => `${value.ownerId}:${value.generation}`;

function createMemoryRepository() {
  const datasets = new Map();
  const backups = new Map();
  const operations = new Map();
  const reads = new Map();
  const logOverlays = new Map();
  const logMutations = new Map();
  const retirements = new Map();
  const retiredGenerations = new Set();
  const active = value => {
    if(retiredGenerations.has(key(value)))throw Object.assign(Error('retired'),{code:'FINFLOW_RESOURCE_RETIRED'});
  };
  const dataset = value => {
    const id = key(value);
    if (!datasets.has(id)) datasets.set(id, { ownerId:value.ownerId, generation:value.generation,
      revision:0, records:clone(value.initialRecords), deleted:false });
    return datasets.get(id);
  };
  return {
    datasets, backups, logOverlays, logMutations, retirements, retiredGenerations,
    async readDataset(value) { active(value); return clone(dataset(value)); },
    async deleteDataset(value) {
      const prior=operations.get(value.operationId); if(prior)return clone(prior);
      const current=dataset(value);current.records=[];current.deleted=true;current.revision+=1;
      const result={ownerId:value.ownerId,generation:value.generation,operationId:value.operationId,
        runId:value.runId,revision:current.revision,deleted:true,records:[]};
      operations.set(value.operationId,result);return clone(result);
    },
    async reserveBackup(value) {
      const prior=operations.get(value.operationId);if(prior)return clone(prior);
      if([...backups.values()].some(row=>row.ownerId===value.ownerId&&row.generation===value.generation
          &&row.virtualPath===value.virtualPath))throw Object.assign(Error('path conflict'),{code:'FINFLOW_BACKUP_PATH_CONFLICT'});
      const current=dataset(value);const row={ownerId:value.ownerId,generation:value.generation,
        operationId:value.operationId,runId:value.runId,backupId:value.backupId,fileToken:value.fileToken,
        virtualPath:value.virtualPath,datasetRevision:current.revision,records:clone(current.records),
        status:'writing',contentSha256:null,byteLength:null,recordCount:null};
      backups.set(row.backupId,row);operations.set(value.operationId,row);return clone(row);
    },
    async commitBackup(value) {
      const row=backups.get(value.backupId);if(!row)throw Error('missing reservation');
      if(row.status==='writing')Object.assign(row,{status:'ready',contentSha256:value.contentSha256,
        byteLength:value.byteLength,recordCount:value.recordCount});
      return clone(row);
    },
    async readBackup(value) { return clone([...backups.values()].find(row=>row.ownerId===value.ownerId
      &&row.generation===value.generation&&row.virtualPath===value.virtualPath&&row.status==='ready')); },
    async listBackups(value) { return clone([...backups.values()].filter(row=>row.ownerId===value.ownerId
      &&row.generation===value.generation&&row.status==='ready').sort((a,b)=>a.virtualPath.localeCompare(b.virtualPath))); },
    async recordBackupRead(value) {
      const prior=reads.get(value.operationId);if(prior)return clone(prior);
      const row={ownerId:value.ownerId,generation:value.generation,operationId:value.operationId,
        runId:value.runId,backupId:value.backupId,requestedPath:value.requestedPath,
        contentSha256:value.contentSha256,byteLength:value.byteLength};reads.set(value.operationId,row);return clone(row);
    },
    async beginRetirement(value){
      let row=retirements.get(value.operationId);
      if(!row){row={...value,status:'pending',fileTokens:[],artifactCount:0};retirements.set(value.operationId,row);}
      return clone(row);
    },
    async completeRetirement(value){
      const row=retirements.get(value.operationId);if(!row)throw Error('missing retirement');
      retiredGenerations.add(`${value.ownerId}:${value.fromGeneration}`);
      for(const overlay of logOverlays.values())if(overlay.ownerId===value.ownerId&&overlay.generation===value.fromGeneration)overlay.retired=true;
      Object.assign(row,{status:'completed',completedAt:'2026-09-14T12:00:00.000Z'});return clone(row);
    },
    async readRetirement(value){return clone(retirements.get(value.operationId)||null);},
  };
}

function createMemoryLogRepository(storage) {
  return {
    async read(value) { active(value);const row=storage.logOverlays.get(`${key(value)}:${value.logType}`);return row?.retired?null:clone(row); },
    async write(value) {
      active(value);
      const prior=storage.logMutations.get(value.operationId);
      const overlayKey=`${key(value)}:${value.logType}`,before=storage.logOverlays.get(overlayKey);
      if(prior){
        if(!before||before.retired||before.revision!==prior.revision
            ||before.contentSha256!==prior.contentSha256||before.byteLength!==prior.byteLength){
          throw Object.assign(Error('FinFlow log overlay replay is stale'),{code:'55000'});
        }
        return clone(prior);
      }
      if(before&&!before.retired&&before.content===value.content){
        throw Object.assign(Error('FinFlow log overlay mutation has no effect'),{code:'55000'});
      }
      const overlay={ownerId:value.ownerId,generation:value.generation,logType:value.logType,action:value.action,
        content:value.content,contentSha256:value.contentSha256,byteLength:Buffer.byteLength(value.content),
        revision:(before?.revision||0)+1};
      storage.logOverlays.set(overlayKey,overlay);
      const mutation={...overlay,operationId:value.operationId,runId:value.runId,completedAt:'2026-09-14T12:00:00.000Z'};
      storage.logMutations.set(value.operationId,mutation);return clone(mutation);
    },
  };
  function active(value){
    if(storage.retiredGenerations.has(key(value)))throw Object.assign(Error('retired'),{code:'FINFLOW_RESOURCE_RETIRED'});
  }
}

function createDurableAgentFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'finflow-agent-resources-'));
  const repository = createMemoryRepository();
  const logRepository = createMemoryLogRepository(repository);
  const files = createFinflowBackupFileStore({ root:path.join(root,'backups') });
  const resources = createFinflowDurableResources({ repository, logRepository, files,
    initialRecords:initialFinflowCustomerDataset() });
  const cleanup = () => fs.rmSync(root,{recursive:true,force:true});
  t?.after(cleanup);
  return { root, repository, logRepository, files, resources, cleanup };
}

function execution(ownerId, generation=0, runId='30000000-0000-4000-8000-000000000001') {
  return {ownerId:String(ownerId),ownerKey:JSON.stringify(['FinFlow',String(ownerId)]),
    durableGeneration:generation,runId,async check(){},async effect(_key,work){return work();}};
}

module.exports = { createDurableAgentFixture, createMemoryRepository, createMemoryLogRepository, execution };
