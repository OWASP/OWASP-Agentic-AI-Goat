'use strict';

// Startup-owned leaf composition. This module never discovers pools, imports
// candidate adapters, installs routes, or calls the legacy singleton getters.
const cores = new WeakSet();
const coreMetadata = new WeakMap();
function notReady() {
  return Object.assign(new Error('Objective grading is not ready'), {code:'GRADE_STORE_NOT_READY'});
}
function createObjectiveGradingCore({identityPool,progress,personaBindings,judge,coordinatorFactory}={}, constructors={}) {
  if(typeof identityPool?.query!=='function'||typeof identityPool?.connect!=='function'
    ||typeof progress?.getGeneration!=='function'
    ||(personaBindings!==undefined&&typeof personaBindings?.capture!=='function')
    ||(judge!==undefined&&typeof judge!=='function')
    ||(coordinatorFactory!==undefined&&typeof coordinatorFactory!=='function'))throw new TypeError('Explicit grading core dependencies required');
  const repositoryFactory=constructors.createObjectiveJudgmentRepository
    ||require('../database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository;
  const completionFactory=constructors.createObjectiveCompletionService
    ||require('./objectiveCompletionService').createObjectiveCompletionService;
  const regradeFactory=constructors.createObjectiveRegradeService
    ||require('./objectiveRegradeService').createObjectiveRegradeService;
  const receipts=repositoryFactory(identityPool,...(personaBindings===undefined?[]:[{personaBindings}]));
  if(typeof receipts?.listRecoverable!=='function')throw new TypeError('Recoverable judgment repository required');
  // Recovery inherits original persisted authority. It must never capture a
  // new persona token from the caller or its current session.
  const completion=completionFactory({receipts,progress,...(judge===undefined?{}:{judge})});
  const regrade=regradeFactory({receipts,completion,...(coordinatorFactory===undefined?{}:{coordinatorFactory})});
  if(typeof regrade!=='function')throw new TypeError('Grading recovery service required');
  const assessmentDependencies=Object.freeze({receipts,progress,...(personaBindings===undefined?{}:{personaBindings})});
  const core=Object.freeze({receipts,progress,completion,regrade,assessmentDependencies,
    listJudgments(userId){return receipts.listRecoverable({userId,judgeVersion:require('../agent-runtime/objectiveJudge').JUDGE_VERSION});}});
  cores.add(core);coreMetadata.set(core,Object.freeze({identityPool,personaBindings,assessmentDependencies}));return core;
}
function resolveObjectiveGradingDependencies(core,{identityPool,personaBindings}={}){
  const metadata=coreMetadata.get(core);
  if(!metadata||identityPool!==metadata.identityPool)throw new TypeError('Matching objective grading core and identity pool required');
  if(Object.prototype.hasOwnProperty.call(arguments[1]||{},'personaBindings')
      &&personaBindings!==metadata.personaBindings)throw new TypeError('Objective grading persona adapter mismatch');
  if(core.assessmentDependencies!==metadata.assessmentDependencies
      ||core.assessmentDependencies.receipts!==core.receipts
      ||core.assessmentDependencies.progress!==core.progress
      ||core.assessmentDependencies.personaBindings!==metadata.personaBindings)
    throw new TypeError('Objective grading assessment dependencies mismatch');
  return metadata.assessmentDependencies;
}
function createDeferredObjectiveGrading() {
  let installed;
  return Object.freeze({
    install(core){
      if(installed)throw Object.assign(new Error('Objective grading is already installed'),{code:'GRADING_CORE_ALREADY_INSTALLED'});
      if(!cores.has(core))throw new TypeError('A constructed objective grading core is required');
      installed=core;
    },
    async listJudgments(userId){if(!installed)throw notReady();return installed.listJudgments(userId);},
    async regrade(input){if(!installed)throw notReady();return installed.regrade(input);},
  });
}
module.exports={createObjectiveGradingCore,createDeferredObjectiveGrading,resolveObjectiveGradingDependencies};
