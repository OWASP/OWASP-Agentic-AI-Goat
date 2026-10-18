'use strict';
const assert=require('node:assert/strict');
if(process.env.SQL_NOSQL_OFFLINE_COMPOSITION!=='1')throw Error('Offline composition admission required');

const deny=()=>{throw Object.assign(Error('Offline composition attempted I/O'),{code:'OFFLINE_IO_FORBIDDEN'});};
global.fetch=deny;
for(const name of ['node:net','node:http','node:https','node:dns']){
 const module=require(name);
 for(const method of ['connect','createConnection','request','get','lookup','resolve','resolve4','resolve6']){
  if(typeof module[method]==='function')module[method]=deny;
 }
}

process.env.PLATFORM_DATABASE_ENGINE='postgres';
process.env.WORKSHOP_DATABASE_ENGINE='postgres';
process.env.MCP_WORKSHOP_AUTOSTART='false';
process.env.MCP_SIDECARS_AUTOSTART='false';
process.env.SS_ENABLE='false';
process.env.JWT_SECRET='offline-composition-only-00000000000000000000000000000000';
process.env.IDENTITY_DATABASE_URL='postgresql://offline@127.0.0.1:1/offline';

// Load the actual HTTP route graph and force the seed's lazy curriculum imports.
const originalLog=console.log;
console.log=()=>{};
assert.ok(require('../../server/routes/sqlWorkshop'));
assert.ok(require('../../server/routes/nosqlWorkshop'));
const seed=require('../../server/database/postgres/workshopPlatformSeed');
assert.ok(seed.solutionFixtures().sql_injection_workshop);
assert.ok(seed.solutionFixtures().nosql_injection_workshop);

const inertStore={};
const inertModel={provider:'fixture',async generateResponse(){throw Error('Offline model invocation forbidden');}};
const inertLedger={};
assert.equal(typeof require('../../server/services/ariaAgentService')
  .createAgent({store:inertStore,model:inertModel,runLedger:inertLedger}).invoke,'function');
assert.equal(typeof require('../../server/services/novaAgentService')
  .createAgent({store:inertStore,model:inertModel,runLedger:inertLedger}).invoke,'function');

const noDatabase={query:deny,connect:deny};
const judgments=require('../../server/database/postgres/objectiveJudgmentRepository')
  .createObjectiveJudgmentRepository(noDatabase,{xssBindings:{}});
assert.equal(typeof judgments.beginEvaluation,'function');
assert.equal(typeof require('../../server/services/workshopObjectiveGrader')
  .createWorkshopObjectiveGrader({workshopKey:'sql_injection_workshop',postgres:true}).evaluate,'function');
console.log=originalLog;

const admission=require('../../server/agent-runtime/effectAdmissionContext');
const execution={ownerKey:'["offline","1"]',runId:'00000000-0000-4000-8000-000000000001',durableGeneration:'0'};
admission.withEffectAdmission(execution,'offline:effect',async()=>{
 assert.deepEqual(admission.currentEffectAdmission(execution),{ledgerEffectKey:'offline:effect'});
}).then(()=>process.stdout.write('SQL_NOSQL_OFFLINE_COMPOSITION_READY\n'));
