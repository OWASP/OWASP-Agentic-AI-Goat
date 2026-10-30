'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {CASES,installCommitBoundary}=require('./fixtures/applicationMaintenanceInprocessOriginalProcess.cjs');
for(const stage of ['begin','finish'])test('loss occurs once after actual delegated '+stage+' COMMIT',async()=>{
 const calls=[];class Client{constructor(){this.connectionParameters={application_name:'owasp-ai-goat-maintenance-lease'};}async query(sql){calls.push(sql);return{rows:[]};}}
 const restore=installCommitBoundary(Client,stage+'-commit-loss',async m=>{assert.equal(calls.at(-1),'COMMIT');assert.equal(m.stage,stage);calls.push('observed');});
 try{const c=new Client();await c.query('BEGIN');await c.query('INSERT INTO dvaia_maintenance.'+(stage==='begin'?'epoch_replay_profiles':'epoch_finish_receipts'));await assert.rejects(c.query('COMMIT'),{code:'OWNED_COMMIT_RESPONSE_LOST'});await c.query('COMMIT');assert.equal(calls.filter(x=>x==='observed').length,1);}finally{restore();}
});
test('failed actual COMMIT is not counted as delegated loss and unrelated client is untouched',async()=>{
 let notifications=0;class Client{constructor(){this.connectionParameters={application_name:'owasp-ai-goat-maintenance-lease'};}async query(sql){if(sql==='COMMIT')throw Error('actual failure');return{};}}
 const restore=installCommitBoundary(Client,'begin-commit-loss',()=>{notifications++;});try{const c=new Client();await c.query('INSERT INTO dvaia_maintenance.epoch_replay_profiles');await assert.rejects(c.query('COMMIT'),/actual failure/);assert.equal(notifications,0);assert.throws(()=>installCommitBoundary(Client,'force-clear',()=>{}));assert.equal(CASES.length,4);}finally{restore();}
});

test('stage diagnostics preserve receiver, arguments, capability identity and original failure without secrets',async()=>{
 const {createStageDiagnostics}=require('./fixtures/applicationMaintenanceInprocessOriginalProcess.cjs');
 const diagnostic=createStageDiagnostics(),capability=Object.freeze({}),argument=Object.freeze({});
 const target={async operation(arg){assert.equal(this,target);assert.equal(arg,argument);return capability;}};
 diagnostic.wrap(target,'operation','initialize');assert.equal(await target.operation(argument),capability);
 const error=Object.assign(Error('secret URL password'),{code:'PRIVATE_SECRET',stack:'private stack'});
 target.failure=async()=>{throw error;};diagnostic.wrap(target,'failure','drain-inspect');
 await assert.rejects(target.failure(),e=>e===error);
 const result=diagnostic.snapshot(error);assert.equal(result.stage,'drain-inspect');assert.equal(result.lastCompleted,'initialize');assert.equal(result.code,'UNCLASSIFIED');assert(!JSON.stringify(result).includes('secret'));assert(!JSON.stringify(result).includes('private'));
 assert.equal(diagnostic.snapshot({code:'EACCES'}).code,'EACCES');
 for(let i=0;i<30;i++)await target.operation(argument);assert.equal(diagnostic.snapshot(error).events.length,24);
});
