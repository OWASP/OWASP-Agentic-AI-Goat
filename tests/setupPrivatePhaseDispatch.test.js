'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {privatePhaseCommand}=require('./fixtures/setupPrivatePhaseDispatch');
test('private setup rebases only canonical initializer and retains private cwd contract',()=>{
 const args=['server/database/sensitiveInfoFiles.js','--initialize-missing'];
 assert.deepEqual(privatePhaseCommand(process.execPath,args,'/owned/installation','/owned/installation'),[path.resolve(__dirname,'../server/database/sensitiveInfoFiles.js'),'--initialize-missing']);
 assert.deepEqual(args,['server/database/sensitiveInfoFiles.js','--initialize-missing']);
});
test('private setup rejects executable, arguments and installation mismatches',()=>{
 const valid=[process.execPath,['server/database/sensitiveInfoFiles.js','--initialize-missing'],'/owned/installation','/owned/installation'];
 for(const [index,value]of [[0,'node'],[1,['server/index.js','--initialize-missing']],[1,['server/database/sensitiveInfoFiles.js','--reset']],[1,['server/database/sensitiveInfoFiles.js','--initialize-missing','extra']],[2,'/main'],[3,'relative']]){const values=[...valid];values[index]=value;assert.throws(()=>privatePhaseCommand(...values));}
});

test('private phase failure exposes only bounded codes and migration basename',()=>{
 const {privatePhaseFailure}=require('./fixtures/setupPrivatePhaseDispatch');
 assert.deepEqual(privatePhaseFailure({code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',message:'private',errors:[{code:'MIGRATION_FAILED',message:'private'},{code:'postgres://secret'},null],migration:'0127_fixture.sql',password:'private'}),{type:'failure',code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',causes:['MIGRATION_FAILED'],migration:'0127_fixture.sql'});
 assert.deepEqual(privatePhaseFailure({code:'private value',errors:'private',migration:'../0127_fixture.sql'}),{type:'failure',code:'SETUP_PHASE_FAILED',causes:[]});
 assert.equal(privatePhaseFailure({errors:Array.from({length:30},()=>({code:'SAFE'}))}).causes.length,16);
 assert.equal(privatePhaseFailure({migration:'0127_'+('a'.repeat(130))+'.sql'}).migration,undefined);
 assert.deepEqual(privatePhaseFailure(null),{type:'failure',code:'SETUP_PHASE_FAILED',causes:[]});
});

test('parent failure sanitizes string causes without accepting object or private fields',()=>{
 const {privateParentFailure}=require('./fixtures/setupPrivatePhaseDispatch');
 assert.deepEqual(privateParentFailure({code:'SETUP_PHASE_FAILED',causes:['MIGRATION_FAILED','private url',{code:'OBJECT_NOT_ALLOWED'}],migration:'0127_fixture.sql',message:'private'}),{code:'SETUP_PHASE_FAILED',causes:['MIGRATION_FAILED'],migration:'0127_fixture.sql'});
 assert.deepEqual(privateParentFailure({causes:'private',migration:'/private/0127.sql'}),{code:'SETUP_PHASE_FAILED',causes:[]});
 assert.equal(privateParentFailure({causes:Array(25).fill('SAFE')}).causes.length,16);
});
