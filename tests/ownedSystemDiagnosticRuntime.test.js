'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const runtime=require('./postgres/ownedSystemDiagnosticRuntime');
const consumer=require('./postgres/ownedSystemPrivateHttpConsumer')._internals;
const runId='a'.repeat(32),inputSha256='c'.repeat(64);
const binding=()=>({version:1,target:'original-v03-diagnostic',runId,imageId:'sha256:'+'b'.repeat(64),
 inputSha256,daemonId:'d'.repeat(36),physical:{privateDockerHost:'unix:///var/tmp/owasp-ai-goat-v23-build-'+runId+'/fs/docker.sock',
 namespaceInode:'net:[12345]',filesystemIdentity:{device:1,inode:2},
 daemonProcess:{pid:101,startTicks:'100',exe:'/usr/bin/dockerd'},namespaceHolder:{pid:102,startTicks:'101',exe:'/usr/bin/sleep'}}});
const helper='tests/postgres/owned_system_private_http_channel.py';
const cohort=()=>({parentRunId:'e'.repeat(32),runId,combinedPlanSha256:'d'.repeat(64),
 guestBootId:'01234567-0123-0123-0123-012345678901',phase:'cohortClaim',startedAtMs:100000,deadlineMs:1310000});
const plan=()=>({target:'original-v03-diagnostic',runId,captured:{inputSha256},helperHashes:{[helper]:
 crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__dirname,'..',helper))).digest('hex')}});

test('fixed operations keep token exclusively in bounded private input and bind current helper',()=>{
 const p=plan(),b=binding(),token='X'.repeat(43);
 for(const [kind,settings]of [['start',{deadline:100,runtimeDeadline:200,token}],
  ['inspect',{deadline:100}],['claim-cohort',{deadline:100,cohort:cohort()}],['stop',{deadline:100}]]){
  const op=runtime.operation(p,b,kind,settings);
  assert.equal(op.name,'diagnostic-runtime-'+kind);assert.deepEqual(JSON.parse(op.input),settings);
  assert.ok(!op.command.includes(token));assert.ok(op.command.startsWith('/usr/bin/python3 -I -S -B -c '));
 }
 assert.throws(()=>runtime.operation({...p,helperHashes:{}},b,'inspect',{deadline:100}),{code:'DIAGNOSTIC_RUNTIME_SOURCE'});
});
test('foreign target, caller command, nonfinite deadlines and channel misuse fail before dispatch',()=>{
 const p=plan(),b=binding();
 for(const target of ['original-v24-system','original-v24-policy','foreign'])
  assert.throws(()=>runtime.operation(p,{...b,target},'inspect',{deadline:100}));
 for(const settings of [{deadline:Infinity},{deadline:NaN},{deadline:true},{deadline:100,command:'x'}])
  assert.throws(()=>runtime.operation(p,b,'inspect',settings));
 assert.throws(()=>runtime.operation(p,b,'start',{deadline:100,runtimeDeadline:99,token:'x'.repeat(43)}));
 assert.throws(()=>runtime.operation(p,b,'claim-cohort',{deadline:100,cohortDeadline:99}));
 for(const delta of [{phase:'start'},{deadlineMs:1310001},{guestBootId:'bad'},{runId:'f'.repeat(32)},
  {startedAtMs:true},{extra:true}])assert.throws(()=>runtime.operation(p,b,'claim-cohort',{deadline:100,cohort:{...cohort(),...delta}}));
 assert.throws(()=>runtime.operation(p,b,'inspect',{deadline:100},['e'.repeat(32)]));
 assert.throws(()=>runtime.operation(p,b,'arbitrary',{deadline:100}));
});
test('diagnostic observations cannot be confused with original System or policy receipts',()=>{
 const b=binding(),row={version:1,runId,target:b.target,claimed:true};
 assert.equal(runtime.validateCohortClaim(b,row),row);
 for(const changed of [{...row,target:'original-v24-system'},{...row,claimed:false},{...row,extra:true}])
  assert.throws(()=>runtime.validateCohortClaim(b,changed));
 const observed={version:1,runId,target:b.target,imageId:b.imageId,containerId:'f'.repeat(64),running:true,namespaceInode:12345};
 assert.equal(consumer.validateRuntime(b,observed),observed);
 assert.throws(()=>consumer.validateRuntime(b,{...observed,target:'original-v24-system'}));
 assert.throws(()=>consumer.validateRuntime(b,{...observed,namespaceInode:12346}));
});
