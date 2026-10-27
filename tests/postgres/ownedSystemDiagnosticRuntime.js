'use strict';
// Fixed code preparation only. No spawn, capability mint, or public runtime.
// The diagnostic driver must obtain Linux deadlines from its authenticated
// clock mapping and the branded common owner before dispatching these commands.
const crypto=require('node:crypto');
const consumer=require('./ownedSystemPrivateHttpConsumer')._internals;
const fail=code=>Object.assign(new Error(code),{code});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const positive=value=>typeof value==='number'&&Number.isFinite(value)&&value>0;
const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');

function operation(plan,binding,kind,settings,channelIds=[]){
 binding=consumer.validateBinding(binding);
 if(binding.target!=='original-v03-diagnostic'||plan?.target!=='original-v03-diagnostic'
  ||binding.runId!==plan.runId||binding.inputSha256!==plan.captured?.inputSha256)
  throw fail('DIAGNOSTIC_RUNTIME_BINDING');
 const keys={start:'deadline,runtimeDeadline,token',inspect:'deadline',
  'claim-cohort':'deadline,cohort',stop:'deadline'}[kind];
 if(!keys||!exact(settings,keys)||!positive(settings.deadline))throw fail('DIAGNOSTIC_RUNTIME_SETTINGS');
 if(kind==='start'&&(!positive(settings.runtimeDeadline)||settings.runtimeDeadline<settings.deadline
  ||typeof settings.token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(settings.token)))throw fail('DIAGNOSTIC_RUNTIME_SETTINGS');
 if(kind==='claim-cohort'){
  const c=settings.cohort;
  if(!exact(c,'parentRunId,runId,combinedPlanSha256,guestBootId,phase,startedAtMs,deadlineMs')
   ||c.runId!==binding.runId||! /^[a-f0-9]{32}$/.test(c.parentRunId||'')
   ||! /^[a-f0-9]{64}$/.test(c.combinedPlanSha256||'')||c.phase!=='cohortClaim'
   ||! /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(c.guestBootId||'')
   ||!Number.isSafeInteger(c.startedAtMs)||!Number.isSafeInteger(c.deadlineMs)
   ||c.startedAtMs<0||c.deadlineMs-c.startedAtMs!==1210000||c.deadlineMs/1000<settings.deadline)
   throw fail('DIAGNOSTIC_RUNTIME_SETTINGS');
 }
 const template=consumer.operationProgram(binding,kind,channelIds);
 if(template.helperSha256!==plan.helperHashes?.['tests/postgres/owned_system_private_http_channel.py'])
  throw fail('DIAGNOSTIC_RUNTIME_SOURCE');
 const input=Buffer.from(JSON.stringify(settings));
 if(input.length>4096)throw fail('DIAGNOSTIC_RUNTIME_INPUT');
 return Object.freeze({name:'diagnostic-runtime-'+kind,
  command:'/usr/bin/python3 -I -S -B -c '+quote(template.source),
  input,sourceSha256:hash(template.source),helperSha256:template.helperSha256});
}

function validateCohortClaim(binding,value){
 consumer.validateBinding(binding);
 if(binding.target!=='original-v03-diagnostic'||!exact(value,'version,runId,target,claimed')
  ||value.version!==1||value.runId!==binding.runId||value.target!==binding.target||value.claimed!==true)
  throw fail('DIAGNOSTIC_COHORT_UNPROVEN');
 return value;
}

module.exports={operation,validateCohortClaim};
