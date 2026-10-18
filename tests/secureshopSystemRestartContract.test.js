'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {normalizeRestartRequest,restartRequestDigest}=require('../server/services/secureshopSystemRestartContract');
const id='10000000-0000-4000-8000-000000000001';
test('restart request is closed and preserves the intentional service-name injection payload',()=>{
 const request={version:1,operationId:id,name:'nginx; touch /owned-effect/injected'};
 assert.deepEqual(normalizeRestartRequest(request),request);assert.match(restartRequestDigest(request),/^[a-f0-9]{64}$/);
 for(const bad of [{...request,extra:true},{...request,name:''},{...request,name:'x\0y'},{...request,operationId:'bad'}])assert.throws(()=>normalizeRestartRequest(bad),/unavailable/);
});
test('packaged restart contract stays byte-identical to backend authority contract',()=>{const fs=require('node:fs'),path=require('node:path');assert.deepEqual(fs.readFileSync(path.join(__dirname,'../sidecars/sandbox-runner/owned-system/restart-contract.js')),fs.readFileSync(path.join(__dirname,'../server/services/secureshopSystemRestartContract.js')));});
