'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process'),fs=require('node:fs');
const worker='sidecars/sandbox-runner/owned-mcp-registry/invocation-worker.js';
test('worker malformed input reports closed phase without attacker text',()=>{
 const secret='PRIVATE_TOKEN_DO_NOT_LOG';
 const result=spawnSync(process.execPath,[worker],{input:secret,encoding:'utf8',timeout:3000});
 assert.equal(result.status,70);assert.equal(result.stdout,'');assert.equal(result.stderr,'DVAIA_WORKER_FAILURE phase=2 category=1\n');assert(!result.stderr.includes(secret));
});
test('worker claim validation failure reports only closed phase',()=>{
 const result=spawnSync(process.execPath,[worker],{input:JSON.stringify({secret:'PRIVATE_TOKEN_DO_NOT_LOG'}),encoding:'utf8',timeout:3000});
 assert.equal(result.status,70);assert.equal(result.stderr,'DVAIA_WORKER_FAILURE phase=3 category=1\n');assert.equal(result.stdout,'');
});
test('supervisor diagnostics never interpolate child output and keep uncertain discard',()=>{
 const source=fs.readFileSync('sidecars/sandbox-runner/owned-mcp-registry/invocation-supervisor.c','utf8');
 const log=source.match(/fprintf\(stderr,"DVAIA_SUPERVISOR_RESULT[^;]+;/)[0];
 assert(!log.includes('%s'));assert(!log.includes('r->output'));assert(log.includes('r->size'));assert(source.includes('r->size=4;memcpy(r->output,"null",4)'));
});
test('fixture records authenticated receipt privately before positive assertion',()=>{
 const source=fs.readFileSync('tests/fixtures/secureshopOwnedMcpInvocationOs.native.js','utf8');
 assert(source.includes("signer.verify('receipt',wire)"));assert(source.includes('O_EXCL|fs.constants.O_NOFOLLOW,0o600'));assert(source.includes('fs.fsyncSync(fd);claimReceiptSaved=true'));assert(source.indexOf("signer.verify('receipt',wire)")<source.indexOf("assert.equal(positive.state,'completed')"));
});
