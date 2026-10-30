'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {requireToolResult}=require('./fixtures/ctfSetupExternalEffects');
test('external-effect proof rejects HTTP success with blocked/error tool output',()=>{
 for(const body of [{error:{code:-32603}},{result:{isError:true,content:[{text:'not executed'}]}},{result:{content:[]}}])assert.throws(()=>requireToolResult(200,body));
 assert.throws(()=>requireToolResult(503,{result:{isError:false,content:[{text:'claimed'}]}}));
 assert.equal(requireToolResult(200,{result:{isError:false,content:[{type:'text',text:'actual output'}]}}),'actual output');
});

test('retirement proof requires exact subject scope and completed receipt, not blanket OK',()=>{
 const {requireRetirement}=require('./fixtures/ctfSetupExternalEffects');const scope={targetId:'owned',platformOwnerId:17,platformSessionId:2,generation:0};
 const value={targetId:'owned',ownerId:17,platformSessionId:2,generation:0,operationId:'op',status:'completed',cleanupPending:false,receiptSha256:'a'.repeat(64)};
 requireRetirement(value,scope,'op');
 for(const change of [{ownerId:18},{status:'pending'},{cleanupPending:true},{operationId:'other'},{receiptSha256:'invalid'}])assert.throws(()=>requireRetirement({...value,...change},scope,'op'));
 assert.throws(()=>requireRetirement({ok:true},scope,'op'));
});


test('fixture profile matches actual strict client receipt schema; diagnostics never retain arbitrary fields',async()=>{
 const {execFileSync}=require('node:child_process');
 const profile=execFileSync('python3',['-B','-c',"import sys;sys.path.insert(0,'tests/postgres');from ctf_setup_sidecars import OwnedSidecars;from types import SimpleNamespace;print(OwnedSidecars(SimpleNamespace(),'.','.', 'a'*32,None,None).profile)"],{encoding:'utf8',timeout:10000,maxBuffer:16384}).trim();
 const {createMcpOwnedTargetClient}=require('../server/services/mcp/ownedTargetClient');
 const client=name=>createMcpOwnedTargetClient({baseURL:'http://127.0.0.1:1',token:'a'.repeat(48),fetchImpl:async()=>({ok:true,json:async()=>({version:'mcp-owned-target-http.v1',ready:true,isolation:'bwrap-seccomp-v1',supervisorProfile:name+' (enforce)'})})});
 assert.equal((await client(profile).readiness()).runnerReady,true);
 await assert.rejects(client('owasp-ai-goat-ctf-'+'a'.repeat(32)).readiness(),{code:'MCP_OWNED_TARGET_UNAVAILABLE'});
 const {readinessDiagnostic}=require('./fixtures/ctfSetupExternalEffects');
 const diagnostic=readinessDiagnostic([{status:'rejected',reason:new Error('private token URL')},{status:'fulfilled',value:{ready:false,smtp:true,api:false,token:'private',endpoint:'private'}}]);
 assert.deepEqual(diagnostic,{sandbox:{ready:false,runnerReady:false,reason:'readiness_rejected'},mail:{ready:false,smtp:true,api:false,reason:'receipt_not_ready'}});
 assert(!JSON.stringify(diagnostic).includes('private'));
});
