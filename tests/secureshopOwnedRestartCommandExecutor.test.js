'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const {createRoleSystemRestartProposal}=require('../server/services/secureshopRoleSystemRestartProposal');
const {CAPABILITY}=require('../server/services/secureshopSystemRestartClient');
const {createOwnedRestartCommandExecutor,buildRestartArgv,decodeStatus,inspectEffects,INIT,SYSTEMCTL}=require('../sidecars/sandbox-runner/owned-system/restart-command-executor');
test('restart namespace argv is fixed, networkless, and exposes only owned effect plus synthetic systemctl',()=>{const argv=buildRestartArgv('systemctl restart nginx; touch /owned-effect/witness','/var/lib/dvaia-owned-restart/effects/op',['/usr','/bin']);assert.deepEqual(argv.slice(0,6),['--cap-drop','ALL','--cap-add','CAP_SETPCAP','--unshare-user','--unshare-net']);assert.ok(argv.includes('--unshare-pid'));assert.ok(argv.includes('--clearenv'));assert.deepEqual(argv.slice(-2),[INIT,'systemctl restart nginx; touch /owned-effect/witness']);const joined=argv.join('\n');assert.match(joined,new RegExp(SYSTEMCTL.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));assert.match(joined,/\/owned-effect/);assert.doesNotMatch(joined,/Users|home\/|\.env/);});
test('restart status requires private drained receipt',()=>{assert.deepEqual(decodeStatus(Buffer.from('R1 0 0 drained\n'),0),{exitCode:0,signal:null,drained:true});assert.throws(()=>decodeStatus(Buffer.from('R1 0 0\n'),0));});
test('effect receipt is independently derived from owned regular files',()=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'restart-effects-'));try{fs.writeFileSync(path.join(root,'systemctl.called'),'nginx\n',{mode:0o600});fs.writeFileSync(path.join(root,'witness'),'',{mode:0o600});const one=inspectEffects(root),two=inspectEffects(root);assert.equal(one.effectFiles,2);assert.equal(one.effectSha256,two.effectSha256);fs.symlinkSync('/etc/passwd',path.join(root,'bad'));assert.throws(()=>inspectEffects(root),/unavailable/);}finally{fs.rmSync(root,{recursive:true,force:true});}});
test('a generated v5 restart operation reaches owned executor admission; invalid IDs stop first',async()=>{
 const proposal=createRoleSystemRestartProposal({
  context:{scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:17,platformSessionId:19},persona:{id:23,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}},
  administration:{restartCapability:CAPABILITY,targetId:randomUUID()},source:{sessionId:randomUUID(),requestId:randomUUID()},origin:{step:2,callId:'restart-prepare'},name:'nginx',
  modeCapability:{version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'admin_assistant'}}});
 assert.equal(proposal.proposalId[14],'5');
 const reached=Error('executor assets reached');let checks=0;
 const executor=createOwnedRestartCommandExecutor({verify(){checks++;throw reached;}});
 await assert.rejects(executor.execute({command:`systemctl restart ${proposal.name}`,operationId:proposal.proposalId}),error=>error===reached);
 assert.equal(checks,1);
 for(const operationId of [proposal.proposalId.replace(/.$/,'/'),`${proposal.proposalId}/../other`,proposal.proposalId.toUpperCase(),'00000000-0000-6000-8000-000000000000']){
  await assert.rejects(executor.execute({command:'systemctl restart nginx',operationId}),TypeError);
 }
 assert.equal(checks,1);
});
