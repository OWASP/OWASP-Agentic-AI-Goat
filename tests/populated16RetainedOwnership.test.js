'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {runRetainedOwnershipInitializer,retainedPlatformTargets,retainedOwnershipReceipt,verifyRetainedOwnershipPrivateState}=require('./release-inputs/populated16-rehearsal.cjs');
const {assertResult,publish,RESULT_KEYS}=require('./release-inputs/populated16-retained-ownership.cjs');

test('retained ownership receipt requires preserved sixteen stores, a platform target, and collision isolation',()=>{
 const platform=retainedPlatformTargets({descriptor:{targets:[{authorityKind:'platform',sceneId:null},{authorityKind:'shop-tenant',sceneId:'a'}]}});
 const receipt=retainedOwnershipReceipt({restored:Array.from({length:16},()=>({})),platformTargets:platform,
  collision:{principalsDistinct:true,platformPermissions:0,restoredReceiptActorIsolated:true}});
 assert.deepEqual(Object.keys(receipt).sort(),RESULT_KEYS.slice().sort());assert.doesNotThrow(()=>assertResult(receipt));
 assert.equal(retainedPlatformTargets({descriptor:{targets:[{authorityKind:'platform',sceneId:'linked'}]}}).length,1);
 assert.throws(()=>retainedPlatformTargets({descriptor:{targets:[{authorityKind:'shop-tenant',sceneId:null}]}}));
 assert.throws(()=>retainedOwnershipReceipt({restored:Array.from({length:15},()=>({})),platformTargets:platform,
  collision:{principalsDistinct:true,platformPermissions:0,restoredReceiptActorIsolated:true}}));
 assert.throws(()=>assertResult({...receipt,fullSetupProven:true}));
});

test('retained initializer stages admitted environment and invokes canonical initialization with no injected scope',async()=>{
 const original=process.env.A21_RETAINED_CONTROLLED;let calls=0;
 try{await runRetainedOwnershipInitializer({environment:{A21_RETAINED_CONTROLLED:'yes'},initialize:async(...args)=>{calls++;assert.deepEqual(args,[]);}});
  assert.equal(calls,1);assert.equal(process.env.A21_RETAINED_CONTROLLED,'yes');
 }finally{if(original===undefined)delete process.env.A21_RETAINED_CONTROLLED;else process.env.A21_RETAINED_CONTROLLED=original;}
});


test('retained migration preserves archived CTF authority bytes without activating authority state',()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'a21-retained-private-')));
 try{const archive=(name,contents)=>{const file=path.join(root,'archived-'+name);fs.writeFileSync(file,contents,{mode:0o600});return file;};
  const authority=archive('authority','installed-authority\n'),delivery=archive('delivery','installed-delivery\n'),pending=archive('pending','installed-pending\n');
  const deliveryTarget=path.join(root,'ctf-delivery.json'),pendingTarget=path.join(root,'ctf-delivery.json.pending');fs.writeFileSync(deliveryTarget,'owned-delivery\n',{mode:0o600});fs.writeFileSync(pendingTarget,'owned-pending\n',{mode:0o600});
  const entries=[
   {name:'ctf-authority.json',archivePath:authority,archivedSha256:require('node:crypto').createHash('sha256').update(fs.readFileSync(authority)).digest('hex'),target:path.join(root,'ctf-authority.json')},
   {name:'ctf-delivery.json',archivePath:delivery,archivedSha256:require('node:crypto').createHash('sha256').update(fs.readFileSync(delivery)).digest('hex'),target:deliveryTarget},
   {name:'ctf-delivery.json.pending',archivePath:pending,archivedSha256:require('node:crypto').createHash('sha256').update(fs.readFileSync(pending)).digest('hex'),target:pendingTarget},
  ];
  assert.deepEqual(verifyRetainedOwnershipPrivateState(entries),{archivedAuthorityBytesPreserved:true,disposableDeliveryRegenerated:true,noActiveAuthorityState:true});
  fs.writeFileSync(entries[0].target,'forbidden\n',{mode:0o600});assert.throws(()=>verifyRetainedOwnershipPrivateState(entries));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('retained result publication accepts only a private owned evidence directory',()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'a21-retained-result-')));
 try{fs.chmodSync(root,0o700);const receipt={status:'passed',scope:'retained-ownership-migrations-v1',restoredStores:16,canonicalLeaseRuns:2,
   retainedPlatformTargets:1,allStoresPreserved:true,collisionChecksPassed:true,noAutomaticLinking:true,noPrivilegedSurrogate:true,fullSetupProven:false,installedWrites:false};
  assert.doesNotThrow(()=>assertResult(receipt));
  const file=publish(root,'result.json',receipt),stat=fs.lstatSync(file);
  assert.equal(stat.isFile(),true);assert.equal(stat.nlink,1);assert.equal(stat.mode&0o777,0o600);
  assert.throws(()=>publish(root,'result.json',receipt));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
