'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {captureAssetBundle}=require('../db/postgres/asset-bundle');
const {restoreAssetBundle,verifyRestoredAssetBundle,isAssetRestoreProof}=require('../db/postgres/restore-asset-bundle');
async function fixture(fn){const root=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-restore-'));try{
 const source=path.join(root,'source');await fs.mkdir(source);const bytes=Buffer.from([0,255,60,115,99,114,105,112,116,62]);await fs.writeFile(path.join(source,'raw.svg'),bytes);
 const bundle=await captureAssetBundle({sourceRoot:source,relativePaths:['raw.svg'],destinationRoot:path.join(root,'bundle')});
 const input={bundleRoot:bundle.bundleRoot,expectedManifestDigest:bundle.manifestDigest,destinationRoot:path.join(root,'restore'),bindings:[{sourcePath:'raw.svg',targetPath:'uploads/raw.svg'}]};await fn({root,bytes,bundle,input});
 }finally{await fs.rm(root,{recursive:true,force:true});}}
test('restores exact opaque bytes into private new staging without activating or rewriting DB references',async()=>fixture(async({bytes,input})=>{
 const proof=await restoreAssetBundle(input);assert.equal(isAssetRestoreProof(proof),true);assert.equal(isAssetRestoreProof({...proof}),false);assert.equal(proof.activated,false);
 assert.deepEqual(await fs.readFile(path.join(proof.assetRoot,'uploads/raw.svg')),bytes);
 assert.equal((await fs.stat(proof.destinationRoot)).mode&0o777,0o700);assert.equal((await fs.stat(path.join(proof.assetRoot,'uploads/raw.svg'))).mode&0o777,0o600);
 await assert.rejects(fs.stat(path.join(proof.destinationRoot,'INCOMPLETE')),{code:'ENOENT'});
 await assert.rejects(restoreAssetBundle(input),{code:'ASSET_RESTORE_DESTINATION_EXISTS'});
}));
test('verifies an existing restore staging tree without mutating or activating it',async()=>fixture(async({bytes,input})=>{
 const created=await restoreAssetBundle(input);
 const manifestPath=path.join(created.destinationRoot,'restore.json');
 const before=await fs.readFile(manifestPath);
 const proof=await verifyRestoredAssetBundle({destinationRoot:created.destinationRoot,expectedRestoreManifestDigest:created.restoreManifestDigest});
 assert.equal(isAssetRestoreProof(proof),true);
 assert.equal(proof.activated,false);
 assert.equal(proof.restoreManifestDigest,created.restoreManifestDigest);
 assert.deepEqual(await fs.readFile(path.join(proof.assetRoot,'uploads/raw.svg')),bytes);
 assert.deepEqual(await fs.readFile(manifestPath),before);
 await assert.rejects(verifyRestoredAssetBundle({destinationRoot:created.destinationRoot,expectedRestoreManifestDigest:'0'.repeat(64)}),{code:'ASSET_RESTORE_MANIFEST_MISMATCH'});
 await fs.writeFile(path.join(proof.assetRoot,'unexpected.bin'),Buffer.from('extra'));
 await assert.rejects(verifyRestoredAssetBundle({destinationRoot:created.destinationRoot,expectedRestoreManifestDigest:created.restoreManifestDigest}),{code:'ASSET_RESTORE_FILE_SET_MISMATCH'});
}));
test('rejects stale digest, missing/duplicate bindings and traversal before creating destination',async()=>fixture(async({input})=>{
 const cases=[{expectedManifestDigest:'0'.repeat(64)},{bindings:[]},{bindings:[...input.bindings,...input.bindings]},{bindings:[{sourcePath:'raw.svg',targetPath:'../escape'}]},{bindings:[{sourcePath:'raw.svg',targetPath:'C:\\escape'}]}];
 for(const change of cases){await assert.rejects(restoreAssetBundle({...input,...change}));await assert.rejects(fs.stat(input.destinationRoot),{code:'ENOENT'});}
}));
test('does not trust modified captured files or an existing symlink destination',async()=>fixture(async({root,bundle,input})=>{
 await fs.symlink(path.join(root,'source'),input.destinationRoot);await assert.rejects(restoreAssetBundle(input),{code:'ASSET_RESTORE_DESTINATION_EXISTS'});await fs.unlink(input.destinationRoot);
 await fs.appendFile(path.join(bundle.bundleRoot,bundle.files[0].bundlePath),'changed');await assert.rejects(restoreAssetBundle(input));await assert.rejects(fs.stat(input.destinationRoot),{code:'ENOENT'});
}));
test('mutation between verification and copy leaves an incomplete owned staging directory',async()=>fixture(async({bundle,input})=>{
 const original=fs.open;let reads=0;const file=path.join(bundle.bundleRoot,bundle.files[0].bundlePath);
 fs.open=async function(name,...args){if(name===file&&++reads===2)await fs.appendFile(file,'late change');return original.call(this,name,...args);};
 try{await assert.rejects(restoreAssetBundle(input),{code:'ASSET_BUNDLE_CHANGED'});}finally{fs.open=original;}
 assert.ok(await fs.stat(path.join(input.destinationRoot,'INCOMPLETE')));
 await assert.rejects(fs.stat(path.join(input.destinationRoot,'restore.json')),{code:'ENOENT'});
 await assert.rejects(restoreAssetBundle({...input,bundleRoot:bundle.bundleRoot}));
}));
