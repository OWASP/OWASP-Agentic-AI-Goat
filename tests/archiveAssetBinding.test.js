'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{createHash}=require('node:crypto');
const {captureAssetBundle}=require('../db/postgres/asset-bundle');
const {bindAndRestoreArchiveAssets,isArchiveAssetBindingProof}=require('../db/postgres/archive-asset-binding');
async function fixture(fn){const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-binding-'));try{
 const sourceRoot=path.join(root,'source');await fs.mkdir(sourceRoot);await fs.writeFile(path.join(sourceRoot,'opaque.svg'),'<svg onload="fixture()"/>');
 const bundle=await captureAssetBundle({sourceRoot,relativePaths:['opaque.svg'],destinationRoot:path.join(root,'bundle')});
 const ref={source:'secureshop.db',table:'product_images',key:'7',column:'path',path:'../../opaque-teaching.svg'};
 const mapping={source:ref.source,table:ref.table,key:ref.key,column:ref.column,referenceSha256:createHash('sha256').update(ref.path).digest('hex'),sourcePath:'opaque.svg',targetPath:'uploads/opaque.svg'};
 const input={archiveDigest:'a'.repeat(64),assetReferences:[ref],bundleRoot:bundle.bundleRoot,expectedManifestDigest:bundle.manifestDigest,destinationRoot:path.join(root,'restored'),mappings:[mapping]};await fn(input);
 }finally{await fs.rm(root,{recursive:true,force:true});}}
test('binds exact opaque DB references to verified staged bytes without rewriting or activation',async()=>fixture(async input=>{
 const proof=await bindAndRestoreArchiveAssets(input);assert.equal(isArchiveAssetBindingProof(proof),true);assert.equal(isArchiveAssetBindingProof({...proof}),false);
 assert.equal(proof.activated,false);assert.equal(proof.databaseReferencesRewritten,false);assert.equal(input.assetReferences[0].path,'../../opaque-teaching.svg');
 assert.equal(await fs.readFile(path.join(proof.assetRoot,'uploads/opaque.svg'),'utf8'),'<svg onload="fixture()"/>');
 assert.equal(proof.referenceDigest,createHash('sha256').update(JSON.stringify(input.assetReferences)).digest('hex'));
}));
test('stale reference hash, wrong column, missing mapping and unknown bundle file fail before restore',async()=>fixture(async input=>{
 for(const mutate of [x=>x.assetReferences[0].path='changed',x=>x.mappings[0].column='avatar_path',x=>x.mappings=[],x=>x.mappings[0].sourcePath='absent']){
  const x=structuredClone(input);mutate(x);await assert.rejects(bindAndRestoreArchiveAssets(x));await assert.rejects(fs.stat(input.destinationRoot),{code:'ENOENT'});
 }
}));
test('multiple references may bind one shared asset but conflicting targets cannot',async()=>fixture(async input=>{
 const second={...input.assetReferences[0],key:'8'};input.assetReferences.push(second);input.mappings.push({...input.mappings[0],key:'8',targetPath:'different.svg'});
 await assert.rejects(bindAndRestoreArchiveAssets(input),{code:'CONFLICTING_ARCHIVE_ASSET_BINDING'});
 input.mappings[1].targetPath=input.mappings[0].targetPath;assert.equal((await bindAndRestoreArchiveAssets(input)).mappings.length,2);
}));
