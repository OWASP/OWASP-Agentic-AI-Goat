'use strict';
const {createHash}=require('node:crypto');
const {verifyAssetBundle,MAX_FILES}=require('./asset-bundle');
const {restoreAssetBundle}=require('./restore-asset-bundle');
const PROOFS=new WeakSet();
const hash=value=>createHash('sha256').update(value).digest('hex');
function fail(code){throw Object.assign(new Error(code),{code});}
function exact(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==keys.split(' ').sort().join(','))fail('INVALID_ARCHIVE_ASSET_BINDING');}
function address(value){return JSON.stringify([value.source,value.table,value.key,value.column]);}
/** Caller supplies mapper output. This primitive neither opens an archive DB nor rewrites references. */
async function bindAndRestoreArchiveAssets(input={}){
 exact(input,'archiveDigest assetReferences bundleRoot expectedManifestDigest destinationRoot mappings');
 const {archiveDigest,assetReferences,bundleRoot,expectedManifestDigest,destinationRoot,mappings}=structuredClone(input);
 if(typeof archiveDigest!=='string'||!/^[a-f0-9]{64}$/.test(archiveDigest)||!Array.isArray(assetReferences)||!Array.isArray(mappings)||assetReferences.length>MAX_FILES||mappings.length!==assetReferences.length)fail('INVALID_ARCHIVE_ASSET_BINDING');
 const refs=new Map();
 for(const ref of assetReferences){
  exact(ref,'source table key column path');
  if(Object.values(ref).some(v=>typeof v!=='string'||!v||v.includes('\0')))fail('INVALID_ARCHIVE_ASSET_REFERENCE');
  const key=address(ref);if(refs.has(key))fail('DUPLICATE_ARCHIVE_ASSET_REFERENCE');refs.set(key,ref);
 }
 const used=new Set(),bySource=new Map(),byTarget=new Map(),bound=[];
 for(const mapping of mappings){
  exact(mapping,'source table key column referenceSha256 sourcePath targetPath');
  const key=address(mapping),ref=refs.get(key);
  if(!ref||used.has(key)||mapping.referenceSha256!==hash(ref.path))fail('ARCHIVE_ASSET_REFERENCE_MISMATCH');
  used.add(key);
  if(typeof mapping.sourcePath!=='string'||typeof mapping.targetPath!=='string')fail('INVALID_ARCHIVE_ASSET_BINDING');
  if((bySource.has(mapping.sourcePath)&&bySource.get(mapping.sourcePath)!==mapping.targetPath)||(byTarget.has(mapping.targetPath)&&byTarget.get(mapping.targetPath)!==mapping.sourcePath))fail('CONFLICTING_ARCHIVE_ASSET_BINDING');
  bySource.set(mapping.sourcePath,mapping.targetPath);byTarget.set(mapping.targetPath,mapping.sourcePath);
  bound.push(Object.freeze({...mapping}));
 }
 const bundle=await verifyAssetBundle(bundleRoot);
 if(bundle.manifestDigest!==expectedManifestDigest)fail('ARCHIVE_ASSET_BUNDLE_MISMATCH');
 if(bySource.size!==bundle.files.length||bundle.files.some(f=>!bySource.has(f.sourcePath)))fail('INCOMPLETE_ARCHIVE_ASSET_COVERAGE');
 const restored=await restoreAssetBundle({bundleRoot,expectedManifestDigest,destinationRoot,bindings:[...bySource].map(([sourcePath,targetPath])=>({sourcePath,targetPath}))});
 const proof=Object.freeze({archiveDigest,referenceDigest:hash(JSON.stringify(assetReferences)),bundleManifestDigest:bundle.manifestDigest,restoreManifestDigest:restored.restoreManifestDigest,destinationRoot:restored.destinationRoot,assetRoot:restored.assetRoot,mappings:Object.freeze(bound),activated:false,databaseReferencesRewritten:false});
 PROOFS.add(proof);return proof;
}
function isArchiveAssetBindingProof(value){return PROOFS.has(value);}
module.exports={bindAndRestoreArchiveAssets,isArchiveAssetBindingProof};
