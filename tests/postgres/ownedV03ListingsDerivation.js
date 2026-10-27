'use strict';
// Fixed second domain of the reviewed V03 parent-bound holder derivation.
// Neither this source-only loader nor its serialized result is live authority.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto'),Module=require('node:module');
const shared=require('./ownedV03DiagnosticDerivation');
const fail=code=>Object.assign(new Error(code),{code});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
async function loadListingsBounded(){
 const filename=path.join(__dirname,'ownedMcpBoundedBuild.js');
 if(await fs.realpath(filename)!==filename)throw fail('V03_LISTINGS_DERIVATION_PATH');
 const handle=await fs.open(filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);let source;
 try{
  const before=await handle.stat();
  if(!before.isFile()||before.nlink!==1||before.size>1024**2)throw fail('V03_LISTINGS_DERIVATION_FILE');
  source=await handle.readFile('utf8');const after=await handle.stat();
  if(['dev','ino','size','mtimeMs','ctimeMs'].some(key=>before[key]!==after[key]))throw fail('V03_LISTINGS_DERIVATION_CHANGED');
 }finally{await handle.close();}
 const text=shared.deriveListingsSource(source),derived=new Module(filename,module);
 derived.filename=filename;derived.paths=Module._nodeModulePaths(__dirname);
 derived._compile(text,filename);
 return Object.freeze({bounded:derived.exports,sourceSha256:sha(source),derivedSha256:sha(text),
  target:'original-v03-listings-combined-owner-v1',executionApproved:false});
}
module.exports={loadListingsBounded};
