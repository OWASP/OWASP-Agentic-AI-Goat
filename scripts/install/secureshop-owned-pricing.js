'use strict';
// Read-only local installation planning. This module cannot build, install a
// profile, generate a credential, write a private record or create a container.
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {workspaceId}=require('../application-data-root');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest}=require('../local-docker-authority');
const {capturePricingPackage,PRICING_PACKAGE_FILES}=require('../../server/services/secureshopPricingPackage');
const managed=require('../../server/services/secureshopPricingManagedConfiguration');
const QUALIFICATION='tasks/sidecar-pricing-package-qualified-2026-09-26.json';
const fail=code=>Object.assign(Error('Owned Pricing installation plan unavailable'),{code});
const DEFAULT_PORT=8096;
function qualifiedSource(root){
 const filename=path.join(root,'sidecars/sandbox-runner/owned-pricing-http/local-package-manifest.json');
 let fd;
 try{
  fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const before=fs.fstatSync(fd);
  if(!before.isFile()||before.nlink!==1||before.size>16384)throw fail('PRICING_PACKAGE_MANIFEST_INVALID');
  const bytes=fs.readFileSync(fd),after=fs.fstatSync(fd),named=fs.lstatSync(filename);
  if(bytes.length!==before.size||before.ino!==named.ino||before.dev!==named.dev||named.isSymbolicLink()||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw fail('PRICING_PACKAGE_MANIFEST_INVALID');
  const value=JSON.parse(bytes),captured=capturePricingPackage(root);
  if(!value||Object.keys(value).sort().join()!=='architecture,files,qualification,sha256,version'||value.version!==1||value.architecture!=='arm64'||value.qualification!==QUALIFICATION||value.sha256!==captured.sha256||JSON.stringify(Object.keys(value.files).sort())!==JSON.stringify(PRICING_PACKAGE_FILES)||PRICING_PACKAGE_FILES.some(file=>value.files[file]!==captured.files[file]))throw fail('PRICING_PACKAGE_SOURCE_CHANGED');
  return Object.freeze({...captured,qualification:QUALIFICATION});
 }catch(error){if(error.code?.startsWith('PRICING_'))throw error;throw fail('PRICING_PACKAGE_MANIFEST_INVALID');}
 finally{if(fd!==undefined)fs.closeSync(fd);}
}
async function plan({root=path.resolve(__dirname,'../..'),home=os.homedir(),platform=process.platform,architecture=process.arch,port,environment=process.env,execute}={}){
 if(!path.isAbsolute(root)||!path.isAbsolute(home)||!['darwin','linux'].includes(platform)||architecture!=='arm64')throw fail('PRICING_INSTALL_PLATFORM_UNQUALIFIED');
 if(port!==undefined&&(!Number.isInteger(port)||port<1024||port>65535))throw fail('PRICING_INSTALL_PORT_INVALID');
 const id=workspaceId(root),directory=path.join(home,'.owasp-ai-goat',id),source=qualifiedSource(root);
 const authority=await readLocalDockerAuthority({directory,workspaceId:id,platform});
 if(!authority)throw fail('PRICING_INSTALL_AUTHORITY_REQUIRED');
 await verifyDockerAuthority({authority,execute,environment});
 const record=managed.load({root,home}),selectedPort=port??record?.config.port??DEFAULT_PORT;
 if(record&&(record.config.dockerAuthoritySha256!==authorityDigest(authority)||record.config.packageSha256!==source.sha256||record.config.port!==selectedPort))throw fail('PRICING_INSTALL_EXISTING_CONFLICT');
 return Object.freeze({version:1,mutating:false,workspaceId:id,architecture:'arm64',dockerAuthoritySha256:authorityDigest(authority),source,container:'owasp-ai-goat-pricing-'+id,network:'owasp-ai-goat-pricing-'+id+'-network',profile:'owasp-ai-goat-owned-pricing-http-'+id,port:selectedPort,existing:!!record,enabled:record?.config.enabled===true,imageId:record?.config.imageId??null,namespaceProfileVerified:false,resources:Object.freeze({memoryBytes:536870912,cpu:1,pids:128,tmpfsBytes:134217728,user:'10001:10001',readOnlyRoot:true,hostMounts:false,loopbackOnlyPublication:true,outerEgressIsolation:false}),next:'Explicit provisioning must reconcile exact owned resources and actual private readiness before compare-and-swap activation; profile installation remains separately scoped.'});
}
module.exports={plan,qualifiedSource,DEFAULT_PORT};
