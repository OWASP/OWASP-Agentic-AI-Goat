'use strict';
// Explicit, read-only plan. Qualification input is supplied by the installer,
// never learned from the HTTP service whose identity it is supposed to verify.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {workspaceId}=require('../application-data-root');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest}=require('../local-docker-authority');
const managed=require('../../server/services/secureshopListingsManagedConfiguration');
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const fail=code=>Object.assign(new Error('Owned Listings installation unavailable'),{code});
const ROOTS=['sidecars/sandbox-runner/owned-listings','sidecars/sandbox-runner/owned-mcp-registry/package.json','sidecars/sandbox-runner/owned-mcp-registry/package-lock.json','sidecars/sandbox-runner/owned-mcp-registry/process-supervisor.c','sidecars/sandbox-runner/owned-http/namespace-init.c','sidecars/sandbox-runner/mcpSeccompFilter.c','server/services/secureshopListingRequestContract.js','tests/fixtures/secureshopOwnedListingsPackaged.native.cjs','tests/fixtures/secureshopListingsSharedManager.native.cjs'];
function sourceManifest(root){
 const files={};
 function visit(name){const file=path.join(root,name),stat=fs.lstatSync(file);if(stat.isSymbolicLink())throw fail('LISTINGS_INSTALL_SOURCE_INVALID');if(stat.isDirectory()){for(const child of fs.readdirSync(file).sort())visit(name+'/'+child);}else{if(!stat.isFile()||stat.size>1048576)throw fail('LISTINGS_INSTALL_SOURCE_INVALID');files[name]=sha(fs.readFileSync(file));}}
 for(const name of ROOTS)visit(name);
 const sorted=Object.fromEntries(Object.entries(files).sort(([a],[b])=>a.localeCompare(b)));
 return Object.freeze({sha256:sha(JSON.stringify(sorted)),files:Object.freeze(sorted)});
}
async function plan({root=path.resolve(__dirname,'../..'),home=os.homedir(),platform=process.platform,architecture,port,runtimeDigest,qualifiedSourceSha256,execute,environment=process.env,existingQualification}={}){
 if(!path.isAbsolute(root)||!path.isAbsolute(home)||!['linux','darwin'].includes(platform)||architecture!=='arm64')throw fail('LISTINGS_INSTALL_PLATFORM_UNQUALIFIED');
 if(!/^[a-f0-9]{64}$/.test(runtimeDigest||'')||!/^[a-f0-9]{64}$/.test(qualifiedSourceSha256||''))throw fail('LISTINGS_INSTALL_QUALIFICATION_REQUIRED');
 const filePath=managed.managedPath({root,home}),existing=managed.load({filePath});
 const source=existingQualification===undefined?sourceManifest(root):require('./secureshop-owned-listings-qualified-candidate').installedSourceFor(existingQualification,existing);
 if(source.sha256!==qualifiedSourceSha256)throw fail('LISTINGS_INSTALL_SOURCE_UNQUALIFIED');
 const id=workspaceId(root),directory=path.join(home,'.dvaia',id),authority=await readLocalDockerAuthority({directory,workspaceId:id,platform});
 if(!authority)throw fail('LISTINGS_INSTALL_AUTHORITY_REQUIRED');await verifyDockerAuthority({authority,execute,environment});
 const profileName='dvaia-owned-listings-'+id;
 const profileBytes=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profileName);
 const profile=Object.freeze({name:profileName,sha256:sha(profileBytes)});
 // Existing installations retain their selected port. Fresh installations use
 // the bounded owned Listings port, distinct from the owned MCP registry.
 if(port===undefined)port=existing?Number(new URL(existing.manager.url).port):8099;
 if(!Number.isInteger(port)||port<1024||port>65535)throw fail('LISTINGS_INSTALL_PORT_INVALID');
 const manager=Object.freeze({container:profileName,url:'http://127.0.0.1:'+port}),dockerAuthoritySha256=authorityDigest(authority);
 if(existing&&(existing.workspaceId!==id||existing.sourceManifestSha256!==source.sha256||existing.runtimeDigest!==runtimeDigest||existing.dockerAuthoritySha256!==dockerAuthoritySha256||existing.profile.sha256!==profile.sha256||existing.manager.url!==manager.url))throw fail('LISTINGS_INSTALL_EXISTING_CONFLICT');
 return Object.freeze({version:1,mutating:false,ready:false,capabilityAvailable:false,workspaceId:id,architecture,managedPath:filePath,source,runtimeDigest,profile,manager,dockerAuthoritySha256,existing:!!existing,enabled:existing?.enabled===true,imageId:existing?.imageId||null});
}
module.exports={plan,sourceManifest};
