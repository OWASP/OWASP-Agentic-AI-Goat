'use strict';
// Private write-ahead resource identity. Persist before Docker create; never
// adopt an existing foreign identity or rotate credentials during recovery.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const managed=require('../../server/services/secureshopPricingManagedConfiguration');
const {workspaceId}=require('../application-data-root');
const {validateAuthorityState,authorityDigest}=require('../local-docker-authority');
const KEYS=['version','workspaceId','ownerId','dockerAuthoritySha256','packageSha256','imageId','port','token'];
const fail=()=>Object.assign(Error('Owned Pricing provisioning stage conflict'),{code:'PRICING_PROVISION_STAGE_CONFLICT'});
function validate(value,root){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join()!==[...KEYS].sort().join())throw fail();
 const id=workspaceId(root);
 managed.validate({...value,enabled:false,containerName:'owasp-ai-goat-pricing-'+id,containerId:'0'.repeat(64),profile:'owasp-ai-goat-owned-pricing-http-'+id},{root});
 return Object.freeze(Object.fromEntries(KEYS.map(key=>[key,value[key]])));
}
function location(options){return path.join(managed.paths(options).directory,'pricing-provisioning.json');}
function read(options){
 try{const captured=managed._private.captureFile(location(options),16384);return Object.freeze({value:validate(JSON.parse(captured.bytes),options.root),sha256:captured.sha256,identity:Object.freeze(captured.identity)});}catch(error){if(error.code==='ENOENT')return null;throw fail();}
}
function prepare({root,home,plan,imageId}={}){
 const directory=managed.paths({root,home}).directory;
 const authority=validateAuthorityState(JSON.parse(managed._private.captureFile(path.join(directory,'local-docker.json'),8192).bytes),{workspaceId:workspaceId(root)});
 if(!plan||plan.workspaceId!==workspaceId(root)||authorityDigest(authority)!==plan.dockerAuthoritySha256)throw fail();
 const existing=read({root,home});
 const expected={workspaceId:plan.workspaceId,dockerAuthoritySha256:plan.dockerAuthoritySha256,packageSha256:plan.source.sha256,imageId,port:plan.port};
 if(existing){if(Object.entries(expected).some(([key,value])=>existing.value[key]!==value))throw fail();return Object.freeze({created:false,...existing});}
 const current=managed.load({root,home});if(current&&Object.entries(expected).some(([key,value])=>current.config[key]!==value))throw fail();
 const value=validate({version:1,...expected,ownerId:current?.config.ownerId||crypto.randomUUID(),token:current?.config.token||crypto.randomBytes(32).toString('base64url')},root);
 managed._private.publishImmutable(location({root,home}),Buffer.from(JSON.stringify(value)+'\n'));
 return Object.freeze({created:true,...read({root,home})});
}
module.exports={prepare,read,location,validate};
