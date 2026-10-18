'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
// Called only after the existing full-index fixture initializes all owned stores.
// Uses the supported managed installer, never a substituted SQL service.
async function prepareCouponFullApp({source,root,home,env}) {
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 assert.equal(fs.realpathSync(source),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 assert.equal(path.dirname(home),root);
 const environment={...env,DOCKER_HOST:process.env.DOCKER_HOST};
 assert.equal(environment.DOCKER_HOST,'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock');
 await require('../../scripts/install/analytics-setup').setupOwnedAnalytics({requested:true,explicitActivation:true,root:source,homeDirectory:home,environment,applicationEnvironment:env});
 const record=await require('../../server/services/secureshopAnalyticsManagedConfiguration').readManagedAnalyticsConfiguration({root:source,homeDirectory:home});
 assert.equal(record.config.enabled,true);
 env.SS_BOUND_COUPONS_ENABLED='true';env.DOCKER_HOST=environment.DOCKER_HOST;
 // Redacted resource identities only. The parent owns cleanup even if this
 // helper fails before producing the record, via the install intent on disk.
 const resources={container:record.config.containerName,containerId:record.config.containerId,volume:record.config.volumeName,workspaceId:record.config.workspaceId,ownerId:record.config.ownerId,port:record.config.port};
 fs.writeFileSync(path.join(root,'coupon-analytics-resources.json'),JSON.stringify(resources,null,2),{mode:0o600});
 return resources;
}
module.exports={prepareCouponFullApp};
