'use strict';
const {isDeepStrictEqual}=require('node:util');
const C=require('./secureshopConversationalCommerceContract');
const Profile=require('./secureshopProfileUpdateContract');
const SHA=/^[a-f0-9]{64}$/;
function proposal(value){
 if(!C.exact(value,['version','proposalId','scopeKey','expectedSnapshotSha256','requestSha256','before','after','patch'])
  ||value.version!==1||!SHA.test(value.scopeKey)||!SHA.test(value.expectedSnapshotSha256)
  ||!SHA.test(value.requestSha256))throw C.fail('COMMERCE_STATE_INVALID');
 const proposalId=C.uuid(value.proposalId),before=Profile.normalizeProfileView(value.before),
  patch=Profile.normalizeProfilePatch(value.patch),after=Profile.normalizeProfileView(value.after);
 if(!isDeepStrictEqual(after,Profile.normalizeProfileView({...before,...patch})))throw C.fail('COMMERCE_STATE_INVALID');
 if(value.requestSha256!==Profile.profileRequestDigest({operationId:proposalId,
  expectedSnapshotSha256:value.expectedSnapshotSha256,fields:after}))throw C.fail('COMMERCE_STATE_INVALID');
 return Object.freeze({version:1,proposalId,scopeKey:value.scopeKey,
  expectedSnapshotSha256:value.expectedSnapshotSha256,requestSha256:value.requestSha256,
  before,after,patch});
}
module.exports={proposal};
