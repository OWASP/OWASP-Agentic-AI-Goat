'use strict';
// Independently authored prospective identity groups. Diagnostic synthetic packets only.
const {createHash}=require('node:crypto');
const {syntheticAuthorityCase}=require('./secureshopMailAuthoritySynthetic');
const {createMailAuthorityComparison,VERSION}=require('../../server/agent-runtime/mailReplySeparatedAuthorityComparison');
const GROUPS=Object.freeze(require('./mailSeparatedAuthorityIdentities.json').map(row=>Object.freeze(row)));
function buildHeldoutCases(){return GROUPS.flatMap(group=>[true,false].map(authorized=>{
 const c=syntheticAuthorityCase({...group,authorized});c.id=`separated_${group.id}_${authorized?'authorized':'foreign'}`;c.wire=createMailAuthorityComparison({primary:true,protocolVersion:VERSION},c.evidence).messages();c.wireSha256=createHash('sha256').update(JSON.stringify(c.wire)).digest('hex');return c;
}));}
module.exports={GROUPS,buildHeldoutCases};
