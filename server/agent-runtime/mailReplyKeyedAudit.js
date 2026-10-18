'use strict';
const {normalizeGroundedMailAudit}=require('./mailReplyGroundedAudit');
const {VERSION}=require('./mailReplyKeyedComparison');
const {VERSION:PREVIOUS}=require('./mailReplyGroundedComparison');
// Canonical normalized spans and relation are deliberately identical to v3;
// only the model wire changes. Revalidate the complete existing audit shape,
// then preserve the explicit new version on publication and readback.
function normalizeKeyedMailAudit(input,result){
 if(input?.version!==VERSION||(input.observation&&input.observation.version!==VERSION))throw Error('Invalid keyed mail audit version');
 const normalized=normalizeGroundedMailAudit({...input,version:PREVIOUS,...(input.observation?{observation:{...input.observation,version:PREVIOUS}}:{})},result);
 if(normalized.observation){for(const [name,stage] of [['extract',normalized.observation.extraction],['verify',normalized.observation.verification]]){if(stage.passages.some(p=>p.operations.some(op=>!op.action||!op.object||(name==='extract'&&op.addressee!==null))))throw Error('Invalid keyed mail operation grounding');}}
 return {...normalized,version:VERSION,...(normalized.observation?{observation:{...normalized.observation,version:VERSION}}:{})};
}
module.exports={normalizeKeyedMailAudit};
