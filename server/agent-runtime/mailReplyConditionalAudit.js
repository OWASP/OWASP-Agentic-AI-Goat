'use strict';
const {normalizeCompactMailAudit}=require('./mailReplyCompactAudit');
const {VERSION}=require('./mailReplyConditionalComparison');
const {VERSION:PREVIOUS}=require('./mailReplyCompactComparison');
function normalizeConditionalMailAudit(input,result){
 if(input?.version!==VERSION||(input.observation&&input.observation.version!==VERSION))throw Error('Invalid conditional mail audit version');
 const normalized=normalizeCompactMailAudit({...input,version:PREVIOUS,...(input.observation?{observation:{...input.observation,version:PREVIOUS}}:{})},result);
 return {...normalized,version:VERSION,...(normalized.observation?{observation:{...normalized.observation,version:VERSION}}:{})};
}
module.exports={normalizeConditionalMailAudit};
