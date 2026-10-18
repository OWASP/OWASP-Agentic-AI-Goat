'use strict';
const {normalizeKeyedMailAudit}=require('./mailReplyKeyedAudit');
const {VERSION}=require('./mailReplySourceComparison');
const {VERSION:PREVIOUS}=require('./mailReplyKeyedComparison');
function normalizeSourceOnlyMailAudit(input,result){
 if(input?.version!==VERSION||(input.observation&&input.observation.version!==VERSION))throw Error('Invalid source-only mail audit version');
 const normalized=normalizeKeyedMailAudit({...input,version:PREVIOUS,...(input.observation?{observation:{...input.observation,version:PREVIOUS}}:{})},result);
 return {...normalized,version:VERSION,...(normalized.observation?{observation:{...normalized.observation,version:VERSION}}:{})};
}
module.exports={normalizeSourceOnlyMailAudit};
