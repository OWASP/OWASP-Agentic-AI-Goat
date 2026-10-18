'use strict';
const {createBoundedSourceClassificationEvaluation}=require('./boundedSourceClassificationEvaluation');
function createMailReplyEvaluation(options){return createBoundedSourceClassificationEvaluation({...options,auditField:'mailReplyComparison',eventPrefix:'judge_mail',label:'mail source'});}
module.exports={createMailReplyEvaluation};
