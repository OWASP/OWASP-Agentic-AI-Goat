'use strict';
const {main}=require('./pricingManualActualJudgeCalibration');
const {STRONG_JUDGE}=require('./pricingDirectiveGroupsActualJudge');
if(require.main===module)main({judgeIdentity:STRONG_JUDGE}).catch(()=>{console.error('Pricing manual Judge calibration unavailable');process.exitCode=1;});
module.exports={main,STRONG_JUDGE};
