'use strict';
const {main}=require('./pricingManualActualJudgeCalibration');
const {STRONG_JUDGE}=require('./pricingDirectiveGroupsActualJudge');
if(require.main===module)main({judgeIdentity:STRONG_JUDGE,contract:'v5'}).catch(()=>{console.error('Pricing manual V5 Judge calibration unavailable');process.exitCode=1;});
