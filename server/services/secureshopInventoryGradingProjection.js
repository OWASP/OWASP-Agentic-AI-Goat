'use strict';
const {UUID}=require('./secureshopCouponContract');
// Public status only. Never expose the retained packet, receipt, trace or provider.
function inventoryGradingProjection(value){
 const judgment=value?.judgment;
 if(judgment&&UUID.test(judgment.evaluationId||'')&&['pass','fail','inconclusive','unavailable'].includes(judgment.verdict))return{status:'evaluated',completed:value.completed===true&&judgment.verdict==='pass',judgment:{evaluationId:judgment.evaluationId,verdict:judgment.verdict,canRetry:judgment.verdict==='unavailable'&&judgment.canRetry===true}};
 return{status:['disabled','ineligible','unavailable'].includes(value?.status)?value.status:'unavailable',completed:false};
}
module.exports={inventoryGradingProjection};
