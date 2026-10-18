'use strict';
const {createHash}=require('node:crypto');
const sha=value=>createHash('sha256').update(value).digest('hex');
const fail=()=>Object.assign(Error('Analytics protected-column evidence invalid'),{code:'ANALYTICS_RECEIPT_MISMATCH'});
function exact(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))throw fail();}
function validateProtectedEvidence(value,result){
 exact(value,['version','observations','truncated']);if(value.version!==1||typeof value.truncated!=='boolean'||!Array.isArray(value.observations)||value.observations.length>32)throw fail();const seen=new Set();
 for(const item of value.observations){exact(item,['rowIndex','column','category','relation','attribute','valueSha256']);
  if(!Number.isSafeInteger(item.rowIndex)||item.rowIndex<0||item.rowIndex>=result.rows.length||!result.columns.includes(item.column)||item.category!=='synthetic_api_key'||item.relation!=='shop_users'||item.attribute!=='api_key'||!/^[a-f0-9]{64}$/.test(item.valueSha256))throw fail();
  const key=JSON.stringify([item.rowIndex,item.column]),observed=result.rows[item.rowIndex][item.column];if(seen.has(key)||typeof observed!=='string'||!/^SYNTHETIC_KEY_[a-f0-9]{48}$/.test(observed)||sha(observed)!==item.valueSha256)throw fail();seen.add(key);
 }
 return value;
}
module.exports={validateProtectedEvidence};
