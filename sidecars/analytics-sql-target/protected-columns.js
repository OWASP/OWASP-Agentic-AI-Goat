'use strict';
const {createHash}=require('node:crypto');
const sha=value=>createHash('sha256').update(value).digest('hex');
const MAX_OBSERVATIONS=32;
// PostgreSQL supplies field origins; labels/SQL text cannot assert ownership.
function protectedColumns({fields,rows,origin}){
 if(!Array.isArray(fields)||!Array.isArray(rows)||!Number.isSafeInteger(origin?.tableId)||origin.tableId<1||!Number.isSafeInteger(origin?.columnId)||origin.columnId<1)throw TypeError('Protected column catalog origin required');
 const columns=fields.filter(field=>field.tableID===origin.tableId&&field.columnID===origin.columnId&&typeof field.name==='string');
 const observations=[];let truncated=false;
 for(let rowIndex=0;rowIndex<rows.length;rowIndex++)for(const field of columns){const value=rows[rowIndex]?.[field.name];if(typeof value!=='string'||!/^SYNTHETIC_KEY_[a-f0-9]{48}$/.test(value))continue;if(observations.length===MAX_OBSERVATIONS){truncated=true;continue;}observations.push({rowIndex,column:field.name,category:'synthetic_api_key',relation:'shop_users',attribute:'api_key',valueSha256:sha(value)});}
 return {version:1,observations,truncated};
}
module.exports={protectedColumns,MAX_OBSERVATIONS};
