'use strict';
const {createHash}=require('node:crypto');
// Raw owned review snapshot. The model's fixed-mode redaction is not a CAS version.
function reviewSnapshotSha256(row){
 const at=value=>value==null?null:new Date(value).toISOString();
 const value={id:row.id,productId:row.productId,authorId:row.authorId,body:row.body,
  rating:row.rating,status:row.status,moderatorKind:row.moderatorKind??null,
  moderatorNotes:row.moderatorNotes??null,createdAt:at(row.createdAt),moderatedAt:at(row.moderatedAt)};
 if(!Number.isSafeInteger(value.id)||!Number.isSafeInteger(value.productId)||!Number.isSafeInteger(value.authorId)
  ||typeof value.body!=='string'||!Number.isSafeInteger(value.rating)||!['pending','approved','rejected'].includes(value.status))
  throw Object.assign(new Error('Review snapshot unavailable'),{code:'INVALID_REVIEW_RESULT'});
 return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
module.exports={reviewSnapshotSha256};
