'use strict';
const assert=require('node:assert/strict');
const id='ss_mail_reply_redirect';
// Disposable qualification copy only. Derived catalog sets and predicates must
// consume the same candidate row; promoted source is a strict byte-for-byte no-op.
function stageMailReplyCandidateCatalog(source){
 const lines=source.split('\n'),matches=lines.map((line,index)=>line.includes(`{ id: '${id}',`)?index:-1).filter(index=>index>=0);
 assert.equal(matches.length,1,'Exact reply catalog row required');const index=matches[0];
 if(lines[index].includes("qualification: 'native-model'"))return source;
 assert(lines[index].includes("qualification: 'pending'"),'Reviewed pending reply required');
 lines[index]=lines[index].replace("qualification: 'pending'","qualification: 'native-model'");return lines.join('\n');
}
module.exports={stageMailReplyCandidateCatalog};
