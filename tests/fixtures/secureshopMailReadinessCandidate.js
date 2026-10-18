'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
function promoteKnownFlag(text,before,after){assert(text.includes(before)!==text.includes(after),'Exact known qualification required');const marker=text.includes(before)?before:after;assert.equal(text.split(marker).length,2);return text.includes(before)?text.replace(before,after):text;}
function stageMailReadinessCandidate(root){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 for(const [file,before,after]of [
 ['server/services/secureshopMailProduction.js','const PRODUCTION_QUALIFIED=false;','const PRODUCTION_QUALIFIED=true;'],
 ['server/services/secureshopMailObjectiveReadiness.js','ss_mail_header_construction:false','ss_mail_header_construction:true']]){
  const p=path.join(root,file),text=fs.readFileSync(p,'utf8'),next=promoteKnownFlag(text,before,after);if(next!==text)fs.writeFileSync(p,next);
 }
}
module.exports={stageMailReadinessCandidate,promoteKnownFlag};
