'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const file='tests/postgres/run-listings-integrated-isolated.py';
for(const incompatible of ['--actual8b','--actual-grading','--actual-grading-browser','--full-app-retry','--catalog-candidate','--rendered-catalog','--production-assembly','--saved-evidence'])test('DPI display cohort rejects mixed qualification mode '+incompatible,()=>{
 const result=spawnSync('python3',['-B',file,'--docker-host','deliberately-not-a-daemon','--dpi-rendered',incompatible],{encoding:'utf8',timeout:5000});
 assert.equal(result.status,1);assert.match(result.stderr,/DPI rendered mode cannot enable model or Listings effect branches/);assert.doesNotMatch(result.stderr,/docker|Traceback/);
});
test('DPI display cohort requires explicit dependency inventory before any resource preparation',()=>{
 const result=spawnSync('python3',['-B',file,'--docker-host','deliberately-not-a-daemon','--dpi-rendered'],{encoding:'utf8',timeout:5000});assert.equal(result.status,1);assert.match(result.stderr,/full application requires explicit dependency hashes/);
});
