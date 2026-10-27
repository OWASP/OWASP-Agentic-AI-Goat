'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

function admitOwnedPricingRepoPaths({workspace,descriptorPath,evidence}){
 const qualificationRoot=path.join(workspace,'tasks','qualification');
 const runRoot=path.dirname(evidence);
 assert.equal(path.dirname(runRoot),qualificationRoot);
 assert.match(path.basename(runRoot),/^run-[a-z0-9_]{8}$/);
 assert.equal(descriptorPath,path.join(runRoot,'pricing-listener-descriptor.json'));
 assert.equal(evidence,path.join(runRoot,'merchant-pricing-chat-browser.json'));
 for(const directory of [qualificationRoot,runRoot]){
  const state=fs.lstatSync(directory);
  assert.ok(state.isDirectory()&&!state.isSymbolicLink());
  assert.equal(state.uid,process.getuid());
  assert.equal(state.mode&0o077,0);
  assert.equal(fs.realpathSync(directory),directory);
 }
 const descriptor=fs.lstatSync(descriptorPath);
 assert.ok(descriptor.isFile()&&!descriptor.isSymbolicLink());
 assert.equal(descriptor.uid,process.getuid());
 assert.equal(descriptor.mode&0o077,0);
 assert.equal(descriptor.nlink,1);
 assert.equal(fs.realpathSync(descriptorPath),descriptorPath);
 assert.throws(()=>fs.lstatSync(evidence),error=>error&&error.code==='ENOENT');
 return true;
}
module.exports={admitOwnedPricingRepoPaths};
