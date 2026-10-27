'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {admitOwnedPricingRepoPaths}=require('./fixtures/secureshopPricingPrivatePaths');

test('owned Pricing chat accepts only a fresh private repository run root',()=>{
 const privateRoot=fs.mkdtempSync(path.join(process.env.TMPDIR||os.tmpdir(),'pricing-path-'));
 try{
  const workspace=path.join(privateRoot,'workspace');
  const qualificationRoot=path.join(workspace,'tasks','qualification');
  const runRoot=path.join(qualificationRoot,'run-abcdefgh');
  fs.mkdirSync(runRoot,{recursive:true,mode:0o700});
  fs.chmodSync(qualificationRoot,0o700);fs.chmodSync(runRoot,0o700);
  const descriptorPath=path.join(runRoot,'pricing-listener-descriptor.json');
  const evidence=path.join(runRoot,'merchant-pricing-chat-browser.json');
  fs.writeFileSync(descriptorPath,'{}',{mode:0o600});
  const input={workspace,descriptorPath,evidence};
  assert.equal(admitOwnedPricingRepoPaths(input),true);
  assert.throws(()=>admitOwnedPricingRepoPaths({...input,evidence:path.join(privateRoot,'outside.json')}));
  assert.throws(()=>admitOwnedPricingRepoPaths({...input,descriptorPath:path.join(runRoot,'other.json')}));
  fs.writeFileSync(evidence,'{}',{mode:0o600});
  assert.throws(()=>admitOwnedPricingRepoPaths(input));fs.rmSync(evidence);
  fs.chmodSync(runRoot,0o777);
  assert.throws(()=>admitOwnedPricingRepoPaths(input));
  fs.chmodSync(runRoot,0o700);
  const original=path.join(runRoot,'actual-descriptor.json');
  fs.renameSync(descriptorPath,original);fs.symlinkSync(original,descriptorPath);
  assert.throws(()=>admitOwnedPricingRepoPaths(input));
 }finally{fs.rmSync(privateRoot,{recursive:true,force:true});}
});
