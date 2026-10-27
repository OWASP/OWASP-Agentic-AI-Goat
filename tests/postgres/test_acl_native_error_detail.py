from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[2]
class NativeDetail(unittest.TestCase):
 def test_actual_native_and_hostile_controls(self):
  script=r'''
const {projectStartupDetail}=require('./server/services/applicationStartupDiagnostic');
const assert=require('node:assert/strict'),vm=require('node:vm');
const make=vm.runInThisContext('(function(){return new TypeError("PRIVATE_SECRET");})',{filename:process.cwd()+'/server/applicationServer.js'});
const error=make(),originalFormatter=Object.getOwnPropertyDescriptor(Error,'prepareStackTrace');
const detail=projectStartupDetail(error);assert.equal(detail.name,'TypeError');assert.equal(detail.frames[0].file,'server/applicationServer.js');assert.ok(!JSON.stringify(detail).includes('PRIVATE_SECRET'));
assert.deepEqual(Object.getOwnPropertyDescriptor(Error,'prepareStackTrace'),originalFormatter);
let called=0;Object.defineProperty(Error,'prepareStackTrace',{configurable:true,get(){called++;throw Error('SECRET');}});
const next=make();assert.equal(projectStartupDetail(next).name,'TypeError');assert.equal(called,0);
assert.equal(typeof Object.getOwnPropertyDescriptor(Error,'prepareStackTrace').get,'function');
Object.defineProperty(Error,'prepareStackTrace',originalFormatter);
Object.defineProperty(Function.prototype,'prepareStackTrace',{configurable:true,get(){called++;throw Error('SECRET');}});
assert.equal(projectStartupDetail(make()).frames.length,0);assert.equal(called,0);delete Function.prototype.prepareStackTrace;
for(const key of ['name','message','stack']){const e=make();Object.defineProperty(e,key,{configurable:true,get(){called++;throw Error('SECRET');}});projectStartupDetail(e);assert.equal(called,0);}
projectStartupDetail(new Proxy(error,{get(){called++;throw Error('SECRET');},getOwnPropertyDescriptor(){called++;throw Error('SECRET');}}));
assert.equal(called,0);
assert.ok(!JSON.stringify(projectStartupDetail(new Error('PRIVATE_SECRET'))).includes('PRIVATE_SECRET'));
const e=make();assert.equal(e.message,'PRIVATE_SECRET');projectStartupDetail(e);assert.equal(e.message,'PRIVATE_SECRET');
'''
  subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',script],cwd=ROOT,check=True,timeout=5)
if __name__=='__main__':unittest.main()
