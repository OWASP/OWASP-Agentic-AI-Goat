import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/postgres'))
class Shape(unittest.TestCase):
 def test_actual_transformed_emitter_and_reader(self):
  code=r'''
const fs=require('node:fs'),Module=require('node:module'),assert=require('node:assert/strict'),vm=require('node:vm');
const d=require('./server/services/applicationStartupDiagnostic');let callbacks=0;
class Custom extends Error{}
assert.equal(d.projectStartupShape(new Error('PRIVATE_SECRET')).prototype,'builtin');
for(const e of [new Custom('PRIVATE_SECRET'),vm.runInNewContext('new Error("PRIVATE_SECRET")')]){const s=d.projectStartupShape(e);assert.equal(s.kind,'native');assert.equal(s.prototype,'other');assert.equal(d.projectStartupDetail(e).name,'OTHER');}
const hostile={get code(){callbacks++;},get name(){callbacks++;},get stack(){callbacks++;},get cause(){callbacks++;}};
assert.equal(d.projectStartupShape(hostile).stack,'accessor');assert.equal(callbacks,0);
const proxy=new Proxy({}, {getPrototypeOf(){callbacks++;throw Error();},getOwnPropertyDescriptor(){callbacks++;throw Error();}});
assert.equal(d.projectStartupShape(proxy).kind,'proxy');assert.equal(callbacks,0);
const cycle={};cycle.cause=cycle;assert.equal(d.projectStartupShape(cycle).cause,'data');
for(const v of [null,undefined,'PRIVATE_SECRET',42])assert.equal(d.projectStartupShape(v).kind,'primitive');
const old=Object.getOwnPropertyDescriptor(Error,'prepareStackTrace');
try{Object.defineProperty(Error,'prepareStackTrace',{configurable:true,get(){callbacks++;throw Error();}});d.projectStartupShape(new Error('PRIVATE_SECRET'));assert.equal(callbacks,0);}finally{if(old)Object.defineProperty(Error,'prepareStackTrace',old);else delete Error.prepareStackTrace;}
d.reportStartupDiagnostic(new Custom('PRIVATE_SECRET'),(...args)=>process.stdout.write(require('node:util').format(...args)+'\n'));
'''
  raw=subprocess.check_output([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',code],cwd=ROOT,timeout=10)
  self.assertNotIn(b'PRIVATE_SECRET',raw)
  from acl_permission_execution import initializer_failure_summary
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp') as directory:
   fixture=Path(directory)/'fixture';fixture.mkdir();log=fixture/'2.log';log.write_bytes(raw);log.chmod(0o600)
   read=lambda:initializer_failure_summary(directory,backend=True)
   result=read();self.assertEqual(result['shape']['kind'],'native');self.assertEqual(result['shape']['prototype'],'other');self.assertEqual(result['detail']['name'],'OTHER')
   prefix=raw.split(b'application_start_shape ')[0]
   for bad in [b'{',b'x'*513,b'{"version":1,"kind":[],"prototype":"other","code":"data","name":"absent","stack":"accessor","cause":"absent"}',b'{"version":1,"kind":"PRIVATE_SECRET"}']:
    log.write_bytes(prefix+b'application_start_shape '+bad+b'\n');r=read();self.assertEqual(r['status'],'retained');self.assertNotIn('shape',r);self.assertEqual(r['detail'],result['detail'])
   log.write_bytes(raw+raw[raw.index(b'application_start_shape '):]);self.assertNotIn('shape',read())
if __name__=='__main__':unittest.main()
