import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/postgres'))
from acl_permission_execution import initializer_failure_summary as read
class Detail(unittest.TestCase):
    def test_actual_projector_and_reader(self):
        js=r'''
const {projectStartupDetail,projectStartupDiagnostic,reportStartupDiagnostic}=require('./server/services/applicationStartupDiagnostic');
const assert=require('node:assert/strict');
const error={code:'42P01',name:'TypeError',stack:'PRIVATE_SECRET\n    at f (/private/root/server/applicationServer.js:493:12)\n    at f (/private/root/secrets/PRIVATE_SECRET.js:1:2)',message:'PRIVATE_SECRET'};
const detail=projectStartupDetail(error);assert.deepEqual(detail,{version:1,code:'42P01',name:'TypeError',frames:[{file:'server/applicationServer.js',line:493,column:12}]});
const hostile={get code(){throw Error('secret');},get stack(){throw Error('secret');},get name(){throw Error('secret');}};
assert.equal(projectStartupDetail(hostile).code,'OTHER');
assert.equal(projectStartupDetail({code:'PRIVATE_SECRET',stack:'x'.repeat(16385)}).frames.length,0);
const cycle={};cycle.cause=cycle;assert.equal(projectStartupDiagnostic(cycle).reason,'UNCLASSIFIED_STARTUP_ERROR');
assert.doesNotThrow(()=>reportStartupDiagnostic(error,()=>{throw Error('sink');}));
reportStartupDiagnostic(error,(...args)=>process.stdout.write(require('node:util').format(...args)+'\n'));
'''
        raw=subprocess.check_output([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',js],cwd=ROOT,timeout=5)
        self.assertNotIn(b'PRIVATE_SECRET',raw)
        with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp') as directory:
            path=Path(directory)/'fixture';path.mkdir();log=path/'2.log';log.write_bytes(raw);log.chmod(0o600)
            result=read(directory,backend=True)
            self.assertEqual(result['detail']['code'],'42P01')
            self.assertEqual(result['detail']['frames'],[{'file':'server/applicationServer.js','line':493,'column':12}])
            for detail in [{'version':1,'code':'PRIVATE_SECRET','name':'Error','frames':[]},{'version':1,'code':'OTHER','name':'Error','frames':[{'file':'private/secret','line':1,'column':2}]}]:
                log.write_bytes(raw.split(b'application_start_detail ')[0]+b'application_start_detail '+json.dumps(detail).encode()+b'\n')
                self.assertNotIn('detail',read(directory,backend=True))
            prefix=raw.split(b'application_start_detail ')[0]
            invalid=[b'{',b'x'*2049,json.dumps({'version':1,'code':[],'name':'Error','frames':[]}).encode(),json.dumps({'version':1,'code':'OTHER','name':{},'frames':[]}).encode(),json.dumps({'version':1,'code':'OTHER','name':'Error','frames':[{'file':[],'line':1,'column':1}]}).encode()]
            for value in invalid:
                log.write_bytes(prefix+b'application_start_detail '+value+b'\n')
                result=read(directory,backend=True)
                self.assertEqual(result['status'],'retained');self.assertNotIn('detail',result)
            log.write_bytes(raw+raw[raw.index(b'application_start_detail '):])
            result=read(directory,backend=True)
            self.assertEqual(result['status'],'retained');self.assertNotIn('detail',result)
if __name__=='__main__':unittest.main()
