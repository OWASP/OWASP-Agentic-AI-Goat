'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const launcher=path.join(__dirname,'run-ipi-email-canonical-migration-isolated.py');
function runPython(script){const result=spawnSync('/usr/bin/python3',['-c',script],{cwd:path.join(__dirname,'../..'),encoding:'utf8'});assert.equal(result.status,0,result.stderr||result.stdout);}
test('IPI launcher rejects grant identity drift and stale predecessor reuse without Docker',()=>runPython(`
import argparse, importlib.util, json, tempfile, sys
from pathlib import Path
sys.path.insert(0, str(Path(${JSON.stringify(path.join(__dirname))})))
spec=importlib.util.spec_from_file_location('l', ${JSON.stringify(launcher)}); l=importlib.util.module_from_spec(spec); spec.loader.exec_module(l)
values={'docker_host':'unix:///reviewed','docker_daemon_id':'daemon','postgres_image_id':'sha256:'+'a'*64,'docker_cli':'/bin/echo','docker_cli_sha256':'b'*64,'package':'/pkg/source','manifest':'/pkg/manifest.json','manifest_sha256':'c'*64,'node':'/node','node_sha256':'d'*64,'evidence_root':'/evidence','control':'/control','owner_handle':'12345','slot':'/slot'}
base={**values,'scope':l.SCOPE,'owner':'/root','status':'granted','allowedLaunches':1,'priorSlot':{'status':'terminal_fail_cleaned','cleanupVerified':True}}
l.validate_grant(base,values)
for mutator in [lambda x:x.update(scope='wrong'),lambda x:x.update(owner='/other'),lambda x:x.update(extra=True),lambda x:x.update(owner_handle='bad'),lambda x:x.pop('package')]:
 bad=dict(base);mutator(bad)
 try:l.validate_grant(bad,values);raise AssertionError('accepted invalid grant')
 except RuntimeError:pass
with tempfile.TemporaryDirectory() as d:
 root=Path(d); control=root/'control.json';slot=root/'slot.json'; evidence=root/'evidence'; evidence.mkdir()
 values['control']=str(control);values['slot']=str(slot);values['evidence_root']=str(evidence)
 base={**values,'scope':l.SCOPE,'owner':'/root','status':'granted','allowedLaunches':1,'priorSlot':{'status':'terminal_fail_cleaned','cleanupVerified':True}}
 control.write_text(json.dumps(base));slot.write_text(json.dumps(base['priorSlot']))
 control.chmod(0o600);slot.chmod(0o600)
 args=argparse.Namespace(**values)
 l.consume(args)
 consumed=json.loads(control.read_text());assert consumed['status']=='consumed'
 try:l.consume(args);raise AssertionError('accepted consumed grant')
 except RuntimeError:pass
 base['status']='granted';control.write_text(json.dumps(base));control.chmod(0o600)
 slot.write_text(json.dumps({'status':'terminal_fail_cleaned','cleanupVerified':True,'stale':True}))
 try:l.consume(args);raise AssertionError('accepted stale predecessor')
 except RuntimeError:pass
`));

test('IPI launcher parser requires complete ownership and package pins',()=>runPython(`
import importlib.util, sys
from pathlib import Path
sys.path.insert(0, str(Path(${JSON.stringify(path.join(__dirname))})))
spec=importlib.util.spec_from_file_location('l', ${JSON.stringify(launcher)}); l=importlib.util.module_from_spec(spec); spec.loader.exec_module(l)
required={a.dest for a in l.parser()._actions if a.dest!='help'}
assert required == {'docker_host','docker_daemon_id','postgres_image_id','docker_cli','docker_cli_sha256','package','manifest','manifest_sha256','node','node_sha256','evidence_root','control','owner_handle','slot'}
`));
