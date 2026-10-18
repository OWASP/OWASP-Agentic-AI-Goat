'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
const launcher=fs.readFileSync(path.join(root,'tests/postgres/run-finflow-route-isolated.py'),'utf8');
const inventory=JSON.parse(fs.readFileSync(path.join(root,'docs/modernization/drafts/finflow-route-admin-logs-v4-tracked-files-2026-09-14.json'),'utf8'));
const sourceHashManifest=JSON.parse(fs.readFileSync(path.join(root,'docs/modernization/drafts/finflow-route-admin-logs-v5-source-hash-manifest-2026-09-14.json'),'utf8'));
test('FinFlow native route launcher is a source-bound one-use owner gate',()=>{
 assert.match(launcher,/--grant-id/);assert.match(launcher,/--owner-handle-file/);assert.match(launcher,/WAITING_OWNER_HANDLE/);assert.match(launcher,/native-verification-slot\.json/);assert.match(launcher,/validate_grant/);assert.match(launcher,/verify_source_copy\(source,copy,tracked,granted=/);assert.match(launcher,/status='consumed'/);assert.match(launcher,/ownerHandle=owner_handle/);assert.match(launcher,/consumerPid=os\.getpid\(\)/);assert.match(launcher,/cleanup_owned/);assert.match(launcher,/terminal_pass_cleaned/);
 assert.match(launcher,/attempted=True;run\(docker\+\['run'/);assert.match(launcher,/cleanup_owned\(stop_child=stop_child/);assert.match(launcher,/if result\.exists\(\):state\['resultSha256'\]=sha\(result\)/);
 assert.match(launcher,/for command in postgres_store_setup\(stores\):run\(psql\+\['-c',command\]/);
 assert.match(launcher,/if profile=='historical-route-controls':return \('tests\/finflowLogArtifactAuthority\.test\.js','tests\/finflowRouteNativeLauncher\.test\.js',route\)/);
 assert.match(launcher,/execution_tests=caller_selection\(selected,a\.caller_profile\)/);
 assert.match(launcher,/if a\.caller_profile=='current':raise SystemExit\('FinFlow route launcher is retained for historical qualification only; use tests\/postgres\/run-setup-database-phase-isolated\.py with owner-bound finflow-policy or finflow-0055 scenarios'\)/);
});
test('FinFlow native route inventory protects the launcher, authority test, route test and artifact code',()=>{
 assert.equal(inventory.version,1);assert.deepEqual(inventory.trackedFiles,[...inventory.trackedFiles].sort());
 for(const name of ['tests/postgres/run-finflow-route-isolated.py','tests/postgres/finflowRoute.integration.test.js','tests/finflowLogArtifactAuthority.test.js','tests/objectiveJudgmentRepositoryMetadata.test.js','scripts/register-native-owner-handle.py','server/services/finflowLogArtifactReceipt.js','server/services/sensitiveInfoWorkshopAgent.js','docs/modernization/drafts/finflow_llm_request_log_default_content_guarded.sql','docs/modernization/drafts/finflow_log_default_content_snapshots.json','docs/modernization/drafts/generate_finflow_log_default_content_draft.js'])assert.ok(inventory.trackedFiles.includes(name),name);
});
test('FinFlow grant and source-copy gates reject invalid slots before a native launch',()=>{
 const script=`import sys,tempfile;from pathlib import Path;sys.path.insert(0,'tests/postgres');from finflow_native_gate import cleanup_owned,validate_grant;from native_source_provenance import verify_source_copy\nauthority={'canonical_workspace':'/canonical','candidate_source_root':'/candidate','candidate_manifest_sha256':'a'*64,'source_hashes':{'server/a.js':'b'*64}}\ngood={'grantId':'g','owner':'/root/dpi_release_gate','status':'granted','allowedLaunches':1,'dockerHost':'owned','canonicalWorkspaceRoot':'/canonical','candidateSourceRoot':'/candidate','candidateManifestSha256':'a'*64,'sourceHashes':authority['source_hashes']}\nvalidate_grant(good,grant_id='g',owner=good['owner'],docker_host='owned',**authority)\nfor key,value in [('status','consumed'),('allowedLaunches',2),('owner','other'),('candidateManifestSha256','c'*64)]:\n bad=dict(good);bad[key]=value\n try: validate_grant(bad,grant_id='g',owner=good['owner'],docker_host='owned',**authority)\n except RuntimeError: pass\n else: raise AssertionError(key)\nwith tempfile.TemporaryDirectory() as d:\n source=Path(d)/'source';copied=Path(d)/'copied';source.mkdir();copied.mkdir();(source/'a').write_text('one');(copied/'a').write_text('one');h=verify_source_copy(source,copied,['a']);\n try: verify_source_copy(source,copied,['a'],granted={'a':'wrong'})\n except RuntimeError: pass\n else: raise AssertionError('grant mismatch')\n (copied/'a').write_text('two')\n try: verify_source_copy(source,copied,['a'],granted=h)\n except RuntimeError: pass\n else: raise AssertionError('copy mismatch')\nevents=[]\ndef stop(): events.append('stop');raise RuntimeError('reap')\ndef remove(): events.append('remove');return 0\ndef absent(): events.append('absent');return True\nr=cleanup_owned(stop_child=stop,remove_container=remove,container_absent=absent);assert events==['stop','remove','absent'] and not r['clean'] and not r['childReaped']\nevents=[]\nr=cleanup_owned(stop_child=lambda:True,remove_container=lambda:(events.append('remove') or 1),container_absent=lambda:(events.append('absent') or True));assert events==['remove','absent'] and not r['clean']`;
 const result=require('node:child_process').spawnSync('python3',['-c',script],{cwd:root,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
});
test('FinFlow private secret, fixture sequencing, store setup, and owner-handle registration are executable preflight gates',()=>{
 const script=`import json,subprocess,sys,tempfile;from pathlib import Path;sys.path.insert(0,'tests/postgres');from finflow_native_gate import fixture_override_hashes,postgres_store_setup,private_jwt_secret
secret=private_jwt_secret();assert len(secret.encode())>=32
baselines={'server/sensitive_files/logs/access.log':{},'server/sensitive_files/logs/error.log':{},'server/sensitive_files/logs/audit.log':{},'server/sensitive_files/logs/llm_requests.log':{}}
fixtures={'server/sensitive_files/config/secrets.env':'secret','server/sensitive_files/config/llm_config.yml':'model','server/sensitive_files/etc/passwd':'root','server/sensitive_files/logs/access.log':'owned','server/config/secrets.env':'platform'}
overrides=fixture_override_hashes(baselines,fixtures);assert set(overrides)==set(fixtures) and overrides['server/sensitive_files/logs/access.log']['byteLength']==5
for bad_baselines,bad_overrides in [({},{}),(baselines,{'server/sensitive_files/logs/llm_requests.log':'forbidden'}),(baselines,{**fixtures,'server/sensitive_files/logs/llm_requests.log':'forbidden'})]:
 try: fixture_override_hashes(bad_baselines,bad_overrides)
 except RuntimeError: pass
 else: raise AssertionError('fixture sequencing')
commands=postgres_store_setup([('identity','identity_db'),('finflow','finflow_db')])
assert len(commands)==8
for family,database in [('identity','identity_db'),('finflow','finflow_db')]:
 assert f'CREATE ROLE dvaia_{family}_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' in commands
 assert f'CREATE ROLE dvaia_{family}_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' in commands
 assert f'CREATE DATABASE {database} OWNER dvaia_{family}_migration' in commands
 assert f'GRANT CONNECT ON DATABASE {database} TO dvaia_{family}_migration,dvaia_{family}_runtime' in commands[-1 if family=='finflow' else -5]
with tempfile.TemporaryDirectory() as d:
 grant=Path(d)/'grant.json';grant.write_text(json.dumps({'grantId':'g','owner':'/root/dpi_release_gate','status':'consumed','allowedLaunches':1,'consumerPid':123}))
 registered=subprocess.run([sys.executable,'scripts/register-native-owner-handle.py','--grant-file',str(grant),'--grant-id','g','--owner','/root/dpi_release_gate','--owner-handle','77'],capture_output=True,text=True,check=True)
 assert json.loads(registered.stdout)['ownerHandle']==77 and json.loads(grant.read_text())['ownerHandle']==77`;
 const result=require('node:child_process').spawnSync('python3',['-c',script],{cwd:root,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
});
test('FinFlow staging maps a valid explicit unit-only closure virtually and verifies tracked main bytes',()=>{
 const script=`import shutil,sys,tempfile,os;from pathlib import Path;sys.path.insert(0,'tests/postgres');from finflow_native_gate import stage_source_copy;from native_source_provenance import verify_source_copy
source=Path('.').resolve();tracked=['scripts/register-native-owner-handle.py','tests/postgres/finflow_candidate_source.py','tests/postgres/finflow_native_gate.py']
with tempfile.TemporaryDirectory() as directory:
 copied=Path(directory)/'source';virtual={};links={}
 real_read=Path.read_bytes;real_file=Path.is_file;real_mkdir=Path.mkdir;real_link=Path.symlink_to;real_rglob=Path.rglob
 def is_virtual(p): return p==copied or copied in p.parents
 def read(p): return real_read(virtual[str(p)]) if is_virtual(p) else real_read(p)
 def file(p): return str(p) in virtual if is_virtual(p) else real_file(p)
 def mkdir(p,*a,**kw):
  if not is_virtual(p): return real_mkdir(p,*a,**kw)
 def link(p,target,**kw):
  assert is_virtual(p);links[str(p)]=str(target)
 def copy2(src,dst,*a,**kw):
  src=Path(src);dst=Path(dst);assert is_virtual(dst);virtual[str(dst)]=src
 def rglob(p,pattern):
  if is_virtual(p):
   prefix=str(p)+os.sep;return [Path(name) for name in sorted(virtual) if name.startswith(prefix)]
  return real_rglob(p,pattern)
 Path.read_bytes=read;Path.is_file=file;Path.mkdir=mkdir;Path.symlink_to=link;Path.rglob=rglob
 shutil.copy2=copy2
 stage_source_copy(source,copied,tracked,dependency_root=source/'node_modules',cohort='combined-admin-durable')
 assert str(copied/'server/config/secrets.env') not in virtual, 'private platform configuration must not enter staged source'
 assert str(copied/'server/platform_secrets.json') not in virtual, 'private platform signing data must not enter staged source'
 assert links=={str(copied/'node_modules'):str(source/'node_modules')}
 assert not copied.exists(), 'virtual destination must not be materialized'
 assert (copied/'scripts/register-native-owner-handle.py').is_file();assert len(verify_source_copy(source,copied,tracked))==len(tracked)`;
 const result=require('node:child_process').spawnSync('python3',['-c',script],{cwd:root,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
});
test('retained FinFlow route launcher rejects its unsupported current profile before source or grant access',()=>{
 const args=['tests/postgres/run-finflow-route-isolated.py','--docker-host','owned','--grant-id','g','--owner-handle','7','--canonical-workspace','/canonical','--candidate-source-root','/candidate','--candidate-manifest','/candidate/manifest.json','--candidate-manifest-sha256','a'.repeat(64),'--cohort','durable-v9','--caller-profile','current'];
 const result=require('node:child_process').spawnSync('python3',args,{cwd:root,encoding:'utf8'});
 assert.notEqual(result.status,0);assert.match(result.stderr,/retained for historical qualification only/);assert.match(result.stderr,/run-setup-database-phase-isolated\.py/);
});
test('retained historical FinFlow source-hash report preserves its own ordered inventory',()=>{
 const script=`import hashlib,json;from pathlib import Path
source=Path('.')
report=json.loads((source/'docs/modernization/drafts/finflow-route-admin-logs-v5-source-hash-manifest-2026-09-14.json').read_text())
# Historical qualification bytes are immutable; current staging is checked above.
hashes=report['sourceHashes']
paths=sorted(hashes)
assert report['sourceInventoryCount']==len(paths)
assert all(len(value)==64 and all(c in '0123456789abcdef' for c in value) for value in hashes.values())
assert report['orderedPathSha256']==hashlib.sha256(('\\n'.join(paths)+'\\n').encode()).hexdigest()
assert report['orderedPathAndContentSha256']==hashlib.sha256((''.join(f'{p} {hashes[p]}\\n' for p in paths)).encode()).hexdigest()`;
 const result=require('node:child_process').spawnSync('python3',['-c',script],{cwd:root,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
 assert.equal(sourceHashManifest.sourceInventoryCount,544);
});


test('current FinFlow grant rejects every missing or mismatched bound field without effects',()=>{
 const script=`import sys;sys.dont_write_bytecode=True;sys.path.insert(0,'tests/postgres')
from finflow_native_gate import validate_grant
from unittest.mock import patch
import socket,subprocess
expected=dict(grant_id='owned-grant',owner='/root/current-owner',docker_host='owned-daemon',canonical_workspace='/canonical',candidate_source_root='/candidate',candidate_manifest_sha256='a'*64,source_hashes={'server/a.js':'b'*64})
good=dict(grantId='owned-grant',owner='/root/current-owner',status='granted',allowedLaunches=1,dockerHost='owned-daemon',canonicalWorkspaceRoot='/canonical',candidateSourceRoot='/candidate',candidateManifestSha256='a'*64,sourceHashes=expected['source_hashes'])
with patch.object(socket,'socket',side_effect=AssertionError('network forbidden')),patch.object(subprocess,'run',side_effect=AssertionError('child forbidden')),patch.object(subprocess,'Popen',side_effect=AssertionError('child forbidden')):
 validate_grant(good,**expected)
 for key,wrong in [('grantId','foreign'),('owner','foreign'),('status','consumed'),('allowedLaunches',2),('dockerHost','foreign'),('canonicalWorkspaceRoot','/foreign'),('candidateSourceRoot','/foreign'),('candidateManifestSha256','c'*64),('sourceHashes',{})]:
  for bad in [{k:v for k,v in good.items() if k!=key},{**good,key:wrong}]:
   try: validate_grant(bad,**expected)
   except RuntimeError as error: assert str(error)=='exact one-use FinFlow grant is required'
   else: raise AssertionError('accepted invalid '+key)
 print('CURRENT_GRANT_NEGATIVES_18_PASSED')`;
 const result=require('node:child_process').spawnSync('python3',['-B','-c',script],{cwd:root,encoding:'utf8',env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/CURRENT_GRANT_NEGATIVES_18_PASSED/);
});
