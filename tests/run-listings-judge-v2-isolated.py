#!/usr/bin/env python3
"""Bounded actual Judge calibration only; no DB, browser, actor or completion write."""
import pathlib,subprocess,tempfile,os,signal,json,hashlib,time
REPO=pathlib.Path(__file__).resolve().parents[1]
NODE=pathlib.Path.home()/'.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node'
assert subprocess.check_output([str(NODE),'--version'],text=True).strip()=='v26.9.0'
root=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-listings-judge-v2-')).resolve();source=root/'source'
subprocess.run([str(NODE),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(REPO),str(source)],cwd=REPO,check=True,timeout=30)
os.symlink(REPO/'node_modules',source/'node_modules',target_is_directory=True)
hashfile=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files={str(p.relative_to(source)):hashfile(p) for folder in ['server/services','server/agent-runtime','tests/fixtures'] for p in (source/folder).rglob('*') if p.is_file() and not p.is_symlink()}
(root/'source-manifest.json').write_text(json.dumps(files,indent=2))
env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root),'NODE_ENV':'test','AWS_EC2_METADATA_DISABLED':'true'}
with (root/'stdout.log').open('w')as out,(root/'stderr.log').open('w')as err:
 child=subprocess.Popen([str(NODE),str(source/'tests/fixtures/secureshopListingsJudgeV2Qualification.js'),str(root)],cwd=source,env=env,stdout=out,stderr=err,start_new_session=True)
 print(json.dumps({'root':str(root),'pid':child.pid,'deadlineSeconds':240}),flush=True)
 try:code=child.wait(timeout=240)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=4)
  code=124
absent=False
try:os.killpg(child.pid,0)
except ProcessLookupError:absent=True
if not absent:
 os.killpg(child.pid,signal.SIGKILL);time.sleep(.3)
 try:os.killpg(child.pid,0)
 except ProcessLookupError:absent=True
unchanged=all(hashfile(source/name)==value for name,value in files.items())
report={'root':str(root),'exitCode':code,'processGroupAbsent':absent,'sourceFiles':len(files),'sourceUnchanged':unchanged,'nodeSha256':hashfile(NODE)}
if(root/'result.json').exists():report['result']=json.loads((root/'result.json').read_text())
(root/'launcher-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
raise SystemExit(0 if code==0 and absent and unchanged and report.get('result',{}).get('status')=='passed' else 1)
