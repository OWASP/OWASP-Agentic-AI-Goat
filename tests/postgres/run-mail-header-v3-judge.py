#!/usr/bin/env python3
"""Freeze/preflight or execute the reviewed header suite; no DB/browser/credit."""
import argparse,hashlib,json,os,signal,subprocess,tempfile,time
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
p=argparse.ArgumentParser();p.add_argument('--prepared-root');args=p.parse_args()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(NODE)==NODE_SHA
root=Path(args.prepared_root).resolve() if args.prepared_root else Path(tempfile.mkdtemp(prefix='dvaia-header-judge-'))
child=None;state={}
def persist(): (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n')
def interrupted(*_):raise TimeoutError('Header Judge parent interrupted/deadline')
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGALRM,interrupted);signal.alarm(360)
try:
 if not args.prepared_root:
  os.chmod(root,0o700)
  subprocess.run([str(NODE),'-e',"const fs=require('node:fs'),path=require('node:path'),{createCopyFilter}=require('./scripts/lib/isolated-source-copy');const [src,dst]=process.argv.slice(1),base=createCopyFilter(src),omit=new Set(['server/platform_secrets.json','server/config/secrets.env']);for(const d of ['server','shared','db/postgres'])if(fs.existsSync(path.join(src,d)))fs.cpSync(path.join(src,d),path.join(dst,d),{recursive:true,filter:p=>base(p)&&!omit.has(path.relative(src,p).split(path.sep).join('/'))});",str(SOURCE),str(root)],cwd=SOURCE,check=True,timeout=30)
  files=['tests/postgres/secureshopMailHeaderJudgeCases.js','tests/postgres/secureshopMailHeaderV3Preflight.js','tests/postgres/secureshopMailHeaderV3Actual.js','tests/postgres/secureshopMailActualTransport.js','tests/postgres/run-mail-header-v3-judge.py','tests/postgres/secureshopMailHeaderV3Cases.js','package.json','package-lock.json']
  for f in files:
   dest=root/f;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((SOURCE/f).read_bytes())
  (root/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
  report=json.loads((SOURCE/'tasks/secureshop-mail-header-native-2026-09-26.json').read_text());original=Path(report['evidenceDirectory'])/'candidate-result.json';assert sha(original)==report['runtimeResultSha256'];(root/'retained-input.json').write_bytes(original.read_bytes())
  prior=Path('/private/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-header-judge-5uztbsos/result.json');(root/'prior-v2.json').write_bytes(prior.read_bytes())
  state={'priorSha256':sha(root/'prior-v2.json'),'status':'preparing','launcherPid':os.getpid(),'nodeSha256':NODE_SHA,'inputSha256':sha(root/'retained-input.json'),'bounds':{'parentSeconds':360,'childSeconds':300,'httpSeconds':60,'judgeSeconds':90,'maximumHttp':4},'noActorDatabaseBrowserSmtpCredit':True,'sourceSha256':{str(f.relative_to(root)):sha(f) for f in root.rglob('*') if f.is_file()}}
 else:
  state=json.loads((root/'ownership.json').read_text());assert state['status']=='prepared';assert state['bounds']=={'parentSeconds':360,'childSeconds':300,'httpSeconds':60,'judgeSeconds':90,'maximumHttp':4};assert all(sha(root/f)==h for f,h in state['sourceSha256'].items());assert sha(root/'preflight.json')==state['preflightSha256'];state['launcherPid']=os.getpid()
 env={'PATH':str(NODE.parent)+':/usr/bin:/bin','MAIL_PRIOR_INPUT':str(root/'prior-v2.json'),'MAIL_PRIOR_SHA':state['priorSha256'],'MAIL_CALIBRATION_INPUT':str(root/'retained-input.json'),'MAIL_CALIBRATION_INPUT_SHA':state['inputSha256'],'MAIL_CALIBRATION_RESULT':str(root/'result.json')}
 if not args.prepared_root:
  result=subprocess.run([str(NODE),'tests/postgres/secureshopMailHeaderV3Preflight.js'],cwd=root,env=env,capture_output=True,text=True,check=True,timeout=30);(root/'preflight.json').write_text(result.stdout);state.update(status='prepared',preflightSha256=sha(root/'preflight.json'))
 else:
  with (root/'run.log').open('w') as log:
   child=subprocess.Popen([str(NODE),'tests/postgres/secureshopMailHeaderV3Actual.js'],cwd=root,env=env,stdout=log,stderr=log,start_new_session=True);state.update(status='running',child={'pid':child.pid,'pgid':os.getpgid(child.pid)});persist();code=child.wait(timeout=300)
  if code:raise RuntimeError('Header Judge failed; retain result/log')
  state.update(status='completed',resultSha256=sha(root/'result.json'),logSha256=sha(root/'run.log'))
except BaseException as e:state.update(status='failed',error=type(e).__name__);raise
finally:
 signal.alarm(0)
 pgid=state.get('child',{}).get('pgid')
 def members():
  if not pgid:return []
  rows=[tuple(map(int,r.split())) for r in subprocess.check_output(['ps','-axo','pid=,pgid=,uid='],text=True).splitlines() if len(r.split())==3 and int(r.split()[1])==pgid]
  if any(r[2]!=os.getuid() for r in rows):raise RuntimeError('Foreign process group member')
  return rows
 if members():
  os.killpg(pgid,signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(pgid,signal.SIGKILL);child.wait(timeout=5)
 state['cleanup']={'wholeProcessGroupAbsent':not members()};persist();print(json.dumps({'evidence':str(root),'status':state['status'],'cleanup':state['cleanup']}))
