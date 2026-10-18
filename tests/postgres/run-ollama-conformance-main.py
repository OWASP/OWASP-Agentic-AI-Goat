"""Two-call provider conformance owner; reuses reviewed process lifecycle, never grades."""
import argparse,importlib.util,json,os,signal,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=load('conformance_owner_base',ROOT/'tests/postgres/run-rag-whole-evidence-main.py')
ENTRY='tests/fixtures/ollamaSchemaConformanceMain.js'
INPUT='tests/release-inputs/ollama-root-ref-conformance-input-v1.json'
INPUT_SHA='313bd79ee27962bdfd38ec96f92f4037794c82dd857050c7539f83e3ea79abd6'
def admit(a):
 for p,h in [(base.exact(a.manifest),a.manifest_sha256),(base.exact(a.node),a.node_sha256),(Path(sys.executable).resolve(),a.python_sha256)]:
  if base.digest(p)!=h:raise ValueError('Authority pin mismatch')
 m=json.loads(Path(a.manifest).read_text())
 if m.get('root')!=str(ROOT) or m.get('node')!={'path':a.node,'sha256':a.node_sha256}:raise ValueError('Manifest identity')
 pins={}
 for f in m['files']:
  p=f['path']
  if Path(p).is_absolute() or '..' in Path(p).parts or p in pins or base.digest(base.exact(ROOT/p))!=f['sha256']:raise ValueError('Source mismatch')
  pins[p]=f['sha256']
 required={ENTRY,INPUT,'tests/ollamaSchemaConformance.test.js','tests/postgres/run-ollama-conformance-main.py','tests/postgres/run-rag-whole-evidence-main.py','tests/postgres/sql_nosql_process_ownership.py','node_modules/ajv/package.json'}
 if not required.issubset(pins) or base.digest(ROOT/INPUT)!=INPUT_SHA:raise ValueError('Required closure missing')
 return m
def main(argv):
 p=argparse.ArgumentParser(allow_abbrev=False)
 for k in ['manifest','manifest-sha256','node','node-sha256','python-sha256']:p.add_argument('--'+k,required=True)
 p.add_argument('--plan',action='store_true');a=p.parse_args(argv);admit(a)
 if a.plan:print(json.dumps({'allocation':False,'chat':2,'metadata':1,'cohortSeconds':50,'outerSeconds':60,'cleanupSeconds':30}));return 0
 parent=ROOT/'backups/private-recovery/ollama-conformance';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 st=parent.lstat()
 if parent.resolve()!=parent or st.st_uid!=os.getuid() or st.st_mode&511!=448:raise ValueError('Private parent')
 evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent))
 for name in ['home','tmp','results']:(evidence/name).mkdir(mode=0o700)
 state={'parentPid':os.getpid(),'evidenceRoot':str(evidence),'manifestSha256':a.manifest_sha256,'children':[],'cleanupVerified':False,'remoteInferenceSettled':None}
 record=lambda:base.publish(evidence/'ownership.json',state)
 helper=load('conformance_processes',base.HELPER);owned=helper.OwnedProcesses(base.stop_group,lambda row:(state['children'].append(row),record()));owned.install();code=1
 previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()))
 try:
  env={'PATH':str(Path(a.node).parent)+':/usr/bin:/bin','HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'OLLAMA_CONFORMANCE_NATIVE':'1','OLLAMA_CONFORMANCE_OUTPUT':str(evidence/'results'),'OLLAMA_CONFORMANCE_MANIFEST':a.manifest,'OLLAMA_CONFORMANCE_MANIFEST_SHA256':a.manifest_sha256}
  record();print(json.dumps({'evidenceRoot':str(evidence)}),flush=True);signal.setitimer(signal.ITIMER_REAL,60)
  with (evidence/'child.log').open('xb') as log:
   os.chmod(log.name,0o600);child=owned.launch([a.node,str(ROOT/ENTRY)],name='ollama-conformance',cwd=evidence,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,stdin=subprocess.PIPE);base.release_child(child,state,record)
   while child.poll() is None:
    if log.tell()>1048576:raise RuntimeError('Log cap')
    time.sleep(.05)
   code=child.returncode;state['childExitCode']=code
 except BaseException as e:state['failure']=type(e).__name__
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);owned.mask_cleanup_signals();signal.setitimer(signal.ITIMER_REAL,30)
  try:owned.cleanup();state['cleanupVerified']=True
  except BaseException as e:state['cleanupFailure']=type(e).__name__;code=1
  finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
  try:admit(a);state['sourceUnchanged']=True
  except BaseException:state['sourceUnchanged']=False;code=1
  state['status']='terminal' if code==0 else 'failed';record()
 return code
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
