# Explicit v4 compatibility regression; original v3 remains unchanged.
"""Explicit main-only diagnostic supervisor. Plan never launches or allocates."""
import argparse, hashlib, importlib.util, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/'tests/postgres/sql_nosql_process_ownership.py'
ENTRY='tests/fixtures/ragWholeEvidenceDefenseMainV4.js'
INPUT='tests/release-inputs/rag-whole-evidence-fresh12-inputs-v1.json'
INPUT_SHA='dbf7f326cdfcee3221896cef0bffe1d320bcce729e9e0aa91d969511521117c5'

def digest(p):
    value=hashlib.sha256()
    with open(p,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):value.update(block)
    return value.hexdigest()
def exact(p):
    p=Path(p)
    if not p.is_absolute() or p.resolve()!=p:raise ValueError('Canonical path required')
    return p

def admit(a):
    for p,h in [(exact(a.manifest),a.manifest_sha256),(exact(a.node),a.node_sha256),(Path(sys.executable).resolve(),a.python_sha256),(Path(__file__).resolve(),a.supervisor_sha256),(HELPER,a.helper_sha256)]:
        if digest(p)!=h:raise ValueError('Pin mismatch')
    m=json.loads(Path(a.manifest).read_text())
    if m['version']!=1 or m['root']!=str(ROOT) or m['node']!={'path':a.node,'sha256':a.node_sha256}:raise ValueError('Manifest identity mismatch')
    seen=set()
    for row in m['files']:
        p=row['path']
        if Path(p).is_absolute() or '..' in Path(p).parts or p in seen:raise ValueError('Invalid manifest path')
        seen.add(p)
        if digest(exact(ROOT/p))!=row['sha256']:raise ValueError('Manifest source mismatch')
    if not {ENTRY,INPUT,'tests/fixtures/ragWholeEvidenceDefenseDiagnosticV4.js','server/agent-runtime/ragWholeEvidenceDefenseContractV4.js','tests/fixtures/ragWholeEvidenceActualTransport.js','server/agent-runtime/ragWholeEvidenceDefenseContract.js'}.issubset(seen):raise ValueError('Required diagnostic closure missing')
    if digest(ROOT/INPUT)!=INPUT_SHA:raise ValueError('Frozen input changed')
    return m

def publish(p,value):
    tmp=p.with_suffix('.tmp')
    with open(tmp,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as f:
        json.dump(value,f);f.flush();os.fsync(f.fileno())
    os.replace(tmp,p)
    fd=os.open(p.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def members(pgid,sid):
    r=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env={'PATH':'/usr/bin:/bin','LANG':'C'},capture_output=True,text=True,check=True,timeout=2)
    found=[]
    for line in r.stdout.splitlines():
        pid,group,uid=map(int,line.split())
        if group!=pgid:continue
        try:
            if uid!=os.getuid() or os.getsid(pid)!=sid:raise RuntimeError('Unknown group identity')
        except ProcessLookupError:continue
        found.append(pid)
    return found

def stop_group(child,pgid,sid):
    until=time.monotonic()+25
    if members(pgid,sid):os.killpg(pgid,signal.SIGTERM)
    grace=min(until,time.monotonic()+8)
    while members(pgid,sid) and time.monotonic()<grace:child.poll();time.sleep(.05)
    if members(pgid,sid):os.killpg(pgid,signal.SIGKILL)
    child.wait(timeout=max(.1,min(8,until-time.monotonic())))
    while members(pgid,sid) and time.monotonic()<until:time.sleep(.05)
    if members(pgid,sid):raise RuntimeError('Owned group remains')

def release_child(child,state,record):
    state['nativePid']=child.pid;state['nativeStarted']=True;record()
    child.stdin.write(b'1');child.stdin.flush();child.stdin.close()

def main(argv):
    p=argparse.ArgumentParser(allow_abbrev=False)
    for key in ['manifest','manifest-sha256','node','node-sha256','python-sha256','supervisor-sha256','helper-sha256']:p.add_argument('--'+key,required=True)
    p.add_argument('--plan',action='store_true')
    flags=[s.split('=')[0] for s in argv if s.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flag')
    a=p.parse_args(argv);admit(a)
    if a.plan:print(json.dumps({'allocation':False,'childSeconds':780,'cleanupSeconds':30,'stores':0,'maximumInference':12,'maximumMetadata':1}));return 0
    spec=importlib.util.spec_from_file_location('rag_owned_processes',HELPER);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if Path(module.__file__).resolve()!=HELPER:raise RuntimeError('Helper origin')
    if shutil.disk_usage(ROOT).free < 2*1024**3+512*1024**2+16*1024**2:raise RuntimeError('Artifact space plus reserve required')
    parent=ROOT/'backups/private-recovery/rag-whole-evidence-v4';parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=parent.lstat()
    if parent.resolve()!=parent or s.st_uid!=os.getuid() or s.st_mode&0o777!=0o700:raise RuntimeError('Private evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));os.chmod(evidence,0o700)
    for name in ['home','tmp','results']:(evidence/name).mkdir(mode=0o700)
    state={'parentPid':os.getpid(),'status':'preparing','manifestSha256':a.manifest_sha256,'evidenceRoot':str(evidence),'children':[],'cleanupVerified':False,'failure':None}
    record=lambda:publish(evidence/'ownership.json',state)
    owned=module.OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));owned.install()
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Phase deadline')))
    code=1
    try:
        clean={'PATH':str(Path(a.node).parent)+':/usr/bin:/bin','HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'LANG':'C','RAG_WHOLE_EVIDENCE_V4_RELEASE_REQUIRED':'1','RAG_WHOLE_EVIDENCE_V4_DIAGNOSTIC':'1','RAG_WHOLE_EVIDENCE_V4_MANIFEST':a.manifest,'RAG_WHOLE_EVIDENCE_V4_MANIFEST_SHA256':a.manifest_sha256,'RAG_WHOLE_EVIDENCE_V4_OUTPUT_ROOT':str(evidence/'results')}
        record();print(json.dumps({'evidenceRoot':str(evidence)}),flush=True);signal.setitimer(signal.ITIMER_REAL,780)
        with open(evidence/'child.log','xb',opener=lambda name,flags:os.open(name,flags,0o600)) as log:
            child=owned.launch([a.node,str(ROOT/ENTRY)],name='rag-whole-evidence',cwd=ROOT,env=clean,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,stdin=subprocess.PIPE)
            release_child(child,state,record)
            deadline=time.monotonic()+780
            while child.poll() is None:
                if time.monotonic()>=deadline:raise TimeoutError('Child deadline')
                if log.tell()>16*1024*1024:raise RuntimeError('Log cap')
                time.sleep(.1)
            code=child.returncode
        state['childExitCode']=code;state['status']='child-exited'
    except BaseException as error:state['failure']=type(error).__name__;code=1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);owned.mask_cleanup_signals();signal.setitimer(signal.ITIMER_REAL,30)
        try:owned.cleanup();state['cleanupVerified']=True
        except BaseException as error:state['cleanupFailure']=type(error).__name__;code=1
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
        if (evidence/'child.log').exists() and (evidence/'child.log').stat().st_size>16*1024*1024:state['failure']='LogCap';code=1
        try:
            admit(a);state['sourceUnchanged']=True
        except BaseException as error:state['sourceUnchanged']=False;state['integrityFailure']=type(error).__name__;code=1
        state['status']='terminal' if code==0 and state['cleanupVerified'] else 'failed';record()
    return code
if __name__=='__main__':
    try:sys.exit(main(sys.argv[1:]))
    except Exception as error:print(json.dumps({'status':'admission-failed','error':type(error).__name__}));sys.exit(1)
