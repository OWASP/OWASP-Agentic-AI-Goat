"""Root-invoked owned public-key reader. --plan validates pins without allocation."""
import argparse,hashlib,importlib.util,json,os,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
BASE=load('public_key_owner_base',ROOT/'tests/postgres/run-rag-whole-evidence-main.py')
from sql_nosql_process_ownership import OwnedProcesses
from mcp_vm_public_host_key import read_owned_key,plan as resource_plan
REQUIRED=['tests/postgres/run-mcp-vm-public-host-key.py','tests/postgres/mcp_vm_public_host_key.py','tests/postgres/sql_nosql_docker_ownership.py','tests/postgres/sql_nosql_process_ownership.py','tests/postgres/run-rag-whole-evidence-main.py']
def socket_identity(a):
    p=BASE.exact(a.socket);s=p.lstat()
    if not stat.S_ISSOCK(s.st_mode) or (s.st_uid,s.st_dev,s.st_ino)!=(a.socket_uid,a.socket_dev,a.socket_ino):raise ValueError('Pinned local socket identity mismatch')
def authority(a):return {'docker':a.docker,'dockerSha256':a.docker_sha256,'socket':a.socket,'socketUid':a.socket_uid,'socketDev':a.socket_dev,'socketIno':a.socket_ino,'daemonId':a.daemon_id,'imageId':a.image_id,'sshHost':a.ssh_host,'sshPort':a.ssh_port,'pythonSha256':a.python_sha256}
def admit(a):
    resource_plan('0'*32,a.image_id)
    if not a.daemon_id.strip() or not 1<=a.ssh_port<=65535:raise ValueError('Explicit daemon/endpoint required')
    manifest=BASE.exact(a.manifest)
    if not manifest.is_relative_to(ROOT) or manifest.stat().st_size>1048576 or BASE.digest(manifest)!=a.manifest_sha256:raise ValueError('Private manifest identity')
    m=json.loads(manifest.read_text())
    if m.get('root')!=str(ROOT) or m.get('authority')!=authority(a):raise ValueError('Explicit authority mismatch')
    if BASE.digest(BASE.exact(a.docker))!=a.docker_sha256 or BASE.digest(Path(sys.executable).resolve())!=a.python_sha256:raise ValueError('Runtime pin mismatch')
    pins=m.get('sourcePins',{})
    if not set(REQUIRED)<=set(pins):raise ValueError('Required owner closure absent')
    for p,h in pins.items():
        if Path(p).is_absolute() or '..' in Path(p).parts or BASE.digest(BASE.exact(ROOT/p))!=h:raise ValueError('Current source mismatch')
    socket_identity(a);return m
def parser():
    p=argparse.ArgumentParser(allow_abbrev=False)
    for key in ['manifest','manifest-sha256','docker','docker-sha256','socket','daemon-id','image-id','python-sha256','ssh-host']:p.add_argument('--'+key,required=True)
    for key in ['socket-uid','socket-dev','socket-ino','ssh-port']:p.add_argument('--'+key,required=True,type=int)
    p.add_argument('--plan',action='store_true');return p
def bounded_command(*,argv,owned,evidence,env,index,timeout):
    out=evidence/f'command-{index}.stdout';err=evidence/f'command-{index}.stderr';child=None;primary=None;result=None
    try:
        with open(out,'xb',opener=lambda n,f:os.open(n,f,0o600)) as stdout,open(err,'xb',opener=lambda n,f:os.open(n,f,0o600)) as stderr:
            child=owned.launch(argv,name=f'docker-{index}',cwd=evidence,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
            deadline=time.monotonic()+timeout
            while child.poll() is None:
                if out.stat().st_size+err.stat().st_size>65536:raise RuntimeError('Docker output cap')
                if time.monotonic()>=deadline:raise TimeoutError('Docker command deadline')
                time.sleep(.025)
            if out.stat().st_size+err.stat().st_size>65536:raise RuntimeError('Docker output cap')
            result=subprocess.CompletedProcess(argv,child.returncode,out.read_text(),err.read_text())
    except BaseException as error:primary=error
    finally:
        if child is not None:
            try:owned.finish(child)
            except BaseException as cleanup:
                if primary:raise BaseExceptionGroup('Docker command and cleanup failed',[primary,cleanup])
                raise
    if primary:raise primary
    return result
def execute_owned(*,state,work,check_work,enter_cleanup,check_cleanup,cleanup,readmit,publish_receipt,publish_state,restore):
    """One failure boundary; a returned receipt never erases earlier failure."""
    receipt=None;code=1
    try:
        try:receipt=work();check_work()
        except BaseException as error:state.setdefault('failure',type(error).__name__)
        try:
            enter_cleanup()
            try:check_cleanup();cleanup();check_cleanup();state['cleanupVerified']=True
            except BaseException as error:state['cleanupFailure']=type(error).__name__
            try:check_cleanup();readmit();check_cleanup();state['sourceUnchanged']=True
            except BaseException as error:state['sourceUnchanged']=False;state['admissionFailure']=type(error).__name__
            if receipt and not any(k in state for k in ('failure','cleanupFailure','admissionFailure')) and state.get('cleanupVerified') and state.get('sourceUnchanged'):
                try:check_cleanup();publish_receipt(receipt);check_cleanup();code=0
                except BaseException as error:state['publicationFailure']=type(error).__name__
        except BaseException as error:state['finalizationFailure']=type(error).__name__
    finally:
        # Restoration is attempted even when starting cleanup or publication is
        # interrupted. Only the final journal can declare the execution passed.
        try:restore()
        except BaseException as error:state['restorationFailure']=type(error).__name__;code=1
        if any(k in state for k in ('failure','cleanupFailure','admissionFailure','publicationFailure','finalizationFailure','restorationFailure')):code=1
        state['status']='passed' if code==0 else 'failed'
        try:publish_state()
        except BaseException as error:state['journalFailure']=type(error).__name__;state['status']='failed';code=1
    return code
def main(argv):
    flags=[x.split('=')[0] for x in argv if x.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flag')
    a=parser().parse_args(argv);admit(a)
    if a.plan:print(json.dumps({'allocation':False,'workSeconds':90,'cleanupSeconds':60,'maxCommandSeconds':20,'maxCommandBytes':65536,'mount':'readonly nonrecursive /etc/ssh','onlyOpenedFile':'ssh_host_ed25519_key.pub','ssh':False}));return 0
    parent=ROOT/'backups/private-recovery/mcp-vm-public-key';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    s=parent.lstat()
    if parent.resolve()!=parent or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('Private parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));(evidence/'home').mkdir(mode=0o700);(evidence/'tmp').mkdir(mode=0o700)
    state={'parentPid':os.getpid(),'manifestSha256':a.manifest_sha256,'authority':authority(a),'evidenceRoot':str(evidence),'events':[],'children':[],'cleanupVerified':False,'status':'preparing'}
    publish=lambda:BASE.publish(evidence/'ownership.json',state)
    owned=OwnedProcesses(BASE.stop_group,lambda row:(state['children'].append(row),publish()));owned.install()
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Public key phase deadline')))
    work_end=time.monotonic()+90;cleanup_end=None;counter=0;receipt=None;code=1
    def cleanup_remaining():
        nonlocal cleanup_end
        if cleanup_end is None:
            owned.mask_cleanup_signals();cleanup_end=time.monotonic()+60;signal.setitimer(signal.ITIMER_REAL,60)
        return cleanup_end-time.monotonic()
    def record(event,value):state['events'].append({'event':event,'value':value});publish()
    clean={'PATH':str(Path(a.docker).parent)+':/usr/bin:/bin','HOME':str(evidence/'home'),'TMPDIR':str(evidence/'tmp'),'LANG':'C','DOCKER_CONFIG':str(evidence/'home')}
    def docker(args,timeout):
        nonlocal counter
        socket_identity(a);counter+=1
        if counter>32:raise RuntimeError('Closed command count exceeded')
        return bounded_command(argv=[a.docker,'--host','unix://'+a.socket,*args],owned=owned,evidence=evidence,env=clean,index=counter,timeout=timeout)
    def work():
        publish();signal.setitimer(signal.ITIMER_REAL,90)
        return read_owned_key(docker=docker,record=record,remaining=lambda:work_end-time.monotonic(),cleanup_remaining=cleanup_remaining,daemon_id=a.daemon_id,image=a.image_id,nonce=os.urandom(16).hex(),ssh_host=a.ssh_host,ssh_port=a.ssh_port)
    def check_cleanup():
        if cleanup_end is None or time.monotonic()>=cleanup_end:raise TimeoutError('Public key cleanup deadline')
    def check_work():
        # Helper enters its independent cleanup before returning a receipt.
        if cleanup_end is not None:check_cleanup()
        elif time.monotonic()>=work_end:raise TimeoutError('Public key work deadline')
    def restore():
        try:signal.setitimer(signal.ITIMER_REAL,0)
        finally:
            try:signal.signal(signal.SIGALRM,previous)
            finally:owned.restore()
    def publish_receipt(receipt):
        known=receipt.pop('knownHostsContent');target=evidence/'known_hosts'
        with open(target,'xb',opener=lambda n,f:os.open(n,f,0o600)) as f:f.write(known.encode());f.flush();os.fsync(f.fileno())
        if BASE.digest(target)!=receipt['knownHostsSha256']:raise RuntimeError('Known-host readback failed')
        receipt.update(knownHostsPath=str(target),manifestSha256=a.manifest_sha256,authority=authority(a));BASE.publish(evidence/'host-key-authority.json',receipt);state['receiptSha256']=BASE.digest(evidence/'host-key-authority.json')
    code=execute_owned(state=state,work=work,check_work=check_work,enter_cleanup=cleanup_remaining,check_cleanup=check_cleanup,cleanup=owned.cleanup,readmit=lambda:admit(a),publish_receipt=publish_receipt,publish_state=publish,restore=restore)
    print(json.dumps({'status':state['status'],'evidenceRoot':str(evidence),'cleanupVerified':state['cleanupVerified']}));return code
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
