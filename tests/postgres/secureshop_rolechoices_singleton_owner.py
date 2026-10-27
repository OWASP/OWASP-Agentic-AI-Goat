"""UNAPPLIED thin RoleChoices binding of the existing V27 singleton owner.

No signals, discovery or recursive deletion. Existing Node --test argv survives.
"""
import importlib.util,os,time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]
TEST='tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'
RECORD='rolechoices-browser-birth.json'
ACK='rolechoices-browser-ack.json'
KIND='rolechoices_browser'
SCOPES={'admin-policy-chat-browser':('SECURESHOP_ADMIN_POLICY_CHAT_BROWSER','dvaia-role-admin-policy-'),
        'admin-audit-browser':('SECURESHOP_ADMIN_AUDIT_CHAT_BROWSER','dvaia-role-admin-audit-'),
        'admin-acl-chat-browser':('SECURESHOP_ADMIN_ACL_CHAT_BROWSER','dvaia-q64-admin-acl-')}
TESTS={scope:TEST for scope in SCOPES}
TESTS['admin-acl-chat-browser']='tests/postgres/secureshopStandaloneAdminAclChatRendered.integration.test.js'
def load(relative,name):
    p=ROOT/relative;spec=importlib.util.spec_from_file_location(name,p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def verify_live(record,coordinator_birth,runtime,*,api,coordinator,node,profile_prefix,zombie,getsid=os.getsid,fixture=TEST):
    expected=(record['pid'],record['parentPid'],os.getuid(),os.getuid(),record['pgid'],*record['birth'])
    fields=lambda p:(p.pid,p.ppid,p.uid,p.ruid,p.pgid,p.start_sec,p.start_usec)
    def parents():
        leader=api.identity(coordinator);worker=api.identity(record['parentPid'])
        if leader is None or (leader.start_sec,leader.start_usec)!=tuple(coordinator_birth) or leader.uid!=os.getuid() or leader.ruid!=os.getuid() or leader.pgid!=coordinator or leader.status==zombie:raise RuntimeError('RoleChoices coordinator birth')
        if worker is None or worker.ppid!=coordinator or worker.uid!=os.getuid() or worker.ruid!=os.getuid() or worker.pgid!=coordinator or worker.status==zombie:raise RuntimeError('RoleChoices worker ownership')
        argv=api.arguments(worker.pid)
        if not argv or argv[0]!=node or not any(str(x).endswith('/'+fixture) or x==fixture for x in argv):raise RuntimeError('RoleChoices worker executable')
        return fields(worker)
    parent=parents();first=api.identity(record['pid'])
    if first is None or fields(first)!=expected or first.status==zombie or getsid(first.pid)!=record['sessionId']:raise RuntimeError('RoleChoices browser birth')
    argv=api.arguments(first.pid);profiles=[x.split('=',1)[1] for x in argv if x.startswith('--user-data-dir=')]
    if not argv or argv[0]!=record['executablePath'] or len(profiles)!=1:raise RuntimeError('RoleChoices browser executable')
    profile=Path(profiles[0]);temporary=Path(runtime)/'tmp'
    if profile.parent!=temporary or not profile.name.startswith(profile_prefix) or profile.resolve()!=profile:raise RuntimeError('RoleChoices profile path')
    second=api.identity(first.pid)
    if second is None or fields(second)!=expected or second.status==zombie or parents()!=parent:raise RuntimeError('RoleChoices birth changed')
    return SimpleNamespace(record=dict(record),profile=str(profile))
def make_owner(original,parsed):
    if parsed.cohort not in SCOPES:raise RuntimeError('RoleChoices exact scope')
    prefix,profile_prefix=SCOPES[parsed.cohort]
    fixture=TESTS[parsed.cohort]
    watcher=load('tests/postgres/run-secureshop-idor-lesson-browser.py','rolechoices_existing_watcher')
    ownership=load('tests/postgres/run-secureshop-audit-collection-browser.py','rolechoices_existing_birth')
    singleton=load('tests/postgres/secureshop_chrome_singleton_owner.py','rolechoices_existing_singleton')
    watcher.TEST,watcher.RECORD,watcher.ACK,watcher.KIND=fixture,RECORD,ACK,KIND
    def direct(command,args):
        plain=[args.node,'--test','--test-reporter=tap','--test-concurrency=1',fixture]
        preloaded=[args.node,'--require',str(ROOT/'tasks/qualification/admin-policy-existing-only-preload.cjs'),*plain[1:]]
        if list(command)!=plain and not (args.cohort=='admin-policy-chat-browser' and list(command)==preloaded):raise RuntimeError('RoleChoices original argv')
        return list(command) # No --test removal or Chrome flag changes.
    watcher.direct_command=direct
    def environment(env,args):
        out=dict(env);evidence=Path(out[prefix+'_EVIDENCE_PATH']).parent
        if out.get(prefix+'_NATIVE')!='1' or evidence.parent!=ROOT/'tasks/qualification' or not evidence.name.startswith('run-') or out.get('TMPDIR')!=str(evidence/'runtime/tmp'):raise RuntimeError('RoleChoices owned environment')
        out.update(SECURESHOP_ROLECHOICES_BROWSER_RECORD_PATH=str(evidence/RECORD),SECURESHOP_ROLECHOICES_BROWSER_ACK_PATH=str(evidence/ACK),SECURESHOP_ROLECHOICES_BROWSER_SHA256=args.browser_sha256,
          SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT/'tests/postgres/secureshop_darwin_browser_birth.py'),SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(__import__('sys').executable).resolve()))
        return out,evidence
    watcher.owned_environment=environment
    original_modules=ownership._browser_modules
    def modules():
        api_type,zombie,third,read,absent=original_modules()
        def worker_record(root,filename,kind,browser,browser_sha,pgid,**kwargs):
            # Existing bounded birth reader validates the full row. Only its
            # expected parent differs for the retained Node --test worker.
            import json,stat
            p=Path(root)/filename;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=4096:raise RuntimeError('RoleChoices private record')
                raw=os.read(fd,4097);after=os.fstat(fd);named=p.lstat()
                if len(raw)!=info.st_size or any(getattr(info,k)!=getattr(after,k) or getattr(after,k)!=getattr(named,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):raise RuntimeError('RoleChoices record changed')
                worker=json.loads(raw)['processes'][0]['parentPid']
            finally:os.close(fd)
            # Run the unchanged existing schema validator over exactly the
            # nofollow bytes above; do not reopen a mutable journal pathname.
            from types import FunctionType
            class Record:
                def lstat(self):return info
                def read_text(self,encoding):return raw.decode(encoding)
            class Directory:
                def __truediv__(self,name):
                    if name!=filename:raise RuntimeError('RoleChoices journal name')
                    return Record()
            scope=dict(read.__globals__);scope['Path']=lambda _:Directory()
            validate=FunctionType(read.__code__,scope,read.__name__,read.__defaults__,read.__closure__)
            rows=validate(root,filename,kind,browser,browser_sha,pgid,parent_pid=worker,require_all=True,allow_browser_session=True)
            rows[0]['_coordinator']=pgid
            return rows
        return api_type,zombie,third,worker_record,absent
    ownership._browser_modules=modules
    def capture(record,birth,runtime,*,api,deadline,stop):
        record=dict(record);coordinator=record.pop('_coordinator');zombie=original_modules()[1]
        verify=lambda:verify_live(record,birth,runtime,api=api,coordinator=coordinator,node=parsed.node,profile_prefix=profile_prefix,zombie=zombie,fixture=fixture)
        first=verify();value,proof=singleton.capture_until(first.profile,Path(runtime)/'tmp',verify,deadline,stop)
        value.singleton=proof;return value
    def retire(value,*,api,**kwargs):
        # Reused exact nofollow descriptor retirement also proves worker/group
        # absence. If any process remains, retain files and report debt.
        return singleton.retire(value.singleton,value.record,api)
    ownership.capture_live_v36_with_deadline=capture;ownership.retire_live_v36=retire
    return watcher.BrowserOwner(original,parsed,ownership)

def run_owned(run_node,label,command,timeout,parsed,original):
    owner=make_owner(original,parsed)
    try:
        result=run_node(label,command,timeout,spawner=owner)
    except BaseException as error:
        if owner.error is not None or owner.captured is None or owner.retired is None:
            error.add_note('RoleChoices singleton retirement unproven; retain owned evidence for cleanup review')
        raise
    if owner.error is not None or owner.captured is None or owner.retired is None:
        raise RuntimeError('RoleChoices singleton retirement incomplete') from owner.error
    return result
