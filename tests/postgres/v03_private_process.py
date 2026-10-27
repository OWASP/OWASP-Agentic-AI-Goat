"""Fixed local V03 parent process observation/retirement, no shell commands.

Only the current parent's direct child or its direct browser child is in scope.
Retirement additionally requires the exact previously observed birth and argv.
"""
import hashlib,importlib.util,json,os,re,signal,stat,sys,time

def require(value,code):
    if not value:raise RuntimeError(code)

def load_inventory(root,digest):
    file=root+'/tests/postgres/darwin_process_inventory.py'
    require(os.path.realpath(file)==file and re.fullmatch('[a-f0-9]{64}',digest),'V03_PROCESS_SOURCE')
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=1048576,'V03_PROCESS_SOURCE')
        raw=os.read(fd,1048577);after=os.fstat(fd)
        require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==digest and
            all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'V03_PROCESS_SOURCE')
    finally:os.close(fd)
    module=type(sys)('v03_inventory');module.__file__=file;sys.modules[module.__name__]=module
    exec(compile(raw,file,'exec'),module.__dict__);return module.LibProc()

def identity(row):
    return None if row is None else dict(pid=row.pid,ppid=row.ppid,pgid=row.pgid,uid=row.uid,birth=[row.start_sec,row.start_usec])

def inspect(api,pid,parent,main_identity=None):
    first=identity(api.identity(pid))
    if first is None:return None
    require(first['uid']==os.getuid() and first['pid']==first['pgid'] and os.getsid(pid)==pid,'V03_PROCESS_OWNER')
    if main_identity is None:require(first['ppid']==parent,'V03_PROCESS_PARENT')
    else:
        require(identity(api.identity(main_identity['pid']))==main_identity and main_identity['ppid']==parent
            and first['ppid']==main_identity['pid'],'V03_PROCESS_PARENT')
    argv=list(api.arguments(pid))
    require(identity(api.identity(pid))==first and argv,'V03_PROCESS_CHANGED')
    return dict(identity=first,argv=argv)

def operation(api,request,now=time.monotonic,send=os.killpg,sleep=time.sleep):
    require(type(request) is dict and set(request)=={'version','op','pid','mainIdentity','expected'},'V03_PROCESS_REQUEST')
    require(type(request['version']) is int and request['version']==1 and request['op'] in ('parent','inspect','retire','term','kill')
        and type(request['pid']) is int and request['pid']>1,'V03_PROCESS_REQUEST')
    parent=os.getppid();pid=request['pid'];main=request['mainIdentity'];expected=request['expected']
    if request['op']=='parent':
        require(pid==parent and main is None and expected is None,'V03_PROCESS_PARENT_REQUEST')
        first=identity(api.identity(parent));require(first is not None and first['uid']==os.getuid(),'V03_PROCESS_PARENT')
        argv=list(api.arguments(parent))
        require(argv and identity(api.identity(parent))==first,'V03_PROCESS_CHANGED')
        return dict(observed=dict(identity=first,argv=argv),groupAbsent=False)
    if main is not None:
        require(type(main) is dict and set(main)=={'pid','ppid','pgid','uid','birth'} and main['ppid']==parent,'V03_PROCESS_MAIN')
    current=inspect(api,pid,parent,main)
    if request['op']=='inspect':
        require(expected is None,'V03_PROCESS_REQUEST');require(current is not None,'V03_PROCESS_NOT_OBSERVED')
        return dict(observed=current,groupAbsent=False)
    require(type(expected) is dict and set(expected)=={'identity','argv'} and expected['identity']['pid']==pid,'V03_PROCESS_EXPECTED')
    if current is not None:
        require(current==expected,'V03_PROCESS_CHANGED')
        send(pid,signal.SIGKILL if request['op']=='kill' else signal.SIGTERM)
    if request['op'] in ('term','kill'):
        # Signal-only wrapper stages never invent closure. If the captured
        # leader disappeared, a nonempty group has no current birth authority.
        if current is None:
            require(not api.group_pids(pid),'V03_PROCESS_GROUP_UNPROVEN')
        return dict(observed=expected,groupAbsent=current is None,signalSent=current is not None)
    end=now()+6
    while now()<end:
        row=identity(api.identity(pid))
        if row is not None:require(row==expected['identity'],'V03_PROCESS_CHANGED')
        members=api.group_pids(pid)
        if not members:return dict(observed=expected,groupAbsent=True)
        # Never kill a reused group or infer descendants absent from leaderexit.
        for member in members:
            value=identity(api.identity(member))
            require(value is not None and value['uid']==os.getuid() and value['pgid']==pid,'V03_PROCESS_GROUP_CHANGED')
        sleep(min(.05,max(0,end-now())))
    raise RuntimeError('V03_PROCESS_GROUP_UNJOINED')

def main():
    require(sys.platform=='darwin' and len(sys.argv)==3,'V03_PROCESS_PLATFORM')
    root,digest=sys.argv[1:];require(os.path.realpath(root)==root,'V03_PROCESS_ROOT')
    raw=sys.stdin.buffer.read(16385);require(len(raw)<=16384,'V03_PROCESS_BOUND')
    request=json.loads(raw);api=load_inventory(root,digest)
    own=identity(api.identity(os.getpid()));require(own is not None,'V03_PROCESS_CONTROLLER')
    result=operation(api,request)
    print(json.dumps(dict(version=1,controller=own,result=result),separators=(',',':')))

if __name__=='__main__':main()
