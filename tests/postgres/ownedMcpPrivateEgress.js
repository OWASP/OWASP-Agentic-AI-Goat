'use strict';

// Controlled-only transport building block. Not installed or enabled by builder.
// CONNECT preserves client TLS; encrypted HTTP paths/credentials are not inspected.
// Both processes use the same admitted nonroot UID. Their separate private0700
// relay directory does not require access through the root-owned builder root.
// Linux SO_PEERCRED/runtime namespace integration and real client compatibility
// remain prerequisites; these scripts alone are not a build admission grant.
const HOSTS=Object.freeze(['registry-1.docker.io','auth.docker.io','deb.debian.org']);
const LIMITS=Object.freeze({wholeSeconds:300,shutdownSeconds:10,idleSeconds:15,connectSeconds:5,dnsSeconds:3,
 headerBytes:8192,concurrency:4,connections:32,registryBytes:128*1024**2,
 authBytes:1024**2,aptBytes:132*1024**2,totalBytes:261*1024**2});
const program=String.raw`
import os, sys, stat, socket, selectors, time, json, re, ipaddress, struct, threading, subprocess, signal, math
HOST_LIMITS={'registry-1.docker.io':134217728,'auth.docker.io':1048576,'deb.debian.org':138412032}
TOTAL=273678336
class Denied(Exception): pass
def check_cancel(stop,deadline):
    if (stop is not None and stop.is_set()) or time.monotonic()>=deadline: raise Denied('cancelled')
def established(client):
    client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
def authority(raw):
    if len(raw)>8192 or not raw.endswith(b'\r\n\r\n'): raise Denied('header')
    try: lines=raw.decode('ascii').split('\r\n')
    except UnicodeError: raise Denied('header')
    match=re.fullmatch(r'CONNECT ([a-z0-9.-]+):443 HTTP/1\.[01]',lines[0])
    if not match or match[1] not in HOST_LIMITS: raise Denied('destination')
    seen=set()
    for line in lines[1:-2]:
        key,sep,value=line.partition(':')
        key=key.lower()
        if not sep or key in seen or key not in ('host','proxy-connection','connection','user-agent'): raise Denied('header')
        seen.add(key)
        if any(ord(c)<32 or ord(c)>126 for c in value): raise Denied('header')
        if key=='host' and value.strip()!=match[1]+':443': raise Denied('destination')
        if key in ('connection','proxy-connection') and value.strip().lower() not in ('keep-alive','close'): raise Denied('header')
    return match[1]
def public_address(value):
    try: ip=ipaddress.ip_address(value)
    except ValueError: raise Denied('dns')
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved: raise Denied('dns')
    if ip.version==6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo or ip in ipaddress.ip_network('64:ff9b::/96')): raise Denied('dns')
    return str(ip)
DNS_CODE="import socket,json,sys; r=socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM); assert 0<len(r)<=32; print(json.dumps(sorted(set(x[4][0] for x in r))))"
def resolve(host,deadline,stop=None,unresolved=None):
    if host not in HOST_LIMITS: raise Denied('destination')
    check_cancel(stop,deadline)
    # Dedicated bounded resolver process avoids an uninterruptible worker-thread lookup.
    owned=unresolved if unresolved is not None else [];selector=None
    child=subprocess.Popen([sys.executable,'-I','-S','-B','-c',DNS_CODE,host],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={})
    owned.append(child) # Exact owned process, registered before any setup allocation.
    try:
        limit=min(deadline,time.monotonic()+3); output=bytearray(); selector=selectors.DefaultSelector()
        selector.register(child.stdout,selectors.EVENT_READ)
        while True:
            check_cancel(stop,deadline)
            remaining=limit-time.monotonic()
            if remaining<=0: raise Denied('dns')
            if not selector.select(min(remaining,.1)): continue
            chunk=os.read(child.stdout.fileno(),1024)
            if not chunk: break
            output.extend(chunk)
            if len(output)>4096: raise Denied('dns')
        if child.wait(timeout=max(.001,limit-time.monotonic()))!=0: raise Denied('dns')
        values=json.loads(output)
        if not isinstance(values,list) or not 0<len(values)<=32: raise Denied('dns')
        # Mixed private/public answers are denied; never fall back or resolve twice.
        return sorted(set(public_address(value) for value in values))
    except (ValueError,subprocess.TimeoutExpired): raise Denied('dns')
    finally:
        cleanup_failed=False;reaped=False
        try:
            if selector is not None: selector.close()
        except Exception: cleanup_failed=True
        try: child.stdout.close()
        except Exception: cleanup_failed=True
        try:
            if child.poll() is None: child.kill()
        except Exception: cleanup_failed=True
        try: reaped=type(child.wait(timeout=.5)) is int
        except Exception: cleanup_failed=True
        if reaped and not cleanup_failed: owned.remove(child)
        else:
            raise Denied('resolver-unreaped')
def connect_public(host,deadline,stop=None,track=None,unresolved=None):
    check_cancel(stop,deadline)
    address=resolve(host,deadline,stop,unresolved)[0]
    check_cancel(stop,deadline)
    family=socket.AF_INET6 if ':' in address else socket.AF_INET
    remote=socket.socket(family,socket.SOCK_STREAM)
    try:
        if track: track(remote)
        remote.settimeout(max(.001,min(5,deadline-time.monotonic())))
        check_cancel(stop,deadline)
        remote.connect((address,443)) # numeric literal: no destination-changing lookup
        check_cancel(stop,deadline)
        if public_address(remote.getpeername()[0])!=address: raise Denied('peer')
        return remote
    except BaseException: remote.close(); raise
class Budget:
    def __init__(self):
        self.lock=threading.Lock(); self.total=0; self.hosts={key:0 for key in HOST_LIMITS}; self.connections=0
    def admit(self):
        with self.lock:
            if self.connections>=32: raise Denied('connections')
            self.connections+=1
    def charge(self,host,count):
        with self.lock:
            if host not in self.hosts or count<0 or self.total+count>TOTAL or self.hosts[host]+count>HOST_LIMITS[host]: raise Denied('bytes')
            self.total+=count; self.hosts[host]+=count
def header(client,deadline,stop=None):
    result=bytearray(); end=min(deadline,time.monotonic()+5)
    while not result.endswith(b'\r\n\r\n'):
        check_cancel(stop,deadline)
        if len(result)>=8192 or time.monotonic()>=end: raise Denied('header')
        client.settimeout(max(.001,min(.25,end-time.monotonic())))
        try: byte=client.recv(1)
        except socket.timeout: continue
        if not byte: raise Denied('header')
        result.extend(byte)
    return bytes(result)
def pump(left,right,host,budget,deadline,stop):
    left.setblocking(False);right.setblocking(False)
    pending={left:bytearray(),right:bytearray()}; other={left:right,right:left}; readers={left,right}; idle=time.monotonic()+15
    while readers or any(pending.values()):
        remaining=min(deadline,idle)-time.monotonic()
        if stop.is_set() or remaining<=0: raise Denied('deadline')
        with selectors.DefaultSelector() as selector:
            for sock in (left,right):
                events=(selectors.EVENT_READ if sock in readers and len(pending[other[sock]])<65536 else 0)|(selectors.EVENT_WRITE if pending[sock] else 0)
                if events: selector.register(sock,events)
            events=selector.select(min(remaining,.25))
        for key,mask in events:
            sock=key.fileobj
            if mask&selectors.EVENT_READ:
                try: chunk=sock.recv(min(16384,65536-len(pending[other[sock]])))
                except BlockingIOError: chunk=None
                if chunk:
                    budget.charge(host,len(chunk));pending[other[sock]].extend(chunk);idle=time.monotonic()+15
                elif chunk==b'': readers.remove(sock)
            if mask&selectors.EVENT_WRITE:
                try: count=sock.send(pending[sock])
                except BlockingIOError: count=0
                if count: del pending[sock][:count];idle=time.monotonic()+15
        for sock in (left,right):
            if other[sock] not in readers and not pending[sock]:
                try: sock.shutdown(socket.SHUT_WR)
                except OSError: pass
def private_directory(directory,uid):
    if uid<=0 or os.getuid()!=uid: raise Denied('uid')
    if not os.path.isabs(directory) or os.path.realpath(directory)!=directory: raise Denied('path')
    current='/'
    for part in directory.strip('/').split('/'):
        current=os.path.join(current,part); info=os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise Denied('path')
    info=os.lstat(directory)
    if info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700: raise Denied('owner')
def socket_identity(path,uid):
    info=os.lstat(path)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o600: raise Denied('socket')
    return (info.st_dev,info.st_ino)
def peer_uid(client,uid):
    if not hasattr(socket,'SO_PEERCRED'): raise Denied('peercred')
    pid,actual,gid=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if pid<=0 or actual!=uid: raise Denied('peercred')
def remove_owned_socket(directory,path,uid,identity):
    private_directory(directory,uid)
    if path!=os.path.join(directory,'connector.sock') or socket_identity(path,uid)!=identity: raise Denied('replacement')
    os.unlink(path)
def deadline_from_argv(argv):
    if len(argv)!=2 or len(argv[1])>32 or not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?',argv[1]): raise Denied('deadline')
    return validate_deadline(float(argv[1]))
def validate_deadline(deadline):
    if type(deadline) not in (int,float) or not math.isfinite(deadline): raise Denied('deadline')
    remaining=deadline-time.monotonic()
    if not 0<remaining<=300: raise Denied('deadline')
    return deadline
def serve(mode,directory,uid,deadline):
    validate_deadline(deadline) # Same acquisition deadline; no new work window.
    private_directory(directory,uid);path=os.path.join(directory,'connector.sock')
    stop=threading.Event();budget=Budget();gate=threading.BoundedSemaphore(4);workers=[]
    identity=None;listener=None; records=[]; lock=threading.Lock();active=set();unresolved=[];socket_created=False
    def track(sock):
        with lock:
            if stop.is_set(): sock.close();raise Denied('cancelled')
            active.add(sock)
    def finish(signum,frame): stop.set()
    signal.signal(signal.SIGTERM,finish);signal.signal(signal.SIGINT,finish)
    def worker(client):
        host=None;status='denied';remote=None
        try:
            check_cancel(stop,deadline)
            if mode=='connector': peer_uid(client,uid)
            raw=header(client,deadline,stop);host=authority(raw);check_cancel(stop,deadline)
            if mode=='connector':
                remote=connect_public(host,deadline,stop,track,unresolved);check_cancel(stop,deadline);established(client)
            else:
                if socket_identity(path,uid)!=identity: raise Denied('socket')
                check_cancel(stop,deadline)
                remote=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);track(remote);remote.settimeout(min(5,max(.001,deadline-time.monotonic())))
                check_cancel(stop,deadline);remote.connect(path);check_cancel(stop,deadline);peer_uid(remote,uid)
                check_cancel(stop,deadline)
                remote.sendall(raw)
            pump(client,remote,host,budget,deadline,stop);status='closed'
        except Exception: status='denied'
        finally:
            client.close()
            if remote: remote.close()
            with lock:
                active.discard(client);active.discard(remote);records.append({'host':host,'status':status})
            gate.release()
    try:
        if mode=='connector':
            if os.path.lexists(path): raise Denied('exists')
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            old=os.umask(0o177)
            try: listener.bind(path);socket_created=True
            finally: os.umask(old)
            identity=socket_identity(path,uid)
        elif mode=='adapter':
            identity=socket_identity(path,uid);listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0))
        else: raise Denied('mode')
        listener.listen(4);listener.settimeout(.25)
        print(json.dumps({'kind':'relay-ready','mode':mode,'port':listener.getsockname()[1] if mode=='adapter' else None}),flush=True)
        while not stop.is_set() and time.monotonic()<deadline:
            try: client,_=listener.accept()
            except socket.timeout: continue
            if stop.is_set(): client.close();break
            if not gate.acquire(False): client.close();continue
            try: budget.admit()
            except Denied: gate.release();client.close();continue
            try:
                track(client);check_cancel(stop,deadline)
                thread=threading.Thread(target=worker,args=(client,),daemon=True);thread.start();workers.append(thread)
            except BaseException:
                client.close()
                with lock: active.discard(client)
                gate.release();raise
    finally:
        stop.set()
        if listener: listener.close()
        with lock:
            for sock in active: sock.close()
        shutdown=time.monotonic()+10
        for thread in workers: thread.join(max(0,shutdown-time.monotonic()))
        unjoined=sum(thread.is_alive() for thread in workers)
        socket_absent=not socket_created
        if mode=='connector' and identity and not unjoined and not unresolved:
            try: remove_owned_socket(directory,path,uid,identity);socket_absent=True
            except Exception: socket_absent=False
        clean=not unjoined and not unresolved and socket_absent
        print(json.dumps({'kind':'relay-terminal','connections':budget.connections,'bytes':budget.total,'hostBytes':budget.hosts,'records':records,'unjoinedWorkers':unjoined,'unresolvedResolverCleanup':len(unresolved),'cleanupVerified':clean}),flush=True)
        # Outer launcher must own/reap this process group on any unresolved debt.
        if not clean: raise Denied('outer-cleanup-required')
`;
function guestProgram({runId,uid,mode,deadlineFromArgv}){
 if(!/^[a-f0-9]{32}$/.test(runId)||!Number.isSafeInteger(uid)||uid<=0||!['connector','adapter'].includes(mode)||deadlineFromArgv!==true)throw new Error('EGRESS_SPEC_INVALID');
 return program+`\nserve(${JSON.stringify(mode)},${JSON.stringify('/var/tmp/owasp-ai-goat-v23-relay-'+runId)},${uid},deadline_from_argv(sys.argv))\n`;
}
module.exports={HOSTS,LIMITS,guestProgram,_internals:{program}};
