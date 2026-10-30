"""Exact disposable Listings resource admission/cleanup; commands are injected."""
import hashlib
import json
import subprocess
import re

from sql_nosql_docker_ownership import verify_daemon

HEX = re.compile(r'^[a-f0-9]{64}$')


def private_handoff(value):
    """Closed, copied authority for the retained Listings manager, not shared Docker."""
    keys = {'runId', 'root', 'filesystemDevice', 'filesystemInode', 'namespaceInode',
            'holderPid', 'holderStart', 'containerPid', 'containerStart', 'containerId',
            'imageId', 'sourceSha256', 'runtimeSha256', 'environmentSha256', 'publicOrigin',
            'workspaceId', 'profileName', 'profileSha256', 'containerName', 'privateDockerHost', 'daemonId'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    row = json.loads(json.dumps(value))
    if (not isinstance(row['runId'], str) or not re.fullmatch('[a-f0-9]{32}', row['runId'])
            or row['root'] != '/var/tmp/owasp-ai-goat-v23-build-' + row['runId'] + '/fs'):
        raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    for key in ('filesystemDevice', 'filesystemInode', 'namespaceInode', 'holderPid',
                'holderStart', 'containerPid', 'containerStart'):
        if type(row[key]) is not int or row[key] <= 1:
            raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    for key in ('containerId', 'sourceSha256', 'runtimeSha256', 'environmentSha256', 'profileSha256'):
        if not isinstance(row[key], str) or not HEX.fullmatch(row[key]):
            raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    if not isinstance(row['imageId'], str) or not re.fullmatch('sha256:[a-f0-9]{64}', row['imageId']):
        raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    if (not isinstance(row['workspaceId'],str) or not re.fullmatch('[a-f0-9]{12}',row['workspaceId'])
            or row['profileName']!='owasp-ai-goat-owned-listings-'+row['workspaceId']
            or row['containerName']!=row['profileName']
            or row['privateDockerHost']!='unix://'+row['root']+'/docker.sock'
            or not isinstance(row['daemonId'],str) or not re.fullmatch('[a-f0-9-]{16,}',row['daemonId'])):
        raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    origin = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{1,5})', row['publicOrigin']) if isinstance(row['publicOrigin'], str) else None
    if origin is None or not 1024 <= int(origin[1]) <= 65535:
        raise ValueError('LISTINGS_PRIVATE_HANDOFF')
    return row


def private_channel_program(handoff, channel_id, seconds):
    row = private_handoff(handoff)
    if (not isinstance(channel_id, str) or not re.fullmatch('[a-f0-9]{32}', channel_id)
            or type(seconds) is not int or not 1 <= seconds <= 120):
        raise ValueError('LISTINGS_PRIVATE_CHANNEL')
    return 'H=' + repr(row) + '\nCHANNEL=' + repr(channel_id) + '\nSECONDS=' + repr(seconds) + '\nend=__import__("time").monotonic()+SECONDS\n' + _PRIVATE_CHANNEL


_PRIVATE_CHANNEL = r'''
import ctypes,hashlib,json,os,pwd,select,socket,stat,subprocess,time
from pathlib import Path
def need(ok):
 if not ok:raise RuntimeError('LISTINGS_PRIVATE_CHANNEL_DENIED')
need(os.geteuid()==0)
root=Path(H['root']);point=Path('/')
for part in root.parts[1:]:
 point=point/part;s=point.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not stat.S_ISLNK(s.st_mode))
s=root.stat();need((s.st_dev,s.st_ino)==(H['filesystemDevice'],H['filesystemInode']))
def birth(pid):return int(Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
def identity():
 for name in ('holder','container'):
  pid=H[name+'Pid'];need(birth(pid)==H[name+'Start'])
  need(os.stat('/proc/'+str(pid)+'/ns/net').st_ino==H['namespaceInode'])
 need(os.readlink('/proc/'+str(H['holderPid'])+'/exe')=='/usr/bin/sleep')
 need(H['namespaceInode']!=os.stat('/proc/1/ns/net').st_ino)
identity()
child=subprocess.Popen(['/usr/bin/docker','--host','unix://'+str(root/'docker.sock'),'inspect',H['containerId']],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
buffers={child.stdout:bytearray(),child.stderr:bytearray()};pending=set(buffers);inspect_end=time.monotonic()+5
try:
 for stream in pending:os.set_blocking(stream.fileno(),False)
 while pending:
  need(time.monotonic()<inspect_end)
  ready,_,_=select.select(list(pending),[],[],min(.1,max(0,inspect_end-time.monotonic())))
  for stream in ready:
   chunk=os.read(stream.fileno(),16384)
   if not chunk:pending.remove(stream);continue
   buffers[stream].extend(chunk);need(len(buffers[stream])<=(1048576 if stream is child.stdout else 65536))
 need(child.wait(timeout=max(.001,inspect_end-time.monotonic()))==0)
finally:
 try:
  if child.poll() is None:
   child.terminate()
   try:child.wait(timeout=1)
   except subprocess.TimeoutExpired:child.kill();child.wait(timeout=1)
 finally:child.stdout.close();child.stderr.close()
rows=json.loads(buffers[child.stdout]);need(isinstance(rows,list) and len(rows)==1);c=rows[0]
need(c['Id']==H['containerId'] and c['Image']==H['imageId'] and c['State']['Running'] is True and c['State']['Pid']==H['containerPid'])
labels=c['Config']['Labels'];need(labels.get('owasp-ai-goat.test.owner')==H['runId'])
need(labels.get('owasp-ai-goat.listings.source')==H['sourceSha256'] and labels.get('owasp-ai-goat.listings.runtime')==H['runtimeSha256'])
profile=H['profileName'];volume='owasp-ai-goat-listings-journal-'+H['runId']
need(c['Name']=='/'+H['containerName'])
need(c['Config']['Entrypoint']==['node'] and c['Config']['Cmd']==['/app/sidecars/sandbox-runner/owned-listings/manager-entry.js'])
need(c['Config']['User']=='10001:10001' and c['HostConfig']['NetworkMode']=='host')
need(c['HostConfig']['ReadonlyRootfs'] is True and c['HostConfig']['Privileged'] is False and not c['HostConfig'].get('PortBindings'))
host=c['HostConfig']
need(host['Memory']==536870912 and host['NanoCpus']==1000000000 and host['PidsLimit']==128)
need(host['CapDrop']==['ALL'] and host.get('CapAdd') in (None,[]))
need(set(host['SecurityOpt'])=={'apparmor='+profile,'seccomp=unconfined'} and c['AppArmorProfile']==profile)
need(host['Tmpfs']=={'/tmp':'rw,nosuid,nodev,noexec,size=16m'})
need(host['LogConfig']=={'Type':'local','Config':{'max-size':'1m','max-file':'1','compress':'false'}})
mounts=c['Mounts']
need(type(mounts) is list and len(mounts)==1 and type(mounts[0]) is dict)
mount=mounts[0]
need(type(mount.get('Mode')) is str and mount['Mode'] in ('','z') and mount.get('RW') is True)
need(mount=={'Type':'volume','Name':volume,'Source':str(root/'data'/'volumes'/volume/'_data'),'Destination':'/journal','Driver':'local','Mode':mount['Mode'],'RW':True,'Propagation':''})
keys={'LISTINGS_MANAGER_ENABLED','LISTINGS_PROFILE','LISTINGS_PUBLIC_ORIGIN','LISTINGS_CONTROL_TOKEN'}
env=[v for v in c['Config']['Env'] if v.split('=',1)[0] in keys]
need(len(env)==4 and len({v.split('=',1)[0] for v in env})==4)
need('LISTINGS_PUBLIC_ORIGIN='+H['publicOrigin'] in env and 'LISTINGS_MANAGER_ENABLED=true' in env)
need('LISTINGS_PROFILE='+profile in env)
need(hashlib.sha256('\n'.join(sorted(env)).encode()).hexdigest()==H['environmentSha256'])
identity()
import fcntl
lock=os.open(root/'listings-channel.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
journal=None;admitted=False
try:
 ls=os.fstat(lock);need(stat.S_ISREG(ls.st_mode) and ls.st_uid==0 and ls.st_nlink==1 and stat.S_IMODE(ls.st_mode)==0o600)
 while True:
  remaining=end-time.monotonic();need(remaining>0)
  try:
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   need(time.monotonic()<end);break
  except BlockingIOError:
   remaining=end-time.monotonic();need(remaining>0)
   time.sleep(min(.01,remaining))
 need(not (root/'listings-channel-admission-closed').exists())
 journal=os.open(root/('listings-channel-'+CHANNEL+'.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 def record(value):
  raw=(json.dumps(value,sort_keys=True)+'\n').encode();need(len(raw)<=2048)
  while raw:
   n=os.write(journal,raw);need(n>0);raw=raw[n:]
  os.fsync(journal)
 record(dict(version=1,runId=H['runId'],channelId=CHANNEL,pid=os.getpid(),startTicks=birth(os.getpid()),namespaceInode=H['namespaceInode'],stage='started'))
 directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(directory)
 finally:os.close(directory)
 admitted=True
finally:
 os.close(lock)
 if not admitted and journal is not None:os.close(journal)
sock=None;complete=False;sent=received=0
try:
 fd=os.open('/proc/'+str(H['holderPid'])+'/ns/net',os.O_RDONLY)
 try:
  need(os.fstat(fd).st_ino==H['namespaceInode']);identity()
  libc=ctypes.CDLL(None,use_errno=True);need(libc.setns(fd,0)==0)
 finally:os.close(fd)
 need(os.stat('/proc/self/ns/net').st_ino==H['namespaceInode'])
 account=pwd.getpwnam('lima');need(account.pw_uid==501 and account.pw_gid>0)
 need(libc.prctl(38,1,0,0,0)==0);os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
 remaining=end-time.monotonic();need(remaining>0)
 sock=socket.socket();sock.settimeout(min(5,remaining));sock.connect(('127.0.0.1',8095));need(time.monotonic()<end);sock.setblocking(False)
 os.set_blocking(0,False);os.set_blocking(1,False)
 incoming=bytearray();outgoing=bytearray();eof=False;peer=False;half=False
 while time.monotonic()<end:
  reads=([0] if not eof and len(incoming)<65536 else [])+([sock] if not peer and len(outgoing)<65536 else [])
  writes=([sock] if incoming else [])+([1] if outgoing else [])
  rr,ww,_=select.select(reads,writes,[],min(.25,max(0,end-time.monotonic())))
  if 0 in rr:
   b=os.read(0,16384)
   if b:incoming.extend(b)
   else:eof=True
  if sock in rr:
   b=sock.recv(16384)
   if b:outgoing.extend(b)
   else:peer=True
  need(sent+len(incoming)<=8388608 and received+len(outgoing)<=8388608)
  if sock in ww:
   n=sock.send(incoming);need(n>0);del incoming[:n];sent+=n
  if 1 in ww:
   n=os.write(1,outgoing);need(n>0);del outgoing[:n];received+=n
  if eof and not incoming and not half:sock.shutdown(socket.SHUT_WR);half=True
  if peer and not outgoing:complete=True;break
 need(complete)
finally:
 if sock is not None:sock.close()
 try:record(dict(version=1,runId=H['runId'],channelId=CHANNEL,stage='terminal',complete=complete,sentBytes=sent,receivedBytes=received))
 finally:os.close(journal)
'''


def private_channels_retirement_program(handoff, channels):
    row = private_handoff(handoff)
    if (not isinstance(channels, (tuple, list)) or len(channels)>32
            or any(not isinstance(c,str) or not re.fullmatch('[a-f0-9]{32}',c) for c in channels)
            or len(set(channels))!=len(channels)):
        raise ValueError('LISTINGS_PRIVATE_CHANNELS')
    # Reuse the exact pre-inspect filesystem/birth/namespace guard. Manager and
    # holder must still be alive; channels retire before the manager is stopped.
    prefix=_PRIVATE_CHANNEL[:_PRIVATE_CHANNEL.index('child=subprocess.Popen')]
    return 'H='+repr(row)+'\nCHANNELS='+repr(list(channels))+'\n'+prefix+r'''
import fcntl
lock=os.open(root/'listings-channel.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
ls=os.fstat(lock);need(stat.S_ISREG(ls.st_mode) and ls.st_uid==0 and ls.st_nlink==1 and stat.S_IMODE(ls.st_mode)==0o600)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
fence=os.open(root/'listings-channel-admission-closed',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:os.write(fence,H['runId'].encode());os.fsync(fence)
finally:os.close(fence)
directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(directory)
finally:os.close(directory)
expected={'listings-channel-'+c+'.jsonl' for c in CHANNELS}
need({p.name for p in root.iterdir() if p.name.startswith('listings-channel-') and p.name!='listings-channel-admission-closed'}==expected)
proof=[]
for channel in CHANNELS:
 path=root/('listings-channel-'+channel+'.jsonl')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=4096)
  raw=os.read(fd,4097);after=os.fstat(fd)
  need(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
 finally:os.close(fd)
 rows=[json.loads(line) for line in raw.splitlines()];need(len(rows)==2)
 first,last=rows
 need(set(first)=={'version','runId','channelId','pid','startTicks','namespaceInode','stage'})
 need(first['version']==1 and first['runId']==H['runId'] and first['channelId']==channel and first['stage']=='started' and first['namespaceInode']==H['namespaceInode'])
 need(type(first['pid']) is int and first['pid']>1 and type(first['startTicks']) is int and first['startTicks']>1)
 need(set(last)=={'version','runId','channelId','stage','complete','sentBytes','receivedBytes'})
 need(last['version']==1 and last['runId']==H['runId'] and last['channelId']==channel and last['stage']=='terminal' and type(last['complete']) is bool)
 for key in ('sentBytes','receivedBytes'):need(type(last[key]) is int and 0<=last[key]<=8388608)
 # Terminal rows, including failures, do not themselves prove process absence.
 need(not Path('/proc/'+str(first['pid'])).exists())
 proof.append(dict(channelId=channel,sha256=hashlib.sha256(raw).hexdigest(),pid=first['pid'],startTicks=first['startTicks'],complete=last['complete']))
identity()
print(json.dumps(dict(version=1,runId=H['runId'],remoteChannelsAbsent=True,channels=proof),sort_keys=True))
fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
'''


class PrivateListingsBridge:
    """One owned host listener; remote terminal proof is deliberately separate."""
    def __init__(self, root, handoff, deadline):
        import time
        import threading
        from pathlib import Path
        import owned_mcp_mux_relay as mux
        source = Path(root).resolve() / 'tests/postgres/owned_mcp_mux_relay.py'
        if (Path(mux.__file__).resolve() != source
                or hashlib.sha256(source.read_bytes()).hexdigest() !=
                '345ab0b2d82a71e678759a4ff42386e341f1f036c0ae1edcab4e21497619e253'
                or type(deadline) not in (int, float) or not 0 < deadline-time.monotonic() <= 600):
            raise ValueError('LISTINGS_BRIDGE_ADMISSION')
        self.root, self._handoff, self.deadline, self.mux = Path(root).resolve(), (private_handoff(handoff) if handoff is not None else None), deadline, mux
        self.stop = threading.Event(); self.guard = threading.Lock()
        self.children = set(); self.clients = set(); self.threads = []; self.channels = []; self.channel_states = {}
        self.failures = []; self.listener = None; self.acceptor = None; self.authority = None

    def open(self):
        import socket
        import threading
        import time
        if self.listener is not None or self.stop.is_set() or time.monotonic() >= self.deadline:
            raise RuntimeError('LISTINGS_BRIDGE_STATE')
        self.authority = self.mux.admit_existing_mux(self.root)
        self.listener = socket.socket()
        try:
            self.listener.bind(('127.0.0.1', 0)); self.listener.listen(4); self.listener.settimeout(.1)
            self.origin = 'http://127.0.0.1:' + str(self.listener.getsockname()[1])
            return self.origin
        except BaseException:
            self.stop.set(); self.listener.close(); raise

    def activate(self, handoff):
        """After manager startup, bind its observed identity to the reserved origin."""
        import threading
        import time
        if self.listener is None or self.acceptor is not None or self.stop.is_set() or time.monotonic() >= self.deadline:
            raise RuntimeError('LISTINGS_BRIDGE_STATE')
        captured = private_handoff(handoff)
        if captured['publicOrigin'] != self.origin or (self._handoff is not None and captured != self._handoff):
            raise RuntimeError('LISTINGS_BRIDGE_IDENTITY_CHANGED')
        self._handoff = captured
        self.acceptor = threading.Thread(target=self._accept, daemon=True); self.acceptor.start()

    def _accept(self):
        import socket
        import threading
        import time
        accepted = 0
        try:
            while not self.stop.is_set():
                if time.monotonic() >= self.deadline: raise RuntimeError('LISTINGS_BRIDGE_DEADLINE')
                try: client, address = self.listener.accept()
                except socket.timeout: continue
                try:
                    with self.guard:
                        if address[0] != '127.0.0.1' or accepted >= 32 or len(self.clients) >= 4 or self.stop.is_set():
                            raise RuntimeError('LISTINGS_BRIDGE_CONNECTIONS')
                        self.clients.add(client)
                        thread = threading.Thread(target=self._connection, args=(client,), daemon=True)
                        self.threads.append(thread)
                    thread.start(); accepted += 1
                except BaseException:
                    with self.guard: self.clients.discard(client)
                    client.close(); raise
        except BaseException as error:
            if not self.stop.is_set(): self.failures.append(type(error).__name__)
            self.stop.set()

    def _connection(self, client):
        import shlex
        import time
        import uuid
        try:
            authority = self.mux.admit_existing_mux(self.root, self.authority)
            seconds = min(120, int(self.deadline-time.monotonic())-7)
            if self.stop.is_set(): return
            channel = uuid.uuid4().hex
            with self.guard: self.channel_states[channel] = 'reserved'
            program = private_channel_program(self._handoff, channel, seconds)
            argv = self.mux.mux_command(authority, shlex.join(['sudo', '-n', 'timeout',
                '--signal=TERM', '--kill-after=2', str(seconds+5), '/usr/bin/python3', '-I', '-S', '-B', '-c', program]))
            def before_spawn():
                with self.guard:
                    if self.channel_states[channel] != 'reserved':
                        raise RuntimeError('LISTINGS_BRIDGE_CHANNEL_STATE')
                    self.channel_states[channel] = 'spawn_attempted'
                    self.channels.append(channel)
            outcome = self.mux.relay_connection(client, argv, self.stop, self.children,
                                                self.guard, before_spawn=before_spawn)
            if outcome == 'never_attempted':
                with self.guard:
                    if self.channel_states[channel] != 'reserved':
                        raise RuntimeError('LISTINGS_BRIDGE_CHANNEL_STATE')
                    self.channel_states[channel] = 'never_attempted'
        except BaseException as error:
            self.failures.append(type(error).__name__); self.stop.set()
        finally:
            client.close()
            with self.guard: self.clients.discard(client)

    def close(self, deadline):
        import time
        if type(deadline) not in (int, float) or not time.monotonic() < deadline <= time.monotonic()+10:
            raise ValueError('LISTINGS_BRIDGE_CLEANUP_DEADLINE')
        self.stop.set(); errors = []
        if self.listener is not None:
            try: self.listener.close()
            except BaseException as error: errors.append(error)
        with self.guard: clients = tuple(self.clients)
        for client in clients:
            try: client.shutdown(2)
            except OSError: pass
            try: client.close()
            except BaseException as error: errors.append(error)
        if self.acceptor is not None and self.acceptor.ident is not None:
            self.acceptor.join(max(0, deadline-time.monotonic()))
        for thread in self.threads:
            if thread.ident is not None: thread.join(max(0, deadline-time.monotonic()))
        with self.guard:
            joined = not self.children and not self.clients and not any(t.is_alive() for t in self.threads)
            states = tuple(dict(channelId=channel, state=state)
                           for channel, state in self.channel_states.items())
            attempted = tuple(self.channels)
            committed = {row['channelId'] for row in states if row['state'] == 'spawn_attempted'}
            unresolved = any(row['state'] not in ('never_attempted', 'spawn_attempted') for row in states)
        if errors or not joined or unresolved or set(attempted) != committed or \
                len(set(attempted)) != len(attempted) or \
                (self.acceptor is not None and self.acceptor.is_alive()):
            raise RuntimeError('LISTINGS_BRIDGE_RETIREMENT_UNPROVEN')
        return dict(listenerClosed=True, localChannelsRetired=True, remoteChannelsVerified=False,
                    channelIds=attempted, channelStates=states, failures=tuple(self.failures))


def inspect(command, kind, name):
    parts = ['inspect', '--type', 'container', name] if kind == 'container' else [kind, 'inspect', name]
    result = command(parts)
    if result.returncode:
        absent = {
            'container': [f'Error: No such object: {name}', f'Error: No such container: {name}',
                          f'Error response from daemon: No such container: {name}'],
            'network': [f'Error response from daemon: network {name} not found', f'Error: No such network: {name}'],
            'volume': [f'Error response from daemon: get {name}: no such volume',
                       f'Error response from daemon: no such volume: {name}'],
        }
        if result.returncode == 1 and result.stderr.strip() in absent[kind]:
            return None
        raise RuntimeError('Listings resource absence unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError('Listings resource inspection invalid')
    return rows[0]


def owned(command, state, kind):
    row = inspect(command, kind, state[kind])
    if row is None:
        if kind == 'container' and state.get('containerId') and inspect(command, kind, state['containerId']) is not None:
            raise RuntimeError('Listings container was renamed')
        return None
    labels = row.get('Config', {}).get('Labels') if kind == 'container' else row.get('Labels')
    expected_name = '/' + state[kind] if kind == 'container' else state[kind]
    if row.get('Name') != expected_name or not isinstance(labels, dict) or any(
            labels.get(k) != v for k, v in state['labels'].items()):
        raise RuntimeError('Refusing foreign Listings resource')
    if kind in ('container', 'network'):
        identifier = row.get('Id', '')
        if not HEX.fullmatch(identifier) or state.get(kind + 'Id', identifier) != identifier:
            raise RuntimeError('Listings resource identity changed')
        state[kind + 'Id'] = identifier
    if kind == 'container':
        host = row.get('HostConfig', {})
        mounts = row.get('Mounts')
        packaged = state.get('packaged') is True
        bindings = {} if packaged else {'8095/tcp': [{'HostIp': '127.0.0.1', 'HostPort': state['port']}]}
        if (row.get('Image') != state['image'] or row.get('Config', {}).get('User') != '10001:10001'
                or host.get('NetworkMode') != state['network'] or host.get('ReadonlyRootfs') is not True
                or host.get('Privileged') is not False or host.get('Memory') != 536870912
                or host.get('NanoCpus') != 1000000000 or host.get('PidsLimit') != 128
                or host.get('CapDrop') != ['ALL'] or host.get('CapAdd') not in (None, [])
                or set(host.get('SecurityOpt') or []) != {'apparmor=' + state['profile']['name'], 'seccomp=unconfined'}
                or host.get('Tmpfs') != {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'}
                or (host.get('PortBindings') or {}) != bindings or not isinstance(mounts, list) or len(mounts) != 1
                or mounts[0].get('Type') != 'volume' or mounts[0].get('Name') != state['volume']
                or mounts[0].get('Destination') != '/journal' or mounts[0].get('RW') is not True
                or mounts[0].get('Source') != state.get('volumeMountpoint')):
            raise RuntimeError('Listings container resources changed')
        environment = row.get('Config', {}).get('Env')
        keys = ('LISTINGS_PROFILE',) if packaged else ('LISTINGS_MANAGER_ENABLED', 'LISTINGS_PROFILE', 'LISTINGS_PUBLIC_ORIGIN', 'LISTINGS_CONTROL_TOKEN')
        values = [value for value in environment or [] if isinstance(value, str) and value.split('=', 1)[0] in keys]
        if (len(values) != len(keys) or len({v.split('=', 1)[0] for v in values}) != len(keys)
                or hashlib.sha256('\n'.join(sorted(values)).encode()).hexdigest() != state.get('environmentSha256')):
            raise RuntimeError('Listings manager environment changed')
        networks = row.get('NetworkSettings', {}).get('Networks')
        if not isinstance(networks, dict) or set(networks) - {state['network']}:
            raise RuntimeError('Listings foreign container endpoint')
        if networks and not packaged and networks[state['network']].get('NetworkID') != state.get('networkId'):
            raise RuntimeError('Listings network identity changed')
        if packaged and (row.get('Config', {}).get('Entrypoint') != ['node']
                or row.get('Config', {}).get('Cmd') != ['/app/tests/fixtures/secureshopOwnedListingsPackaged.native.cjs']
                or row.get('NetworkSettings', {}).get('Ports') not in (None, {})):
            raise RuntimeError('Listings packaged fixture identity changed')
    elif kind == 'network':
        endpoints = row.get('Containers')
        if (row.get('Driver') != 'bridge' or row.get('Internal') is not False
                or row.get('Options') not in (None, {}) or not isinstance(endpoints, dict)
                or set(endpoints) - ({state['containerId']} if state.get('containerId') else set())):
            raise RuntimeError('Listings network resources changed')
    else:
        point = row.get('Mountpoint')
        if (row.get('Driver') != 'local' or row.get('Scope') != 'local'
                or row.get('Options') not in (None, {}) or not isinstance(point, str) or not point.startswith('/')
                or state.get('volumeMountpoint', point) != point):
            raise RuntimeError('Listings volume identity changed')
        state['volumeMountpoint'] = point
    return row


def no_foreign_attachments(command, state, allow_owned=False):
    result = command(['ps', '-aq', '--no-trunc'])
    ids = result.stdout.split()
    if result.returncode or len(ids) > 4096 or len(set(ids)) != len(ids) or any(not HEX.fullmatch(i) for i in ids):
        raise RuntimeError('Listings attachment inventory unavailable')
    for identifier in ids:
        row = inspect(command, 'container', identifier)
        if row is None:
            continue
        if allow_owned and identifier == state.get('containerId'):
            continue
        networks = row.get('NetworkSettings', {}).get('Networks')
        mounts = row.get('Mounts')
        status = row.get('State')
        if not isinstance(networks, dict) or not isinstance(mounts, list) or not isinstance(status, dict) or type(status.get('Running')) is not bool:
            raise RuntimeError('Listings attachment inventory invalid')
        profile = row.get('AppArmorProfile')
        security = row.get('HostConfig', {}).get('SecurityOpt') or []
        if ((state['network'] != 'none' and state['network'] in networks)
                or (state.get('networkId') and any(n.get('NetworkID') == state['networkId'] for n in networks.values()))
                or any(m.get('Type') == 'volume' and m.get('Name') == state['volume'] for m in mounts)
                or profile == state['profile']['name']
                or isinstance(profile, str) and profile.startswith(state['profile']['name'] + '//')
                or 'apparmor=' + state['profile']['name'] in security):
            raise RuntimeError('Listings resources attached to another container')


def capture_container(command, state):
    """Recover create acknowledgement only from exact labeled name and resources."""
    verify_daemon(command, state['daemon'])
    # Capture ID before checking the bridge's endpoint set.
    row = inspect(command, 'container', state['container'])
    if row is None:
        raise RuntimeError('Listings manager creation unconfirmed')
    candidate = row.get('Id', '')
    if not HEX.fullmatch(candidate) or state.get('containerId', candidate) != candidate:
        raise RuntimeError('Listings container identity changed')
    state['containerId'] = candidate
    if state.get('packaged') is not True:
        owned(command, state, 'network')
    owned(command, state, 'volume')
    row = owned(command, state, 'container')
    no_foreign_attachments(command, state, allow_owned=True)
    return row


def cleanup(command, state, remove_profile, persist=lambda: None):
    """Preflight the whole owned set, then remove by exact captured identity."""
    verify_daemon(command, state['daemon'])
    attempted = state.get('attempted', [])
    # A lost run response may still have created a labeled container.
    if 'container' in attempted:
        row = inspect(command, 'container', state['container'])
        if row is not None:
            capture_container(command, state)
            persist()
        elif state.get('containerId') and inspect(command, 'container', state['containerId']) is not None:
            raise RuntimeError('Listings container was renamed')
    for kind in ('network', 'volume'):
        if kind in attempted:
            owned(command, state, kind)
    no_foreign_attachments(command, state, allow_owned=True)
    result = {}
    for kind in ('container', 'volume', 'network'):
        if kind not in attempted:
            continue
        verify_daemon(command, state['daemon'])
        row = owned(command, state, kind)
        if row is not None:
            if kind != 'container':
                no_foreign_attachments(command, state)
            target = row['Id'] if kind in ('container', 'network') else row['Name']
            # A lost removal ACK is resolved solely by exact absence below.
            try:
                command(['rm', '--force', target] if kind == 'container' else [kind, 'rm', target])
            except (TimeoutError, OSError, subprocess.TimeoutExpired):
                pass
            if owned(command, state, kind) is not None:
                raise RuntimeError('Listings resource removal unconfirmed')
        result[kind + 'Absent'] = True
        persist()
    if 'profile' in attempted:
        verify_daemon(command, state['daemon'])
        no_foreign_attachments(command, state)
        remove_profile(state['profile'])
        result['profileAbsent'] = True
    return result
