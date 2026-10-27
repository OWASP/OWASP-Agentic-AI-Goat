'use strict';

// Explicit qualification helper: import performs no I/O or process launch.
// A built image is not activation, native confinement, or model qualification.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const source = require('../../scripts/install/secureshop-owned-mcp-registry-setup')._internals;
const authority = require('../../scripts/install/manifests/secureshop-owned-mcp-registry-build.json');
const GIB = 1024 ** 3;
const LIMITS = Object.freeze({disk:6*GIB, export:GIB, output:2*1024**2, buildMs:300000});
const PINS = Object.freeze({
  lima:'6d32fb0f880c0ea750434f2ac855a3f2129126752a301ce4d88adbd2fa599e1e',
  daemon:'945f6fce-3aaf-4d8f-a483-170464fb2416',
  postgres:'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336',
  dockerd:'eb4bf018da78f7b9d01d69209d0944d1fe995869ac3caefa5c93e4552e181301',
  containerd:'618ab28107664e3d5219b836031d6016cef05ab0f392f0811e0f4dac1dff7a3d',
});
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const fail = code => Object.assign(new Error(code),{code});
const RELAY_SOURCE_SHA = '2f1ac0b8bace7bbd97001d3c5bea836c0b3906d05f6156d458aee465431bf102';
// Prospective lifecycle only. This admission describes already inspected guest
// identities; structural validation is not permission to launch or acquire.
function relayAdmission(value) {
  if(!value||Object.keys(value).sort().join(',')!=='account,gid,python,pythonSha256,setprivSha256,uid'||
    !/^[a-z_][a-z0-9_-]{0,31}$/.test(value.account)||
    !Number.isSafeInteger(value.uid)||value.uid<=0||value.uid>2147483647||
    !Number.isSafeInteger(value.gid)||value.gid<=0||value.gid>2147483647||
    !/^\/usr\/bin\/python3\.[0-9]{1,2}$/.test(value.python)||
    !/^[a-f0-9]{64}$/.test(value.pythonSha256)||! /^[a-f0-9]{64}$/.test(value.setprivSha256))throw fail('BUILD_RELAY_ADMISSION_REQUIRED');
  return Object.freeze({...value});
}
const relayLifecycleProgram=String.raw`
import os, sys, json, stat, time, signal, subprocess, hashlib, pwd, selectors, re, math
class RelayFailure(Exception): pass
class RelayExitTransition(RelayFailure): pass
def require(condition,reason='ownership_unproven'):
    if not condition:
        error=RelayFailure('BUILD_RELAY_OWNERSHIP_UNPROVEN');error.reason=reason;raise error
def mark_lookup(error,site):
    error.lookupSite=site
    return error
def cleanup_diagnostic(details):
    # Evidence only: closed literals, at most one failure per relay. Never
    # serialize an exception, process identity, argv, path or environment.
    try:
        modes=('adapter','connector')
        stages=('record','group_check','leader_check','signal','join')
        reasons=('ownership_unproven','record_missing','record_invalid','birth_group_session',
          'executable_argv','namespace_identity','privilege_state','descendant_identity',
          'process_lookup_unproven','signal_failed','deadline_exhausted','unexpected_failure')
        sites=('proc_stat','proc_recheck_stat','proc_link','group_stat','group_member')
        rows=[]
        for mode in modes:
            if mode not in details: continue
            stage,reason,site=details[mode]
            row=dict(mode=mode,stage=stage if stage in stages else 'join',
              reason=reason if reason in reasons else 'unexpected_failure')
            if site in sites: row['lookupSite']=site
            rows.append(row)
        packet=json.dumps(dict(kind='relay-cleanup-failure',version=1,failures=rows),separators=(',',':'))
        if len(packet)<=1024: print(packet,file=sys.stderr,flush=True)
    except BaseException: pass # Reporting must not replace the ownership failure.
def digest(value): return hashlib.sha256(value).hexdigest()
def regular(path,mode=None):
    info=os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022)
    if mode is not None: require(stat.S_IMODE(info.st_mode)==mode)
    return info
def read(path):
    regular(path);require(os.path.getsize(path)<=262144)
    with open(path,'r') as handle: return handle.read()
def save(name,value):
    path=ROOT+'/fs/'+name
    with open(path,'x',encoding='utf-8') as handle:
        os.chmod(path,0o600);handle.write(json.dumps(value,separators=(',',':')));handle.flush();os.fsync(handle.fileno())
def exists(pid): return os.path.isdir('/proc/'+str(pid))
def proc(pid):
    base='/proc/'+str(pid)
    try:
        with open(base+'/stat') as handle: fields=handle.read().rsplit(')',1)[1].split()
    except (FileNotFoundError,ProcessLookupError) as error:
        raise mark_lookup(error,'proc_stat')
    # A zombie/exiting task is still present, but exe/net may already be gone.
    # Cleanup may wait for independent absence; it must neither signal nor
    # mistake this transition for absence or a replacement process.
    if fields[0] in ('Z','X'): raise RelayExitTransition('BUILD_RELAY_EXIT_PENDING')
    with open(base+'/cmdline','rb') as handle: args=handle.read().split(b'\0')[:-1]
    with open(base+'/status') as handle: status=dict(line.split(':',1) for line in handle if ':' in line)
    try:
        executable=os.readlink(base+'/exe');network=os.readlink(base+'/ns/net')
    except (FileNotFoundError,ProcessLookupError) as error:
        try:
            with open(base+'/stat') as handle: after=handle.read().rsplit(')',1)[1].split()
        except (FileNotFoundError,ProcessLookupError) as recheck_error:
            raise mark_lookup(recheck_error,'proc_recheck_stat')
        try: require(after[19]==fields[19])
        except RelayFailure as mismatch:
            raise mark_lookup(mismatch,'proc_recheck_stat')
        if after[0] in ('Z','X'): raise RelayExitTransition('BUILD_RELAY_EXIT_PENDING')
        raise mark_lookup(error,'proc_link')
    return dict(pid=pid,start=int(fields[19]),pgid=int(fields[2]),sid=int(fields[3]),exe=executable,
      argv=[arg.decode() for arg in args],net=network,
      uids=[int(x) for x in status['Uid'].split()],gids=[int(x) for x in status['Gid'].split()],
      groups=status['Groups'].split(),caps=[int(status[key],16) for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')],
      noNewPrivs=int(status['NoNewPrivs']))
def group_members(pgid):
    rows=[]
    for name in os.listdir('/proc'):
        if not name.isdigit(): continue
        site='group_stat'
        try:
            with open('/proc/'+name+'/stat') as handle: fields=handle.read().rsplit(')',1)[1].split()
            if int(fields[2])==pgid:
                site='group_member';rows.append(proc(int(name)))
        except (FileNotFoundError,ProcessLookupError):
            try: require(not exists(int(name)))
            except RelayFailure as error: raise mark_lookup(error,site)
    return rows
def context():
    require(os.geteuid()==0 and ROOT=='/var/tmp/dvaia-v23-build-'+RUN and os.path.realpath(ROOT)==ROOT)
    info=os.lstat(ROOT);require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    require(os.path.realpath(ROOT+'/fs')==ROOT+'/fs');info=os.lstat(ROOT+'/fs')
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
    require(read(ROOT+'/owner')==RUN)
    account=pwd.getpwnam(ADMISSION['account']);require(account.pw_uid==ADMISSION['uid'] and account.pw_gid==ADMISSION['gid'])
    for path,key in ((ADMISSION['python'],'pythonSha256'),('/usr/bin/setpriv','setprivSha256')):
        regular(path);require(os.path.realpath(path)==path)
        with open(path,'rb') as handle: require(digest(handle.read())==ADMISSION[key])
    require(os.path.realpath('/usr/bin/nsenter')=='/usr/bin/nsenter');regular('/usr/bin/nsenter')
def namespace_coordinate(value):
    # readlink journals have one terminal LF; preserve the raw journal and
    # normalize only this typed coordinate, never logs or arbitrary whitespace.
    if value.endswith('\n'): value=value[:-1]
    require(re.fullmatch(r'net:\[[1-9][0-9]*\]',value) is not None)
    return value
def coordinates():
    private=namespace_coordinate(read(ROOT+'/fs/namespace.inode'));shared=namespace_coordinate(read(ROOT+'/fs/shared.inode'))
    require(private!=shared)
    shared_pid=int(read(ROOT+'/fs/shared.pid'));row=proc(shared_pid)
    require(row['start']==int(read(ROOT+'/fs/shared.start')) and row['exe']=='/usr/bin/dockerd' and row['net']==shared and shared==os.readlink('/proc/1/ns/net'))
    return private,shared
def check_child(row,current):
    require(current['pid']==row['pid'] and current['start']==row['start'] and current['pgid']==row['pid'] and current['sid']==row['pid'],'birth_group_session')
    require(current['exe']==ADMISSION['python'] and current['argv']==[ADMISSION['python'],'-I','-S','-B','-',row['deadline']],'executable_argv')
    check_privileges(current,row['net'])
def check_privileges(current,net):
    require(current['net']==net and current['uids']==[ADMISSION['uid']]*4 and current['gids']==[ADMISSION['gid']]*4,'namespace_identity')
    require(not current['groups'] and not any(current['caps']) and current['noNewPrivs']==1,'privilege_state')
def check_group(row):
    members=group_members(row['pid'])
    if not members:
        if exists(row['pid']): require(proc(row['pid'])['start']!=row['start'],'birth_group_session')
        return []
    # A vanished leader with surviving descendants is uncertainty, not a group
    # we may adopt by its recycled numeric ID. Preserve it for outer handling.
    if not exists(row['pid']): raise RelayExitTransition('BUILD_RELAY_EXIT_PENDING')
    check_child(row,proc(row['pid']))
    for member in members:
        if member['pid']==row['pid']: continue
        check_privileges(member,row['net'])
        require(row['mode']=='connector' and member['sid']==row['pid'] and member['start']>=row['start'],'descendant_identity')
        require(member['exe']==ADMISSION['python'] and member['argv'][:5]==[ADMISSION['python'],'-I','-S','-B','-c'],'descendant_identity')
        require(len(member['argv'])==7 and member['argv'][5]==DNS_CODE and member['argv'][6] in HOSTS,'descendant_identity')
    return members
def socket_record():
    info=os.lstat(RELAY+'/connector.sock')
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==ADMISSION['uid'] and stat.S_IMODE(info.st_mode)==0o600)
    return [info.st_dev,info.st_ino]
def directory_record():
    require(os.path.realpath(RELAY)==RELAY)
    info=os.lstat(RELAY)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==ADMISSION['uid'] and info.st_gid==ADMISSION['gid'] and stat.S_IMODE(info.st_mode)==0o700)
    return [info.st_dev,info.st_ino]
def journal():
    result=json.loads(read(ROOT+'/fs/relay.intent'))
    require(result==dict(version=1,runId=RUN,sourceSha256=SOURCE_SHA,admission=ADMISSION))
def remaining(deadline):
    require(isinstance(deadline,str) and len(deadline)<=32 and re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]{1,9})?',deadline) is not None)
    value=float(deadline);require(math.isfinite(value) and 0<value-time.monotonic()<=300)
    return value-time.monotonic()
def send_source(child,source,deadline):
    data=memoryview(source.encode());require(len(data)<=65536)
    try:
        os.set_blocking(child.stdin.fileno(),False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdin,selectors.EVENT_WRITE)
            while data:
                require(child.poll() is None)
                left=remaining(deadline)
                if not selector.select(min(left,.1)): continue
                try: written=os.write(child.stdin.fileno(),data[:8192])
                except BlockingIOError: continue
                require(written>0);data=data[written:]
    finally: child.stdin.close()
def launch(mode,deadline,net):
    remaining(deadline)
    if mode=='adapter':
        holder=int(read(ROOT+'/fs/namespace.pid'));current=proc(holder)
        require(current['start']==int(read(ROOT+'/fs/namespace.start')) and current['exe']=='/usr/bin/sleep' and current['argv']==['/usr/bin/sleep','900'] and current['net']==net)
    save('relay.'+mode+'.intent',dict(mode=mode,deadline=deadline,net=net))
    command=['/usr/bin/setpriv','--reuid='+str(ADMISSION['uid']),'--regid='+str(ADMISSION['gid']),'--clear-groups','--no-new-privs',
      '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',ADMISSION['python'],'-I','-S','-B','-',deadline]
    if mode=='adapter': command=['/usr/bin/nsenter','--net=/proc/'+read(ROOT+'/fs/namespace.pid')+'/ns/net','--']+command
    with open(ROOT+'/fs/relay.'+mode+'.log','xb') as output,open(ROOT+'/fs/relay.'+mode+'.err','xb') as error:
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=output,stderr=error,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
        # Capture before sending source. A failed capture leaves an explicit
        # unresolved spawn intent; cleanup must not invent absence.
        with open('/proc/'+str(child.pid)+'/stat') as handle: start=int(handle.read().rsplit(')',1)[1].split()[19])
        row=dict(mode=mode,pid=child.pid,start=start,deadline=deadline,net=net)
        save('relay.'+mode+'.process',row)
        send_source(child,CHILDREN[mode],deadline)
    return child,row
def ready(row,deadline):
    until=min(float(deadline),time.monotonic()+10)
    while time.monotonic()<until:
        path=ROOT+'/fs/relay.'+row['mode']+'.log';value=read(path)
        if '\n' in value:
            packet=json.loads(value.split('\n')[0]);require(set(packet)=={'kind','mode','port'} and packet.get('kind')=='relay-ready' and packet.get('mode')==row['mode'])
            check_child(row,proc(row['pid']))
            if row['mode']=='adapter': require(type(packet.get('port')) is int and 1<=packet['port']<=65535)
            else: require(packet.get('port') is None)
            return packet
        require(exists(row['pid']));time.sleep(.02)
    raise RelayFailure('BUILD_RELAY_READY_TIMEOUT')
def start():
    context();private,shared=coordinates()
    deadline=read(ROOT+'/acquisition.deadline')
    remaining(deadline)
    require(not os.path.lexists(RELAY));save('relay.intent',dict(version=1,runId=RUN,sourceSha256=SOURCE_SHA,admission=ADMISSION))
    controller=proc(os.getpid());save('relay.controller',dict(pid=controller['pid'],start=controller['start']))
    os.mkdir(RELAY,0o700);os.chown(RELAY,ADMISSION['uid'],ADMISSION['gid']);save('relay.directory',directory_record())
    connector,row=launch('connector',deadline,shared);ready(row,deadline);identity=socket_record();save('relay.socket',identity)
    adapter,row=launch('adapter',deadline,private);packet=ready(row,deadline)
    require(socket_record()==identity)
    save('relay.ready',dict(version=1,runId=RUN,sourceSha256=SOURCE_SHA,port=packet['port'],deadline=deadline,socket=identity))
def authority():
    context();journal();private,shared=coordinates()
    require(directory_record()==json.loads(read(ROOT+'/fs/relay.directory')))
    packet=json.loads(read(ROOT+'/fs/relay.ready'))
    require(set(packet)=={'version','runId','sourceSha256','port','deadline','socket'} and packet['version']==1)
    require(packet['runId']==RUN and packet['sourceSha256']==SOURCE_SHA);remaining(packet['deadline'])
    require(type(packet['port']) is int and 1<=packet['port']<=65535 and socket_record()==packet['socket']==json.loads(read(ROOT+'/fs/relay.socket')))
    for mode,net in (('connector',shared),('adapter',private)):
        row=json.loads(read(ROOT+'/fs/relay.'+mode+'.process'));require(row['mode']==mode and row['net']==net and row['deadline']==packet['deadline'])
        check_child(row,proc(row['pid']))
    return packet['port']
def cleanup():
    context();journal();errors=[];pending=[];end=time.monotonic()+10
    details={}
    def note(mode,stage,reason,site=None):
        if mode not in details: details[mode]=(stage,reason,site)
    require(os.path.lexists(ROOT+'/fs/relay.controller'))
    controller=json.loads(read(ROOT+'/fs/relay.controller'))
    if exists(controller['pid']): require(proc(controller['pid'])['start']!=controller['start'])
    for mode in ('adapter','connector'):
        intent=ROOT+'/fs/relay.'+mode+'.intent';record=ROOT+'/fs/relay.'+mode+'.process'
        if not os.path.lexists(intent): continue
        row=None
        try:
            stage='record'
            require(os.path.lexists(record),'record_missing');row=json.loads(read(record));require(row['mode']==mode,'record_invalid')
            stage='group_check'
            if check_group(row):
                stage='leader_check';check_child(row,proc(row['pid']))
                stage='signal';os.killpg(row['pid'],signal.SIGTERM)
            pending.append(row)
        except RelayExitTransition: pending.append(row)
        except (FileNotFoundError,ProcessLookupError) as error:
            if row is not None and row.get('mode')==mode and not exists(row['pid']): pending.append(row)
            else: errors.append(mode);note(mode,stage,'process_lookup_unproven',getattr(error,'lookupSite',None))
        except Exception as error:
            errors.append(mode);note(mode,stage,getattr(error,'reason',
              'signal_failed' if stage=='signal' else 'record_invalid' if stage=='record' else 'unexpected_failure'),getattr(error,'lookupSite',None))
    # Signal both first, then join under ONE aggregate shutdown deadline.
    while pending:
        if time.monotonic()>=end:
            errors.extend(row['mode'] for row in pending)
            for row in pending: note(row['mode'],'join','deadline_exhausted')
            break
        survivors=[]
        for row in pending:
            try:
                if check_group(row): survivors.append(row)
            except RelayExitTransition: survivors.append(row)
            except (FileNotFoundError,ProcessLookupError) as error:
                if not exists(row['pid']): survivors.append(row)
                elif getattr(error,'lookupSite',None)=='proc_link':
                    # Same-birth link loss may be an exit transition; rescan under the fixed join deadline.
                    survivors.append(row)
                else: errors.append(row['mode']);note(row['mode'],'join','process_lookup_unproven',getattr(error,'lookupSite',None))
            except RelayFailure as error:
                # An unrelated /proc entry can vanish between listdir and stat.
                # A still-present but unreadable entry proves neither membership
                # nor absence. Re-scan only these two census lookup sites under
                # the existing aggregate deadline; never signal on this scan.
                if getattr(error,'reason',None)=='ownership_unproven' and getattr(error,'lookupSite',None) in ('group_stat','group_member'):
                    survivors.append(row)
                else:
                    errors.append(row['mode']);note(row['mode'],'join',getattr(error,'reason','unexpected_failure'),getattr(error,'lookupSite',None))
            except Exception as error:
                errors.append(row['mode']);note(row['mode'],'join',getattr(error,'reason','unexpected_failure'),getattr(error,'lookupSite',None))
        # A census completed after the fixed deadline is not timely absence.
        if time.monotonic()>=end:
            errors.extend(row['mode'] for row in pending)
            for row in pending: note(row['mode'],'join','deadline_exhausted')
            break
        pending=survivors
        if not pending: break
        time.sleep(.02)
    if errors: cleanup_diagnostic(details)
    require(not errors)
    # No deletion or successful publication may outlive the same shutdown end.
    require(time.monotonic()<end,'deadline_exhausted')
    if os.path.lexists(RELAY):
        require(directory_record()==json.loads(read(ROOT+'/fs/relay.directory')))
        # Only remove the captured socket after independent process absence.
        if os.path.lexists(RELAY+'/connector.sock'):
            require(socket_record()==json.loads(read(ROOT+'/fs/relay.socket')))
            require(time.monotonic()<end,'deadline_exhausted');os.unlink(RELAY+'/connector.sock')
        require(not os.listdir(RELAY))
        require(time.monotonic()<end,'deadline_exhausted');os.rmdir(RELAY)
    require(time.monotonic()<end,'deadline_exhausted')
    require(not os.path.lexists(RELAY));print('relay-absent',flush=True)
`;
const lifecycleNoConnect=String.raw`
# Lifecycle qualification never authorizes DNS, CONNECT, or resolver children.
def lifecycle_audit(event,args):
    if event in ('socket.connect','socket.getaddrinfo','subprocess.Popen'):
        raise PermissionError('LIFECYCLE_ONLY_NO_ACQUISITION')
sys.addaudithook(lifecycle_audit)
`;
const transportAudit=String.raw`
import atexit
TRANSPORT_COUNTS=dict(dnsSubprocesses=0,externalConnectAttempts=0,unixConnectAttempts=0,peerChecks=0,peerDenied=0)
TRANSPORT_SEQUENCE=0
def transport_audit(event,args):
    if event=='subprocess.Popen': TRANSPORT_COUNTS['dnsSubprocesses']+=1
    if event=='socket.connect':
        key='unixConnectAttempts' if args[0].family==socket.AF_UNIX else 'externalConnectAttempts'
        TRANSPORT_COUNTS[key]+=1
sys.addaudithook(transport_audit)
_original_peer_uid=peer_uid
def peer_uid(sock,uid):
    TRANSPORT_COUNTS['peerChecks']+=1
    try: return _original_peer_uid(sock,uid)
    except BaseException:
        TRANSPORT_COUNTS['peerDenied']+=1
        raise
def transport_snapshot(kind):
    global TRANSPORT_SEQUENCE
    # Observational checkpoint only: let already-owned workers finish before
    # claiming their rejection/response boundary. Never extend work deadline.
    end=min(float(sys.argv[1]),time.monotonic()+1)
    while kind=='checkpoint' and threading.active_count()>1 and time.monotonic()<end: time.sleep(.01)
    TRANSPORT_SEQUENCE+=1
    print(json.dumps(dict(kind='transport-audit',variant='connect-audit-v1',runId=TRANSPORT_RUN,
      mode=TRANSPORT_MODE,sequence=TRANSPORT_SEQUENCE,trigger=kind,counts=TRANSPORT_COUNTS,
      activeWorkers=threading.active_count()-1)),flush=True)
signal.signal(signal.SIGUSR1,lambda signum,frame:transport_snapshot('checkpoint'))
atexit.register(transport_snapshot,'terminal')
`;
// Metadata-only diagnostics delegate the original closed authority check. This
// is an explicitly different instrumented variant, not a new allowed origin.
const metadataAuthorityAudit=String.raw`
METADATA_DENIED_LOCK=threading.Lock()
METADATA_DENIED=dict(hosts={},unclassified=0,overflow=0)
_original_metadata_authority=authority
def metadata_denied_hostname(raw):
    if type(raw) is not bytes or len(raw)>8192 or not raw.endswith(b'\r\n\r\n'): return None
    try: line=raw.decode('ascii').split('\r\n',1)[0]
    except UnicodeDecodeError: return None
    match=re.fullmatch(r'CONNECT ([a-z0-9.-]{1,253}):443 HTTP/1\.[01]',line)
    if not match: return None
    host=match[1]
    if host in HOST_LIMITS or '.' not in host: return None
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')): return None
    try: ipaddress.ip_address(host)
    except ValueError: return host
    return None
def authority(raw):
    try: return _original_metadata_authority(raw)
    except Denied:
        host=metadata_denied_hostname(raw)
        with METADATA_DENIED_LOCK:
            if host is None: METADATA_DENIED['unclassified']+=1
            elif host in METADATA_DENIED['hosts']: METADATA_DENIED['hosts'][host]+=1
            elif len(METADATA_DENIED['hosts'])<8: METADATA_DENIED['hosts'][host]=1
            else: METADATA_DENIED['overflow']+=1
        raise
def metadata_denied_snapshot():
    with METADATA_DENIED_LOCK:
        return dict(hosts=dict(METADATA_DENIED['hosts']),unclassified=METADATA_DENIED['unclassified'],overflow=METADATA_DENIED['overflow'])
`+transportAudit.replace("variant='connect-audit-v1'","variant='metadata-authority-audit-v1'")
  .replace('activeWorkers=threading.active_count()-1)',
    'activeWorkers=threading.active_count()-1,deniedAuthorities=metadata_denied_snapshot())');
// Exact public blob authority observed in retained metadata run 2a623f48...
// and explicitly admitted for this metadata variant only. The original relay
// module, historical transport variant, total bytes and connection caps stay fixed.
const METADATA_BLOB_HOST='production.cloudfront.docker.com';
const metadataBlobAuthorityAudit=`\nHOST_LIMITS[${JSON.stringify(METADATA_BLOB_HOST)}]=134217728\n`+
  metadataAuthorityAudit.replace("variant='metadata-authority-audit-v1'","variant='metadata-blob-authority-audit-v2'");
const metadataAdmissionAudit=String.raw`
METADATA_ADMISSION=dict(workerLimitRejected=0,connectionLimitRejected=0,saturated=False)
def metadata_admission_rejected(kind):
    if METADATA_ADMISSION[kind]<65535: METADATA_ADMISSION[kind]+=1
    else: METADATA_ADMISSION['saturated']=True
`+metadataBlobAuthorityAudit.replace("variant='metadata-blob-authority-audit-v2'","variant='metadata-admission-audit-v3'")
  .replace("    while kind=='checkpoint' and threading.active_count()>1 and time.monotonic()<end: time.sleep(.01)",
    '    # Point-in-time observation: do not wait for or retire existing tunnels.')
  .replace('deniedAuthorities=metadata_denied_snapshot())','deniedAuthorities=metadata_denied_snapshot(),admission=dict(METADATA_ADMISSION))');
function metadataAdmissionProgram(program){
  let result=replaceOnce(program,'if not gate.acquire(False): client.close();continue',
    "if not gate.acquire(False): metadata_admission_rejected('workerLimitRejected');client.close();continue");
  return replaceOnce(result,'except Denied: gate.release();client.close();continue',
    "except Denied: metadata_admission_rejected('connectionLimitRejected');gate.release();client.close();continue");
}
const metadataIdleProgram=String.raw`
def idle():
    authority()
    deadline=read(ROOT+'/acquisition.deadline');remaining(deadline)
    started=time.monotonic();end=min(float(deadline),started+16)
    rows={mode:json.loads(read(ROOT+'/fs/relay.'+mode+'.process')) for mode in ('connector','adapter')}
    for row in rows.values(): check_child(row,proc(row['pid']))
    save('relay.idle.intent',dict(version=1,runId=RUN,deadline=deadline,started=started,end=end,
      processes={mode:dict(pid=row['pid'],start=row['start'],net=row['net']) for mode,row in rows.items()}))
    attempts=0;observations=None
    try:
        while True:
            if time.monotonic()>=end: raise RelayFailure('BUILD_RELAY_IDLE_DEADLINE')
            remaining(deadline);authority();attempts+=1;require(attempts<=33)
            observations={}
            for mode,row in rows.items():
                check_child(row,proc(row['pid']))
                tids=os.listdir('/proc/'+str(row['pid'])+'/task')
                require(1<=len(tids)<=5 and str(row['pid']) in tids and all(re.fullmatch('[1-9][0-9]*',tid) for tid in tids))
                check_child(row,proc(row['pid']))
                observations[mode]=len(tids)-1
            if not any(observations.values()):
                # Kernel thread absence plus identity-bound fresh application
                # observations; neither observation alone is a drain proof.
                packet=checkpoint(end)
                require(all(type(row['activeWorkers']) is int and row['activeWorkers']==0 for row in packet['rows'].values()))
                for row in rows.values():
                    check_child(row,proc(row['pid']))
                    require(os.listdir('/proc/'+str(row['pid'])+'/task')==[str(row['pid'])])
                    check_child(row,proc(row['pid']))
                completed=time.monotonic();remaining(deadline);require(completed<end)
                save('relay.idle.result',dict(version=1,runId=RUN,quiescent=True,attempts=attempts,
                  observations=observations,checkpointSequences={mode:row['sequence'] for mode,row in packet['rows'].items()},completedAt=completed))
                print(json.dumps(dict(kind='metadata-idle-barrier',runId=RUN,quiescent=True,attempts=attempts)),flush=True)
                return
            time.sleep(min(.5,max(0,end-time.monotonic())))
    except BaseException as error:
        # An interrupted/unknown drain never admits the guest. Intent remains
        # authoritative cleanup debt even if failure receipt writing also fails.
        code='interrupted' if isinstance(error,(KeyboardInterrupt,SystemExit)) else 'deadline' if str(error)=='BUILD_RELAY_IDLE_DEADLINE' else 'unverified'
        try: save('relay.idle.result',dict(version=1,runId=RUN,quiescent=False,attempts=attempts,
          observations=observations,failure=code))
        except Exception: pass # Preserve the primary failure and the pre-wait intent.
        raise
`;
async function privateRelayPlan(spec,value,{lifecycleOnly=false,transportOnly=false,metadataOnly=false}={}) {
  if(lifecycleOnly&&transportOnly)throw fail('BUILD_RELAY_VARIANT');
  if(metadataOnly&&(!transportOnly||lifecycleOnly))throw fail('BUILD_RELAY_VARIANT');
  const admission=relayAdmission(value);
  if(spec.guest!=='/var/tmp/dvaia-v23-build-'+spec.runId||!/^[a-f0-9]{32}$/.test(spec.runId))throw fail('BUILD_RELAY_ADMISSION_REQUIRED');
  const modulePath=path.join(__dirname,'ownedMcpPrivateEgress.js');
  if(sha(await fs.readFile(modulePath))!==RELAY_SOURCE_SHA)throw fail('BUILD_RELAY_SOURCE_CHANGED');
  const relay=require('./ownedMcpPrivateEgress');
  const children=Object.fromEntries(['connector','adapter'].map(mode=>[mode,lifecycleOnly||transportOnly?
    (metadataOnly?metadataAdmissionProgram(relay._internals.program):relay._internals.program)+(lifecycleOnly?lifecycleNoConnect:`\nTRANSPORT_MODE=${JSON.stringify(mode)}\nTRANSPORT_RUN=${JSON.stringify(spec.runId)}\n`+(metadataOnly?metadataAdmissionAudit.replace("variant='metadata-admission-audit-v3'","variant='metadata-idle-barrier-v4'"):transportAudit))+`\nserve(${JSON.stringify(mode)},${JSON.stringify('/var/tmp/dvaia-v23-relay-'+spec.runId)},${admission.uid},deadline_from_argv(sys.argv))\n`:
    relay.guestProgram({runId:spec.runId,uid:admission.uid,mode,deadlineFromArgv:true})]));
  // Loading the frozen definition supplies DNS_CODE for exact descendant checks;
  // it does not invoke serve or open any sockets.
  const hosts=metadataOnly?[...relay.HOSTS,METADATA_BLOB_HOST]:relay.HOSTS;
  const configuration=`\nROOT=${JSON.stringify(spec.guest)}\nRUN=${JSON.stringify(spec.runId)}\nRELAY=${JSON.stringify('/var/tmp/dvaia-v23-relay-'+spec.runId)}\nADMISSION=json.loads(${JSON.stringify(JSON.stringify(admission))})\nSOURCE_SHA=${JSON.stringify(RELAY_SOURCE_SHA)}\nCHILDREN=json.loads(${JSON.stringify(JSON.stringify(children))})\nHOSTS=json.loads(${JSON.stringify(JSON.stringify(hosts))})\n_library={}\nexec(${JSON.stringify(relay._internals.program)},_library)\nDNS_CODE=_library['DNS_CODE']\n`;
  const evidenceProgram=metadataOnly?lifecycleEvidenceProgram.replace('capBytes=16777216','capBytes=6442450944,logicalBytes=os.stat(ROOT+\'/disk\').st_size,allocatedBytes=os.stat(ROOT+\'/disk\').st_blocks*512')
    .replace("names=['relay.intent'","names=['relay.idle.intent','relay.idle.result','relay.intent'"):lifecycleEvidenceProgram;
  const checkpointProgram=metadataOnly?transportCheckpointProgram.replace("variant='connect-audit-v1'","variant='metadata-idle-barrier-v4'")
    .replace('def checkpoint():','def checkpoint(until=None):')
    .replace('end=time.monotonic()+2','end=min(float(read(ROOT+\'/acquisition.deadline\')),time.monotonic()+2,until if until is not None else math.inf)')
    .replace("        check_child(row,proc(row['pid']));os.kill(row['pid'],signal.SIGUSR1)",
      "        check_child(row,proc(row['pid']));require(time.monotonic()<end);os.kill(row['pid'],signal.SIGUSR1)")
    .replace("    print(json.dumps(dict(version=1,runId=RUN,variant='metadata-idle-barrier-v4',rows=rows)),flush=True)",
      "    packet=dict(version=1,runId=RUN,variant='metadata-idle-barrier-v4',rows=rows)\n    print(json.dumps(packet),flush=True)\n    return packet")+metadataIdleProgram:transportCheckpointProgram;
  const source=relayLifecycleProgram+configuration+(transportOnly?'\nTRANSPORT_ONLY=True\n':'')+((lifecycleOnly||transportOnly)?evidenceProgram:'')+(transportOnly?checkpointProgram:'')+"\nif __name__=='__main__':\n    require(len(sys.argv)==2 and sys.argv[1] in "+(metadataOnly?"('start','authority','cleanup','evidence','checkpoint','idle')":transportOnly?"('start','authority','cleanup','evidence','checkpoint')":lifecycleOnly?"('start','authority','cleanup','evidence')":"('start','authority','cleanup')")+")\n    if sys.argv[1]=='authority': print(authority(),flush=True)\n    else: globals()[sys.argv[1]]()\n";
  const sourceSha256=sha(source);
  const install=guard+`\nrequire_private_egress\ncheck_mount; check_namespace\n[ ! -e "$root/fs/relay-lifecycle.py" ] && [ ! -L "$root/fs/relay-lifecycle.py" ]\n( set -C; cat > "$root/fs/relay-lifecycle.py" <<'DVAIA_RELAY_LIFECYCLE'\n${source}DVAIA_RELAY_LIFECYCLE\n)\nchmod 0400 "$root/fs/relay-lifecycle.py"\nprintf '%s' '${sourceSha256}' > "$root/fs/relay-lifecycle.sha256"\nprintf '%s' '${admission.python}' > "$root/fs/relay-lifecycle.python"\nprintf '%s' '${admission.pythonSha256}' > "$root/fs/relay-lifecycle.python.sha256"\n${admission.python} -I -S -B "$root/fs/relay-lifecycle.py" start\n`;
  return Object.freeze({source,sourceSha256,relaySourceSha256:RELAY_SOURCE_SHA,admission,install,executionApproved:false});
}
const lifecycleEvidenceProgram=String.raw`
def evidence():
    context()
    names=['relay.intent','relay.controller','relay.directory','relay.socket','relay.ready',
      'relay.connector.intent','relay.adapter.intent','relay.connector.process','relay.adapter.process',
      'relay.connector.log','relay.adapter.log','relay.connector.err','relay.adapter.err',
      'namespace.pid','namespace.start','namespace.inode','shared.pid','shared.start','shared.inode']
    files={};total=0
    for name in names:
        file=ROOT+'/fs/'+name
        if not os.path.lexists(file): files[name]=None;continue
        value=read(file);total+=len(value.encode());require(total<=262144);files[name]=value
    s=os.statvfs(ROOT+'/fs')
    print(json.dumps(dict(version=1,runId=RUN,lifecycleOnly=not globals().get('TRANSPORT_ONLY',False),sourceSha256=SOURCE_SHA,
      admission=ADMISSION,files=files,storage=dict(capBytes=16777216,usedBytes=(s.f_blocks-s.f_bfree)*s.f_frsize)),sort_keys=True),flush=True)
`;
const transportCheckpointProgram=String.raw`
def checkpoint():
    authority();end=time.monotonic()+2;rows={}
    for mode in ('connector','adapter'):
        row=json.loads(read(ROOT+'/fs/relay.'+mode+'.process'))
        previous=read(ROOT+'/fs/relay.'+mode+'.log').count('\n')
        check_child(row,proc(row['pid']));os.kill(row['pid'],signal.SIGUSR1)
        while time.monotonic()<end:
            lines=read(ROOT+'/fs/relay.'+mode+'.log').splitlines()
            if len(lines)>previous:
                packet=json.loads(lines[-1])
                require(packet['kind']=='transport-audit' and packet['mode']==mode and packet['runId']==RUN and packet['trigger']=='checkpoint')
                rows[mode]=packet;break
            check_child(row,proc(row['pid']));time.sleep(.01)
        require(mode in rows)
    print(json.dumps(dict(version=1,runId=RUN,variant='connect-audit-v1',rows=rows)),flush=True)
`;
const LIFECYCLE_PROBE=Object.freeze({path:'tasks/qualification/relay-guest-probe.nwNg9C/result.json',
  sha256:'939eaa0a0fbb1543571d7942319e0dea6883d4153413b219dfacfe2c249aa7ce',
  nsenterSha256:'cb407a058c84154e192a5b6a4be111f2891b4223f93e11c61bf7620303cc241e'});
const TRANSPORT_PREREQUISITE=Object.freeze({path:'tasks/qualification/relay-lifecycle-9c1b05e4f6a34da7900fb245e18bc632/result.json',
  sha256:'7c95afe8f84be39d021048b2ec2de89c773a238978f39c95f7932fde9b18e0ad'});
const TRANSPORT_CLIENT_SHA='0b319bcdb6c2fc185e5662a052e001043802f251f739eba6e87524f55bb3a5c7';
function specification(root, runId) {
  if(typeof root!=='string'||!path.isAbsolute(root)||path.resolve(root)!==root||root==='/'||
    !/^[a-f0-9]{32}$/.test(runId))throw fail('BUILD_INVALID_PATH_OR_ID');
  const guest='/var/tmp/dvaia-v23-build-'+runId;
  return Object.freeze({root,runId,guest, mount:guest+'/fs', socket:guest+'/fs/docker.sock',
    artifact:path.join(root,'tasks/tmp/v23-build-'+runId),
    lima:path.join(root,'tasks/runtime/container/bin/limactl'),
    limaHome:path.join(root,'tasks/l'),tag:'dvaia-v23-build:'+runId});
}

// Read-only shared-network witness. No bridge repair, forwarding, namespace or
// firewall mutation is permitted here. Volatile counters/lease countdowns are
// not configuration; rule order, interface identities and addresses are.
const networkSnapshotProgram = String.raw`
import json, subprocess, re, os, selectors, time
def read(args):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    value = bytearray()
    deadline = time.monotonic() + 5
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining): raise TimeoutError('network witness timeout')
            chunk = os.read(process.stdout.fileno(), min(65536, 524289 - len(value)))
            if not chunk: break
            value.extend(chunk)
            if len(value) > 524288: raise ValueError('network witness bound')
        if process.wait(timeout=max(0.001, deadline-time.monotonic())) != 0: raise ValueError('network witness command failed')
        return value.decode('utf-8')
    finally:
        if process.poll() is None: process.kill()
        process.wait(timeout=3)
        selector.close()
        process.stdout.close()
def stable(value):
    if isinstance(value, list): return [stable(item) for item in value]
    if isinstance(value, dict):
        return {key: stable(item) for key, item in value.items() if key not in ('valid_life_time', 'preferred_life_time', 'expires', 'hello_timer', 'tcn_timer', 'topology_change_timer', 'gc_timer')}
    return value
def firewall(args):
    # iptables-save omits rule counters unless -c is requested. Policy counters
    # and generated timestamps still vary on otherwise identical rulesets.
    lines = read(args).splitlines()
    return '\n'.join(re.sub(r'\[\d+:\d+\]', '[0:0]', line) if line.startswith(':') else line
                     for line in lines if not line.startswith('#'))
def nft_config(value):
    if isinstance(value, list): return [nft_config(item) for item in value if not (isinstance(item, dict) and 'metainfo' in item)]
    if isinstance(value, dict):
        return {key: ({field: item[field] for field in item if field not in ('packets', 'bytes')} if key == 'counter' and isinstance(item, dict) else nft_config(item)) for key, item in value.items()}
    return value
def snapshot():
    bridge = json.loads(read(['docker', '--host', 'unix:///run/docker.sock', 'network', 'inspect', 'bridge']))
    if len(bridge) != 1 or bridge[0].get('Containers') != {}: raise ValueError('shared bridge not idle')
    bridge = bridge[0]
    if bridge.get('Options', {}).get('com.docker.network.bridge.name') != 'docker0': raise ValueError('shared bridge name')
    links = json.loads(read(['ip', '-json', '-details', 'link', 'show']))
    selected = [row for row in links if row.get('ifname') == 'docker0']
    if len(selected) != 1 or selected[0].get('linkinfo', {}).get('info_kind') != 'bridge': raise ValueError('shared bridge missing')
    addresses = json.loads(read(['ip', '-json', 'address', 'show']))
    gateways = [row.get('Gateway') for row in bridge.get('IPAM', {}).get('Config', []) if row.get('Gateway')]
    own = [address.get('local') for row in addresses if row.get('ifname') == 'docker0' for address in row.get('addr_info', [])]
    if not gateways or not all(gateway in own for gateway in gateways): raise ValueError('shared bridge address')
    return dict(version=1, bridge=bridge, links=stable(links), addresses=stable(addresses),
                routes4=stable(json.loads(read(['ip', '-json', '-4', 'route', 'show', 'table', 'all']))),
                routes6=stable(json.loads(read(['ip', '-json', '-6', 'route', 'show', 'table', 'all']))),
                rules4=json.loads(read(['ip', '-json', '-4', 'rule', 'show'])),
                rules6=json.loads(read(['ip', '-json', '-6', 'rule', 'show'])),
                firewall4=firewall(['iptables-save']), firewall6=firewall(['ip6tables-save']),
                nft=nft_config(json.loads(read(['nft', '-json', 'list', 'ruleset']))),
                forwarding=read(['sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding']))
print(json.dumps(snapshot(), sort_keys=True, separators=(',', ':')))
`;
const networkShell = `
network_snapshot() {
 /usr/bin/python3 -B - <<'DVAIA_NETWORK_PY'
${networkSnapshotProgram}
DVAIA_NETWORK_PY
}
check_network() {
 [ -f "$root/network.before.json" ] && [ ! -L "$root/network.before.json" ] || return 94
 current_network=$(network_snapshot) || return 94
 [ "$current_network" = "$(cat "$root/network.before.json")" ] || return 94
}
`;
// Every guest operation has fixed code and positional arguments. No caller
// supplies a shell fragment, cleanup path, daemon option, or destructive target.
const guard = `set -eu
${networkShell}
umask 077
root="$1"; nonce="$2"
[ "$root" = "/var/tmp/dvaia-v23-build-$nonce" ]
[ "\${#nonce}" = 32 ]
case "$nonce" in *[!a-f0-9]*) exit 80;; esac
require_private_egress() { printf '%s\\n' BUILD_PRIVATE_EGRESS_UNAVAILABLE >&2; return 95; }
relay_control() {
 case "$1" in authority|cleanup) ;; *) return 97;; esac
 for file in relay-lifecycle.py relay-lifecycle.sha256 relay-lifecycle.python relay-lifecycle.python.sha256; do
  [ -f "$root/fs/$file" ] && [ ! -L "$root/fs/$file" ] || return 97
  [ "$(stat -c '%u:%h' "$root/fs/$file")" = '0:1' ] || return 97
 done
 [ "$(stat -c %a "$root/fs/relay-lifecycle.py")" = 400 ] || return 97
 expected=$(cat "$root/fs/relay-lifecycle.sha256")
 case "$expected" in ''|*[!a-f0-9]*) return 97;; esac
 [ "\${#expected}" = 64 ] || return 97
 [ "$(sha256sum "$root/fs/relay-lifecycle.py" | cut -d ' ' -f 1)" = "$expected" ] || return 97
 interpreter=$(cat "$root/fs/relay-lifecycle.python")
 case "$interpreter" in /usr/bin/python3.[0-9]|/usr/bin/python3.[0-9][0-9]) ;; *) return 97;; esac
 [ "$(readlink -f "$interpreter")" = "$interpreter" ] || return 97
 expected=$(cat "$root/fs/relay-lifecycle.python.sha256")
 case "$expected" in ''|*[!a-f0-9]*) return 97;; esac
 [ "\${#expected}" = 64 ] || return 97
 [ "$(sha256sum "$interpreter" | cut -d ' ' -f 1)" = "$expected" ] || return 97
 "$interpreter" -I -S -B "$root/fs/relay-lifecycle.py" "$1"
}
stop_private_relay() {
 [ -e "$root/fs/relay.intent" ] || [ -L "$root/fs/relay.intent" ] || return 0
 relay_control cleanup >&2
}
validate_loop() {
 case "$1" in /dev/loop*) ;; *) return 81;; esac
 suffix="\${1#/dev/loop}"
 case "$suffix" in ''|*[!0-9]*) return 81;; esac
}
containerd_config() {
 printf 'version = 3\\nimports = []\\ndisabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime", "io.containerd.nri.v1.nri"]\\nroot = "%s/containerd-root"\\nstate = "%s/containerd-state"\\ntemp = "%s/tmp"\\n[grpc]\\n  address = "%s/containerd.sock"\\n[plugins."io.containerd.internal.v1.opt"]\\n  path = "%s/opt"\\n[plugins."io.containerd.image-verifier.v1.bindir"]\\n  bin_dir = "%s/verifiers"\\n' "$root/fs" "$root/fs" "$root/fs" "$root/fs" "$root/fs" "$root/fs"
}
write_containerd_config() { containerd_config > "$root/fs/containerd.toml"; }
containerd_arguments() {
 printf '%s\\n' /usr/bin/containerd "--config=$root/fs/containerd.toml" "--root=$root/fs/containerd-root" "--state=$root/fs/containerd-state" "--address=$root/fs/containerd.sock"
}
daemon_arguments() {
 printf '%s\\n' /usr/bin/dockerd "--config-file=$root/fs/daemon.json" "--containerd=$root/fs/containerd.sock" "--containerd-namespace=v23-$nonce" "--containerd-plugins-namespace=v23-plugins-$nonce" "--host=unix://$root/fs/docker.sock" "--data-root=$root/fs/data" "--exec-root=$root/fs/exec" "--pidfile=$root/fs/docker.pid" --feature=containerd-snapshotter=false --storage-driver=overlay2 --bridge=none --iptables=false --ip6tables=false --ip-forward=false --ip-masq=false
}
check_binary() {
 case "$1" in dockerd) digest='${PINS.dockerd}';; containerd) digest='${PINS.containerd}';; *) return 82;; esac
 [ "$(sha256sum "/usr/bin/$1" | cut -d ' ' -f 1)" = "$digest" ]
}
process_exists() { [ -d "/proc/$1" ]; }
process_start() { awk '{print $22}' "/proc/$1/stat"; }
process_comm() { cat "/proc/$1/comm"; }
process_exe() { readlink "/proc/$1/exe"; }
process_args() { tr '\\000' '\\n' < "/proc/$1/cmdline"; }
process_net() { readlink "/proc/$1/ns/net"; }
namespace_members() { printf '%s\\n' /proc/[0-9]*; }
check_namespace_coordinates() {
 holder=$(cat "$root/fs/namespace.pid")
 holder_start=$(cat "$root/fs/namespace.start")
 shared=$(cat "$root/fs/shared.pid")
 shared_start=$(cat "$root/fs/shared.start")
 shared_net=$(cat "$root/fs/shared.inode")
 case "$holder:$holder_start:$shared:$shared_start" in *[!0-9:]*|:*|*:) return 96;; esac
 [ "$holder" -gt 1 ] && [ "$shared" -gt 1 ] && [ "$holder" != "$shared" ]
 [ "$(process_exe "$shared")" = /usr/bin/dockerd ]
 [ "$(process_start "$shared")" = "$shared_start" ]
 [ "$(process_net "$shared")" = "$shared_net" ]
 [ "$shared_net" = "$(process_net 1)" ]
}
check_private_inode() {
 [ "$private_net" != "$shared_net" ] || return 96
 case "$private_net" in 'net:['*']') ;; *) return 96;; esac
 net_number=\${private_net#"net:["}; net_number=\${net_number%"]"}
 case "$net_number" in ''|*[!0-9]*) return 96;; esac
}
check_namespace_record() {
 check_namespace_coordinates
 private_net=$(cat "$root/fs/namespace.inode")
 check_private_inode
}
check_holder() {
 process_exists "$holder" || return 96
 [ "$(process_start "$holder")" = "$holder_start" ] || return 96
 [ "$(process_exe "$holder")" = /usr/bin/sleep ] || return 96
 [ "$(process_args "$holder")" = "$(printf '/usr/bin/sleep\\n900')" ] || return 96
 [ "$(process_net "$holder")" = "$private_net" ] || return 96
}
check_namespace() { check_namespace_record; check_holder; }
scan_namespace_members() {
 for member in $(namespace_members); do
  member_pid=\${member#/proc/}
  case "$member_pid" in ''|*[!0-9]*) return 96;; esac
  [ "$member_pid" = "$holder" ] && continue
  if member_net=$(process_net "$member_pid" 2>/dev/null); then
   [ "$member_net" != "$private_net" ] || return 96
  else
   # A live process with unreadable namespace evidence is not proven absent.
   process_exists "$member_pid" && return 96
  fi
 done
 return 0
}
namespace_exec() {
 check_namespace
 /usr/bin/nsenter --net="/proc/$holder/ns/net" -- "$@"
}
stop_namespace() {
 if [ ! -f "$root/fs/namespace.pid" ]; then
  # A failed PID write after spawn is uncertainty, not absence.
  [ ! -e "$root/fs/namespace.intent" ] || return 96
  return 0
 fi
 holder=$(cat "$root/fs/namespace.pid")
 case "$holder" in ''|*[!0-9]*) return 96;; esac
 [ "$holder" -gt 1 ] || return 96
 if [ ! -s "$root/fs/namespace.inode" ] || [ ! -s "$root/fs/namespace.start" ]; then
  # Startup records these before any daemon can be launched. An absent holder
  # plus no daemon intents proves this early prefix has no retained namespace.
  # A live, incompletely identified PID is never adopted or signalled.
  [ ! -e "$root/fs/daemon.pid" ] && [ ! -e "$root/fs/containerd.pid" ] || return 96
  if ! process_exists "$holder"; then return 0; fi
  # If birth was captured, the exact intended sleep can still be identified
  # after an interrupted inode write. Derive only its own current inode; never
  # adopt a PID lacking birth proof or a process still in the shared namespace.
  [ -s "$root/fs/namespace.start" ] || return 96
  check_namespace_coordinates
  private_net=$(process_net "$holder") || return 96
  check_private_inode
 else
  check_namespace_record
 fi
 if process_exists "$holder"; then check_holder; fi
 scan_namespace_members
 # Recheck immediately after the scan: it may outlive the holder or observe a
 # recycled PID. No stale numeric-PID signal is authorized by the first check.
 if ! process_exists "$holder"; then return 0; fi
 check_namespace_coordinates
 check_private_inode
 check_holder
 kill -TERM "$holder"
 attempts=0
 while process_exists "$holder"; do
  # Reuse proves our captured holder retired; never wait on or signal its heir.
  current_start=$(process_start "$holder") || { process_exists "$holder" && return 96; return 0; }
  [ "$current_start" = "$holder_start" ] || return 0
  attempts=$((attempts+1)); [ "$attempts" -lt 50 ]; sleep .2
 done
}
check_owner() {
 [ -d "$root" ] && [ ! -L "$root" ]
 [ "$(stat -c '%u:%a' "$root")" = '0:700' ]
 [ -f "$root/owner" ] && [ ! -L "$root/owner" ]
 [ "$(cat "$root/owner")" = "$nonce" ]
}
check_mount() {
 check_owner
 [ ! -L "$root/disk" ] && [ "$(stat -c %s "$root/disk")" = 6442450944 ]
 loop=$(cat "$root/loop")
 validate_loop "$loop"
 [ "$(losetup --noheadings --output BACK-FILE "$loop")" = "$root/disk" ]
 [ "$(findmnt -rn -o SOURCE --mountpoint "$root/fs")" = "$loop" ]
 [ "$(findmnt -rn -o FSTYPE --mountpoint "$root/fs")" = ext4 ]
}
check_identity() {
 case "$1" in daemon) executable=dockerd;; containerd) executable=containerd;; *) return 82;; esac
 pid=$(cat "$root/fs/$1.pid")
 ticks=$(cat "$root/fs/$1.start")
 case "$pid" in ''|*[!0-9]*) return 82;; esac
 case "$ticks" in ''|*[!0-9]*) return 82;; esac
 [ "$pid" -gt 1 ]
 process_exists "$pid"
 [ "$(process_start "$pid")" = "$ticks" ]
 [ "$(process_comm "$pid")" = "$executable" ]
 [ "$(process_exe "$pid")" = "/usr/bin/$executable" ]
 check_binary "$executable"
}
check_process() {
 check_identity daemon
 check_namespace_record
 [ "$(process_net "$pid")" = "$private_net" ]
 [ "$(process_args "$pid")" = "$(daemon_arguments)" ]
 [ -f "$root/fs/daemon.json" ] && [ ! -L "$root/fs/daemon.json" ]
 printf '{}\\n' | cmp - "$root/fs/daemon.json"
}
check_containerd() {
 # This pinned containerd merges its default import glob even with imports=[].
 # Refuse that external directory instead of loading unreviewed host config.
 [ ! -e /etc/containerd/conf.d ] && [ ! -L /etc/containerd/conf.d ]
 check_identity containerd
 check_namespace_record
 [ "$(process_net "$pid")" = "$private_net" ]
 [ "$(process_args "$pid")" = "$(containerd_arguments)" ]
 [ -f "$root/fs/containerd.toml" ] && [ ! -L "$root/fs/containerd.toml" ]
 containerd_config | cmp - "$root/fs/containerd.toml"
}
check_runtime() {
 check_namespace
 check_process; check_containerd
 [ -S "$root/fs/containerd.sock" ]
}
stop_owned() {
 process_kind="$1"
 case "$process_kind" in daemon|containerd) ;; *) return 82;; esac
 [ -f "$root/fs/$process_kind.pid" ] || return 0
 check_mount
 pid=$(cat "$root/fs/$process_kind.pid")
 case "$pid" in ''|*[!0-9]*) return 82;; esac
 [ "$pid" -gt 1 ]
 process_exists "$pid" || return 0
 if [ "$process_kind" = daemon ]; then check_process; else check_containerd; fi
 kill -TERM "$pid"
 attempts=0
 while process_exists "$pid" && [ "$attempts" -lt 100 ]; do attempts=$((attempts+1)); sleep .2; done
 if process_exists "$pid"; then
  if [ "$process_kind" = daemon ]; then check_process; else check_containerd; fi
  kill -KILL "$pid"
  attempts=0
  while process_exists "$pid"; do attempts=$((attempts+1)); [ "$attempts" -lt 25 ]; sleep .2; done
 fi
}
`;
const baseScripts = Object.freeze({
  inventory:`set -eu
${networkShell}
docker --host unix:///run/docker.sock info --format '{{json .ID}}'
docker --host unix:///run/docker.sock image ls --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' | sort -u
printf '\\nCONTAINERS\\n'
docker --host unix:///run/docker.sock ps -a --no-trunc --quiet | sort
printf '\\nVOLUMES\\n'
docker --host unix:///run/docker.sock volume ls --quiet | sort
printf '\\nNETWORK\\n'
network_snapshot
`,
  preflight:guard+`
[ ! -e "$root" ] && [ ! -L "$root" ]
for tool in dockerd docker containerd losetup mkfs.ext4 mount umount mountpoint fallocate timeout setsid findmnt readlink sha256sum cmp unshare nsenter sleep ip systemctl; do command -v "$tool" >/dev/null; done
[ "$(command -v dockerd)" = /usr/bin/dockerd ]
[ "$(command -v containerd)" = /usr/bin/containerd ]
check_binary dockerd; check_binary containerd
[ ! -e /etc/containerd/conf.d ] && [ ! -L /etc/containerd/conf.d ]
docker buildx version
available=$(df -B1 --output=avail /var/tmp | tail -1)
[ "$available" -ge 8589934592 ]
grep -w ext4 /proc/filesystems >/dev/null
grep -w overlay /proc/filesystems >/dev/null
`,
  prepare:guard+`
mkdir -m 700 "$root"
printf '%s' "$nonce" > "$root/owner"
/usr/bin/python3 -I -S -B -c 'import sys,time,re,math; value=sys.argv[1] if len(sys.argv)==2 and sys.argv[1] else format(time.monotonic()+300,".6f"); assert len(value)<=32 and re.fullmatch(r"[1-9][0-9]*(?:\\.[0-9]{1,9})?",value) and math.isfinite(float(value)) and 0<float(value)-time.monotonic()<=300; print(value,end="")' "\${3:-}" > "$root/acquisition.deadline"
network_snapshot > "$root/network.before.json"
fallocate -l 6442450944 "$root/disk"
mkfs.ext4 -q -F -m 0 "$root/disk"
mkdir "$root/fs"
loop=$(losetup --find --show "$root/disk")
printf '%s' "$loop" > "$root/loop"
mount -t ext4 "$loop" "$root/fs"
check_mount
printf '{}\\n' > "$root/fs/daemon.json"
write_containerd_config
mkdir "$root/fs/tmp"
`,
  start:guard+`
check_mount
check_binary dockerd; check_binary containerd
[ ! -e /etc/containerd/conf.d ] && [ ! -L /etc/containerd/conf.d ]
shared=$(systemctl show --value -p MainPID docker)
case "$shared" in ''|*[!0-9]*) exit 96;; esac
[ "$shared" -gt 1 ] && [ "$(process_exe "$shared")" = /usr/bin/dockerd ]
printf '%s' "$shared" > "$root/fs/shared.pid"
process_start "$shared" > "$root/fs/shared.start"
process_net "$shared" > "$root/fs/shared.inode"
printf '%s' "$nonce" > "$root/fs/namespace.intent"
setsid /usr/bin/unshare --net -- /usr/bin/sleep 900 > "$root/fs/namespace.log" 2>&1 < /dev/null &
holder=$!
printf '%s' "$holder" > "$root/fs/namespace.pid"
process_start "$holder" > "$root/fs/namespace.start"
attempt=0
until [ "$(process_exe "$holder")" = /usr/bin/sleep ]; do
 attempt=$((attempt+1)); [ "$attempt" -lt 100 ]; sleep .2
done
process_net "$holder" > "$root/fs/namespace.inode"
check_namespace
namespace_exec /usr/sbin/ip link set lo up
TMPDIR="$root/fs/tmp" setsid /usr/bin/nsenter --net="/proc/$holder/ns/net" -- /usr/bin/containerd --config="$root/fs/containerd.toml" --root="$root/fs/containerd-root" --state="$root/fs/containerd-state" --address="$root/fs/containerd.sock" > "$root/fs/containerd.log" 2>&1 < /dev/null &
pid=$!
printf '%s' "$pid" > "$root/fs/containerd.pid"
awk '{print $22}' "/proc/$pid/stat" > "$root/fs/containerd.start"
attempt=0
until [ -S "$root/fs/containerd.sock" ]; do
 attempt=$((attempt+1)); [ "$attempt" -lt 100 ]; sleep .2
done
check_containerd
check_namespace
TMPDIR="$root/fs/tmp" setsid /usr/bin/nsenter --net="/proc/$holder/ns/net" -- /usr/bin/dockerd --config-file="$root/fs/daemon.json" --containerd="$root/fs/containerd.sock" --containerd-namespace="v23-$nonce" --containerd-plugins-namespace="v23-plugins-$nonce" --host="unix://$root/fs/docker.sock" --data-root="$root/fs/data" --exec-root="$root/fs/exec" --pidfile="$root/fs/docker.pid" --feature=containerd-snapshotter=false --storage-driver=overlay2 --bridge=none --iptables=false --ip6tables=false --ip-forward=false --ip-masq=false > "$root/fs/daemon.log" 2>&1 < /dev/null &
pid=$!
printf '%s' "$pid" > "$root/fs/daemon.pid"
awk '{print $22}' "/proc/$pid/stat" > "$root/fs/daemon.start"
attempt=0
until docker --host "unix://$root/fs/docker.sock" info >/dev/null 2>&1; do
 attempt=$((attempt+1)); [ "$attempt" -lt 100 ]; sleep .2
done
check_runtime
check_network
docker --host "unix://$root/fs/docker.sock" info --format '{{json .}}'
`,
  inspect:guard+`
check_mount; check_runtime
docker --host "unix://$root/fs/docker.sock" info --format '{{json .}}'
`,
  build:guard+`
require_private_egress
check_mount; check_runtime
timeout --signal=TERM --kill-after=10 300 docker --host "unix://$root/fs/docker.sock" build --pull=false --network=host --platform linux/arm64 --label "dvaia.registry.package=$3" --label "dvaia.build-run=$nonce" -f "$4" -t "dvaia-v23-build:$nonce" -
`,
  image:guard+`
check_mount; check_runtime
docker --host "unix://$root/fs/docker.sock" image inspect "dvaia-v23-build:$nonce"
`,
  metadata:guard+`
require_private_egress
check_mount; check_runtime
proxy_port=$(relay_control authority)
case "$proxy_port" in ''|*[!0-9]*) exit 97;; esac
[ "$proxy_port" -ge 1 ] && [ "$proxy_port" -le 65535 ]
printf 'DVAIA_METADATA_STAGE=base-pull\\n' >&2
case "$3" in
 sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5|sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1) ;;
 *) exit 90;;
esac
timeout --signal=TERM --kill-after=10 120 docker --host "unix://$root/fs/docker.sock" pull --platform linux/arm64 "node@$3" >&2
printf 'DVAIA_METADATA_STAGE=base-pulled\\n' >&2
name="dvaia-metadata-$nonce"
base_image=$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' "node@$3")
[ -z "$(docker --host "unix://$root/fs/docker.sock" ps -aq --filter "name=^/$name$")" ]
cleanup_metadata() {
 if [ -n "$(docker --host "unix://$root/fs/docker.sock" ps -aq --filter "name=^/$name$")" ]; then
  [ -f "$root/fs/metadata.cid" ] && [ ! -L "$root/fs/metadata.cid" ] || exit 91
  cid=$(cat "$root/fs/metadata.cid")
  [ "\${#cid}" = 64 ] || exit 91
  case "$cid" in *[!a-f0-9]*) exit 91;; esac
  [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$name")" = "$cid" ] || exit 91
  [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$base_image" ] || exit 91
  [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "dvaia.metadata.owner"}}' "$name")" = "$nonce" ] || exit 91
  docker --host "unix://$root/fs/docker.sock" rm -f "$cid" >&2 || exit 92
 fi
}
trap cleanup_metadata EXIT
trap 'exit 124' TERM INT
printf 'DVAIA_METADATA_STAGE=guest-start\\n' >&2
timeout --signal=TERM --kill-after=10 170 docker --host "unix://$root/fs/docker.sock" run --cidfile "$root/fs/metadata.cid" --name "$name" --label "dvaia.metadata.owner=$nonce" --pull never --network host --read-only --memory 768m --cpus 1 --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges --env "DVAIA_METADATA_PROXY_PORT=$proxy_port" --tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --entrypoint /usr/local/bin/node -i "node@$3" -
`,
  export:guard+`
check_mount; check_runtime
timeout --signal=TERM --kill-after=10 120 docker --host "unix://$root/fs/docker.sock" image save "$3"
`,
  cleanup:guard+`
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'absent\\n'; exit 0; fi
check_owner
stop_private_relay
# Sibling processes have independent captured identities. Stop Docker first,
# then its explicitly owned containerd; never discover/adopt the shared daemon.
stop_owned daemon
stop_owned containerd
stop_namespace
# No private daemon, managed containerd or build task may survive unmount.
for proc in /proc/[0-9]*/cmdline; do
 [ -r "$proc" ] || continue
 if tr '\\000' '\\n' < "$proc" 2>/dev/null | grep -F -- "$root/fs/" >/dev/null; then exit 83; fi
done
if mountpoint -q "$root/fs"; then check_mount; umount "$root/fs"; fi
if [ -f "$root/loop" ]; then
 loop=$(cat "$root/loop")
 validate_loop "$loop"
 [ "$(losetup --noheadings --output BACK-FILE "$loop")" = "$root/disk" ]
 losetup --detach "$loop"
 [ -z "$(losetup -j "$root/disk")" ]
fi
check_owner
[ -z "$(findmnt -rn --mountpoint "$root/fs")" ]
network_status=0
check_network || network_status=94
rm -rf -- "$root"
[ ! -e "$root" ] && [ ! -L "$root" ]
[ "$network_status" = 0 ] || exit "$network_status"
printf 'absent\\n'
`,
});
// One guest process owns the entire metadata work deadline. Separate SSH calls
// for setup and pull must not each restart an acquisition allowance.
const quoteScript=value=>"'"+value.replace(/'/g,"'\\''")+"'";
const metadataNamespaceCleanup=`
unmount_metadata_namespace() {
 check_mount
 child="$root/fs/exec/netns/default"
 tree=$(findmnt -rn -R -o TARGET --mountpoint "$root/fs")
 if [ "$tree" = "$root/fs" ]; then return 0; fi
 [ "$tree" = "$(printf '%s\\n%s' "$root/fs" "$child")" ] || return 93
 check_metadata_path() {
  for ancestor in "$root/fs/exec" "$root/fs/exec/netns"; do
   [ -d "$ancestor" ] && [ ! -L "$ancestor" ] || return 93
   [ "$(readlink -f "$ancestor")" = "$ancestor" ] || return 93
  done
  [ ! -L "$child" ] && [ "$(readlink -f "$child")" = "$child" ] || return 93
 }
 check_metadata_path || return 93
 identity=$(findmnt -rn -o ID,PARENT,FSTYPE,SOURCE --mountpoint "$child")
 set -- $identity
 [ "$#" = 4 ] && [ "$3" = nsfs ] || return 93
 case "$1:$2" in *[!0-9:]*|:*|*:) return 93;; esac
 [ "$2" = "$(findmnt -rn -o ID --mountpoint "$root/fs")" ] || return 93
 ns_source="$4"
 case "$ns_source" in 'nsfs[net:['*']]') ;; *) return 93;; esac
 ns_id=\${ns_source#"nsfs[net:["}; ns_id=\${ns_id%"]]"}
 case "$ns_id" in ''|*[!0-9]*) return 93;; esac
 check_mount
 check_metadata_path || return 93
 [ "$(findmnt -rn -R -o TARGET --mountpoint "$root/fs")" = "$tree" ] || return 93
 [ "$(findmnt -rn -o ID,PARENT,FSTYPE,SOURCE --mountpoint "$child")" = "$identity" ] || return 93
 umount -- "$child" || return 93
 [ -z "$(findmnt -rn --mountpoint "$child")" ] || return 93
 [ "$(findmnt -rn -R -o TARGET --mountpoint "$root/fs")" = "$root/fs" ] || return 93
}
`;
const scripts=Object.freeze({...baseScripts,'metadata-acquire':guard+`
require_private_egress
acquisition_deadline=$(/usr/bin/python3 -I -S -B -c 'import time; print(format(time.monotonic()+300,".6f"),end="")')
printf 'DVAIA_METADATA_STAGE=preflight\\n' >&2
/bin/sh -c ${quoteScript(baseScripts.preflight)} metadata-preflight "$root" "$nonce" >&2
printf 'DVAIA_METADATA_STAGE=prepare\\n' >&2
/bin/sh -c ${quoteScript(baseScripts.prepare)} metadata-prepare "$root" "$nonce" "$acquisition_deadline" >&2
printf 'DVAIA_METADATA_STAGE=daemon-start\\n' >&2
/bin/sh -c ${quoteScript(baseScripts.start)} metadata-start "$root" "$nonce" >&2
/bin/sh -c ${quoteScript(baseScripts.metadata)} metadata-fetch "$root" "$nonce" "$3"
`,'metadata-cleanup':baseScripts.cleanup.replace(
 'if mountpoint -q "$root/fs"; then check_mount; umount "$root/fs"; fi',
 metadataNamespaceCleanup+'\nif mountpoint -q "$root/fs"; then unmount_metadata_namespace; check_mount; umount "$root/fs"; fi')
 .replace('check_owner\nstop_private_relay\n# Sibling',"printf 'DVAIA_METADATA_STAGE=cleanup-owner\\n' >&2\ncheck_owner\nstop_private_relay\n# Sibling")
 .replace('stop_owned daemon',"printf 'DVAIA_METADATA_STAGE=cleanup-daemon\\n' >&2\nstop_owned daemon")
 .replace('stop_owned containerd',"printf 'DVAIA_METADATA_STAGE=cleanup-containerd\\n' >&2\nstop_owned containerd")
 .replace('for proc in /proc/',"printf 'DVAIA_METADATA_STAGE=cleanup-process-scan\\n' >&2\nfor proc in /proc/")
 .replace('if mountpoint -q "$root/fs";',"printf 'DVAIA_METADATA_STAGE=cleanup-mounts\\n' >&2\nif mountpoint -q \"$root/fs\";")
 .replace('if [ -f "$root/loop" ];',"printf 'DVAIA_METADATA_STAGE=cleanup-loop\\n' >&2\nif [ -f \"$root/loop\" ];")});

// Separate non-acquiring entry; the full-build mount and egress guards above
// remain unchanged. Only a previously reviewed, exact guest probe is admitted.
async function lifecycleQualificationPlan(root,runId,phase='lifecycle') {
  if(!['lifecycle','transport'].includes(phase))throw fail('BUILD_RELAY_PHASE');
  const spec=specification(root,runId),receiptPath=path.join(root,LIFECYCLE_PROBE.path);
  if(await fs.realpath(root)!==root||await fs.realpath(receiptPath)!==receiptPath)throw fail('BUILD_RELAY_PROBE_PATH');
  const bytes=await fs.readFile(receiptPath);
  if(sha(bytes)!==LIFECYCLE_PROBE.sha256)throw fail('BUILD_RELAY_PROBE_CHANGED');
  const probe=JSON.parse(bytes);
  if(!probe.passed||!probe.muxUnchanged||probe.errors.length||
    JSON.stringify(probe.sourceBefore)!==JSON.stringify(probe.sourceAfter)||
    probe.children.length!==5||probe.children.some(row=>!row.reaped||!row.groupAbsent))throw fail('BUILD_RELAY_PROBE_UNPROVEN');
  const admission=relayAdmission(probe.guest.admission);
  let client;
  if(phase==='transport'){
    const prerequisite=path.join(root,TRANSPORT_PREREQUISITE.path),clientPath=path.join(__dirname,'ownedMcpPrivateTransportClient.py');
    if(await fs.realpath(prerequisite)!==prerequisite||await fs.realpath(clientPath)!==clientPath)throw fail('BUILD_TRANSPORT_PATH');
    const receipt=await fs.readFile(prerequisite);client=await fs.readFile(clientPath,'utf8');
    if(sha(receipt)!==TRANSPORT_PREREQUISITE.sha256||sha(client)!==TRANSPORT_CLIENT_SHA)throw fail('BUILD_TRANSPORT_PIN');
    const prior=JSON.parse(receipt);
    if(!prior.passed||!prior.guestAbsent||!prior.sharedStateUnchanged||!prior.sourceUnchanged||!prior.muxUnchanged||prior.errors.length||prior.cleanupErrors.length)throw fail('BUILD_TRANSPORT_PREREQUISITE');
  }
  const plan=await privateRelayPlan(spec,admission,{lifecycleOnly:phase==='lifecycle',transportOnly:phase==='transport'});
  const begin=guard.indexOf('check_mount() {'),end=guard.indexOf('check_identity() {');
  if(begin<0||end<=begin)throw fail('BUILD_RELAY_GUARD_CHANGED');
  const mountGuard=`check_mount() {
 check_owner
 [ -d "$root/fs" ] && [ ! -L "$root/fs" ]
 [ "$(findmnt -rn -o SOURCE --mountpoint "$root/fs")" = "dvaia-relay-$nonce" ]
 [ "$(findmnt -rn -o FSTYPE --mountpoint "$root/fs")" = tmpfs ]
 [ "$(findmnt -rn -o ID --mountpoint "$root/fs")" = "$(cat "$root/mount.id")" ]
 options=",$(findmnt -rn -o OPTIONS --mountpoint "$root/fs"),"
 for option in noexec nosuid nodev size=16384k; do case "$options" in *",$option,"*) ;; *) return 97;; esac; done
}
`;
  const lifecycleGuard=(guard.slice(0,begin)+mountGuard+guard.slice(end))
    .replace('case "$1" in authority|cleanup)', phase==='transport'?'case "$1" in authority|cleanup|evidence|checkpoint)':'case "$1" in authority|cleanup|evidence)');
  const namespaceEnd=baseScripts.start.indexOf('TMPDIR="$root/fs/tmp" setsid /usr/bin/nsenter');
  if(namespaceEnd<=guard.length)throw fail('BUILD_RELAY_NAMESPACE_SOURCE_CHANGED');
  const install=plan.install.replace(guard,lifecycleGuard).replace('\nrequire_private_egress\ncheck_mount; check_namespace','\ncheck_mount; check_namespace');
  if(install===plan.install||!install.includes(phase==='transport'?'connect-audit-v1':'LIFECYCLE_ONLY_NO_ACQUISITION'))throw fail('BUILD_RELAY_LIFECYCLE_GATE');
  const interpreter=admission.python;
  const commands={
    inventory:baseScripts.inventory,
    preflight:lifecycleGuard+`
[ ! -e "$root" ] && [ ! -L "$root" ]
for tool in mount umount findmnt timeout setsid unshare nsenter sleep ip systemctl; do command -v "$tool" >/dev/null; done
[ "$(sha256sum '${interpreter}' | cut -d ' ' -f 1)" = '${admission.pythonSha256}' ]
[ "$(sha256sum /usr/bin/setpriv | cut -d ' ' -f 1)" = '${admission.setprivSha256}' ]
[ "$(sha256sum /usr/bin/nsenter | cut -d ' ' -f 1)" = '${LIFECYCLE_PROBE.nsenterSha256}' ]
`,
    prepare:lifecycleGuard+`
[ ! -e "$root" ] && [ ! -L "$root" ]
mkdir -m 700 "$root"
printf '%s' "$nonce" > "$root/owner"
${interpreter} -I -S -B -c 'import time; print(format(time.monotonic()+300,".6f"),end="")' > "$root/acquisition.deadline"
network_snapshot > "$root/network.before.json"
mkdir -m 700 "$root/fs"
mount -t tmpfs -o size=16m,nosuid,nodev,noexec,mode=700 "dvaia-relay-$nonce" "$root/fs"
findmnt -rn -o ID --mountpoint "$root/fs" > "$root/mount.id"
check_mount
`,
    namespace:lifecycleGuard+baseScripts.start.slice(guard.length,namespaceEnd),
    start:install,
    authority:lifecycleGuard+'\ncheck_mount; check_namespace\nrelay_control authority\n',
    evidence:lifecycleGuard+'\ncheck_mount\nrelay_control evidence\n',
    stop:lifecycleGuard+'\ncheck_mount\nstop_private_relay\n',
    cleanup:lifecycleGuard+`
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'absent\\n'; exit 0; fi
check_owner
stop_private_relay
stop_namespace
for proc in /proc/[0-9]*/cmdline; do
 [ -r "$proc" ] || continue
 if tr '\\000' '\\n' < "$proc" 2>/dev/null | grep -F -- "$root/fs/" >/dev/null; then exit 83; fi
done
if mountpoint -q "$root/fs"; then check_mount; umount "$root/fs"; fi
[ -z "$(findmnt -rn --mountpoint "$root/fs")" ]
check_owner
network_status=0
check_network || network_status=94
rm -rf -- "$root"
[ ! -e "$root" ] && [ ! -L "$root" ]
[ "$network_status" = 0 ] || exit "$network_status"
printf 'absent\\n'
`};
  if(phase==='transport'){
    commands.checkpoint=lifecycleGuard+'\ncheck_mount; check_namespace\nrelay_control checkpoint\n';
    for(const name of ['deny-peer','deny-host','registry','auth','debian']){
      const privilege=name==='deny-peer'?'':`/usr/bin/setpriv --reuid=${admission.uid} --regid=${admission.gid} --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all `;
      commands['client-'+name]=lifecycleGuard+`\ncheck_mount; check_namespace\nport=$(relay_control authority)\ndeadline=$(cat "$root/acquisition.deadline")\nnamespace_exec /usr/bin/env -i PATH=/usr/bin:/bin ${privilege}${interpreter} -I -S -B - '${name}' "$port" '/var/tmp/dvaia-v23-relay-${runId}' "$private_net" "$deadline" <<'DVAIA_TRANSPORT_CLIENT'\n${client}\nDVAIA_TRANSPORT_CLIENT\n`;
    }
  }
  return {version:1,kind:phase==='transport'?'private-relay-real-transport':'private-relay-lifecycle-only',phase,runId,guest:spec.guest,
    executionApproved:false,acquisitionApproved:false,storageCapBytes:16*1024**2,
    probe:LIFECYCLE_PROBE,admission,mux:probe.muxAfter,relaySourceSha256:RELAY_SOURCE_SHA,
    lifecycleSourceSha256:plan.sourceSha256,...(phase==='transport'?{variant:'connect-audit-v1',
      prerequisite:TRANSPORT_PREREQUISITE,clientSha256:TRANSPORT_CLIENT_SHA}:{}),commands};
}

const METADATA_TRANSPORT_PROOF=Object.freeze({path:'tasks/qualification/relay-transport-d84e217ab4f74ee39a9ca602e51a438b/result.json',
  sha256:'c38c0b87f71dd1fa732a15f9a85b9498ade49a21721984348e1829b53b4868a8'});
function replaceOnce(source,before,after){
  if(source.split(before).length!==2)throw fail('BUILD_METADATA_SOURCE_SHAPE');
  return source.replace(before,after);
}
async function metadataQualificationPlan(root,runId){
  return closedMetadataQualificationPlan(root,runId,'v23-registry');
}
async function systemMetadataQualificationPlan(root,runId){
  return closedMetadataQualificationPlan(root,runId,'v24-system');
}
async function pricingMetadataQualificationPlan(root,runId){
  return closedMetadataQualificationPlan(root,runId,'v33-pricing');
}
async function policyRendererMetadataQualificationPlan(root,runId){
  return closedMetadataQualificationPlan(root,runId,'v24-policy');
}
async function listingsMetadataQualificationPlan(root,runId){
  return closedMetadataQualificationPlan(root,runId,'listings-package');
}
async function closedMetadataQualificationPlan(root,runId,targetName){
  if(!['v23-registry','v24-system','v33-pricing','v24-policy','listings-package'].includes(targetName))throw fail('BUILD_METADATA_TARGET');
  const spec=specification(root,runId),proofPath=path.join(root,METADATA_TRANSPORT_PROOF.path);
  const buildFiles=await source.capture(root);
  const buildSources=Object.fromEntries(buildFiles.map(file=>[file.name,sha(file.bytes)]));
  if(await fs.realpath(proofPath)!==proofPath)throw fail('BUILD_METADATA_PROOF_PATH');
  const bytes=await fs.readFile(proofPath);if(sha(bytes)!==METADATA_TRANSPORT_PROOF.sha256)throw fail('BUILD_METADATA_PROOF_PIN');
  const proof=JSON.parse(bytes);
  if(proof.passed!==true||proof.realTransportVerified!==true||proof.guestAbsent!==true||proof.sharedStateUnchanged!==true
    ||proof.sourceUnchanged!==true||proof.muxUnchanged!==true||proof.errors.length||proof.cleanupErrors.length
    ||proof.children.length!==24||proof.children.some(row=>row.reaped!==true||row.groupAbsent!==true))throw fail('BUILD_METADATA_TRANSPORT_UNPROVEN');
  const prerequisite=await lifecycleQualificationPlan(root,runId,'transport');
  const metadata=require('./ownedPolicySystemMetadata');
  const target=require('./ownedPolicySystemBuild').targetSpecification(targetName);
  const retention=require('./ownedPolicySystemBuild').metadataRetentionSpecification(targetName);
  if(targetName==='listings-package'){
    const listings=require('../../scripts/install/secureshop-owned-listings').sourceManifest(root);
    Object.assign(buildSources,listings.files);
    for(const helper of ['scripts/install/secureshop-owned-listings.js','tests/postgres/ownedPolicySystemBuild.js','tests/postgres/ownedPolicySystemMetadata.js']){
      buildSources[helper]=sha(await fs.readFile(path.join(root,helper)));
    }
  }
  let rendererInputs;
  if(targetName==='v24-policy'){
    rendererInputs=await require('./ownedPolicyRendererBuildInputs').capturePolicyRendererBuildInputs(root);
    const recipe=rendererInputs.recipe;
    if(recipe.base!==target.base||JSON.stringify(recipe.stages.map(({name,packages})=>({name,packages})))!==JSON.stringify(retention.stages))throw fail('BUILD_METADATA_RENDERER_RECIPE');
    Object.assign(buildSources,rendererInputs.sourceManifest.files,
      {[rendererInputs.provider.path]:rendererInputs.provider.sha256,[rendererInputs.canonicalContract.path]:rendererInputs.canonicalContract.sha256});
    const helper='tests/postgres/ownedPolicyRendererBuildInputs.js';buildSources[helper]=sha(await fs.readFile(path.join(root,helper)));
  }
  const base=targetName==='v24-system'?'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5':'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
  if(target.base!==base)throw fail('BUILD_METADATA_BASE');
  const binding={runId,target:targetName,base},guestSource=metadata.guestMetadataSource(binding,{retention:retention.mode});
  if(Buffer.byteLength(guestSource)>262144||guestSource.includes('\nDVAIA_METADATA_GUEST\n'))throw fail('BUILD_METADATA_SOURCE_SIZE');
  const relay=await privateRelayPlan(spec,prerequisite.admission,{transportOnly:true,metadataOnly:true});
  // Explicit per-run proxy authority. No ambient proxy or daemon configuration
  // can become authority; the loopback address exists only in the owned netns.
  const proxyFunctions=String.raw`
docker() {
 if [ -e "$root" ] || [ -L "$root" ]; then
  check_owner
  [ -d "$root/fs/docker-client" ] && [ ! -L "$root/fs/docker-client" ]
  [ "$(stat -c %u "$root/fs/docker-client")" = 0 ] && [ "$(stat -c %a "$root/fs/docker-client")" = 700 ]
  [ -f "$root/fs/docker-client/config.json" ] && [ ! -L "$root/fs/docker-client/config.json" ]
  [ "$(stat -c %u "$root/fs/docker-client/config.json")" = 0 ] && [ "$(stat -c %a "$root/fs/docker-client/config.json")" = 600 ]
  printf '{}\n' | cmp - "$root/fs/docker-client/config.json"
 fi
 env -i PATH=/usr/bin:/bin DOCKER_CONFIG="$root/fs/docker-client" /usr/bin/docker "$@"
}
metadata_proxy_port() {
 check_owner
 file="$root/fs/metadata.proxy.port"
 [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c %u "$file")" = 0 ] && [ "$(stat -c %a "$file")" = 600 ]
 port=$(cat "$file"); case "$port" in ''|*[!0-9]*) return 97;; esac
 [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
 printf '%s' "$port"
}
metadata_daemon_config() {
 port=$(metadata_proxy_port)
 printf '{"proxies":{"http-proxy":"http://127.0.0.1:%s","https-proxy":"http://127.0.0.1:%s","no-proxy":""}}\n' "$port" "$port"
}
check_metadata_proxy_env() {
 port=$(metadata_proxy_port)
 /usr/bin/python3 -I -S -B - "$1" "$root" "$port" <<'DVAIA_PROXY_ENV'
import sys
pid,root,port=sys.argv[1:]
with open('/proc/'+pid+'/environ','rb') as f: data=f.read(65537)
assert len(data)<=65536 and data.endswith(b'\0')
values=data[:-1].split(b'\0')
expected=[('PATH=/usr/bin:/bin').encode(),('TMPDIR='+root+'/fs/tmp').encode(),('HTTP_PROXY=http://127.0.0.1:'+port).encode(),('HTTPS_PROXY=http://127.0.0.1:'+port).encode(),b'NO_PROXY=']
assert sorted(values)==sorted(expected)
DVAIA_PROXY_ENV
}
stop_metadata_daemon() {
 case "$1" in daemon|containerd) ;; *) return 97;; esac
 if [ -e "$root/fs/$1.intent" ] || [ -L "$root/fs/$1.intent" ]; then
  [ -f "$root/fs/$1.pid" ] && [ ! -L "$root/fs/$1.pid" ] || return 97
 fi
 stop_owned "$1"
}
`;
  let metadataGuard=replaceOnce(guard,'case "$1" in authority|cleanup)','case "$1" in authority|cleanup|evidence|checkpoint|idle)');
  metadataGuard=replaceOnce(metadataGuard," printf '{}\\n' | cmp - \"$root/fs/daemon.json\"",' metadata_daemon_config | cmp - "$root/fs/daemon.json"\n check_metadata_proxy_env "$pid"');
  metadataGuard=replaceOnce(metadataGuard,' containerd_config | cmp - "$root/fs/containerd.toml"',' containerd_config | cmp - "$root/fs/containerd.toml"\n check_metadata_proxy_env "$pid"')+proxyFunctions;
  const stage=(script)=>replaceOnce(script,guard,metadataGuard);
  let prepare=stage(baseScripts.prepare);
  prepare+='\nmkdir -m 0700 "$root/fs/docker-client"\nprintf \'{}\\n\' > "$root/fs/docker-client/config.json"\nchmod 0600 "$root/fs/docker-client/config.json"\n';
  prepare+='\nmkdir -m 0700 "$root/fs/metadata-retained"\n';
  prepare=replaceOnce(prepare,'fallocate -l 6442450944 "$root/disk"',String.raw`/usr/bin/python3 -I -S -B - "$root/disk" <<'DVAIA_SPARSE_DISK'
import os,sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
 os.ftruncate(fd,6442450944);os.fsync(fd)
 s=os.fstat(fd);assert s.st_size==6442450944 and s.st_nlink==1 and s.st_blocks*512<=1048576
finally: os.close(fd)
DVAIA_SPARSE_DISK`);
  const split=baseScripts.start.indexOf('TMPDIR="$root/fs/tmp" setsid /usr/bin/nsenter');
  if(split<guard.length)throw fail('BUILD_METADATA_START_SHAPE');
  const namespace=metadataGuard+baseScripts.start.slice(guard.length,split);
  let daemonBody=baseScripts.start.slice(split);
  for(const [name,binary] of [['containerd','containerd'],['daemon','dockerd']]){
    const marker=`TMPDIR="$root/fs/tmp" setsid /usr/bin/nsenter --net="/proc/$holder/ns/net" -- /usr/bin/${binary}`;
    daemonBody=replaceOnce(daemonBody,marker,`printf '%s' "$nonce" > "$root/fs/${name}.intent"\nenv -i PATH=/usr/bin:/bin TMPDIR="$root/fs/tmp" HTTP_PROXY="http://127.0.0.1:$proxy_port" HTTPS_PROXY="http://127.0.0.1:$proxy_port" NO_PROXY= setsid /usr/bin/nsenter --net="/proc/$holder/ns/net" -- /usr/bin/${binary}`);
  }
  const daemons=metadataGuard+`\ncheck_mount; check_namespace\nholder=$(cat "$root/fs/namespace.pid")\nproxy_port=$(relay_control authority)\nprintf '%s' "$proxy_port" > "$root/fs/metadata.proxy.port"\nchmod 0600 "$root/fs/metadata.proxy.port"\nmetadata_daemon_config > "$root/fs/daemon.json"\n`+daemonBody;
  let install=stage(relay.install);install=replaceOnce(install,'\nrequire_private_egress\n','\n');
  let fetch=stage(baseScripts.metadata);fetch=replaceOnce(fetch,'\nrequire_private_egress\n','\n');
  fetch=replaceOnce(fetch,'name="dvaia-metadata-$nonce"',
    'printf \'DVAIA_METADATA_STAGE=pull-checkpoint\\n\' >&2\nrelay_control checkpoint >&2\nprintf \'DVAIA_METADATA_STAGE=pull-idle\\n\' >&2\nrelay_control idle >&2\nname="dvaia-metadata-$nonce"');
  fetch=replaceOnce(fetch,'--tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m',
    '--mount "type=bind,source=$root/fs/metadata-retained,target=/metadata-retained,bind-propagation=rprivate" --tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m');
  fetch=replaceOnce(fetch,'printf \'DVAIA_METADATA_STAGE=guest-start\\n\' >&2',
    '[ -d "$root/fs/metadata-retained" ] && [ ! -L "$root/fs/metadata-retained" ]\n[ "$(stat -c %u "$root/fs/metadata-retained")" = 0 ] && [ "$(stat -c %a "$root/fs/metadata-retained")" = 700 ]\n'+
    'printf \'DVAIA_METADATA_STAGE=guest-start\\n\' >&2');
  const preflight=replaceOnce(stage(baseScripts.preflight),'docker buildx version','[ -x /usr/bin/docker ]');
  const acquire=metadataGuard+`
acquisition_deadline=$(/usr/bin/python3 -I -S -B -c 'import time; print(format(time.monotonic()+300,".6f"),end="")')
printf 'DVAIA_METADATA_STAGE=preflight\\n' >&2
/bin/sh -c ${quoteScript(preflight)} metadata-preflight "$root" "$nonce" >&2
printf 'DVAIA_METADATA_STAGE=prepare\\n' >&2
/bin/sh -c ${quoteScript(prepare)} metadata-prepare "$root" "$nonce" "$acquisition_deadline" >&2
printf 'DVAIA_METADATA_STAGE=namespace\\n' >&2
/bin/sh -c ${quoteScript(namespace)} metadata-namespace "$root" "$nonce" >&2
printf 'DVAIA_METADATA_STAGE=relay-start\\n' >&2
/bin/sh -c ${quoteScript(install)} metadata-relay "$root" "$nonce" >&2
printf 'DVAIA_METADATA_STAGE=daemon-start\\n' >&2
/bin/sh -c ${quoteScript(daemons)} metadata-daemons "$root" "$nonce" >&2
/bin/sh -c ${quoteScript(fetch)} metadata-fetch "$root" "$nonce" '${base}' <<'DVAIA_METADATA_GUEST'
${guestSource}
DVAIA_METADATA_GUEST
`;
  // Evidence is retained after process retirement and before deleting journals.
  // A partial daemon spawn without its captured PID is never absence.
  const stop=metadataGuard+`
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'absent\\n'; exit 0; fi
check_owner
stop_metadata_daemon daemon
stop_metadata_daemon containerd
stop_private_relay
`;
  let cleanup=stage(scripts['metadata-cleanup']);
  cleanup=replaceOnce(cleanup,'stop_private_relay\n# Sibling','stop_metadata_daemon daemon\nstop_metadata_daemon containerd\nstop_private_relay\n# Sibling');
  const evidence=metadataGuard+`
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf '{"version":1,"absent":true}\\n'; exit 0; fi
check_owner
if [ ! -e "$root/fs/relay-lifecycle.py" ] && [ ! -L "$root/fs/relay-lifecycle.py" ]; then
 [ ! -e "$root/fs/relay.intent" ] && [ ! -L "$root/fs/relay.intent" ]
 printf '{"version":1,"partial":true,"runId":"%s","relayIntent":false}\\n' "$nonce"
 exit 0
fi
check_mount
relay_control evidence
`;
  const retainedExport=metadataGuard+String.raw`
check_owner; check_mount
for name in daemon containerd; do
 [ -f "$root/fs/$name.pid" ] && [ ! -L "$root/fs/$name.pid" ]
 pid=$(cat "$root/fs/$name.pid"); case "$pid" in ''|*[!0-9]*) exit 97;; esac
 [ ! -e "/proc/$pid" ]
done
/usr/bin/python3 -I -S -B - "$root/fs/metadata-retained" "$nonce" <<'DVAIA_METADATA_ARCHIVE'
import os,sys,stat,json,hashlib,tarfile
root,run=sys.argv[1:];cap=144*1024**2
assert os.path.realpath(root)==root
s=os.lstat(root);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
assert sorted(os.listdir(root))==['manifest.json','objects','partial','result.json']
for name in ('objects','partial'):
 s=os.lstat(root+'/'+name);assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
assert not os.listdir(root+'/partial')
def opened(name,maximum):
 fd=os.open(root+'/'+name,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o444 and 0<s.st_size<=maximum
 return os.fdopen(fd,'rb'),s
with opened('manifest.json',1048576)[0] as f: manifest=json.load(f)
assert manifest['version']==1 and manifest['kind']=='${retention.kind}' and manifest['binding']['runId']==run
objects=manifest['objects'];assert 8<=len(objects)<=64
names={row['file']:row for row in objects}
assert len(names)<=64
assert sorted(os.listdir(root+'/objects'))==sorted(name.removeprefix('objects/') for name in names)
for name,row in names.items():
 assert name=='objects/'+row['sha256'] and len(row['sha256'])==64 and all(c in '0123456789abcdef' for c in row['sha256'])
 with opened(name,32*1048576)[0] as f:
  assert os.fstat(f.fileno()).st_size==row['bytes'] and hashlib.file_digest(f,'sha256').hexdigest()==row['sha256']
names=['manifest.json','result.json']+sorted(names)
total=0
class Bounded:
 def __init__(self): self.count=0
 def write(self,data):
  self.count+=len(data);assert self.count<=145*1048576
  return sys.stdout.buffer.write(data)
sink=Bounded()
with tarfile.open(fileobj=sink,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
 for name in names:
  f,s=opened(name,1048576 if '/' not in name else 32*1048576)
  with f:
   total+=s.st_size;assert total<=cap
   info=tarfile.TarInfo(name);info.size=s.st_size;info.mode=0o444;info.uid=0;info.gid=0;info.mtime=0
   archive.addfile(info,f)
   after=os.fstat(f.fileno());assert (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
sys.stdout.buffer.flush()
DVAIA_METADATA_ARCHIVE
`;
  return {version:1,kind:targetName==='listings-package'?'private-listings-metadata':targetName==='v23-registry'?'private-v23-registry-metadata':targetName==='v24-system'?'private-v24-system-metadata':targetName==='v24-policy'?'private-v24-policy-metadata':'private-v33-pricing-metadata',runId,guest:spec.guest,binding,
    ...(rendererInputs?{rendererInputs}:{}),executionApproved:false,buildApproved:false,candidateOnly:true,storageCapBytes:LIMITS.disk,storageAllocation:'sparse-fixed-size',
    acquisitionSeconds:300,admission:prerequisite.admission,mux:prerequisite.mux,transportProof:METADATA_TRANSPORT_PROOF,
    probe:LIFECYCLE_PROBE,prerequisite:TRANSPORT_PREREQUISITE,buildSources,buildPackageDigest:source.packageDigest(),relaySourceSha256:RELAY_SOURCE_SHA,
    relayLifecycleSourceSha256:relay.sourceSha256,guestSourceSha256:sha(guestSource),variant:'metadata-idle-barrier-v4',
    metadataRetention:{version:1,mode:retention.mode,guestPath:spec.mount+'/metadata-retained',containerPath:'/metadata-retained',bytes:144*1024**2,archiveBytes:145*1024**2,objects:64},
    phases:{version:1,preflight,prepare,namespace,relayStart:install,daemonStart:daemons,metadataFetch:fetch,stop,evidence,retainedExport,cleanup},
    commands:{inventory:baseScripts.inventory,acquire,inspect:stage(baseScripts.inspect),stop,evidence,retainedExport,cleanup}};
}

function checkDaemon(row,spec) {
  if(!row||typeof row.ID!=='string'||!row.ID||row.ID===PINS.daemon||
    row.DockerRootDir!==spec.mount+'/data'||row.Driver!=='overlay2'||
    !['aarch64','arm64'].includes(row.Architecture))throw fail('BUILD_PRIVATE_DAEMON_MISMATCH');
  return row.ID;
}
function checkInventory(value) {
  if(typeof value!=='string'||!value.startsWith(JSON.stringify(PINS.daemon)+'\n')||
    !value.split('\n').includes(PINS.postgres+' postgres:18'))throw fail('BUILD_SHARED_IDENTITY_MISMATCH');
  const parts=value.split('\nNETWORK\n');
  let network;
  try{network=JSON.parse(parts[1]);}catch{throw fail('BUILD_SHARED_NETWORK_UNPROVEN');}
  if(parts.length!==2||network?.version!==1||!network.bridge||
    !Array.isArray(network.links)||!network.links.some(row=>row.ifname==='docker0')||
    JSON.stringify(Object.keys(network).sort())!==JSON.stringify(['version','bridge','links','addresses','routes4','routes6','rules4','rules6','firewall4','firewall6','nft','forwarding'].sort()))throw fail('BUILD_SHARED_NETWORK_UNPROVEN');
  return value;
}
function boundedSink(write,limit=LIMITS.export) {
  let bytes=0;
  return async chunk=>{
    if(!Buffer.isBuffer(chunk)||bytes+chunk.length>limit)throw fail('BUILD_EXPORT_LIMIT');
    bytes+=chunk.length;
    await write(chunk);
  };
}

// Bounded local SSH client. Guest commands also have their own build/export
// deadline; terminating the local client alone is never treated as cleanup.
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
function metadataDiagnostics(){
 const stages=new Set(['preflight','prepare','daemon-start','base-pull','base-pulled','guest-start','guest-enter',
  'sources','apt-update','expanded-meter','selection','report','cleanup-owner','cleanup-daemon','cleanup-containerd',
  'cleanup-process-scan','cleanup-mounts','cleanup-loop']);
 const codes=new Set(['EACCES','ENOENT','ENOSPC','ECONNRESET','ECONNREFUSED','ETIMEDOUT','CERT_HAS_EXPIRED',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE','ERR_TLS_CERT_ALTNAME_INVALID']);
 let tail='',dropping=false,bytes=0,lastStage=null,errorCode=null;
 const hash=crypto.createHash('sha256');
 function line(value){
  const stage=/^DVAIA_METADATA_STAGE=([a-z-]+)$/.exec(value);
  if(stage&&stages.has(stage[1]))lastStage=stage[1];
  const error=/^DVAIA_METADATA_ERROR=([A-Z_]+)$/.exec(value);
  if(error&&(codes.has(error[1])||/^METADATA_[A-Z_]{1,64}$/.test(error[1])))errorCode=error[1];
  if(/^SyntaxError:/.test(value))errorCode='NODE_SYNTAX_ERROR';
 }
 return {push(chunk){bytes+=chunk.length;hash.update(chunk);
  for(const part of chunk.toString('utf8').split(/(?<=\n)/)){
   const ended=part.endsWith('\n');
   if(!dropping){tail+=part;if(tail.length>512){tail='';dropping=true;}else if(ended){line(tail.slice(0,-1));tail='';}}
   if(ended){dropping=false;tail='';}
  }
 },finish({code,signal,stdoutBytes}){if(tail&&!dropping)line(tail);
  return Object.freeze({version:1,lastStage,errorCode,exitCode:Number.isInteger(code)?code:null,
   signal:['SIGTERM','SIGKILL','SIGINT'].includes(signal)?signal:null,stdoutBytes,stderrBytes:bytes,
   stderrSha256:hash.digest('hex'),rawStderrRetained:false});}};
}
function createExecutor({launch=spawn,kill=(pid,signal)=>process.kill(pid,signal),delay=wait}={}) {
return async function execute(spec,operation,{input,sink,args=[],onDiagnostics}={}) {
  if(!Object.hasOwn(scripts,operation))throw fail('BUILD_UNKNOWN_OPERATION');
  // No reviewed relay exists yet. Never fall back to the shared network or
  // accidentally treat loopback-only startup as acquisition/build readiness.
  if(['build','metadata','metadata-acquire'].includes(operation)){input?.destroy();throw fail('BUILD_PRIVATE_EGRESS_UNAVAILABLE');}
  const env={PATH:process.env.PATH,TMPDIR:path.join(spec.root,'tasks/tmp'),
    LIMA_HOME:spec.limaHome,HOME:process.env.HOME};
  return new Promise((resolve,reject)=>{
    const metadata=operation==='metadata'||operation==='metadata-acquire';
    const diagnostics=metadata||operation==='metadata-cleanup'?metadataDiagnostics():null;
    const remoteTimeoutSeconds=operation==='metadata-acquire'?300:operation==='build'||metadata?310:150;
    const child=launch(spec.lima,['shell','--workdir','/','colima-goat-q','sudo','-n','timeout','--signal=TERM','--kill-after=10',String(remoteTimeoutSeconds),'/bin/sh','-c',scripts[operation],'owned-build',spec.guest,spec.runId,...args],
      {cwd:spec.root,env,detached:true,stdio:['pipe','pipe','pipe']});
    let error,bytes=0,stderrBytes=0,chunks=[],pending=Promise.resolve();
    const stop=reason=>{error ||= reason; input?.destroy();if(child.pid)try{kill(-child.pid,'SIGKILL');}catch(cause){if(cause.code!=='ESRCH')error=cause;}};
    // Wait longer than the guest's TERM+KILL deadline, avoiding a cleanup race.
    const timer=setTimeout(()=>stop(fail('BUILD_TIMEOUT')),operation==='build'||metadata?LIMITS.buildMs+40000:180000);
    child.on('error',stop);
    child.stdin.on('error',stop);
    child.stderr.on('data',chunk=>{diagnostics?.push(chunk);stderrBytes+=chunk.length;if(stderrBytes>(metadata?LIMITS.output/2:LIMITS.output))stop(fail('BUILD_OUTPUT_LIMIT'));});
    child.stdout.on('data',chunk=>{
      bytes+=chunk.length;
      if(bytes>(metadata?1024**2:sink?LIMITS.export:LIMITS.output)){stop(fail('BUILD_EXPORT_OR_OUTPUT_LIMIT'));return;}
      if(sink){child.stdout.pause();pending=pending.then(()=>sink(chunk));pending.then(()=>child.stdout.resume(),stop);}else chunks.push(chunk);
    });
    child.on('close',async (code,signal)=>{
      clearTimeout(timer);input?.destroy();
      try{await pending;}catch(cause){error ||= cause;}
      const diagnostic=diagnostics?.finish({code,signal,stdoutBytes:bytes});
      if(diagnostic&&onDiagnostics)try{onDiagnostics(diagnostic);}catch(cause){error ||= cause;}
      if(error||code!==0){
        // SSH client death is not remote completion. Starting FROM close (not
        // launch), allow a full guest timeout + kill-after + scheduling margin
        // before the caller can begin cleanup. This also covers lost replies.
        // Cleanup still verifies processes/mounts: elapsed time alone never
        // establishes resource absence or permits a destructive operation.
        if(child.pid)try{await delay((remoteTimeoutSeconds+20)*1000);}catch(cause){reject(cause);return;}
        const failure=error||fail('BUILD_GUEST_'+operation.toUpperCase()+'_FAILED');
        if(diagnostic)failure.metadataDiagnostics=diagnostic;
        reject(failure);
      }else resolve(Buffer.concat(chunks).toString('utf8'));
    });
    if(input){input.on('error',stop);input.pipe(child.stdin);}else child.stdin.end();
  });
};
}
const execute=createExecutor();

async function verifyHost(spec) {
  if(await fs.realpath(spec.root)!==spec.root||await fs.realpath(path.dirname(spec.artifact))!==path.dirname(spec.artifact)||
    await fs.realpath(spec.lima)!==spec.lima||sha(await fs.readFile(spec.lima))!==PINS.lima)throw fail('BUILD_HOST_IDENTITY_MISMATCH');
}
function validateClosedBuildTarget(target) {
  if(target===undefined||target==='mcp-registry')return;
  require('./ownedPolicySystemBuild').requireApprovedTarget(target);
}
async function runBoundedBuild({root,runId,runner=execute,capture=source.capture,verify=verifyHost,target}={}) {
  validateClosedBuildTarget(target);
  if(runner===execute)throw fail('BUILD_PRIVATE_EGRESS_UNAVAILABLE');
  const spec=specification(root,runId);
  await verify(spec);
  const files=await capture(root); // exact manifest checks, before any VM mutation
  const digest=source.packageDigest();
  const before=checkInventory(await runner(spec,'inventory'));
  await runner(spec,'preflight');
  await fs.mkdir(spec.artifact,{mode:0o700});
  let intended=false,result,primary;
  try {
    await fs.writeFile(path.join(spec.artifact,'intent.json'),JSON.stringify({version:1,runId,guest:spec.guest,packageDigest:digest,limits:LIMITS,before}),{flag:'wx',mode:0o600});
    intended=true;
    await runner(spec,'prepare');
    const daemon=checkDaemon(JSON.parse(await runner(spec,'start')),spec);
    const inspect=async()=>{if(checkDaemon(JSON.parse(await runner(spec,'inspect')),spec)!==daemon)throw fail('BUILD_DAEMON_CHANGED');};
    await inspect();
    await runner(spec,'build',{input:source.contextStream(files),args:[digest,authority.dockerfile]});
    await inspect();
    const rows=JSON.parse(await runner(spec,'image'));
    const image=rows?.[0];
    if(rows.length!==1||!/^sha256:[a-f0-9]{64}$/.test(image?.Id)||image.Architecture!=='arm64'||image.Os!=='linux'||
      image.Config?.Labels?.['dvaia.registry.package']!==digest||image.Config?.Labels?.['dvaia.build-run']!==runId)throw fail('BUILD_IMAGE_MISMATCH');
    await capture(root);
    const file=await fs.open(path.join(spec.artifact,'image.tar'),'wx',0o600),hash=crypto.createHash('sha256');
    let bytes=0;
    try {
      await runner(spec,'export',{args:[image.Id],sink:boundedSink(async chunk=>{
        bytes+=chunk.length;
        hash.update(chunk);await file.writeFile(chunk);
      })});
      await file.sync();
    }finally{await file.close();}
    if(bytes===0)throw fail('BUILD_EXPORT_EMPTY');
    result={version:1,runId,imageId:image.Id,packageDigest:digest,archiveSha256:hash.digest('hex'),archiveBytes:bytes,qualificationComplete:false};
  }catch(error){primary=error;}
  const cleanupErrors=[];
  if(intended)try{if((await runner(spec,'cleanup')).trim()!=='absent')throw fail('BUILD_CLEANUP_UNPROVEN');}catch(error){cleanupErrors.push(error);}
  try{if(checkInventory(await runner(spec,'inventory'))!==before)throw fail('BUILD_SHARED_STATE_CHANGED');}catch(error){cleanupErrors.push(error);}
  const receipt={result:primary?null:result,error:primary?.code||primary?.message||null,cleanupErrors:cleanupErrors.map(x=>x.code||x.message),cleanupVerified:cleanupErrors.length===0};
  await fs.writeFile(path.join(spec.artifact,'result.json'),JSON.stringify(receipt),{flag:'wx',mode:0o600});
  if(primary||cleanupErrors.length)throw new AggregateError([primary,...cleanupErrors].filter(Boolean),'Bounded build failed; inspect retained receipt');
  return {...result,cleanupVerified:true,artifact:spec.artifact};
}
module.exports={runBoundedBuild,validateClosedBuildTarget,specification,LIMITS,PINS,_internals:{scripts,guard,networkShell,networkSnapshotProgram,metadataNamespaceCleanup,metadataDiagnostics,execute,createExecutor,checkDaemon,checkInventory,verifyHost,boundedSink,privateRelayPlan,relayAdmission,relayLifecycleProgram,RELAY_SOURCE_SHA,lifecycleQualificationPlan,lifecycleNoConnect,LIFECYCLE_PROBE,transportAudit,metadataAuthorityAudit,metadataBlobAuthorityAudit,metadataAdmissionAudit,metadataAdmissionProgram,metadataIdleProgram,transportCheckpointProgram,TRANSPORT_CLIENT_SHA,metadataQualificationPlan,systemMetadataQualificationPlan,pricingMetadataQualificationPlan,policyRendererMetadataQualificationPlan,listingsMetadataQualificationPlan,METADATA_TRANSPORT_PROOF}};
