#!/usr/bin/env python3
"""Owned V23 metadata acquisition only. Default --plan is local and inert.

The coordinating operator alone runs --run after source review. No build,
dependency installation, shared Docker mutation, or activation is admitted.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_SHA = 'b70793b7a8cd4cc97601064ded415fc6b29a245982d2a4f459ab0c9ead50ce0a'
BUILDER_SHA = 'df42d9db584233bda4e9100c64b05dea4597ff1fa7b6d632af17623620486bd2'
METADATA_SHA = 'e2c4cf076f8cfdc03f2595b2413559a65e1b4ab75ef184998403906435c11678'
TARGET_SHA = '7c1c7d05f520fde31902ea8f0992517dbd0648c985d7750d461a917524850870'
BASE = 'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'
SYSTEM_BASE = 'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5'
HOST_LIMITS = {'registry-1.docker.io':128*1024**2,'auth.docker.io':1024**2,'deb.debian.org':132*1024**2,
               'production.cloudfront.docker.com':128*1024**2}
OPERATIONS = {'inventory','acquire','inspect','stop','evidence','retainedExport','cleanup'}
ARCHIVE_CAP = 145*1024**2
STAGES = {'preflight','prepare','namespace','relay-start','daemon-start','base-pull','base-pulled','pull-checkpoint','pull-idle',
          'guest-start','guest-enter','sources','apt-update','expanded-meter','selection','report'}
ERROR_SIGNALS = {
    'proxy-connect':r'\bproxyconnect tcp\b',
    'unexpected-eof':r'\bunexpected eof\b',
    'connection-reset':r'\bconnection reset by peer\b',
    'connection-refused':r'\bconnection refused\b',
    'timeout':r'\b(?:i/o timeout|context deadline exceeded|tls handshake timeout)\b',
    'certificate':r'\bx509:',
    'dns':r'\bno such host\b',
    'unauthorized':r'\bunauthorized\b',
    'rate-limit':r'\btoo many requests\b',
    'storage-full':r'\bno space left on device\b',
}


def stage_error(stderr,stage,status):
    """Closed observations, not causal claims; never return stderr fragments."""
    if type(stderr) is not str or len(stderr.encode())>1024**2:raise RuntimeError('METADATA_STREAM_LIMIT')
    if type(status) is int and status==0:return None
    return {'version':1,'stage':stage if stage in STAGES else None,
            'exitCode':status if type(status) is int and -255<=status<=255 else None,
            'stderrSignals':[key for key,pattern in ERROR_SIGNALS.items() if re.search(pattern,stderr,re.I)],
            'interpretation':'observed-substrings-not-root-cause'}
NODE_PLAN = r'''const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const x=JSON.parse(fs.readFileSync(0,'utf8'));if(fs.realpathSync(x.root)!==x.root)throw Error('ROOT');process.chdir(x.root);
if(!['v23-registry','v24-system'].includes(x.target))throw Error('TARGET');
require(path.join(x.root,'tests/postgres/ownedMcpBoundedBuild'))._internals[x.target==='v24-system'?'systemMetadataQualificationPlan':'metadataQualificationPlan'](x.root,x.runId).then(plan=>{
 const sources={};for(const file of Object.keys(require.cache)){
  if(!file.startsWith(x.root+'/')||fs.realpathSync(file)!==file)throw Error('SOURCE_PATH');
  const s=fs.lstatSync(file);if(!s.isFile()||s.size>8*1024*1024)throw Error('SOURCE_SIZE');
  sources[path.relative(x.root,file)]=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
 }if(Object.keys(sources).length>512)throw Error('SOURCE_COUNT');console.log(JSON.stringify({plan,sources}));
}).catch(()=>{process.stderr.write('METADATA_PLAN_FAILED\n');process.exitCode=1});'''
NODE_VALIDATE = r'''const fs=require('node:fs'),path=require('node:path');const x=JSON.parse(fs.readFileSync(0,'utf8'));
if(fs.realpathSync(x.root)!==x.root)throw Error('ROOT');
const value=require(path.join(x.root,'tests/postgres/ownedPolicySystemMetadata')).validateResultEnvelope(x.raw,x.binding);
console.log(JSON.stringify(value));'''


def load_lifecycle():
    path = ROOT / 'tests/postgres/run_owned_mcp_relay_lifecycle.py'
    if path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != LIFECYCLE_SHA:
        raise RuntimeError('METADATA_LIFECYCLE_PIN')
    spec = importlib.util.spec_from_file_location('metadata_lifecycle',path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def make_plan(run_id, lifecycle, runner, target='v23-registry'):
    if target not in ('v23-registry','v24-system'): raise RuntimeError('METADATA_TARGET')
    if not re.fullmatch('[a-f0-9]{32}',run_id): raise RuntimeError('METADATA_RUN_ID')
    for name,digest in [('tests/postgres/ownedMcpBoundedBuild.js',BUILDER_SHA),
                        ('tests/postgres/ownedPolicySystemMetadata.js',METADATA_SHA),
                        ('tests/postgres/ownedPolicySystemBuild.js',TARGET_SHA)]:
        lifecycle.pinned(ROOT/name,digest)
    lifecycle.pinned(lifecycle.NODE,lifecycle.NODE_SHA)
    response=runner([str(lifecycle.NODE),'-e',NODE_PLAN],input=json.dumps({'root':str(ROOT),'runId':run_id,'target':target}),timeout=20)
    if response.stderr: raise RuntimeError('METADATA_PLAN_STDERR')
    packet=json.loads(response.stdout);plan=packet['plan'];sources=packet['sources']
    if (plan['kind']!=('private-v23-registry-metadata' if target=='v23-registry' else 'private-v24-system-metadata') or plan['variant']!='metadata-idle-barrier-v4' or plan['runId']!=run_id
            or plan['binding']!={'runId':run_id,'target':target,'base':BASE if target=='v23-registry' else SYSTEM_BASE}
            or plan['guest']!='/var/tmp/dvaia-v23-build-'+run_id or set(plan['commands'])!=OPERATIONS
            or plan['executionApproved'] is not False or plan['buildApproved'] is not False
            or plan['candidateOnly'] is not True or plan['storageCapBytes']!=6442450944
            or plan['storageAllocation']!='sparse-fixed-size' or plan['acquisitionSeconds']!=300):
        raise RuntimeError('METADATA_PLAN_SHAPE')
    if plan.get('metadataRetention')!={'version':1,'mode':'v23-metadata-retention-v1' if target=='v23-registry' else 'v24-system-metadata-retention-v1',
            'guestPath':plan['guest']+'/fs/metadata-retained','containerPath':'/metadata-retained',
            'bytes':144*1024**2,'archiveBytes':ARCHIVE_CAP,'objects':64}:
        raise RuntimeError('METADATA_RETENTION_PLAN')
    sources.update({str(Path(__file__).relative_to(ROOT)):lifecycle.sha(Path(__file__)),
                    'tests/postgres/run_owned_mcp_relay_lifecycle.py':LIFECYCLE_SHA,
                    'tests/postgres/probe_owned_mcp_relay_guest.py':lifecycle.PROBE_SHA,
                    str(lifecycle.NODE.relative_to(ROOT)):lifecycle.NODE_SHA,
                    'tests/postgres/ownedMcpPrivateTransportClient.py':
                        '0b319bcdb6c2fc185e5662a052e001043802f251f739eba6e87524f55bb3a5c7'})
    for key in ('transportProof','probe','prerequisite'):
        sources[plan[key]['path']]=plan[key]['sha256']
    if type(plan.get('buildSources')) is not dict or len(plan['buildSources'])!=20:
        raise RuntimeError('METADATA_BUILD_SOURCE_CLOSURE')
    sources.update(plan['buildSources'])
    probe=lifecycle.load_probe()
    for name,digest in probe.DEPENDENCIES.items():sources['tests/postgres/'+name+'.py']=digest
    lifecycle.verify_sources(sources)
    return plan,sources


def verify_audit(audit,plan,mode,trigger='terminal',sequence=3):
    if (type(audit) is not dict or set(audit)!={'kind','variant','runId','mode','sequence','trigger','counts','activeWorkers','deniedAuthorities','admission'}
            or audit['kind']!='transport-audit' or audit['variant']!='metadata-idle-barrier-v4'
            or audit['runId']!=plan['runId'] or audit['mode']!=mode or audit['trigger']!=trigger
            or type(audit['sequence']) is not int or audit['sequence']!=sequence
            or type(audit['activeWorkers']) is not int or not 0<=audit['activeWorkers']<=(4 if trigger=='checkpoint' else 0)):
        raise RuntimeError('METADATA_AUDIT')
    admission=audit['admission']
    if (type(admission) is not dict or set(admission)!={'workerLimitRejected','connectionLimitRejected','saturated'}
            or type(admission['saturated']) is not bool
            or any(type(admission[k]) is not int or not 0<=admission[k]<=65535 for k in ('workerLimitRejected','connectionLimitRejected'))
            or admission['saturated'] and max(admission['workerLimitRejected'],admission['connectionLimitRejected'])!=65535):
        raise RuntimeError('METADATA_ADMISSION_COUNTS')
    counts=audit['counts']
    if (type(counts) is not dict or set(counts)!={'dnsSubprocesses','externalConnectAttempts','unixConnectAttempts','peerChecks','peerDenied'}
            or any(type(v) is not int or not 0<=v<=32 for v in counts.values())
            or mode=='adapter' and (counts['dnsSubprocesses'] or counts['externalConnectAttempts'])
            or mode=='connector' and counts['unixConnectAttempts']):raise RuntimeError('METADATA_AUDIT_COUNTS')
    denied=audit['deniedAuthorities']
    if (type(denied) is not dict or set(denied)!={'hosts','unclassified','overflow'}
            or type(denied['hosts']) is not dict or len(denied['hosts'])>8
            or any(type(denied[k]) is not int or not 0<=denied[k]<=32 for k in ('unclassified','overflow'))):
        raise RuntimeError('METADATA_DENIED_AUTHORITIES')
    for host,count in denied['hosts'].items():
        if (type(host) is not str or not 1<=len(host)<=253 or '.' not in host
                or host in HOST_LIMITS
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.'))
                or type(count) is not int or not 1<=count<=32):raise RuntimeError('METADATA_DENIED_AUTHORITIES')
        try:ipaddress.ip_address(host)
        except ValueError:pass
        else:raise RuntimeError('METADATA_DENIED_AUTHORITIES')
    if sum(denied['hosts'].values())+denied['unclassified']+denied['overflow']>32:
        raise RuntimeError('METADATA_DENIED_AUTHORITIES')


def relay_diagnostics(snapshot,plan):
    """Retain bounded hostname-only observations even on failed acquisition."""
    diagnostics={}
    for mode in ('connector','adapter'):
        raw=snapshot.get('files',{}).get('relay.'+mode+'.log')
        if raw is None:diagnostics[mode]=None;continue
        rows=[json.loads(line) for line in raw.splitlines()]
        audits=[row for row in rows if row.get('kind')=='transport-audit']
        if not audits:diagnostics[mode]=None;continue
        if len(audits)>3:raise RuntimeError('METADATA_AUDIT')
        checkpoints=[row for row in audits if row.get('trigger')=='checkpoint']
        terminals=[row for row in audits if row.get('trigger')=='terminal']
        if len(checkpoints)>2 or len(terminals)>1 or len(checkpoints)+len(terminals)!=len(audits):raise RuntimeError('METADATA_AUDIT')
        for index,row in enumerate(checkpoints):verify_audit(row,plan,mode,'checkpoint',index+1)
        if terminals:verify_audit(terminals[0],plan,mode,'terminal',1+len(checkpoints))
        if audits!=checkpoints+terminals:raise RuntimeError('METADATA_AUDIT')
        for previous,current in zip(audits,audits[1:]):
            for group,keys in [('counts',previous['counts']),('admission',('workerLimitRejected','connectionLimitRejected'))]:
                if any(current[group][k]<previous[group][k] for k in keys):raise RuntimeError('METADATA_AUDIT')
            if previous['admission']['saturated'] and not current['admission']['saturated']:raise RuntimeError('METADATA_AUDIT')
        project=lambda row:{key:row[key] for key in ('counts','activeWorkers','deniedAuthorities','admission')}
        diagnostics[mode]={'variant':audits[0]['variant'],'checkpoint':project(checkpoints[0]) if checkpoints else None,
                           'idleCheckpoint':project(checkpoints[1]) if len(checkpoints)>1 else None,
                           'terminal':project(terminals[0]) if terminals else None}
    return diagnostics


def verify_idle(snapshot,plan):
    files=snapshot['files']
    intent=json.loads(files['relay.idle.intent']);result=json.loads(files['relay.idle.result'])
    if (type(intent) is not dict or set(intent)!={'version','runId','deadline','started','end','processes'}
            or type(intent['version']) is not int or intent['version']!=1 or intent['runId']!=plan['runId']
            or type(intent['deadline']) is not str or not re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]{1,9})?',intent['deadline'])
            or len(intent['deadline'])>32 or intent['deadline']!=json.loads(files['relay.ready'])['deadline']
            or any(type(intent[k]) not in (int,float) or not math.isfinite(intent[k]) for k in ('started','end'))
            or not 0<float(intent['deadline'])-intent['started']<=300
            or intent['end']!=min(float(intent['deadline']),intent['started']+16)
            or type(intent['processes']) is not dict or set(intent['processes'])!={'connector','adapter'}):
        raise RuntimeError('METADATA_IDLE_INTENT')
    for mode in ('connector','adapter'):
        row=json.loads(files['relay.'+mode+'.process']);bound=intent['processes'][mode]
        if (type(bound) is not dict or set(bound)!={'pid','start','net'}
                or any(type(bound[k]) is not int or bound[k]<=0 for k in ('pid','start'))
                or bound!={key:row[key] for key in ('pid','start','net')} or row['deadline']!=intent['deadline']):
            raise RuntimeError('METADATA_IDLE_IDENTITY')
    if (type(result) is not dict or set(result)!={'version','runId','quiescent','attempts','observations','checkpointSequences','completedAt'}
            or type(result['version']) is not int or result['version']!=1 or result['runId']!=plan['runId'] or result['quiescent'] is not True
            or type(result['attempts']) is not int or not 1<=result['attempts']<=33
            or type(result['completedAt']) not in (int,float) or not math.isfinite(result['completedAt'])
            or not intent['started']<=result['completedAt']<intent['end']):raise RuntimeError('METADATA_IDLE_PROOF')
    for key,expected in [('observations',0),('checkpointSequences',2)]:
        if (type(result[key]) is not dict or set(result[key])!={'connector','adapter'}
                or any(type(v) is not int or v!=expected for v in result[key].values())):raise RuntimeError('METADATA_IDLE_PROOF')


def verify_terminal(snapshot,plan):
    if (type(snapshot) is not dict or snapshot.get('version')!=1 or snapshot.get('runId')!=plan['runId']
            or snapshot.get('sourceSha256')!=plan['relaySourceSha256'] or snapshot.get('lifecycleOnly') is not False
            or snapshot.get('admission')!=plan['admission']):raise RuntimeError('METADATA_TERMINAL_BINDING')
    storage=snapshot.get('storage',{})
    if (storage.get('capBytes')!=6442450944 or storage.get('logicalBytes')!=6442450944
            or any(type(storage.get(k)) is not int or not 0<=storage[k]<=6442450944 for k in ('usedBytes','allocatedBytes'))):
        raise RuntimeError('METADATA_STORAGE')
    for mode in ('connector','adapter'):
        rows=[json.loads(line) for line in snapshot['files']['relay.'+mode+'.log'].splitlines()]
        if len(rows)!=5 or rows[0].get('kind')!='relay-ready' or rows[0].get('mode')!=mode:raise RuntimeError('METADATA_RELAY_LOG')
        verify_audit(rows[1],plan,mode,'checkpoint',1)
        verify_audit(rows[2],plan,mode,'checkpoint',2)
        if rows[2]['activeWorkers']!=0:raise RuntimeError('METADATA_IDLE_PROOF')
        last,audit=rows[-2:]
        if (last.get('kind')!='relay-terminal' or last.get('cleanupVerified') is not True
                or type(last.get('unjoinedWorkers')) is not int or last['unjoinedWorkers']!=0
                or type(last.get('unresolvedResolverCleanup')) is not int or last['unresolvedResolverCleanup']!=0
                or type(last.get('connections')) is not int or not 1<=last['connections']<=32
                or type(last.get('bytes')) is not int or not 1<=last['bytes']<=261*1024**2):
            raise RuntimeError('METADATA_RELAY_RETIREMENT')
        limits=HOST_LIMITS
        totals=last.get('hostBytes',{})
        if (set(totals)!=set(limits) or any(type(totals[h]) is not int or not 0<=totals[h]<=limits[h] for h in limits)
                or sum(totals.values())!=last['bytes']):raise RuntimeError('METADATA_RELAY_BYTES')
        records=last.get('records')
        if type(records) is not list or len(records)!=last['connections']:raise RuntimeError('METADATA_RELAY_RECORDS')
        for row in records:
            if (type(row) is not dict or set(row)!={'host','status'} or
                    not (row=={'host':None,'status':'denied'} or row['host'] in limits and row['status'] in ('closed','denied'))):
                raise RuntimeError('METADATA_RELAY_RECORDS')
        verify_audit(audit,plan,mode)
        denied=audit['deniedAuthorities']
        if sum(denied['hosts'].values())+denied['unclassified']+denied['overflow']>sum(row=={'host':None,'status':'denied'} for row in records):
            raise RuntimeError('METADATA_DENIED_AUTHORITIES')
    relay_diagnostics(snapshot,plan)
    verify_idle(snapshot,plan)


def verify_retained_archive(path,envelope):
    """No extraction. Exact closed USTAR bytes and envelope/manifest/object joins."""
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=ARCHIVE_CAP):raise RuntimeError('METADATA_ARCHIVE_FILE')
    manifest=envelope['candidate']['retainedMetadata']
    canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    objects={row['file']:row for row in manifest['objects']}
    expected={'manifest.json','result.json'}|set(objects);seen=set();total=0;offset=0
    with path.open('rb') as source,tarfile.open(fileobj=source,mode='r:') as archive:
        for member in archive:
            if (member.name not in expected or member.name in seen or not member.isfile() or member.type!=tarfile.REGTYPE
                    or member.pax_headers or member.linkname or member.uid!=0 or member.gid!=0 or member.uname or member.gname
                    or member.mode!=0o444 or member.mtime!=0 or member.offset!=offset or member.offset_data!=offset+512):
                raise RuntimeError('METADATA_ARCHIVE_MEMBER')
            seen.add(member.name);total+=member.size
            if total>144*1024**2 or member.size<=0 or member.size>(32*1024**2 if member.name in objects else 1024**2):
                raise RuntimeError('METADATA_ARCHIVE_LIMIT')
            offset=member.offset_data+((member.size+511)//512)*512
            digest=hashlib.sha256();content=bytearray()
            with archive.extractfile(member) as stream:
                while True:
                    chunk=stream.read(65536)
                    if not chunk:break
                    digest.update(chunk)
                    if member.name not in objects:content.extend(chunk)
            if member.name in objects:
                row=objects[member.name]
                if member.size!=row['bytes'] or digest.hexdigest()!=row['sha256']:raise RuntimeError('METADATA_ARCHIVE_DIGEST')
            elif canonical(json.loads(content))!=canonical(manifest if member.name=='manifest.json' else envelope):
                raise RuntimeError('METADATA_ARCHIVE_JOIN')
        if seen!=expected:raise RuntimeError('METADATA_ARCHIVE_MISSING')
        source.seek(offset);remaining=source.read(10753)
        if len(remaining)!=1024+(-(offset+1024))%10240 or any(remaining) or source.read(1):raise RuntimeError('METADATA_ARCHIVE_TRAILER')
    digest_state=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(65536),b''):digest_state.update(chunk)
    digest=digest_state.hexdigest()
    return {'version':1,'file':'metadata-retained.tar','sha256':digest,'bytes':info.st_size,
            'objects':len(objects),'candidateOnly':True,'authenticatedReplayComplete':False}


def run_metadata(plan,sources,directory,lifecycle,probe,mux,work,cleanup,validate,pause=time.sleep,setup_children=()):
    result={'version':1,'kind':plan['kind'],'variant':plan['variant'],'runId':plan['runId'],'passed':False,'candidateOnly':True,
            'executionApproved':False,'buildApproved':False,'errors':[],'cleanupErrors':[],'commandFailures':[]}
    authority=None;before=None;intended=False;stopped=False;captured=False;candidate=None;envelope=None;command_count=0
    remote_quiescent=True;pending_remote=None;interruption=None
    def healthy(runner):return all(row['reaped'] and row['groupAbsent'] for row in runner.children)
    def command(operation,runner,stdout_fd=None):
        nonlocal command_count,remote_quiescent,pending_remote
        if operation not in OPERATIONS:raise RuntimeError('METADATA_OPERATION')
        if not remote_quiescent:raise RuntimeError('METADATA_REMOTE_QUIESCENCE_UNVERIFIED')
        seconds=300 if operation=='acquire' else 60 if operation in ('stop','cleanup','retainedExport') else 15
        argv=mux.mux_command(authority,'sudo','-n','timeout','--signal=TERM','--kill-after=10',str(seconds),
            '/bin/sh','-s','--',plan['guest'],plan['runId'])
        started=time.monotonic();command_count+=1;remote_terminal=False
        remote_quiescent=False
        pending_remote={'operation':operation,'notBeforeHostMonotonic':started+seconds+12}
        try:
            extra={'stdout_fd':stdout_fd,'stdout_limit':ARCHIVE_CAP} if stdout_fd is not None else {}
            response=runner(argv,input=plan['commands'][operation],timeout=seconds+15,check=False,**extra)
            # SSH reserves 255 for transport failure. A reaped local child,
            # a signal exit, or a missing status says nothing about the remote
            # timeout process. Only a normal, unambiguous SSH status is terminal.
            remote_terminal=type(response.returncode) is int and 0<=response.returncode<255
            if remote_terminal:remote_quiescent=True;pending_remote=None
            if len(response.stdout.encode())>1024**2 or len(response.stderr.encode())>1024**2:raise RuntimeError('METADATA_STREAM_LIMIT')
            stages=[stage for stage in re.findall(r'^DVAIA_METADATA_STAGE=([a-z-]+)$',response.stderr,re.M) if stage in STAGES]
            lifecycle.persist(directory,str(command_count)+'-'+operation+'-command.json',{'exitCode':response.returncode,
                'lastStage':stages[-1] if stages else None,
                'stageError':stage_error(response.stderr,stages[-1] if stages else None,response.returncode),
                'stdoutBytes':len(response.stdout.encode()),'stderrBytes':len(response.stderr.encode()),
                'stderrSha256':hashlib.sha256(response.stderr.encode()).hexdigest(),'rawStderrRetained':False})
            if operation=='acquire':lifecycle.persist(directory,'acquisition-output.json',{'raw':response.stdout})
            if type(response.returncode) is not int:raise RuntimeError('COMMAND_STATUS_UNKNOWN')
            if response.returncode:raise RuntimeError('COMMAND_EXIT_'+str(response.returncode))
            return response.stdout
        except Exception as exc:
            code=str(exc)
            if not re.fullmatch(r'(?:COMMAND_EXIT_-?\d+|COMMAND_STATUS_UNKNOWN|COMMAND_DEADLINE|HOST_DEADLINE|OUTPUT_LIMIT|METADATA_STREAM_LIMIT)',code):code='METADATA_COMMAND_FAILED'
            result['commandFailures'].append({'operation':operation,'code':code})
            # Lost SSH completion cannot prove the remote timeout has elapsed.
            # No cleanup starts until its full remaining bound has been allowed.
            if not remote_terminal:
                pause(max(0,started+seconds+12-time.monotonic()))
                if time.monotonic()<started+seconds+12:
                    raise RuntimeError('METADATA_REMOTE_GRACE_UNVERIFIED')
                remote_quiescent=True;pending_remote=None
            raise
    try:
        expected=dict(plan['mux']);expected['masterBirth']=tuple(expected['masterBirth'])
        authority=mux.admit_existing_mux(ROOT,expected=expected,
            run=lambda argv,**kw:work(argv,**(kw|{'timeout':2})))
        result['muxBefore']=authority
        before=lifecycle.inventory_valid(command('inventory',work))
        lifecycle.persist(directory,'inventory-before.json',{'text':before})
        lifecycle.persist(directory,'intent.json',{'runId':plan['runId'],'guest':plan['guest'],'binding':plan['binding'],
            'guestSourceSha256':plan['guestSourceSha256'],'storageCapBytes':6442450944,'storageAllocation':'sparse-fixed-size'})
        intended=True
        raw=command('acquire',work)
        envelope=validate(raw)
        if envelope.get('version')!=3:raise RuntimeError('METADATA_RETENTION_ENVELOPE')
        lifecycle.persist(directory,'validated-envelope.json',envelope)
        if envelope.get('ok') is not True:raise RuntimeError('METADATA_SEMANTIC_FAILURE')
        candidate=envelope['candidate']
        info=json.loads(command('inspect',work))
        if (not info.get('ID') or info['ID']=='945f6fce-3aaf-4d8f-a483-170464fb2416'
                or info.get('DockerRootDir')!=plan['guest']+'/fs/data' or info.get('Driver')!='overlay2'
                or info.get('Architecture') not in ('arm64','aarch64')):raise RuntimeError('METADATA_DAEMON_ID')
        lifecycle.persist(directory,'private-daemon.json',info)
    except Exception:
        result['errors'].append('METADATA_ACQUISITION_FAILED')
    except BaseException as exc:
        interruption=exc;result['errors'].append('METADATA_INTERRUPTED')
    finally:
        try:
            if intended and healthy(work) and remote_quiescent and interruption is None:
                try:command('stop',cleanup);stopped=True
                except Exception:result['cleanupErrors'].append('METADATA_STOP_FAILED')
                if remote_quiescent:
                    try:
                        snapshot=json.loads(command('evidence',cleanup));lifecycle.persist(directory,'terminal.json',snapshot);captured=True
                        result['relayDiagnostics']=relay_diagnostics(snapshot,plan)
                        if candidate is not None:verify_terminal(snapshot,plan);result['idleBarrierVerified']=True
                    except Exception:result['cleanupErrors'].append('METADATA_TERMINAL_UNVERIFIED')
                if stopped and captured and healthy(cleanup) and remote_quiescent:
                    if candidate is not None:
                        fd=None
                        try:
                            partial=directory/'metadata-retained.tar.partial'
                            fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                            command('retainedExport',cleanup,stdout_fd=fd)
                            os.close(fd);fd=None
                            result['metadataArchive']=verify_retained_archive(partial,envelope)
                            os.link(partial,directory/'metadata-retained.tar',follow_symlinks=False)
                            partial.unlink()
                            parent=os.open(directory,os.O_RDONLY)
                            try:os.fsync(parent)
                            finally:os.close(parent)
                        except Exception:result['cleanupErrors'].append('METADATA_EXPORT_UNVERIFIED')
                        finally:
                            if fd is not None:os.close(fd)
                    if remote_quiescent and healthy(cleanup):
                        try:
                            if command('cleanup',cleanup).strip()!='absent':raise RuntimeError('METADATA_ABSENCE')
                            result['guestAbsent']=True
                        except Exception:result['cleanupErrors'].append('METADATA_CLEANUP_UNVERIFIED')
                    else:result['cleanupErrors'].append('METADATA_GUEST_RETAINED')
                else:result['cleanupErrors'].append('METADATA_GUEST_RETAINED')
            elif intended:
                result['cleanupErrors'].append('METADATA_GUEST_RETAINED')
                if not healthy(work):result['cleanupErrors'].append('HOST_QUIESCENCE_UNVERIFIED')
            if authority is not None and remote_quiescent and interruption is None:
                try:
                    after=lifecycle.inventory_valid(command('inventory',cleanup))
                    lifecycle.persist(directory,'inventory-after.json',{'text':after})
                    if before is None or after!=before:raise RuntimeError('SHARED_CHANGED')
                    result['sharedStateUnchanged']=True
                except Exception:result['cleanupErrors'].append('SHARED_POSTFLIGHT_FAILED')
                if remote_quiescent:
                    try:
                        result['muxAfter']=mux.admit_existing_mux(ROOT,expected=authority,
                            run=lambda argv,**kw:cleanup(argv,**(kw|{'timeout':2})));result['muxUnchanged']=True
                    except Exception:result['cleanupErrors'].append('MUX_POSTFLIGHT_FAILED')
        except BaseException as exc:
            interruption=exc;result['errors'].append('METADATA_INTERRUPTED')
        if not remote_quiescent:result['cleanupErrors'].append('REMOTE_QUIESCENCE_UNVERIFIED')
        if interruption is not None:
            result['interrupted']='KeyboardInterrupt' if isinstance(interruption,KeyboardInterrupt) else 'SystemExit' if isinstance(interruption,SystemExit) else 'BaseException'
            if intended and not result.get('guestAbsent'):result['cleanupErrors'].append('METADATA_GUEST_RETAINED')
        try:lifecycle.verify_sources(sources);result['sourceUnchanged']=True
        except Exception:result['cleanupErrors'].append('SOURCE_POSTFLIGHT_FAILED')
        except BaseException as exc:
            interruption=exc;result['errors'].append('METADATA_INTERRUPTED')
        result['remoteQuiescenceVerified']=remote_quiescent
        result['pendingRemote']=pending_remote
        result['children']=list(setup_children)+work.children+cleanup.children
        result['passed']=not result['errors'] and not result['cleanupErrors'] and result.get('guestAbsent') is True
        result['candidate']=candidate if result['passed'] else None
        lifecycle.persist(directory,'result.json',result)
    if interruption is not None:raise interruption
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true')
    parser.add_argument('--target',choices=('v23-registry','v24-system'),default='v23-registry')
    parser.add_argument('--run-id',default='a'*32);parser.add_argument('--output-dir');args=parser.parse_args()
    if args.run and (args.run_id=='a'*32 or not args.output_dir):parser.error('--run requires unique --run-id and --output-dir')
    if not args.run and args.output_dir:parser.error('--output-dir requires --run')
    lifecycle=load_lifecycle();probe=lifecycle.load_probe()
    setup=probe.BoundedRunner(time.monotonic()+30)
    plan,sources=make_plan(args.run_id,lifecycle,setup,args.target)
    if not args.run:
        print(json.dumps({key:value for key,value in plan.items() if key not in ('commands','phases','mux')},sort_keys=True));return 0
    directory=lifecycle.private_directory(args.output_dir)
    lifecycle.persist(directory,'plan.json',plan);lifecycle.persist(directory,'sources.json',sources)
    work=probe.BoundedRunner(time.monotonic()+360,command_seconds=320)
    class Cleanup:
        actual=None
        @property
        def children(self):return self.actual.children if self.actual else []
        def __call__(self,*a,**kw):
            if self.actual is None:self.actual=probe.BoundedRunner(time.monotonic()+180,command_seconds=80)
            return self.actual(*a,**kw)
    def validate(raw):
        response=work([str(lifecycle.NODE),'-e',NODE_VALIDATE],input=json.dumps({'root':str(ROOT),'raw':raw,'binding':plan['binding']}),timeout=15)
        if response.stderr:raise RuntimeError('METADATA_VALIDATOR_STDERR')
        return json.loads(response.stdout)
    try:mux=probe.load_mux()
    except Exception:
        result={'passed':False,'errors':['METADATA_MUX_IMPORT_FAILED'],'candidateOnly':True,
                'buildApproved':False,'executionApproved':False,'children':setup.children}
        lifecycle.persist(directory,'result.json',result)
    else:result=run_metadata(plan,sources,directory,lifecycle,probe,mux,work,Cleanup(),validate,setup_children=setup.children)
    print(json.dumps({'passed':result['passed'],'result':str(directory/'result.json'),'candidateOnly':True,'buildApproved':False}))
    return 0 if result['passed'] else 1


if __name__=='__main__':sys.exit(main())
