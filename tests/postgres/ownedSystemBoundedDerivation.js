'use strict';
// System-only, source-pinned derivation. Never writes or replaces shared code.
// This constructs commands; it does not admit or execute a native operation.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto'),Module=require('node:module');
const lease=require('./ownedSystemRuntimeLease');
const SOURCE_SHA='ab71e0fb17929f9323e1ff92f452b96b1b813641e4f70c1f3c6a555873a37c22';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
const PAIR_POLICY=Object.freeze({version:1,name:'v24-pair-phase-credits-v2',lifetime:320,overhead:32,artifacts:128});
// Authenticated original index -> arm64 manifests 0e8905de... / daa57f03...
// contain 141550808 unique compressed layer bytes. ceilMiB(payload + 1MiB)
// is a bounded protocol allowance, not proof of wire usage or renderer APT fit.
// Both original bases, recipes and all non-CloudFront limits remain unchanged.
const PAIR_WIRE_POLICY=Object.freeze({version:1,name:'v24-pair-wire-v1',
 uniqueLayerPayloadBytes:141550808,cloudfrontBytes:136*1024**2,
 registryBytes:128*1024**2,authBytes:1024**2,aptBytes:132*1024**2,totalBytes:261*1024**2});
// Only the paired factory installs this controller. Capacity is not package
// authentication: the unchanged guest must replay APT before any .deb request.
const PAIR_COMMON=String.raw`
PAIR_POLICY='v24-pair-phase-credits-v2'
PAIR_PHASES=('system-overhead','system-artifacts','policy-overhead','policy-artifacts','sealed')
def pair_shape(row,run):
    if type(row) is not dict or set(row)!={'version','policy','runId','sequence','phase','allocation','starts','quota','artifactCount'}: raise ValueError('PAIR_CREDIT_SHAPE')
    if type(row['version']) is not int or row['version']!=1 or row['policy']!=PAIR_POLICY or row['runId']!=run: raise ValueError('PAIR_CREDIT_BINDING')
    seq=row['sequence'];quota=row['quota'];n=row['artifactCount']
    if type(n) is not int or (seq in (1,3) and not 1<=n<=128) or (seq not in (1,3) and n!=0): raise ValueError('PAIR_ARTIFACT_COUNT')
    if type(seq) is not int or not 0<=seq<=4 or row['phase']!=PAIR_PHASES[seq]: raise ValueError('PAIR_CREDIT_PHASE')
    if type(quota) is not int or (seq in (0,2) and quota!=32) or (seq in (1,3) and not n<=quota<=2*n) or (seq==4 and quota!=0): raise ValueError('PAIR_CREDIT_QUOTA')
    if type(row['allocation']) is not int or not 32<=row['allocation']<=320: raise ValueError('PAIR_CREDIT_ALLOCATION')
    if type(row['starts']) is not dict or set(row['starts'])!={'adapter','connector'} or any(type(n) is not int or n<0 or n+quota>row['allocation'] for n in row['starts'].values()): raise ValueError('PAIR_CREDIT_START')
    if seq==0 and (row['allocation']!=32 or any(row['starts'].values())): raise ValueError('PAIR_CREDIT_INITIAL')
    return row
def pair_read(path,mode,maximum=4096):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        a=os.fstat(fd)
        if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)!=mode or not 0<a.st_size<=maximum: raise ValueError('PAIR_CREDIT_FILE')
        data=os.read(fd,maximum+1);z=os.fstat(fd)
        if len(data)!=a.st_size or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns): raise ValueError('PAIR_CREDIT_CHANGED')
        return json.loads(data)
    finally:os.close(fd)
`;
const PAIR_CHILD=PAIR_COMMON+String.raw`
PAIR_BUDGET=None
def pair_refresh_checked(budget):
    row=pair_shape(pair_read('/var/tmp/dvaia-v23-relay-'+TRANSPORT_RUN+'/pair-credit.json',0o444),TRANSPORT_RUN)
    old=budget.pair_credit
    if old is None:
        if row['sequence']!=0 or budget.connections!=0: raise Denied('pair-initial')
    elif row['sequence']==old['sequence']:
        if row!=old: raise Denied('pair-rewrite')
    else:
        if row['sequence']!=old['sequence']+1 or row['allocation']!=old['allocation']+(row['artifactCount'] if row['sequence'] in (1,3) else row['quota']) or row['starts'][TRANSPORT_MODE]!=budget.connections: raise Denied('pair-advance')
        used=budget.connections-old['starts'][TRANSPORT_MODE]
        if used<0 or used>old['quota'] or (old['sequence'] in (1,3) and used<old['artifactCount']): raise Denied('pair-spend')
    budget.pair_credit=row
    return row
def pair_refresh(budget):
    if budget.pair_failed:raise Denied('pair-poisoned')
    try:return pair_refresh_checked(budget)
    except BaseException:
        budget.pair_failed=True
        raise
def pair_budget_snapshot():
    if PAIR_BUDGET is None: raise Denied('pair-not-started')
    # Signals run on the accept thread; RLock also covers a signal interrupting
    # that thread's own admit. No second network worker gets admission authority.
    with PAIR_BUDGET.lock:
        row=pair_refresh(PAIR_BUDGET)
        return dict(policy=PAIR_POLICY,lifetime=320,connections=PAIR_BUDGET.connections,credit=row)
`;
const PAIR_CONTROLLER=PAIR_COMMON+String.raw`
def pair_publish(row,initial=False):
    pair_shape(row,RUN)
    # Exclusive intent precedes publication. A failed/uncertain advance is never
    # repeatable, including failure after rename but before directory fsync.
    save('pair.credit.'+str(row['sequence'])+'.intent',row)
    parent=os.open(ROOT+'/fs',os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)
    target=RELAY+'/pair-credit.json';temporary=RELAY+'/pair-credit.pending'
    if initial: require(not os.path.lexists(target))
    else: pair_read(target,0o444)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
    try:
        data=json.dumps(row,sort_keys=True,separators=(',',':')).encode()
        while data:
            n=os.write(fd,data);require(n>0);data=data[n:]
        os.fchmod(fd,0o444);os.fsync(fd)
    finally:os.close(fd)
    os.replace(temporary,target)
    fd=os.open(RELAY,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def pair_initialize():
    pair_publish(dict(version=1,policy=PAIR_POLICY,runId=RUN,sequence=0,phase=PAIR_PHASES[0],allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0),True)
def pair_remove(end):
    # Called only after the original exact child/group absence proof. Partial
    # publication is removed only when bytes equal its durable exclusive intent.
    for name in ('pair-credit.json','pair-credit.pending'):
        file=RELAY+'/'+name
        if not os.path.lexists(file):continue
        row=pair_shape(pair_read(file,0o444),RUN)
        require(row==json.loads(read(ROOT+'/fs/pair.credit.'+str(row['sequence'])+'.intent')))
        require(time.monotonic()<end,'deadline_exhausted')
        os.unlink(file)
def pair_worker_rejections(packet):
    result={}
    for mode in ('adapter','connector'):
        admission=packet['rows'][mode]['admission'];n=admission['workerLimitRejected']
        require(type(n) is int and 0<=n<=65535 and admission['connectionLimitRejected']==0 and admission['saturated'] is False)
        result[mode]=n
    return result
def pair_observe():
    import io,contextlib
    # Same fixed process/namespace authority; do not reuse the metadata idle
    # writer's exclusive records. This bounded barrier publishes via advance.
    authority();end=min(float(read(ROOT+'/acquisition.deadline')),time.monotonic()+16)
    while True:
        require(time.monotonic()<end);authority()
        processes={mode:json.loads(read(ROOT+'/fs/relay.'+mode+'.process')) for mode in ('adapter','connector')}
        quiet=True
        for process in processes.values():
            check_child(process,proc(process['pid']))
            quiet=quiet and os.listdir('/proc/'+str(process['pid'])+'/task')==[str(process['pid'])]
        if quiet:
            with contextlib.redirect_stdout(io.StringIO()):packet=checkpoint(end)
            if all(item['activeWorkers']==0 for item in packet['rows'].values()):break
        time.sleep(min(.05,max(0,end-time.monotonic())))
    for process in processes.values():
        check_child(process,proc(process['pid']))
        require(os.listdir('/proc/'+str(process['pid'])+'/task')==[str(process['pid'])])
    row=pair_shape(pair_read(RELAY+'/pair-credit.json',0o444),RUN)
    counts={}
    for mode in ('adapter','connector'):
        item=packet['rows'][mode];budget=item.get('pairBudget')
        require(type(budget) is dict and set(budget)=={'policy','lifetime','connections','credit'} and budget['policy']==PAIR_POLICY and budget['lifetime']==320 and budget['credit']==row)
        n=budget['connections'];require(type(n) is int and row['starts'][mode]<=n<=row['starts'][mode]+row['quota'])
        require(item['activeWorkers']==0)
        require(item['deniedAuthorities']==dict(hosts={},unclassified=0,overflow=0))
        counts[mode]=n
    pair_worker_rejections(packet)
    require(counts['adapter']==counts['connector'])
    return row,counts,packet
def pair_idle_save(kind,value):
    row=pair_shape(pair_read(RELAY+'/pair-credit.json',0o444),RUN)
    require(row['sequence'] in (0,2) and kind in ('intent','result'))
    save('pair.idle.'+str(row['sequence'])+'.'+kind,value)
def pair_candidate(slot):
    target='v24-system' if slot=='system' else 'v24-policy'
    base=PAIR_BASES[slot]
    value=pair_read(ROOT+'/fs/'+slot+'-metadata-retained/result.json',0o444,1048576)
    require(value['version']==3 and value['ok'] is True and value['binding']==dict(base=base,runId=RUN,target=target))
    rows=value['candidate']['selected'];require(type(rows) is list and 1<=len(rows)<=128)
    identities=[r['sha256'] for r in rows]
    require(all(type(x) is str and re.fullmatch('[a-f0-9]{64}',x) for x in identities) and len(set(identities))==len(identities))
    return len(rows)
def pair_attempt_count(slot):
    value=pair_read(ROOT+'/fs/'+slot+'-closure/closure.json',0o400,1048576)
    selected=pair_read(ROOT+'/fs/'+slot+'-metadata-retained/result.json',0o444,1048576)['candidate']['selected']
    proof=value['acquired']['attemptProof'];require(set(proof)=={'version','attempts'} and type(proof['version']) is int and proof['version']==1)
    rows=proof['attempts'];require(type(rows) is list and len(selected)<=len(rows)<=2*len(selected))
    require({a['digest'] for a in value['acquired']['artifacts']}=={a['sha256'] for a in selected})
    pos=0
    for index,artifact in enumerate(value['acquired']['artifacts']):
        require(index<len(selected) and artifact['kind']=='deb')
        for ordinal in (1,2):
            require(pos<len(rows));row=rows[pos];pos+=1
            require(set(row)=={'index','kind','digest','ordinal','outcome'} and type(row['index']) is int and type(row['ordinal']) is int)
            require(row['index']==index and row['kind']=='deb' and row['digest']==artifact['digest'] and row['ordinal']==ordinal)
            if row['outcome']=='verified':break
            require(ordinal==1 and row['outcome']=='retired-pre-response-reset')
        else:require(False)
    require(len(value['acquired']['artifacts'])==len(selected) and pos==len(rows))
    return pos
def pair_advance(sequence):
    authority();old,counts,before=pair_observe();require(old['sequence']==sequence-1)
    rejected=pair_worker_rejections(before)
    previous=pair_worker_rejections(json.loads(read(ROOT+'/fs/pair.credit.'+str(old['sequence'])+'.ack'))['after']) if old['sequence'] else dict(adapter=0,connector=0)
    require(all(rejected[mode]>=previous[mode] for mode in previous))
    used={mode:counts[mode]-old['starts'][mode] for mode in counts}
    # Base/index overhead may hit the unchanged four-worker gate. Those
    # pre-Budget rejections consume no credit, but remain bounded evidence.
    # Only the existing privately branded retry can add an artifact attempt.
    if old['sequence'] in (1,3):
        attempts=pair_attempt_count('system' if old['sequence']==1 else 'policy')
        require(all(n==attempts and old['artifactCount']<=n<=old['quota'] for n in used.values()) and rejected==previous)
    quota=pair_candidate('system' if sequence==1 else 'policy') if sequence in (1,3) else 32 if sequence==2 else 0
    n=quota if sequence in (1,3) else 0
    allocation=old['allocation']+quota
    if n:quota=min(2*n,allocation-max(counts.values()));require(quota>=n)
    row=dict(version=1,policy=PAIR_POLICY,runId=RUN,sequence=sequence,phase=PAIR_PHASES[sequence],allocation=allocation,starts=counts,quota=quota,artifactCount=n)
    pair_publish(row)
    after,current,ack=pair_observe();require(after==row and current==counts and pair_worker_rejections(ack)==rejected)
    proof=dict(version=1,policy=PAIR_POLICY,runId=RUN,before=before,after=ack)
    save('pair.credit.'+str(sequence)+'.ack',proof)
    fd=os.open(ROOT+'/fs',os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    print(json.dumps(proof,separators=(',',':')),flush=True)
def pair_system_reserve():pair_advance(1)
def pair_policy_overhead():pair_advance(2)
def pair_policy_reserve():pair_advance(3)
def pair_seal():pair_advance(4)
`;
function pairChild(source){
 source=replaceOnce(source,'def worker(client):','def worker(client,connection):');
 source=replaceOnce(source,"records.append({'host':host,'status':status})","records.append({'host':host,'status':status,'connection':connection})");
 source=replaceOnce(source,'target=worker,args=(client,),','target=worker,args=(client,budget.connections),');
 let result=replaceOnce(source,'class Budget:',PAIR_CHILD+'\nclass Budget:');
 result=replaceOnce(result,'self.lock=threading.Lock(); self.total=0;','self.lock=threading.RLock(); self.pair_credit=None; self.pair_failed=False; self.total=0;');
 result=replaceOnce(result,"            if self.connections>=32: raise Denied('connections')",
  "            row=pair_refresh(self)\n            if self.connections>=320 or self.connections-row['starts'][TRANSPORT_MODE]>=row['quota']: raise Denied('connections')");
 result=replaceOnce(result,'stop=threading.Event();budget=Budget();gate=',
  'global PAIR_BUDGET\n    stop=threading.Event();budget=Budget();PAIR_BUDGET=budget;pair_refresh(budget);gate=');
 result=replaceOnce(result,'activeWorkers=threading.active_count()-1,','activeWorkers=threading.active_count()-1,pairBudget=pair_budget_snapshot(),');
 return result;
}
const LEASE_PY=String.raw`import os,sys,stat,json,time,re
ROOT,RUN,OP=sys.argv[1:]
def require(v):
 if not v:raise RuntimeError('SYSTEM_LEASE_UNPROVEN')
require(re.fullmatch('[a-f0-9]{32}',RUN) and ROOT=='/var/tmp/dvaia-v23-build-'+RUN and os.path.realpath(ROOT)==ROOT)
s=os.lstat(ROOT);require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700)
def read(name):
 fd=os.open(ROOT+'/'+name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096)
  b=os.read(fd,4097);require(len(b)==s.st_size);return b.decode('ascii')
 finally:os.close(fd)
def save(name,value):
 fd=os.open(ROOT+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  b=value.encode('ascii')
  while b:
   n=os.write(fd,b);require(n>0);b=b[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
TOTAL=3636000
TARGET='original-v24-system-total-lease-v1'
if OP=='create':
 start=time.monotonic_ns()//1000000
 save('system-lease.json',json.dumps(dict(version=1,target=TARGET,runId=RUN,clock='linux-monotonic-ms',startedAtMs=start,expiresAtMs=start+TOTAL),sort_keys=True,separators=(',',':')))
else:
 row=json.loads(read('system-lease.json'))
 require(type(row) is dict and set(row)=={'version','target','runId','clock','startedAtMs','expiresAtMs'})
 require(type(row['version']) is int and row['version']==1 and row['target']==TARGET and row['runId']==RUN and row['clock']=='linux-monotonic-ms')
 require(type(row['startedAtMs']) is int and row['startedAtMs']>=0 and type(row['expiresAtMs']) is int and row['expiresAtMs']==row['startedAtMs']+TOTAL)
 now=time.monotonic_ns()//1000000;require(now>=row['startedAtMs'])
 if OP=='claim':
  left=row['expiresAtMs']-now;require(1000<left<=TOTAL)
  # The absolute record remains the authority. Relative sleep is only a passive
  # holder; no operation may gain time from scheduling or rereading this value.
  value=format((left-1)/1000,'.3f');save('system-holder.seconds',value);print(value,end='')
 elif OP=='read':
  value=read('system-holder.seconds');require(re.fullmatch('[1-9][0-9]*\.[0-9]{3}',value) and 0<float(value)<=TOTAL/1000)
  print(value,end='')
 elif OP=='active':
  require(now<row['expiresAtMs']);print(row['expiresAtMs'],end='')
 else:require(False)
`;
function replaceOnce(source,from,to){
 if(source.split(from).length!==2)throw fail('SYSTEM_DERIVATION_ANCHOR');
 return source.replace(from,to);
}
function deriveSource(source,paired=false){
 if(typeof paired!=='boolean')throw fail('SYSTEM_DERIVATION_TARGET');
 if(sha(source)!==SOURCE_SHA||lease.TOTAL_MS!==3636000)throw fail('SYSTEM_DERIVATION_SOURCE');
 const command=op=>'/usr/bin/python3 -I -S -B -c '+quote(LEASE_PY)+' "$root" "$nonce" '+op;
 // JSON-string expression is spliced inside the original JS template literal;
 // the emitted shell is fixed and source-bound, not caller-provided code.
 const expression=x=>'${'+JSON.stringify(x)+'}';
 const prepare="prepare:guard+`\nmkdir -m 700 \"$root\"\nprintf '%s' \"$nonce\" > \"$root/owner\"";
 let result=replaceOnce(source,prepare,prepare+'\n'+expression(command('create')));
 result=replaceOnce(result,'setsid /usr/bin/unshare --net -- /usr/bin/sleep 900',
  expression('holder_seconds=$('+command('claim')+')\n')+'setsid /usr/bin/unshare --net -- /usr/bin/sleep "$holder_seconds"');
 result=replaceOnce(result,'"$(printf \'/usr/bin/sleep\\\\n900\')"',
  expression('"$(printf \'%s\\n%s\' /usr/bin/sleep "$('+command('read')+')")"'));
 result=replaceOnce(result,"current['argv']==['/usr/bin/sleep','900']",
  "current['argv']==['/usr/bin/sleep',read(ROOT+'/system-holder.seconds')]");
 if(paired){
  result=replaceOnce(result,'HOST_LIMITS[${JSON.stringify(METADATA_BLOB_HOST)}]=134217728',
   'HOST_LIMITS[${JSON.stringify(METADATA_BLOB_HOST)}]='+PAIR_WIRE_POLICY.cloudfrontBytes);
  result=replaceOnce(result,'  // Loading the frozen definition supplies DNS_CODE for exact descendant checks;',
   "  if (metadataOnly) for (const mode of ['connector','adapter']) children[mode]=require('./ownedSystemBoundedDerivation')._internals.pairChild(children[mode]);\n  // Loading the frozen definition supplies DNS_CODE for exact descendant checks;");
  result=replaceOnce(result,"save('relay.directory',directory_record())\n    connector,row=launch",
   "save('relay.directory',directory_record())\n    pair_initialize()\n    connector,row=launch");
  result=replaceOnce(result,"        require(not os.listdir(RELAY))\n        require(time.monotonic()<end,'deadline_exhausted');os.rmdir(RELAY)",
   "        pair_remove(end)\n        require(not os.listdir(RELAY))\n        require(time.monotonic()<end,'deadline_exhausted');os.rmdir(RELAY)");
  result=replaceOnce(result,"save('relay.idle.intent',","pair_idle_save('intent',");
  // Success and failure retain the original separate result publication paths.
  if(result.split("save('relay.idle.result',").length!==3)throw fail('SYSTEM_DERIVATION_ANCHOR');
  result=result.replaceAll("save('relay.idle.result',","pair_idle_save('result',");
  result=replaceOnce(result,'+(transportOnly?checkpointProgram:\'\')+"\\nif __name__',
   "+(transportOnly?checkpointProgram:'')+(metadataOnly?require('./ownedSystemBoundedDerivation')._internals.pairController():'')+\"\\nif __name__");
  result=replaceOnce(result,'\"(\'start\',\'authority\',\'cleanup\',\'evidence\',\'checkpoint\',\'idle\')\"',
   '"(\'start\',\'authority\',\'cleanup\',\'evidence\',\'checkpoint\',\'idle\',\'pair_system_reserve\',\'pair_policy_overhead\',\'pair_policy_reserve\',\'pair_seal\')"');
  result=replaceOnce(result,"case \"$1\" in authority|cleanup|evidence|checkpoint|idle)",
   "case \"$1\" in authority|cleanup|evidence|checkpoint|idle|pair_system_reserve|pair_policy_overhead|pair_policy_reserve|pair_seal)");
  result=replaceOnce(result,"names=['relay.idle.intent','relay.idle.result','relay.intent'",
   "names=['pair.credit.0.intent','pair.credit.1.intent','pair.credit.1.ack','pair.credit.2.intent','pair.credit.2.ack','pair.credit.3.intent','pair.credit.3.ack','pair.credit.4.intent','pair.credit.4.ack','pair.idle.0.intent','pair.idle.0.result','pair.idle.2.intent','pair.idle.2.result','relay.idle.intent','relay.idle.result','relay.intent'");
 }
 return result;
}
function pairController(){
 const {TARGETS}=require('./ownedPolicySystemBuild');
 return '\nPAIR_BASES='+JSON.stringify({system:TARGETS['v24-system'].base,policy:TARGETS['v24-policy'].base})+'\n'+PAIR_CONTROLLER;
}
async function loadSystemBounded(paired=false){
 if(typeof paired!=='boolean')throw fail('SYSTEM_DERIVATION_TARGET');
 const filename=path.join(__dirname,'ownedMcpBoundedBuild.js');
 if(await fs.realpath(filename)!==filename)throw fail('SYSTEM_DERIVATION_PATH');
 const fd=await fs.open(filename,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);let source;
 try{
  const before=await fd.stat();if(!before.isFile()||before.nlink!==1||before.size>1024**2)throw fail('SYSTEM_DERIVATION_FILE');
  source=await fd.readFile('utf8');const after=await fd.stat();
  if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw fail('SYSTEM_DERIVATION_CHANGED');
 }finally{await fd.close();}
 const text=deriveSource(source,paired),derived=new Module(filename,module);
 derived.filename=filename;derived.paths=Module._nodeModulePaths(__dirname);derived._compile(text,filename);
 const bounded=paired?Object.freeze({specification:derived.exports.specification,_internals:Object.freeze({
  systemMetadataQualificationPlan:derived.exports._internals.systemMetadataQualificationPlan,
  policyRendererMetadataQualificationPlan:derived.exports._internals.policyRendererMetadataQualificationPlan})}):derived.exports;
 return Object.freeze({bounded,sourceSha256:SOURCE_SHA,derivedSha256:sha(text),leaseTarget:lease.TARGET,totalMs:lease.TOTAL_MS,
  ...(paired?{pairPolicy:PAIR_POLICY,pairWirePolicy:PAIR_WIRE_POLICY}:{} )});
}
module.exports={loadSystemBounded,SOURCE_SHA,PAIR_POLICY,PAIR_WIRE_POLICY,_internals:{deriveSource,replaceOnce,LEASE_PY,PAIR_COMMON,PAIR_CHILD,PAIR_CONTROLLER,pairChild,pairController}};
