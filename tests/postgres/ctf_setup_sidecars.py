"""Owned B-only sidecars. Importing performs no process or network work."""
import hashlib,json,os,re,secrets,subprocess
from pathlib import Path
from sql_nosql_docker_ownership import verify_image,inspect_owned,cleanup_owned
MAILPIT='sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
BASE='docker.io/library/node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def build_context(root):
    root=Path(root).resolve();dockerfile=root/'Dockerfile'
    # Current reviewed context has no ignore file. Do not guess Docker's glob dialect.
    if (root/'.dockerignore').exists() or (root/'Dockerfile.dockerignore').exists():raise RuntimeError('Unreviewed Docker ignore rules')
    selected={'Dockerfile'}
    for line in dockerfile.read_text().splitlines():
        if not line.startswith('COPY ') or '--from=' in line:continue
        for value in line.split()[1:-1]:
            p=root/value
            if not p.is_relative_to(root) or '..' in Path(value).parts:raise RuntimeError('Build source escapes context')
            if not p.exists():raise RuntimeError('Missing COPY input')
            selected.add(value)
            if p.is_dir():selected.update(str(x.relative_to(root)) for x in p.rglob('*'))
    for value in list(selected):
        for parent in Path(value).parents:
            if str(parent)!='.':selected.add(str(parent))
    result={}
    for value in sorted(selected):
        p=root/value
        # Closed no-link context avoids different Docker dereference semantics.
        if p.is_symlink():raise RuntimeError('Unreviewed build input symlink')
        result[value]={'mode':p.stat().st_mode&0o777,**({'directory':True} if p.is_dir() else {'sha256':sha(p)})}
    return {'base':BASE,'dockerignore':'absent; exact COPY inputs only','entries':result}
def validate_sidecar_args(args):
    names=['sandbox_image_id','ssh','scp','ssh_config','ssh_config_sha256','ssh_sha256','scp_sha256','ssh_host']
    if args.scenario!='ctf-populated':
        if any(getattr(args,x,None) for x in names):raise RuntimeError('Sidecars only admitted for B')
        return
    if any(not getattr(args,x,None) for x in names):raise RuntimeError('Exact B sidecar pins required')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',args.sandbox_image_id):raise RuntimeError('Sandbox image digest required')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',args.ssh_host):raise RuntimeError('Invalid SSH host alias')
    for name in ['ssh','scp','ssh_config']:
        p=Path(getattr(args,name))
        if not p.is_absolute() or p.is_symlink() or sha(p)!=getattr(args,name+'_sha256'):raise RuntimeError('Sidecar executable/config pin mismatch')
class OwnedSidecars:
    def __init__(self,args,source,evidence,owner,docker,record):
        if not re.fullmatch(r'[a-f0-9]{32}',owner):raise RuntimeError('Invalid owner nonce')
        self.args=args;self.source=Path(source);self.evidence=Path(evidence);self.owner=owner;self.docker=docker;self.record=record
        self.profile='owasp-ai-goat-mcp-sandbox-'+owner[:12];self.remote='/tmp/owasp-ai-goat-ctf-'+owner;self.labels={'owasp-ai-goat.test.owner':owner,'owasp-ai-goat.test.cohort':'ctf-setup-sidecars'}
        self.rows=[];self.remote_owned=False;self.profile_attempted=False
        self.state={'containers':self.rows,'profile':self.profile,'profileLoaded':False,'cleanupComplete':False}
    def remote_command(self,argv,input=None):
        # Every remote path/name is generated from the fixed hexadecimal owner.
        return subprocess.run([self.args.ssh,'-F',self.args.ssh_config,self.args.ssh_host,*argv],input=input,capture_output=True,text=True,timeout=20,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
    def checked(self,result):
        if result.returncode:raise RuntimeError('Owned sidecar operation failed')
        return result
    def start(self):
        verify_image(self.docker,self.args.sandbox_image_id);verify_image(self.docker,MAILPIT)
        if self.remote_command(['test','!','-e',self.remote]).returncode!=0:raise RuntimeError('Remote owner path occupied')
        probe=self.remote_command(['sudo','grep','-F',self.profile,'/sys/kernel/security/apparmor/profiles'])
        if probe.returncode!=1:raise RuntimeError('Profile absent observation unavailable')
        self.checked(self.remote_command(['mkdir','-m','0700',self.remote]));self.remote_owned=True
        self.checked(self.remote_command(['tee',self.remote+'/owner'],input=self.owner+'\n'))
        template=(self.source/'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').read_text()
        rendered=template.replace('@@SUPERVISOR_PROFILE@@',self.profile)
        if '@@' in rendered:raise RuntimeError('Unknown profile substitution')
        local=self.evidence/'sandbox.apparmor';local.write_text(rendered);local.chmod(0o600)
        self.checked(subprocess.run([self.args.scp,'-F',self.args.ssh_config,str(local),self.args.ssh_host+':'+self.remote+'/profile'],capture_output=True,text=True,timeout=20))
        self.checked(self.remote_command(['chmod','0600',self.remote+'/profile']))
        self.checked(self.remote_command(['sudo','apparmor_parser','--skip-kernel-load',self.remote+'/profile']))
        self.profile_attempted=True;self.record(self.state)
        self.checked(self.remote_command(['sudo','apparmor_parser','-r',self.remote+'/profile']))
        label=self.checked(self.remote_command(['sudo','grep','-F',self.profile,'/sys/kernel/security/apparmor/profiles'])).stdout
        if self.profile+' (enforce)' not in label:raise RuntimeError('Profile not enforcing')
        self.state['profileLoaded']=True;self.state['profileSha256']=sha(local);self.record(self.state)
        token=secrets.token_urlsafe(48);envfile=self.evidence/'sandbox-private.env'
        fd=os.open(envfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:stream.write('MCP_OWNED_TARGETS_ENABLED=true\nMCP_OWNED_TARGET_TOKEN='+token+'\nMCP_OWNED_TARGET_APPARMOR_PROFILE='+self.profile+'\n');stream.flush();os.fsync(stream.fileno())
        ports={}
        for kind,image,extra,specs in [
          ('mail',MAILPIT,['--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216'],['1025','8025']),
          ('sandbox',self.args.sandbox_image_id,['--security-opt','seccomp=unconfined','--security-opt','apparmor='+self.profile,'--tmpfs','/sandbox:rw,size=268435456,uid=10001,gid=10001,mode=0700','--env-file',str(envfile)],['8090'])]:
            name='owasp-ai-goat-ctf-'+kind+'-'+self.owner[:12]
            if inspect_owned(self.docker,name=name,labels=self.labels,image=image) is not None:raise RuntimeError('Sidecar name occupied')
            row={'name':name,'image':image,'id':None};self.rows.append(row);self.record(self.state)
            cmd=['run','--detach','--pull','never','--name',name,'--memory','512m','--cpus','1','--pids-limit','128',*sum((['--label',k+'='+v] for k,v in self.labels.items()),[]),*extra,*sum((['-p','127.0.0.1::'+p] for p in specs),[]),image]
            self.checked(self.docker(cmd));actual=inspect_owned(self.docker,name=name,labels=self.labels,image=image);row['id']=actual['Id'];self.record(self.state)
            host=actual['HostConfig']
            if actual['Mounts'] or host['Memory']!=536870912 or host['NanoCpus']!=1000000000 or host['PidsLimit']!=128:raise RuntimeError('Sidecar resource layout mismatch')
            if kind=='sandbox' and ('apparmor='+self.profile not in host['SecurityOpt'] or 'seccomp=unconfined' not in host['SecurityOpt']):raise RuntimeError('Sidecar isolation options mismatch')
            for p in specs:
                binding=actual['NetworkSettings']['Ports'][p+'/tcp']
                if len(binding)!=1 or binding[0]['HostIp']!='127.0.0.1':raise RuntimeError('Sidecar not loopback bound')
                ports[p]=binding[0]['HostPort']
        return {'MCP_OWNED_TARGET_URL':'http://127.0.0.1:'+ports['8090'],'MCP_OWNED_TARGET_TOKEN':token,'MAILPIT_API_URL':'http://127.0.0.1:'+ports['8025'],'MAILPIT_SMTP_HOST':'127.0.0.1','MAILPIT_SMTP_PORT':ports['1025']}
    def cleanup(self,within):
        failures=[]
        for row in reversed(self.rows):
            try:within(lambda:cleanup_owned(self.docker,daemon_id=self.args.docker_daemon,name=row['name'],labels=self.labels,image=row['image'],captured_id=row['id']))
            except BaseException:failures.append('container_cleanup_unavailable')
        if self.remote_owned and not failures:
            try:
                def policy_cleanup():
                    if self.checked(self.remote_command(['cat',self.remote+'/owner'])).stdout!=self.owner+'\n':raise RuntimeError('Remote owner changed')
                    if self.profile_attempted:
                        self.checked(self.remote_command(['sudo','apparmor_parser','-R',self.remote+'/profile']))
                        if self.remote_command(['sudo','grep','-F',self.profile,'/sys/kernel/security/apparmor/profiles']).returncode!=1:raise RuntimeError('Profile remains')
                    self.checked(self.remote_command(['rm','-f',self.remote+'/profile',self.remote+'/owner']))
                    self.checked(self.remote_command(['rmdir',self.remote]))
                within(policy_cleanup)
            except BaseException:failures.append('profile_cleanup_unavailable')
        if self.remote_owned and failures:failures.append('profile_retained_until_containers_absent')
        self.state['cleanupComplete']=not failures;self.state['cleanupFailures']=failures;self.record(self.state)
        if failures:raise RuntimeError('Owned sidecar cleanup incomplete')
