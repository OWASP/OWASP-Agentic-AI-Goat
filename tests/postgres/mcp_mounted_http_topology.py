"""Main-only MCP topology helper. Import is inert; commands/deadlines are parent-owned.

No source build/copy, process supervisor, credentials in public receipts, or default
Docker/SSH discovery. Caller must independently admit runtime/build/SSH identity.
"""
import hashlib
import re
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER

SHA = re.compile(r'^[a-f0-9]{64}$')

IMAGE_DECLARED_PORTS={
 'sha256:09c27624ef733fbec300b07edee2ac8c0972dbcaf404b8849fbdeb1babb3664d':{'8090/tcp'},
 'sha256:c17a5db3bacea934909a58d32a5bdefac88956e58603cefffc239c7e88c672c6':{'8090/tcp'},
 'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365':{'1025/tcp','1110/tcp','8025/tcp'},
}

def resource_plan(nonce, runner_image, mailpit_image, cli_template, http_template, *, cohort="mcp-mounted-http"):
    if cohort not in ("mcp-mounted-http", "codebot-current-representative", "codebot-current-full-six", "codebot-current-clean-fixed"):raise ValueError("Closed topology cohort")
    if not re.fullmatch(r'[a-f0-9]{32}', nonce):
        raise ValueError('Exact owner nonce required')
    if any(not re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in ((runner_image, mailpit_image) if cohort=='mcp-mounted-http' else (runner_image,))):
        raise ValueError('Immutable local images required')
    if cohort in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') and (mailpit_image is not None or http_template is not None):raise ValueError('CodeBot owns only CLI topology')
    prefix='owasp-ai-goat-mcp-mounted-' if cohort=='mcp-mounted-http' else 'owasp-ai-goat-codebot-current-'
    result = {'owner': nonce, 'directory': '/tmp/'+prefix+nonce, 'resources': {}}
    resources=[('cli',runner_image,[8090],cli_template)]
    if cohort=='mcp-mounted-http':resources += [('http',runner_image,[8091],http_template),('mail',mailpit_image,[1025,8025],None)]
    for kind, image, ports, template in resources:
        name=prefix+kind+'-'+nonce
        value={'kind':kind,'name':name,'image':image,'ports':ports,'labels':{'owasp-ai-goat.qualification':cohort,'owasp-ai-goat.owner':nonce,'owasp-ai-goat.resource':kind}}
        if template is not None:
            if not isinstance(template,bytes) or template.count(b'@@SUPERVISOR_PROFILE@@')<1:
                raise ValueError('Exact profile template required')
            profile=('owasp-ai-goat-mcp-sandbox-' if kind=='cli' else 'owasp-ai-goat-owned-http-')+nonce[:12]
            policy=template.replace(b'@@SUPERVISOR_PROFILE@@',profile.encode())
            if b'@@' in policy:raise ValueError('Unresolved profile template')
            value.update(profile=profile,profileNames=[profile,profile+'//bwrap'],policy=policy,policySha256=hashlib.sha256(policy).hexdigest())
        result['resources'][kind]=value
    return result

def profile_members(lines, profile):
    """Exact parent or nested child, never a lexical prefix sibling."""
    return [line for line in lines if line.split(' (',1)[0]==profile or line.split(' (',1)[0].startswith(profile+'//')]

def layout_diagnostic(row, spec):
    """Closed metadata only: never serialize Config.Env, command, errors or logs."""
    state=row.get('State') or {};result={'kind':spec['kind'],'state':{}}
    if state.get('Status') in ('created','running','paused','restarting','removing','exited','dead'):result['state']['status']=state['Status']
    for key in ('Running','Paused','Restarting','OOMKilled','Dead'):
        if type(state.get(key)) is bool:result['state'][key]=state[key]
    for key in ('Pid','ExitCode'):
        if type(state.get(key)) is int and -1<=state[key]<=2147483647:result['state'][key]=state[key]
    for label,value in [('ports',(row.get('NetworkSettings')or{}).get('Ports')),('requestedBindings',(row.get('HostConfig')or{}).get('PortBindings'))]:
        output={}
        if isinstance(value,dict):
            for port,bindings in list(value.items())[:16]:
                if not isinstance(port,str) or not re.fullmatch(r'[0-9]{1,5}/(?:tcp|udp)',port):continue
                if bindings is None:output[port]=None;continue
                if isinstance(bindings,list):output[port]=[{'HostIp':x.get('HostIp') if x.get('HostIp') in ('127.0.0.1','0.0.0.0','::','::1','') else 'other','HostPort':x.get('HostPort') if isinstance(x.get('HostPort'),str) and re.fullmatch(r'[0-9]{0,5}',x['HostPort']) else 'invalid'}for x in bindings[:4] if isinstance(x,dict)]
        result[label]=output
    return result

def record_and_validate_layout(row,spec,record):
    record('topology-container-layout',layout_diagnostic(row,spec))
    return validate_layout(row,spec)

def validate_layout(row, spec):
    host=row['HostConfig'];ports=row['NetworkSettings']['Ports']
    if (host.get('Memory')!=536870912 or host.get('NanoCpus')!=1000000000 or host.get('PidsLimit')!=128 or host.get('NetworkMode') not in ('default','bridge') or host.get('PidMode') not in ('',None) or host.get('IpcMode') not in ('private',None)):
        raise RuntimeError('Resource or namespace mismatch')
    expected_tmpfs={'/sandbox':'rw,uid=10001,gid=10001,mode=0700'} if 'profile' in spec else {'/tmp':'rw,noexec,nosuid,size=16777216'}
    if host.get('Tmpfs')!=expected_tmpfs:raise RuntimeError('Private storage mismatch')
    if 'profile' in spec and (row['Config'].get('User')!='10001:10001' or row['Config'].get('Entrypoint')!=['node'] or row['Config'].get('Cmd')!=['/app/index.js' if spec['kind']=='cli' else '/app/owned-http/service.js']):raise RuntimeError('Runner launch identity mismatch')
    if spec['kind']=='mail' and host.get('ReadonlyRootfs') is not True:raise RuntimeError('Mail filesystem mismatch')
    if host.get('Privileged') is not False or host.get('CapAdd') not in (None,[]):raise RuntimeError('Unexpected privilege')
    if any(m.get('Type')!='tmpfs' for m in row.get('Mounts',[])):raise RuntimeError('Unexpected mount')
    expected_security=['seccomp=unconfined','apparmor='+spec['profile']] if 'profile' in spec else ['no-new-privileges']
    if host.get('SecurityOpt')!=expected_security:raise RuntimeError('Security profile mismatch')
    expected_ports={str(p)+'/tcp' for p in spec['ports']}
    extras=set(ports)-expected_ports
    declared=IMAGE_DECLARED_PORTS.get(spec['image'],set())
    permitted_unbound=declared-expected_ports
    if extras:
        if row.get('Image')!=spec['image'] or not extras<=permitted_unbound:raise RuntimeError('Unexpected port')
        for extra in extras:
            if ports[extra] is not None or extra not in row['Config'].get('ExposedPorts',{}) or host.get('PortBindings',{}).get(extra) is not None:raise RuntimeError('Unexpected port')
    if not expected_ports<=set(ports):raise RuntimeError('Unexpected port')
    output={}
    for p in spec['ports']:
        bindings=ports[str(p)+'/tcp']
        if len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1':raise RuntimeError('Nonloopback port')
        actual=int(bindings[0]['HostPort'])
        if not 1<=actual<=65535:raise RuntimeError('Invalid port')
        output[p]=actual
    return output

class OwnedMcpTopology:
    def __init__(self, *, plan, docker, remote, record, remaining, daemon_id, remote_binding, evidence_root):
        # binding is a parent's verified strict-host-key/SSH-runtime receipt.
        if type(remote_binding.get('uid')) is not int or remote_binding['uid']<0 or remote_binding.get('daemonId')!=daemon_id or remote_binding.get('strictHostKeyChecking') is not True or remote_binding.get('noHostAuthenticationForLocalhost') is not False or not SHA.fullmatch(remote_binding.get('knownHostsSha256','')) or not SHA.fullmatch(remote_binding.get('resolvedConfigurationSha256','')):
            raise RuntimeError('Bound strict SSH identity required')
        from pathlib import Path
        self.evidence_root=Path(evidence_root)
        if not self.evidence_root.is_absolute() or self.evidence_root.resolve()!=self.evidence_root:raise RuntimeError('Exact evidence root required')
        self.plan,self.docker,self.remote,self.record,self.remaining=plan,docker,remote,record,remaining
        self.remote_uid=remote_binding['uid'];self.daemon_id=daemon_id;self.attempted={};self.ids={};self.remote_attempted=False
    def call(self, command, args, **kwargs):
        timeout=min(20,self.remaining())
        if timeout<=0:raise TimeoutError('Parent deadline expired')
        result=command(args,timeout=timeout,**kwargs)
        if result.returncode:raise RuntimeError('Owned topology command failed')
        return result
    def docker_command(self,args):
        timeout=min(20,self.remaining())
        if timeout<=0:raise TimeoutError('Parent deadline expired')
        return self.docker(args,timeout=timeout)
    def profile_kinds(self):return tuple(k for k in ('cli','http') if k in self.plan['resources'])
    def profiles(self):return self.call(self.remote,['sudo','cat','/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    def remote_metadata(self, file, kind, mode):
        canonical=self.call(self.remote,['readlink','-f','--',file]).stdout.strip()
        value=self.call(self.remote,['stat','-c','%F|%a|%u|%h|%i|%s|%Y|%Z','--',file]).stdout.strip()
        fields=value.split('|')
        if canonical!=file or len(fields)!=8 or fields[:3]!=[kind,mode,str(self.remote_uid)] or (kind=='regular file' and fields[3]!='1'):
            raise RuntimeError('Remote metadata mismatch')
        return value
    def verify_remote(self):
        directory=self.plan['directory']
        self.remote_metadata(directory,'directory','700')
        for name,expected in [('owner',self.plan['owner']+'\n')]+[(kind+'.apparmor',self.plan['resources'][kind]['policy'].decode()) for kind in self.profile_kinds()]:
            file=directory+'/'+name;before=self.remote_metadata(file,'regular file','600')
            content=self.call(self.remote,['cat','--',file]).stdout
            if content!=expected or self.remote_metadata(file,'regular file','600')!=before:raise RuntimeError('Remote ownership/policy mismatch')
    def prepare(self):
        verify_daemon(self.docker_command,self.daemon_id)
        remote_id=self.call(self.remote,['sudo','docker','info','--format','{{.ID}}']).stdout.strip()
        if remote_id!=self.daemon_id:raise RuntimeError('SSH/Docker kernel identity mismatch')
        for image in {x['image'] for x in self.plan['resources'].values()}:verify_image(self.docker_command,image)
        lines=self.profiles()
        for kind in self.profile_kinds():
            if profile_members(lines,self.plan['resources'][kind]['profile']):raise RuntimeError('Profile collision')
        self.call(self.remote,['test','!','-e',self.plan['directory']])
        self.record('topology-remote-intent',{'directory':self.plan['directory'],'owner':self.plan['owner'],'creationAttempted':True,'profiles':{k:{x:v for x,v in self.plan['resources'][k].items() if x in ('profile','profileNames','policySha256')} for k in self.profile_kinds()}})
        self.remote_attempted=True
        self.call(self.remote,['mkdir','-m','0700','--',self.plan['directory']])
        self.call(self.remote,['tee',self.plan['directory']+'/owner'],input=self.plan['owner']+'\n')
        self.call(self.remote,['chmod','600','--',self.plan['directory']+'/owner'])
        self.record('topology-owner-published',{'directory':self.plan['directory']})
        for kind in self.profile_kinds():
            self.call(self.remote,['tee',self.plan['directory']+'/'+kind+'.apparmor'],input=self.plan['resources'][kind]['policy'].decode())
            self.call(self.remote,['chmod','600','--',self.plan['directory']+'/'+kind+'.apparmor'])
            self.record('topology-policy-published',{'kind':kind,'policySha256':self.plan['resources'][kind]['policySha256']})
        self.verify_remote()
        for kind in self.profile_kinds():
            self.record('topology-profile-load-intent',{'kind':kind,'profile':self.plan['resources'][kind]['profile']})
            self.call(self.remote,['sudo','apparmor_parser','-r',self.plan['directory']+'/'+kind+'.apparmor'])
            spec=self.plan['resources'][kind]
            if set(profile_members(self.profiles(),spec['profile']))!={x+' (enforce)' for x in spec['profileNames']}:raise RuntimeError('Exact profile tree not enforcing')
    def launch(self, kind, env_file):
        # Parent writes/reviews a 0600 file under its admitted owned evidence root.
        # Only its path crosses argv; raw synthetic tokens never enter journal.
        import os,stat
        if kind not in self.plan['resources']:raise ValueError('Closed resource kind')
        from pathlib import Path
        file=Path(env_file)
        if file!=self.evidence_root/(kind+'.env') or file.resolve()!=file:raise RuntimeError('Exact owned env file required')
        st=os.lstat(env_file)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600:raise RuntimeError('Private env file required')
        spec=self.plan['resources'][kind];verify_daemon(self.docker_command,self.daemon_id)
        if kind in ('cli','http'):self.verify_remote()
        if inspect_owned(self.docker_command,name=spec['name'],labels=spec['labels'],image=spec['image']) is not None:raise RuntimeError('Container collision')
        self.record('topology-container-intent',{'kind':kind,'name':spec['name'],'image':spec['image'],'labels':spec['labels'],'creationAttempted':True});self.attempted[kind]=True
        args=['run','--detach','--pull','never','--name',spec['name']]
        for k,v in spec['labels'].items():args+=['--label',k+'='+v]
        args+=['--env-file',str(env_file),'--memory','512m','--cpus','1','--pids-limit','128']
        for p in spec['ports']:args+=['-p','127.0.0.1::'+str(p)]
        if kind in ('cli','http'):
            args+=['--user','10001:10001','--security-opt','seccomp=unconfined','--security-opt','apparmor='+spec['profile'],'--tmpfs','/sandbox:rw,uid=10001,gid=10001,mode=0700','--entrypoint','node',spec['image'],'/app/index.js' if kind=='cli' else '/app/owned-http/service.js']
        else:args+=['--read-only','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216',spec['image']]
        identifier=self.call(self.docker,args).stdout.strip()
        if not CONTAINER.fullmatch(identifier):raise RuntimeError('Missing container identity')
        self.ids[kind]=identifier;self.record('topology-container-created',{'kind':kind,'containerId':identifier})
        row=inspect_owned(self.docker_command,name=spec['name'],labels=spec['labels'],image=spec['image'],captured_id=identifier)
        return record_and_validate_layout(row,spec,self.record)
    def cleanup(self):
        # Parent switches remaining() to its independent cleanup deadline first.
        errors=[]
        for kind in ('http','cli','mail'):
            if not self.attempted.get(kind):continue
            spec=self.plan['resources'][kind]
            try:
                result=cleanup_owned(self.docker_command,daemon_id=self.daemon_id,name=spec['name'],labels=spec['labels'],image=spec['image'],captured_id=self.ids.get(kind))
                self.record('topology-container-cleanup',{'kind':kind,**result});self.attempted[kind]=False
            except BaseException as e:errors.append(e)
        if errors:raise BaseExceptionGroup('Topology cleanup unverified; profiles retained',errors)
        if not self.remote_attempted:return
        self.verify_remote()
        for kind in reversed(self.profile_kinds()):
            spec=self.plan['resources'][kind]
            if profile_members(self.profiles(),spec['profile']):self.call(self.remote,['sudo','apparmor_parser','-R',self.plan['directory']+'/'+kind+'.apparmor'])
            if profile_members(self.profiles(),spec['profile']):raise RuntimeError('Profile absence unverified')
        self.call(self.remote,['rm','--']+[self.plan['directory']+'/'+k+'.apparmor' for k in reversed(self.profile_kinds())]+[self.plan['directory']+'/owner'])
        self.call(self.remote,['rmdir','--',self.plan['directory']]);self.call(self.remote,['test','!','-e',self.plan['directory']]);self.remote_attempted=False
        self.record('topology-remote-cleanup',{'status':'absence_verified','directory':self.plan['directory']})
