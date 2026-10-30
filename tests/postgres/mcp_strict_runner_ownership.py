"""Injected-command strict runner lifecycle. No commands execute on import.

The caller supplies pinned Docker/SSH transports and an independently reviewed image
build receipt. This manager never builds, deletes a shared image, or changes sidecars.
"""
import hashlib
import json
import re
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER

SHA = re.compile(r'^[a-f0-9]{64}$')

def validate_build_receipt(receipt, *, image, context_sha256, template_sha256):
    expected = dict(version=1, imageId=image, contextSha256=context_sha256,
                    policyTemplateSha256=template_sha256, nodeVersion='v26.8.2')
    if type(receipt) is not dict or receipt != expected or type(receipt.get('version')) is not int:
        raise RuntimeError('Exact reviewed runner build receipt required')
    if not SHA.fullmatch(context_sha256) or not SHA.fullmatch(template_sha256):
        raise RuntimeError('Runner source hashes required')


def validate_runner_layout(row, profile):
    try:
        config = row['HostConfig']
        if (config['SecurityOpt'] != ['seccomp=unconfined', 'apparmor='+profile]
                or config['Tmpfs'] != {'/sandbox': 'rw,uid=10001,gid=10001,mode=0700'}
                or row['Mounts'] != [] or config.get('Privileged') is not False
                or config.get('CapAdd') not in (None, [])):
            raise ValueError()
        ports = row['NetworkSettings']['Ports']
        if set(ports) != {'8090/tcp'} or len(ports['8090/tcp']) != 1:
            raise ValueError()
        binding = ports['8090/tcp'][0];port = int(binding['HostPort'])
        if binding['HostIp'] != '127.0.0.1' or not 1 <= port <= 65535 or port == 8090:
            raise ValueError()
        return port
    except (ValueError, TypeError, KeyError):
        raise RuntimeError('Strict runner layout mismatch') from None


def validate_health(health, profile):
    expected = dict(ready=True, version='mcp-owned-target-http.v1', isolation='bwrap-seccomp-v1',
                    supervisorProfile=profile+' (enforce)',
                    protectedStateCapability='mcp-owned-protected-state-transition.v2',
                    observedActionCapability='mcp-owned-observed-action.v1',
                    packageInstallCapability='mcp-owned-package-install.v1',
                    ticketReadCapability='mcp-owned-ticket-read.v2')
    if health != expected:
        raise RuntimeError('Strict runner readiness mismatch')


class StrictRunner:
    def __init__(self, *, docker, remote, record, daemon_id, image, nonce, uid, policy,
                 policy_sha256, build_receipt, context_sha256, template_sha256, template):
        if not re.fullmatch(r'[a-f0-9]{32}', nonce) or type(uid) is not int or uid < 0:
            raise RuntimeError('Owned runner identity required')
        if not isinstance(policy, bytes) or hashlib.sha256(policy).hexdigest() != policy_sha256:
            raise RuntimeError('Rendered policy hash mismatch')
        validate_build_receipt(build_receipt, image=image, context_sha256=context_sha256, template_sha256=template_sha256)
        profile = 'owasp-ai-goat-mcp-sandbox-'+nonce[:12]
        if (not isinstance(template, bytes) or hashlib.sha256(template).hexdigest() != template_sha256
                or b'@@SUPERVISOR_PROFILE@@' not in template):
            raise RuntimeError('Exact reviewed policy template required')
        rendered = template.replace(b'@@SUPERVISOR_PROFILE@@', profile.encode('ascii'))
        if b'@@' in rendered or rendered != policy:
            raise RuntimeError('Policy must equal exact reviewed template/profile rendering')
        self.docker, self.remote, self.record = docker, remote, record
        self.daemon_id, self.image = daemon_id, image
        self.profile = profile
        self.directory = '/tmp/'+self.profile
        self.name = 'owasp-ai-goat-mcp-connected-runner-'+nonce
        self.labels = {'owasp-ai-goat.qualification':'mcp_connected_baseline','owasp-ai-goat.run-nonce':nonce,'owasp-ai-goat.owner-uid':str(uid)}
        self.marker = nonce+'\n';self.policy = policy;self.policy_sha256 = policy_sha256
        self.remote_intended = False;self.container_intended = False;self.captured = None

    @staticmethod
    def checked(result):
        if result.returncode:
            raise RuntimeError('Owned runner operation failed')
        return result

    def profiles(self):
        result = self.checked(self.remote(['sudo','cat','/sys/kernel/security/apparmor/profiles']))
        return result.stdout.splitlines()

    def prepare_policy(self):
        verify_daemon(self.docker,self.daemon_id)
        verify_image(self.docker,self.image)
        if any(line.startswith(self.profile+' ') for line in self.profiles()):
            raise RuntimeError('Profile already exists')
        absent = self.remote(['test','!','-e',self.directory])
        if absent.returncode != 0:
            raise RuntimeError('Remote ownership directory already exists')
        self.record('runner-policy-intent',dict(profile=self.profile,directory=self.directory,policySha256=self.policy_sha256))
        self.remote_intended = True
        self.checked(self.remote(['mkdir','-m','0700','--',self.directory]))
        self.checked(self.remote(['tee',self.directory+'/owner'],input=self.marker))
        self.checked(self.remote(['tee',self.directory+'/policy.apparmor'],input=self.policy.decode('utf8')))
        self.verify_remote()
        self.checked(self.remote(['sudo','apparmor_parser','-r',self.directory+'/policy.apparmor']))
        if self.profile+' (enforce)' not in self.profiles():
            raise RuntimeError('Owned profile not enforced')

    def verify_remote(self):
        marker = self.checked(self.remote(['cat','--',self.directory+'/owner'])).stdout
        policy = self.checked(self.remote(['cat','--',self.directory+'/policy.apparmor'])).stdout
        if marker != self.marker or hashlib.sha256(policy.encode()).hexdigest() != self.policy_sha256:
            raise RuntimeError('Remote ownership/policy mismatch')

    def launch(self, token):
        if not self.remote_intended or self.profile+' (enforce)' not in self.profiles():
            raise RuntimeError('Prepare enforced policy first')
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{48,128}',token):
            raise RuntimeError('Explicit synthetic runner token required')
        verify_daemon(self.docker,self.daemon_id);self.verify_remote()
        self.record('runner-container-intent',dict(name=self.name,labels=self.labels,imageId=self.image))
        self.container_intended = True
        labels = [arg for key,value in self.labels.items() for arg in ['--label',key+'='+value]]
        result = self.checked(self.docker(['run','--detach','--pull','never','--name',self.name]+labels+[
            '--security-opt','seccomp=unconfined','--security-opt','apparmor='+self.profile,
            '--tmpfs','/sandbox:rw,uid=10001,gid=10001,mode=0700',
            '-e','MCP_OWNED_TARGETS_ENABLED=true','-e','MCP_OWNED_TARGET_TOKEN='+token,
            '-e','MCP_OWNED_TARGET_APPARMOR_PROFILE='+self.profile,'-p','127.0.0.1::8090',self.image]))
        if not CONTAINER.fullmatch(result.stdout.strip()):
            raise RuntimeError('Runner ID missing')
        self.captured = result.stdout.strip()
        row = inspect_owned(self.docker,name=self.name,labels=self.labels,image=self.image,captured_id=self.captured)
        port = validate_runner_layout(row,self.profile)
        self.record('runner-created',dict(containerId=self.captured,port=port,profile=self.profile))
        return port

    def cleanup(self):
        # Never unload confinement while a possibly live runner remains.
        if self.container_intended:
            try:
                result = cleanup_owned(self.docker,daemon_id=self.daemon_id,name=self.name,
                                       labels=self.labels,image=self.image,captured_id=self.captured)
            except BaseException:
                self.record('runner-cleanup',dict(status='cleanup_unverified',containerId=self.captured))
                raise
            self.record('runner-cleanup',result)
            self.container_intended = False
        if self.remote_intended:
            self.verify_remote()
            if any(line.startswith(self.profile+' ') for line in self.profiles()):
                self.checked(self.remote(['sudo','apparmor_parser','-R',self.directory+'/policy.apparmor']))
            if any(line.startswith(self.profile+' ') for line in self.profiles()):
                raise RuntimeError('Profile absence unverified')
            self.checked(self.remote(['rm','--',self.directory+'/policy.apparmor',self.directory+'/owner']))
            self.checked(self.remote(['rmdir','--',self.directory]))
            self.checked(self.remote(['test','!','-e',self.directory]))
            self.remote_intended = False
            self.record('runner-policy-cleanup',dict(status='absence_verified',profile=self.profile,directory=self.directory))
