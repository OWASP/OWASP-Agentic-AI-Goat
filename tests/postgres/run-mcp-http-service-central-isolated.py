import subprocess,uuid,json,pathlib,hashlib,shlex,os,time,urllib.request
root=pathlib.Path('/Users/averma5/Documents/github/OWASP Agentic AI GOAT');nonce=uuid.uuid4().hex[:12];name='owasp-ai-goat-owned-http-'+nonce;profile=name;remote='/tmp/'+name
D=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'];S=['/usr/bin/ssh','-F',str(pathlib.Path.home()/'.colima/_lima/colima-owasp-ai-goat-pg-verify/ssh.config'),'lima-colima-owasp-ai-goat-pg-verify'];image='sha256:ba0128a2a64f17b1fdf4158979b0c401ba74c0fa8229b61da30f40bc2f9030e4'
def ssh(args,**kw):return subprocess.run(S+[shlex.join(args)],text=True,capture_output=True,timeout=30,**kw)
def checked(r):
 if r.returncode:raise RuntimeError(r.stderr)
 return r.stdout
base=(root/'sidecars/sandbox-runner/owned-http/http-profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',profile)
# Template already contains HTTP setup capability.
policy=base
source=(root/'tests/fixtures/mcpOwnedHttpServiceGate.cjs').read_text().replace('if(require.main===module)','if(true)').replace("'owasp-ai-goat-mcp-sandbox (enforce)'",repr(profile+' (enforce)')).replace("'--cap-add','CAP_SETPCAP'","'--cap-add','CAP_SETPCAP','--cap-add','CAP_NET_BIND_SERVICE'")
# Existingstore readiness expects explicit profile parameter via environment.
result={'profile':profile,'policySha256':hashlib.sha256(policy.encode()).hexdigest(),'image':image};created=False;loaded=False
try:
 labels=checked(ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']));assert not any(line.startswith(profile+' ') or line.startswith(profile+'//') for line in labels.splitlines())
 checked(ssh(['test','!','-e',remote]));checked(ssh(['mkdir','-m','0700',remote]));created=True
 checked(ssh(['tee',remote+'/owner'],input=nonce+'\n'));checked(ssh(['tee',remote+'/policy'],input=policy));checked(ssh(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy']));checked(ssh(['sudo','apparmor_parser','-r',remote+'/policy']));loaded=True
 labels=checked(ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']));result['enforcingProfiles']=[line for line in labels.splitlines() if line.startswith(profile)]
 token=uuid.uuid4().hex+uuid.uuid4().hex
 cmd=D+['run','--detach','--rm','--name',name,'--label','owasp-ai-goat.owner='+nonce,'--user','10001:10001','--security-opt','apparmor='+profile,'--security-opt','seccomp=unconfined','-p','127.0.0.1::8091','--env','MCP_OWNED_HTTP_TOKEN='+token,'--env','MCP_OWNED_HTTP_ROOT=/tmp/owned-http-state','--env','MCP_OWNED_TARGET_APPARMOR_PROFILE='+profile,'--entrypoint','node',image,'/app/owned-http/service.js']
 checked(subprocess.run(cmd,text=True,capture_output=True,timeout=30))
 port=checked(subprocess.run(D+['port',name,'8091/tcp'],text=True,capture_output=True,timeout=10)).strip().rsplit(':',1)[1]
 base='http://127.0.0.1:'+port
 for _ in range(60):
  try:
   request=urllib.request.Request(base+'/owned-http/readiness',data=b'{}',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
   with urllib.request.urlopen(request,timeout=10) as response:ready=json.load(response)
   if ready.get('ready'):break
  except Exception:time.sleep(.2)
 else:raise RuntimeError('owned HTTP service did not become ready')
 env=dict(os.environ);env.update(MCP_HTTP_TEST_BASE_URL=base,MCP_HTTP_TEST_TOKEN=token)
 r=subprocess.run(['/usr/local/bin/python3.14','-B',str(root/'tests/postgres/run-mcp-http-receipt-isolated.py')],env=env,text=True,capture_output=True,timeout=150)
 result.update(exitCode=r.returncode,stdout=r.stdout,stderr=r.stderr)
 result['centralEvidence']=json.loads((root/'tasks/mcp-http-central-receipt-2026-09-19.json').read_text())

finally:
 subprocess.run(D+['rm','-f',name],capture_output=True,timeout=10);result['containerAbsent']=not subprocess.run(D+['ps','-aq','--filter','name=^/'+name+'$'],capture_output=True,text=True).stdout.strip()
 if created:
  assert checked(ssh(['cat',remote+'/owner']))==nonce+'\n';assert checked(ssh(['cat',remote+'/policy']))==policy
  if loaded and result['containerAbsent']:checked(ssh(['sudo','apparmor_parser','-R',remote+'/policy']))
  labels=checked(ssh(['sudo','cat','/sys/kernel/security/apparmor/profiles']));result['profileAbsent']=not any(line.startswith(profile+' ') or line.startswith(profile+'//') for line in labels.splitlines())
  if result['profileAbsent']:checked(ssh(['rm',remote+'/owner',remote+'/policy']));checked(ssh(['rmdir',remote]));result['remoteAbsent']=ssh(['test','!','-e',remote]).returncode==0
 pathlib.Path('/private/tmp/owned-http-service-central-result.json').write_text(json.dumps(result,indent=2));pathlib.Path('/private/tmp/owned-http-service-central-policy.txt').write_text(policy);print(json.dumps(result))
