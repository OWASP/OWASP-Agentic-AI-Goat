"""Controlled strict-runner lifecycle; no remote, Docker, or native execution."""
import hashlib
import subprocess
import unittest
from unittest.mock import patch
import mcp_strict_runner_ownership as module

class Runner(unittest.TestCase):
 def fixture(self):
  events=[];files={};profiles=[];template=b'profile "@@SUPERVISOR_PROFILE@@" { }\n';policy=template.replace(b'@@SUPERVISOR_PROFILE@@',b'owasp-ai-goat-mcp-sandbox-'+b'c'*12);template_hash=hashlib.sha256(template).hexdigest()
  def remote(args,**kwargs):
   events.append(args)
   if args[:2]==['sudo','cat']:out='\n'.join(profiles)
   elif args[0]=='tee':files[args[1]]=kwargs['input'];out=''
   elif args[0]=='cat':out=files[args[-1]]
   elif args[:2]==['sudo','apparmor_parser']:
    if args[2]=='-r':profiles.append(runner.profile+' (enforce)')
    else:profiles.clear()
    out=''
   else:out=''
   return subprocess.CompletedProcess(args,0,out,'')
  runner=module.StrictRunner(docker=lambda args:subprocess.CompletedProcess(args,0,'a'*64+'\n',''),remote=remote,record=lambda *args:events.append(args),daemon_id='owned',image='sha256:'+'b'*64,nonce='c'*32,uid=501,policy=policy,policy_sha256=hashlib.sha256(policy).hexdigest(),context_sha256='d'*64,template_sha256=template_hash,template=template,build_receipt=dict(version=1,imageId='sha256:'+'b'*64,contextSha256='d'*64,policyTemplateSha256=template_hash,nodeVersion='v26.8.2'))
  return runner,events,files
 def test_policy_preparation_and_exact_removal(self):
  runner,events,files=self.fixture()
  with patch.object(module,'verify_daemon'),patch.object(module,'verify_image'):
   runner.prepare_policy();runner.cleanup()
  self.assertFalse(runner.remote_intended)
  self.assertIn(['sudo','apparmor_parser','-R',runner.directory+'/policy.apparmor'],events)
 def test_remote_mismatch_never_unloads(self):
  runner,events,files=self.fixture()
  with patch.object(module,'verify_daemon'),patch.object(module,'verify_image'):
   runner.prepare_policy();files[runner.directory+'/owner']='foreign'
   with self.assertRaises(RuntimeError):runner.cleanup()
  self.assertNotIn(['sudo','apparmor_parser','-R',runner.directory+'/policy.apparmor'],events)
 def test_uncertain_runner_cleanup_precedes_policy_unload(self):
  runner,events,files=self.fixture()
  with patch.object(module,'verify_daemon'),patch.object(module,'verify_image'):
   runner.prepare_policy();runner.container_intended=True
   with patch.object(module,'cleanup_owned',side_effect=RuntimeError('uncertain')):
    with self.assertRaises(RuntimeError):runner.cleanup()
  self.assertTrue(runner.remote_intended)
  self.assertNotIn(['sudo','apparmor_parser','-R',runner.directory+'/policy.apparmor'],events)
 def test_uncertain_creation_retains_cleanup_intent(self):
  runner,events,files=self.fixture()
  with patch.object(module,'verify_daemon'),patch.object(module,'verify_image'):
   runner.prepare_policy()
   runner.docker=lambda args:(_ for _ in ()).throw(subprocess.TimeoutExpired('controlled',1))
   with self.assertRaises(subprocess.TimeoutExpired):runner.launch('t'*48)
   self.assertTrue(runner.container_intended)
   with patch.object(module,'cleanup_owned',return_value={'status':'absent'}) as cleanup:
    runner.cleanup();self.assertIsNone(cleanup.call_args.kwargs['captured_id'])
 def test_layout_cannot_relax_confinement(self):
  profile='owned';row={'HostConfig':{'SecurityOpt':['seccomp=unconfined','apparmor='+profile],'Tmpfs':{'/sandbox':'rw,uid=10001,gid=10001,mode=0700'},'Privileged':False,'CapAdd':None},'Mounts':[],'NetworkSettings':{'Ports':{'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':'38090'}]}}}
  self.assertEqual(module.validate_runner_layout(row,profile),38090)
  for key,value in [('Privileged',True),('CapAdd',['SYS_ADMIN']),('SecurityOpt',['seccomp=unconfined']),('Tmpfs',{})]:
   original=row['HostConfig'][key];row['HostConfig'][key]=value
   with self.assertRaises(RuntimeError):module.validate_runner_layout(row,profile)
   row['HostConfig'][key]=original
 def test_render_mismatch_rejected_before_remote_io(self):
  calls=[];template=b'profile "@@SUPERVISOR_PROFILE@@" {}';wrong=b'arbitrary policy'
  th=hashlib.sha256(template).hexdigest()
  with self.assertRaisesRegex(RuntimeError,'exact reviewed template/profile rendering'):
   module.StrictRunner(docker=lambda *a:calls.append(a),remote=lambda *a:calls.append(a),record=lambda *a:calls.append(a),daemon_id='owned',image='sha256:'+'b'*64,nonce='c'*32,uid=501,policy=wrong,policy_sha256=hashlib.sha256(wrong).hexdigest(),context_sha256='d'*64,template_sha256=th,template=template,build_receipt=dict(version=1,imageId='sha256:'+'b'*64,contextSha256='d'*64,policyTemplateSha256=th,nodeVersion='v26.8.2'))
  self.assertEqual(calls,[])
 def test_exact_health_includes_ticket_capability(self):
  health=dict(ready=True,version='mcp-owned-target-http.v1',isolation='bwrap-seccomp-v1',supervisorProfile='owned (enforce)',protectedStateCapability='mcp-owned-protected-state-transition.v2',observedActionCapability='mcp-owned-observed-action.v1',packageInstallCapability='mcp-owned-package-install.v1',ticketReadCapability='mcp-owned-ticket-read.v2')
  module.validate_health(health,'owned')
  del health['ticketReadCapability']
  with self.assertRaises(RuntimeError):module.validate_health(health,'owned')
 def test_build_receipt_and_health_fail_closed(self):
  with self.assertRaises(RuntimeError):module.validate_build_receipt({},image='sha256:'+'a'*64,context_sha256='b'*64,template_sha256='c'*64)
  with self.assertRaises(RuntimeError):module.validate_health({'ready':True},'owned')

if __name__=='__main__':unittest.main()
