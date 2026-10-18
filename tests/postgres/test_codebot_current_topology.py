import unittest
from pathlib import Path
from mcp_mounted_http_topology import resource_plan,OwnedMcpTopology
class CodeBotTopology(unittest.TestCase):
 def test_cli_only_plan_and_no_optional_resources(self):
  args=('a'*32,'sha256:'+'b'*64,None,b'profile @@SUPERVISOR_PROFILE@@ { profile bwrap {} }',None)
  p=resource_plan(*args,cohort='codebot-current-representative')
  self.assertEqual(list(p['resources']),['cli']);self.assertEqual(p['resources']['cli']['ports'],[8090]);self.assertEqual(p['resources']['cli']['labels']['dvaia.qualification'],'codebot-current-representative')
  for change in [('a'*32,'sha256:'+'b'*64,'sha256:'+'c'*64,args[3],None),('a'*32,'sha256:'+'b'*64,None,args[3],args[3])]:
   with self.assertRaises(ValueError):resource_plan(*change,cohort='codebot-current-representative')
 def test_full_six_keeps_cli_only_and_exact_cohort(self):
  args=('a'*32,'sha256:'+'b'*64,None,b'profile @@SUPERVISOR_PROFILE@@ {}',None)
  p=resource_plan(*args,cohort='codebot-current-full-six')
  self.assertEqual(list(p['resources']),['cli']);self.assertEqual(p['resources']['cli']['labels']['dvaia.qualification'],'codebot-current-full-six')
  with self.assertRaises(ValueError):resource_plan(args[0],args[1],'sha256:'+'c'*64,args[3],None,cohort='codebot-current-full-six')
 def test_closed_profile_iteration_retains_only_admitted_cli(self):
  p=resource_plan('a'*32,'sha256:'+'b'*64,None,b'profile @@SUPERVISOR_PROFILE@@ {}',None,cohort='codebot-current-representative')
  m=OwnedMcpTopology(plan=p,docker=lambda *a:None,remote=lambda *a:None,record=lambda *a:None,remaining=lambda:1,daemon_id='d',evidence_root=Path.cwd(),remote_binding={'uid':501,'daemonId':'d','strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHostsSha256':'c'*64,'resolvedConfigurationSha256':'d'*64})
  self.assertEqual(m.profile_kinds(),('cli',));self.assertEqual(m.attempted,{})
if __name__=='__main__':unittest.main()
