import importlib.util,unittest,tempfile,json,contextlib,io
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('rag_launcher',Path(__file__).with_name('run-mcp-central-sql-return-loss-isolated.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class LauncherTests(unittest.TestCase):
 def arguments(self,root):
  return ['--central-sql-return-loss',*sum((['--'+k,v] for k,v in {'source':str(root/'source'),'manifest':str(root/'manifest.json'),'manifest-sha256':'a'*64,'node-binary':'/owned/node','node-sha256':'b'*64,'python-binary':str(root/'python'),'python-sha256':'e'*64,'docker-binary':str(root/'docker'),'docker-sha256':'c'*64,'docker-host':'unix:///owned/docker.sock','docker-daemon':'owned-daemon','image-id':'sha256:'+'d'*64,'evidence-root':str(root/'evidence')}.items()),[])]
 def test_closed_mode_and_unknown_flags(self):
  with tempfile.TemporaryDirectory() as d:
   argv=self.arguments(Path(d))
   self.assertTrue(m.parser().parse_args(argv).central_sql_return_loss)
   for bad in [argv[1:],argv+['--workshop-rag-defense-explicit'],[x.replace('--central-sql-return-loss','--central-sql-return-l') for x in argv]]:
    with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):m.parser().parse_args(bad)
 def test_bad_manifest_and_docker_pins_fail_before_temp_or_subprocess(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);docker=root/'docker';docker.write_text('not-docker');docker.chmod(0o700)
   python=root/'python';python.write_text('owned fake executable');python.chmod(0o700)
   argv=self.arguments(root);argv[argv.index('--python-sha256')+1]=m.digest(python)
   for failure in ['manifest','docker']:
    with patch.object(m.contract,'validate_package',side_effect=RuntimeError('manifest') if failure=='manifest' else None,return_value={'files':dict.fromkeys(m.REQUIRED,'x')}),patch.object(m.tempfile,'mkdtemp') as temp,patch.object(m.subprocess,'run') as run:
     with self.assertRaisesRegex(RuntimeError,'manifest' if failure=='manifest' else 'Docker executable pin mismatch'):m.main(argv)
     temp.assert_not_called();run.assert_not_called()
 def test_python_pin_rejection_precedes_resource_admission(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   with patch.object(m.contract,'validate_package',return_value={'files':dict.fromkeys(m.REQUIRED,'x')}),patch.object(m.tempfile,'mkdtemp') as temp,patch.object(m.subprocess,'run') as run:
    with self.assertRaisesRegex(RuntimeError,'Python executable pin mismatch'):m.main(self.arguments(root))
    temp.assert_not_called();run.assert_not_called()
 def test_exact_four_owned_role_urls(self):
  e=m.database_environment('a'*12,54321)
  self.assertEqual(set(e),{'PG_GRAPH_TEST_RUNTIME_URL','PG_GRAPH_TEST_MIGRATION_URL','PG_MCP_RUNTIME_URL','PG_MCP_MIGRATION_URL'})
  for key,store,role in [('PG_GRAPH_TEST_RUNTIME_URL','identity','runtime'),('PG_GRAPH_TEST_MIGRATION_URL','identity','migration'),('PG_MCP_RUNTIME_URL','mcp','runtime'),('PG_MCP_MIGRATION_URL','mcp','migration')]:self.assertEqual(e[key],f'postgresql://dvaia_{store}_{role}@127.0.0.1:54321/owasp_ai_goat_test_central_ack_'+('a'*12)+'_'+store)
  for owner,port in [('bad',5432),('a'*12,0),('a'*12,65536),('a'*12,'1;sql')]:
   with self.assertRaises(ValueError):m.database_environment(owner,port)
 def test_container_layout_rejects_wrong_resources_and_remote_port(self):
  row={'Mounts':[],'HostConfig':{'Memory':1073741824,'NanoCpus':2000000000,'PidsLimit':256,'Tmpfs':{'/var/lib/postgresql':'rw,size=536870912'}},'NetworkSettings':{'Ports':{'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':'54321'}]}}}
  self.assertEqual(m.validate_layout(row),54321)
  for field,value in [('Memory',536870912),('NanoCpus',1000000000),('PidsLimit',512),('Tmpfs',{})]:
   changed=json.loads(json.dumps(row));changed['HostConfig'][field]=value
   with self.assertRaises(RuntimeError):m.validate_layout(changed)
  row['NetworkSettings']['Ports']['5432/tcp'][0]['HostIp']='0.0.0.0'
  with self.assertRaises(RuntimeError):m.validate_layout(row)
 def test_ownership_helpers_refuse_foreign_container(self):
  from types import SimpleNamespace
  row={'Id':'a'*64,'Name':'/owned','Image':'sha256:'+'b'*64,'Config':{'Labels':{'owasp-ai-goat.test.owner':'foreign'}}}
  commands=[]
  def command(argv):commands.append(argv);return SimpleNamespace(returncode=0,stdout=json.dumps([row]),stderr='')
  with self.assertRaises(RuntimeError):m.inspect_owned(command,name='owned',labels={'owasp-ai-goat.test.owner':'ours'},image='sha256:'+'b'*64)
  self.assertEqual(commands,[['inspect','--type','container','owned']])
 def test_shared_cleanup_budget_cannot_renew_after_failure(self):
  now=[0];budget=m.CleanupBudget(30,clock=lambda:now[0]);now[0]=31
  called=[]
  with self.assertRaises(TimeoutError):budget.run(lambda:called.append(True))
  self.assertEqual(called,[])
 def test_closed_bounds_and_no_provider_environment(self):
  self.assertEqual((m.WORK_SECONDS,m.CHILD_SECONDS,m.CLEANUP_SECONDS),(180,120,30))
  text=Path(m.__file__).read_text()
  self.assertNotIn('OLLAMA_BASE_URL',text)
  self.assertNotIn('drafts/',text)
  self.assertIn("'PG_MCP_CENTRAL_ACK':'yes'",text)
 def test_exhausted_physical_budget_still_runs_separate_integrity(self):
  now=[0];physical=m.CleanupBudget(30,clock=lambda:now[0]);now[0]=31;calls=[];budgets=[]
  def factory(seconds):budgets.append(seconds);return m.CleanupBudget(seconds)
  results,failures=m.physical_cleanup_and_integrity([('processes',lambda:calls.append('unsafe cleanup')),('container',lambda:calls.append('unsafe container'))],lambda:calls.append('integrity'),physical_budget=physical,budget_factory=factory)
  self.assertEqual(calls,['integrity']);self.assertEqual(budgets,[120]);self.assertEqual(results,{'integrity':True});self.assertEqual(failures,['processes:TimeoutError','container:TimeoutError'])
 def test_integrity_failure_remains_separate_from_physical_failure(self):
  def bad():raise RuntimeError('controlled')
  result,failures=m.physical_cleanup_and_integrity([('processes',bad),('container',lambda:{'status':'absent'})],bad,physical_budget=m.CleanupBudget(30))
  self.assertEqual(result,{'container':{'status':'absent'}});self.assertEqual(failures,['processes:RuntimeError','integrity:RuntimeError'])
if __name__=='__main__':unittest.main()
