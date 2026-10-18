import unittest,tempfile,sys,subprocess,shutil,stat,ast,time
from unittest.mock import Mock
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from bound_mail_modes import create_parser,bounds_for
from mail_disclosure_freeze import stage_expected,CURRICULUM
class DisclosureModes(unittest.TestCase):
 def test_bounds_and_selector(self):
  self.assertEqual(bounds_for('disclosure-native'),(900,480));self.assertEqual(bounds_for('disclosure-actual'),(900,780))
  self.assertEqual(create_parser().parse_args(['--docker-host','unused','--mode','disclosure-native','--disclosure-state','populated']).disclosure_state,'populated')
 def test_closed_cli_before_resources(self):
  script=str(Path(__file__).with_name('run-bound-mail-isolated.py'))
  for args in [['--mode','disclosure-native'],['--mode','disclosure-actual','--disclosure-state','populated'],['--mode','migration','--disclosure-state','fresh'],['--mode','disclosure-native','--disclosure-state','fresh']]:
   p=subprocess.run([sys.executable,script,'--docker-host','unused',*args],capture_output=True,text=True);self.assertEqual(p.returncode,2,p.stderr);self.assertIn('error:',p.stderr)
 def test_actual_readonly_copy_root_normalized_before_dependency_link(self):
  from mail_reply_authority_freeze import copy
  launcher=Path(__file__).with_name('run-bound-mail-isolated.py').read_text()
  tree=ast.parse(launcher);nodes=[n for n in ast.walk(tree) if isinstance(n,ast.Expr) and ast.unparse(n).startswith('workspace.chmod(')]
  self.assertEqual(len(nodes),1);self.assertLess(nodes[0].lineno, next(n.lineno for n in ast.walk(tree) if isinstance(n,ast.Expr) and "(workspace / 'node_modules').symlink_to" in ast.unparse(n)))
  with tempfile.TemporaryDirectory() as t:
   source=Path(t)/'source';workspace=Path(t)/'copy';(source/'scripts/lib').mkdir(parents=True);(source/'server/config').mkdir(parents=True)
   shutil.copy2(Path(__file__).resolve().parents[2]/'scripts/lib/isolated-source-copy.js',source/'scripts/lib/isolated-source-copy.js')
   candidate=source/CURRICULUM;candidate.write_bytes(b'owned original')
   for p in source.rglob('*'):p.chmod(0o555 if p.is_dir() else 0o444)
   source.chmod(0o555)
   try:
    copy(source,workspace);self.assertEqual(stat.S_IMODE(workspace.stat().st_mode),0o555)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual launcher root normalization>','exec'),{'workspace':workspace})
    (workspace/'node_modules').symlink_to(Path(t)/'owned-dependencies')
    staged=workspace/CURRICULUM;staged.chmod(0o600);staged.write_bytes(b'owned staged');self.assertTrue((workspace/'node_modules').is_symlink())
    self.assertEqual(candidate.read_bytes(),b'owned original');self.assertEqual(stat.S_IMODE(candidate.stat().st_mode),0o444);self.assertEqual(stat.S_IMODE(source.stat().st_mode),0o555)
   finally:
    for root in [source,workspace]:
     if root.exists():
      root.chmod(0o700)
      for p in root.rglob('*'):
       if p.is_dir() and not p.is_symlink():p.chmod(0o700)
 def cleanup_functions(self,deadline,process_module=subprocess):
  tree=ast.parse(Path(__file__).with_name('run-bound-mail-isolated.py').read_text())
  names={'cleanup_timeout','bounded_run','attempt_cleanup'}
  scope={'cleanup_deadline':deadline,'time':time,'subprocess':process_module}
  exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),'<actual cleanup functions>','exec'),scope)
  return scope
 def test_cleanup_deadline_stops_hung_subprocess_and_preserves_attempts(self):
  scope=self.cleanup_functions(time.monotonic()+0.15);errors=[]
  scope['attempt_cleanup'](errors,'hung',lambda:scope['bounded_run']([sys.executable,'-c','import time; time.sleep(10)'],timeout=30))
  self.assertEqual(errors,['hung:TimeoutExpired']);attempted=[]
  scope['attempt_cleanup'](errors,'next-owned-cleanup',lambda:attempted.append(True))
  self.assertEqual(attempted,[True])
 def test_expired_cleanup_does_not_launch_and_continues_reporting(self):
  process=Mock();scope=self.cleanup_functions(time.monotonic()-1,process);errors=[]
  for label in ['child','remove','absence','integrity']:
   scope['attempt_cleanup'](errors,label,lambda:scope['bounded_run'](['unused'],timeout=10))
  process.run.assert_not_called();self.assertEqual(errors,[label+':TimeoutError' for label in ['child','remove','absence','integrity']])
 def test_cleanup_remaining_budget_clamps_and_legacy_timeout_preserved(self):
  process=Mock();scope=self.cleanup_functions(time.monotonic()+1,process);scope['bounded_run'](['owned'],timeout=30)
  self.assertGreater(process.run.call_args.kwargs['timeout'],0);self.assertLessEqual(process.run.call_args.kwargs['timeout'],1)
  scope=self.cleanup_functions(None,process);scope['bounded_run'](['legacy'],timeout=7);self.assertEqual(process.run.call_args.kwargs['timeout'],7)
  launcher=Path(__file__).with_name('run-bound-mail-isolated.py').read_text();cleanup=launcher[launcher.index('finally:'):]
  self.assertLess(cleanup.index("docker+['rm'"),cleanup.index('cleanup_verify(SOURCE'))
 def test_actual_staged_curriculum_has_json_examples_and_preserves_siblings(self):
  from mail_reply_authority_freeze import NODE
  root=Path(__file__).resolve().parents[2]
  with tempfile.TemporaryDirectory() as t:
   staged=Path(t)/'staged.cjs';staged.write_bytes((root/CURRICULUM).read_bytes())
   code=r"""const assert=require('node:assert/strict'),path=require('node:path');
const [root,staged]=process.argv.slice(1),original=require(path.join(root,'server/config/secureshopCurriculum')),candidate=require(staged),provenance=require(path.join(root,'server/database/postgres/catalogDefaultProvenance'));
const id='ss_mail_cross_persona_read';assert.equal(original.OBJECTIVES.find(x=>x.id===id).qualification,'native-model');assert.equal(original.isQualifiedObjective(id),true);assert.equal(candidate.OBJECTIVES.find(x=>x.id===id).qualification,'native-model');assert.equal(candidate.isQualifiedObjective(id),true);
for(const row of candidate.OBJECTIVES){assert.equal(row.defaultEnabled,false);provenance.encode(candidate.HINTS[row.id]);provenance.encode(candidate.SOLUTIONS[row.id]);if(candidate.isQualifiedObjective(row.id)){assert(candidate.SOLUTIONS[row.id].examples.length>0);for(const example of candidate.SOLUTIONS[row.id].examples){assert.equal(typeof example.action,'string');assert.equal(typeof example.explanation,'string');}}if(row.id!==id){assert.deepEqual(candidate.SOLUTIONS[row.id],original.SOLUTIONS[row.id]);assert.deepEqual(candidate.HINTS[row.id],original.HINTS[row.id]);}}
assert.match(candidate.SOLUTIONS[id].examples[0].explanation,/manual IDOR/);assert.match(candidate.SOLUTIONS[id].examples[0].action,/readOperationId/);assert.match(candidate.HINTS[id].hints.join(' '),/Reload is ungraded browsing/);
console.log('all staged curriculum content validates through canonical provenance; qualified examples defined; siblings unchanged');"""
   result=subprocess.run([str(NODE),'-e',code,str(root),str(staged)],capture_output=True,text=True,timeout=15)
   self.assertEqual(result.returncode,0,result.stderr);self.assertIn('siblings unchanged',result.stdout)
 def test_staging_changes_single_canonical_row_not_predicate_or_defaults(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/CURRICULUM;p.parent.mkdir(parents=True);source="{ id: 'ss_mail_cross_persona_read', qualification: 'pending', defaultEnabled: false },\nfunction isQualifiedObjective(id) { return SET.has(id); }\n";p.write_text(source)
   rows,data=stage_expected({},t);self.assertEqual(p.read_text(),source);self.assertEqual(data.decode(),source.replace("qualification: 'pending'","qualification: 'native-model'"));self.assertEqual(set(rows),{CURRICULUM})
   p.write_text(data.decode());self.assertRaises(RuntimeError,stage_expected,{},t)
if __name__=='__main__':unittest.main()
