import importlib.util,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location('capacity_parent',Path(__file__).with_name('run-setup-database-phase-isolated.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class CapacityMain(unittest.TestCase):
 def test_closed_bounds_and_retained_auth(self):
  self.assertEqual(m.scenario_bounds('main-capacity-200'),(1200,1080,120));self.assertEqual(m.scenario_bounds('main-backend-auth'),(600,480,120))
  self.assertEqual(m.scenario_fixture('main-capacity-200'),'tests/postgres/mainBackendAuth.integration.test.js')
  with self.assertRaises(KeyError):m.scenario_bounds('capacity-arbitrary')
 def test_command_uses_current_entry(self):
  args=SimpleNamespace(scenario='main-capacity-200',node='/pinned/node',package='/main')
  self.assertEqual(m.scenario_command(args),['/pinned/node','--test','--test-isolation=none','--test-reporter=tap','tests/postgres/mainBackendAuth.integration.test.js'])
 def test_journal_precedes_release(self):
  events=[]
  class Pipe:
   def write(self,v):events.append(('write',v))
   def flush(self):events.append('flush')
   def close(self):events.append('close')
  state={};child=SimpleNamespace(pid=123,stdin=Pipe())
  m.publish_child_start(child,state,lambda:events.append(('record',dict(state))),'main-capacity-200')
  self.assertEqual(events[0],('record',{'nativeStarted':True,'nativePid':123}));self.assertEqual(events[1],('write',b'1'))
 def test_wrong_main_root_denied_before_inventory(self):
  args=SimpleNamespace(scenario='main-capacity-200',package='/foreign')
  with patch.object(m,'inventory',side_effect=AssertionError('must not inspect')):
   with self.assertRaisesRegex(RuntimeError,'Main prospective root'):m.validate_prospective_main(args)
 def test_terminal_rejects_model_claim_and_incomplete_phases(self):
  import json,os
  names=['arrival','read-mix','normal-runs','foreign-history','cancel-revoke-reset','global-backpressure','owner-backpressure','lifecycle-contention','recovery']
  runs=[f'00000000-0000-4000-8000-{n:012x}' for n in range(10)]
  value={'passed':True,'actualModel':False,'fullQualificationComplete':True,'phases':[{'name':n} for n in names],'requests':10506,'limits':{'requests':12000,'owners':200},'provider':{'actualModel':False,'total':1200,'maxTurns':5,'standardMaxTurns':4,'gradingProjectionRuns':10,'gradingProjectionMaxTurns':5},'presentationProjection':{'dto':200,'ownerDetails':200,'foreignDenied':20,'selectedObservationGrading':'controlled_unavailable_not_pass'},'gradingProjection':{'owners':10,'runs':runs,'expectedVerdict':'unavailable','expectedDisposition':'not_pass','expectedErrorCode':'INVALID_JUDGE_OUTPUT','actualModel':False}}
  st=SimpleNamespace(st_nlink=1,st_uid=os.getuid(),st_mode=0o600,st_size=1000)
  shutdown={'passed':True,'pools':{'managedReservedFinal':0,'dedicatedActive':0,'allocationFailures':0,'managedReservedPeak':78}}
  def read(p):return json.dumps(shutdown if p.name=='capacity-shutdown.json' else value)
  with patch.object(Path,'lstat',return_value=st),patch.object(Path,'is_symlink',return_value=False),patch.object(Path,'is_file',return_value=True),patch.object(Path,'read_text',read):
   self.assertTrue(m.verify_capacity_result('/synthetic'))
   import copy
   for field,bad in [('provider',None),('provider',{'actualModel':True,'total':1,'maxTurns':1}),('provider',{'actualModel':False,'total':6001,'maxTurns':5,'standardMaxTurns':4,'gradingProjectionRuns':10,'gradingProjectionMaxTurns':5}),('provider',{'actualModel':False,'total':1,'maxTurns':6,'standardMaxTurns':4,'gradingProjectionRuns':10,'gradingProjectionMaxTurns':5}),('provider',{'actualModel':False,'total':True,'maxTurns':5,'standardMaxTurns':4,'gradingProjectionRuns':10,'gradingProjectionMaxTurns':5})]:
    original=copy.deepcopy(value[field]);value[field]=bad
    with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
    value[field]=original
   for field,bad in [('presentationProjection',None),('presentationProjection',{'dto':200,'ownerDetails':200,'foreignDenied':10,'selectedObservationGrading':'controlled_unavailable_not_pass'}),('gradingProjection',None),('gradingProjection',{**value['gradingProjection'],'runs':runs[:9]}),('gradingProjection',{**value['gradingProjection'],'runs':[runs[0]]*10}),('gradingProjection',{**value['gradingProjection'],'runs':['not-a-uuid']*10}),('gradingProjection',{**value['gradingProjection'],'expectedDisposition':'awarded'})]:
    original=copy.deepcopy(value[field]);value[field]=bad
    with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
    value[field]=original
   original=value['provider']['gradingProjectionRuns'];value['provider']['gradingProjectionRuns']=9
   with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
   value['provider']['gradingProjectionRuns']=original
   for key in ('managedReservedFinal','dedicatedActive','allocationFailures','managedReservedPeak'):
    original=shutdown['pools'][key]
    for bad in (None,True,-1,79):
     shutdown['pools'][key]=bad
     with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
    shutdown['pools'][key]=original
   original=shutdown.pop('pools')
   with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
   shutdown['pools']=original
   value['actualModel']=True
   with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
   value['actualModel']=False;value['phases'].pop()
   with self.assertRaises(RuntimeError):m.verify_capacity_result('/synthetic')
if __name__=='__main__':unittest.main()
