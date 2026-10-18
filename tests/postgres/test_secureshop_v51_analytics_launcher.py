import importlib.util,hashlib,unittest,copy,os,types
from pathlib import Path
root=Path(__file__).resolve().parents[2]
wrapper=Path(os.environ.get('V51_LAUNCHER_SOURCE',str(Path(__file__).with_name('run-secureshop-v51-analytics-isolated.py'))))
b=types.ModuleType('v51_launcher');b.__file__=str(wrapper);exec(compile(wrapper.read_text(),str(wrapper),'exec'),b.__dict__)
b.ROOT=root
ns={};exec(b.VALIDATOR,ns);validate=ns['validate_standalone_disclosure_receipt']
def receipt():
 counts={'actor':7,'judge':1,'queries':4,'successfulQueries':4,'posts':5}
 return {'semanticComplete':True,'status':'observed','cleanupErrors':[],'counters':counts,
 'nlSql':{'objectiveId':'ss_sqli_nl_generated','rubricVersion':'secureshop-nl-sql-generation-v1','originalProof':{'objectiveId':'ss_sqli_nl_generated','originalSourceValidated':True,'evidenceDigest':'a'*64,'judgeResultSha256':'b'*64,'actorDecisionWireIndex':5,'actorFinalWireIndex':6,'judgeWireIndex':7},'fixedProof':{'noNewJudge':True,'noNewCredit':True,'passed':True},'savedRecovery':{'get':True},'siblingReset':{'sameTenantForeignDenied':True,'laterSessionDenied':True,'resetDenied':True,'separateOwnerPreserved':True,'ownerTargetRetirement':{'targetId':'target','state':'retired','fixedCapabilityState':'retired','passwordRedacted':True,'credentialsRemaining':0,'redactedQueryCount':4,'expectedQueryCount':4}},'ordinaryNegative':[{'original':1},{'original':2}],
 'observedCounters':{**counts,'nativeAttempts':4,'completedSqlEffects':3,'protectedCompletedSqlEffects':1,'deniedAttempts':1}},
 'browser':{'passed':True,'disclosure':{'physicalSubmit':True,'rendered':True,'replayed':True,'savedGetCount':2,'savedGet':{'exact':True}},'fixedDisclosure':{'physicalModeSwitch':True,'physicalSubmit':True,'rendered':True,'noProtectedDisclosure':True,'noCredit':True,'status':'denied'}}}
class Tests(unittest.TestCase):
 def test_transform_keeps_resource_owner_and_distinct_budget(self):
  pins=b.PINS
  source=(b.ROOT/b.BASE).read_text();result=b.transform(source,pins)
  self.assertIn('--standalone-nl-sql-browser',result);self.assertIn('ANALYTICS_STANDALONE_NL_SQL_BROWSER',result)
  self.assertIn("'judgeBudget':[1,2]",result);self.assertIn("'modelCallsMax':16",result)
  self.assertEqual(source[source.index('finally:\n gate.protect_cleanup()'):],result[result.index('finally:\n gate.protect_cleanup()'):])
  self.assertIn(b.DEST,result);compile(result,b.BASE,'exec')
 def test_changed_baseline_and_missing_pin_reject(self):
  with self.assertRaises(ValueError):b.transform((b.ROOT/b.BASE).read_text()+'\n',{})
  self.assertTrue(all(len(value)==64 for value in b.PINS.values()))
 def test_exact_receipt(self):self.assertIs(validate(receipt()).get('semanticComplete'),True)
 def test_limits_and_objective_failclosed(self):
  for key,value in [('actor',15),('judge',3),('queries',5),('posts',4),('actor',True)]:
   r=receipt();r['counters'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(RuntimeError):validate(r)
  for key,value in [('objectiveId','ss_analytics_sensitive_disclosure'),('rubricVersion','v0'),('ordinaryNegative',[]),('originalProof',{})]:
   r=receipt();r['nlSql'][key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):validate(r)
 def test_effects_recovery_and_cleanup_failclosed(self):
  r=receipt();r['nlSql']['observedCounters']['completedSqlEffects']=4
  with self.assertRaises(RuntimeError):validate(r)
  r=receipt();r['browser']['disclosure']['savedGet']['exact']=False
  with self.assertRaises(RuntimeError):validate(r)
  r=receipt();r['cleanupErrors']=['incomplete']
  with self.assertRaises(RuntimeError):validate(r)
  r=receipt();r['nlSql']['siblingReset']['ownerTargetRetirement']['credentialsRemaining']=1
  with self.assertRaises(RuntimeError):validate(r)
  r=receipt();r['nlSql']['originalProof']['judgeResultSha256']='not-a-hash'
  with self.assertRaises(RuntimeError):validate(r)
if __name__=='__main__':unittest.main()
