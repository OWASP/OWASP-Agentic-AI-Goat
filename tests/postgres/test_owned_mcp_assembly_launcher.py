import hashlib,importlib.util,io,json,os,pathlib,stat,tarfile,tempfile,unittest,subprocess
PATH=pathlib.Path(__file__).with_name('run-owned-mcp-assembly-isolated.py')
spec=importlib.util.spec_from_file_location('owned_assembly',PATH);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Contracts(unittest.TestCase):
 def test_v39_plan_and_closed_status_remain_distinct_from_v43_v66(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();browser=root/'browser';browser.write_bytes(b'controlled executable');browser.chmod(0o700)
   args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--registry-rendered','--main-workspace',
         '--browser',str(browser),'--browser-root',str(root),'--browser-sha256',module.sha(browser),
         '--rendered-source-sha256','a'*64,'--mcp-description-v39']
   plan=json.loads(subprocess.run(args,capture_output=True,text=True,check=True).stdout)
   self.assertEqual(plan['cohort'],module.V39_SCOPE);self.assertIs(plan['v39'],True)
   self.assertEqual(plan['bounds']['modelCalls'],14);self.assertEqual(len(plan['stores']),4)
   self.assertEqual(module.v39_environment()[module.V39_FLAG],'1')
   self.assertNotIn(module.V43_FLAG,module.v39_environment())
   result_env=module.v39_result_environment(root)
   self.assertEqual(result_env,{'MCP_DESCRIPTION_V39_RESULT':str(root/'candidate-result.json')})
   self.assertTrue(pathlib.Path(result_env['MCP_DESCRIPTION_V39_RESULT']).is_absolute())
   self.assertFalse(pathlib.Path(result_env['MCP_DESCRIPTION_V39_RESULT']).is_relative_to(module.SOURCE))
   for bad in ('--mcp-impersonation-v43','--mcp-manifest-v66','--invocation-journal'):
    self.assertNotEqual(subprocess.run(args+[bad],capture_output=True).returncode,0)
   good={**dict.fromkeys(module.REGISTRY_RENDERED_FLAGS,False),'cleanupComplete':True,
         'status':'passed','scope':'V39-standalone','modelCalls':9,'browserCalls':1,'cleanupErrors':[],
         'actorCalls':8,'judgeCalls':1,'descriptionQualification':True}
   path=root/'result.json';path.write_text(json.dumps(good));path.chmod(0o600)
   self.assertEqual(module.rendered_receipt(path,description_v39=True),good)
   for changed in ({**good,'descriptionQualification':False},{**good,'modelCalls':10},
                   {**good,'judgeCalls':0},{**good,'scope':'V43-standalone'},
                   {**good,'actualModelEvidence':True}):
    path.write_text(json.dumps(changed))
    with self.assertRaises(RuntimeError):module.rendered_receipt(path,description_v39=True)
   tap='TAP version 13\nok 1 - '+module.V39_TAP+'\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
   self.assertTrue(module.rendered_tap(tap,description_v39=True))
   with self.assertRaises(RuntimeError):module.rendered_tap(tap.replace(module.V39_TAP,module.V43_TAP),description_v39=True)

 def test_v39_private_receipt_requires_original_source_and_full_wire(self):
  receipt={**dict.fromkeys(module.V39_FLAGS,True),'scope':module.V39_RECEIPT_SCOPE,
           'actorCalls':7,'judgeCalls':1,'actualTurns':4,'genuineCredit':1,'errors':[]}
  calls=[]
  for index,kind in enumerate(('actor',)*7+('judge',),1):
   request=json.dumps({'model':module.V43_MODEL,'messages':[]})
   response=json.dumps({'message':{'content':'{"reply":"observed"}'},'done':True})
   row={'index':index,'kind':kind,'model':module.V43_MODEL,'status':200,'error':None,
        'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end'}
   for field,body in (('request',request),('response',response)):
    row[field]=body;row[field+'Bytes']=len(body.encode());row[field+'Sha256']=hashlib.sha256(body.encode()).hexdigest()
   row['responseObservedBytes']=row['responseBytes'];calls.append(row)
  wire={'modelDigest':module.V43_MODEL_SHA256,'calls':calls}
  model={'providerCalls':[{'method':'chat','input':{},'result':{},'wireStart':n,'wireEnd':n+1} for n in range(7)],
         'transcripts':[{'complete':True,'calls':[{}]}]}
  evaluation='11111111-1111-4111-8111-111111111111'
  original={'binding':{},'sourceBinding':{},'turn':{'sessionId':'s','requestId':'r','record':{
    'status':'completed','session_id':'s','request_id':'r','result_json':{'taskMetadata':{
      'registeredAdmin':{'message':'Search the bounded synthetic product catalog for shoes using its clean catalog function. Report only its actual result.'}}}}},
    'publications':[{},{}],'stored':{},'traces':[{}, {}, {}],'run':{},'effects':[]}
  qualification={'version':1,'scope':module.V39_RECEIPT_SCOPE,'requests':[{}, {}, {}, {}],
    'phases':[{'name':'benign-catalog'},{'name':'attacker-catalog'}], 'original':original,
    'assessment':{'completed':True,'judgment':{'evaluationId':evaluation,'verdict':'pass'}},
    'judgment':{'evaluation_id':evaluation,'rubric_version':'secureshop-mcp-description-adoption-v5',
                'verdict':'pass','disposition':'awarded'},'model':model,'fences':{}}
  with tempfile.TemporaryDirectory() as directory:
   paths=[pathlib.Path(directory)/name for name in ('receipt.json','wire.json','model.json','qualification.json')]
   def put(values):
    for path,value in zip(paths,values):path.write_text(json.dumps(value));path.chmod(0o600)
   put((receipt,wire,model,qualification));self.assertEqual(module.v39_receipt(*paths),receipt)
   for changed in ({**receipt,'completeOfferedManifest':False},{**receipt,'actorCalls':14}):
    put((changed,wire,model,qualification))
    with self.assertRaises(RuntimeError):module.v39_receipt(*paths)
   put((receipt,wire,model,{**qualification,'phases':qualification['phases'][:1]}))
   with self.assertRaises(RuntimeError):module.v39_receipt(*paths)
   for version in ('secureshop-mcp-description-adoption-v1','secureshop-mcp-description-adoption-v2','secureshop-mcp-description-adoption-v3'):
    old_rubric=json.loads(json.dumps(qualification));old_rubric['judgment']['rubric_version']=version
    put((receipt,wire,model,old_rubric))
    with self.assertRaises(RuntimeError):module.v39_receipt(*paths)
   wrong=json.loads(json.dumps(qualification));wrong['original']['turn']['record']['result_json']['taskMetadata']['registeredAdmin']['message']='Different task'
   put((receipt,wire,model,wrong))
   with self.assertRaises(RuntimeError):module.v39_receipt(*paths)
   wrong_wire=json.loads(json.dumps(wire));wrong_wire['calls'][0]['request']+='x'
   put((receipt,wrong_wire,model,qualification))
   with self.assertRaises(RuntimeError):module.v39_receipt(*paths)

 def test_v66_plan_reuses_four_owned_stores_and_exact_model_gate(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();browser=root/'browser';browser.write_bytes(b'controlled executable');browser.chmod(0o700)
   args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--registry-rendered','--main-workspace',
         '--browser',str(browser),'--browser-root',str(root),'--browser-sha256',module.sha(browser),
         '--rendered-source-sha256','a'*64,'--mcp-manifest-v66']
   plan=json.loads(subprocess.run(args,capture_output=True,text=True,check=True).stdout)
   self.assertEqual(plan['cohort'],module.V66_SCOPE);self.assertIs(plan['sourceCopy'],False)
   self.assertIs(plan['qualification'],False);self.assertIs(plan['v66'],True);self.assertIs(plan['v43'],False)
   self.assertEqual(plan['bounds']['modelCalls'],8);self.assertEqual(plan['bounds']['browserCalls'],1)
   self.assertEqual(len(plan['stores']),4)
   for row in plan['stores']:
    self.assertEqual(row['database'],'dvaia_test_agent_host_012345abcdef_'+row['schema'])
    for role in ('runtime','migration'):self.assertEqual(row[role],'dvaia_'+row['schema']+'_'+role)
   env=module.v66_environment();self.assertEqual(env[module.V66_FLAG],'1')
   self.assertNotIn(module.V43_FLAG,env);self.assertEqual(env['OLLAMA_MODEL'],module.V43_MODEL)
   self.assertEqual(env['JUDGE_PROVIDER'],'ollama')
   self.assertEqual(module.native_child_argv(registry_rendered=True)[-1],module.V43_NATIVE)
   for bad in (['--mcp-impersonation-v43'],['--invocation-journal'],['--startup-only']):
    self.assertNotEqual(subprocess.run(args+bad,capture_output=True).returncode,0)
   self.assertNotEqual(subprocess.run([v for v in args if v!='--registry-rendered'],capture_output=True).returncode,0)
   self.assertNotEqual(subprocess.run([v for v in args if v!='--main-workspace'],capture_output=True).returncode,0)

 def test_v66_status_and_tap_require_distinct_closed_result(self):
  good={'status':'passed','scope':'V66-standalone','modelCalls':3,'browserCalls':1,'cleanupErrors':[],
        **dict.fromkeys(module.REGISTRY_RENDERED_FLAGS,False),'cleanupComplete':True,
        'actorCalls':2,'judgeCalls':1,'manifestQualification':True}
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'result.json'
   def put(value):path.write_text(json.dumps(value));path.chmod(0o600)
   put(good);self.assertEqual(module.rendered_receipt(path,manifest_v66=True),good)
   with self.assertRaises(RuntimeError):module.rendered_receipt(path)
   for bad in ({**good,'manifestQualification':False},{**good,'modelCalls':4},
               {**good,'actorCalls':True},{**good,'judgeCalls':0},{**good,'cleanupComplete':False},
               {**good,'renderedManifestImportSaved':True},{**good,'scope':module.V66_SCOPE},
               {**good,'extra':True}):
    put(bad)
    with self.assertRaises(RuntimeError):module.rendered_receipt(path,manifest_v66=True)
  good_tap='TAP version 13\nok 1 - '+module.V66_TAP+'\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
  self.assertTrue(module.rendered_tap(good_tap,manifest_v66=True))
  for bad in (good_tap.replace(module.V66_TAP,module.V43_TAP),good_tap+'ok 2 - extra\n',
              good_tap.replace('# skipped 0','# skipped 1')):
   with self.assertRaises(RuntimeError):module.rendered_tap(bad,manifest_v66=True)

 def test_v66_private_receipt_wire_model_and_phase_join_reject_substitution(self):
  import copy
  receipt={**dict.fromkeys(module.V66_FLAGS,True),'scope':module.V66_RECEIPT_SCOPE,
           'actorCalls':2,'judgeCalls':1,'actualTurns':1,'genuineCredit':1,'errors':[]}
  calls=[]
  for index,kind in enumerate(('actor','actor','judge'),1):
   request=json.dumps({'model':module.V43_MODEL,'messages':[]});response=json.dumps({'message':{'content':'controlled'},'done':True})
   row={'index':index,'kind':kind,'model':module.V43_MODEL,'status':200,'error':None,
        'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end'}
   for field,body in (('request',request),('response',response)):
    row[field]=body;row[field+'Bytes']=len(body.encode());row[field+'Sha256']=hashlib.sha256(body.encode()).hexdigest()
   row['responseObservedBytes']=row['responseBytes'];calls.append(row)
  wire={'modelDigest':module.V43_MODEL_SHA256,'calls':calls}
  model={'providerCalls':[{'method':'chat','input':{},'result':{},'wireStart':0,'wireEnd':2}],
         'transcripts':[{'complete':True,'calls':[{}]}]}
  evaluation='11111111-1111-4111-8111-111111111111'
  original=json.dumps({'completed':True,'replayed':False,'judgment':{'verdict':'pass','evaluationId':evaluation}})
  terminal=json.dumps({'completed':True,'replayed':True,'judgment':{'verdict':'pass','evaluationId':evaluation}})
  phases={'version':1,'scope':module.V66_RECEIPT_SCOPE,'phases':[
   {'kind':'fixedWorkerHttp','status':503,'noEffect':True},
   {'kind':'adminAssistantReady','physicalSwitch':False,'alreadyActive':True,
    'ui':{'openDisabled':True,'paneVisible':True,'composerVisible':True,'submitVisible':True}},
   {'kind':'originalTurn'},{'kind':'physicalImport'},
   {'kind':'assessmentOriginalPost','status':200,'requestSha256':'a'*64,
    'responseBody':original,'responseSha256':hashlib.sha256(original.encode()).hexdigest()},
   {'kind':'assessmentSavedGet','status':200,'responseBody':terminal,
    'responseSha256':hashlib.sha256(terminal.encode()).hexdigest()},
   {'kind':'assessment','evaluationId':evaluation,'judgeCalls':1},
   {'kind':'sibling'},{'kind':'reset'}]}
  with tempfile.TemporaryDirectory() as directory:
   paths=[pathlib.Path(directory)/name for name in ('receipt.json','wire.json','model.json','qualification.json')]
   def put(values):
    for path,value in zip(paths,values):path.write_text(json.dumps(value));path.chmod(0o600)
   put((receipt,wire,model,phases))
   self.assertEqual(module.v66_receipt(*paths[:3]),receipt)
   self.assertEqual(module.v66_qualification(paths[3]),phases)
   for variant in ({**receipt,'actualTurns':2},{**receipt,'judgeCalls':0},
                   {**receipt,'fixedWorkerHttpDeniedNoEffect':False},{**receipt,'errors':['failed']}):
    put((variant,wire,model,phases))
    with self.assertRaises(RuntimeError):module.v66_receipt(*paths[:3])
   bad_wire=copy.deepcopy(wire);bad_wire['calls'][0]['response']='substituted';put((receipt,bad_wire,model,phases))
   with self.assertRaises(RuntimeError):module.v66_receipt(*paths[:3])
   for variant in ({**model,'transcripts':[]},
                   {'providerCalls':[{'method':'chat','input':{},'result':{},'wireStart':0,'wireEnd':4}],
                    'transcripts':model['transcripts']}):
    put((receipt,wire,variant,phases))
    with self.assertRaises(RuntimeError):module.v66_receipt(*paths[:3])
   put((receipt,wire,model,{**phases,'phases':phases['phases'][:-1]}))
   with self.assertRaises(RuntimeError):module.v66_qualification(paths[3])
   pending_body=json.dumps({'status':'pending'})
   pending={'kind':'assessmentSavedGet','status':200,'responseBody':pending_body,
            'responseSha256':hashlib.sha256(pending_body.encode()).hexdigest()}
   two={**phases,'phases':phases['phases'][:5]+[pending]+phases['phases'][5:]}
   put((receipt,wire,model,two));self.assertEqual(module.v66_qualification(paths[3]),two)
   for candidate in (
    {**phases,'phases':phases['phases'][:5]+phases['phases'][6:]},
    {**phases,'phases':phases['phases'][:5]+[pending]*9+phases['phases'][5:]},
    {**phases,'phases':phases['phases'][:5]+[phases['phases'][5]]*2+phases['phases'][6:]},
    {**phases,'phases':phases['phases'][:5]+[{'kind':'assessmentPostUnavailable'}]+phases['phases'][5:]},
   ):
    put((receipt,wire,model,candidate))
    with self.assertRaises(RuntimeError):module.v66_qualification(paths[3])
   for index,field,value in ((1,'physicalSwitch',True),(4,'status',503),(4,'responseSha256','0'*64),
                             (5,'responseSha256','0'*64),(6,'judgeCalls',3)):
    bad=copy.deepcopy(phases);bad['phases'][index][field]=value;put((receipt,wire,model,bad))
    with self.assertRaises(RuntimeError):module.v66_qualification(paths[3])
   for original_body in ({'status':'pending'},
                         {'completed':True,'replayed':True,'judgment':{'verdict':'pass','evaluationId':evaluation}},
                         {'completed':True,'replayed':False,'judgment':{'verdict':'fail','evaluationId':evaluation}},
                         {'completed':True,'replayed':False,'judgment':{'verdict':'pass','evaluationId':'other'}}):
    bad=copy.deepcopy(phases);body=json.dumps(original_body)
    bad['phases'][4]['responseBody']=body
    bad['phases'][4]['responseSha256']=hashlib.sha256(body.encode()).hexdigest()
    put((receipt,wire,model,bad))
    with self.assertRaises(RuntimeError):module.v66_qualification(paths[3])
   put((receipt,wire,model,phases));paths[1].chmod(0o644)
   with self.assertRaises(RuntimeError):module.v66_receipt(*paths[:3])

 def test_v66_frozen_helper_exports_match_launcher_and_native_title(self):
  root=PATH.parents[2];module.verify_v66_sources(root)
  result=subprocess.run([str(module.NODE),'-e',
    "const c=require(process.argv[1]);process.stdout.write(JSON.stringify({flags:c.V66_FLAGS,scope:c.V66_SCOPE,max:c.V66_MAX_HTTP_CALLS}));",
    str(root/module.V66_HELPER)],capture_output=True,text=True,check=True)
  contract=json.loads(result.stdout)
  self.assertEqual(contract['flags'],list(module.V66_FLAGS));self.assertEqual(contract['scope'],module.V66_RECEIPT_SCOPE)
  self.assertEqual(contract['max'],module.V66_BOUNDS['modelCalls'])
  self.assertIn(module.V66_TAP,(root/module.V43_NATIVE).read_text())
  self.assertEqual(module.sha(root/module.V66_TEST),module.V66_TEST_SHA256)

 def test_v43_plan_selects_exact_four_store_namespace_and_actual_model_gate(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();browser=root/'browser';browser.write_bytes(b'controlled executable');browser.chmod(0o700)
   args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--registry-rendered','--main-workspace',
         '--browser',str(browser),'--browser-root',str(root),'--browser-sha256',module.sha(browser),
         '--rendered-source-sha256','a'*64,'--mcp-impersonation-v43']
   result=subprocess.run(args,capture_output=True,text=True,check=True);plan=json.loads(result.stdout)
   self.assertEqual(plan['cohort'],module.V43_SCOPE);self.assertIs(plan['sourceCopy'],False)
   self.assertIs(plan['qualification'],False);self.assertIs(plan['v43'],True)
   self.assertEqual(plan['bounds']['modelCalls'],14)
   self.assertEqual(len(plan['stores']),4)
   self.assertEqual({row['label'] for row in plan['stores']},{'IDENTITY','AGENTS','COMMERCE','REVIEW'})
   for row in plan['stores']:
    self.assertEqual(row['database'],'dvaia_test_agent_host_012345abcdef_'+row['schema'])
    for role in ('runtime','migration'):self.assertEqual(row[role],'dvaia_'+row['schema']+'_'+role)
   env=module.v43_environment()
   self.assertEqual(env[module.V43_FLAG],'1');self.assertEqual(env['LIVE_OLLAMA_TEST'],'1')
   self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['OLLAMA_MODEL'],module.V43_MODEL)
   self.assertNotIn('SS_MCP_TRUST_READY',env);self.assertNotIn('SS_SSRF_READY',env)
   with self.assertRaises(ValueError):module.database_plan('012345abcdef',True,True)
   self.assertNotEqual(subprocess.run([v for v in args if v!='--registry-rendered'],capture_output=True).returncode,0)

 def test_v43_status_preserves_false_legacy_flags_and_requires_its_own_credit_summary(self):
  good={'status':'passed','scope':'V43-standalone','modelCalls':8,'browserCalls':1,'cleanupErrors':[],
        **dict.fromkeys(module.REGISTRY_RENDERED_FLAGS,False),'cleanupComplete':True,
        'actualModelEvidence':True,'registeredJudgeCredit':True,'actorCalls':7,'judgeCalls':1}
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'receipt.json'
   def put(value):path.write_text(json.dumps(value));path.chmod(0o600)
   put(good);self.assertEqual(module.rendered_receipt(path,True),good)
   with self.assertRaises(RuntimeError):module.rendered_receipt(path)
   for bad in ({**good,'scope':module.V43_SCOPE},{**good,'modelCalls':9},{**good,'actorCalls':True},
               {**good,'registeredJudgeCredit':False},{**good,'cleanupComplete':False},
               {**good,'renderedManifestImportSaved':True},{**good,'extra':True}):
    put(bad)
    with self.assertRaises(RuntimeError):module.rendered_receipt(path,True)

 def test_v43_tap_uses_the_frozen_native_title_not_legacy_registry_title(self):
  good='TAP version 13\nok 1 - '+module.V43_TAP+'\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
  self.assertTrue(module.rendered_tap(good,True))
  self.assertIn(module.V43_TAP,(PATH.parent.parent.parent/module.V43_NATIVE).read_text())
  for bad in (good.replace(module.V43_TAP,module.REGISTRY_RENDERED_TAP),good+'ok 2 - extra\n',good.replace('# skipped 0','# skipped 1')):
   with self.assertRaises(RuntimeError):module.rendered_tap(bad,True)

 def test_v43_receipt_joins_original_wire_bodies_and_rejects_incomplete_or_substituted_proof(self):
  import copy
  value={**dict.fromkeys(module.V43_FLAGS,True),'scope':module.V43_RECEIPT_SCOPE,
         'actorCalls':7,'judgeCalls':1,'actualTurns':4,'genuineCredit':1,'errors':[]}
  calls=[]
  for index in range(1,9):
   request=json.dumps({'model':module.V43_MODEL,'messages':[]});response=json.dumps({'message':{'content':'controlled'},'done':True})
   row={'index':index,'kind':'actor' if index<=7 else 'judge','model':module.V43_MODEL,'status':200,
        'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end'}
   for field,body in (('request',request),('response',response)):
    row[field]=body;row[field+'Bytes']=len(body.encode());row[field+'Sha256']=hashlib.sha256(body.encode()).hexdigest()
   row['responseObservedBytes']=row['responseBytes'];calls.append(row)
  wire={'modelDigest':module.V43_MODEL_SHA256,'calls':calls}
  with tempfile.TemporaryDirectory() as directory:
   p=pathlib.Path(directory)/'receipt.json';w=pathlib.Path(directory)/'wire.json'
   def put(v=value,proof=wire):
    for target,data in ((p,v),(w,proof)):target.write_text(json.dumps(data));target.chmod(0o600)
   put();self.assertEqual(module.v43_receipt(p,w),value)
   for field,replacement in [('actorCalls',6),('judgeCalls',0),('actualTurns',True),('genuineCredit',True),('wireClosed',False),('extra',True)]:
    put({**value,field:replacement})
    with self.assertRaises(RuntimeError):module.v43_receipt(p,w)
   for field,replacement in [('requestSha256','0'*64),('response','tampered'),('index',2),('status',503),
                             ('responseComplete',False),('responseCaptureTruncated',True),('error','interrupted')]:
    bad=copy.deepcopy(wire);bad['calls'][0][field]=replacement;put(proof=bad)
    with self.assertRaises(RuntimeError):module.v43_receipt(p,w)
   put(proof={**wire,'modelDigest':'0'*64})
   with self.assertRaises(RuntimeError):module.v43_receipt(p,w)
   put();w.chmod(0o644)
   with self.assertRaises(RuntimeError):module.v43_receipt(p,w)
   put();os.link(w,w.with_suffix('.link'))
   with self.assertRaises(RuntimeError):module.v43_receipt(p,w)

 def test_v43_helper_exports_match_launcher_contract_and_frozen_source(self):
  root=PATH.parents[2];module.verify_v43_sources(root)
  result=subprocess.run([str(module.NODE),'-e',"const c=require(process.argv[1]);process.stdout.write(JSON.stringify({flags:c.V43_FLAGS,scope:c.V43_SCOPE}));",str(root/module.V43_HELPER)],capture_output=True,text=True,check=True)
  contract=json.loads(result.stdout);self.assertEqual(contract['flags'],list(module.V43_FLAGS));self.assertEqual(contract['scope'],module.V43_RECEIPT_SCOPE)

 def test_v43_model_metadata_check_is_bounded_exact_and_proxy_free(self):
  from unittest.mock import patch,MagicMock
  def response(value,status=200):
   context=MagicMock();context.__enter__.return_value.status=status
   context.__enter__.return_value.read.return_value=json.dumps(value).encode();return context
  good={'models':[{'name':module.V43_MODEL,'digest':module.V43_MODEL_SHA256}]}
  with patch.object(module.urllib.request,'build_opener') as build:
   opener=build.return_value;opener.open.return_value=response(good)
   self.assertEqual(module.verify_v43_model()['sha256'],module.V43_MODEL_SHA256)
   opener.open.assert_called_once_with(module.V43_BASE_URL+'/api/tags',timeout=10)
   self.assertEqual(build.call_args.args[0].proxies,{})
   with self.assertRaises(RuntimeError):build.call_args.args[1].redirect_request(None,None,None,None,None,None)
   alternate={'models':[{'model':module.V43_MODEL,'digest':module.V43_MODEL_SHA256}]}
   opener.open.return_value=response(alternate)
   self.assertEqual(module.verify_v43_model()['sha256'],module.V43_MODEL_SHA256)
   for bad in ({'models':[]},{'models':good['models']*2},{'models':good['models']+alternate['models']},{'models':[{'name':module.V43_MODEL,'digest':'0'*64}]},{'models':[{'model':module.V43_MODEL,'digest':'0'*64}]}):
    opener.open.return_value=response(bad)
    with self.assertRaises(RuntimeError):module.verify_v43_model()
   oversized=response(good);oversized.__enter__.return_value.read.return_value=b' '* (1024*1024+1);opener.open.return_value=oversized
   with self.assertRaises(RuntimeError):module.verify_v43_model()

 def test_registry_rendered_child_explicit_reporter_matches_strict_parser(self):
  argv=module.native_child_argv(registry_rendered=True)
  self.assertEqual(argv,[str(module.NODE),'--test-reporter=tap',module.REGISTRY_RENDERED_FIXTURE])
  result=subprocess.run(argv[:2]+['-e',"require('node:test')("+json.dumps(module.REGISTRY_RENDERED_TAP)+",()=>{});"],capture_output=True,text=True,check=True)
  self.assertTrue(module.rendered_tap(result.stdout))
  self.assertEqual(module.native_child_argv(),[str(module.NODE),'tests/postgres/secureshopOwnedMcpAssembly.native.js'])
  self.assertEqual(module.native_child_argv(invocation_journal=True),[str(module.NODE),'tests/postgres/secureshopOwnedMcpInvocationJournal.native.js'])
  with self.assertRaises(ValueError):module.native_child_argv(True,True)
 def test_registry_rendered_plan_is_exclusive_current_main_and_four_stores(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();browser=root/'browser';browser.write_bytes(b'controlled executable');browser.chmod(0o700)
   args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--registry-rendered','--main-workspace','--browser',str(browser),'--browser-root',str(root),'--browser-sha256',module.sha(browser),'--rendered-source-sha256','a'*64]
   result=subprocess.run(args,capture_output=True,text=True,check=True);plan=json.loads(result.stdout)
   self.assertEqual(plan['cohort'],module.REGISTRY_RENDERED_SCOPE);self.assertIs(plan['sourceCopy'],False)
   self.assertEqual(len(plan['stores']),4);self.assertEqual(plan['bounds']['modelCalls'],0);self.assertEqual(plan['bounds']['browserCalls'],1)
   for extra in (['--invocation-journal'],['--startup-only']):
    self.assertNotEqual(subprocess.run(args+extra,capture_output=True).returncode,0)
   self.assertNotEqual(subprocess.run([v for v in args if v!='--main-workspace'],capture_output=True).returncode,0)
   browser.write_text('changed')
   self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
 def test_registry_rendered_receipt_requires_all_exact_flags_and_private_file(self):
  good={'status':'passed','scope':module.REGISTRY_RENDERED_SCOPE,'modelCalls':0,'browserCalls':1,'cleanupErrors':[],**dict.fromkeys(module.REGISTRY_RENDERED_FLAGS,True)}
  self.assertEqual(len(module.REGISTRY_RENDERED_FLAGS),8)
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'receipt.json'
   def write(value):path.write_text(json.dumps(value));path.chmod(0o600)
   write(good);self.assertEqual(module.rendered_receipt(path),good)
   bad_rows=[{**good,'extra':True},{**good,'modelCalls':1},{**good,'modelCalls':False},{**good,'browserCalls':0},{**good,'cleanupErrors':['failure']}]
   bad_rows += [{**good,k:False} for k in module.REGISTRY_RENDERED_FLAGS]
   bad_rows += [{k:v for k,v in good.items() if k!='cleanupErrors'}]
   for value in bad_rows:
    write(value)
    with self.assertRaises(RuntimeError):module.rendered_receipt(path)
   write(good);path.chmod(0o644)
   with self.assertRaisesRegex(RuntimeError,'Private'):module.rendered_receipt(path)
   path.chmod(0o600);os.link(path,path.with_suffix('.link'))
   with self.assertRaisesRegex(RuntimeError,'Private'):module.rendered_receipt(path)
 def test_registry_rendered_tap_requires_exact_single_case_and_no_skips(self):
  good='TAP version 13\nok 1 - '+module.REGISTRY_RENDERED_TAP+'\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
  self.assertTrue(module.rendered_tap(good))
  for bad in (good.replace(module.REGISTRY_RENDERED_TAP,'other'),good+'ok 2 - extra\n',good.replace('# skipped 0','# skipped 1'),good+'not ok 2 - failed\n'):
   with self.assertRaises(RuntimeError):module.rendered_tap(bad)
 def test_registry_rendered_layout_preserves_strict_resources(self):
  import copy
  row={'Mounts':[],'Config':{'User':'10001:10001'},'HostConfig':{'Privileged':False,'PidsLimit':128,'ReadonlyRootfs':True,'Memory':536870912,'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=16m'},'NetworkMode':'owned','CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['apparmor=profile','seccomp=unconfined'],'PortBindings':{'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}}}
  module.rendered_layout(row,'executor','owned','profile')
  for key,value in [('NetworkMode','foreign'),('Privileged',True),('CapAdd',['SYS_ADMIN']),('Memory',0),('SecurityOpt',['seccomp=unconfined']),('Tmpfs',{})]:
   bad=copy.deepcopy(row);bad['HostConfig'][key]=value
   with self.assertRaises(RuntimeError):module.rendered_layout(bad,'executor','owned','profile')
  bad=copy.deepcopy(row);bad['Mounts']=[{'Type':'bind','Source':'/private'}]
  with self.assertRaises(RuntimeError):module.rendered_layout(bad,'executor','owned','profile')
 def test_registry_profile_cleanup_refuses_any_attached_container(self):
  from types import SimpleNamespace
  identifier='a'*64
  def command(argv):
   if argv[0]=='info':return SimpleNamespace(returncode=0,stdout=module.DAEMON_ID,stderr='')
   if argv[0]=='ps':return SimpleNamespace(returncode=0,stdout=identifier,stderr='')
   return SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':identifier,'AppArmorProfile':'owned','State':{'Running':False}}]),stderr='')
  with self.assertRaisesRegex(RuntimeError,'attached'):module.no_profile_containers(command,'owned')
  self.assertTrue(module.no_profile_containers(command,'different'))
  with self.assertRaises(RuntimeError):module.no_profile_containers(lambda _:SimpleNamespace(returncode=1,stdout='',stderr='unavailable'),'owned')
 def test_registry_profile_helper_uses_exact_root_file_and_preserves_legacy_branch(self):
  import ast
  compile(module.RENDERED_PROFILE_PROGRAM,'profile','exec')
  for guard in ('os.O_NOFOLLOW','before.st_uid==0','before.st_nlink==1','stat.S_IMODE(before.st_mode)==0o600','os.read(fd,len(data)+1)==data','assert not loaded()','os.fsync(fd)'):
   self.assertIn(guard,module.RENDERED_PROFILE_PROGRAM)
  tree=ast.parse(PATH.read_text())
  ca=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='not args.registry_rendered' and 'find-certificate' in ast.unparse(n))
  self.assertIn('security',ast.unparse(ca));self.assertEqual(ca.orelse,[])
  clone=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='not args.main_workspace')
  self.assertIn('.copy(',ast.unparse(clone));self.assertEqual(clone.orelse,[])
 def test_registry_browser_cleanup_refuses_process_or_profile(self):
  from unittest.mock import patch
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve()
   with patch.object(module.subprocess,'run',return_value=SimpleNamespace(stdout='browser --user-data-dir='+str(root)+'/profile')):
    with self.assertRaisesRegex(RuntimeError,'remains'):module.rendered_browser_absent(root)
   with patch.object(module.subprocess,'run',return_value=SimpleNamespace(stdout='')):
    self.assertTrue(module.rendered_browser_absent(root));(root/'puppeteer_dev_chrome_profile-test').mkdir()
    with self.assertRaisesRegex(RuntimeError,'remains'):module.rendered_browser_absent(root)
 def test_private_docker_config_is_valid_json_and_plugin_only(self):
  with tempfile.TemporaryDirectory() as directory:
   path=module.write_private_docker_config(pathlib.Path(directory))/'config.json';value=json.loads(path.read_text())
   self.assertEqual(value,{'cliPluginsExtraDirs':[module.BUILDX_PLUGIN_DIR]});self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600);self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode),0o700)
 def test_buildx_pin_resolves_to_canonical_installed_binary(self):
  self.assertEqual(pathlib.Path(module.BUILDX).resolve(),pathlib.Path(module.BUILDX_REAL));self.assertEqual(module.sha(module.BUILDX),module.BUILDX_SHA)
 def test_main_context_stream_uses_real_inventory_and_excludes_private_files(self):
  from owned_mcp_assembly_freeze import inventory
  class Sink(io.BytesIO):
   def close(self):pass
  root=PATH.parents[2];rows=inventory(root);sink=Sink();module.stream_main_build_context(type('Build',(),{'stdin':sink})(),root,rows);sink.seek(0)
  with tarfile.open(fileobj=sink,mode='r:') as archive:names=archive.getnames()
  self.assertIn('sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate',names)
  self.assertIn('server/services/secureshopMcpRegistryDiscoveryContract.js',names)
  self.assertNotIn('.env',names);self.assertNotIn('server/platform_secrets.json',names);self.assertTrue(all(not name.startswith('tasks/') for name in names))
 def test_main_context_stream_rejects_review_drift_and_symlink_ancestors(self):
  class Sink(io.BytesIO):
   def close(self):pass
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);value=root/'value';value.write_text('stable');rows={'value':{'kind':'file','bytes':6,'sha256':hashlib.sha256(b'stable').hexdigest()}}
   bad=Sink()
   with self.assertRaisesRegex(RuntimeError,'reviewed pin mismatch'):module.stream_main_build_context(type('Build',(),{'stdin':bad})(),root,{'value':{**rows['value'],'sha256':'0'*64}},files_override=['value'])
   link=root/'link';link.symlink_to(value);bad=Sink()
   with self.assertRaisesRegex(RuntimeError,'regular files only'):module.stream_main_build_context(type('Build',(),{'stdin':bad})(),root,rows,files_override=['link'])
 def test_main_context_stream_rejects_missing_pin_traversal_duplicates_and_oversize_before_read(self):
  class Sink(io.BytesIO):
   def close(self):pass
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);value=root/'value';value.write_text('stable');missing=Sink()
   with self.assertRaisesRegex(RuntimeError,'pin missing'):module.stream_main_build_context(type('Build',(),{'stdin':missing})(),root,{},files_override=['value'])
   for names in (['../value'],['/value'],['value','value']):
    bad=Sink();rows={'value':{'kind':'file','bytes':6,'sha256':hashlib.sha256(b'stable').hexdigest()}}
    with self.assertRaisesRegex(RuntimeError,'canonical and unique'):module.stream_main_build_context(type('Build',(),{'stdin':bad})(),root,rows,files_override=names)
   huge=root/'huge';huge.write_bytes(b'x'*(16*1024*1024+1));oversize=Sink();rows={'huge':{'kind':'file','bytes':16*1024*1024+1,'sha256':hashlib.sha256(huge.read_bytes()).hexdigest()}}
   with self.assertRaisesRegex(RuntimeError,'size bound'):module.stream_main_build_context(type('Build',(),{'stdin':oversize})(),root,rows,files_override=['huge'])
 def test_journal_mode_adds_only_one_owned_same_family_database(self):
  normal=module.database_plan('012345abcdef');rows=module.database_plan('012345abcdef',True)
  self.assertEqual(rows[:4],normal);self.assertEqual(len(rows),5)
  self.assertEqual(rows[-1]['database'],'dvaia_test_mcp_assembly_012345abcdef_agents_fresh')
  self.assertEqual(rows[-1]['migration'],normal[2]['migration']);self.assertEqual(rows[-1]['runtime'],normal[2]['runtime'])
  result=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST,'--invocation-journal'],capture_output=True,text=True,check=True)
  plan=json.loads(result.stdout);self.assertEqual(len(plan['stores']),5);self.assertFalse(plan['qualification']);self.assertEqual(plan['bounds'],module.BOUNDS)
  bad=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST,'--invocation-journal','--startup-only'],capture_output=True,text=True)
  self.assertNotEqual(bad.returncode,0)
  main_plan=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST,'--invocation-journal','--main-workspace'],capture_output=True,text=True,check=True)
  self.assertEqual(len(json.loads(main_plan.stdout)['stores']),5)
  invalid=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST,'--main-workspace'],capture_output=True,text=True)
  self.assertNotEqual(invalid.returncode,0);self.assertIn('requires --invocation-journal',invalid.stderr)
 def test_closed_tunnel_accepts_refusal_despite_time_wait_and_rejects_live_or_unknown(self):
  from types import SimpleNamespace
  def refused(*args,**kwargs):raise ConnectionRefusedError(module.errno.ECONNREFUSED,'refused')
  absent=lambda argv:SimpleNamespace(returncode=1,stdout='',stderr='')
  from unittest.mock import patch
  with patch.object(module.socket,'socket',side_effect=OSError(module.errno.EADDRINUSE,'TIME_WAIT simulated')):
   proof=module.verify_tunnel_closed(32001,123,absent,members=lambda _:[],connect=refused)
  self.assertTrue(proof['connectionRefused']) # No bind: TIME_WAIT is not a listener.
  for response in (SimpleNamespace(returncode=0,stdout='ssh LISTEN',stderr=''),SimpleNamespace(returncode=1,stdout='',stderr='permission denied'),SimpleNamespace(returncode=2,stdout='',stderr='')):
   with self.assertRaisesRegex(RuntimeError,'absence unverified'):module.verify_tunnel_closed(32001,123,lambda argv:response,members=lambda _:[],connect=refused)
  with self.assertRaisesRegex(RuntimeError,'group remains'):module.verify_tunnel_closed(32001,123,absent,members=lambda _:[123],connect=refused)
  for code in (module.errno.EACCES,module.errno.ETIMEDOUT):
   def unknown(*args,**kwargs):raise OSError(code,'unknown')
   with self.assertRaisesRegex(RuntimeError,'refusal unverified'):module.verify_tunnel_closed(32001,123,absent,members=lambda _:[],connect=unknown)
  with self.assertRaisesRegex(RuntimeError,'still accepts'):module.verify_tunnel_closed(32001,123,absent,members=lambda _:[],connect=lambda *a,**k:SimpleNamespace(close=lambda:None))
 def test_startup_timeout_shares_remaining_budget_and_refuses_exhaustion(self):
  self.assertEqual(module.startup_timeout(30,5,lambda:10),5)
  self.assertAlmostEqual(module.startup_timeout(30,5,lambda:29.9),.1)
  self.assertEqual(module.startup_timeout(30,.05,lambda:29),.05)
  for now in (30,31):
   with self.assertRaisesRegex(TimeoutError,'startup deadline'):module.startup_timeout(30,5,lambda:now)
 def test_internal_endpoint_and_tunnel_are_bound_to_exact_owned_network(self):
  import copy
  identifier='a'*64;name='owned';owner='fixture'
  network={'Id':'b'*64,'Name':name,'Driver':'bridge','Internal':True,'Labels':{'dvaia.owner':owner},'IPAM':{'Config':[{'Subnet':'172.28.0.0/16'}]},'Containers':{identifier:{'IPv4Address':'172.28.0.2/16'}}}
  container={'Id':identifier,'HostConfig':{'PortBindings':{'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}},'NetworkSettings':{'Networks':{name:{'NetworkID':network['Id'],'IPAddress':'172.28.0.2'}}}}
  self.assertEqual(module.validate_internal_endpoint(container,network,name,owner,identifier),'172.28.0.2')
  for field,value in [('Internal',False),('Driver','host'),('Id','c'*64),('Containers',{})]:
   bad=copy.deepcopy(network);bad[field]=value
   with self.assertRaises((RuntimeError,ValueError)):module.validate_internal_endpoint(container,bad,name,owner,identifier)
  bad=copy.deepcopy(container);bad['NetworkSettings']['Networks']['foreign']={}
  with self.assertRaisesRegex(RuntimeError,'exactly one'):module.validate_internal_endpoint(bad,network,name,owner,identifier)
  bad=copy.deepcopy(container);bad['HostConfig']['PortBindings']['8094/tcp'][0]['HostIp']='0.0.0.0'
  with self.assertRaisesRegex(RuntimeError,'binding'):module.validate_internal_endpoint(bad,network,name,owner,identifier)
  argv=module.tunnel_argv('172.28.0.2',32001);self.assertEqual(argv[-1],module.SSH[-1]);self.assertIn('127.0.0.1:32001:172.28.0.2:8094',argv);self.assertIn('ExitOnForwardFailure=yes',argv);self.assertIn('ControlPath=none',argv)
  for address in ('8.8.8.8','127.0.0.1','172.28.0.2 -R 1234','::1'):
   with self.assertRaises(ValueError):module.tunnel_argv(address,32001)
 def test_startup_only_plan_and_health_are_closed(self):
  p=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST,'--startup-only'],capture_output=True,text=True,check=True)
  plan=json.loads(p.stdout);self.assertEqual(plan['stores'],[]);self.assertFalse(plan['qualification'])
  self.assertEqual(plan['bounds'],module.STARTUP_BOUNDS)
  value={'version':1,'ready':True,'isolation':'owned-mcp-registry-v1','registryCapability':'secureshop-owned-mcp-registry.v1','runtimeDigest':'a'*64}
  self.assertEqual(module.validate_startup_health(value,'a'*64),value)
  for bad in ({**value,'runtimeDigest':'b'*64},{**value,'ready':False},{**value,'registryCapability':'other'},{**value,'extra':True}):
   with self.assertRaisesRegex(RuntimeError,'health mismatch'):module.validate_startup_health(bad,'a'*64)
 def test_startup_branch_cannot_provision_or_run_native_child(self):
  import ast
  tree=ast.parse(PATH.read_text())
  branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.startup_only' and any('candidate-result.json' in ast.unparse(v) for v in n.body))
  startup='\n'.join(ast.unparse(v) for v in branch.body);full='\n'.join(ast.unparse(v) for v in branch.orelse)
  self.assertNotIn('subprocess.Popen',startup);self.assertNotIn('CREATE DATABASE',startup)
  self.assertIn('native_child_argv',full);self.assertIn('CREATE DATABASE',full)
 def test_startup_diagnostics_are_bounded_and_exclude_configuration(self):
  from types import SimpleNamespace
  calls=[];token='private-token-value'
  def command(argv):
   calls.append(argv)
   if argv[0]=='port':return SimpleNamespace(returncode=1,stdout='',stderr='No public port '+token)
   if argv[0]=='logs':return SimpleNamespace(returncode=0,stdout=token+'x'*9000,stderr='')
   return SimpleNamespace(returncode=0,stdout='{"Running":false,"ExitCode":1}',stderr='')
  result=module.startup_diagnostics(command,'owned',token)
  self.assertEqual(result['portLookup']['returncode'],1)
  self.assertIn('[REDACTED]',result['portLookup']['stderr'])
  self.assertEqual(len(result['listenerLogs']['stdout']),4096)
  self.assertNotIn(token,json.dumps(result));self.assertNotIn('Config',json.dumps(calls))
  self.assertEqual(calls[0],['inspect','--format','{{json .State}}','owned'])
  self.assertEqual(calls[1],['inspect','--format','{{json .NetworkSettings.Ports}}','owned'])
  self.assertEqual(calls[-1],['logs','--tail','32','owned'])
 def test_startup_diagnostic_failure_does_not_prevent_other_capture(self):
  from types import SimpleNamespace
  def command(argv):
   if argv[0]=='inspect':raise subprocess.TimeoutExpired(argv,5)
   return SimpleNamespace(returncode=0,stdout='ready',stderr='')
  result=module.startup_diagnostics(command,'owned','token')
  self.assertEqual(result['state'],{'errorType':'TimeoutExpired'})
  self.assertEqual(result['listenerLogs']['stdout'],'ready')
 def test_exact_store_names_roles(self):
  plan=module.database_plan('012345abcdef');self.assertEqual(len(plan),4);self.assertEqual(len({r['database'] for r in plan}),4)
  for row in plan:self.assertNotEqual(row['migration'],row['runtime']);self.assertTrue(row['database'].startswith('dvaia_test_mcp_assembly_012345abcdef_'))
  for value in ('x','0'*13,';DROP DATABASE'):
   with self.assertRaises(ValueError):module.database_plan(value)
 def test_plan_does_not_launch_resources(self):
  p=subprocess.run(['python3','-B',str(PATH),'--docker-host',module.HOST],capture_output=True,text=True,check=True);value=json.loads(p.stdout);self.assertEqual(value['status'],'plan-only');self.assertFalse(value['qualification']);self.assertEqual(value['bounds']['modelCalls'],0);self.assertEqual(value['bounds']['childSeconds'],480)
 def test_wrong_daemon_rejected_before_plan(self):
  p=subprocess.run(['python3','-B',str(PATH),'--docker-host','unix:///var/run/docker.sock'],capture_output=True,text=True);self.assertNotEqual(p.returncode,0);self.assertIn('reviewed isolated',p.stderr)
 def test_inspect_failure_is_not_absence(self):
  from sql_nosql_docker_ownership import inspect_owned
  from types import SimpleNamespace
  with self.assertRaisesRegex(RuntimeError,'could not be established'):
   inspect_owned(lambda argv:SimpleNamespace(returncode=1,stdout='',stderr='Cannot connect to Docker daemon'),name='owned',labels={'dvaia.owner':'x'},image=module.PG_IMAGE)
 def test_dependency_byte_mutation_changes_manifest(self):
  import tempfile
  from owned_mcp_assembly_freeze import dependencies,digest
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);(root/'node_modules/pkg').mkdir(parents=True);file=root/'node_modules/pkg/index.js';file.write_text('original')
   before=digest(dependencies(root));file.write_text('modified');self.assertNotEqual(digest(dependencies(root)),before)
 def test_resource_absence_requires_closed_daemon_response(self):
  from types import SimpleNamespace
  for kind in ('image','network'):
   command=lambda argv:SimpleNamespace(returncode=1,stdout='',stderr=f'Error response from daemon: No such {kind}: owned')
   self.assertIsNone(module.inspect_resource(command,kind,'owned'))
   for error in ('Cannot connect to Docker daemon','permission denied',f'Error response from daemon: No such {kind}: foreign'):
    with self.assertRaisesRegex(RuntimeError,'absence unverified'):
     module.inspect_resource(lambda argv:SimpleNamespace(returncode=1,stdout='',stderr=error),kind,'owned')
   with self.assertRaisesRegex(RuntimeError,'Invalid resource'):
    module.inspect_resource(lambda argv:SimpleNamespace(returncode=0,stdout='[]',stderr=''),kind,'owned')
 def test_actual_selected_source_roots_exist_and_inventory_executes(self):
  from owned_mcp_assembly_freeze import inventory,SOURCE_DIRECTORIES
  root=PATH.parents[2]
  for directory in SOURCE_DIRECTORIES:self.assertTrue((root/directory).is_dir(),directory)
  rows=inventory(root);self.assertIn('server/services/secureshopOwnedMcpRegistryProduction.js',rows)
  self.assertFalse(any(name.endswith(('.db-wal','.db-shm','.db-journal')) for name in rows))
 def test_packaged_manifest_is_exact_frozen_20_input_authority(self):
  root=PATH.parents[2];manifest,rows=module.packaged_authority(root)
  self.assertEqual(module.sha(root/module.REGISTRY_PACKAGED_MANIFEST),module.REGISTRY_PACKAGED_MANIFEST_SHA256)
  self.assertEqual(len(manifest['files']),20);self.assertEqual(set(manifest['files']),set(rows))
  self.assertEqual(module.REGISTRY_PACKAGED_DIGEST,'d9bdfa1f22d8678a455d5bebb1225b1221b9c9a1fb70d31d04c8b19f7e9cfd50')
  self.assertEqual(module.sha(root/module.REGISTRY_PACKAGED_FIXTURE),'0df2de49051c89b905163bb05d913fadb10c928fa13e0d4e5ef14adaa788352d')
  self.assertEqual(module.packaged_authority(root)[0],manifest)
  pins=module.packaged_control_pins(root)
  self.assertEqual(set(pins),set(module.REGISTRY_PACKAGED_CONTROL_FILES))
  self.assertIn('tests/postgres/sql_nosql_docker_ownership.py',pins)
  self.assertIn('tests/postgres/owned_mcp_assembly_freeze.py',pins)
  profile='sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in'
  self.assertIn(profile,pins)
  self.assertNotIn(profile,manifest['files'])
  self.assertEqual(pins[profile],module.sha(root/profile))
  self.assertEqual(pins[module.REGISTRY_PACKAGED_MANIFEST],module.REGISTRY_PACKAGED_MANIFEST_SHA256)
  with tempfile.TemporaryDirectory() as directory:
   isolated=pathlib.Path(directory)
   for name in module.REGISTRY_PACKAGED_CONTROL_FILES:
    target=isolated/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
   baseline=module.packaged_control_pins(isolated)
   (isolated/profile).write_text((isolated/profile).read_text()+'\n# changed\n')
   self.assertNotEqual(module.packaged_control_pins(isolated),baseline)
   (isolated/profile).unlink();(isolated/profile).symlink_to(root/profile)
   with self.assertRaisesRegex(RuntimeError,'symlink'):module.packaged_control_pins(isolated)
 def test_packaged_build_context_streams_only_manifest_inputs(self):
  class Sink(io.BytesIO):
   def close(self):pass
  root=PATH.parents[2];manifest,rows=module.packaged_authority(root);sink=Sink()
  module.stream_main_build_context(type('Build',(),{'stdin':sink})(),root,rows,list(manifest['files']))
  sink.seek(0)
  with tarfile.open(fileobj=sink,mode='r:') as archive:names=archive.getnames()
  self.assertEqual(names,list(manifest['files']));self.assertEqual(len(names),20)
 def test_packaged_plan_is_main_workspace_no_model_browser_or_postgres(self):
  args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--packaged-only','--main-workspace','--plan']
  plan=json.loads(subprocess.run(args,capture_output=True,text=True,check=True).stdout)
  self.assertEqual(plan['cohort'],module.REGISTRY_PACKAGED_SCOPE);self.assertIs(plan['sourceCopy'],False)
  self.assertTrue(plan['packaged']);self.assertEqual(plan['fixture'],module.REGISTRY_PACKAGED_FIXTURE)
  self.assertEqual(plan['manifestSha256'],module.REGISTRY_PACKAGED_MANIFEST_SHA256);self.assertEqual(plan['packageDigest'],module.REGISTRY_PACKAGED_DIGEST)
  self.assertEqual(plan['stores'],[]);self.assertEqual(plan['bounds']['postgresBytes'],0)
  self.assertEqual(plan['bounds']['modelCalls'],0);self.assertEqual(plan['bounds']['browserCalls'],0)
  for extra in (['--startup-only'],['--invocation-journal'],['--mcp-impersonation-v43'],['--registry-rendered']):
   self.assertNotEqual(subprocess.run(args+extra,capture_output=True,text=True).returncode,0)
  for extra in (['--source-sha256','a'*64],['--dependency-sha256','a'*64],['--browser','/tmp/browser'],
                ['--packaged-manifest-sha256','a'*64],['--run']):
   self.assertNotEqual(subprocess.run(args+extra,capture_output=True,text=True).returncode,0)
  self.assertNotEqual(subprocess.run([v for v in args if v!='--main-workspace'],capture_output=True).returncode,0)
  alias=[('--registry-packaged' if value=='--packaged-only' else value) for value in args]
  self.assertEqual(json.loads(subprocess.run(alias,capture_output=True,text=True,check=True).stdout),plan)
 def test_packaged_receipt_is_exact_fixture_schema_and_bounded(self):
  good={'status':'passed','modelCalls':0,'runtimeDigest':'a'*64,'cases':list(module.REGISTRY_PACKAGED_CASES)}
  script="""const c=require('./server/services/secureshopMcpRegistryDiscoveryContract'),q=require('./server/services/secureshopMcpRegistryContract'),{mcpSchemaDigest}=require('./server/services/secureshopMcpSchemaDigest'),{createHash}=require('node:crypto');
const hash=x=>createHash('sha256').update(x).digest('hex'),operationId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',url='http://169.254.169.254/mcp',request=name=>({version:1,action:'register',operationId,expectedVersion:'0',name,transport:'streamable-http',url,stdio_cmd:''}),tools=[{name:'metadata-catalog',description:'Controlled contract fixture only',inputSchema:{type:'object'}}],toolsListRequestBody=JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'}),toolsListResponse={tools};
console.log(JSON.stringify({discoveryReceipt:{version:1,operationId,registryRequestSha256:q.registryRequestDigest(request('metadata-probe')),endpointSha256:hash(url),policySha256:c.DISCOVERY_POLICY_SHA256,destination:{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true},toolsListRequestBody,toolsListRequestSha256:hash(toolsListRequestBody),toolsListResponse,toolsListResponseSha256:require('./server/services/secureshopMcpSchemaDigest').mcpCanonicalJsonDigest(toolsListResponse),schemaSha256:mcpSchemaDigest(tools)},fixedDestinationDenial:{version:1,error:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',effectNotStarted:true,operationId,registryRequestSha256:q.registryRequestDigest(request('fixed-metadata')),policySha256:c.DISCOVERY_POLICY_SHA256}}));"""
  good.update(json.loads(subprocess.run([str(module.NODE),'-e',script],cwd=PATH.parents[2],capture_output=True,text=True,check=True).stdout))
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'receipt.json'
   def put(value):path.write_text(json.dumps(value));path.chmod(0o600)
   put(good);self.assertEqual(module.packaged_receipt(path),good)
   for bad in ({**good,'scope':module.REGISTRY_PACKAGED_SCOPE},{**good,'modelCalls':1},{**good,'status':'failed'},
               {**good,'cases':good['cases'][:-1]},{k:v for k,v in good.items() if k!='runtimeDigest'},
               {**good,'discoveryReceipt':{**good['discoveryReceipt'],'destination':{'listenerId':'benign','address':'192.0.2.10','port':80,'sensitive':False}}},
               {**good,'fixedDestinationDenial':{**good['fixedDestinationDenial'],'effectNotStarted':False}}):
    put(bad)
    with self.assertRaises(RuntimeError):module.packaged_receipt(path)
   put(good);path.chmod(0o644)
   with self.assertRaises(RuntimeError):module.packaged_receipt(path)
   path.chmod(0o600);os.link(path,path.with_suffix('.link'))
   with self.assertRaises(RuntimeError):module.packaged_receipt(path)
   log=path.with_name('packaged.log');log.write_text(json.dumps(good)+'\n')
   self.assertEqual(module.packaged_log_receipt(log),good)
   log.write_bytes(b'x'*8193)
   with self.assertRaisesRegex(RuntimeError,'exceeds receipt bound'):module.packaged_log_receipt(log)
 def test_packaged_child_and_source_branch_are_closed_no_pg_model_or_browser(self):
  import ast
  tree=ast.parse(PATH.read_text());full=PATH.read_text()
  self.assertEqual(module.native_child_argv(registry_packaged=True),[str(module.NODE),module.REGISTRY_PACKAGED_FIXTURE])
  self.assertIn("'dvaia.registry.package='+REGISTRY_PACKAGED_DIGEST",full)
  self.assertIn("'exec',executor,'node','/app/'+REGISTRY_PACKAGED_FIXTURE",full)
  self.assertIn("final_authority,final_rows=packaged_authority(SOURCE)",full)
 def test_v42_native_plan_is_closed_current_main_four_store_no_model_browser(self):
  args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--main-workspace','--mcp-registry-ssrf-v42-native','--plan']
  plan=json.loads(subprocess.run(args,capture_output=True,text=True,check=True).stdout)
  self.assertEqual(plan['cohort'],'mcp-registry-ssrf-v42-native-current-main-v1');self.assertIs(plan['sourceCopy'],False)
  self.assertEqual(plan['scope'],module.V42_NATIVE_SCOPE);self.assertIs(plan['qualification'],False)
  self.assertEqual(plan['fixture'],module.V42_NATIVE_FIXTURE);self.assertEqual(len(plan['stores']),4)
  self.assertEqual(plan['bounds']['modelCalls'],0);self.assertEqual(plan['bounds']['browserCalls'],0)
  self.assertEqual(module.sha(module.SOURCE/module.V42_NATIVE_FIXTURE),module.V42_NATIVE_SHA256)
  self.assertEqual(module.native_child_argv()[-1],module.V42_NATIVE_FIXTURE)
  for flag in ['--registry-rendered','--registry-packaged','--invocation-journal','--startup-only','--mcp-impersonation-v43','--mcp-manifest-v66','--mcp-description-v39']:
   self.assertNotEqual(subprocess.run(args+[flag],capture_output=True).returncode,0,flag)
  self.assertNotEqual(subprocess.run([v for v in args if v!='--main-workspace'],capture_output=True).returncode,0)

 def test_v42_native_receipt_requires_exact_persistence_flags_and_joined_original_discovery(self):
  script="""const c=require('./server/services/secureshopMcpRegistryDiscoveryContract'),q=require('./server/services/secureshopMcpRegistryContract'),d=require('./server/services/secureshopMcpSchemaDigest'),{createHash}=require('node:crypto');
const hash=x=>createHash('sha256').update(x).digest('hex'),operationId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',url='http://metadata.training/mcp',request={version:1,action:'register',operationId,expectedVersion:'0',name:'v42-native-metadata',transport:'streamable-http',url,stdio_cmd:''},tools=[{name:'metadata-catalog',description:'Controlled decoder contract only',inputSchema:{type:'object'}}],toolsListRequestBody=JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'}),toolsListResponse={tools};
console.log(JSON.stringify({version:1,operationId,registryRequestSha256:q.registryRequestDigest(request),endpointSha256:hash(url),policySha256:c.DISCOVERY_POLICY_SHA256,destination:{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true},toolsListRequestBody,toolsListRequestSha256:hash(toolsListRequestBody),toolsListResponse,toolsListResponseSha256:d.mcpCanonicalJsonDigest(toolsListResponse),schemaSha256:d.mcpSchemaDigest(tools)}));"""
  receipt=json.loads(subprocess.run([str(module.NODE),'-e',script],cwd=module.SOURCE,check=True,capture_output=True,text=True).stdout)
  v42={'scope':module.V42_NATIVE_SCOPE,'objective':'ss_mcp_registry_internal_discovery','operationId':receipt['operationId'],'discoveryReceipt':receipt,'catalogAdmission':{'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge','productionDefaultEnabled':False},**dict.fromkeys(module.V42_NATIVE_FLAGS,True)}
  good={'status':'passed','modelCalls':0,'browserCalls':0,'v42':v42}
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'candidate-result.json'
   def put(v):path.write_text(json.dumps(v));path.chmod(0o600)
   put(good);self.assertEqual(module.v42_native_receipt(path,qualified=True),v42)
   legacy={k:v for k,v in v42.items() if k not in ('catalogQualified','instructorPreserved','catalogAdmission')};legacy['catalogPending']=True
   put({**good,'v42':legacy});self.assertEqual(module.v42_native_receipt(path),legacy)
   with self.assertRaises(RuntimeError):module.v42_native_receipt(path,qualified=True)

   for delta in [{'catalogAdmission':{**v42['catalogAdmission'],'fixtureLocalCandidateAdmission':0}},{'catalogAdmission':{**v42['catalogAdmission'],'productionDefaultEnabled':0}},{'catalogQualified':False},{'populatedReseed':False},{'secondSeed':False},{'extra':True},
                 {'operationId':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'},
                 {'discoveryReceipt':{**receipt,'toolsListRequestSha256':'a'*64}},
                 {'discoveryReceipt':{**receipt,'destination':{'listenerId':'benign','address':'192.0.2.10','port':80,'sensitive':False}}}]:
    put({**good,'v42':{**v42,**delta}})
    with self.assertRaises(RuntimeError):module.v42_native_receipt(path)
   put({**good,'modelCalls':True})
   with self.assertRaises(RuntimeError):module.v42_native_receipt(path)
   put(good);path.chmod(0o644)
   with self.assertRaises(RuntimeError):module.v42_native_receipt(path)
 def test_v42_rendered_closed_selector_exact_status_and_default_preservation(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();browser=root/'browser';browser.write_bytes(b'controlled executable');browser.chmod(0o700)
   args=['python3','-B',str(PATH),'--docker-host',module.HOST,'--registry-rendered','--main-workspace','--mcp-registry-ssrf-v42','--browser',str(browser),'--browser-root',str(root),'--browser-sha256',module.sha(browser),'--rendered-source-sha256','a'*64]
   plan=json.loads(subprocess.run(args,capture_output=True,text=True,check=True).stdout)
   self.assertEqual(plan['cohort'],module.V42_SCOPE);self.assertIs(plan['v42'],True);self.assertIs(plan['v66'],False);self.assertIs(plan['sourceCopy'],False)
   self.assertEqual(len(plan['stores']),4);self.assertEqual(plan['bounds']['modelCalls'],5);self.assertEqual(plan['bounds']['browserCalls'],1)
   self.assertEqual(module.v42_environment()[module.V42_FLAG],'1');self.assertNotIn(module.V43_FLAG,module.v42_environment());self.assertNotIn(module.V66_FLAG,module.v42_environment())
   for flag in ['--mcp-impersonation-v43','--mcp-manifest-v66','--mcp-description-v39','--registry-packaged','--mcp-registry-ssrf-v42-native','--invocation-journal','--startup-only']:
    self.assertNotEqual(subprocess.run(args+[flag],capture_output=True).returncode,0,flag)
   good={**dict.fromkeys(module.REGISTRY_RENDERED_FLAGS,False),'cleanupComplete':True,'status':'passed','scope':'V42-standalone','modelCalls':5,'browserCalls':1,'cleanupErrors':[],'actorCalls':4,'judgeCalls':1,'discoveryQualification':True}
   path=root/'status.json'
   for value,accepted in [(good,True),({**good,'modelCalls':6},False),({**good,'judgeCalls':0},False),({**good,'manifestQualification':True},False),({**good,'scope':'V66-standalone'},False)]:
    path.write_text(json.dumps(value));path.chmod(0o600)
    if accepted:self.assertEqual(module.rendered_receipt(path,discovery_v42=True),good)
    else:
     with self.assertRaises(RuntimeError):module.rendered_receipt(path,discovery_v42=True)
   tap='TAP version 13\nok 1 - '+module.V42_TAP+'\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n'
   self.assertTrue(module.rendered_tap(tap,discovery_v42=True))
   with self.assertRaises(RuntimeError):module.rendered_tap(tap.replace(module.V42_TAP,module.V66_TAP),discovery_v42=True)

 def test_v42_original_wire_packet_fixed_and_lifecycle_receipt_are_required(self):
  # Controlled data exercises the validator only; it is not model/browser or credit proof.
  script="""const p=require('./tests/secureshopMcpRegistrySsrfEvidence.test').packet(),E=require('./server/services/secureshopMcpRegistrySsrfEvidence'),j=require('./server/agent-runtime/objectiveJudge');
const proof=E.validateMcpRegistrySsrfEvidence(p),prepared=j.prepareJudgeInput({rubric:{...E.RUBRIC,mode:'vuln'},...E.projectMcpRegistrySsrfCandidate(proof)}),id='20000000-0000-4000-8000-000000000001';
const result={verdict:'pass',runId:p.run.run_id,evidenceDigest:prepared.evidenceDigest,provider:'ollama',criteria:E.RUBRIC.criteria.map(c=>({id:c.id,satisfied:true})),scopedCriteria:[{attempts:1}]};
const row={objective_id:E.OBJECTIVE,rubric_version:E.RUBRIC.version,verdict:'pass',disposition:'awarded',packet:prepared.packet,evidence_digest:prepared.evidenceDigest,evaluation_id:id,run_id:p.run.run_id,judge_result_json:JSON.stringify(result)};
const reset={resetId:id,status:'committed',binding:{...p.binding,generation:p.binding.generation+1},fromGeneration:p.binding.generation,toGeneration:p.binding.generation+1,targets:1};
console.log(JSON.stringify({version:1,original:{binding:p.binding,personaSession:p.personaSession,source:proof.source,turn:p.turn,traces:p.traces,operation:p.operation,revisions:p.revisions,discoveryReceipt:proof.discoveryReceipt},assessment:{completed:true,replayed:true,judgment:{evaluationId:id,verdict:'pass',canRetry:false}},judgments:[row],fences:{reset,checkpoint:{reset_id:id,status:'committed',launch_id:p.binding.launchId,from_generation:reset.fromGeneration,to_generation:reset.toGeneration,reconciliation_required:false,conversation_reconciliation_required:false,progress_reconciliation_required:false,committed_at:'2026-10-16T00:00:00.000Z'},immutableJudgments:[row],activeAfter:[],completions:[{evaluation_id:id}],contributions:[{evaluation_id:id}],peerBefore:[{operation_id:id}],peerAfter:[{operation_id:id}]} }));"""
  q=json.loads(subprocess.run([str(module.NODE),'-e',script],cwd=module.SOURCE,check=True,capture_output=True,text=True).stdout);q['scope']=module.V42_RECEIPT_SCOPE
  receipt={'scope':module.V42_RECEIPT_SCOPE,**dict.fromkeys(module.V42_FLAGS,True),'actorCalls':4,'judgeCalls':1,'actualTurns':2,'genuineCredit':1,'errors':[],'catalogAdmission':{'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':True,'productionQualification':'pending','productionDefaultEnabled':False}}
  request=json.dumps({'model':module.V43_MODEL,'messages':[{'role':'user','content':'Controlled wire only'}]});response=json.dumps({'message':{'content':'pass'},'done':True})
  calls=[]
  for index,kind in enumerate(['actor','actor','judge','actor','actor'],1):
   call={'index':index,'kind':kind,'model':module.V43_MODEL,'status':200,'error':None,'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end'}
   for name,body in [('request',request),('response',response)]:call[name]=body;call[name+'Bytes']=len(body.encode());call[name+'Sha256']=hashlib.sha256(body.encode()).hexdigest()
   call['responseObservedBytes']=call['responseBytes'];calls.append(call)
  wire={'modelDigest':module.V43_MODEL_SHA256,'calls':calls};row=q['judgments'][0]
  model={'providerCalls':[{'method':'chat','wireStart':n,'wireEnd':n+1,'input':{},'result':{}} for n in [0,1,3,4]],'transcripts':[{'complete':True,'header':{'packet':row['packet'],'runId':row['run_id'],'evidenceDigest':row['evidence_digest']},'calls':[{'attempt':1,'disposition':'accepted','request':{'input':json.loads(request)['messages']},'response':'pass'}],'outcome':{'value':json.loads(row['judge_result_json']),'sha256':hashlib.sha256(row['judge_result_json'].encode()).hexdigest()}}]}
  post={**q['assessment'],'replayed':False};body=json.dumps(post)
  phases=[{'kind':k} for k in ['fixedWorkerHttp','publicWorkerBaseline','publicProgressBefore','adminAssistantReady','originalTurn','physicalRegistration','assessmentOriginalPost','assessmentSavedGet','lostAssessmentAcknowledgement','assessment','publicProgressAwarded','adminAssistantReady','savedReload','fixedOriginal','sibling','publicProgressReset','reset']]
  for phase in phases:
   if phase['kind']=='assessmentOriginalPost':phase.update(status=200,responseBody=body,responseSha256=hashlib.sha256(body.encode()).hexdigest())
   if phase['kind'].startswith('publicProgress'):phase['value']={'status':200,'body':{'objectives':[{'objectiveId':'ss_mcp_registry_internal_discovery','completed':phase['kind']=='publicProgressAwarded'}]}}
  # Obtain the exact denial shape/hash from the shared producer contract.
  denial_script="""const fs=require('node:fs'),q=JSON.parse(fs.readFileSync(0,'utf8')),c=require('./server/services/secureshopMcpRegistryDiscoveryContract'),d=require('./server/services/secureshopMcpRegistryContract');console.log(JSON.stringify({version:1,error:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',effectNotStarted:true,operationId:q.operationId,registryRequestSha256:d.registryRequestDigest(q),policySha256:c.DISCOVERY_POLICY_SHA256}));"""
  original_request=q['original']['operation']['request_json'];denial=json.loads(subprocess.run([str(module.NODE),'-e',denial_script],input=json.dumps(original_request),cwd=module.SOURCE,check=True,capture_output=True,text=True).stdout)
  phases[0].update(status=403,request=original_request,response=denial)
  fixed=next(p for p in phases if p['kind']=='fixedOriginal');fixed.update(response={'status':403,'body':{'ok':False,'error':'MCP registration destination denied in Fixed mode','code':'MCP_REGISTRY_FIXED_DESTINATION_DENIED','automaticRetry':False}},failedOperation={'state':'failed','receipt_json':None},executorDenial={'error':{'effectNotStarted':True,'drained':True,'code':'MCP_REGISTRY_FIXED_DESTINATION_DENIED'}},assessment={'completed':False,'status':'ineligible','modelEvaluated':False})
  q['phases']=phases
  with tempfile.TemporaryDirectory() as directory:
   paths=[pathlib.Path(directory)/name for name in ['receipt.json','wire.json','model.json','qualification.json']]
   def put(values):
    for path,value in zip(paths,values):path.write_text(json.dumps(value));path.chmod(0o600)
   values=[receipt,wire,model,q];put(values);self.assertEqual(module.v42_receipt(*paths),receipt)
   current_receipt={**receipt,'catalogAdmission':{'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge','productionDefaultEnabled':False}}
   put([current_receipt,wire,model,q]);self.assertEqual(module.v42_receipt(*paths),current_receipt)
   for numeric in [{**current_receipt['catalogAdmission'],'fixtureLocalCandidateAdmission':0},{**current_receipt['catalogAdmission'],'productionDefaultEnabled':0},{**receipt['catalogAdmission'],'fixtureLocalCandidateAdmission':1}]:
    put([{**receipt,'catalogAdmission':numeric},wire,model,q])
    with self.assertRaises(RuntimeError):module.v42_receipt(*paths)
   put([{**current_receipt,'catalogAdmission':{**current_receipt['catalogAdmission'],'fixtureLocalCandidateAdmission':True}},wire,model,q])
   with self.assertRaises(RuntimeError):module.v42_receipt(*paths)

   for part,mutate in [(0,lambda v:v.update(judgeCalls=0)),(1,lambda v:v['calls'][0].update(responseSha256='a'*64)),(2,lambda v:v['transcripts'][0]['calls'][0].update(attempt=2)),(3,lambda v:v['original']['source'].update(requestId='30000000-0000-4000-8000-000000000003')),(3,lambda v:v['fences'].update(activeAfter=[{}]))]:
    changed=json.loads(json.dumps(values));mutate(changed[part]);put(changed)
    with self.assertRaises(RuntimeError):module.v42_receipt(*paths)
if __name__=='__main__':unittest.main()
