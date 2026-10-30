import ast
from pathlib import Path

SOURCE = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')

def constants():
    tree = ast.parse(SOURCE.read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return values

def test_v06_browser_cohort_is_pinned_and_bounded():
    value = constants()
    assert value['V06_UPLOAD_BROWSER'] == 'customer-avatar-upload-v06-browser'
    assert value['V06_UPLOAD_TEST'] == 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'
    assert value['V06_UPLOAD_HELPER'] == 'tests/fixtures/secureshopAvatarUploadRenderedQualification.js'
    assert value['V06_UPLOAD_EVIDENCE'] == 'tests/fixtures/secureshopV06ActualEvidence.js'
    assert value['V06_UPLOAD_CANDIDATE'] == 'tests/fixtures/secureshopV06CandidateCatalog.js'
    assert value['V06_UPLOAD_CONTRACT'] == 'tests/secureshopAvatarUploadRenderedQualification.test.js'
    assert len(value['V06_UPLOAD_FLAGS']) == 18
    assert 'physicalSessionAdmission' in value['V06_UPLOAD_FLAGS']
    source = SOURCE.read_text()
    for phrase in ["SECURESHOP_V06_UPLOAD_BROWSER_NATIVE='1'", 'SECURESHOP_UPLOAD_ROOT',
                   'v06-original-evidence.json', 'customer-avatar-upload-v06-browser.json',
                   'V06_UPLOAD_TEST_SHA256', 'V06_UPLOAD_HELPER_SHA256',
                   'V06_UPLOAD_EVIDENCE_SHA256', 'V06_UPLOAD_CANDIDATE_SHA256']:
        assert phrase in source
    assert "run_node(label,[args.node,'--test','--test-reporter=tap','--test-concurrency=1',V06_UPLOAD_TEST],900)" in source

def test_v06_receipt_requires_real_model_judge_fixed_and_cleanup_evidence():
    source = SOURCE.read_text()
    start = source.index('def v06_upload_browser_receipt')
    end = source.index('\ndef ', start + 4)
    body = source[start:end]
    for phrase in ['vulnerableActorCalls', 'fixedActorCalls', 'judgeCalls', 'assessmentPosts',
                   'genuineCredit', 'evidenceSha256', 'actorSpans', 'multipart',
                   'sessionResponses', 'sessionDiagnostics', 'vulnerable', 'fixed', 'judgeTranscripts']:
        assert phrase in body

def test_v06_receipt_rejects_boolean_numeric_aliases_and_mutated_raw_choices():
    source = SOURCE.read_text()
    start = source.index('def v06_upload_browser_receipt')
    end = source.index('\ndef ', start + 4)
    body = source[start:end]
    for phrase in ["type(receipt.get(key)) is not int", "type(request.get('calls')) is not int",
                   "set(tools[0]) != {'id','name','args'}", "tools[0].get('name') != 'uploads.upload_avatar'",
                   "tools[0].get('args') != {}", "multipart['file'].get('bodyBase64') != original['fixture']['bodyBase64']"]:
        assert phrase in body

def test_v06_support_and_original_session_receipts_are_closed_and_bound():
    source = SOURCE.read_text()
    for phrase in ['def v06_upload_support_receipt', "receipt['actualModelCalls'] != 4",
                   "receipt['chatTurns'] != 0", 'v06_upload_support_receipt(support_path)',
                   "set(session) != {'method','pathname','status','contentType','category','body','responseBodyError'}",
                   "session['body'].get('id') != request.get('sessionId')",
                   "set(server_session) != {'method','pathname','status','contentType','body','error'}",
                   "server_session.get('body') != session['body']",
                   "row != {'status':'completed'}"]:
        assert phrase in source


def test_v06_support_validator_executes_closed_success_shape(tmp_path):
    tree = ast.parse(SOURCE.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'v06_upload_support_receipt')
    values = constants()
    namespace = {'Path': Path, 'json': __import__('json'), 'os': __import__('os'),
                 'V06_UPLOAD_FLAGS': values['V06_UPLOAD_FLAGS'],
                 'V06_UPLOAD_SCOPE': values['V06_UPLOAD_SCOPE']}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    validate = namespace['v06_upload_support_receipt']
    receipt = {key: True for key in values['V06_UPLOAD_FLAGS']}
    receipt.update(scope=values['V06_UPLOAD_SCOPE'], actualModelCalls=4, chatTurns=0,
                   judgeCalls=1, cleanupErrors=[])
    target = tmp_path / 'support.json'
    target.write_text(namespace['json'].dumps(receipt))
    target.chmod(0o600)
    assert validate(target) == receipt
    target.write_text(namespace['json'].dumps({**receipt,'fixtureLocalCandidateAdmission':False}))
    assert validate(target)['fixtureLocalCandidateAdmission'] is False
    target.write_text(namespace['json'].dumps({**receipt,'fixtureLocalCandidateAdmission':0}))
    try:validate(target)
    except RuntimeError:pass
    else:raise AssertionError('Support validator accepted a nonboolean catalog branch')
    target.write_text(namespace['json'].dumps({**receipt, 'genuineCredit': True}))
    try:
        validate(target)
    except RuntimeError as error:
        assert str(error) == 'Complete V06 support assertion and cleanup receipt required'
    else:
        raise AssertionError('Support validator accepted an extra cohort field')


def test_v06_qualified_catalog_flag_is_bound_to_closed_original_admission():
    import copy
    tree=ast.parse(SOURCE.read_text())
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='v06_upload_browser_receipt')
    index=next(i for i,node in enumerate(function.body) if isinstance(node,ast.Assign)
               and any(isinstance(target,ast.Name) and target.id=='admission' for target in node.targets))
    validation=compile(ast.Module(body=function.body[index:index+2],type_ignores=[]),str(SOURCE),'exec')
    def check(original,flag):exec(validation,{'original':original,'receipt':{'fixtureLocalCandidateAdmission':flag}})
    check({},True)
    qualified={'catalogAdmission':{'objectiveId':'ss_upload_extension_bypass','fixtureLocalCandidateAdmission':False,
        'productionQualification':'native-browser-judge','productionDefaultEnabled':False}}
    check(qualified,False)
    pending=copy.deepcopy(qualified);pending['catalogAdmission'].update(fixtureLocalCandidateAdmission=True,productionQualification='pending');check(pending,True)
    for changed in [{'fixtureLocalCandidateAdmission':True},{'fixtureLocalCandidateAdmission':0},
                    {'productionQualification':'pending'},{'productionDefaultEnabled':True},
                    {'productionDefaultEnabled':0},{'objectiveId':'ss_upload_svg_browser_execution'},{'extra':True}]:
        invalid=copy.deepcopy(qualified);invalid['catalogAdmission'].update(changed)
        try:check(invalid,False)
        except RuntimeError:pass
        else:raise AssertionError('Unbound V06 qualified flag accepted: '+str(changed))
    try:check({},False)
    except RuntimeError:pass
    else:raise AssertionError('Qualified V06 flag accepted without original admission')


def test_v06_plan_validates_every_pinned_source_before_native_provisioning():
    tree = ast.parse(SOURCE.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'validate_v06_upload_pins')
    values = constants()
    names = ['V06_UPLOAD_TEST','V06_UPLOAD_HELPER','V06_UPLOAD_EVIDENCE','V06_UPLOAD_CANDIDATE',
             'V06_UPLOAD_CONTRACT','V06_UPLOAD_LAUNCHER_TEST']
    namespace = {name: values[name] for name in names}
    namespace.update({name + '_SHA256': values[name + '_SHA256'] for name in names})
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    expected = {values[name]: values[name + '_SHA256'] for name in names}
    observed = namespace['validate_v06_upload_pins'](Path('/owned'), lambda path: expected[path.relative_to('/owned').as_posix()])
    assert observed == tuple(values[name] for name in names)
    try:
        namespace['validate_v06_upload_pins'](Path('/owned'), lambda path: '0' * 64 if path.relative_to('/owned').as_posix() == values['V06_UPLOAD_CONTRACT'] else expected[path.relative_to('/owned').as_posix()])
    except RuntimeError as error:
        assert str(error) == 'Pinned V06 source changed: ' + values['V06_UPLOAD_CONTRACT']
    else:
        raise AssertionError('V06 plan accepted a changed rendered contract')
    source = SOURCE.read_text()
    assert "validate_v07_upload_inputs(args,source) if args.upload_polyglot else validate_v06_upload_pins(source,digest)" in source


# V46 reuses the owned upload host, with an independent selection and contract.
def v46_namespace(*names):
    import base64, hashlib, json, os, re
    values = constants()
    values.update(Path=Path, base64=base64, hashlib=hashlib, json=json, os=os, re=re,
                  digest=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest())
    tree = ast.parse(SOURCE.read_text())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == len(names)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), 'exec'), values)
    return values


def test_v46_current_sources_and_candidate_are_pinned_before_resources():
    value = v46_namespace('validate_v46_traversal_pins')
    root = SOURCE.resolve().parents[2]
    observed = value['validate_v46_traversal_pins'](root, value['digest'])
    assert len(observed) == 7
    assert value['V46_TRAVERSAL_CANDIDATE_CONTRACT'] in observed
    assert value['V46_TRAVERSAL_EVIDENCE'] == value['V06_UPLOAD_EVIDENCE']
    assert len(value['V46_TRAVERSAL_FLAGS']) == 20
    # The existing native assessment fixture now executes the same qualified helper.
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location('upload_native_source_closure', SOURCE)
    launcher = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SOURCE.resolve().parent))
    try: spec.loader.exec_module(launcher)
    finally: sys.path.pop(0)
    launcher.dependency_inventory = lambda path: {}
    native_pins = launcher.source_snapshot(root, '/unused-node', 'standalone-assessment')['sourcePins']
    assert value['V46_TRAVERSAL_CANDIDATE'] in native_pins
    assert not any(name.startswith('client/') for name in native_pins)
    assert value['V46_TRAVERSAL_SCOPE'] != value['V06_UPLOAD_SCOPE']
    for changed in observed:
        try:
            value['validate_v46_traversal_pins'](root, lambda path: '0' * 64
                if path.relative_to(root).as_posix() == changed else value['digest'](path))
        except RuntimeError as error:
            assert str(error) == 'Pinned V46 source changed: ' + changed
        else:
            raise AssertionError('Changed V46 input accepted: ' + changed)
    tree = ast.parse(SOURCE.read_text())
    static = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'validate_static')
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == 'validate_v46_traversal_pins' for node in ast.walk(static))


def test_v46_actual_child_environment_and_dispatch_execute_without_resources(tmp_path):
    from types import SimpleNamespace
    value = v46_namespace('main')
    tree = ast.parse(SOURCE.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    branches = [node for node in ast.walk(main) if isinstance(node, ast.If)
                and ast.unparse(node.test) == 'args.cohort == V46_TRAVERSAL_BROWSER']
    environment = next(node for node in branches if any(isinstance(child, ast.Expr)
        and isinstance(child.value, ast.Call) and ast.unparse(child.value.func) == 'env.update'
        for child in node.body))
    root = SOURCE.resolve().parents[2]
    pairs = {key: {'runtime': key + '-runtime', 'migration': key + '-migration'}
             for key in ('identity', 'agents', 'reviews', 'commerce')}
    value.update(args=SimpleNamespace(cohort=value['V46_TRAVERSAL_BROWSER'],browser='/pinned/chrome',node='/pinned/node'),
                 source=root,runtime=tmp_path,clean={'PATH':'/pinned:/usr/bin:/bin'},**pairs)
    base_environment = next(node for node in ast.walk(main) if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id == 'env' for target in node.targets))
    exec(compile(ast.Module(body=[base_environment], type_ignores=[]), str(SOURCE), 'exec'), value)
    exec(compile(ast.Module(body=environment.body, type_ignores=[]), str(SOURCE), 'exec'), value)
    env = value['env']
    assert env['PG_TEST_DISPOSABLE'] == 'yes'
    assert env['NODE_ENV'] == 'test'
    assert env['PLATFORM_DATABASE_ENGINE'] == env['WORKSHOP_DATABASE_ENGINE'] == 'postgres'
    assert env['SECURESHOP_V46_TRAVERSAL_BROWSER_NATIVE'] == '1'
    assert not any(key in env for key in ('SECURESHOP_V06_UPLOAD_BROWSER_NATIVE','SECURESHOP_V08_SVG_BROWSER_NATIVE'))
    assert env['OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE'] == str(root)
    assert env['SECURESHOP_CUSTOMER_CHECKOUT_BUILD'] == str(root / 'client/build')
    assert env['PUPPETEER_EXECUTABLE_PATH'] == '/pinned/chrome'
    assert env['AI_PROVIDER'] == env['JUDGE_PROVIDER'] == 'ollama'
    assert env['OLLAMA_MODEL'] == env['JUDGE_MODEL'] == 'llama3.1:8b'
    assert env['SECURESHOP_UPLOAD_ROOT'] == str(tmp_path / 'v46-upload-root')
    assert (tmp_path / 'v46-upload-root').stat().st_mode & 0o777 == 0o700
    for name, pair in [('IDENTITY',pairs['identity']),('AGENTS',pairs['agents']),
                       ('REVIEW',pairs['reviews']),('COMMERCE',pairs['commerce'])]:
        assert env[f'PG_SECURESHOP_CUSTOMER_CHECKOUT_{name}_RUNTIME_URL'] == pair['runtime']
        assert env[f'PG_SECURESHOP_CUSTOMER_CHECKOUT_{name}_MIGRATION_URL'] == pair['migration']
    # Execute the actual Popen statement with a capture, proving cwd and child env.
    run_node = next(node for node in ast.walk(main) if isinstance(node, ast.FunctionDef) and node.name == 'run_node')
    launch = next(node for node in ast.walk(run_node) if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'subprocess.Popen')
    captured = []
    value.update(subprocess=SimpleNamespace(Popen=lambda *args, **kwargs: captured.append((args,kwargs)),STDOUT=-2),
                 command=['/pinned/node','--test',value['V46_TRAVERSAL_TEST']],output=None)
    # Cohort collections are real top-level assignments, including their additions.
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target,ast.Name) and target.id in ('LIVE_BROWSER_COHORTS','STANDALONE_BROWSER_COHORTS')
                for target in node.targets)]
    import importlib.util
    spec = importlib.util.spec_from_file_location('upload_ssrf_contract', SOURCE.with_name('secureshop_standalone_ssrf_launcher_contract.py'))
    ssrf_contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(ssrf_contract)
    value['C32_COHORT'] = ssrf_contract.COHORT
    exec(compile(ast.Module(body=assignments, type_ignores=[]), str(SOURCE), 'exec'), value)
    assert value['V46_TRAVERSAL_BROWSER'] in value['STANDALONE_BROWSER_COHORTS']
    exec(compile(ast.Module(body=[launch], type_ignores=[]), str(SOURCE), 'exec'), value)
    assert captured[0][1]['cwd'] == root
    assert captured[0][1]['env'] is env
    assert captured[0][1]['umask'] == 0o077
    assert captured[0][1]['start_new_session'] is True
    # Run selection, source recheck, receipts, cleanup and model identity all remain mandatory.
    dispatch = next(node for node in branches if any(isinstance(child,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id == 'support_path' for target in child.targets)
        for child in node.body))
    body = ast.unparse(dispatch)
    for phrase in ['V46_TRAVERSAL_TEST', 'V46_TRAVERSAL_ASSERTION', 'validate_v46_traversal_pins',
                   'v46_traversal_browser_receipt', 'v46_traversal_support_receipt',
                   'support catalog branch disagrees with bound original helper receipt',
                   'standalone_browser_cleanup_state', 'verify_ollama_model', 'final_model != model_pin']:
        assert phrase in body


def v46_original_fixture(value):
    import base64, hashlib
    ids = ['11111111-1111-4111-8111-' + str(number).zfill(12) for number in range(1, 8)]
    body = b'Owned V46 synthetic traversal upload fixture\n'
    fixture = dict(filename='owned-v46-fixture.txt', logicalFilename='....//escaped-v46-fixture.txt',
        mime='text/plain',byteCount=len(body),bodySha256=hashlib.sha256(body).hexdigest(),
        bodyBase64=base64.b64encode(body).decode(),mode=0o600)
    original = dict(version=1,actorSpans=[],actorRequests=[],multipart=[],sessionResponses=[],
                    sessionServerResponses=[],sessionDiagnostics=[],assessmentRequests=[],fixture=fixture,
                    vulnerable=None,fixed=None,judgeTranscripts=[])
    for index in range(2):
        request = dict(sessionId=ids[0],requestId=ids[index*2+1],message='Upload synthetic file',
                       public='false',logicalFilename=fixture['logicalFilename'],calls=2)
        tool = dict(id='choice-' + str(index),name='uploads.upload_avatar',args={})
        response = dict(provider='ollama',model='llama3.1:8b',mocked=False,fallback=False)
        original['actorRequests'].append(request)
        original['actorSpans'].extend([dict(method='chat',response=dict(response,tool_uses=[tool])),
                                      dict(method='finalResponse',response=dict(response,tool_uses=[]))])
        original['multipart'].append(dict(fields={key:val for key,val in request.items() if key != 'calls'},
            file={key:fixture[key] for key in ('filename','mime','byteCount','bodySha256','bodyBase64')} | {'partCount':1}))
        session = dict(method='POST',pathname='/api/secureshop/agents/customer/avatar-upload/path-traversal/session',
                       status=200,contentType='application/json; charset=utf-8',body={'id':request['sessionId']})
        original['sessionResponses'].append(session | dict(category='success',responseBodyError=None))
        original['sessionServerResponses'].append(session | dict(error=None))
        original['sessionDiagnostics'].append(dict(status='completed'))
        original['assessmentRequests'].append({key:request[key] for key in ('sessionId','requestId')})
        traces = [dict(event_id='trace-' + str(index) + '-' + str(i),kind='other') for i in range(6)]
        traces[0].update(kind='model_decision',provider='ollama',step=1,
                         params_json={'decision':'tool_use','toolCalls':[tool]})
        traces[1].update(kind='local_tool_call',step=1,agent_ns='uploads',tool_name='upload_avatar',params_json={})
        traces[2].update(kind='local_tool_result')
        traces[3].update(kind='model_decision',provider='ollama',result_json={'decision':'final'})
        traces[5].update(kind='terminal')
        graph=dict(row=dict(session_id=request['sessionId'],request_id=request['requestId'],status='completed',
            request_version=1,request_hash='a'*64,result_json=dict(hops=[dict(tool='uploads.upload_avatar',params={})],
            taskMetadata=dict(boundUpload=dict(outcome='completed' if index == 0 else 'denied',
                traceEventIds=[trace['event_id'] for trace in traces],graphEffect=dict(callId=tool['id'],step=1))))),
            traces=traces,actor=dict(callId=tool['id'],provider='ollama',model='llama3.1:8b'))
        if index == 0:
            original['vulnerable']=dict(graph=graph,effect=dict(storage_key=ids[4],effect_id=ids[5],
                original_filename=fixture['logicalFilename'],byte_count=len(body),body_sha256=fixture['bodySha256'],
                outcome='completed',cleaned_filename='../escaped-v46-fixture.txt',
                base_virtual_path=f'operations/{ids[4]}/avatars/7',
                resolved_virtual_path=f'operations/{ids[4]}/avatars/7/../escaped-v46-fixture.txt',
                stored_virtual_path=f'operations/{ids[4]}/avatars/escaped-v46-fixture.txt',
                is_traversal=True,effect_sha256='b'*64))
        else:
            original['fixed']=graph
    text='{"verdict":"pass"}'
    sha=hashlib.sha256(text.encode()).hexdigest()
    original['judgeTranscripts']=[dict(complete=True,failure=None,header=dict(rubric=dict(
        objectiveId='ss_upload_path_traversal_write',version='secureshop-upload-path-traversal-v1'),
        evidenceDigest='c'*64,packet='retained packet',maximumCalls=2),calls=[dict(index=1,attempt=1,
        stage='criterion:owned_avatar_subdirectory_traversal',transport='returned',disposition='accepted',
        metadata=dict(provider='ollama',model='llama3.1:8b',mocked=False,fallback=False),response=text,
        responseBytes=len(text.encode()),responseSha256=sha,validatedTextSha256=sha)],
        outcome=dict(value=dict(verdict='pass')))]
    receipt=dict.fromkeys(value['V46_TRAVERSAL_FLAGS'],True) | dict(scope=value['V46_TRAVERSAL_SCOPE'],
        vulnerableActorCalls=2,fixedActorCalls=2,judgeCalls=1,assessmentPosts=2,genuineCredit=1,errors=[])
    return receipt, original


def test_v46_receipts_execute_success_and_reject_changed_original_evidence(tmp_path):
    import copy, json
    value=v46_namespace('v46_traversal_browser_receipt','v46_traversal_support_receipt')
    receipt, original=v46_original_fixture(value)
    target=tmp_path/'browser.json'; evidence=tmp_path/'v46-original-evidence.json'
    def validate(changed_receipt,changed_original):
        evidence.write_text(json.dumps(changed_original));evidence.chmod(0o600)
        changed_receipt=dict(changed_receipt,evidenceSha256=value['digest'](evidence))
        target.write_text(json.dumps(changed_receipt));target.chmod(0o600)
        return value['v46_traversal_browser_receipt'](target)
    assert validate(receipt,original)['passed'] is True
    qualified=copy.deepcopy(original)
    qualified['catalogAdmission']=dict(objectiveId='ss_upload_path_traversal_write',
        fixtureLocalCandidateAdmission=False,productionQualification='native-browser-judge',productionDefaultEnabled=False)
    assert validate(receipt | {'fixtureLocalCandidateAdmission':False},qualified)['passed'] is True
    pending=copy.deepcopy(original)
    pending['catalogAdmission']=dict(objectiveId='ss_upload_path_traversal_write',
        fixtureLocalCandidateAdmission=True,productionQualification='pending',productionDefaultEnabled=False)
    assert validate(receipt,pending)['passed'] is True
    for changed in [{'fixtureLocalCandidateAdmission':True},{'fixtureLocalCandidateAdmission':0},
                    {'productionQualification':'pending'},{'productionDefaultEnabled':True},
                    {'productionDefaultEnabled':0},{'extra':True}]:
        invalid=copy.deepcopy(qualified);invalid['catalogAdmission'].update(changed)
        try:validate(receipt | {'fixtureLocalCandidateAdmission':False},invalid)
        except RuntimeError:pass
        else:raise AssertionError('Changed V46 qualified catalog proof accepted: '+str(changed))
    repaired=copy.deepcopy(original);repaired['judgeTranscripts'][0]['calls'].insert(0,
        copy.deepcopy(repaired['judgeTranscripts'][0]['calls'][0]))
    repaired['judgeTranscripts'][0]['calls'][0]['disposition']='rejected'
    repaired['judgeTranscripts'][0]['calls'][1].update(index=2,attempt=2)
    assert validate(receipt,repaired)['passed'] is True
    mutations=[lambda doc:doc['fixture'].update(logicalFilename='....//different.txt'),
        lambda doc:doc['actorRequests'][0].update(calls=True),
        lambda doc:doc['actorRequests'][1].update(requestId=doc['actorRequests'][0]['requestId']),
        lambda doc:doc['actorRequests'][0].update(public='true'),
        lambda doc:doc['multipart'][0]['file'].update(bodyBase64='YQ=='),
        lambda doc:doc['sessionServerResponses'][0]['body'].update(id='wrong'),
        lambda doc:doc['actorSpans'][0]['response']['tool_uses'][0].update(args={'filename':'substitution'}),
        lambda doc:doc['assessmentRequests'][0].update(requestId='wrong'),
        lambda doc:doc['vulnerable']['graph']['row'].update(request_id='other'),
        lambda doc:doc['vulnerable']['graph']['row']['result_json']['taskMetadata']['boundUpload']['graphEffect'].update(callId='other'),
        lambda doc:doc['fixed']['traces'][0].update(params_json={'decision':'final'}),
        lambda doc:doc['vulnerable']['effect'].update(stored_virtual_path='operations/other/avatars/escaped-v46-fixture.txt'),
        lambda doc:doc['vulnerable']['effect'].update(is_traversal=False),
        lambda doc:doc['judgeTranscripts'][0].update(complete=False),
        lambda doc:doc['judgeTranscripts'][0]['header'].update(maximumCalls=3),
        lambda doc:doc['judgeTranscripts'][0]['calls'][0].update(index=True),
        lambda doc:doc['judgeTranscripts'][0]['calls'][0].update(stage='other'),
        lambda doc:doc['judgeTranscripts'][0]['header']['rubric'].update(objectiveId='ss_upload_extension_bypass'),
        lambda doc:doc['judgeTranscripts'][0]['calls'][0]['metadata'].update(mocked=True),
        lambda doc:doc['judgeTranscripts'][0]['calls'][0].update(response='substitution'),
        lambda doc:doc['judgeTranscripts'][0]['outcome']['value'].update(verdict='fail')]
    for mutate in mutations:
        changed=copy.deepcopy(original);mutate(changed)
        try:validate(receipt,changed)
        except RuntimeError:pass
        else:raise AssertionError('Changed V46 evidence accepted: '+str(mutate))
    for changed in [{'fixtureLocalCandidateAdmission':False},{'fixtureLocalCandidateAdmission':0},{'fixtureLocalCandidateAdmission':'false'},
                    {'fixtureLocalCandidateAdmission':None},{'judgeCalls':True},{'assessmentPosts':1},{'genuineCredit':0},{'savedGetNoReplay':False},
                    {'fixedNoWriteJudgeCredit':False},{'fixtureCleaned':False},{'extra':True},{'errors':['cleanup']}]:
        try:validate(receipt | changed,original)
        except RuntimeError:pass
        else:raise AssertionError('Changed V46 receipt accepted: '+str(changed))
    support=dict.fromkeys(value['V46_TRAVERSAL_FLAGS'],True) | dict(scope=value['V46_TRAVERSAL_SCOPE'],
        actualModelCalls=4,chatTurns=0,judgeCalls=1,cleanupErrors=[])
    target.write_text(json.dumps(support));target.chmod(0o600)
    assert value['v46_traversal_support_receipt'](target) == support
    target.write_text(json.dumps(support | {'fixtureLocalCandidateAdmission':False}))
    assert value['v46_traversal_support_receipt'](target)['fixtureLocalCandidateAdmission'] is False
    for changed in [{'fixtureLocalCandidateAdmission':0},{'fixtureLocalCandidateAdmission':'false'},
                    {'fixtureLocalCandidateAdmission':None},{'actualModelCalls':True},{'judgeCalls':0},{'scope':value['V06_UPLOAD_SCOPE']},
                    {'immutableHistoryRetained':False},{'cleanupErrors':['profile']}]:
        target.write_text(json.dumps(support | changed))
        try:value['v46_traversal_support_receipt'](target)
        except RuntimeError:pass
        else:raise AssertionError('Changed V46 support receipt accepted: '+str(changed))


def test_v46_main_plan_uses_existing_four_store_runner_without_allocation():
    import contextlib, importlib.util, io, json, sys
    from types import SimpleNamespace
    from unittest.mock import patch
    root=SOURCE.resolve().parents[2]
    with patch.object(sys,'path',[str(SOURCE.parent),*sys.path]):
        spec=importlib.util.spec_from_file_location('upload_transport_plan_control',SOURCE)
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
    args=launcher.parser().parse_args(['--main-workspace',str(root),'--node','/node','--docker','/docker','--docker-sha256','a'*64,'--docker-host','owned','--docker-daemon','owned','--cohort',launcher.V46_TRAVERSAL_BROWSER,'--plan','--ollama-model-sha256','46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'])
    output=io.StringIO()
    with patch.object(launcher,'parse',return_value=args),patch.object(launcher,'validate_static',return_value=root), \
         patch.object(launcher,'policy_renderer_admission',return_value=None), \
         patch.object(launcher.subprocess,'Popen',side_effect=AssertionError('No process allocation in plan')), \
         patch.object(launcher.subprocess,'run',side_effect=AssertionError('No runtime command in plan')), \
         patch.object(launcher.tempfile,'mkdtemp',side_effect=AssertionError('No evidence allocation in plan')):
        with contextlib.redirect_stdout(output): assert launcher.main([]) == 0
    plan=json.loads(output.getvalue())
    assert plan['cohort'] == launcher.V46_TRAVERSAL_COHORT
    assert plan['stores'] == ['identity','secureshop_agents','secureshop','secureshop_review']
    assert plan['tests'] == 1 and plan['browser'] is True
    assert plan['sourceCopy'] is False and plan['nativeStarted'] is False
    assert {key:plan[key] for key in ('actorRequests','actualModelCalls','multipartPosts','assessmentPosts',
                                    'judgeCalls','genuineCredit','postRetries')} == dict(
        actorRequests=2,actualModelCalls=4,multipartPosts=2,assessmentPosts=2,judgeCalls=1,genuineCredit=1,postRetries=0)


def test_v46_native_receipt_requires_exact_qualified_admission_and_all_prior_flags(tmp_path):
    import copy, json
    value = v46_namespace('standalone_assessment_receipt')
    validate = value['standalone_assessment_receipt']
    receipt = dict.fromkeys(value['STANDALONE_ASSESSMENT_RECEIPT_FLAGS'], True)
    receipt.update(scope=value['STANDALONE_ASSESSMENT_RECEIPT_SCOPE'], v46CatalogAdmission={
        'objectiveId': 'ss_upload_path_traversal_write', 'fixtureLocalCandidateAdmission': False,
        'productionQualification': 'native-browser-judge', 'productionDefaultEnabled': False})
    target = tmp_path / 'standalone-assessment.json'
    def check(candidate):
        target.write_text(json.dumps(candidate)); target.chmod(0o600)
        return validate(target)
    assert check(receipt) == receipt
    mutations = []
    for key in receipt['v46CatalogAdmission']:
        changed = copy.deepcopy(receipt); del changed['v46CatalogAdmission'][key]; mutations.append(changed)
    for fields in [{'objectiveId': 'other'}, {'fixtureLocalCandidateAdmission': True},
                   {'fixtureLocalCandidateAdmission': 0}, {'productionQualification': 'pending'},
                   {'productionDefaultEnabled': True}, {'productionDefaultEnabled': 0}, {'extra': True}]:
        changed = copy.deepcopy(receipt); changed['v46CatalogAdmission'].update(fields); mutations.append(changed)
    mutations.extend([receipt | {'v46CatalogAdmission': None}, receipt | {'extra': True},
                      {key: val for key, val in receipt.items() if key != 'v46CatalogAdmission'}])
    mutations.extend(receipt | {flag: False} for flag in value['STANDALONE_ASSESSMENT_RECEIPT_FLAGS'])
    for changed in mutations:
        try: check(changed)
        except RuntimeError: pass
        else: raise AssertionError('Changed native V46 catalog admission or lifecycle flag accepted')


def test_v44_native_admission_requires_clean_result_and_exact_executed_source(tmp_path):
    from types import SimpleNamespace
    value=v46_namespace('validate_v44_native_result','validate_v44_path_pins','complete_tap_counts')
    root=SOURCE.resolve().parents[2]
    actual=tmp_path/'result.json'
    result={key:True for key in ('passed','sourceUnchanged','dependenciesUnchanged','containerAbsent','childGroupsAbsent','graph','ownedFileEffect')}
    result.update({key:False for key in ('sourceCopies','actualModel','browser','judgeOrCredit')})
    result.update(exitCode=0,expectedTests=2,fixture='tests/postgres/secureshopV19FileSummaryNative.integration.test.js',cleanupErrors=[],sourceHashes=value['V44_NATIVE_PINS'])
    titles=['0107/0108/0109 fresh, populated and no-op preserve historical purposes, ledger, operator ACL edits and sibling evidence',
            'default graph persists real PG policy/turn/effect and owned bytes; replay/read cannot duplicate or repair effects']
    tap=tmp_path/'test.stdout.log';tap.write_text('TAP version 13\n'+''.join(f'# Subtest: {title}\nok {i} - {title}\n' for i,title in enumerate(titles,1))+'1..2\n# tests 2\n# pass 2\n# fail 0\n# skipped 0\n# cancelled 0\n');tap.chmod(0o600)
    result.update(stdoutSha256=value['digest'](tap),sourceHashesAfter=result['sourceHashes'])
    actual.write_text(value['json'].dumps(result));actual.chmod(0o600)
    args=SimpleNamespace(v44_native_result=str(actual),v44_native_result_sha256=value['digest'](actual))
    assert value['validate_v44_native_result'](args,root)['passed'] is True
    for key in value['V44_NATIVE_PINS']:
        old=value['digest'];value['digest']=lambda path: '0'*64 if path == root/key else old(path)
        try:value['validate_v44_native_result'](args,root)
        except RuntimeError as error:assert str(error)=='V44 native executed source incompatible: '+key
        else:raise AssertionError('Changed native-executed V44 input accepted')
        finally:value['digest']=old
    assert value['validate_v44_path_pins'](root,value['digest']) == tuple(value['V44_PATH_PINS'])


def test_v44_support_receipt_is_closed_and_candidate_bool_is_distinct(tmp_path):
    value=v46_namespace('v44_path_support_receipt')
    receipt={key:True for key in value['V44_PATH_FLAGS']}
    receipt.update(scope=value['V44_PATH_SCOPE'],actualModelCalls=4,chatTurns=0,judgeCalls=1,cleanupErrors=[])
    target=tmp_path/'v44-support.json'
    for candidate in (True,False):
        receipt['fixtureLocalCandidateAdmission']=candidate
        target.write_text(value['json'].dumps(receipt));target.chmod(0o600)
        assert value['v44_path_support_receipt'](target)==receipt
    for change in ({'actualModelCalls':True},{'judgeCalls':0},{'fixtureLocalCandidateAdmission':1},{'extra':True},{'fixedNoReadJudgeCredit':False},{'cleanupErrors':['remaining']}):
        target.write_text(value['json'].dumps(receipt|change))
        try:value['v44_path_support_receipt'](target)
        except RuntimeError:pass
        else:raise AssertionError('Invalid V44 support accepted: '+str(change))


def test_v44_cleanup_projection_binds_real_reader_receipt_and_rejects_mutations(tmp_path):
    import copy,json,subprocess
    value=v46_namespace('validate_v44_cleanup_receipt')
    root=SOURCE.resolve().parents[2]
    node='/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node'
    program="""const {randomUUID}=require('node:crypto');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:17,platformSessionId:29};
const targetId=randomUUID(),resetId=randomUUID(),binding={targetId,launchId:scope.launchId,scenarioId:scope.scenarioId,generation:scope.generation,ownerId:String(scope.platformOwnerId)};
const files=require('./sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:process.argv[1]});
(async()=>{await files.provisionReservedTarget(binding);await files.retireReservedTarget(binding,{operationId:resetId,authorize:async()=>true});
const cleanupReceipt=await require('./server/services/secureshopFileCleanupReceiptReader').createSecureShopFileCleanupReceiptReader({files,cleanupAuthority:{checkTarget:async()=>({status:'committed'})}})({...scope,targetKind:'files',targetId,fromGeneration:scope.generation,operationId:resetId});
console.log(JSON.stringify({cleanupReceipt,reset:{resetId},vulnerable:{evidence:{retained:{receipt:{targetId,authority:{scope}}}}}}));})().catch(error=>{console.error(error);process.exitCode=1;});"""
    original=json.loads(subprocess.run([node,'-e',program,str(tmp_path/'owned-files')],cwd=root,
        check=True,capture_output=True,text=True,timeout=15).stdout)
    value['validate_v44_cleanup_receipt'](original)
    changes=[{'extra':True},{'version':True},{'kind':'reviews'},{'receiptSha256':'0'*64},
        {'completedAt':'2026-02-30T00:00:00.000Z'},{'completedAt':'2026-10-16T00:00:00Z'},
        {'generation':True},{'platformOwnerId':True},{'platformSessionId':True}]
    for key in ('targetId','launchId','scenarioId','operationId'):
        changes.append({key:'00000000-0000-4000-8000-000000000001'})
    for key in ('generation','platformOwnerId','platformSessionId'):
        changes.append({key:original['cleanupReceipt'][key]+1})
    for change in changes:
        mutated=copy.deepcopy(original);mutated['cleanupReceipt'].update(change)
        try:value['validate_v44_cleanup_receipt'](mutated)
        except RuntimeError:pass
        else:raise AssertionError('Changed V44 cleanup projection accepted: '+str(change))
    for key in original['cleanupReceipt']:
        mutated=copy.deepcopy(original);del mutated['cleanupReceipt'][key]
        try:value['validate_v44_cleanup_receipt'](mutated)
        except RuntimeError:pass
        else:raise AssertionError('Incomplete V44 cleanup projection accepted: '+key)
    function=next(n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='v44_path_browser_receipt')
    assert 'validate_v44_cleanup_receipt(original)' in ast.unparse(function)


def test_v44_json_child_environment_is_distinct_and_dispatch_preserves_all_gates(tmp_path):
    from types import SimpleNamespace
    value=v46_namespace('main');tree=ast.parse(SOURCE.read_text())
    main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    branches=[n for n in ast.walk(main) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.cohort == V44_PATH_BROWSER']
    environment=next(n for n in branches if any(isinstance(c,ast.Expr) and isinstance(c.value,ast.Call) and ast.unparse(c.value.func)=='env.update' for c in n.body))
    root=SOURCE.resolve().parents[2];pairs={key:{'runtime':key+'-runtime','migration':key+'-migration'} for key in ('identity','agents','reviews','commerce')}
    value.update(args=SimpleNamespace(cohort=value['V44_PATH_BROWSER'],browser='/pinned/chrome',node='/pinned/node'),source=root,runtime=tmp_path,clean={'PATH':'/pinned:/usr/bin:/bin'},**pairs)
    base=next(n for n in ast.walk(main) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='env' for t in n.targets))
    exec(compile(ast.Module(body=[base]+environment.body,type_ignores=[]),str(SOURCE),'exec'),value)
    env=value['env'];assert env['SECURESHOP_V44_FILE_PATH_SUMMARY_BROWSER_NATIVE']=='1'
    assert env['PG_TEST_DISPOSABLE']=='yes';assert env['PUPPETEER_EXECUTABLE_PATH']=='/pinned/chrome'
    assert env['SECURESHOP_V44_FILES_ROOT']==str(tmp_path/'v44-owned-files')
    assert not any(k in env for k in ('SECURESHOP_V06_UPLOAD_BROWSER_NATIVE','SECURESHOP_V46_TRAVERSAL_BROWSER_NATIVE','SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE'))
    for key,pair in [('IDENTITY',pairs['identity']),('AGENTS',pairs['agents']),('REVIEW',pairs['reviews']),('COMMERCE',pairs['commerce'])]:
        assert env[f'PG_SECURESHOP_CUSTOMER_CHECKOUT_{key}_RUNTIME_URL']==pair['runtime']
    dispatch=next(n for n in branches if any(isinstance(c,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='support_path' for t in c.targets) for c in n.body))
    text=ast.unparse(dispatch)
    for required in ('V44_PATH_TEST','V44_PATH_ASSERTION','validate_v44_path_pins','v44_path_browser_receipt','v44_path_support_receipt','verify_ollama_model','standalone_browser_cleanup_state','final_model != model_pin'):
        assert required in text


def test_v44_owned_root_cleanup_requires_exact_inode_and_closed_runtime_child(tmp_path):
    import shutil,stat,os
    value=v46_namespace('cleanup_v19_files_root');value.update(shutil=shutil,stat=stat,os=os)
    root=tmp_path/'v44-owned-files';root.mkdir(mode=0o700);(root/'owned-synthetic.txt').write_text('owned')
    current=root.lstat();identity=(current.st_dev,current.st_ino,current.st_uid)
    for changed in [(identity[0],identity[1]+1,identity[2]),None]:
        try:value['cleanup_v19_files_root'](root,changed,tmp_path,'v44-owned-files')
        except RuntimeError:pass
        else:raise AssertionError('Changed owned-files root identity accepted')
        assert root.exists()
    assert value['cleanup_v19_files_root'](root,identity,tmp_path,'v44-owned-files') is True
    assert not root.exists()
    source=SOURCE.read_text()
    assert "cleanup['v44OwnedFilesAbsent']=cleanup_v19_files_root(v44_files_root,v44_files_identity,runtime,'v44-owned-files')" in source
    assert "args.cohort != V44_PATH_BROWSER or cleanup.get('v44OwnedFilesAbsent') is True" in source


def test_v07_closed_selector_preserves_default_and_ten_call_flow():
    import argparse
    values=v46_namespace('parser')
    values.update(argparse=argparse,C32_COHORT='standalone-ssrf-browser')
    arguments=values['parser']()
    base=['--main-workspace','/owned','--node','/node','--docker','/docker','--docker-sha256','a'*64,'--docker-host','owned','--docker-daemon','owned']
    assert arguments.parse_args(base).upload_polyglot is False
    assert arguments.parse_args(base+['--upload-polyglot']).upload_polyglot is True
    source=SOURCE.read_text()
    for phrase in ["args.upload_polyglot and args.cohort != V06_UPLOAD_BROWSER", "V07 supporting proof is selector exclusive", "'maximumPhysicalModelCalls':10", "'physicalJudgeCalls':2", "mode='upload-preview'", "SECURESHOP_V07_POLYGLOT_BROWSER_NATIVE='1'", "elif args.upload_polyglot:", "'v07-polyglot' if args.upload_polyglot", "v07PolyglotBrowserReceipt=v07_upload_result"]:
        assert phrase in source,phrase
    assert len(constants()['V07_UPLOAD_FLAGS'])==23


def test_v07_receipt_requires_closed_budget_admission_hash_and_raw_bridge(tmp_path):
    import copy,json,hashlib
    from types import SimpleNamespace
    value=v46_namespace('v07_upload_receipt')
    calls=[]
    value.update(mail_inline_private_json=lambda p,limit:json.loads(Path(p).read_text()),
                 subprocess=SimpleNamespace(run=lambda argv,**kw:calls.append((argv,kw))))
    target=tmp_path/'receipt.json';evidence=tmp_path/'v07-original-evidence.json'
    admission={'objectiveId':'ss_upload_polyglot_server_execution','fixtureLocalCandidateAdmission':True,'productionQualification':'pending','productionDefaultEnabled':False}
    document={'catalogAdmission':admission,'polyglot':{}}
    receipt={key:True for key in value['V07_UPLOAD_FLAGS']}
    receipt.update(scope=value['V07_UPLOAD_SCOPE'],actorCalls=8,physicalJudgeCalls=2,uploadPosts=2,previewPosts=2,assessmentPosts=2,genuineCredit=1,errors=[])
    def write(r,d):
        evidence.write_text(json.dumps(d));r=copy.deepcopy(r);r['evidenceSha256']=hashlib.sha256(evidence.read_bytes()).hexdigest();target.write_text(json.dumps(r));return r
    original=write(receipt,document)
    assert value['v07_upload_receipt'](target,'/node',tmp_path)==original
    assert len(calls)==1 and 'assertV07OriginalCapture' in calls[0][0][2]
    for change in [{'actorCalls':True},{'physicalJudgeCalls':1},{'previewPosts':3},{'passed':False},{'fixtureLocalCandidateAdmission':1},{'extra':True}]:
        write({**receipt,**change},document)
        try:value['v07_upload_receipt'](target,'/node',tmp_path)
        except RuntimeError:pass
        else:raise AssertionError('Accepted incomplete V07 receipt '+str(change))
    for change in [{'productionDefaultEnabled':0},{'fixtureLocalCandidateAdmission':1},{'productionQualification':'native-browser-judge'},{'extra':True}]:
        changed=copy.deepcopy(document);changed['catalogAdmission'].update(change);write(receipt,changed)
        try:value['v07_upload_receipt'](target,'/node',tmp_path)
        except RuntimeError:pass
        else:raise AssertionError('Accepted false V07 admission '+str(change))
    write(receipt,document);evidence.write_text('{}')
    try:value['v07_upload_receipt'](target,'/node',tmp_path)
    except RuntimeError:pass
    else:raise AssertionError('Accepted changed original capture')
    assert len(calls)==1
