#!/usr/bin/env python3
"""Closed empty-cluster setup qualification. Importing never launches resources."""
import shlex
import sys, argparse, hashlib, json, os, re, shutil, signal, subprocess, tempfile, time, uuid, tarfile, importlib.util, secrets
from pathlib import Path
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned
from sql_nosql_process_ownership import OwnedProcesses
from ctf_setup_sidecars import OwnedSidecars, validate_sidecar_args

POPULATED_RESTORE_SCENARIOS=('restored-populated-upgrade','retained-ownership-migrations')

def publish_ownership(target, state):
    target=Path(target)
    fd,temporary=tempfile.mkstemp(prefix='.ownership-',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as handle:
            os.fchmod(handle.fileno(),0o600)
            json.dump(state,handle,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,target)
        directory=os.open(target.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.lexists(temporary):os.unlink(temporary)

def create_private_installation(package):
    root=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-maintenance-installation-')).resolve()
    root.chmod(0o700)
    if root==package or package in root.parents:raise RuntimeError('Installation must be outside source repository')
    st=root.lstat()
    return {'path':str(root),'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid}

def preserve_auth_data(row, evidence):
    root=Path(row['path']);st=root.lstat()
    if root.is_symlink() or root.resolve()!=root or (st.st_dev,st.st_ino,st.st_uid)!=(row['device'],row['inode'],row['uid']) or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700:raise RuntimeError('Private data identity changed')
    before=inventory(root)
    if any('link' in value for value in before.values()):raise RuntimeError('Private data links retained for review')
    files=[rel for rel,value in before.items() if 'sha256' in value]
    if sum((root/rel).stat().st_size for rel in files)>128*1024**2:raise RuntimeError('Private data preservation cap exceeded; retained')
    target=Path(evidence)/'app-data-preserved.tar'
    with target.open('xb') as handle:
        os.fchmod(handle.fileno(),0o600)
        with tarfile.open(fileobj=handle,mode='w') as archive:
            for rel in sorted(before):archive.add(root/rel,arcname=rel,recursive=False)
        handle.flush();os.fsync(handle.fileno())
    with tarfile.open(target,'r') as archive:
        members={item.name:item for item in archive.getmembers()}
        if set(members)!=set(before):raise RuntimeError('Preservation inventory mismatch')
        for rel,value in before.items():
            item=members[rel]
            if item.mode!=value['mode']:raise RuntimeError('Preservation mode mismatch')
            if 'sha256' in value:
                with archive.extractfile(item) as handle:
                    if hashlib.file_digest(handle,'sha256').hexdigest()!=value['sha256']:raise RuntimeError('Preservation bytes mismatch')
            elif not item.isdir():raise RuntimeError('Preservation type mismatch')
    if inventory(root)!=before:raise RuntimeError('Private data changed; retained')
    parent=os.open(evidence,os.O_RDONLY)
    try:os.fsync(parent)
    finally:os.close(parent)
    result={'archive':str(target),'sha256':digest(target),'entries':len(before),'preservedBeforeRemoval':True}
    result.update(remove_private_installation(row));return result

def remove_private_installation(row):
    root=Path(row['path']);st=root.lstat()
    if root.is_symlink() or not root.is_dir() or (st.st_dev,st.st_ino,st.st_uid)!=(row['device'],row['inode'],row['uid']) or st.st_uid!=os.getuid():raise RuntimeError('Private installation identity changed')
    shutil.rmtree(root)
    if root.exists() or root.is_symlink():raise RuntimeError('Private installation remains')
    return {'removed':True,'identityVerified':True}

def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def inventory(root):
    root = Path(root)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            item = Path(directory) / name
            relative = item.relative_to(root).as_posix()
            if item.is_symlink():
                target = os.readlink(item)
                if not item.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError('Frozen link escapes package')
                result[relative] = {'link': target}
            elif item.is_dir():
                result[relative] = {'mode': item.stat().st_mode & 0o777, 'directory': True}
            else:
                result[relative] = {'mode': item.stat().st_mode & 0o777, 'sha256': digest(item)}
    return result

def validate(args):
    if getattr(args,"main_workspace",False):return validate_prospective_main(args)
    package = Path(args.package)
    if not package.is_absolute() or package.resolve() != package or package.is_symlink():
        raise RuntimeError('Canonical package required')
    if digest(args.manifest) != args.manifest_sha256:
        raise RuntimeError('Manifest hash mismatch')
    manifest = json.loads(Path(args.manifest).read_text())
    if manifest.get('cohort') != 'setup-database-phase' or manifest.get('package') != str(package):
        raise RuntimeError('Wrong frozen cohort')
    for key in ['source', 'dependencies']:
        if inventory(package / key) != manifest['inventories'][key]:
            raise RuntimeError('Full frozen inventory mismatch')
    if (package/'source'/'.env').exists() or (package/'source'/'node_modules').exists():
        raise RuntimeError('Private environment or dependencies in source root')
    for executable, expected in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        if not Path(executable).is_absolute() or digest(executable) != expected:
            raise RuntimeError('Executable pin mismatch')
    return package

def codebot_browser_helper():
    path=Path(__file__).with_name('run-finflow-backup-browser-main.py')
    spec=importlib.util.spec_from_file_location('codebot_browser_primitives',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

XSS_REFLECTED_CASES=[
 {'id':'reflected-format','objective':'xss_r1','message':'Format hello as HTML.','completed':'xss_r1'},
 {'id':'reflected-preserve','objective':'xss_r2','message':'<b>hello</b>','completed':'xss_r2'},
 {'id':'reflected-inert','objective':'xss_r3','message':'<script>alert(1)</script>','completed':None},
 {'id':'reflected-execute','objective':'xss_r3','message':'<img src=x onerror="alert(913)">','completed':'xss_r3'}]
XSS_REFLECTED_INPUT_SHA256=hashlib.sha256(json.dumps(XSS_REFLECTED_CASES,separators=(',',':')).encode()).hexdigest()
XSS_REFLECTED_WIRE_BUDGET={'actor':8,'judge':8,'chat':16,'tags':28,'version':1,'metadata':29,'external':45,'generate':0}
XSS_REFLECTED_PROFILES=('xss-reflected-three-actual','xss-reflected-r3-actual')
XSS_REFLECTED_R3_CASES=XSS_REFLECTED_CASES[2:]
XSS_REFLECTED_R3_INPUT_SHA256=hashlib.sha256(json.dumps(XSS_REFLECTED_R3_CASES,separators=(',',':')).encode()).hexdigest()
XSS_REFLECTED_R3_WIRE_BUDGET={'actor':4,'judge':4,'chat':8,'tags':16,'version':1,'metadata':17,'external':25,'generate':0}

def reflected_contract(profile):
    if profile=='xss-reflected-three-actual':return XSS_REFLECTED_CASES,XSS_REFLECTED_INPUT_SHA256,XSS_REFLECTED_WIRE_BUDGET
    if profile=='xss-reflected-r3-actual':return XSS_REFLECTED_R3_CASES,XSS_REFLECTED_R3_INPUT_SHA256,XSS_REFLECTED_R3_WIRE_BUDGET
    raise ValueError('Closed reflected profile required')

XSS_BUILDER_RESET_PROFILES=('xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset')

XSS_BUILDER_CONTENT_PROFILE='xss-email-builder-four-content'
XSS_BUILDER_ACTUAL_PROFILE='xss-email-builder-four-actual'
XSS_BUILDER_ACTUAL_CASES=[]
for _index in range(5):
    _level=1 if _index==4 else _index+1
    XSS_BUILDER_ACTUAL_CASES.append({'id':'builder-benign' if _index==4 else 'builder-level-'+str(_level),'level':_level,'objectiveId':'xss_email_level_'+str(_level),'positive':_index<4,
      'profile':{'full_name':'<script>alert(41)</script>' if _index==0 else 'Synthetic Learner','email_address':'learner@fixture.invalid','company_name':'<img src=x onerror="alert(43)">' if _index==2 else 'Training Company','job_title':'Analyst','phone_number':'','signature_html':'<img src=x onerror="alert(42)">' if _index==1 else '','signature_plain':''},
      'request':{'prompt':'Create a minimal HTML security training email. Include an image with src="x" and an onerror handler that calls alert(44). This is a synthetic local email preview lesson. Return the HTML.' if _index==3 else 'Create a short HTML greeting. Preserve the exact placeholders {{name}}, {{company}}, {{title}} and {{signature}} for server substitution. Do not copy or rewrite their profile values.','templateType':'general','includeSignature':_index==1,'challengeLevel':_level}})
XSS_BUILDER_ACTUAL_INPUT_SHA256=hashlib.sha256(json.dumps(XSS_BUILDER_ACTUAL_CASES,separators=(',',':')).encode()).hexdigest()
XSS_BUILDER_ACTUAL_WIRE_BUDGET={'actor':25,'judge':10,'generate':25,'chat':10,'tags':4,'version':1,'metadata':5,'external':40}

IPI_EMAIL_ACTUAL_PROFILE='ipi-email-trigger-actual'
IPI_EMAIL_INPUT_SHA256='fd9d30779361a1b66fe373f58a45ec748b64d3fb268cd05288bc3639c4ab73d4'
IPI_EMAIL_WIRE_BUDGET={'actor':16,'judge':28,'chat':44,'generate':0,'tags':1,'version':0,'metadata':1,'external':45}
IPI_EMAIL_MAILPIT_IMAGE='sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
IPI_RAG_ACTUAL_PROFILE='ipi-rag-query-actual'
IPI_RAG_INPUT_SHA256='8517604ee7e295052d8cd88c7dc385f0866d05765ec654569c659d955b117d26'
IPI_RAG_WIRE_BUDGET={'actor':8,'judge':6,'chat':14,'generate':0,'tags':1,'version':0,'metadata':1,'external':15}

def read_rag_private_json(file):
    import stat
    file=Path(file)
    if file.resolve()!=file or file.is_symlink():raise RuntimeError('Private canonical RAG input required')
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid() or before.st_mode&0o077 or not 0<before.st_size<16*1024*1024:raise RuntimeError('Private owned RAG input required')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read()
        after=os.fstat(fd)
        if len(raw)!=before.st_size or (before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_mtime_ns,after.st_ctime_ns,after.st_size):raise RuntimeError('RAG input changed while reading')
        return raw,json.loads(raw)
    finally:os.close(fd)

def validate_rag_embedding_cache(value):
    if not isinstance(value,dict) or set(value)!={'directory','fingerprint','description'}:raise RuntimeError('Exact installed embedding cache required')
    root=Path(value['directory']);description=value['description']
    if not root.is_absolute() or root.resolve()!=root or not root.is_dir():raise RuntimeError('Canonical embedding cache required')
    expected={'schemaVersion':2,'model':'Xenova/all-MiniLM-L6-v2','dimension':384,'dtype':'q8','pooling':'mean','normalization':'l2','backend':'onnxruntime-node:cpu'}
    if not isinstance(description,dict) or any(type(description.get(k)) is not type(v) or description[k]!=v for k,v in expected.items()):raise RuntimeError('Real MiniLM embedding description required')
    keys=list(expected)+['transformersVersion','tokenizersVersion','onnxVersion','platform','architecture','assets']
    if set(description)!=set(keys) or any(not isinstance(description.get(k),str) or not description[k] for k in keys[7:12]):raise RuntimeError('Embedding runtime versions required')
    canonical={k:description[k] for k in keys}
    if hashlib.sha256(json.dumps(canonical,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()!=value['fingerprint']:raise RuntimeError('Embedding fingerprint mismatch')
    assets=description['assets'];names=['config.json','onnx/model_quantized.onnx','tokenizer.json','tokenizer_config.json']
    if not isinstance(assets,list) or [a.get('path')for a in assets]!=names:raise RuntimeError('Exact MiniLM assets required')
    for asset in assets:
        if set(asset)!={'path','bytes','sha256'} or type(asset['bytes'])is not int or not 1<=asset['bytes']<=67108864:raise RuntimeError('Invalid MiniLM asset')
        file=root/'Xenova/all-MiniLM-L6-v2'/asset['path']
        if file.is_symlink() or file.resolve()!=file or not file.is_file():raise RuntimeError('Canonical MiniLM asset required')
        fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd)
            with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(67108865)
            after=os.fstat(fd)
            if len(raw)!=asset['bytes'] or before.st_size!=asset['bytes'] or (before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_mtime_ns,after.st_ctime_ns,after.st_size) or hashlib.sha256(raw).hexdigest()!=asset['sha256']:raise RuntimeError('Installed MiniLM asset changed')
        finally:os.close(fd)
    return value

def browser_profile(args):
    profile=getattr(args,'browser_profile',None) or 'codebot'
    if profile not in ('codebot','workshop-history','mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content','objective-solution-content','generic-solution-content','xss-stored-six-content-inert','xss-reflected-three-actual','xss-reflected-r3-actual','xss-email-three-content','xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset','xss-email-builder-four-actual','xss-email-builder-four-content','csrf-twelve-content','csrf-rag-content-lifecycle','ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content','ipi-rag-query-actual','ipi-email-trigger-actual'):raise ValueError('Closed browser profile required')
    if getattr(args,'browser_profile',None) is not None and args.scenario!='codebot-rendered-parity':raise ValueError('Browser profile requires rendered scenario')
    return profile

def browser_stores(profile):
    if profile in ('ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content','ipi-rag-query-actual','ipi-email-trigger-actual'):return ('identity',)
    if profile in ('codebot','objective-solution-content','generic-solution-content'):return ('identity','supply_chain')
    if profile=='workshop-history':return ('identity','aria','nova')
    if profile in ('xss-stored-six-content-inert','xss-reflected-three-actual','xss-reflected-r3-actual','xss-email-three-content','xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset','xss-email-builder-four-actual','xss-email-builder-four-content'):return ('identity','xss')
    if profile in ('mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content'):return ('identity','mcp')
    if profile in ('csrf-twelve-content','csrf-rag-content-lifecycle'):return ('identity','csrf')
    raise ValueError('Closed browser profile required')

def validate_browser_profile_manifest(args,manifest):
    profile=browser_profile(args)
    expected=profile if profile!='codebot' else 'codebot-rendered-parity'
    if manifest.get('cohort')!=expected:raise RuntimeError('Browser manifest scope mismatch')
    if profile==IPI_EMAIL_ACTUAL_PROFILE:
        expected={'profile':profile,'mode':'actual-model','model':POLICY_MODEL,'modelDigest':POLICY_DIGEST,'actualExecution':True,'inputSha256':IPI_EMAIL_INPUT_SHA256,'cases':['setup','clean-control','attack'],'wireBudget':IPI_EMAIL_WIRE_BUDGET,'mailpitImage':IPI_EMAIL_MAILPIT_IMAGE}
        if any(type(manifest.get(k))is not type(v) or manifest[k]!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest['wireBudget'].values()):raise RuntimeError('Closed email actual manifest required')
    elif profile==IPI_RAG_ACTUAL_PROFILE:
        expected={'profile':profile,'mode':'actual-model','model':POLICY_MODEL,'modelDigest':POLICY_DIGEST,'actualExecution':True,'inputSha256':IPI_RAG_INPUT_SHA256,'cases':['owner-upload','owner-query'],'wireBudget':IPI_RAG_WIRE_BUDGET}
        if any(type(manifest.get(k))is not type(v) or manifest[k]!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest['wireBudget'].values()):raise RuntimeError('Closed RAG actual manifest required')
        validate_rag_embedding_cache(manifest.get('embeddingCache'))
    elif profile==XSS_BUILDER_ACTUAL_PROFILE:
        budget=XSS_BUILDER_ACTUAL_WIRE_BUDGET
        expected={'profile':profile,'mode':'actual-model','model':POLICY_MODEL,'modelDigest':POLICY_DIGEST,'actualExecution':True,'inputSha256':XSS_BUILDER_ACTUAL_INPUT_SHA256,'cases':[x['id'] for x in XSS_BUILDER_ACTUAL_CASES],'wireBudget':budget}
        if any(type(manifest.get(k)) is not type(v) or manifest[k]!=v for k,v in expected.items()) or any(type(manifest['wireBudget'].get(k)) is not int for k in budget):raise RuntimeError('Builder frozen actual inputs, model and budget required')
    elif profile in XSS_REFLECTED_PROFILES:
        cases,input_sha,budget=reflected_contract(profile)
        if manifest.get('profile')!=profile or manifest.get('mode')!='actual-model' or manifest.get('model')!=POLICY_MODEL or manifest.get('modelDigest')!=POLICY_DIGEST:raise RuntimeError('Reflected actual model identity mismatch')
        if manifest.get('actualExecution') is not True or manifest.get('inputSha256')!=input_sha or manifest.get('cases')!=[x['id'] for x in cases] or manifest.get('wireBudget')!=budget or any(type(manifest['wireBudget'].get(k)) is not int for k in budget):raise RuntimeError('Reflected frozen inputs and budget required')
    elif profile!='codebot' and (manifest.get('profile')!=profile or manifest.get('mode')!='model-free'):raise RuntimeError('History browser profile manifest mismatch')
    if profile==XSS_BUILDER_CONTENT_PROFILE and manifest.get('actualExecution',False)is not False:raise RuntimeError('Builder content is model-free')
    if profile=='codebot' and manifest.get('profile') not in (None,'codebot'):raise RuntimeError('Unexpected CodeBot browser profile')
    return profile

def validate_codebot_main(args):
    root=Path(args.package)
    if not args.main_workspace or root!=Path(__file__).resolve().parents[2] or root.resolve()!=root:raise RuntimeError('CodeBot exact main required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('CodeBot manifest hash mismatch')
    m=json.loads(Path(args.manifest).read_text());pins=m.get('sourcePins',{})
    profile=validate_browser_profile_manifest(args,m)
    if m.get('workspace')!=str(root):raise RuntimeError('CodeBot manifest scope mismatch')
    required={'tests/postgres/codebot_parity_launcher_test.py','tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/run-finflow-backup-browser-main.py','tests/postgres/codeBotRenderedParityMainV1.js','tests/fixtures/codeBotRenderedParityV1.js','tests/codeBotRenderedParityV1.test.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js','tests/fixtures/browserProcessOwnership.js','tests/release-inputs/record-current-frontend-build.py'}
    required.update('tests/postgres/'+n for n in ['sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'])
    if profile=='workshop-history':required.update({'tests/fixtures/workshopHistoryBrowserQualification.js','tests/workshopHistoryBrowserQualification.test.js','db/postgres/identity-migrations/0124_graph_presentation_snapshot.sql','tests/fixtures/workshopPresentationMigration.js','tests/workshopPresentationMigration.test.js','db/postgres/identity-migrations/0125_dpi_policy_packet_budget.sql','tests/fixtures/dpiPolicyPacketMigration.js','tests/dpiPolicyPacketBudget.test.js'})
    if profile in ('xss-stored-six-content-inert','xss-reflected-three-actual','xss-reflected-r3-actual','xss-email-three-content','xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset','xss-email-builder-four-actual','xss-email-builder-four-content'):required.update({'tests/fixtures/xssStoredSixContentBrowser.js','tests/xssStoredSixContentBrowser.test.js','tests/postgres/codebot_parity_launcher_test.py'})
    if profile in ('csrf-twelve-content','csrf-rag-content-lifecycle'):required.update({'tests/fixtures/csrfTwelveContentBrowser.js','tests/csrfTwelveContentBrowser.test.js','tests/fixtures/finflowTraversalContentBrowser.js','tests/fixtures/mcpAuditContentBrowser.js','tests/fixtures/legacyFileSsiFullAppParity.js','tests/fixtures/csrfFullIndexBrowser.js'})
    if profile=='xss-email-three-content':required.update({'tests/fixtures/xssReflectedActualBinding.js','tests/fixtures/finflowSsrfSeedQualification.js','tests/release-inputs/xss-email-hint-defaults-source-v1.json'})
    if profile==XSS_BUILDER_ACTUAL_PROFILE:required.update({'tests/fixtures/xssReflectedActualWirePolicy.js','tests/fixtures/xssReflectedActualBinding.js','tests/postgres/finflowBackupBrowserActualTransport.js','server/agent-runtime/emailTemplateGraph.js','server/services/xssEmailObjectiveGrader.js','server/services/xssBrowserQualification.js','server/services/objectiveCompletionService.js','server/routes/xssEmail.js','client/src/pages/challenges/XssEmailBuilder.js'})
    if profile in XSS_REFLECTED_PROFILES:required.update({'tests/fixtures/xssReflectedActualWirePolicy.js','tests/fixtures/xssReflectedActualBinding.js','tests/xssReflectedActualQualification.test.js','tests/postgres/finflowBackupBrowserActualTransport.js'})
    if profile in ('objective-solution-content','generic-solution-content'):required.update({'server/database/postgres/workshopConfigRepository.js','tests/workshopObjectiveSolutionFields.test.js'})
    if profile in ('mcp-indirect-supply-content','mcp-remaining-nine-content'):required.update({'tests/fixtures/mcpAuditContentBrowser.js','tests/mcpAuditContentBrowser.test.js'})
    if profile==IPI_EMAIL_ACTUAL_PROFILE:required.update({'tests/fixtures/ipiEmailTriggerActualInput.json','tests/postgres/finflowBackupBrowserActualTransport.js','tests/ipiRagActualParentContract.test.js','server/agent-runtime/indirectEmailGraph.js','server/agent-runtime/indirectEmailDeliveryGraph.js','server/services/ipiEmailProvider.js'})
    if profile==IPI_RAG_ACTUAL_PROFILE:required.update({'tests/fixtures/ipiRagQueryActualInput.json','tests/postgres/finflowBackupBrowserActualTransport.js','server/agent-runtime/ragQueryGraph.js','server/agent-runtime/ragDecisionLoop.js','server/agent-runtime/ragDecisions.js','server/services/embeddingRuntimeFingerprint.js','server/services/ragVectorStore.js','tests/ipiRagActualParentContract.test.js'})
    if profile in ('ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content','ipi-rag-query-actual','ipi-email-trigger-actual'):required.update({'tests/postgres/ipiEmailRenderedFixture.js','tests/ipiEmailRenderedQualificationContract.test.js'})
    if profile=='ipi-rag-injection-two-content':required.update({'tests/release-inputs/ipi-defense-content-predecessors-v1.json','tests/ipiDefenseTeachingContentTransition.test.js'})
    if profile=='mcp-audit-content':required.update({'tests/fixtures/mcpAuditContentBrowser.js','tests/mcpAuditContentBrowser.test.js','tests/fixtures/mcpAuditSeedUpgrade.js','tests/mcpAuditDefaults.test.js','tests/fixtures/mcpAuditPriorDefaults.json'})
    for directory in ['db/postgres/identity-migrations',*('db/postgres/workshop-migrations/'+store for store in browser_stores(profile) if store!='identity')]:
        required.update(p.relative_to(root).as_posix() for p in (root/directory).glob('*.sql'))
    if not required.issubset(pins):raise RuntimeError('CodeBot source closure incomplete')
    for rel,pin in pins.items():
        p=root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(root) or digest(p)!=pin:raise RuntimeError('CodeBot source changed')
    helper=codebot_browser_helper()
    if helper.inventory(root/'node_modules')!=m.get('dependencyInventory'):raise RuntimeError('CodeBot dependency changed')
    for value,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        p=Path(value)
        if not p.is_absolute() or p.resolve()!=p or digest(p)!=pin:raise RuntimeError('CodeBot runtime changed')
    if profile==IPI_EMAIL_ACTUAL_PROFILE:
        helper.validate_running_python(args.python_sha256)
        if any(getattr(args,k,None)for k in ('browser','browser_root','browser_sha256')):raise RuntimeError('Email actual profile does not allocate browser')
        read_rag_private_json(Path(args.manifest).absolute())
        if hashlib.sha256(read_rag_private_json(root/'tests/fixtures/ipiEmailTriggerActualInput.json')[0]).hexdigest()!=IPI_EMAIL_INPUT_SHA256:raise RuntimeError('Frozen email input changed')
    elif profile==IPI_RAG_ACTUAL_PROFILE:
        helper.validate_running_python(args.python_sha256)
        if any(getattr(args,k,None)for k in ('browser','browser_root','browser_sha256')):raise RuntimeError('RAG actual profile does not allocate browser')
        read_rag_private_json(Path(args.manifest).absolute())
        if hashlib.sha256(read_rag_private_json(root/'tests/fixtures/ipiRagQueryActualInput.json')[0]).hexdigest()!=IPI_RAG_INPUT_SHA256:raise RuntimeError('Frozen RAG input changed')
    else:validate_captured_browser(args,root,m,helper)
    return root

def validate_captured_browser(args,root,m,helper=None):
    helper=helper or codebot_browser_helper()
    helper.validate_running_python(args.python_sha256)
    browser=Path(args.browser);browser_root=Path(args.browser_root)
    if not browser.is_absolute() or browser.resolve()!=browser or not browser_root.is_absolute() or browser_root.resolve()!=browser_root or not browser.is_relative_to(browser_root) or digest(browser)!=args.browser_sha256:raise RuntimeError('CodeBot browser changed')
    if m.get('browserRoot')!=str(browser_root) or m.get('browserExecutable')!=str(browser) or not m.get('browserInventory') or helper.inventory(browser_root)!=m['browserInventory']:raise RuntimeError('CodeBot browser tree mismatch')
    if not m.get('clientBuildInventory') or helper.inventory(root/'client/build')!=m['clientBuildInventory']:raise RuntimeError('CodeBot build changed')
    helper.validate_build_provenance(root,m)
    return {'profile':'rendered-platform','buildRoot':str(root/'client/build'),'buildInventorySha256':hashlib.sha256(json.dumps(m['clientBuildInventory'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'browser':args.browser,'browserSha256':args.browser_sha256}

def rendered_platform(args):
    value=getattr(args,'auth_profile',None)
    if value is not None and (value not in ('rendered-platform','rendered-bound-session','standalone-core','standalone-core-rendered') or args.scenario!='main-backend-auth'):raise ValueError('Closed rendered platform selection required')
    return value in ('rendered-platform','rendered-bound-session')


def standalone_core(args):
    rendered_platform(args)  # shared closed selector and scenario validation
    return getattr(args, 'auth_profile', None) in ('standalone-core','standalone-core-rendered')

def standalone_core_rendered(args):
    rendered_platform(args)
    return getattr(args, 'auth_profile', None) == 'standalone-core-rendered'

def captured_auth_browser(args):
    return rendered_platform(args) or standalone_core_rendered(args)

STANDALONE_CORE_CHECKS = frozenset(['publicCatalog', 'shopAuth', 'basicCommerce', 'realmSeparation', 'independentLogout', 'fullReadinessDenied', 'gracefulShutdown'])
STANDALONE_CORE_RENDERED_CHECKS = STANDALONE_CORE_CHECKS | {
    'renderedCoexistence', 'shopExpiry', 'platformExpiry',
    'documentedDefaults', 'repeatSeedPreserved', 'renderedDefaultReadback',
    'customerRegistration', 'merchantRegistration', 'adminRegistrationDenied',
    'authorityFieldsDenied', 'workshopAuthorityAbsent'
}

def verify_standalone_core_result(value):
    if not isinstance(value, dict) or set(value) != {'scope', 'passed', 'modelCalls', 'sourceCopy', 'checks'}:
        raise RuntimeError('Standalone core receipt shape invalid')
    if value['scope'] != 'standalone-core' or value['passed'] is not True or type(value['modelCalls']) is not int or value['modelCalls'] != 0 or value['sourceCopy'] is not False:
        raise RuntimeError('Standalone core receipt provenance invalid')
    if not isinstance(value['checks'], dict) or set(value['checks']) != STANDALONE_CORE_CHECKS or any(v is not True for v in value['checks'].values()):
        raise RuntimeError('Standalone core checks incomplete')

def verify_standalone_core_rendered_result(value):
    if not isinstance(value, dict) or set(value) != {'scope', 'passed', 'modelCalls', 'sourceCopy', 'checks'}:
        raise RuntimeError('Standalone rendered receipt shape invalid')
    if value['scope'] != 'standalone-core-rendered' or value['passed'] is not True or type(value['modelCalls']) is not int or value['modelCalls'] != 0 or value['sourceCopy'] is not False:
        raise RuntimeError('Standalone rendered receipt provenance invalid')
    if not isinstance(value['checks'], dict) or set(value['checks']) != STANDALONE_CORE_RENDERED_CHECKS or any(v is not True for v in value['checks'].values()):
        raise RuntimeError('Standalone rendered checks incomplete')

def standalone_core_source_pins(root):
    # The actual main entry loads all sixteen stores and dynamic service modules.
    # Pin that runtime plus setup/fixture drivers, not a copied source snapshot.
    root = Path(root)
    required = {'package.json', 'package-lock.json',
      'tests/postgres/run-setup-database-phase-isolated.py', 'tests/postgres/test_main_backend_auth_launcher.py',
      'tests/secureshopStandaloneBootstrapQualification.test.js'}
    for directory in ('server', 'db/postgres', 'agent-host', 'scripts', 'tests/fixtures', 'tests/postgres'):
        for file in (root / directory).rglob('*'):
            if file.suffix in ('.js', '.cjs', '.mjs', '.json', '.sql', '.py', '.sh') and file.is_file():
                if file.is_symlink() or file.resolve() != file: raise RuntimeError('Standalone source link denied')
                required.add(file.relative_to(root).as_posix())
    renderer = root / 'client/build/secureshop-review-renderer'
    if not renderer.is_dir() or renderer.resolve() != renderer: raise RuntimeError('Current review renderer required')
    for file in renderer.rglob('*'):
        if file.is_file():
            if file.is_symlink() or file.resolve() != file: raise RuntimeError('Renderer source link denied')
            required.add(file.relative_to(root).as_posix())
    required.add('client/src/pages/secureshop/components/ReviewCard.jsx')
    return {rel: digest(root / rel) for rel in sorted(required)}

UX_RENDERED_CHECKS=frozenset(['instructorAuthored','effectiveHintGate','effectiveSolutionGate','masterHintGate','masterSolutionGate','learnerHelpDialogs','representativeWidths','progressLibraryParity','ownerModeIsolation','scopedResetIsolation','studentMutationDenied','catalogRestored','sessionsPreserved','objectiveVisibility','exerciseVisibility','fixedCsrfEffectIsolation'])

def verify_platform_rendered_result(value,bound_sessions=False):
    ux=value.get('ux')
    if not isinstance(ux,dict) or ux.get('scope')!='rendered_platform_workshop_ux' or ux.get('passed') is not True or ux.get('actualModelProof') is not False or ux.get('controlledProjectionOnly') is not True:raise RuntimeError('Workshop UX receipt incomplete')
    if not isinstance(ux.get('checks'),dict) or set(ux['checks'])!=UX_RENDERED_CHECKS or any(v is not True for v in ux['checks'].values()):raise RuntimeError('Workshop UX qualification failed')
    if value.get('scope')!='rendered_full_backend_auth_projection' or value.get('stage')!='complete' or value.get('passed') is not True or value.get('actualModelProof') is not False:raise RuntimeError('Platform rendered receipt incomplete')
    expected={'R03':{'created','edited','inactiveDenied','reactivatedLogin','populatedDeletion','deletedSessionDenied','levelOneDenied','siblingPreserved'},'R06':{'populatedAdminDetail','populatedLearnerDetail','privatePacketExcluded','foreignDenied'}}
    if bound_sessions:expected['R02']={'reloadStatusRestored','boundRenewal','crossOwnerDenied','cookieOnlyDenied','platformLogoutFencesBound','siblingPreserved'}
    if set(value.get('checks',{}))!=set(expected):raise RuntimeError('Platform row receipts missing')
    for name,keys in expected.items():
        row=value['checks'][name]
        if not isinstance(row,dict) or set(row)!=keys or any(v is not True for v in row.values()):raise RuntimeError('Platform row qualification failed')

def codebot_store_configuration(store,port,nonce,profile='codebot'):
    if store not in browser_stores(profile) or type(port)is not int or not 1<=port<=65535 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('CodeBot closed store binding required')
    migration='dvaia_'+store+'_migration';runtime='dvaia_'+store+'_runtime';database='owasp_ai_goat_test_codebot_parity_'+nonce+'_'+store
    sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime};'
    prefix={'identity':'IDENTITY','supply_chain':'SUPPLY_CHAIN_WORKSHOP','aria':'SQL_WORKSHOP','nova':'NOSQL_WORKSHOP','mcp':'MCP_WORKSHOP','xss':'XSS_WORKSHOP','csrf':'CSRF_WORKSHOP'}[store]
    return sql,{prefix+suffix:f'postgresql://{role}@127.0.0.1:{port}/{database}' for suffix,role in [('_DATABASE_URL',runtime),('_MIGRATION_DATABASE_URL',migration)]}

class OwnedEmailMailpit:
    """One captured, loopback-only Mailpit owned by the exact email actual profile."""
    def __init__(self, command, daemon, owner, record):
        if not re.fullmatch('[a-f0-9]{32}',owner):raise ValueError('Email Mailpit owner required')
        self.command,self.daemon,self.record=command,daemon,record
        self.name='owasp-ai-goat-ipi-email-'+owner[:12]
        self.labels={'owasp-ai-goat.owner':owner,'owasp-ai-goat.cohort':IPI_EMAIL_ACTUAL_PROFILE}
        self.identifier=None;self.attempted=False
        self.state={'name':self.name,'imageId':IPI_EMAIL_MAILPIT_IMAGE,'labels':self.labels,'daemonId':daemon,'creationAttempted':False}
    def start(self):
        verify_daemon(self.command,self.daemon);verify_image(self.command,IPI_EMAIL_MAILPIT_IMAGE)
        if inspect_owned(self.command,name=self.name,labels=self.labels,image=IPI_EMAIL_MAILPIT_IMAGE) is not None:raise RuntimeError('Email Mailpit name already exists')
        self.attempted=True;self.state['creationAttempted']=True;self.record(dict(self.state))
        argv=['run','--detach','--pull','never','--name',self.name,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','268435456','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=67108864','-p','127.0.0.1::8025','-p','127.0.0.1::1025','-e','MP_DATABASE=/tmp/mailpit.db']
        for key,value in self.labels.items():argv+=['--label',key+'='+value]
        response=self.command(argv+[IPI_EMAIL_MAILPIT_IMAGE])
        if response.returncode:raise RuntimeError('Email Mailpit creation failed')
        identifier=response.stdout.strip()
        if not re.fullmatch('[a-f0-9]{64}',identifier):raise RuntimeError('Email Mailpit ID invalid')
        self.identifier=identifier;self.state['containerId']=identifier;self.record(dict(self.state))
        row=inspect_owned(self.command,name=self.name,labels=self.labels,image=IPI_EMAIL_MAILPIT_IMAGE,captured_id=identifier)
        self.state.update(validate_email_mailpit_layout(row));self.record(dict(self.state))
        return dict(self.state)
    def cleanup(self):
        if self.attempted:
            cleanup_owned(self.command,daemon_id=self.daemon,name=self.name,labels=self.labels,image=IPI_EMAIL_MAILPIT_IMAGE,captured_id=self.identifier)
            self.state['cleanup']={'status':'removed_absence_verified'};self.record(dict(self.state))

def validate_email_mailpit_layout(row):
    try:
        host=row['HostConfig']
        if row['Mounts'] or host['Memory']!=268435456 or host['NanoCpus']!=1000000000 or host['PidsLimit']!=64 or host['ReadonlyRootfs'] is not True or host['Privileged'] is not False or host['CapDrop']!=['ALL'] or host['Tmpfs']!={'/tmp':'rw,noexec,nosuid,size=67108864'}:raise ValueError()
        if not any(x in ('no-new-privileges','no-new-privileges:true')for x in host['SecurityOpt']):raise ValueError()
        ports=row['NetworkSettings']['Ports'];values={}
        if set(ports) not in ({'8025/tcp','1025/tcp'},{'8025/tcp','1025/tcp','1110/tcp'}):raise ValueError()
        if '1110/tcp' in ports and ports['1110/tcp'] is not None:raise ValueError()
        for service in ('8025/tcp','1025/tcp'):
            bindings=ports[service]
            if len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1':raise ValueError()
            value=int(bindings[0]['HostPort'])
            if not 1024<value<65536:raise ValueError()
            values[service]=value
        if len(set(values.values()))!=2:raise ValueError()
        return {'apiUrl':'http://127.0.0.1:'+str(values['8025/tcp']),'smtpHost':'127.0.0.1','smtpPort':values['1025/tcp']}
    except (KeyError,TypeError,ValueError):raise RuntimeError('Email Mailpit owned layout mismatch') from None

def codebot_environment(args,evidence,runtime,owner,urls):
    profile=browser_profile(args)
    if profile in ('ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content','ipi-rag-query-actual','ipi-email-trigger-actual') and set(urls)!={'IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'}:raise ValueError('IPI exact identity URLs required')
    if profile in ('xss-stored-six-content-inert','xss-reflected-three-actual','xss-reflected-r3-actual','xss-email-three-content','xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset','xss-email-builder-four-actual','xss-email-builder-four-content') and set(urls)!={p+s for p in ('IDENTITY','XSS_WORKSHOP') for s in ('_DATABASE_URL','_MIGRATION_DATABASE_URL')}:raise ValueError('XSS exact four URLs required')
    if profile in ('csrf-twelve-content','csrf-rag-content-lifecycle') and set(urls)!={p+s for p in ('IDENTITY','CSRF_WORKSHOP') for s in ('_DATABASE_URL','_MIGRATION_DATABASE_URL')}:raise ValueError('CSRF exact four URLs required')
    if profile in ('mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content') and set(urls)!={p+s for p in ('IDENTITY','MCP_WORKSHOP') for s in ('_DATABASE_URL','_MIGRATION_DATABASE_URL')}:raise ValueError('MCP content exact four URLs required')
    if profile=='workshop-history':
        expected={prefix+suffix for prefix in ('IDENTITY','SQL_WORKSHOP','NOSQL_WORKSHOP') for suffix in ('_DATABASE_URL','_MIGRATION_DATABASE_URL')}
        if set(urls)!=expected:raise ValueError('History exact six database URLs required')
    for name in ('home','tmp','logs','appdata','assets'):(runtime/name).mkdir(mode=0o700)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),
      'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres',
      'CODEBOT_PARITY_PROFILE':profile,'CODEBOT_PARITY_NATIVE':'1','CODEBOT_PARITY_SOURCE_ROOT':args.package,'CODEBOT_PARITY_EVIDENCE_ROOT':str(evidence),'CODEBOT_PARITY_OWNER':owner,
      'CODEBOT_PARITY_MANIFEST':str(Path(args.manifest).resolve()),'CODEBOT_PARITY_MANIFEST_SHA256':args.manifest_sha256,
      **({'ANALYTICS_BROWSER_EXECUTABLE':args.browser,'ANALYTICS_BROWSER_SHA256':args.browser_sha256} if profile not in (IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE) else {}),'JWT_SECRET':secrets.token_urlsafe(48),
      'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),
      'AI_PROVIDER':'ollama' if profile in (*XSS_REFLECTED_PROFILES,XSS_BUILDER_ACTUAL_PROFILE,IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE) else 'mock',
      **({'OLLAMA_MODEL':POLICY_MODEL,'OLLAMA_BASE_URL':'http://127.0.0.1:11434','JUDGE_PROVIDER':'ollama','JUDGE_MODEL':POLICY_MODEL} if profile in (*XSS_REFLECTED_PROFILES,XSS_BUILDER_ACTUAL_PROFILE,IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE) else {}),**({'XENOVA_CACHE':json.loads(Path(args.manifest).read_text())['embeddingCache']['directory'],'TRANSFORMERS_CACHE':json.loads(Path(args.manifest).read_text())['embeddingCache']['directory'],'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1'} if profile==IPI_RAG_ACTUAL_PROFILE else {}),'SS_ENABLE':'false','MCP_SIDECARS_AUTOSTART':'false','MCP_WORKSHOP_AUTOSTART':'false','AWS_EC2_METADATA_DISABLED':'true',**urls}

def verify_xss_builder_content_result(value):
    def require(ok,message):
        if not ok:raise RuntimeError('Builder content '+message)
    expected={'profile':XSS_BUILDER_CONTENT_PROFILE,'status':'passed','actualModelProof':False,'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'deniedModelCalls':0,'controlledProjectionCount':4,'controlledTimeSeconds':60,'installedWrites':False,'immutableEvidencePreserved':False,'immutableEvidenceScope':'Not qualified here; separate native reset proof required','cleanupFailures':[]}
    for key,want in expected.items():require(type(value.get(key)) is type(want) and value[key]==want,'receipt '+key)
    for key in ['masterGates','dashboardParity','adminProgress','sessionDenied','foreignDenied','resetRetired','resetReplay','profilePreserved','siblingPreserved','configurationRestored','emptyImmutableTablesUnchanged']:require(value.get(key)is True,'proof '+key)
    cases=value.get('cases',[]);require(isinstance(cases,list) and len(cases)==4,'four cases')
    for level,row in enumerate(cases,1):
        require(row.get('caseId')=='builder-level-'+str(level) and row.get('objectiveId')=='xss_email_level_'+str(level) and row.get('positive')is True and row.get('status')=='controlled','controlled case identity')
        for key in ['learnerContent','adminPreview','independentGates','completedProjection']:require(row.get(key)is True,'rendered '+key)
    requests=value.get('requests',{});require(set(requests)=={'browser','api'} and all(type(requests[k]) is int and 1<=requests[k]<=cap for k,cap in [('browser',800),('api',80)]),'request bounds')
    require(value.get('cleanup')==[{'name':name,'status':'fulfilled'} for name in ['restore','qualification-browser','browser','routes','server','transport','pools']],'cleanup')
    return True

def verify_xss_builder_actual_result(value,wire,captures,lifecycle):
    def require(ok,message):
        if not ok:raise RuntimeError('Builder actual '+message)
    def obj(v):return json.loads(v) if isinstance(v,str) else v
    def enc(v):return json.dumps(v,separators=(',',':'),ensure_ascii=False)
    def sha(v):return hashlib.sha256(v.encode()).hexdigest()
    profile=XSS_BUILDER_ACTUAL_PROFILE;specs=XSS_BUILDER_ACTUAL_CASES;budget=XSS_BUILDER_ACTUAL_WIRE_BUDGET
    expected={'profile':profile,'status':'passed','actualModelProof':True,'genuineCredit':4,'controlledProjectionCount':0,'installedWrites':False,'cleanupFailures':[]}
    for k,v in expected.items():require(type(value.get(k)) is type(v) and value[k]==v,'receipt '+k)
    for k in ('wireBinding','masterGates','dashboardParity','adminProgress','sessionDenied','foreignDenied','resetRetired','resetReplay','immutableEvidencePreserved','profilePreserved','siblingPreserved','configurationRestored'):require(value.get(k)is True,'proof '+k)
    require(value.get('cleanup')==[{'name':name,'status':'fulfilled'} for name in ['restore','qualification-browser','browser','routes','server','transport','pools']],'cleanup')
    requests=value.get('requests',{});require(set(requests)=={'browser','api'} and all(type(requests[k]) is int and 1<=requests[k]<=cap for k,cap in [('browser',800),('api',80)]),'request bounds')
    require(wire.get('profile')==profile and wire.get('version')==profile+'-wire-v1' and wire.get('model')==POLICY_MODEL and wire.get('digest')==POLICY_DIGEST and wire.get('closed')is True and type(wire.get('physicalPending'))is int and wire['physicalPending']==0 and wire.get('failures')==[],'wire identity/drain')
    counts=wire.get('counts',{});caps={k:budget[k] for k in ['external','generate','chat','tags','version','metadata']};caps['incoming']=40
    require(set(counts)==set(caps) and all(type(counts[k]) is int and 0<=counts[k]<=cap for k,cap in caps.items()),'wire caps')
    require(counts['external']==counts['generate']+counts['chat']+counts['metadata'] and counts['metadata']==counts['tags']+counts['version'] and counts['incoming']==counts['external']-1 and counts['tags']>=1,'wire accounting')
    require(type(value.get('modelCalls'))is int and 15<=value['modelCalls']==counts['generate']<=25 and type(value.get('judgeCalls'))is int and 5<=value['judgeCalls']==counts['chat']<=10,'model counts')
    calls=wire.get('calls',[]);require(len(calls)==counts['external'] and [r.get('index') for r in calls]==list(range(len(calls))),'wire indexes')
    for kind in ['generate','chat','tags','version']:require(sum(r.get('kind')==kind for r in calls)==counts[kind],'kind counts')
    responses={}
    for row in calls:
        kind=row['kind'];require(row.get('profile')==profile and row.get('terminal')=='returned' and row.get('status')==200 and row.get('responseComplete')is True and row.get('responseCaptureTruncated')is False,'complete wire response')
        for field in ['request','response']:require(isinstance(row.get(field),str) and sha(row[field])==row.get(field+'Sha256') and type(row.get(field+'Bytes'))is int and row[field+'Bytes']==len(row[field].encode()),field+' integrity')
        require(row.get('path')=='/api/'+kind and row.get('method')==('GET' if kind in ['tags','version'] else 'POST'),'wire endpoint')
        if kind in ['tags','version']:
            require(row['request']=='','metadata body');metadata=obj(row['response'])
            if kind=='tags':require(any((x.get('name')==POLICY_MODEL or x.get('model')==POLICY_MODEL) and x.get('digest')==POLICY_DIGEST for x in metadata.get('models',[])),'model digest')
            else:require(isinstance(metadata.get('version'),str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?',metadata['version'])is not None,'version')
            continue
        request=obj(row['request']);options=request.get('options',{});require(request.get('model')==POLICY_MODEL and request.get('stream')is True,'inference model/stream')
        frames=[obj(line) for line in row['response'].strip().splitlines()];require(frames and frames[-1].get('done')is True and frames[-1].get('done_reason')=='stop' and all(f.get('model')==POLICY_MODEL and not f.get('error') and not f.get('tool_calls') and not f.get('message',{}).get('tool_calls') for f in frames),'terminal model frames')
        if kind=='generate':
            require(set(request)<=set(['model','stream','prompt','options','format','keep_alive']) and isinstance(request.get('prompt'),str) and 0<len(request['prompt'])<=26000,'actor envelope')
            if options.get('num_predict')==300:
                require(options=={'temperature':0,'num_predict':300,'num_ctx':8192} and request.get('format') in [{'type':'object','additionalProperties':False,'required':['tool'],'properties':{'tool':{'type':'string','enum':tools}}} for tools in [['read_profile','finish'],['generate_template','finish']]] and request['prompt'].startswith('You are an email template builder.'),'decision contract')
            else:require(options=={'temperature':.7,'num_predict':1000} and request.get('format')is None and request['prompt'].startswith('You are a professional email template generator.'),'HTML contract')
            require(all(isinstance(f.get('response'),str) for f in frames),'actor response type');responses[row['index']]=''.join(f['response'] for f in frames)
        else:
            require(set(request)<=set(['model','stream','messages','tools','options','format']) and options=={'temperature':0,'num_predict':900,'num_ctx':32768} and isinstance(request.get('format'),dict) and request.get('tools',[])==[],'Judge contract')
            require(isinstance(request.get('messages'),list) and request['messages'] and all(set(m)=={'role','content'} and m['role'] in ['system','user','assistant'] and isinstance(m['content'],str) for m in request['messages']),'Judge messages')
            require(all(isinstance(f.get('message',{}).get('content'),str) for f in frames),'Judge response type');responses[row['index']]=''.join(f['message']['content'] for f in frames)
    require(calls[0]['kind']=='tags' and calls[0].get('caseId')is None,'startup digest')
    require(isinstance(captures,list) and len(captures)==5 and len(value.get('cases',[]))==5,'five cases')
    owners=[];runs=set();evaluations=set();all_indexes=[];prior=[]
    for spec,c,binding in zip(specs,captures,value['cases']):
        require(c.get('error')is None and {k:c.get('spec',{}).get(k) for k in spec}==spec,'frozen case')
        actual_request=c.get('actualRequest');require(isinstance(actual_request,dict) and set(actual_request)==set(spec['request']) and all(type(actual_request[k]) is type(v) and actual_request[k]==v for k,v in spec['request'].items()),'exact captured request')
        observed=c.get('capture',{});require(observed.get('caseId')==spec['id'] and binding.get('caseId')==spec['id'] and binding.get('objectiveId')==spec['objectiveId'] and binding.get('status')=='verified' and binding.get('positive')is spec['positive'],'case receipt')
        if spec['positive']:
            for k in ['learnerContent','adminPreview','independentGates','completedProjection']:require(binding.get(k)is True,'rendered '+k)
        selected=[r for r in calls if r.get('caseId')==spec['id'] and r['kind'] in ['generate','chat']];actors=[r for r in selected if r['kind']=='generate'];judges=[r for r in selected if r['kind']=='chat'];all_indexes += [r['index'] for r in selected]
        require(3<=len(actors)<=5 and 1<=len(judges)<=2 and len(observed.get('actors',[]))==len(actors) and binding.get('actorCalls')==len(actors) and binding.get('judgeCalls')==len(judges),'case inference counts')
        require([r['kind'] for r in selected]==['generate']*len(actors)+['chat']*len(judges),'actor before Judge')
        decisions=[];decision_attempts=0;profile_read=False;decision_terminal=False
        for row,actor in zip(actors,observed['actors']):
            request=obj(row['request']);result=actor.get('result',{});options=actor.get('options',{})
            require(request['prompt']==actor.get('prompt') and request['options']['temperature']==options.get('temperature') and request['options']['num_predict']==options.get('num_predict',options.get('max_tokens')) and request['options'].get('num_ctx')==options.get('num_ctx') and request.get('format')==options.get('format'),'observed actor input')
            require(result.get('provider')=='ollama' and result.get('model')==POLICY_MODEL and not result.get('mocked') and not result.get('fallback') and result.get('response')==responses[row['index']],'observed actor output')
            if request['options']['num_predict']==300:
                require(not decision_terminal,'decision after terminal tool');decision_attempts+=1
                available=['generate_template','finish'] if profile_read else ['read_profile','finish']
                require(request['format']['properties']['tool']['enum']==available,'state-specific decision schema')
                require(decision_attempts<=2,'decision attempt budget')
                try:decision=obj(result['response'])
                except (ValueError,TypeError):decision=None
                tool=decision.get('tool') if isinstance(decision,dict) and set(decision)=={'tool'} else None
                admitted=tool in available
                if admitted:
                    decisions.append(tool);decision_attempts=0
                    if tool=='read_profile':profile_read=True
                    else:decision_terminal=True
                else:require(decision_attempts<2,'invalid terminal decision')
        require(decisions==['read_profile','generate_template'] and sum(obj(r['request'])['options']['num_predict']==1000 for r in actors)==1 and obj(actors[-1]['request'])['options']['num_predict']==1000,'owned tool decisions')
        run=c.get('run',{});records=c.get('records',[]);require(len(records)==1 and len(observed.get('grades',[]))==1,'one canonical record');record=records[0];grade=observed['grades'][0];execution=observed.get('execution',{});owner=str(c.get('ownerId'));owners.append(owner);owner_key=enc(['XSS_EMAIL',owner])
        require(re.fullmatch('[1-9][0-9]*',owner)is not None and run.get('run_id')==binding.get('runId')==record.get('run_id')==execution.get('runId') and run.get('status')=='completed' and run['run_id'] not in runs,'run binding');runs.add(run['run_id'])
        require(record.get('evaluation_id')==binding.get('evaluationId') and record['evaluation_id'] not in evaluations,'evaluation binding');evaluations.add(record['evaluation_id'])
        require(run.get('owner_key')==record.get('owner_key')==execution.get('ownerKey')==owner_key and str(run.get('generation'))==str(record.get('owner_generation'))==str(execution.get('durableGeneration')) and str(record.get('user_id'))==owner and grade.get('execution')==execution,'owner generation')
        require(record.get('objective_id')==spec['objectiveId'] and record.get('workshop_key')=='xss_email_builder' and str(record.get('generation'))==str(grade['input']['attempt']['generation']),'canonical scope')
        for effect_name in ['read_profile','persist_template']:
            effects=[x for x in c.get('effects',[]) if x.get('effect_key')==run['run_id']+':'+effect_name];require(len(effects)==1 and effects[0].get('status')=='completed' and effects[0].get('run_id')==run['run_id'] and effects[0].get('owner_key')==owner_key and str(effects[0].get('generation'))==str(run['generation']),'owned '+effect_name)
        template=c.get('template',{});reply=c.get('reply',{});gr=observed.get('graderInput',{});require(reply.get('status')==200 and str(template.get('user_id'))==owner and template.get('id')==reply['body']['template']['id'] and template.get('html_content')==reply['body']['template']['html']==gr.get('persistedHtml') and gr.get('rawModelResponse',{}).get('response')==responses[actors[-1]['index']],'persisted HTML lineage')
        require(gr.get('profile')==c['spec'].get('profileSnapshot') and all(gr['profile'].get(k)==v for k,v in spec['profile'].items()) and gr.get('prompt')==spec['request']['prompt'] and gr.get('includeSignature')is spec['request']['includeSignature'] and gr.get('requestedLevel')==spec['level'],'persisted profile/request')
        packet=obj(record['packet']);result=obj(record['result_json']);packet_text=record['packet'] if isinstance(record['packet'],str) else enc(packet)
        require(sha(packet_text)==record.get('evidence_digest') and packet['rubric']['objectiveId']==spec['objectiveId'] and packet['evidence']==grade['input']['evidence'] and packet['facts']=={k:grade['input']['facts'].get(k)is True for k in packet['rubric']['requiredFacts']},'canonical packet')
        browser=observed.get('browsers',[]);require(len(browser)==2 and all(x.get('html')==template['html_content'] and x.get('result',{}).get('syntheticCookieOnly')is True for x in browser),'source browser')
        source=browser[1];level=spec['level'];require(source.get('method')==('qualifyDocument' if level==1 else 'qualify') and source['result'].get('scriptExecuted' if level==1 else 'targetEventExecuted')is spec['positive'],'source execution')
        if level in [1,2,3]:require(source.get('options',{}).get('scriptSource' if level==1 else 'eventSource')==spec['profile'][{1:'full_name',2:'signature_html',3:'company_name'}[level]],'exact profile source')
        else:require(isinstance(source.get('options',{}).get('eventSources'),list) and source['options']['eventSources'],'model source attribution')
        if level!=1:require(source['result'].get('targetEffectObserved')is True,'source effect')
        receipt=[e['content'] for e in packet['evidence'] if e.get('id')=='generation_receipt'];require(len(receipt)==1 and receipt[0].get('templateId')==template['id'] and receipt[0].get('authenticatedOwnerId')==owner and receipt[0].get('actualModel')is True,'generation receipt')
        require(packet['facts'].get('all_required_proofs')is spec['positive'] and packet['facts'].get('actual_model_generation')is True and packet['facts'].get('durable_template_effect')is True,'facts')
        verdict='pass' if spec['positive'] else 'fail';require(record.get('verdict')==result.get('verdict')==verdict and record.get('disposition')==('awarded' if spec['positive'] else 'not_pass') and grade.get('output',{}).get('completed')is spec['positive'] and reply['body'].get('completedLevels')==([level] if spec['positive'] else []) and result.get('attempts')==len(judges),'canonical outcome')
        for row in judges:
            messages=obj(row['request'])['messages'];require(len(messages)==2 and messages[0]['role']=='system' and messages[1]=={'role':'user','content':enc(packet['evidence'])} and '\nAUTHORITATIVE RUBRIC:\n'+enc(packet['rubric'])+'\nAUTHORITATIVE SERVER FACTS:\n'+enc(packet['facts'])+'\n' in messages[0]['content'],'Judge packet wire binding')
        completions=[x['row'] for x in c.get('snapshot',{}).get('completions',[])];expected_ids=[x['objectiveId'] for x in specs[:len(runs)] if x['positive']] if spec['positive'] else []
        require(sorted(x.get('objective_id') for x in completions)==sorted(expected_ids) and all(str(x.get('user_id'))==owner and x.get('workshop_key')=='xss_email_builder' for x in completions),'canonical progress')
        if spec['positive']:
            require(all(row in completions for row in prior),'prior completion unchanged');prior=completions
            preview=c.get('preview',{});require(preview.get('sandbox')=='allow-scripts allow-modals' and 'sandbox allow-scripts allow-modals' in preview.get('csp','') and 'Content-Security-Policy' in preview.get('html',''),'rendered isolated preview')
    require(owners[:4]==[owners[0]]*4 and owners[4]!=owners[0],'benign isolated owner')
    require(all_indexes==[r['index'] for r in calls if r['kind'] in ['generate','chat']],'exact ordered inference consumption')
    require(isinstance(lifecycle,dict) and isinstance(lifecycle.get('progress'),list) and [x.get('route') for x in lifecycle['progress']]==['/workshop/progress','/workshop/challenges','/workshop-dashboard'],'three rendered progress routes')
    for row in lifecycle['progress']:require(row.get('challenge',{}).get('workshopKey')=='xss_email_builder' and row['challenge'].get('completedObjectiveCount')==4 and row['challenge'].get('objectiveCount')==4,'progress projection')
    return True

def verify_xss_reflected_result(value,wire,captures,prerequisites=None):
    def require(ok,message):
        if not ok:raise RuntimeError('Reflected actual '+message)
    def obj(v):return json.loads(v) if isinstance(v,str) else v
    def sha(v):return hashlib.sha256(v.encode()).hexdigest()
    def encoded(v):return json.dumps(v,separators=(',',':'),ensure_ascii=False)
    profile=value.get('profile');cases,_,budget=reflected_contract(profile);r3=profile=='xss-reflected-r3-actual'
    for k,v in {'status':'passed','profile':profile,'actualModelProof':True,'genuineCredit':1 if r3 else 3,'installedWrites':False,'cleanupFailures':[]}.items():require(type(value.get(k)) is type(v) and value[k]==v,'receipt identity')
    for k in ('inertNoCredit','actualExecution','wireBinding','dashboardParity','configurationRestored','siblingPreserved','projectionRestored','sessionDenied','resetRetired','immutableHistoryPreserved','immutableEvidencePreserved'):require(value.get(k)is True,'proof '+k)
    flags=('learnerContent','adminPreview','independentGates','completedProjection')
    require(value.get('cases')==[dict(id=id,**dict.fromkeys(flags,True)) for id in ('xss_r1','xss_r2','xss_r3')],'three objectives')
    require(all(c[k]is True for c in value['cases'] for k in flags),'typed case flags')
    counts=value.get('requests',{});require(set(counts)=={'browser','api'} and all(type(counts[k])is int and 1<=counts[k]<=cap for k,cap in [('browser',800),('api',80)]),'browser bounds')
    require([x.get('name') for x in value.get('cleanup',[])]==['runs','restore','browser','xss-route','routes','server','transport','pools'] and all(x.get('status')=='fulfilled' for x in value['cleanup']),'cleanup')
    require(wire.get('profile')==value['profile'] and wire.get('version')==profile+'-wire-v1' and wire.get('model')==POLICY_MODEL and wire.get('digest')==POLICY_DIGEST and wire.get('closed')is True and type(wire.get('physicalPending'))is int and wire['physicalPending']==0 and wire.get('failures')==[],'wire identity/drain')
    wc=wire.get('counts',{});caps={k:budget[k] for k in ('external','chat','generate','metadata','tags','version')};caps['incoming']=budget['external']
    require(all(type(wc.get(k))is int and 0<=wc[k]<=v for k,v in caps.items()),'wire bounds')
    require(wc['external']==wc['chat']+wc['metadata'] and wc['metadata']==wc['tags']+wc['version'] and wc['incoming']==wc['external']-1 and wc['tags']>=1,'accounting')
    require(type(value.get('modelCalls'))is int and len(cases)*2<=value['modelCalls']==wc['chat']<=budget['chat'],'model count')
    calls=wire.get('calls',[]);require(len(calls)==wc['external'] and [r.get('index') for r in calls]==list(range(len(calls))),'wire indexes')
    for kind in ('chat','generate','tags','version'):require(sum(r.get('kind')==kind for r in calls)==wc[kind],'wire kind counts')
    for row in calls:
        require(row.get('terminal')=='returned' and row.get('responseComplete')is True and row.get('status')==200,'complete response')
        require(isinstance(row.get('request'),str) and sha(row['request'])==row.get('requestSha256'),'request hash')
        require(row.get('responseCaptureTruncated')is False and isinstance(row.get('response'),str) and sha(row['response'])==row.get('responseSha256') and row.get('responseBytes')==len(row['response'].encode()),'response hash/bytes')
    require(isinstance(captures,list) and len(captures)==len(cases),'exact captures')
    require(calls[0].get('kind')=='tags' and calls[0].get('caseId')is None and calls[0].get('request')=='','startup metadata')
    generation=value.get('resetGeneration',{});require(set(generation)=={'before','after'} and all(type(generation[k])is int and 0<=generation[k]<=9007199254740991 for k in generation) and generation['after']==generation['before']+1,'reset generation')
    all_indexes=[];runs=set();evaluations=set();owner=None;prior=[]
    if r3:
        require(type(value.get('controlledPrerequisiteCount'))is int and value['controlledPrerequisiteCount']==2 and value.get('actualObjectiveIds')==['xss_r3'] and value.get('prerequisiteProjection')is True and value.get('prerequisiteEvidenceEmpty')is True,'prerequisite distinction')
        require(isinstance(prerequisites,dict) and set(prerequisites)=={'version','ownerId','completions','progress','judgments','packets'} and prerequisites['version']=='xss-reflected-prerequisites-v1' and prerequisites['judgments']==[] and prerequisites['packets']==[],'prerequisite receipt')
        require(type(prerequisites['ownerId']) in (str,int) and re.fullmatch(r'[1-9][0-9]*',str(prerequisites['ownerId'])) is not None,'prerequisite owner');owner=str(prerequisites['ownerId'])
        prior=prerequisites['completions'];require(isinstance(prior,list) and len(prior)==2 and sorted(x.get('objective_id') for x in prior)==['xss_r1','xss_r2'] and all(str(x.get('user_id'))==owner and x.get('workshop_key')=='xss_workshop' for x in prior),'prerequisite completions')
        require(isinstance(prerequisites['progress'],list) and len(prerequisites['progress'])==2 and sorted(x.get('objective_id') for x in prerequisites['progress'])==['xss_r1','xss_r2'] and all(str(x.get('user_key'))==owner and type(x.get('completed'))is int and x['completed']==1 and isinstance(x.get('completed_at'),str) and x['completed_at'] for x in prerequisites['progress']),'prerequisite progress')
    else:require(prerequisites is None,'unexpected prerequisites')
    for spec,c in zip(cases,captures):
        capture=c.get('capture',{});b=c.get('binding',{});run=c.get('run',{});records=c.get('records',[])
        require(capture.get('caseId')==spec['id'] and b.get('caseId')==spec['id'] and b.get('status')=='verified' and b.get('objectiveId')==spec['objective'],'case identity')
        require(len(records)==1 and len(capture.get('grades',[]))==1,'single canonical record')
        record=records[0];grade=capture['grades'][0];ex=grade['execution'];inp=grade['input'];packet=obj(record['packet']);result=obj(record['result_json'])
        require(run.get('run_id')==b.get('runId')==record.get('run_id')==ex.get('runId') and run.get('status')=='completed' and run['run_id'] not in runs,'run binding');runs.add(run['run_id'])
        require(record.get('evaluation_id')==b.get('evaluationId') and b['evaluationId'] not in evaluations,'evaluation binding');evaluations.add(b['evaluationId'])
        if owner is None:owner=str(record['user_id'])
        require(str(record['user_id'])==owner and run.get('owner_key')==record.get('owner_key')==ex.get('ownerKey')==encoded(['XSS',owner]) and str(run.get('generation'))==str(record.get('owner_generation'))==str(ex.get('durableGeneration')),'owner generation')
        require(record.get('objective_id')==spec['objective'] and record.get('workshop_key')=='xss_workshop' and packet['rubric']['objectiveId']==spec['objective'] and inp.get('message')==spec['message'] and inp.get('objectiveId')==spec['objective'] and str(inp.get('userId'))==owner,'input/packet')
        require(sha(record['packet'] if isinstance(record['packet'],str) else encoded(record['packet']))==b.get('packetSha256'),'packet hash')
        expected='pass' if spec['completed'] else 'fail';require(record.get('verdict')==result.get('verdict')==expected and record.get('disposition')==('awarded' if spec['completed'] else 'not_pass') and c['body'].get('completedObjectiveId')==spec['completed'],'canonical outcome')
        selected=[r for r in calls if r.get('caseId')==spec['id'] and r['kind']=='chat'];actors=[];judges=[]
        for row in selected:
            request=json.loads(row['request']);options=request.get('options',{});role=options.get('num_predict');require(request.get('model')==POLICY_MODEL and role in (512,900),'inference role')
            require(options.get('temperature')==(.7 if role==512 else 0) and (options.get('num_ctx')is None if role==512 else options.get('num_ctx')==32768),'inference options')
            (actors if role==512 else judges).append(row['index'])
        require(1<=len(actors)<=2 and 1<=len(judges)<=2 and actors==b.get('actorIndexes') and judges==b.get('judgeIndexes') and b.get('selectedActorIndex')==actors[-1],'inference bijection')
        require(len(capture.get('actors',[]))==len(actors) and type(result.get('attempts'))is int and result['attempts']==len(judges),'observed counts')
        for index,observed in zip(actors,capture['actors']):
            request=json.loads(calls[index]['request']);text=''.join(json.loads(line)['message']['content'] for line in calls[index]['response'].strip().splitlines())
            require(request['messages']==observed['messages'] and text==observed['result']['response'] and observed['result'].get('provider')=='ollama' and observed['result'].get('model')==POLICY_MODEL and not observed['result'].get('mocked') and not observed['result'].get('fallback'),'actor raw binding')
        require(capture['actors'][-1]['result']['response']==c['body']['response']==inp['response'],'selected response')
        completions=c.get('completions',[]);expected_ids=sorted((['xss_r1','xss_r2'] if r3 else [])+[x['completed'] for x in cases[:len(runs)] if x['completed']]);require(sorted(x['objective_id'] for x in completions)==expected_ids and all(str(x['user_id'])==owner and x['workshop_key']=='xss_workshop' for x in completions),'completion lineage')
        require(all(any(x==old for x in completions) for old in prior),'prior completion unchanged');prior=completions
        if r3:
            progress=c.get('progress',[]);require(isinstance(progress,list) and sorted(x.get('objective_id') for x in progress)==expected_ids and all(str(x.get('user_key'))==owner and type(x.get('completed'))is int and x['completed']==1 for x in progress) and all(any(row==old for row in progress) for old in prerequisites['progress']),'prerequisite local progress unchanged')
        all_indexes+=actors+judges
    require(sorted(all_indexes)==[r['index'] for r in calls if r['kind']=='chat'],'all inference consumed')
    return True

def verify_csrf_twelve_result(value,profile='csrf-twelve-content'):
    if profile not in ('csrf-twelve-content','csrf-rag-content-lifecycle'):raise RuntimeError('Closed CSRF profile required')
    required={'status':'passed','profile':profile,'actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'controlledCalls':0,'pendingControlledCalls':0,'controlledProjectionCount':12,'cleanupFailures':[],'immutableEvidenceScope':'empty controlled owner; retained genuine evidence reviewed separately'}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('CSRF controlled receipt identity')
    for key in ('dashboardParity','configurationRestored','siblingPreserved','projectionRestored','immutableEvidencePreserved','resetRetired','emailSetup','sessionDenied','sessionReload'):
        if value.get(key)is not True:raise RuntimeError('CSRF content preservation missing')
    flags=('learnerContent','adminPreview','independentGates','completedProjection')
    ids=['csrf_'+family+str(n) for family in ('g','p','x','i') for n in (1,2,3)]
    all_ids=ids
    if profile=='csrf-rag-content-lifecycle':ids=ids[-3:]
    if profile=='csrf-rag-content-lifecycle' and (value.get('contentObjectiveIds')!=ids or value.get('masterGateObjectiveIds')!=all_ids):raise RuntimeError('CSRF continuation scope required')
    if value.get('cases')!=[dict(id=id,**dict.fromkeys(flags,True)) for id in ids] or any(c[k]is not True for c in value['cases'] for k in flags):raise RuntimeError('CSRF exact twelve content cases required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(counts[k])is not int or not 1<=counts[k]<=cap for k,cap in [('browser',1600),('api',120)]):raise RuntimeError('CSRF content request bounds')
    expected=['runs','restore','browser','csrf-route','teaching','mail','routes','server','pools']
    if [x.get('name') for x in value.get('cleanup',[])]!=expected or any(x.get('status')!='fulfilled' for x in value['cleanup']):raise RuntimeError('CSRF cleanup incomplete')

def verify_codebot_browser_cleanup(args,runtime,state,rows):
    if args.scenario!='codebot-rendered-parity' or browser_profile(args) not in (*XSS_BUILDER_RESET_PROFILES,IPI_EMAIL_ACTUAL_PROFILE):
        return codebot_browser_helper().verify_browser_absence(runtime,state,rows)
    # These closed SQL-only profiles never launch a browser. A success must not
    # manufacture a browser journal, nor bypass retirement of its native group.
    if any(p.exists() or p.is_symlink() for p in (runtime/'browser-process.json',runtime/'browser-profile')):raise RuntimeError('Unexpected browser in builder reset profile')
    native=state.get('nativePid')
    if state.get('nativeStarted') and (type(native)is not int or native<=0):raise RuntimeError('Builder native identity missing')
    if native is not None and any(pid==native or group==native for pid,group,uid in rows):raise RuntimeError('Builder native group remains')
    return {'started':False,'expectedNoBrowser':True,'groupAbsent':True,'profileRetained':False}

def verify_xss_builder_reset_result(value,profile):
    if profile not in XSS_BUILDER_RESET_PROFILES:raise RuntimeError('Builder reset profile required')
    expected={'status':'passed','profile':profile,'mode':'fresh' if profile==XSS_BUILDER_RESET_PROFILES[0] else 'upgrade','actualModelProof':False,'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'requests':{'browser':0,'api':0},'cleanup':[{'name':'pools','status':'fulfilled'}]}
    for key,want in expected.items():
        got=value.get(key)
        if type(got)is not type(want) or got!=want:raise RuntimeError('Builder reset receipt identity or cleanup mismatch')
    if set(value['requests'])!={'browser','api'} or any(type(n)is not int or n!=0 for n in value['requests'].values()):raise RuntimeError('Builder request counts must be exact zero integers')
    groups={
      'migration':{'fresh':profile==XSS_BUILDER_RESET_PROFILES[0],'populatedUpgrade':profile==XSS_BUILDER_RESET_PROFILES[1],**dict.fromkeys(['exactNewMigrations','priorChecksumsPreserved','secondRunNoop','runtimeGrants','publicExecuteDenied'],True)},
      'seed':dict.fromkeys(['fourDefaults','instructorContentPreserved','nullContentPreserved','noHistoricalCredit','secondRunNoop'],True),
      'reset':dict.fromkeys(['pendingBlocks','implicitRecovery','terminalReplay','newRunUncancelled','exactReceipt','siblingPreserved','immutablePreserved','profilePreserved','builderOnly','ownerDeletionReceiptsRetired','lateWriteDenied'],True)}
    for key,want in groups.items():
        got=value.get(key)
        if not isinstance(got,dict) or set(got)!=set(want) or any(type(got[k])is not bool or got[k]is not expected for k,expected in want.items()):raise RuntimeError('Builder reset required checks missing')

def verify_xss_email_three_result(value):
    required={'status':'passed','profile':'xss-email-three-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'controlledCalls':0,'pendingControlledCalls':0,'controlledProjectionCount':3,'cleanupFailures':[]}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('Email controlled receipt identity')
    for key in ('dashboardParity','configurationRestored','siblingPreserved','projectionRestored','immutableEvidencePreserved','resetRetired','emailSetup','emailBrowserTarget','emailBrowserInertDenied','mailProviderClosed','emailBrowserRetired'):
        if value.get(key)is not True:raise RuntimeError('Email content preservation missing')
    if value.get('emailBrowserCases')!=['active-target','comment-target','textarea-target']:raise RuntimeError('Email exact browser target cases required')
    flags=('learnerContent','adminPreview','independentGates','completedProjection')
    if value.get('cases')!=[dict(id=id,**dict.fromkeys(flags,True)) for id in ('xss_e1','xss_e2','xss_e3')] or any(c[k]is not True for c in value['cases'] for k in flags):raise RuntimeError('Email exact three content cases required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(counts[k])is not int or not 1<=counts[k]<=cap for k,cap in [('browser',800),('api',80)]):raise RuntimeError('Email content request bounds')
    seed=value.get('seedReceipt',{})
    flags=('freshDefaults','managedPriorHints','instructorHintsPreserved','nullHintsPreserved','secondRunNoop','siblingCatalogPreserved','rollbackExact')
    if not isinstance(seed,dict) or set(seed)!={'version',*flags} or seed.get('version')!='xss-email-hint-seed-v1' or any(seed[k]is not True for k in flags):raise RuntimeError('Email canonical seed proof required')
    expected=['runs','restore','browser','xss-route','routes','server','pools']
    if [x.get('name') for x in value.get('cleanup',[])]!=expected or any(x.get('status')!='fulfilled' for x in value['cleanup']):raise RuntimeError('Email cleanup incomplete')

def verify_xss_stored_six_result(value):
    required={'status':'passed','profile':'xss-stored-six-content-inert','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'pendingControlledCalls':0,'cleanupFailures':[]}
    for k,v in required.items():
        if type(value.get(k)) is not type(v) or value[k]!=v:raise RuntimeError('XSS controlled receipt identity')
    for k in ('dashboardParity','configurationRestored','siblingPreserved','projectionRestored','inertRendering','noWrite','copiedOriginDenied','missingProofNoCredit','sessionDenied','resetRetired','immutableEvidencePreserved'):
        if value.get(k) is not True:raise RuntimeError('XSS controlled proof missing')
    ids=['xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3']
    if value.get('cases')!=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for id in ids]:raise RuntimeError('XSS exact six cases required')
    if any(c[k] is not True for c in value['cases'] for k in ('learnerContent','adminPreview','independentGates','completedProjection')):raise RuntimeError('XSS case flags must be boolean')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=800 or not 1<=counts['api']<=80:raise RuntimeError('XSS controlled request bounds')
    if type(value.get('controlledCalls'))is not int or not 1<=value['controlledCalls']<=32:raise RuntimeError('XSS controlled provider bounds')
    expected=['runs','restore','browser','xss-route','routes','server','pools']
    if [x.get('name') for x in value.get('cleanup',[])]!=expected or any(x.get('status')!='fulfilled' for x in value['cleanup']):raise RuntimeError('XSS cleanup incomplete')

def verify_objective_solution_content_result(value,profile='objective-solution-content'):
    if profile not in ('objective-solution-content','generic-solution-content'):raise RuntimeError('Closed content profile required')
    expected_cases=[('path_traversal','legacy_sensitive_file_ssi')] if profile=='generic-solution-content' else [('xss_r1','xss_workshop'),('csrf_g1','csrf_workshop')]
    required={'status':'passed','profile':profile,'actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[]}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('Objective content terminal mismatch')
    for key in ('siblingPreserved','gatesPreserved','contentRestored'):
        if value.get(key)is not True:raise RuntimeError('Objective content preservation missing')
    cases=value.get('cases')
    if not isinstance(cases,list) or len(cases)!=len(expected_cases):raise RuntimeError('Objective content exact cases required')
    for row,(id,workshop) in zip(cases,expected_cases):
        if row.get('id')!=id or row.get('workshopKey')!=workshop or any(row.get(k)is not True for k in ('typedSave','readback','learnerProjection','reseedPreserved','restored')):raise RuntimeError('Objective content case incomplete')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=400 or not 1<=counts['api']<=40:raise RuntimeError('Objective content request bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('browser','routes','server','pools')]:raise RuntimeError('Objective content cleanup incomplete')

def verify_mcp_indirect_supply_content_result(value):
    required={'status':'passed','profile':'mcp-indirect-supply-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':1,'completionScope':'Controlled supply completion projection only; no earned credit'}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('MCP current content identity mismatch')
    for flag in ('freshDefaults','secondRunNoop','supplyDone','countParity','contentRestored','siblingPreserved'):
        if value.get(flag)is not True:raise RuntimeError('MCP current content proof missing')
    flags=('label','hint','solution','adminPreview')
    rows=value.get('cases')
    if rows!=[dict(id=id,**dict.fromkeys(flags,True)) for id in ('mcp_indirect_injection','mcp_supply_chain')] or any(row[k]is not True for row in rows for k in flags):raise RuntimeError('MCP exact two content cases required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=400 or not 0<=counts['api']<=40:raise RuntimeError('MCP current content bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('browser','routes','server','pools')]:raise RuntimeError('MCP current content cleanup incomplete')

def verify_ipi_email_actual_result(value,wire,c,manifest):
    def need(ok,message):
        if not ok:raise RuntimeError('Email actual '+message)
    sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
    required={'profile':IPI_EMAIL_ACTUAL_PROFILE,'status':'passed','installedWrites':False,'browserStarted':False,'actualModelProof':True,'controlledProjectionCount':0,'genuineCredit':1,'caseIds':['setup','clean-control','attack'],'cleanupFailures':[]}
    for key,want in required.items():need(type(value.get(key))is type(want) and value[key]==want,'terminal '+key)
    for key in ('foreignArtifactDenied','sessionDenied','resetRetired','noCallNegatives','immutableEvidencePreserved','siblingPreserved'):need(value.get(key)is True,'gate '+key)
    need(value.get('cleanup')==[{'name':n,'status':'fulfilled'}for n in ['routes','server','mail','transport','pools']],'cleanup')
    frozen_path=Path(__file__).resolve().parents[2]/'tests/fixtures/ipiEmailTriggerActualInput.json'
    frozen_raw=frozen_path.read_bytes();need(hashlib.sha256(frozen_raw).hexdigest()==manifest.get('inputSha256')==IPI_EMAIL_INPUT_SHA256,'frozen input hash');frozen=json.loads(frozen_raw)
    need(c.get('input')==frozen,'frozen input')
    need(wire.get('profile')==IPI_EMAIL_ACTUAL_PROFILE and wire.get('version')==IPI_EMAIL_ACTUAL_PROFILE+'-wire-v1' and wire.get('model')==POLICY_MODEL and wire.get('digest')==POLICY_DIGEST,'wire identity')
    need(wire.get('closed')is True and wire.get('physicalPending')==0 and wire.get('failures')==[],'wire quiescence')
    calls=wire.get('calls',[]);counts=wire.get('counts',{});need(bool(calls),'wire rows')
    for key,cap in IPI_EMAIL_WIRE_BUDGET.items():
        if key not in ('actor','judge'):need(type(counts.get(key))is int and 0<=counts[key]<=cap,'wire budget '+key)
    need(counts['external']==len(calls) and counts['incoming']==counts['external']-1 and counts['tags']==1 and counts['metadata']==1 and counts['generate']==counts['version']==0,'wire counters')
    chats=[]
    for index,row in enumerate(calls):
        need(row.get('index')==index and row.get('terminal')=='returned' and row.get('status')==200 and row.get('responseComplete')is True and row.get('responseCaptureTruncated')is False,'returned raw wire')
        for field in ('request','response'):need(isinstance(row.get(field),str) and sha(row[field])==row.get(field+'Sha256') and len(row[field].encode())==row.get(field+'Bytes'),'wire bytes')
        if index==0:
            need(row.get('kind')=='tags' and row.get('caseId')is None and any(x.get('digest')==POLICY_DIGEST and POLICY_MODEL in (x.get('name'),x.get('model'))for x in json.loads(row['response']).get('models',[])),'model digest');continue
        need(row.get('kind')=='chat' and row.get('role')in ('actor','judge') and row.get('caseId')in value['caseIds'],'chat identity')
        frames=[json.loads(line)for line in row['response'].splitlines()if line.strip()];need(bool(frames) and frames[-1].get('done')is True and frames[-1].get('done_reason')=='stop' and all(x.get('model')==POLICY_MODEL and not x.get('error')for x in frames),'complete model frames')
        text=''.join(x.get('message',{}).get('content','')for x in frames);chats.append((row,json.loads(row['request']),text))
    model_calls=c.get('modelCalls',[]);need(len(chats)==len(model_calls)==counts['chat'],'all call accounting')
    for (row,request,text),call in zip(chats,model_calls):
        result=call.get('result',{});need(call.get('error')is None and row['role']==call.get('role') and row['caseId']==call.get('caseId'),'call scope')
        need(request.get('model')==POLICY_MODEL and request.get('messages')==call.get('messages') and request.get('format')==call.get('options',{}).get('format'),'request binding')
        options=call['options'];expected_options={'temperature':options.get('temperature'),'num_predict':options.get('num_predict',options.get('max_tokens'))}
        if call['role']=='actor':expected_options['num_ctx']=options.get('num_ctx',8192)
        else:need(options.get('num_ctx')==32768,'Judge requested context');expected_options['num_ctx']=32768
        need(request.get('options')==expected_options,'request options')
        need(result.get('provider')=='ollama' and result.get('model')==POLICY_MODEL and result.get('response')==text and result.get('fallback')is not True and result.get('mocked')is not True,'raw response')
    for role,lower,upper in [('actor',12,16),('judge',1,28)]:
        n=sum(x.get('role')==role for x in model_calls);need(type(value.get(role+'Calls'))is int and value[role+'Calls']==n and lower<=n<=upper,'role count')
    need(value.get('modelCalls')==len(model_calls),'model count')
    for case in value['caseIds']:
        for role,cap in [('actor',0 if case=='setup'else 8),('judge',8 if case=='setup'else 10)]:need(sum(x.get('caseId')==case and x.get('role')==role for x in model_calls)<=cap,'case cap')
    owner=str(c.get('ownerId'));owner_key=json.dumps(['IndirectEmail',owner],separators=(',',':'));need(owner!=str(c.get('siblingId')),'distinct owners')
    evaluations=c.get('evaluations',[]);used=[]
    for evaluation in evaluations:
        rows=[r for r in c.get('judgments',[])if r.get('run_id')==evaluation.get('runId') and r.get('objective_id')==evaluation.get('packet',{}).get('rubric',{}).get('objectiveId')];need(len(rows)==1,'unique judgment');row=rows[0]
        packets=[p for p in c.get('packets',[])if p.get('evaluation_id')==row['evaluation_id']];need(len(packets)==1,'unique packet');packet=packets[0]
        need(sha(packet['packet'])==row['evidence_digest'] and json.loads(packet['packet'])==evaluation['packet'],'canonical packet digest')
        runs=[r for r in c.get('runs',[])if r.get('run_id')==row['run_id']];need(len(runs)==1,'unique run');run=runs[0]
        need(str(row.get('user_id'))==owner and packet.get('owner_key')==run.get('owner_key')==owner_key and str(packet.get('owner_generation'))==str(run.get('generation')) and run.get('status')=='completed','canonical owner generation')
        result=evaluation.get('result',{});need(result.get('verdict')==row.get('verdict') and result.get('criteria')==row.get('result_json',{}).get('criteria'),'persisted semantic result')
        for index in evaluation.get('callIndexes',[]):need(type(index)is int and 0<=index<len(model_calls) and index not in used and model_calls[index]['role']=='judge' and model_calls[index]['caseId']==evaluation['caseId'],'unique Judge call');used.append(index)
    need(sorted(used)==[i for i,x in enumerate(model_calls)if x['role']=='judge'],'exhaustive Judge calls')
    cases=c.get('cases',[]);need([x.get('id')for x in cases]==['clean-control','attack'],'fixed pair')
    for item in cases:
        body=item.get('response',{}).get('body',{});need(item.get('response',{}).get('status')==200,'mounted response')
        http=[x for x in body.get('judgments',[])if x.get('objectiveId')=='email_trigger_injection'];need(len(http)==1,'HTTP target judgment')
        rows=[r for r in c['judgments']if r['evaluation_id']==http[0].get('evaluationId')];need(len(rows)==1,'HTTP persisted join');row=rows[0]
        positive=item['id']=='attack';need(row.get('verdict')==http[0].get('verdict')==('pass'if positive else'fail') and row.get('disposition')==('awarded'if positive else'not_pass'),'actual expected verdict')
        need(http[0].get('criteria')==row['result_json'].get('criteria') and http[0].get('evidenceDigest')==row['evidence_digest'],'HTTP criteria digest')
        target=[x for x in item.get('completions',[])if x.get('objective_id')=='email_trigger_injection'];need(bool(target)==positive and all(str(x.get('user_id'))==owner for x in target),'case credit')
        artifact=item.get('artifact',{});need(item.get('request')=={'artifactId':artifact.get('artifactId')},'selected artifact')
        need(sha(artifact['body'])==artifact.get('bodySha256') and sha(artifact['modelBody'])==artifact.get('modelBodySha256'),'artifact bytes')
    lifecycle=c.get('lifecycle',{});need(lifecycle.get('wireBefore')==lifecycle.get('wireAfter')==counts,'negative no calls')
    for name,status in [('foreign-artifact',409),('revoked-session',401),('retired-artifact',409),('forged-body',400)]:
        proof=lifecycle.get(name,{});need(proof.get('before')==proof.get('after')==counts and proof.get('response',{}).get('status')==status,'negative '+name)
    need(bool(lifecycle.get('immutableBefore',{}).get('judgments')) and lifecycle.get('immutableBefore')==lifecycle.get('immutableAfter'),'immutable retention')
    need(bool(lifecycle.get('siblingBefore',{}).get('artifacts')) and lifecycle.get('siblingBefore')==lifecycle.get('siblingAfter'),'nonempty sibling preservation')
    before=lifecycle.get('ownerBefore',[]);after=lifecycle.get('ownerAfter',[]);need(len(before)==len(after)==2 and [x['artifact_id']for x in before]==[x['artifact_id']for x in after] and all(x.get('retired_at')for x in after),'owner retirement')
    need(str(lifecycle.get('generationBefore','')).isdigit() and str(lifecycle.get('generationAfter','')).isdigit() and int(lifecycle['generationAfter'])==int(lifecycle['generationBefore'])+1,'reset generation')
    need(lifecycle.get('completionsAfter')==[] and lifecycle.get('reset',{}).get('status')==200 and lifecycle['reset']['body'].get('success')is True,'reset completion')

def verify_ipi_rag_actual_result(value,wire,c,manifest):
    def need(ok,message):
        if not ok:raise RuntimeError('RAG actual '+message)
    sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
    compact=lambda x:json.dumps(x,separators=(',',':'),ensure_ascii=False)
    required={'profile':IPI_RAG_ACTUAL_PROFILE,'status':'passed','installedWrites':False,'actualModelProof':True,'controlledProjectionCount':0,'genuineCredit':1,'caseIds':['owner-upload','owner-query'],'cleanupFailures':[]}
    for k,v in required.items():need(type(value.get(k))is type(v) and value[k]==v,'terminal '+k)
    for k in ('foreignDocumentDenied','sessionDenied','resetRetired','noCallNegatives','immutableEvidencePreserved','siblingPreserved'):need(value.get(k)is True,'gate '+k)
    need(value.get('cleanup')==[{'name':k,'status':'fulfilled'}for k in ['routes','server','embedding','transport','pools']],'cleanup')
    frozen=json.loads((Path(__file__).resolve().parents[2]/'tests/fixtures/ipiRagQueryActualInput.json').read_text())
    need(c.get('input')==frozen and value.get('embeddingFingerprint')==c.get('embeddingFingerprint')=={k:manifest['embeddingCache'][k]for k in ('fingerprint','description')},'input/embedding')
    need(wire.get('profile')==IPI_RAG_ACTUAL_PROFILE and wire.get('version')==IPI_RAG_ACTUAL_PROFILE+'-wire-v1' and wire.get('model')==POLICY_MODEL and wire.get('digest')==POLICY_DIGEST,'wire identity')
    need(wire.get('closed')is True and wire.get('physicalPending')==0 and wire.get('failures')==[],'closed wire')
    calls=wire.get('calls',[]);counts=wire.get('counts',{});need(bool(calls) and calls[0]['kind']=='tags','digest preflight')
    for k,limit in IPI_RAG_WIRE_BUDGET.items():
        if k not in ('actor','judge'):need(type(counts.get(k))is int and 0<=counts[k]<=limit,'wire budget '+k)
    need(counts['external']==len(calls) and counts['tags']==1 and counts['generate']==counts['version']==0 and counts['metadata']==1,'wire counts')
    chats=[]
    for i,row in enumerate(calls):
        need(row.get('index')==i and row.get('terminal')=='returned' and row.get('status')==200 and row.get('responseComplete')is True and row.get('responseCaptureTruncated')is False,'terminal frame')
        for field in ('request','response'):need(isinstance(row.get(field),str) and sha(row[field])==row.get(field+'Sha256') and len(row[field].encode())==row.get(field+'Bytes'),'wire bytes')
        if row['kind']=='tags':
            need(i==0 and row.get('caseId')is None and any(x.get('digest')==POLICY_DIGEST and POLICY_MODEL in (x.get('name'),x.get('model'))for x in json.loads(row['response']).get('models',[])),'metadata digest');continue
        need(row['kind']=='chat' and row.get('caseId')in value['caseIds'],'closed chat')
        frames=[json.loads(line)for line in row['response'].splitlines()if line.strip()];need(bool(frames) and frames[-1].get('done')is True and frames[-1].get('done_reason')=='stop','complete inference')
        need(all(f.get('model')==POLICY_MODEL and not f.get('error') and not f.get('tool_calls') and not f.get('message',{}).get('tool_calls')for f in frames),'model frames')
        chats.append((row,json.loads(row['request']),''.join(f.get('message',{}).get('content','')for f in frames)))
    need(counts['chat']==len(chats)==len(c.get('modelCalls',[])),'all calls captured')
    role_counts={'actor':0,'judge':0};per_case={k:{'actor':0,'judge':0}for k in value['caseIds']};last_case=0
    for (row,req,raw),record in zip(chats,c['modelCalls']):
        role=record.get('role');need(role in role_counts and row.get('role')==role and row['caseId']==record.get('caseId'),'role binding');role_counts[role]+=1;per_case[row['caseId']][role]+=1
        index=value['caseIds'].index(row['caseId']);need(index>=last_case,'case order');last_case=index
        result=record.get('result')or {};need(record.get('error')is None and result.get('response')==raw and result.get('provider')=='ollama' and result.get('model')==POLICY_MODEL and result.get('mocked')is not True and result.get('fallback')is not True,'actual response')
        need(req.get('model')==POLICY_MODEL and req.get('messages')==record.get('messages') and req.get('format')==record.get('options',{}).get('format'),'exact model request')
        need(req.get('options',{}).get('temperature')==0 and req['options'].get('num_predict')==(1200 if role=='actor' else 900),'role budget')
    need(2<=role_counts['actor']<=8 and 1<=role_counts['judge']<=6 and per_case['owner-upload']['actor']==0 and per_case['owner-upload']['judge']<=4 and 1<=per_case['owner-query']['judge']<=2,'actor/Judge ceilings')
    need(value.get('actorCalls')==role_counts['actor'] and value.get('judgeCalls')==role_counts['judge'] and value.get('modelCalls')==len(chats),'result counts')
    owner=c.get('ownerId');owner_key=compact(['RAG',str(owner)]);query=c.get('query',{});need(query.get('status')==200 and query['body'].get('presentation_source')=='model' and query['body'].get('completedObjectiveIds')==['rag_query'],'owned query credit')
    judgments=[x for x in c.get('judgments',[])if x.get('objective_id')=='rag_query'];need(len(judgments)==1,'one query judgment');j=judgments[0]
    need(j.get('verdict')=='pass' and j.get('disposition')=='awarded' and str(j.get('user_id'))==str(owner),'canonical credit')
    packets=[x for x in c.get('packets',[])if x.get('evaluation_id')==j['evaluation_id']];need(len(packets)==1,'packet');pr=packets[0];need(sha(pr['packet'])==j['evidence_digest'] and pr.get('owner_key')==owner_key and str(pr.get('user_id'))==str(owner),'packet digest owner')
    packet=json.loads(pr['packet']);need(packet['rubric'].get('objectiveId')=='rag_query' and packet['rubric'].get('version')=='ipi-rag-evidence-bound-v2' and all(packet['facts'].get(k)is True for k in packet['rubric']['requiredFacts']),'rubric facts')
    runs=[x for x in c.get('runs',[])if x.get('run_id')==j['run_id']];need(len(runs)==1,'run');run=runs[0];need(run.get('status')=='completed' and run.get('owner_key')==owner_key and str(run['generation'])==str(j['generation'])==str(pr['owner_generation']),'generation')
    evidence={x['id']:x['content']for x in packet['evidence']};need(evidence.get('question')==frozen['question'] and evidence.get('raw_response')==query['body']['raw_model_answer'],'answer evidence')
    chunks=query['body'].get('retrieved_chunks',[]);need(bool(chunks) and all(x['text']in frozen['document']for x in chunks) and evidence.get('context')=='\n---\n'.join(x['text']for x in chunks),'retrieved source')
    need(any(x.get('run_id')==run['run_id'] and x.get('node')=='rag_search' and x.get('event_type')=='tool'for x in c.get('events',[])),'tool event')
    searches=[];answer=None
    for row,req,raw in chats:
        if row.get('role')=='actor':
            try:decision=json.loads(raw)
            except (ValueError,TypeError):continue
            if isinstance(decision,dict) and set(decision)=={'action','query','topK'} and decision.get('action')=='search_document' and isinstance(decision.get('query'),str) and 1<=len(decision['query'])<=500 and decision['query'].strip() and type(decision.get('topK'))is int and 1<=decision['topK']<=10:searches.append(decision)
            elif isinstance(decision,dict) and set(decision)=={'action','answer'} and decision.get('action')=='answer' and isinstance(decision.get('answer'),str) and 1<=len(decision['answer'])<=8000 and decision['answer'].strip():answer=decision['answer']
    receipts=evidence.get('retrieval_receipts',[]);need(1<=len(searches)<=3 and len(receipts)==len(searches) and answer==evidence['raw_response'],'actual search/answer')
    for i,(search,receipt)in enumerate(zip(searches,receipts)):
        key=run['run_id']+':rag_search:'+str(i)+':'+sha(compact({k:search[k]for k in ('query','topK')}))
        need(any(e.get('effect_key')==key and e.get('run_id')==run['run_id'] and e.get('owner_key')==owner_key and str(e.get('generation'))==str(run['generation']) and e.get('status')=='completed'for e in c.get('effects',[])),'owned completed search effect')
        need(str(receipt.get('ownerId'))==str(owner) and receipt.get('runId')==run['run_id'] and receipt.get('documentId')==c['upload']['body']['session_id'] and receipt.get('runtimeFingerprint')==c['embeddingFingerprint']['fingerprint'] and receipt.get('sourceSha256')==sha(frozen['document']) and str(receipt.get('graphGeneration'))==str(run['generation']),'retrieval receipt')
    query_judges=[(req,raw)for row,req,raw in chats if row.get('role')=='judge' and row['caseId']=='owner-query']
    for req,raw in query_judges:need('AUTHORITATIVE RUBRIC:\n'+compact(packet['rubric'])+'\nAUTHORITATIVE SERVER FACTS:\n'+compact(packet['facts'])+'\n'in req['messages'][0]['content'] and json.loads(req['messages'][1]['content'])==packet['evidence'],'Judge packet')
    verdict=json.loads(query_judges[-1][1]);reported=[x for x in query['body']['judgments']if x.get('objectiveId')=='rag_query'];need(len(reported)==1 and reported[0].get('evaluationId')==j['evaluation_id'] and verdict.get('verdict')==reported[0].get('verdict')=='pass' and verdict.get('criteria')==reported[0].get('criteria')==j.get('result_json',{}).get('criteria'),'raw canonical Judge')
    lifecycle=c.get('lifecycle',{})
    for name,status in [('foreign-document',404),('revoked-session',401),('retired-document',404)]:
        row=lifecycle.get(name,{});need(row.get('response',{}).get('status')==status and row.get('before')==row.get('after')==counts,'negative no-call '+name)
    need(lifecycle.get('reset',{}).get('status')==200 and lifecycle['reset']['body'].get('success')is True,'reset')
    before_docs=lifecycle.get('ownerBefore',[]);after_docs=lifecycle.get('ownerAfter',[])
    need(len(before_docs)==len(after_docs)==1 and before_docs[0]['row'].get('document_id')==after_docs[0]['row'].get('document_id')==c['upload']['body']['session_id'] and str(before_docs[0]['row'].get('owner_id'))==str(after_docs[0]['row'].get('owner_id'))==str(owner) and after_docs[0]['row'].get('retired_at'),'retired exact owner document')
    need(any(x.get('objective_id')=='rag_query' and x.get('workshop_key')=='indirect_prompt_injection' and str(x.get('user_id'))==str(owner) for x in lifecycle.get('completionsBefore',[])),'canonical completion before reset')
    need(lifecycle.get('wireBefore')==lifecycle.get('wireAfter')==counts,'reset no-call')
    need(lifecycle.get('immutableBefore')==lifecycle.get('immutableAfter') and lifecycle.get('immutableBefore',{}).get('judgments') and lifecycle.get('siblingBefore')==lifecycle.get('siblingAfter') and lifecycle.get('siblingBefore'),'nonempty preservation')

def verify_ipi_rag_query_content_result(value,profile='ipi-rag-query-content'):
    if profile not in ('ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content'):raise RuntimeError('Closed RAG content profile required')
    injection=profile=='ipi-rag-injection-two-content'
    upload_clean=profile=='ipi-rag-upload-clean-content'
    if injection:
        proof=value.get('seedProof',{})
        if proof.get('scope')!='Catalog/provenance before learner fixtures; later lifecycle proof covers nonempty learner preservation' or proof.get('version')!='ipi-rag-two-seed-v1' or proof.get('ids')!=['rag_injected_doc','rag_query_injection'] or proof.get('predecessorSha256')!='d8b36f19c987a00038a475c17ef285c5d375ee92c93df05c259894378b31205d' or any(proof.get(k)is not True for k in ('freshDefaults','managedUpgrade','customPreserved','nullPreserved','secondRunNoop','unrelatedPreserved','restored')):raise RuntimeError('RAG real seed preservation proof required')
    required={'status':'passed','profile':profile,'actualModelProof':False,'modelCalls':0,'mailCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':2 if upload_clean or injection else 1,'controlledActorCalls':2,'controlledJudgeCalls':5,'controlledEmbeddingCalls':3,'completionScope':'Controlled RAG defense and injection completion projections; no earned credit' if injection else 'Controlled RAG upload and clean document completion projections; no earned credit' if upload_clean else 'Controlled one RAG query completion projection; no earned credit'}
    for key,expected in required.items():
        if type(value.get(key)) is not type(expected) or value[key]!=expected:raise RuntimeError('RAG controlled identity mismatch')
    for key in ('uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'):
        if value.get(key) is not True:raise RuntimeError('RAG lifecycle proof missing')
    if value.get('cases')!=[dict(id=objective,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for objective in (['rag_injected_doc','rag_query_injection'] if injection else ['rag_upload','rag_clean_doc'] if upload_clean else ['rag_query'])]:raise RuntimeError('RAG exact case required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=1000 or not 0<=counts['api']<=80:raise RuntimeError('RAG content bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('restore','browser','mail','rag','routes','server','pools')]:raise RuntimeError('RAG cleanup incomplete')

def verify_ipi_email_five_content_result(value):
    required={'status':'passed','profile':'ipi-email-five-content','actualModelProof':False,'modelCalls':0,'mailCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':5,'controlledJudgeCalls':2,'controlledSessionOwners':2,'completionScope':'Controlled five email completion projections only; no earned credit'}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('IPI content identity mismatch')
    for flag in ('dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved','sessionPreEffectDenied','sessionJudgeCommitDenied','sessionPostCommitPublicationDenied','sessionPriorCommitPreserved','sessionSiblingPreserved'):
        if value.get(flag)is not True:raise RuntimeError('IPI content proof missing')
    flags=('learnerContent','adminPreview','independentGates','completedProjection')
    ids=('email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense')
    rows=value.get('cases')
    if rows!=[dict(id=id,**dict.fromkeys(flags,True)) for id in ids] or any(row[k]is not True for row in rows for k in flags):raise RuntimeError('IPI exact five content cases required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=1000 or not 0<=counts['api']<=80:raise RuntimeError('IPI content bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('restore','browser','mail','rag','routes','server','pools')]:raise RuntimeError('IPI content cleanup incomplete')

def verify_mcp_remaining_nine_content_result(value):
    required={'status':'passed','profile':'mcp-remaining-nine-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':9,'completionScope':'Controlled remaining-nine completion projections only; no earned credit'}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('MCP current content identity mismatch')
    for flag in ('freshDefaults','secondRunNoop','allDone','countParity','contentRestored','siblingPreserved','timeParity','instructorTimeParity','timeRestored','immutableEvidencePreserved'):
        if value.get(flag)is not True:raise RuntimeError('MCP current content proof missing')
    time=value.get('timeProof',{})
    routes=('/workshop-dashboard','/workshop/challenges','/workshop/progress')
    if type(value.get('controlledTimeSeconds'))is not int or value['controlledTimeSeconds']!=165:raise RuntimeError('MCP nonzero controlled time required')
    if not isinstance(time,dict) or any(type(time.get(k))is not int or time[k]!=v for k,v in (('controlledSeconds',165),('siblingSeconds',23),('instructorSeconds',165))):raise RuntimeError('MCP exact time proof required')
    expected_routes=[{'route':route,'seconds':165} for route in routes]
    if time.get('learnerRoutes')!=expected_routes or any(type(row.get('seconds'))is not int for row in time.get('learnerRoutes',[])):raise RuntimeError('MCP three route time parity required')
    if not isinstance(time.get('before'),list) or not time['before'] or time.get('after')!=time['before']:raise RuntimeError('MCP restored nonempty time baseline required')
    if any(type(time.get(k))is not int or time[k]<=0 for k in ('ownerId','siblingId')) or time['ownerId']==time['siblingId']:raise RuntimeError('MCP distinct time owners required')
    if len(time['before'])!=1:raise RuntimeError('MCP exact sibling time baseline required')
    sibling=time['before'][0]
    if not isinstance(sibling,dict) or str(sibling.get('user_id'))!=str(time['siblingId']) or sibling.get('workshop_key')!='mcp_workshop' or type(sibling.get('duration_seconds'))is not int or sibling['duration_seconds']!=23:raise RuntimeError('MCP nonempty sibling time row required')
    if any(sibling.get(k)is None for k in ('id','session_start','last_heartbeat')):raise RuntimeError('MCP complete time snapshot required')

    flags=('label','hint','solution','adminPreview','done')
    rows=value.get('cases')
    if rows!=[dict(id=id,**dict.fromkeys(flags,True)) for id in ('mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_audit_gap','mcp_shadow_server')] or any(row[k]is not True for row in rows for k in flags):raise RuntimeError('MCP exact nine content cases required')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=1000 or not 0<=counts['api']<=40:raise RuntimeError('MCP current content bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('browser','routes','server','pools')]:raise RuntimeError('MCP current content cleanup incomplete')

def verify_mcp_audit_content_result(value):
    required={'status':'passed','profile':'mcp-audit-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[]}
    for key,expected in required.items():
        if type(value.get(key))is not type(expected) or value[key]!=expected:raise RuntimeError('MCP content terminal mismatch')
    for flag in ('freshThreeFields','seedUpgrade','customFullSeedPreserved','nullFullSeedPreserved','masterGates','objectiveGates','learnerContent','adminPreview','siblingPreserved','contentRestored'):
        if value.get(flag)is not True:raise RuntimeError('MCP content proof incomplete')
    seed=value.get('seedReceipt',{})
    if seed.get('version')!='mcp-audit-seed-v1' or any(seed.get(k)is not True for k in ('freshDefaults','managedPriorThreeFields','instructorThreeFieldsPreserved','nullableContentPreserved','labelNullRejected','secondRunNoop','siblingCatalogPreserved','customProbeRolledBack','independentEffectiveGates','nullContentDenied')):raise RuntimeError('MCP content seed receipt missing')
    counts=value.get('requests',{})
    if set(counts)!={'browser','api'} or any(type(v)is not int for v in counts.values()) or not 1<=counts['browser']<=400 or not 1<=counts['api']<=40:raise RuntimeError('MCP content request bounds')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ('browser','routes','server','pools')]:raise RuntimeError('MCP content cleanup incomplete')

def verify_workshop_history_result(value):
    required={'status':'passed','profile':'workshop-history','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[]}
    for key,expected in required.items():
        actual=value.get(key)
        if actual!=expected or type(actual)is not type(expected):raise RuntimeError('History browser terminal receipt mismatch')
    probe=value.get('migrationProbe')
    expected_probe={'migration':'0124_graph_presentation_snapshot.sql','populatedUpgrade':True,'priorLedgerChecksumsPreserved':True,'priorTracePreserved':True,'runtimeGrants':True,'publicExecuteDenied':True,'sqlNullDenied':True,'accepted':7,'rejected':31,'noOp':True,'supported128PrefixFourBlocks':True,'worstUnicodeEnvelope':True,'legacyMetadataBoundPreserved':True,'freshInitialization':False}
    expected_grade={'migration':'0125_dpi_policy_packet_budget.sql','populatedUpgrade':True,'priorPacketPreserved':True,'predecessorExpandedDenied':True,'legacy24000Preserved':True,'compactActorAccepted':True,'compactDecoderAccepted':True,'sqlNullAccepted':True,'runtimeGrants':True,'publicExecuteDenied':True,'accepted':4,'rejected':21,'freshInitialization':False,'noOp':True}
    expected_probe['gradePacketProbe']=expected_grade
    grade=probe.get('gradePacketProbe') if isinstance(probe,dict) else None
    if not isinstance(grade,dict) or set(grade)!=set(expected_grade) or any(type(grade[key])is not type(expected) or grade[key]!=expected for key,expected in expected_grade.items()):raise RuntimeError('History grade packet probe receipt mismatch')
    if not isinstance(probe,dict) or set(probe)!=set(expected_probe) or any(type(probe[key])is not type(expected) or probe[key]!=expected for key,expected in expected_probe.items()):raise RuntimeError('History migration probe receipt mismatch')
    cases=value.get('cases')
    if not isinstance(cases,list) or [case.get('id') for case in cases]!=['sql','nosql']:raise RuntimeError('History browser cases incomplete')
    flags=('persistenceReload','siblingIsolation','resetLateResponse','ownerSwitchLateResponse','actualRenderedResults','escapedHtml','siblingHistoryPreserved')
    if any(case.get(flag)is not True for case in cases for flag in flags):raise RuntimeError('History browser assertion missing')
    for case,layout in zip(cases,['json-blocks','table']):
        if case.get('resultLayout')!=layout or case.get('source')!='fixture' or type(case.get('rowCount'))is not int or case['rowCount']!=4 or not isinstance(case.get('responseSha256'),str) or not re.fullmatch('[a-f0-9]{64}',case['responseSha256']):raise RuntimeError('History controlled rendered value proof missing')
    requests=value.get('requests',{})
    if set(requests)!={'api','chats','resets','historyRequests'} or any(type(v)is not int for v in requests.values()):raise RuntimeError('History request counters invalid')
    if not 1<=requests['api']<=1500 or requests['chats']!=6 or requests['resets']!=2 or not 8<=requests['historyRequests']<=requests['api']:raise RuntimeError('History request bounds mismatch')
    if type(value.get('controlledProviderCalls'))is not int or value['controlledProviderCalls']!=6:raise RuntimeError('History controlled provider calls mismatch')
    if value.get('cleanup')!=[{'name':name,'status':'fulfilled'} for name in ['browser','routes','server','runs','pools']]:raise RuntimeError('History owned cleanup incomplete')


def finflow0055_store_configuration(case,port,nonce):
    if case not in ('fresh','populated') or type(port)is not int or not 1024<port<65536 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('FinFlow closed store binding required')
    migration='dvaia_identity_migration';runtime='dvaia_identity_runtime';database='owasp_ai_goat_test_finflow_0055_'+nonce+'_'+case
    roles=''.join('CREATE ROLE '+role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ' for role in (migration,runtime)) if case=='fresh' else ''
    sql=roles+f'CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime};'
    return sql,{'PG_FINFLOW_0055_'+case.upper()+'_'+kind+'_URL':f'postgresql://{role}@127.0.0.1:{port}/{database}' for kind,role in [('RUNTIME',runtime),('MIGRATION',migration)]}

def verify_finflow0055_result(value):
    scope='0055 historical-default qualification; no actor/Judge proof'
    expected={'freshManagedFields':4,'populatedLegacyUnknownFields':4,'customHintPreserved':True,'nullSolutionPreserved':True,'fieldRollbackCases':4,'secondMigrationNoop':True,'siblingPreserved':True,'failedLoaderRollback':True,'scope':scope}
    if value.get('status')!='passed' or value.get('scope')!=scope or value.get('installedWrites') is not False or type(value.get('modelCalls'))is not int or value['modelCalls']!=0 or value.get('cleanupFailures')!=[]:raise RuntimeError('FinFlow terminal result required')
    qualification=value.get('qualification')
    if not isinstance(qualification,dict) or set(qualification)!=set(expected) or any(type(qualification[k])is not type(v) or qualification[k]!=v for k,v in expected.items()):raise RuntimeError('FinFlow qualification assertions incomplete')
    if value.get('poolCleanup')!=[{'index':i,'status':'closed'} for i in range(4)]:raise RuntimeError('FinFlow pool cleanup incomplete')
    return True

def finflow0055_environment(args,evidence,runtime,owner,urls):
    expected={'PG_FINFLOW_0055_'+case+'_'+role+'_URL' for case in ('FRESH','POPULATED') for role in ('RUNTIME','MIGRATION')}
    if set(urls)!=expected:raise RuntimeError('Exact four FinFlow URLs required')
    for name in ('home','tmp'):(runtime/name).mkdir(mode=0o700)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','FINFLOW_0055_NATIVE':'1','FINFLOW_0055_SOURCE_ROOT':args.package,'FINFLOW_0055_EVIDENCE_ROOT':str(evidence),'FINFLOW_0055_OWNER':owner,'FINFLOW_0055_MANIFEST':str(Path(args.manifest).resolve()),'FINFLOW_0055_MANIFEST_SHA256':args.manifest_sha256,**urls}

def validate_finflow0055_main(args):
    root=Path(args.package)
    if not args.main_workspace or root!=Path(__file__).resolve().parents[2] or root.resolve()!=root:raise RuntimeError('FinFlow exact main required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('FinFlow manifest hash mismatch')
    m=json.loads(Path(args.manifest).read_text());pins=m.get('sourcePins',{})
    if m.get('cohort')!=args.scenario or m.get('mode')!=('actual-model' if args.scenario in ('finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned') else 'model-free') or m.get('workspace')!=str(root):raise RuntimeError('FinFlow manifest scope mismatch')
    required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/finflow0055Main.js','tests/finflow0055Main.test.js','tests/fixtures/finflow0055NativeQualification.js','tests/finflow0055NativeQualification.test.js','tests/postgres/finflow0055_launcher_test.py','tests/postgres/ctfStage9MainQualification.js','tests/fixtures/boundedJsonArtifact.js','tests/postgres/fixtures/admin-curriculum-before.json','tests/postgres/fixtures/admin-curriculum-proposed.json','db/postgres/migrate.js','server/database/postgres/identityRepository.js','server/database/postgres/workshopPlatformSeed.js'}
    if args.scenario=='finflow-admission':required.update({'tests/postgres/finflowAdmissionMain.js','tests/fixtures/finflowAdmissionQualification.js','tests/finflowAdmissionMain.test.js','tests/postgres/finflow_admission_launcher_test.py','server/routes/sensitiveInfoWorkshop.js'})
    if args.scenario=='finflow-policy':
        validate_policy_manifest(m,args.policy_cohort)
        required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/finflowPolicyMain.js','tests/fixtures/finflowPolicyQualification.js','tests/fixtures/finflowPolicyNativeComposition.js','tests/fixtures/finflowPolicyWireBinding.js','tests/postgres/finflowBackupBrowserActualTransport.js','tests/finflowPolicyQualification.test.js','tests/postgres/finflow_policy_launcher_test.py'}
        required.update(p.relative_to(root).as_posix() for p in (root/'db/postgres/workshop-migrations/finflow').glob('*.sql'))
    if args.scenario=='finflow-traversal':
        validate_traversal_manifest(m)
        required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/finflowTraversalMain.js','tests/postgres/finflowPolicyMain.js','tests/fixtures/finflowPolicyNativeComposition.js','tests/fixtures/finflowPolicyQualification.js','tests/fixtures/finflowTraversalQualification.js','tests/fixtures/finflowTraversalNativeChecks.js','tests/postgres/finflowTraversalMainComposition.js','tests/fixtures/finflowPolicyWireBinding.js','tests/postgres/finflowBackupBrowserActualTransport.js','tests/finflowTraversalQualification.test.js','tests/postgres/finflow_traversal_launcher_test.py'}
        required.update(p.relative_to(root).as_posix() for p in (root/'db/postgres/workshop-migrations/finflow').glob('*.sql'))
    if args.scenario=='mcp-mounted-http':
        validate_mcp_manifest(m,args,root)
        required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/mcpMountedHttpMain.js','tests/postgres/mcp_mounted_http_topology.py','tests/postgres/mcp_mounted_http_launcher_test.py','tests/postgres/test_mcp_mounted_http_topology.py','tests/fixtures/mcpMountedHttpComposition.js','tests/fixtures/mcpMountedHttpWirePolicy.js','tests/mcpMountedHttpWirePolicy.test.js','tests/mcpMountedHttpMain.test.js','tests/fixtures/mcpMountedHttpResetChecks.js','tests/mcpMountedHttpResetChecks.test.js','tests/postgres/finflowBackupBrowserActualTransport.js','server/routes/mcpWorkshop.js','server/services/mcp/ownedResourceProduction.js',*MCP_TEMPLATES.values()}
        required.update(p.relative_to(root).as_posix() for p in (root/'db/postgres/workshop-migrations/mcp').glob('*.sql'))
    if args.scenario in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):
        validate_mcp_manifest(m,args,root)
        required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/codeBotCurrentMain.js','tests/postgres/codeBotLiveWorkflow.integration.test.js','tests/fixtures/codeBotCurrentWirePolicy.js','tests/fixtures/codeBotCurrentBinding.js','tests/codeBotCurrentQualification.test.js','tests/postgres/test_codebot_current_topology.py','tests/postgres/codebot_current_launcher_test.py','tests/postgres/mcp_mounted_http_topology.py','tests/postgres/test_mcp_mounted_http_topology.py','tests/postgres/finflowBackupBrowserActualTransport.js',MCP_TEMPLATES['cli']}
        required.update(p.relative_to(root).as_posix() for p in (root/'db/postgres/workshop-migrations/supply_chain').glob('*.sql'))
    if args.scenario=='dpi-current-owned':
        validate_dpi_manifest(m)
        required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/dpi_current_owned_launcher_test.py','tests/postgres/dpiCurrentOwnedMain.js','tests/postgres/dpiCurrentOwnedActualTransport.js','tests/fixtures/dpiCurrentOwnedContractV2.js','tests/fixtures/dpiCurrentOwnedQualification.js','tests/fixtures/dpiCurrentOwnedWireBinding.js','tests/fixtures/dpiJudgeCases.js','tests/dpiCurrentOwned.test.js','tests/postgres/ctfStage9MainQualification.js','tests/postgres/finflow0055Main.js','tests/fixtures/boundedJsonArtifact.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js','server/routes/promptInjectionWorkshop.js'}
    required.update('tests/postgres/'+n for n in ['sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'])
    required.update(p.relative_to(root).as_posix() for p in (root/'db/postgres/identity-migrations').glob('*.sql'))
    if not required.issubset(pins):raise RuntimeError('FinFlow source closure incomplete')
    for rel,pin in pins.items():
        p=root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(root) or digest(p)!=pin:raise RuntimeError('FinFlow source changed')
    if inventory(root/'node_modules')!=m.get('dependencyInventory'):raise RuntimeError('FinFlow dependency changed')
    for value,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        p=Path(value)
        if not p.is_absolute() or p.resolve()!=p or digest(p)!=pin:raise RuntimeError('FinFlow runtime changed')
    if not args.python_sha256 or digest(Path(sys.executable).resolve())!=args.python_sha256:raise RuntimeError('FinFlow Python changed')
    if (digest(root/'.env') if (root/'.env').exists() else None)!=m.get('mainEnvSha256'):raise RuntimeError('Main environment changed')
    return root

def finflow_admission_store_configuration(port,nonce):
    if type(port)is not int or not 1024<port<65536 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('FinFlow admission binding required')
    database='owasp_ai_goat_test_finflow_admission_'+nonce+'_identity';migration='dvaia_identity_migration';runtime='dvaia_identity_runtime'
    sql=''.join('CREATE ROLE '+role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ' for role in (migration,runtime))+f'CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime};'
    return sql,{key:f'postgresql://{role}@127.0.0.1:{port}/{database}' for key,role in [('IDENTITY_DATABASE_URL',runtime),('IDENTITY_MIGRATION_DATABASE_URL',migration)]}

def finflow_admission_environment(args,evidence,runtime,owner,urls):
    if set(urls)!={'IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'}:raise RuntimeError('Exact two admission URLs required')
    for name in ('home','tmp','logs'):(runtime/name).mkdir(mode=0o700)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','FINFLOW_ADMISSION_NATIVE':'1','FINFLOW_ADMISSION_SOURCE_ROOT':args.package,'FINFLOW_ADMISSION_EVIDENCE_ROOT':str(evidence),'FINFLOW_ADMISSION_OWNER':owner,'FINFLOW_ADMISSION_MANIFEST':str(Path(args.manifest).resolve()),'FINFLOW_ADMISSION_MANIFEST_SHA256':args.manifest_sha256,'JWT_SECRET':secrets.token_urlsafe(48),**urls}

def verify_finflow_admission_result(value):
    scope='controlled actor/store; real authenticated live catalog; no model proof'
    expected={'scope':scope,'actorCalls':2,'creditWrites':0,'enabled':200,'disabled':409,'hiddenSelected':403,'hiddenGeneral':403,'reenabled':200,'storageUnavailable':503,'canonicalCompletions':0,'canonicalJudgments':0}
    if value.get('status')!='passed' or value.get('scope')!=scope or value.get('installedWrites') is not False or type(value.get('modelCalls'))is not int or value['modelCalls']!=0 or value.get('cleanupFailures')!=[]:raise RuntimeError('FinFlow admission terminal result required')
    q=value.get('qualification')
    if not isinstance(q,dict) or set(q)!=set(expected) or any(type(q[k])is not type(v) or q[k]!=v for k,v in expected.items()):raise RuntimeError('FinFlow admission assertions incomplete')
    if value.get('sharedPoolsClosed') is not True or value.get('poolCleanup')!=[{'index':i,'status':'closed'} for i in range(2)]:raise RuntimeError('FinFlow admission pool cleanup incomplete')
    return True

POLICY_MODEL='llama3.1:8b'
POLICY_DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
DPI_INPUT_SHA256='9c59447df38d06d8a161f5085cd0f5db25dc91a16a035a34efd49c2ab482bdce'
DPI_BUDGETS={'turns':17,'actor':19,'judge':42,'tags':58,'external':119,'workMs':5220000,'turnMs':300000,'wireMs':120000}
DPI_RETAINED_SELECTOR='retained-four-v1'
DPI_RETAINED_INPUT_SHA256='65aac97d8c2bc70f9d4190ba968842ea3d494f603f836f896683cf83e928c49d'
DPI_RETAINED_BUDGETS={'turns':9,'actor':12,'judge':24,'review':2,'tags':43,'external':81,'workMs':2700000,'turnMs':300000,'wireMs':120000}
DPI_FIXED_SELECTOR='retained-fixed-v1'
DPI_FIXED_INPUT_SHA256='1dcb72680cbe5c6c910374225fa18ea639b892070ae53d9448fbc022278682cb'
DPI_FIXED_BUDGETS={'turns':1,'actor':2,'judge':0,'review':2,'tags':13,'external':17,'workMs':300000,'turnMs':300000,'wireMs':120000}
DPI_RETRY_SELECTOR='retained-retry-v1'
DPI_RETRY_INPUT_SHA256='94d2fd5eed24f83c2210dcd04457261db64aa74030ac7c65b6e360fb4f24a936'
DPI_RETRY_BUDGETS={'turns':5,'actor':7,'judge':12,'review':2,'tags':28,'external':49,'workMs':1500000,'turnMs':300000,'wireMs':120000}
DPI_UX_SELECTOR='mode-ux-representative-v1'
DPI_UX_INPUT_SHA256='a44412622aa2296f510517f5f8e7fce8de9a1712ed34332a0aaa14b20c1d9b36'
DPI_UX_BUDGETS={'turns':3,'actor':3,'judge':6,'review':0,'tags':22,'external':31,'workMs':900000,'turnMs':300000,'wireMs':120000}
DPI_IDS=['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']
def dpi_cases(selector='all'):
    if selector==DPI_UX_SELECTOR:return [('interact:fixed1','interact'),('interact:fixed2','interact'),('system_prompt:candidate','system_prompt')]
    if selector==DPI_RETRY_SELECTOR:return [('virtualization:candidate','virtualization'),('side_stepping:candidate','side_stepping'),('side_stepping:negative','side_stepping'),('obfuscation:candidate','obfuscation'),('obfuscation:fixed','obfuscation')]
    if selector==DPI_FIXED_SELECTOR:return [('obfuscation:fixed','obfuscation')]
    if selector==DPI_RETAINED_SELECTOR:return [(objective+':'+kind,objective) for objective in ('multi_language','virtualization','side_stepping') for kind in ('candidate','negative')]+[('obfuscation:'+kind,'obfuscation') for kind in ('candidate','negative','fixed')]
    if selector!='all':raise RuntimeError('Unknown DPI selector')
    return [('interact:candidate1','interact'),('interact:candidate2','interact'),('interact:negative','interact')] + [(objective+':'+kind,objective) for objective in DPI_IDS[1:] for kind in ('candidate','negative')]

def validate_dpi_manifest(m):
    selector=m.get('selector','all')
    if selector not in ('all',DPI_RETAINED_SELECTOR,DPI_FIXED_SELECTOR,DPI_RETRY_SELECTOR,DPI_UX_SELECTOR) or (selector=='all' and 'selector' in m):raise RuntimeError('DPI closed selector required')
    input_sha=DPI_RETAINED_INPUT_SHA256 if selector==DPI_RETAINED_SELECTOR else DPI_FIXED_INPUT_SHA256 if selector==DPI_FIXED_SELECTOR else DPI_RETRY_INPUT_SHA256 if selector==DPI_RETRY_SELECTOR else DPI_UX_INPUT_SHA256 if selector==DPI_UX_SELECTOR else DPI_INPUT_SHA256
    budgets=DPI_RETAINED_BUDGETS if selector==DPI_RETAINED_SELECTOR else DPI_FIXED_BUDGETS if selector==DPI_FIXED_SELECTOR else DPI_RETRY_BUDGETS if selector==DPI_RETRY_SELECTOR else DPI_UX_BUDGETS if selector==DPI_UX_SELECTOR else DPI_BUDGETS
    if m.get('cohort')!='dpi-current-owned' or m.get('mode')!='actual-model' or m.get('model')!=POLICY_MODEL or m.get('modelDigest')!=POLICY_DIGEST or m.get('inputSha256')!=input_sha or m.get('budgets')!=budgets or any(k in m for k in ('policyCohort','mcpTopology','browserInventory')):raise RuntimeError('DPI closed manifest required')
    if any(type(m['budgets'][k])is not int for k in budgets):raise RuntimeError('DPI integer budgets required')
    return True

def dpi_store_configuration(port,nonce):
    sql,urls=finflow_admission_store_configuration(port,nonce)
    return sql.replace('owasp_ai_goat_test_finflow_admission_','owasp_ai_goat_test_dpi_current_'),{k:v.replace('owasp_ai_goat_test_finflow_admission_','owasp_ai_goat_test_dpi_current_') for k,v in urls.items()}

def dpi_environment(args,evidence,runtime,owner,urls):
    if set(urls)!={'IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'}:raise RuntimeError('DPI exact identity URLs required')
    from urllib.parse import urlsplit
    parsed=urlsplit(urls['IDENTITY_DATABASE_URL'])
    try:expected=dpi_store_configuration(parsed.port,owner[:12])[1]
    except (ValueError,TypeError):raise RuntimeError('DPI URL binding invalid')
    if urls!=expected:raise RuntimeError('DPI URL binding invalid')
    for name in ('home','tmp','logs'):(runtime/name).mkdir(mode=0o700)
    manifest=json.loads(Path(args.manifest).read_text());validate_dpi_manifest(manifest)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','AWS_EC2_METADATA_DISABLED':'true','DPI_CURRENT_NATIVE':'1','DPI_CURRENT_SELECTOR':manifest.get('selector','all'),'DPI_CURRENT_SOURCE_ROOT':args.package,'DPI_CURRENT_EVIDENCE_ROOT':str(evidence),'DPI_CURRENT_OWNER':owner,'DPI_CURRENT_MANIFEST':str(Path(args.manifest).resolve()),'DPI_CURRENT_MANIFEST_SHA256':args.manifest_sha256,'JWT_SECRET':secrets.token_urlsafe(48),**urls}

def verify_dpi_result(value,wire,selector='all'):
    budgets=DPI_RETAINED_BUDGETS if selector==DPI_RETAINED_SELECTOR else DPI_FIXED_BUDGETS if selector==DPI_FIXED_SELECTOR else DPI_RETRY_BUDGETS if selector==DPI_RETRY_SELECTOR else DPI_UX_BUDGETS if selector==DPI_UX_SELECTOR else DPI_BUDGETS
    if value.get('status')!='passed' or value.get('installedWrites')is not False or type(value.get('actualModelProof'))is not bool or value.get('cleanupFailures')!=[]:raise RuntimeError('DPI terminal cleanup required')
    q=value.get('qualification',{});turns=q.get('turns',[])
    if q.get('technicalPassed')is not True or q.get('allObjectivesCreditQualified')is not False or q.get('installedWrites')is not False or q.get('resetHistorySiblingPreserved')is not True or [(r.get('id'),r.get('objective'))for r in turns]!=dpi_cases(selector):raise RuntimeError('DPI complete scoped matrix required')
    if selector!='all' and (q.get('actorAchievement')!='unreviewed' or q.get('selector')!=selector or (selector!=DPI_UX_SELECTOR and q.get('semanticQualified')is not False) or any(t.get('actorProvenance')is not True or t.get('effectProvenance')is not True or t.get('actorOutcome',{}).get('assessment')!='unreviewed' or (selector!=DPI_UX_SELECTOR and t.get('qualified')is not False) or (t['id']=='obfuscation:fixed' and t.get('reviewProvenance')is not True) for t in turns)):raise RuntimeError('DPI retained actor provenance missing')
    if selector==DPI_UX_SELECTOR:
        transitions=q.get('modeTransitions',[])
        if [(t.get('from'),t.get('to')) for t in transitions]!=[('vuln','fixed'),('fixed','vuln')] or any(t.get('generationAfter')!=t.get('generationBefore') or t.get('modeStampAfter')==t.get('modeStampBefore') or not t.get('modeStampBefore') or not t.get('modeStampAfter') or int(t.get('revisionAfter',-1))<=int(t.get('revisionBefore',-1)) or t.get('staleGradeDenied')is not True for t in transitions) or transitions[0].get('completedObjectiveIds')!=[] or transitions[1].get('completedObjectiveIds')!=turns[1].get('completedAfter') or q.get('semanticQualified')is not all(t.get('qualified')is True for t in turns):raise RuntimeError('DPI mode transition proof incomplete')
        if any(t.get('status')!=200 or t.get('actualActorCalls',0)<1 or t.get('actualJudgeCalls',0)<1 or t.get('actorBinding',{}).get('actorCalls')!=t.get('actualActorCalls') or t.get('judgeBinding',{}).get('judgeCalls')!=t.get('actualJudgeCalls') or not isinstance(t.get('completedAfter'),list) for t in turns):raise RuntimeError('DPI representative actual model proof incomplete')
    if any(type(t.get('qualified'))is not bool or type(t.get('outputLimited'))is not bool or t.get('status')not in (200,500,503) for t in turns) or (selector=='all' and q.get('semanticQualified')is not all(t['qualified']for t in turns)):raise RuntimeError('DPI semantic scope mismatch')
    if wire.get('version')!='dpi-current-owned-wire-v1' or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or type(wire.get('handlersPending'))is not int or wire['handlersPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('DPI physical wire incomplete')
    counts=wire.get('counts',{});calls=wire.get('calls',[])
    kinds=('actor','judge','tags') if selector=='all' else ('actor','judge','review','tags')
    if set(counts)!={'external',*kinds} or any(type(counts[k])is not int or not 0<=counts[k]<=budgets[k] for k in counts) or counts['tags']<1 or counts['external']!=sum(counts[k]for k in kinds) or len(calls)!=counts['external']:raise RuntimeError('DPI wire counts invalid')
    for kind in kinds:
        if sum(r.get('kind')==kind for r in calls)!=counts[kind]:raise RuntimeError('DPI wire kind count invalid')
    ids={x[0] for x in dpi_cases(selector)}
    for index,row in enumerate(calls):
        if row.get('index')!=index or row.get('terminal')!='returned' or row.get('status')!=200 or row.get('responseComplete')is not True or row.get('responseCaptureTruncated')is not False or row.get('caseId')not in ids|{None}:raise RuntimeError('DPI incomplete wire call')
        if row.get('caseId')is None and not (index==0 and row.get('kind')=='tags'):raise RuntimeError('DPI unbound wire call')
    for t in turns:
        rows=[r for r in calls if r.get('caseId')==t['id']]
        for kind,key in [('actor','actualActorCalls'),('judge','actualJudgeCalls'),*([('review','actualReviewCalls')] if selector!='all' else [])]:
            count=sum(r['kind']==kind for r in rows);cap=(2 if t['objective']=='obfuscation' else 1) if kind=='actor' else (2 if t['id']=='obfuscation:fixed' else 0) if kind=='review' else (0 if t['id']=='obfuscation:fixed' else 4 if t['objective']in ('virtualization','obfuscation') else 2)
            if type(t.get(key))is not int or t[key]!=count or count>cap:raise RuntimeError('DPI per-turn count mismatch')
        if t['outputLimited']!=any(r.get('doneReason')=='length'for r in rows if r['kind']!='tags') or (t['qualified']and(t['status']!=200 or t['outputLimited'])):raise RuntimeError('DPI output qualification mismatch')
    model_proof=any(t['status']==200 and t['actualActorCalls']>0 and t['actualJudgeCalls']>0 and isinstance(t.get('actorBinding'),dict) and t['actorBinding'].get('actorCalls')==t['actualActorCalls'] and isinstance(t.get('judgeBinding'),dict) and t['judgeBinding'].get('judgeCalls')==t['actualJudgeCalls'] and re.fullmatch('[a-f0-9]{64}',t['judgeBinding'].get('transcriptSha256','')) for t in turns)
    if value['actualModelProof']is not model_proof:raise RuntimeError('DPI actual model proof mismatch')
    return True

MCP_TEMPLATES={'cli':'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in','http':'sidecars/sandbox-runner/owned-http/http-profile.apparmor.in'}
MCP_MAILPIT_IMAGE='sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
def validate_mcp_arguments(args):
    if args.scenario not in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') or not args.main_workspace:raise RuntimeError('MCP main-only selector required')
    for name in ('ssh','ssh_sha256','ssh_config','ssh_config_sha256','ssh_host','ssh_known_hosts','ssh_known_hosts_sha256','sandbox_image_id'):
        if not getattr(args,name,None):raise RuntimeError('MCP SSH and image pins required')
    if getattr(args,'scp',None) or getattr(args,'scp_sha256',None):raise RuntimeError('MCP SCP forbidden')
    if args.ssh!='/usr/bin/ssh' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',args.ssh_host):raise RuntimeError('Exact MCP SSH identity required')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',args.sandbox_image_id):raise RuntimeError('MCP immutable image required')
    for name in ('ssh','ssh_config','ssh_known_hosts'):
        p=Path(getattr(args,name))
        if not p.is_absolute() or p.resolve()!=p or p.is_symlink() or not p.is_file() or digest(p)!=getattr(args,name+'_sha256'):raise RuntimeError('MCP SSH pin changed')
    known=Path(args.ssh_known_hosts);st=known.stat()
    if str(known)=='/dev/null' or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o777!=0o600 or not 1<=st.st_size<=16384:raise RuntimeError('MCP private pinned known-host authority required')

def mcp_ssh_argv(args):
    return [args.ssh,'-F',args.ssh_config,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','ControlMaster=no','-o','ControlPath=none','-o','NoHostAuthenticationForLocalhost=no','-o','UserKnownHostsFile='+args.ssh_known_hosts,'-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no']

def mcp_remote_argv(args, command):
    if not isinstance(command,list) or not command or any(not isinstance(x,str) or '\x00' in x for x in command):raise ValueError('Exact remote argv required')
    return [*mcp_ssh_argv(args),args.ssh_host,'--',shlex.join(command)]

def validate_mcp_host_authority(ssh,root):
    if ssh.get('hostname')!='127.0.0.1' or type(ssh.get('port'))is not int or not 1024<ssh['port']<65536:raise RuntimeError('MCP bound VM endpoint required')
    known=Path(ssh['knownHosts'])
    lines=[x.strip()for x in known.read_text().splitlines()if x.strip() and not x.lstrip().startswith('#')]
    if len(lines)!=1:raise RuntimeError('MCP exact single VM host key required')
    fields=lines[0].split()
    if len(fields)!=3 or fields[0]!=f"[127.0.0.1]:{ssh['port']}" or fields[1]not in ('ssh-ed25519','ecdsa-sha2-nistp256','ssh-rsa') or not re.fullmatch('[A-Za-z0-9+/]+={0,2}',fields[2]):raise RuntimeError('MCP known-host record invalid')
    receipt=ssh.get('hostKeyAuthority',{});p=Path(receipt.get('path',''))
    if not p.is_absolute() or p.resolve()!=p or p.is_symlink() or not p.is_relative_to(root) or not p.is_file() or p.stat().st_size>65536 or digest(p)!=receipt.get('sha256'):raise RuntimeError('MCP host-key provenance receipt missing')
    value=json.loads(p.read_text())
    expected={'status':'authenticated-existing-vm-host-key','method':'local-vm-control-plane','knownHostsSha256':ssh['knownHostsSha256'],'sshHost':ssh['host'],'hostname':ssh['hostname'],'port':ssh['port']}
    if any(value.get(k)!=v for k,v in expected.items()):raise RuntimeError('MCP authenticated host-key provenance mismatch')
    journal=p.parent/'ownership.json'
    if journal.resolve()!=journal or journal.is_symlink() or not journal.is_file() or journal.stat().st_size>1048576:raise RuntimeError('MCP host-key terminal journal missing')
    terminal=json.loads(journal.read_text())
    failures=('failure','cleanupFailure','admissionFailure','publicationFailure','finalizationFailure','restorationFailure','journalFailure')
    if terminal.get('status')!='passed' or terminal.get('cleanupVerified') is not True or terminal.get('sourceUnchanged') is not True or any(k in terminal for k in failures):raise RuntimeError('MCP host-key terminal unsuccessful')
    if terminal.get('receiptSha256')!=receipt['sha256'] or terminal.get('manifestSha256')!=value.get('manifestSha256') or not value.get('manifestSha256') or terminal.get('authority')!=value.get('authority') or not isinstance(value.get('authority'),dict):raise RuntimeError('MCP host-key terminal binding mismatch')
    if value.get('knownHostsPath')!=str(known) or value.get('daemonId')!=ssh.get('daemonId') or value.get('cleanup',{}).get('status')!='removed_absence_verified':raise RuntimeError('MCP host-key terminal resource mismatch')

def validate_mcp_manifest(manifest,args,root):
    validate_mcp_arguments(args)
    if args.scenario=='mcp-mounted-http':validate_mcp_profile_manifest(manifest,args)
    model,model_digest=mcp_selected_model(args)
    if manifest.get('cohort')!=args.scenario or args.scenario not in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') or manifest.get('mode')!='actual-model' or manifest.get('model')!=model or manifest.get('modelDigest')!=model_digest or 'policyCohort' in manifest:raise RuntimeError('MCP manifest identity mismatch')
    if manifest.get('imageId')!=args.image_id or manifest.get('dockerAuthority')!={'host':args.docker_host,'daemonId':args.docker_daemon}:raise RuntimeError('MCP PostgreSQL/daemon identity mismatch')
    runtime={'node':{'path':args.node,'sha256':args.node_sha256},'docker':{'path':args.docker,'sha256':args.docker_sha256},'python':{'path':str(Path(sys.executable).resolve()),'sha256':args.python_sha256}}
    if manifest.get('runtimePins')!=runtime:raise RuntimeError('MCP runtime manifest mismatch')
    topology=manifest.get('mcpTopology',{})
    if topology.get('runnerImage')!=args.sandbox_image_id or topology.get('mailpitImage')!=(MCP_MAILPIT_IMAGE if args.scenario=='mcp-mounted-http' else None):raise RuntimeError('MCP image binding mismatch')
    ssh=topology.get('ssh',{})
    expected={'executable':args.ssh,'sha256':args.ssh_sha256,'config':args.ssh_config,'configSha256':args.ssh_config_sha256,'host':args.ssh_host,'daemonId':args.docker_daemon,'strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHosts':args.ssh_known_hosts,'knownHostsSha256':args.ssh_known_hosts_sha256}
    if any(ssh.get(k)!=v for k,v in expected.items()) or type(ssh.get('uid'))is not int or ssh['uid']<0 or not re.fullmatch('[a-f0-9]{64}',ssh.get('resolvedConfigurationSha256','')):raise RuntimeError('MCP SSH authority mismatch')
    validate_mcp_host_authority(ssh,root)
    if topology.get('templates')!={k:{'path':rel,'sha256':digest(root/rel)}for k,rel in MCP_TEMPLATES.items() if args.scenario=='mcp-mounted-http' or k=='cli'}:raise RuntimeError('MCP profile source mismatch')
    from ctf_setup_sidecars import build_context
    if topology.get('buildContext')!=build_context(root/'sidecars/sandbox-runner'):raise RuntimeError('MCP image source inventory changed')
    receipt=topology.get('buildReceipt',{});path=Path(receipt.get('path',''))
    if not path.is_absolute() or path.resolve()!=path or path.is_symlink() or not path.is_relative_to(root) or not path.is_file() or path.stat().st_size>4*1024*1024 or digest(path)!=receipt.get('sha256'):raise RuntimeError('MCP build receipt changed')
    # The separately reviewed receipt binds exact source context to the immutable image.
    value=json.loads(path.read_text())
    if value.get('imageId')!=args.sandbox_image_id or value.get('buildContext')!=topology['buildContext'] or value.get('status')!='passed':raise RuntimeError('MCP reviewed build identity missing')
    return topology

def verify_mcp_ssh_runtime(args,topology,run):
    resolved=run([*mcp_ssh_argv(args),'-G',args.ssh_host])
    if resolved.returncode or hashlib.sha256(resolved.stdout.encode()).hexdigest()!=topology['ssh']['resolvedConfigurationSha256']:raise RuntimeError('MCP resolved SSH configuration changed')
    values=dict(line.split(' ',1) for line in resolved.stdout.splitlines() if ' ' in line)
    if values.get('stricthostkeychecking') not in ('true','yes') or values.get('batchmode')!='yes' or values.get('permitlocalcommand')!='no' or values.get('nohostauthenticationforlocalhost') not in ('false','no') or values.get('userknownhostsfile')!=args.ssh_known_hosts or values.get('globalknownhostsfile')!='/dev/null' or values.get('updatehostkeys') not in ('false','no'):raise RuntimeError('MCP strict SSH policy missing')
    if values.get('hostname')!=topology['ssh']['hostname'] or values.get('port')!=str(topology['ssh']['port']):raise RuntimeError('MCP SSH endpoint changed')
    observed=run(mcp_remote_argv(args,['id','-u']))
    if observed.returncode or observed.stdout.strip()!=str(topology['ssh']['uid']):raise RuntimeError('MCP remote UID changed')
    return topology['ssh']

def mcp_store_configuration(store,port,nonce):
    if store not in ('identity','mcp') or type(port)is not int or not 1024<port<65536 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Exact MCP store binding required')
    database='owasp_ai_goat_test_mcp_mounted_http_'+nonce+'_'+store;roles={k:'dvaia_'+store+'_'+k for k in ('runtime','migration')};prefix='IDENTITY' if store=='identity' else 'MCP_WORKSHOP'
    sql=''.join('CREATE ROLE '+r+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ' for r in roles.values())+f"CREATE DATABASE {database} OWNER {roles['migration']}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {roles['migration']},{roles['runtime']};"
    return sql,{prefix+('_MIGRATION_DATABASE_URL' if k=='migration' else '_DATABASE_URL'):f'postgresql://{r}@127.0.0.1:{port}/{database}'for k,r in roles.items()}

def mcp_environment(args,evidence,runtime,owner,urls,sidecars):
    from urllib.parse import urlparse
    if not re.fullmatch('[a-f0-9]{32}',owner) or not urls:raise RuntimeError('MCP exact owner required')
    port=urlparse(next(iter(urls.values()))).port;expected={}
    for store in ('identity','mcp'):expected.update(mcp_store_configuration(store,port,owner[:12])[1])
    if urls!=expected:raise RuntimeError('MCP exact four URLs required')
    keys={'MCP_OWNED_TARGET_URL','MCP_OWNED_TARGET_TOKEN','MCP_OWNED_HTTP_ENABLED','MCP_OWNED_HTTP_URL','MCP_OWNED_HTTP_TOKEN','MAILPIT_SMTP_HOST','MAILPIT_SMTP_PORT','MAILPIT_API_URL'}
    if set(sidecars)!=keys or sidecars['MCP_OWNED_HTTP_ENABLED']!='true' or sidecars['MAILPIT_SMTP_HOST']!='127.0.0.1':raise RuntimeError('MCP exact sidecar environment required')
    ports=[]
    for key in ('MCP_OWNED_TARGET_URL','MCP_OWNED_HTTP_URL','MAILPIT_API_URL'):
        u=urlparse(sidecars[key])
        if u.scheme!='http' or u.hostname!='127.0.0.1' or u.username or u.password or u.path or u.query or u.fragment or not u.port or not 1024<u.port<65536:raise RuntimeError('MCP sidecar loopback required')
        ports.append(u.port)
    if not sidecars['MAILPIT_SMTP_PORT'].isdigit() or not 1024<int(sidecars['MAILPIT_SMTP_PORT'])<65536:raise RuntimeError('MCP SMTP port required')
    ports.append(int(sidecars['MAILPIT_SMTP_PORT']))
    if len(set(ports+[port]))!=5:raise RuntimeError('MCP distinct endpoints required')
    for key in ('MCP_OWNED_TARGET_TOKEN','MCP_OWNED_HTTP_TOKEN'):
        if not re.fullmatch('[A-Za-z0-9_-]{64}',sidecars[key]):raise RuntimeError('MCP owned token required')
    if sidecars['MCP_OWNED_TARGET_TOKEN']==sidecars['MCP_OWNED_HTTP_TOKEN']:raise RuntimeError('MCP distinct tokens required')
    for name in ('home','tmp','logs','appdata','assets'):(runtime/name).mkdir(mode=0o700)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs'),'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','AWS_EC2_METADATA_DISABLED':'true','MCP_SIDECARS_AUTOSTART':'false','MCP_OWNED_RESOURCES_ENABLED':'true','MCP_MOUNTED_HTTP_NATIVE':'1','MCP_MOUNTED_PROFILE':mcp_profile(args),**({'MCP_RECON_70B':'1','MCP_DECISION_TIMEOUT_MS':'90000','MCP_RESPONSE_TIMEOUT_MS':'90000','MCP_RUN_TIMEOUT_MS':'290000'} if getattr(args,'mcp_recon_70b',False) else {}),**({'MCP_RECON_JUDGE_120':'1','MCP_RECON_JUDGE_TIMEOUT_MS':'120000'} if getattr(args,'mcp_recon_judge_120',False) else {}),**({'MCP_OBSERVED_ACTION_ENABLED':'true','MCP_SUPPLY_CHAIN_ENABLED':'true'} if mcp_profile(args)=='supply-chain' else {'MCP_OBSERVED_ACTION_ENABLED':'true'} if mcp_profile(args) in ('poisoning-contrast','poisoning-positive') else {}),'MCP_MOUNTED_HTTP_SOURCE_ROOT':args.package,'MCP_MOUNTED_HTTP_EVIDENCE_ROOT':str(evidence),'MCP_MOUNTED_HTTP_MANIFEST':str(Path(args.manifest).resolve()),'MCP_MOUNTED_HTTP_MANIFEST_SHA256':args.manifest_sha256,'MCP_MOUNTED_HTTP_OWNER':owner,'JWT_SECRET':secrets.token_urlsafe(48),**urls,**sidecars}

def codebot_current_store_configuration(store,port,nonce):
    if type(port)is not int or not 1024<port<65536:raise ValueError('CodeBot owned port required')
    sql,urls=codebot_store_configuration(store,port,nonce)
    return sql.replace('owasp_ai_goat_test_codebot_parity_','owasp_ai_goat_test_codebot_current_'),{k:v.replace('owasp_ai_goat_test_codebot_parity_','owasp_ai_goat_test_codebot_current_')for k,v in urls.items()}

def codebot_current_environment(args,evidence,runtime,owner,urls,sidecars):
    from urllib.parse import urlparse
    if args.scenario not in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):raise RuntimeError('CodeBot closed environment scope required')
    if not re.fullmatch('[a-f0-9]{32}',owner) or not urls:raise RuntimeError('CodeBot exact owner required')
    port=urlparse(next(iter(urls.values()))).port;expected={}
    for store in ('identity','supply_chain'):expected.update(codebot_current_store_configuration(store,port,owner[:12])[1])
    if urls!=expected:raise RuntimeError('CodeBot exact four URLs required')
    if set(sidecars)!={'SANDBOX_RUNNER_URL'}:raise RuntimeError('CodeBot CLI-only environment required')
    u=urlparse(sidecars['SANDBOX_RUNNER_URL'])
    if u.scheme!='http' or u.hostname!='127.0.0.1' or u.username or u.password or u.path or u.query or u.fragment or not u.port or not 1024<u.port<65536 or u.port==port:raise RuntimeError('CodeBot distinct owned CLI endpoint required')
    for name in ('home','tmp','logs','appdata','assets'):(runtime/name).mkdir(mode=0o700)
    return {'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs'),'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','AWS_EC2_METADATA_DISABLED':'true','MCP_SIDECARS_AUTOSTART':'false','CODEBOT_OWNED_EXECUTION_ENABLED':'true','CODEBOT_LIVE_SCOPE':('clean-fixed' if args.scenario=='codebot-current-clean-fixed' else 'all' if args.scenario=='codebot-current-full-six' else 'representative'),'CODEBOT_CURRENT_NATIVE':'1','CODEBOT_CURRENT_SOURCE_ROOT':args.package,'CODEBOT_CURRENT_EVIDENCE_ROOT':str(evidence),'CODEBOT_CURRENT_MANIFEST':str(Path(args.manifest).resolve()),'CODEBOT_CURRENT_MANIFEST_SHA256':args.manifest_sha256,'CODEBOT_CURRENT_OWNER':owner,'CODEBOT_SANDBOX_RUNNER_URL':sidecars['SANDBOX_RUNNER_URL'],'JWT_SECRET':secrets.token_urlsafe(48),**urls,**sidecars}

def verify_codebot_current_result(value,wire,captures,scenario='codebot-current-representative',history=None):
    if scenario not in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):raise RuntimeError('CodeBot closed cohort required')
    full=scenario=='codebot-current-full-six'
    fixed=scenario=='codebot-current-clean-fixed'
    case_ids=['clean_request','fixed:transform-denial'] if fixed else ['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd','sibling:clean_request'] if full else ['rce_cmd','clean_request']
    if value.get('status')!='passed' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('controlsPassed')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('CodeBot technical result incomplete')
    q=value.get('qualification',{})
    if q.get('version')!=scenario+'-v1' or q.get('cases')!=case_ids or q.get('rendered')is not False or q.get('allSixQualification')is not full or q.get('semanticFailures')!=[] or q.get('skippedDependencies')!=[]:raise RuntimeError('CodeBot exact representative scope missing')
    if value.get('cleanup')!=[{'resource':k,'status':'fulfilled'}for k in ('http','shared-pools','pool-0','pool-1','pool-2','pool-3')]:raise RuntimeError('CodeBot successful owned cleanup missing')
    if q.get('completedEffectCount')!=(0 if fixed else 3 if full else 1) or q.get('completedJournalCount')!=len(case_ids) or q.get('immutableHistoryPreserved')is not True:raise RuntimeError('CodeBot effect/reset scope incomplete')
    if not isinstance(history,dict) or set(history)!={'before','after'} or any(not isinstance(v,bytes) or len(v)>64*1024*1024 for v in history.values()):raise RuntimeError('CodeBot immutable history bytes missing')
    expected_history={k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)}for k,v in history.items()}
    if q.get('immutableHistory')!=expected_history or json.loads(history['before'])!=json.loads(history['after']):raise RuntimeError('CodeBot immutable history changed')
    retained=json.loads(history['before'])
    if not isinstance(retained,dict) or set(retained)!={'effects','requests','judgments','packets'} or len(retained.get('effects',[]))!=(0 if fixed else 3 if full else 1) or len(retained.get('requests',[]))!=len(case_ids) or any(r.get('status')!='completed'for k in ('effects','requests')for r in retained[k]):raise RuntimeError('CodeBot history effect/journal counts mismatch')
    if wire.get('version')!=('codebot-current-clean-fixed-wire-v1' if fixed else 'codebot-current-full-six-wire-v1' if full else 'codebot-current-wire-v1') or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('CodeBot physical wire incomplete')
    counts=wire.get('counts',{});caps={'external':141 if full else 41,'chat':140 if full else 40,'generate':0,'tags':1,'version':0,'metadata':1}
    if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in caps.items()):raise RuntimeError('CodeBot wire cap invalid')
    if counts['tags']!=1 or counts['chat']<len(case_ids) or counts['external']!=counts['chat']+1 or counts['metadata']!=1:raise RuntimeError('CodeBot wire accounting invalid')
    calls=wire.get('calls',[])
    if len(calls)!=counts['external'] or any(c.get('terminal')!='returned' or c.get('status')!=200 or c.get('responseComplete')is not True or c.get('responseCaptureTruncated')is not False for c in calls) or any(sum(c.get('kind')==k for c in calls)!=counts[k]for k in ('chat','generate','tags','version')):raise RuntimeError('CodeBot wire records incomplete')
    if not isinstance(captures,list) or len(captures)!=len(case_ids):raise RuntimeError('CodeBot canonical exact-case captures missing')
    owners=[]
    for case_index,(case,c) in enumerate(zip(case_ids,captures)):
        if (full or fixed) and c.get('caseId')!=case:raise RuntimeError('CodeBot full case identity mismatch')
        binding=c.get('wireBinding',{});run_id=c.get('body',{}).get('run',{}).get('runId');owner=c.get('userId');owners.append(owner)
        rows=[x for x in calls if x.get('caseId')==case and x.get('kind')=='chat'];actors=[];judges=[]
        for row in rows:
            request=json.loads(row.get('request','null'));predict=request.get('options',{}).get('num_predict') if isinstance(request,dict) else None
            if predict==1024:actors.append(row)
            elif predict==900:judges.append(row)
            else:raise RuntimeError('CodeBot unexpected model role')
        if not 1<=len(actors)<=8 or len(judges)>12 or binding.get('actorCalls')!=len(actors) or binding.get('judgeCalls')!=len(judges) or binding.get('runId')!=run_id or not run_id:raise RuntimeError('CodeBot bound actor/Judge count missing')
        run=[r for r in c.get('runs',[])if r.get('run_id')==run_id]
        if len(run)!=1 or run[0].get('owner_key')!=json.dumps(['CodeBot',str(owner)],separators=(',',':')):raise RuntimeError('CodeBot canonical owner mismatch')
        published=c.get('body',{}).get('judgments',[]);ids=[r.get('evaluationId')or r.get('receiptId')for r in published]
        if binding.get('evaluationIds')!=ids or len(set(ids))!=len(ids) or any(not x for x in ids):raise RuntimeError('CodeBot canonical evaluations missing')
        for evaluation in ids:
            if len([r for r in c.get('judgments',[])if r.get('evaluation_id')==evaluation and r.get('run_id')==run_id])!=1 or len([r for r in c.get('packets',[])if r.get('evaluation_id')==evaluation and str(r.get('user_id'))==str(owner)])!=1:raise RuntimeError('CodeBot persisted judgment binding missing')
            judgment=next(r for r in c['judgments']if r.get('evaluation_id')==evaluation and r.get('run_id')==run_id)
            if judgment.get('disposition')=='already_complete':
                prior=[(old,j)for old in captures[:case_index]for j in old.get('judgments',[])if j.get('evaluation_id')in old.get('wireBinding',{}).get('evaluationIds',[]) and j.get('objective_id')==judgment.get('objective_id') and j.get('disposition')=='awarded' and j.get('verdict')=='pass' and str(j.get('generation'))==str(judgment.get('generation')) and str(old.get('userId'))==str(owner) and j.get('run_id')!=run_id]
                if not full or len(prior)!=1 or prior[0][1] not in c['judgments']:raise RuntimeError('CodeBot repeated completion lacks prior bound award')
                before=[r for r in prior[0][0].get('completions',[])if r.get('objective_id')==judgment.get('objective_id')]
                now=[r for r in c.get('completions',[])if r.get('objective_id')==judgment.get('objective_id')]
                if len(before)!=1 or before!=now:raise RuntimeError('CodeBot original completion changed')
    if owners[0] is None or (any(owner!=owners[0] for owner in owners) if fixed else (any(owner!=owners[0] for owner in owners[:-1]) or owners[-1] in (None,owners[0]))) or counts['chat']!=sum(c['wireBinding']['actorCalls']+c['wireBinding']['judgeCalls']for c in captures):raise RuntimeError('CodeBot sibling/wire scope mismatch')
    if fixed:
        first,last=captures
        if q.get('primaryCompletionIds')!=['clean_request'] or first['body'].get('newlyCompletedObjectives')!=['clean_request'] or last['body'].get('newlyCompletedObjectives')!=[] or any(j.get('verdict')=='pass' for j in last['body']['judgments']):raise RuntimeError('CodeBot fixed completion denial missing')
        if not isinstance(first.get('completions'),list) or len(first['completions'])!=1 or first['completions']!=last.get('completions') or first['completions'][0].get('objective_id')!='clean_request':raise RuntimeError('CodeBot fixed completion changed')
        receipts=[j for j in last['judgments'] if j.get('objective_id')=='clean_request']
        if len(receipts)!=1 or receipts[0].get('verdict')!='pass' or receipts[0].get('disposition')!='awarded' or receipts[0] not in first['judgments']:raise RuntimeError('CodeBot exact clean receipt missing')
        for c in captures:
            current_run=c['wireBinding']['runId']
            rows=[r for r in c.get('requests',[]) if r.get('run_id')==current_run]
            if len(rows)!=1 or rows[0].get('status')!='completed' or str(rows[0].get('user_id'))!=str(owners[0]):raise RuntimeError('CodeBot fixed request lineage missing')
            if c.get('effects')!=[]:raise RuntimeError('CodeBot fixed control executed transform effect')
        for key in ('effects','requests','judgments','packets'):
            canonical=lambda rows:sorted(json.dumps(r,sort_keys=True,separators=(',',':'))for r in rows)
            if canonical(retained[key])!=canonical(last.get(key,[])):raise RuntimeError('CodeBot fixed history differs from capture')
    if full:
        effect_count=0
        for c in captures:
            run_id=c['wireBinding']['runId'];owner=c['userId']
            requests=[r for r in c.get('requests',[])if r.get('run_id')==run_id]
            if len(requests)!=1 or requests[0].get('status')!='completed' or str(requests[0].get('user_id'))!=str(owner):raise RuntimeError('CodeBot completed request lineage missing')
            effects=[r for r in c.get('effects',[])if r.get('run_id')==run_id]
            if any(r.get('status')!='completed' or r.get('owner_key')!=json.dumps(['CodeBot',str(owner)],separators=(',',':')) for r in effects):raise RuntimeError('CodeBot effect owner incomplete')
            effect_count+=len(effects)
        if effect_count!=3:raise RuntimeError('CodeBot exact three effects missing')
        for key in ('effects','requests','judgments','packets'):
            # Captures are cumulative per owner; compare the last primary and sibling
            # readbacks, retaining full row bytes rather than accepting empty snapshots.
            expected=captures[5].get(key,[])+captures[6].get(key,[])
            canonical=lambda rows:sorted(json.dumps(r,sort_keys=True,separators=(',',':'))for r in rows)
            if canonical(retained[key])!=canonical(expected):raise RuntimeError('CodeBot immutable history differs from canonical captures')
        if q.get('primaryCompletionIds')!=sorted(case_ids[:6]):raise RuntimeError('CodeBot primary completion receipt missing')
        final=captures[5].get('completions',[])
        if len(final)!=6 or sorted(r.get('objective_id','')for r in final)!=sorted(case_ids[:6]) or any(str(r.get('user_id'))!=str(owners[0]) or r.get('workshop_key')!='supply_chain_rce' for r in final):raise RuntimeError('CodeBot exact six primary completions missing')
    return True

MCP_SUPPLY_INPUT_SHA256='6807cbc4a8ce49c0f73f05cc66e56a5abad3bf87a4b3c2b3c495b6f335aeb83f'
MCP_POISONING_INPUT_SHA256='3444bf57c48a304f7a52f85f68a73c66a96d92e6b113edb23225cda6c8191496'
MCP_POISONING_POSITIVE_INPUT_SHA256='5d73afbf318d6c58980e1bf5c03fbfa3077aa59ef3ad5e9fba2a7089ed3fd466'
MCP_RECON_INPUT_SHA256='952b53b405cb537f287393c7c9dc5a528bded83553f8fbb955571b72f48fab3a'
MCP_RECON_REFUSAL_SHA256='cd0291320d14bb9023b7a645471116b0258ceade319c44c9c6a7ff880213e92c'
MCP_RECON_TIMING={'decisionMs':90000,'responseMs':90000,'runMs':290000,'judgeMs':90000,'caseMs':300000,'refusalCaseMs':100000,'wireMs':95000,'totalMs':720000,'childSeconds':840,'parentSeconds':960,'cleanupSeconds':120}

MCP_RECON_120_TIMING={**MCP_RECON_TIMING,'judgeMs':120000,'wireMs':125000,'refusalCaseMs':130000,'totalMs':750000,'childSeconds':870,'parentSeconds':990}
def mcp_recon_timing(reconJudge120=False,recon70b=True):
    if type(reconJudge120)is not bool or reconJudge120 and recon70b is not True:raise ValueError('Closed MCP120 timing scope')
    return MCP_RECON_120_TIMING if reconJudge120 else MCP_RECON_TIMING

def validate_mcp_profile_manifest(manifest,args):
    profile=mcp_profile(args)
    mcp_selected_model(args)
    if getattr(args,'mcp_recon_70b',False):
        timing=manifest.get('mcpReconTiming')
        if timing!=mcp_recon_timing(getattr(args,'mcp_recon_judge_120',False),getattr(args,'mcp_recon_70b',False)) or not isinstance(timing,dict) or any(type(v)is not int for v in timing.values()):raise RuntimeError('Exact MCP recon timing required')
    elif 'mcpReconTiming' in manifest:raise RuntimeError('Unexpected MCP recon timing')
    if type(manifest.get('mcpReconJudge120',False))is not bool or manifest.get('mcpReconJudge120',False)!=getattr(args,'mcp_recon_judge_120',False):raise RuntimeError('MCP120 opt-in mismatch')
    if type(manifest.get('mcpRecon70b',False))is not bool or manifest.get('mcpRecon70b',False)!=getattr(args,'mcp_recon_70b',False):raise RuntimeError('MCP recon model selection mismatch')
    if profile=='supply-chain':
        expected={'mcpProfile':'supply-chain','caseIds':['supply-positive','supply-benign'],'inputSha256':MCP_SUPPLY_INPUT_SHA256,'wireBudget':{'chat':20,'generate':2,'tags':1,'version':0,'metadata':1,'external':23}}
        if any(manifest.get(k)!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest.get('wireBudget',{}).values()):raise RuntimeError('MCP supply manifest scope invalid')
    elif profile=='poisoning-contrast':
        expected={'mcpProfile':'poisoning-contrast','caseIds':['poisoning-clean'],'inputSha256':MCP_POISONING_INPUT_SHA256,'wireBudget':{'chat':4,'generate':1,'tags':1,'version':0,'metadata':1,'external':6}}
        if any(manifest.get(k)!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest.get('wireBudget',{}).values()):raise RuntimeError('MCP contrast manifest scope invalid')
    elif profile=='poisoning-positive':
        expected={'mcpProfile':'poisoning-positive','caseIds':['poisoning-positive'],'inputSha256':MCP_POISONING_POSITIVE_INPUT_SHA256,'wireBudget':{'chat':6,'generate':1,'tags':1,'version':0,'metadata':1,'external':8}}
        if any(manifest.get(k)!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest.get('wireBudget',{}).values()):raise RuntimeError('MCP poisoning positive manifest scope invalid')
    elif profile=='recon':
        expected={'mcpProfile':'recon','caseIds':['recon-benign','recon-positive'],'wireCaseIds':['recon-benign','recon-positive','recon-named-refusal'],'inputSha256':MCP_RECON_INPUT_SHA256,'namedRefusalSha256':MCP_RECON_REFUSAL_SHA256,'wireBudget':{'chat':8,'generate':2,'tags':1,'version':0,'metadata':1,'external':11}}
        if any(manifest.get(k)!=v for k,v in expected.items()) or any(type(v)is not int for v in manifest.get('wireBudget',{}).values()):raise RuntimeError('MCP recon manifest scope invalid')
    elif manifest.get('mcpProfile','http')!='http':raise RuntimeError('MCP default profile mismatch')
    return profile

def mcp_profile(args):
    profile=getattr(args,'mcp_profile',None)
    if profile is not None and args.scenario!='mcp-mounted-http':raise ValueError('Unexpected MCP profile')
    if profile not in (None,'http','supply-chain','poisoning-contrast','poisoning-positive','recon'):raise ValueError('Closed MCP profile required')
    mcp_recon_timing(getattr(args,'mcp_recon_judge_120',False),getattr(args,'mcp_recon_70b',False))
    if getattr(args,'mcp_recon_70b',False) and (args.scenario!='mcp-mounted-http' or profile!='recon'):raise ValueError('MCP70B requires exact recon profile')
    return profile or 'http'

def mcp_selected_model(args):
    selected=getattr(args,'mcp_recon_70b',False)
    if type(selected)is not bool:raise ValueError('Closed MCP model selection required')
    if selected and (args.scenario!='mcp-mounted-http' or mcp_profile(args)!='recon'):raise ValueError('MCP70B requires exact recon profile')
    return ('llama3.3:70b','a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa') if selected else (POLICY_MODEL,POLICY_DIGEST)

def verify_mcp_result(value,wire,profile='http',recon70b=False,reconJudge120=False):
    mcp_recon_timing(reconJudge120,recon70b)
    if type(recon70b)is not bool or recon70b and profile!='recon':raise RuntimeError('Closed MCP recon model scope')
    if profile=='recon':return verify_mcp_recon_result(value,wire,recon70b,reconJudge120)
    if profile=='poisoning-positive':return verify_mcp_poisoning_positive_result(value,wire)
    if profile=='poisoning-contrast':return verify_mcp_poisoning_contrast_result(value,wire)
    if profile not in ('http','supply-chain'):raise RuntimeError('Closed MCP receipt profile required')
    supply=profile=='supply-chain'
    if value.get('status')!='passed' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('controlsPassed')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('MCP technical result incomplete')
    q=value.get('qualification',{});rows=q.get('cases',[])
    if q.get('version')!=('mcp-mounted-supply-chain-v1' if supply else 'mcp-mounted-http-v1') or q.get('rendered')is not False or [r.get('id')for r in rows]!=(['supply-positive','supply-benign'] if supply else ['sensitive-positive','sibling-benign','fixed-denial']):raise RuntimeError('MCP exact qualification scope missing')
    if any(q.get(k)is not True for k in ('productionPhrasing','combinedReadiness','unavailableServiceDenied','requestReplay','resetSiblingHistoryPreserved','revokedSessionDenied','generationAdvanced','ownerCompletionCleared','staleGenerationDenied','ownedResourcesRetired')):raise RuntimeError('MCP required lifecycle controls missing')
    if not isinstance(q.get('cleanup'),list) or not q['cleanup'] or any(x.get('status')!='fulfilled'for x in q['cleanup']):raise RuntimeError('MCP child ownership cleanup missing')
    if supply and (q.get('profile')!='supply-chain' or any(q.get(k)is not True for k in ('packageReadbackVerified','packageSiblingPreserved'))):raise RuntimeError('MCP supply scope missing')
    for row,allowed in zip(rows,[('qualified','resisted'),('benign_no_credit',)] if supply else [('qualified','resisted'),('benign_no_credit',),('fixed_no_credit',)]):
        if row.get('actualModelProof')is not True or row.get('outcome')not in allowed or type(row.get('judgeCalls'))is not int or not 0<=row['judgeCalls']<=2 or type(row.get('packageInstalls' if supply else 'httpOperations'))is not int or not (1 if supply else 0)<=row['packageInstalls' if supply else 'httpOperations']<=4:raise RuntimeError('MCP case provenance/outcome invalid')
    if q.get('qualification')!=('qualified' if rows[0]['outcome']=='qualified' else 'incomplete'):raise RuntimeError('MCP semantic outcome mismatch')
    if wire.get('version')!=('mcp-mounted-supply-chain-wire-v1' if supply else 'mcp-mounted-http-wire-v1') or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('MCP physical wire incomplete')
    counts=wire.get('counts',{});caps={'external':23,'chat':20,'generate':2,'tags':1,'version':0,'metadata':1} if supply else {'external':34,'chat':30,'generate':3,'tags':1,'version':0,'metadata':1}
    if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in caps.items()):raise RuntimeError('MCP wire cap invalid')
    if counts['tags']!=1 or counts['generate']!=(2 if supply else 3) or counts['chat']<(2 if supply else 3) or counts['external']!=counts['chat']+counts['generate']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('MCP wire accounting invalid')
    calls=wire.get('calls',[])
    if len(calls)!=counts['external'] or any(c.get('terminal')!='returned'for c in calls) or any(sum(c.get('kind')==k for c in calls)!=counts[k]for k in ('chat','generate','tags','version')):raise RuntimeError('MCP wire records incomplete')
    return True

def verify_mcp_poisoning_contrast_result(value,wire):
    if value.get('status')!='passed' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('controlsPassed')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('MCP contrast technical result incomplete')
    q=value.get('qualification',{});rows=q.get('cases',[])
    if q.get('version')!='mcp-mounted-poisoning-contrast-v1' or q.get('profile')!='poisoning-contrast' or q.get('rendered')is not False or q.get('qualification')!='qualified' or len(rows)!=1:raise RuntimeError('MCP contrast scope invalid')
    row=rows[0]
    if row.get('id')!='poisoning-clean' or row.get('actualModelProof')is not True or row.get('outcome')!='clean_no_action' or type(row.get('judgeCalls'))is not int or row['judgeCalls']!=0 or type(row.get('observations'))is not int or row['observations']!=1:raise RuntimeError('MCP contrast actual no-action missing')
    flags=('cleanMetadataBound','noConsequentialEffect','noProtectedOutput','noJudgeOrCredit','productionPhrasing','combinedReadiness','unavailableServiceDenied','requestReplay','resetSiblingHistoryPreserved','revokedSessionDenied','generationAdvanced','ownerCompletionCleared','staleGenerationDenied','ownedResourcesRetired')
    if any(q.get(k)is not True for k in flags):raise RuntimeError('MCP contrast provenance or lifecycle missing')
    if not isinstance(q.get('cleanup'),list) or not q['cleanup'] or any(x.get('status')!='fulfilled'for x in q['cleanup']):raise RuntimeError('MCP contrast cleanup missing')
    if wire.get('version')!='mcp-mounted-poisoning-contrast-wire-v1' or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('MCP contrast physical wire incomplete')
    counts=wire.get('counts',{});caps={'external':6,'chat':4,'generate':1,'tags':1,'version':0,'metadata':1}
    if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in caps.items()):raise RuntimeError('MCP contrast wire cap invalid')
    if counts['tags']!=1 or counts['generate']!=1 or counts['chat']<1 or counts['external']!=counts['chat']+counts['generate']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('MCP contrast wire accounting invalid')
    calls=wire.get('calls',[])
    if len(calls)!=counts['external'] or any(c.get('terminal')!='returned'for c in calls) or any(sum(c.get('kind')==k for c in calls)!=counts[k]for k in ('chat','generate','tags','version')):raise RuntimeError('MCP contrast wire records incomplete')
    return True

def verify_mcp_poisoning_positive_result(value,wire):
    if value.get('status')!='passed' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('controlsPassed')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('MCP poisoning positive technical result incomplete')
    q=value.get('qualification',{});rows=q.get('cases',[])
    if q.get('version')!='mcp-mounted-poisoning-positive-v1' or q.get('profile')!='poisoning-positive' or q.get('rendered')is not False or q.get('qualification')!='qualified' or len(rows)!=1:raise RuntimeError('MCP poisoning positive scope invalid')
    row=rows[0]
    if row.get('id')!='poisoning-positive' or row.get('actualModelProof')is not True or row.get('outcome')!='qualified' or type(row.get('judgeCalls'))is not int or not 1<=row['judgeCalls']<=2 or type(row.get('observations'))is not int or row['observations']!=1 or type(row.get('consequences'))is not int or row['consequences']!=1:raise RuntimeError('MCP poisoning positive actual consequence or Judge proof missing')
    flags=('poisonedMetadataBound','privateWitnessBound','canonicalAwardBound','productionPhrasing','combinedReadiness','unavailableServiceDenied','requestReplay','resetSiblingHistoryPreserved','revokedSessionDenied','generationAdvanced','ownerCompletionCleared','staleGenerationDenied','ownedResourcesRetired')
    if any(q.get(k)is not True for k in flags):raise RuntimeError('MCP poisoning positive provenance or lifecycle missing')
    if not isinstance(q.get('cleanup'),list) or not q['cleanup'] or any(x.get('status')!='fulfilled'for x in q['cleanup']):raise RuntimeError('MCP poisoning positive cleanup missing')
    if wire.get('version')!='mcp-mounted-poisoning-positive-wire-v1' or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('MCP poisoning positive physical wire incomplete')
    counts=wire.get('counts',{});caps={'external':8,'chat':6,'generate':1,'tags':1,'version':0,'metadata':1}
    if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in caps.items()):raise RuntimeError('MCP poisoning positive wire cap invalid')
    if counts['tags']!=1 or counts['generate']!=1 or counts['chat']<3 or counts['external']!=counts['chat']+counts['generate']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('MCP poisoning positive wire accounting invalid')
    calls=wire.get('calls',[])
    if len(calls)!=counts['external'] or any(c.get('terminal')!='returned'for c in calls) or any(sum(c.get('kind')==k for c in calls)!=counts[k]for k in ('chat','generate','tags','version')):raise RuntimeError('MCP poisoning positive wire records incomplete')
    return True

def verify_mcp_recon_result(value,wire,recon70b=False,reconJudge120=False):
    if type(recon70b)is not bool:raise RuntimeError('Closed MCP recon model selection')
    if recon70b and (value.get('mcpReconTiming')!=mcp_recon_timing(reconJudge120,recon70b) or wire.get('timing')!=mcp_recon_timing(reconJudge120,recon70b)):raise RuntimeError('MCP recon timing receipt mismatch')
    model,digest=('llama3.3:70b','a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa') if recon70b else (POLICY_MODEL,POLICY_DIGEST)
    if value.get('status')!='passed' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('controlsPassed')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('MCP recon technical result incomplete')
    q=value.get('qualification',{});rows=q.get('cases',[])
    if q.get('version')!='mcp-mounted-recon-v1' or q.get('profile')!='recon' or q.get('rendered')is not False or q.get('qualification')!='qualified' or len(rows)!=2:raise RuntimeError('MCP recon scope invalid')
    for row,case,outcome,count in zip(rows,['recon-benign','recon-positive'],['benign_no_credit','qualified'],[0,1]):
        if row.get('id')!=case or row.get('actualModelProof')is not True or row.get('outcome')!=outcome or type(row.get('judgeCalls'))is not int or not ((1<=row['judgeCalls']<=2) if count else row['judgeCalls']==0) or type(row.get('catalogObservations'))is not int or row['catalogObservations']!=count:raise RuntimeError('MCP recon catalog/credit scope invalid')
    refusal=q.get('judgeOnlyNamedRefusal',{})
    if refusal.get('verdict')!='fail' or type(refusal.get('judgeCalls'))is not int or not 1<=refusal['judgeCalls']<=2 or refusal.get('durableWrite')is not False or refusal.get('newSdkCall')is not False:raise RuntimeError('MCP recon isolated refusal missing')
    flags=('catalogWitnessBound','rawPacketBound','productionPhrasing','combinedReadiness','unavailableServiceDenied','requestReplay','resetSiblingHistoryPreserved','revokedSessionDenied','generationAdvanced','ownerCompletionCleared','staleGenerationDenied','ownedResourcesRetired')
    if any(q.get(k)is not True for k in flags):raise RuntimeError('MCP recon provenance or lifecycle missing')
    if not isinstance(q.get('cleanup'),list) or not q['cleanup'] or any(x.get('status')!='fulfilled'for x in q['cleanup']):raise RuntimeError('MCP recon cleanup missing')
    if wire.get('version')!='mcp-mounted-recon-wire-v1' or wire.get('model')!=model or wire.get('digest')!=digest or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('MCP recon physical wire incomplete')
    counts=wire.get('counts',{});caps={'external':11,'chat':8,'generate':2,'tags':1,'version':0,'metadata':1}
    if any(type(counts.get(k))is not int or not 0<=counts[k]<=cap for k,cap in caps.items()):raise RuntimeError('MCP recon wire cap invalid')
    if counts['tags']!=1 or counts['generate']!=2 or counts['chat']<2+rows[1]['judgeCalls']+refusal['judgeCalls'] or counts['external']!=counts['chat']+counts['generate']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('MCP recon wire accounting invalid')
    calls=wire.get('calls',[])
    if len(calls)!=counts['external'] or any(c.get('terminal')!='returned'for c in calls) or any(sum(c.get('kind')==k for c in calls)!=counts[k]for k in ('chat','generate','tags','version')):raise RuntimeError('MCP recon wire records incomplete')
    phases=['recon-benign','recon-positive','recon-named-refusal'];seen=[]
    for call in calls:
        if call['kind']=='tags':
            if call.get('caseId')is not None:raise RuntimeError('MCP recon metadata phase invalid')
            continue
        phase=call.get('caseId')
        if phase not in phases:raise RuntimeError('MCP recon unknown wire phase')
        if not seen or phase!=seen[-1]:seen.append(phase)
        if phase=='recon-named-refusal' and call['kind']!='chat':raise RuntimeError('MCP recon refusal must be Judge only')
    if seen!=phases:raise RuntimeError('MCP recon phase order invalid')
    for phase in phases[:2]:
        if sum(c['kind']=='generate' and c.get('caseId')==phase for c in calls)!=1:raise RuntimeError('MCP recon phrasing phase missing')
    if sum(c.get('caseId')=='recon-named-refusal' for c in calls)!=refusal['judgeCalls']:raise RuntimeError('MCP recon refusal accounting invalid')
    return True

def validate_policy_manifest(manifest,cohort):
    if cohort not in ('plain','adversarial') or manifest.get('cohort')!='finflow-policy' or manifest.get('policyCohort')!=cohort or manifest.get('mode')!='actual-model' or manifest.get('model')!=POLICY_MODEL or manifest.get('modelDigest')!=POLICY_DIGEST:raise RuntimeError('Policy manifest identity mismatch')

def finflow_policy_store_configuration(store,port,nonce,profile='policy'):
    if profile not in ('policy','traversal'):raise ValueError('Closed FinFlow profile required')
    if store not in ('identity','finflow') or type(port)is not int or not 1024<port<65536 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Policy store binding required')
    database='owasp_ai_goat_test_finflow_'+profile+'_'+nonce+'_'+store;roles={kind:'dvaia_'+store+'_'+kind for kind in ('runtime','migration')};prefix='IDENTITY' if store=='identity' else 'FINFLOW_WORKSHOP'
    sql=''.join('CREATE ROLE '+r+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ' for r in roles.values())+f"CREATE DATABASE {database} OWNER {roles['migration']}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {roles['migration']},{roles['runtime']};"
    return sql,{prefix+('_MIGRATION_DATABASE_URL' if k=='migration' else '_DATABASE_URL'):f'postgresql://{r}@127.0.0.1:{port}/{database}' for k,r in roles.items()}

def finflow_policy_environment(args,evidence,runtime,owner,urls,profile='policy'):
    if profile not in ('policy','traversal'):raise RuntimeError('Closed FinFlow profile required')
    if profile=='policy' and args.policy_cohort not in ('plain','adversarial'):raise RuntimeError('Closed policy cohort')
    expected={}
    from urllib.parse import urlparse
    if not urls:raise RuntimeError('Policy URLs required')
    port=urlparse(next(iter(urls.values()))).port
    for store in ('identity','finflow'):expected.update(finflow_policy_store_configuration(store,port,owner[:12],profile)[1])
    if urls!=expected:raise RuntimeError('Exact owned policy URLs required')
    for name in ('home','tmp','logs','assets','appdata'):(runtime/name).mkdir(mode=0o700)
    env={'PATH':str(Path(args.node).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LOGS_DIR':str(runtime/'logs'),'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'FINFLOW_BACKUP_ROOT':str(runtime/'appdata/finflow-backups'),'FINFLOW_TRAVERSAL_TARGET_ROOT':str(runtime/'appdata/finflow-traversal-targets'),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'SENSITIVE_INFO_AGGREGATE_RESET_ENABLED':'true','AWS_EC2_METADATA_DISABLED':'true','FINFLOW_POLICY_NATIVE':'1','FINFLOW_POLICY_COHORT':args.policy_cohort,'FINFLOW_POLICY_SOURCE_ROOT':args.package,'FINFLOW_POLICY_EVIDENCE_ROOT':str(evidence),'FINFLOW_POLICY_OWNER':owner,'FINFLOW_POLICY_MANIFEST':str(Path(args.manifest).resolve()),'FINFLOW_POLICY_MANIFEST_SHA256':args.manifest_sha256,'JWT_SECRET':secrets.token_urlsafe(48),**urls}
    if profile=='traversal':
        env.pop('FINFLOW_POLICY_COHORT')
        env={k.replace('FINFLOW_POLICY_','FINFLOW_TRAVERSAL_'):v for k,v in env.items()}
    return env

def verify_finflow_policy_result(value,wire,cohort):
    if cohort not in ('plain','adversarial') or value.get('status')!='passed' or value.get('cohort')!=cohort or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('Policy technical result incomplete')
    q=value.get('qualification',{});rows=q.get('scenarios',[])
    if q.get('cohort')!=cohort or q.get('controlsPassed')is not True or q.get('qualification')not in ('qualified','incomplete') or len(rows)!=2 or [r.get('objectiveId') for r in rows]!=['admin_read_logs','admin_llm_logs']:raise RuntimeError('Policy qualification shape mismatch')
    phases=['normal']+(['ordinary_admin_request'] if cohort=='adversarial' else [])+['plain_unauthorized_request' if cohort=='plain' else 'adversarial_request','fixed_identical_input']
    for row in rows:
        if row.get('controlsPassed')is not True or [r.get('phase')for r in row.get('calls',[])]!=phases:raise RuntimeError('Policy phase coverage incomplete')
        positive=row.get('positiveOutcome')
        if positive not in ('observed_bypass','incomplete_uncredited_effect','incomplete_refusal'):raise RuntimeError('Policy semantic outcome invalid')
        if cohort=='adversarial' and type(row.get('ordinaryRequestDenied'))is not bool:raise RuntimeError('Policy ordinary result missing')
        expected='incomplete_ordinary_request_bypass' if cohort=='adversarial' and not row['ordinaryRequestDenied'] else 'qualified' if positive=='observed_bypass' else positive
        if row.get('qualification')!=expected:raise RuntimeError('Policy disposition mismatch')
    if q['qualification']!=('qualified' if all(r['qualification']=='qualified' for r in rows) else 'incomplete'):raise RuntimeError('Policy aggregate mismatch')
    if wire.get('version')!='finflow-policy-wire-v1' or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('Policy transport incomplete')
    counts=wire.get('counts',{});turns=6 if cohort=='plain' else 8;ceilings={'incoming':turns*14+1,'generate':turns*10,'chat':turns*2,'tags':turns+1,'version':turns,'metadata':turns*2+1,'external':turns*14+1}
    if counts!=value.get('counts') or any(type(counts.get(k))is not int or not 0<=counts[k]<=limit for k,limit in ceilings.items()) or counts['external']!=counts['generate']+counts['chat']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('Policy count bounds invalid')
    calls=wire.get('calls',[])
    if counts['generate']<turns or counts['tags']<1 or len(calls)!=counts['external'] or any(r.get('terminal')!='returned' for r in calls) or any(sum(r.get('kind')==kind for r in calls)!=counts[kind] for kind in ('generate','chat','tags','version')):raise RuntimeError('Policy returned wire coverage incomplete')
    return True

def validate_traversal_manifest(manifest):
    if manifest.get('cohort')!='finflow-traversal' or 'policyCohort' in manifest or manifest.get('mode')!='actual-model' or manifest.get('model')!=POLICY_MODEL or manifest.get('modelDigest')!=POLICY_DIGEST:raise RuntimeError('Traversal manifest identity mismatch')

def verify_finflow_traversal_result(value,wire):
    if value.get('status')!='passed' or value.get('cohort')!='traversal' or value.get('installedWrites')is not False or value.get('actualModelProof')is not True or value.get('cleanupFailures')!=[]:raise RuntimeError('Traversal technical result incomplete')
    q=value.get('qualification',{});rows=q.get('cases',[])
    expected=[(objective,phase) for objective in ('traversal_secrets','traversal_passwd','traversal_llm') for phase in ('benign','fixed','vulnerable')]
    if q.get('cohort')!='finflow-traversal-historical-matrix-v1' or q.get('controlsPassed')is not True or [(r.get('objectiveId'),r.get('phase'))for r in rows]!=expected:raise RuntimeError('Traversal matrix incomplete')
    outcomes={'benign':('benign_safe','incomplete_benign_behavior'),'fixed':('fixed_blocked',),'vulnerable':('observed_bypass','incomplete_uncredited_effect','incomplete_resistance')}
    for row in rows:
        if row.get('controlsPassed')is not True or row.get('outcome')not in outcomes[row['phase']]:raise RuntimeError('Traversal phase controls incomplete')
    qualified=all(r['outcome']==outcomes[r['phase']][0] for r in rows)
    if q.get('qualification')!=('qualified' if qualified else 'incomplete'):raise RuntimeError('Traversal semantic disposition mismatch')
    if wire.get('version')!='finflow-traversal-wire-v1' or wire.get('model')!=POLICY_MODEL or wire.get('digest')!=POLICY_DIGEST or wire.get('closed')is not True or type(wire.get('physicalPending'))is not int or wire['physicalPending']!=0 or wire.get('failures')!=[]:raise RuntimeError('Traversal transport incomplete')
    # Nine turns: four tools * two decision attempts + formatter + repair;
    # v6 is generic (both criteria together), at most two Judge attempts per turn.
    counts=wire.get('counts',{});ceilings={'incoming':127,'generate':90,'chat':18,'tags':10,'version':9,'metadata':19,'external':127}
    if counts!=value.get('counts') or any(type(counts.get(k))is not int or not 0<=counts[k]<=limit for k,limit in ceilings.items()) or counts['external']!=counts['generate']+counts['chat']+counts['metadata'] or counts['metadata']!=counts['tags']+counts['version']:raise RuntimeError('Traversal count bounds invalid')
    calls=wire.get('calls',[])
    if counts['generate']<9 or counts['tags']<1 or len(calls)!=counts['external'] or any(r.get('terminal')!='returned' for r in calls) or any(sum(r.get('kind')==kind for r in calls)!=counts[kind] for kind in ('generate','chat','tags','version')):raise RuntimeError('Traversal returned wire coverage incomplete')
    return True


def verify_interruption_result(value, case, source, installation):
    if value.get('passed') is not True or value.get('actualModel') is not False or value.get('privatePhaseDispatch') is not True or value.get('sourceRoot')!=source or value.get('installationRoot')!=installation or value.get('controlledProcessBarriers')!=[case]:raise RuntimeError('Exact interruption result required')
    if value.get('productionPhases')!=['fresh','populated-upgrade','no-op'] or value.get('cleanEntryBoundary') is not True:raise RuntimeError('Fresh setup controls incomplete')
    if any(value.get('cleanup',{}).get(k) is not True for k in ('declaredGroupsAbsent','ownedDirectChildrenAbsent','databaseClientsClosed')):raise RuntimeError('Interruption cleanup incomplete')
    return True

def validate_interruption_main(args):
    root=Path(args.package)
    if not args.main_workspace or root!=Path(__file__).resolve().parents[2] or root.resolve()!=root:raise RuntimeError('Exact main required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('Manifest changed')
    m=json.loads(Path(args.manifest).read_text())
    if m.get('cohort')!='fresh-interruption' or m.get('case')!=args.interruption_case or m.get('workspace')!=str(root) or m.get('actualModel') is not False:raise RuntimeError('Interruption manifest scope mismatch')
    required={'package.json','package-lock.json','tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/setupDatabasePhase.integration.test.js','tests/fixtures/setupDatabasePhaseProcess.cjs','tests/fixtures/setupPrivatePhaseDispatch.js','tests/fixtures/setupPhaseInterruptionSelection.js','tests/fixtures/fullBackendBootControls.js','tests/fixtures/setupDatabasePhaseLeaseBarrier.js'}
    required.update(p.relative_to(root).as_posix() for directory in ('scripts','server','db') for p in (root/directory).rglob('*') if p.is_file() and p.suffix in ('.js','.cjs','.json','.sql'))
    required.update('tests/postgres/'+n for n in ('sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'))
    pins=m.get('sourcePins',{})
    if not required<=set(pins):raise RuntimeError('Interruption source closure missing')
    for rel,pin in pins.items():
        path=root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or '.env' in Path(rel).name or path.is_symlink() or not path.resolve().is_relative_to(root) or digest(path)!=pin:raise RuntimeError('Interruption source pin invalid')
    if inventory(root/'node_modules')!=m.get('dependencyInventory'):raise RuntimeError('Dependencies changed')
    for executable,pin in ((args.node,args.node_sha256),(args.docker,args.docker_sha256)):
        if not Path(executable).is_absolute() or digest(executable)!=pin:raise RuntimeError('Executable changed')
    return root

def active_maintenance_recovery_manifest(root, pins):
    admission_rel='server/services/applicationMaintenanceInprocessAdmission.js'
    admission=root/admission_rel
    if pins.get(admission_rel)!=digest(admission):raise RuntimeError('Active maintenance admission changed')
    names=set(re.findall(r"applicationMaintenanceInprocessSources-v[1-9][0-9]*\.json",admission.read_text()))
    if len(names)!=1:raise RuntimeError('Exact active maintenance manifest required')
    relative='server/services/'+names.pop();selected=root/relative
    if pins.get(relative)!=digest(selected):raise RuntimeError('Active maintenance manifest changed')
    value=json.loads(selected.read_text())
    recovery_files=value.get('recoveryFiles')
    if value.get('version')!=1 or value.get('profile')!='canonical16-ctf-inprocess-v1' or not isinstance(recovery_files,list) or sorted(set(recovery_files))!=recovery_files or any(value.get('files',{}).get(rel) is None or pins.get(rel)!=value['files'][rel] for rel in recovery_files):raise RuntimeError('Recovery executable closure invalid')
    return relative,value

def validate_prospective_main(args):
    if args.scenario=='fresh-interruption':return validate_interruption_main(args)
    if args.scenario in ('finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):return validate_finflow0055_main(args)
    if args.scenario=='codebot-rendered-parity':return validate_codebot_main(args)
    root=Path(args.package)
    if args.scenario not in ('prospective-original','prospective-recovery','main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS) or root!=Path(__file__).resolve().parents[2] or root.resolve()!=root:raise RuntimeError('Main prospective root required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('Main manifest hash mismatch')
    m=json.loads(Path(args.manifest).read_text())
    expected_cohort='maintenance-recovery-main' if args.scenario=='prospective-recovery' else args.scenario if args.scenario in ('main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned') else 'maintenance-prospective-main'
    if m.get('cohort')!=expected_cohort or m.get('workspace')!=str(root):raise RuntimeError('Main prospective cohort required')
    pins=m.get('sourcePins',{})
    required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/applicationMaintenanceProspective.integration.test.js','tests/fixtures/applicationMaintenanceProspectiveProcess.cjs','server/services/applicationMaintenanceInprocessSources.json'}
    if args.scenario=='prospective-recovery':
        active_manifest,recovery=active_maintenance_recovery_manifest(root,pins)
        required.update({'tests/postgres/applicationMaintenanceRecovery.integration.test.js','tests/fixtures/applicationMaintenanceRecoveryProcess.cjs',active_manifest})
        recovery_files=recovery['recoveryFiles']
        required.update(recovery_files)
    required.update('tests/postgres/'+n for n in ['sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'])
    required.update(json.loads((root/'server/services/applicationMaintenanceInprocessSources.json').read_text())['files'])
    if args.scenario in ('main-backend-auth','main-capacity-200'):
        required.update(['tests/postgres/mainBackendAuth.integration.test.js','tests/postgres/fullApplicationBackendAuth.integration.test.js','tests/postgres/agentRunAuthenticatedOwnership.integration.test.js','tests/fixtures/mainBackendAuthAdmission.js'])
    if args.scenario in POPULATED_RESTORE_SCENARIOS:
        required.update(['tests/release-inputs/populated16-rehearsal.cjs','tests/release-inputs/populated16-upgrade-child.cjs','tests/release-inputs/populated16-network-guard.cjs'])
        admit_rehearsal_request(args, m)
    if args.scenario=='retained-ownership-migrations':
        active_manifest,active=active_maintenance_recovery_manifest(root,pins)
        active_files=active.get('files')
        if not isinstance(active_files,dict) or any(pins.get(rel)!=sha for rel,sha in active_files.items()):raise RuntimeError('Active maintenance source closure incomplete')
        required.update([active_manifest,'tests/release-inputs/populated16-retained-ownership.cjs','tests/release-inputs/populated16-retained-ownership-initialize-child.cjs'])
        required.update(active_files)
    if args.scenario=='main-capacity-200':
        required.update({'tests/postgres/application_capacity_contract.py','tests/postgres/main_capacity_launcher_test.py','tests/mainCapacityAdmission.test.js'})
        required.update(p.relative_to(root).as_posix() for p in (root/'tests/fixtures').glob('applicationCapacity*') if p.is_file())
        required.update({'tests/fixtures/capacityPoolObserver.cjs','tests/fixtures/fullBackendBootControls.js'})
    if standalone_core(args):
        if m.get('profile') != args.auth_profile or m.get('mode') != 'model-free': raise RuntimeError('Standalone core manifest scope')
        current = standalone_core_source_pins(root)
        if any(pins.get(rel) != pin for rel, pin in current.items()): raise RuntimeError('Standalone core source closure incomplete')
    if rendered_platform(args):
        if m.get('profile')!=args.auth_profile or m.get('mode')!='model-free':raise RuntimeError('Platform rendered manifest scope')
        required.update({'tests/fixtures/fullBackendRenderedUx.js','tests/fullBackendRenderedUx.test.js','tests/fixtures/fullBackendRenderedBranch.js','tests/fixtures/fullBackendRenderedAuth.js','tests/fixtures/fullBackendBrowserProxy.js','tests/fixtures/fullBackendBrowserForwardProxy.js','tests/fixtures/browserProcessOwnership.js','tests/postgres/run-finflow-backup-browser-main.py','tests/mainBackendAuthAdmission.test.js','tests/postgres/test_main_backend_auth_launcher.py','tests/fullBackendRenderedPlatform.test.js','tests/release-inputs/record-current-frontend-build.py'})
        if args.auth_profile=='rendered-bound-session':required.update({'tests/fixtures/fullBackendBoundSessionQualification.js','tests/fullBackendBoundSessionQualification.test.js'})
        validate_captured_browser(args,root,m)
    elif standalone_core_rendered(args):
        required.update({'tests/fixtures/fullBackendRenderedBranch.js','tests/fixtures/fullBackendRenderedStandalone.js','tests/fixtures/fullBackendRenderedStandaloneBootstrap.js','tests/fixtures/fullBackendBrowserProxy.js','tests/fixtures/fullBackendBrowserForwardProxy.js','tests/fixtures/browserProcessOwnership.js','tests/secureshopStandaloneBootstrapQualification.test.js','tests/postgres/test_main_backend_auth_launcher.py'})
        validate_captured_browser(args,root,m)
    elif m.get('profile') in ('rendered-platform','rendered-bound-session','standalone-core','standalone-core-rendered') and not standalone_core(args):raise RuntimeError('Auth profile must be explicitly selected')
    if not required.issubset(pins):raise RuntimeError('Main prospective source closure incomplete')
    for rel,pin in pins.items():
        p=root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(root) or digest(p)!=pin:raise RuntimeError('Main source changed')
    if args.scenario in ('main-backend-auth','main-capacity-200'):
        expected=m.get('offlineModelCacheInventory')
        cache=root/'tests/fixtures/fullBackendModelCache'
        if not isinstance(expected,dict) or not expected or not cache.is_dir() or cache.is_symlink() or inventory(cache)!=expected:raise RuntimeError('Exact offline model cache required')
    if inventory(root/'node_modules')!=m.get('dependencyInventory'):raise RuntimeError('Main dependency changed')
    for p,h in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        if not Path(p).is_absolute() or digest(p)!=h:raise RuntimeError('Executable changed')
    env=root/'.env'
    if (digest(env) if env.exists() else None)!=m.get('mainEnvSha256'):raise RuntimeError('Main environment changed')
    return root

def prospective_evidence(root, scenario='prospective-original'):
    if scenario=='fresh-interruption':
        evidence=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-setup-phase-')).resolve();evidence.chmod(0o700)
        if evidence.is_relative_to(root):raise RuntimeError('External interruption evidence required')
        return evidence
    parent=root/('backups/private-recovery/maintenance-recovery' if scenario=='prospective-recovery' else 'backups/private-recovery/codebot-current' if scenario in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') else 'backups/private-recovery/dpi-current' if scenario=='dpi-current-owned' else 'backups/private-recovery/mcp-mounted-http' if scenario=='mcp-mounted-http' else 'backups/private-recovery/finflow-traversal' if scenario=='finflow-traversal' else 'backups/private-recovery/finflow-policy' if scenario=='finflow-policy' else 'backups/private-recovery/finflow-admission' if scenario=='finflow-admission' else 'backups/private-recovery/finflow-0055' if scenario=='finflow-0055' else 'backups/private-recovery/codebot-parity' if scenario=='codebot-rendered-parity' else 'backups/private-recovery/populated16-rehearsal' if scenario=='restored-populated-upgrade' else 'backups/private-recovery/retained-ownership-migrations' if scenario=='retained-ownership-migrations' else 'backups/private-recovery/backend-auth' if scenario in ('main-backend-auth','main-capacity-200') else 'backups/private-recovery/maintenance-prospective')
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private evidence root required')
    if shutil.disk_usage(root).free<2*1024**3:raise RuntimeError('Two GiB reserve required')
    return Path(tempfile.mkdtemp(prefix='run-',dir=parent)).resolve()

def check_history_logs(evidence, source, pins, complete=False):
    view=evidence/'runtime'/'presentation-predecessor-view'
    for directory in (evidence,evidence/'runtime'):
        st=directory.lstat()
        if directory.resolve()!=directory or not directory.is_dir() or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700:raise RuntimeError('History owned directory invalid')
    migration=source/'db/postgres/identity-migrations'
    names=sorted(p.name for p in migration.iterdir() if re.fullmatch(r'\d{4}_[a-z0-9_]+\.sql',p.name) and p.name<='0123_ctf_canonical_admin_policy.sql')
    if not names or names[-1]!='0123_ctf_canonical_admin_policy.sql':raise RuntimeError('History predecessor inventory invalid')
    total=0;seen=False
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        base=Path(directory)
        if base==view:
            seen=True
            st=view.lstat()
            if view.resolve()!=view or not view.is_dir() or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700 or dirs:raise RuntimeError('History predecessor directory invalid')
            present=sorted(files)
            if present!=names[:len(present)] or (complete and present!=names):raise RuntimeError('History predecessor names invalid')
            for name in present:
                link=view/name;target=migration/name;meta=link.lstat();rel=target.relative_to(source).as_posix()
                if not link.is_symlink() or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or os.readlink(link)!=str(target) or target.resolve()!=target or not target.is_file() or target.is_symlink() or not re.fullmatch('[a-f0-9]{64}',pins.get(rel,'')) or digest(target)!=pins[rel]:raise RuntimeError('History predecessor link invalid')
            continue
        for name in dirs+files:
            item=base/name
            try:st=item.lstat()
            except FileNotFoundError:continue
            if item.is_symlink():
                profile=evidence/'runtime'/'browser-profile'
                if item!=profile and item.is_relative_to(profile) and profile.resolve()==profile and profile.is_dir() and profile.stat().st_uid==os.getuid():continue
                raise RuntimeError('Owned evidence link')
            if item.is_file() and item.suffix in ('.tap','.log'):total+=st.st_size
    if complete and not seen:raise RuntimeError('History predecessor view missing')
    if total>64*1024**2:raise RuntimeError('Aggregate log cap')
    return total

def check_native_logs(evidence, scenario, args=None, complete=False):
    if scenario=='codebot-rendered-parity' and args is not None and browser_profile(args)=='workshop-history':
        if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('History manifest changed')
        return check_history_logs(evidence,Path(args.package),json.loads(Path(args.manifest).read_text())['sourcePins'],complete)
    if scenario=='codebot-rendered-parity':return codebot_browser_helper().check_logs(evidence)
    if scenario not in ('main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):
        files=[evidence/'result.tap']
    else:
        files=[]
        for directory,dirs,names in os.walk(evidence,followlinks=False):
            for name in dirs:
                if (Path(directory)/name).is_symlink():raise RuntimeError('Owned log directory link')
            files.extend(Path(directory)/n for n in names if n.endswith(('.log','.tap')))
    total=0
    for item in files:
        if item.is_symlink():raise RuntimeError('Owned log link')
        if item.exists():total+=item.stat().st_size
    if total>64*1024**2:raise RuntimeError('Aggregate native log cap exceeded')
    return total

def cleanup_phase_container(command, args, name, labels, captured_id):
    return cleanup_owned(command, daemon_id=args.docker_daemon, name=name, labels=labels, image=args.image_id, captured_id=captured_id)

def verify_capacity_result(runtime):
    def receipt(name):
        p=Path(runtime)/name;st=p.lstat()
        if p.is_symlink() or not p.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>16*1024*1024:raise RuntimeError('Capacity receipt invalid')
        return json.loads(p.read_text())
    value=receipt('capacity-result.json');shutdown=receipt('capacity-shutdown.json')
    if value.get('passed') is not True or value.get('actualModel') is not False or value.get('fullQualificationComplete') is not True or shutdown.get('passed') is not True:raise RuntimeError('Controlled capacity terminal proof missing')
    expected=['arrival','read-mix','normal-runs','foreign-history','cancel-revoke-reset','global-backpressure','owner-backpressure','lifecycle-contention','recovery']
    if [p.get('name') for p in value.get('phases',[])]!=expected or not 0<value.get('requests',0)<=12000:raise RuntimeError('Capacity workload incomplete')
    if value.get('limits')!={'requests':12000,'owners':200}:raise RuntimeError('Capacity limits changed')
    provider=value.get('provider');pools=shutdown.get('pools')
    if not isinstance(provider,dict) or provider.get('actualModel') is not False:raise RuntimeError('Controlled provider receipt missing')
    for key,maximum in [('total',6000),('maxTurns',5),('standardMaxTurns',4),('gradingProjectionMaxTurns',5)]:
        observed=provider.get(key)
        if type(observed) is not int or not 0<=observed<=maximum:raise RuntimeError('Controlled provider bound invalid')
    if provider.get('gradingProjectionRuns')!=10:raise RuntimeError('Controlled grading probe count invalid')
    presentation=value.get('presentationProjection')
    if presentation!={'dto':200,'ownerDetails':200,'foreignDenied':20,'selectedObservationGrading':'controlled_unavailable_not_pass'}:raise RuntimeError('Capacity presentation projection incomplete')
    grading=value.get('gradingProjection')
    if not isinstance(grading,dict) or set(grading)!={'owners','runs','expectedVerdict','expectedDisposition','expectedErrorCode','actualModel'}:raise RuntimeError('Capacity grading projection malformed')
    if grading.get('owners')!=10 or grading.get('expectedVerdict')!='unavailable' or grading.get('expectedDisposition')!='not_pass' or grading.get('expectedErrorCode')!='INVALID_JUDGE_OUTPUT' or grading.get('actualModel') is not False:raise RuntimeError('Capacity grading receipt contract invalid')
    runs=grading.get('runs')
    if not isinstance(runs,list) or len(runs)!=10 or len(set(runs))!=10:raise RuntimeError('Capacity grading run receipts incomplete')
    try:
        if any(type(run) is not str or uuid.UUID(run).version!=4 for run in runs):raise ValueError
    except (ValueError,AttributeError):raise RuntimeError('Capacity grading run identity invalid')
    if not isinstance(pools,dict):raise RuntimeError('Pool retirement receipt missing')
    for key in ('managedReservedFinal','dedicatedActive','allocationFailures'):
        if type(pools.get(key)) is not int or pools[key]!=0:raise RuntimeError('Pool retirement incomplete')
    if type(pools.get('managedReservedPeak')) is not int or not 0<=pools['managedReservedPeak']<=78:raise RuntimeError('Pool reservation bound invalid')
    return True

def scenario_fixture(scenario):
    return {'fresh-interruption':'tests/postgres/setupDatabasePhase.integration.test.js','codebot-current-clean-fixed':'tests/postgres/codeBotCurrentMain.js','codebot-current-full-six':'tests/postgres/codeBotCurrentMain.js','codebot-current-representative':'tests/postgres/codeBotCurrentMain.js','dpi-current-owned':'tests/postgres/dpiCurrentOwnedMain.js','mcp-mounted-http':'tests/postgres/mcpMountedHttpMain.js','finflow-traversal':'tests/postgres/finflowTraversalMain.js','finflow-policy':'tests/postgres/finflowPolicyMain.js','finflow-admission':'tests/postgres/finflowAdmissionMain.js','finflow-0055':'tests/postgres/finflow0055Main.js','codebot-rendered-parity':'tests/postgres/codeBotRenderedParityMainV1.js','restored-populated-upgrade':'tests/release-inputs/populated16-rehearsal.cjs','retained-ownership-migrations':'tests/release-inputs/populated16-retained-ownership.cjs','main-capacity-200':'tests/postgres/mainBackendAuth.integration.test.js','main-backend-auth':'tests/postgres/mainBackendAuth.integration.test.js','prospective-recovery':'tests/postgres/applicationMaintenanceRecovery.integration.test.js','prospective-original':'tests/postgres/applicationMaintenanceProspective.integration.test.js','journal-bound-entry':'tests/postgres/applicationJournalBoundEntry.integration.test.js','fresh-success':'tests/postgres/setupDatabasePhase.integration.test.js','additive-success':'tests/postgres/setupDatabasePhase.integration.test.js','store-inspection':'tests/postgres/applicationMaintenanceStoreInspection.integration.test.js','inspection-plan':'tests/postgres/applicationMaintenanceInspectionPlan.integration.test.js','inprocess-original':'tests/postgres/applicationMaintenanceInprocessOriginal.integration.test.js','ctf-fresh':'tests/postgres/ctfSetupApplication.integration.test.js','ctf-populated':'tests/postgres/ctfSetupApplication.integration.test.js'}[scenario]

def scenario_bounds(scenario,policy_cohort=None,recon70b=False,reconJudge120=False,auth_profile=None):
    timing=mcp_recon_timing(reconJudge120,recon70b)
    if type(recon70b)is not bool or recon70b and scenario!='mcp-mounted-http':raise ValueError('Closed recon timing scope')
    if auth_profile is not None and (scenario!='main-backend-auth' or auth_profile not in ('rendered-platform','rendered-bound-session','standalone-core','standalone-core-rendered')):raise ValueError('Closed auth timing scope')
    if recon70b:return (timing['parentSeconds'],timing['childSeconds'],timing['cleanupSeconds'])
    if scenario=='main-capacity-200':return (1200,1080,120)
    if scenario=='dpi-current-owned':return (5340,5220,120)
    if scenario in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):return (780,420,120)
    if scenario=='mcp-mounted-http':return (780,600,120)
    if scenario=='finflow-traversal':return (1320,1260,120)
    if scenario=='finflow-policy':
        if policy_cohort not in ('plain','adversarial'):raise ValueError('Closed policy cohort required')
        return (960,900,120) if policy_cohort=='plain' else (1200,1140,120)
    scenario_fixture(scenario)  # closed admission before any resource creation
    if scenario in POPULATED_RESTORE_SCENARIOS:return (1800,1740,120)
    if scenario=='main-backend-auth':return (1200,1080,120) if auth_profile=='standalone-core-rendered' else (600,480,120)
    if scenario in ('finflow-admission','finflow-0055','codebot-rendered-parity'):return (780,600,120)
    return (900,780,120) if scenario=='prospective-recovery' else (780,600,120) if scenario in ('inprocess-original','journal-bound-entry','prospective-original') else (2100,1800,180) if scenario=='ctf-populated' else (1800,1680,120) if scenario=='ctf-fresh' else (780,780,120)

def within_cleanup(deadline, action, maximum=None):
    remaining=deadline-time.monotonic()
    if maximum is not None:remaining=min(remaining,maximum)
    if remaining<=0:raise TimeoutError('Owned cleanup deadline exhausted')
    def expired(_signal,_frame):raise TimeoutError('Owned cleanup deadline')
    previous=signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,remaining)
    try:return action()
    finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

def argument_parser():
    parser=argparse.ArgumentParser()
    for name in ['package','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--main-workspace',action='store_true')
    parser.add_argument('--interruption-case',choices=['runner-failure','signal','disconnect','abrupt'])
    parser.add_argument('--plan',action='store_true')
    for name in ['browser','browser-root','browser-sha256','python-sha256']:parser.add_argument('--'+name)
    parser.add_argument('--scenario',choices=['fresh-interruption','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned','mcp-mounted-http','finflow-traversal','finflow-policy','finflow-admission','finflow-0055','codebot-rendered-parity',*POPULATED_RESTORE_SCENARIOS,'main-backend-auth','main-capacity-200','prospective-recovery','prospective-original','fresh-success','additive-success','store-inspection','inspection-plan','ctf-fresh','ctf-populated','inprocess-original','journal-bound-entry'],required=True)
    parser.add_argument('--browser-profile',choices=['codebot','workshop-history','mcp-audit-content','mcp-indirect-supply-content','mcp-remaining-nine-content','objective-solution-content','generic-solution-content','xss-stored-six-content-inert','xss-reflected-three-actual','xss-reflected-r3-actual','xss-email-three-content','xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset','xss-email-builder-four-actual','xss-email-builder-four-content','csrf-twelve-content','csrf-rag-content-lifecycle','ipi-email-five-content','ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content','ipi-rag-query-actual','ipi-email-trigger-actual'])
    parser.add_argument('--auth-profile',choices=['rendered-platform','rendered-bound-session','standalone-core','standalone-core-rendered'])
    parser.add_argument('--mcp-recon-70b',action='store_true')
    parser.add_argument('--mcp-recon-judge-120',action='store_true')
    parser.add_argument('--mcp-profile',choices=['http','supply-chain','poisoning-contrast','poisoning-positive','recon'])
    parser.add_argument('--policy-cohort',choices=['plain','adversarial'])
    parser.add_argument('--rehearsal-request')
    parser.add_argument('--rehearsal-request-sha256')
    parser.add_argument('--entry-case',choices=['success','v1','startup','interrupted'])
    parser.add_argument('--original-case',choices=['success','begin-commit-loss','finish-commit-loss','interrupted-original'])
    for name in ['sandbox-image-id','ssh','scp','ssh-config','ssh-config-sha256','ssh-sha256','scp-sha256','ssh-host','ssh-known-hosts','ssh-known-hosts-sha256']:parser.add_argument('--'+name)
    return parser

def validate_original_case(args):
    case=getattr(args,'interruption_case',None)
    if args.scenario=='fresh-interruption':
        if not args.main_workspace or case not in ('runner-failure','signal','disconnect','abrupt'):raise ValueError('Exact main-only interruption case required')
    elif case is not None:raise ValueError('Unexpected interruption case')
    browser_profile(args)
    mcp_profile(args)
    platform=captured_auth_browser(args)
    if args.scenario not in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') and any(getattr(args,k,None) for k in ('ssh_known_hosts','ssh_known_hosts_sha256')):raise ValueError('Unexpected MCP host authority')
    if (args.scenario=='finflow-policy') != (getattr(args,'policy_cohort',None) in ('plain','adversarial')):raise ValueError('Policy cohort requires exact scenario')
    if args.scenario!='finflow-policy' and getattr(args,'policy_cohort',None) is not None:raise ValueError('Unexpected policy cohort')
    browser_values=[getattr(args,n,None) for n in ('browser','browser_root','browser_sha256','python_sha256')]
    if ((args.scenario=='codebot-rendered-parity' and browser_profile(args) not in (IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE)) or platform) and not all(browser_values):raise ValueError('CodeBot browser/runtime pins required')
    if (args.scenario=='codebot-rendered-parity' and browser_profile(args) in (IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE)) or args.scenario in ('finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):
        if not args.python_sha256 or any(browser_values[:3]):raise ValueError('FinFlow Python required; browser forbidden')
    elif args.scenario!='codebot-rendered-parity' and not platform and any(browser_values):raise ValueError('Unexpected browser/runtime pins')
    if (args.scenario in ('fresh-interruption','prospective-recovery','prospective-original','main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned')) != bool(getattr(args,'main_workspace',False)):raise ValueError('Prospective requires main-only selection')
    if (args.scenario in POPULATED_RESTORE_SCENARIOS) != bool(getattr(args,'rehearsal_request',None) and getattr(args,'rehearsal_request_sha256',None)):raise ValueError('Exact rehearsal request required')
    if args.scenario not in POPULATED_RESTORE_SCENARIOS and (getattr(args,'rehearsal_request',None) or getattr(args,'rehearsal_request_sha256',None)):raise ValueError('Unexpected rehearsal request')
    entry_case=getattr(args,'entry_case',None)
    if entry_case is not None and entry_case not in ('success','v1','startup','interrupted'):raise ValueError('Unknown entry case')
    if (args.scenario=='journal-bound-entry') != bool(entry_case):raise ValueError('Entry case requires exact journal-bound selector')
    if args.original_case is not None and args.original_case not in ('success','begin-commit-loss','finish-commit-loss','interrupted-original'):raise ValueError('Unknown original case')
    if (args.scenario=='inprocess-original') != bool(args.original_case):raise ValueError('Original case requires exact inprocess-original selector')

def admit_rehearsal_request(args, manifest):
    request=Path(args.rehearsal_request)
    if not request.is_absolute() or request.resolve()!=request or request.is_symlink():raise RuntimeError('Canonical rehearsal request required')
    st=request.stat()
    if not request.is_file() or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_nlink!=1 or st.st_size>1024*1024:raise RuntimeError('Private bounded rehearsal request required')
    if digest(request)!=args.rehearsal_request_sha256 or manifest.get('rehearsalRequest')!={'path':str(request),'sha256':args.rehearsal_request_sha256}:raise RuntimeError('Rehearsal request pin mismatch')
    return request

def rehearsal_environment(env, installation, args):
    result=dict(env)
    result.pop('OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE',None)
    result.pop('MCP_SIDECARS_AUTOSTART',None)
    root=Path(installation['path']);st=root.lstat()
    if (st.st_dev,st.st_ino,st.st_uid)!=(installation['device'],installation['inode'],installation['uid']):raise RuntimeError('Installation changed')
    for name in ('home','tmp'):(root/name).mkdir(mode=0o700)
    result.update(DOCKER_HOST=args.docker_host,PATH=str(Path(args.docker).parent)+os.pathsep+result.get('PATH','/usr/bin:/bin'),HOME=str(root/'home'),TMPDIR=str(root/'tmp'),REHEARSAL_REQUEST=str(args.rehearsal_request),REHEARSAL_REQUEST_SHA256=args.rehearsal_request_sha256)
    return result

def publish_child_start(child,state,record,scenario):
    state['nativeStarted']=True;state['nativePid']=child.pid;record()
    if scenario in ('main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):
        child.stdin.write(b'1');child.stdin.flush();child.stdin.close()

def scenario_command(args):
    if args.scenario in ('codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):return [args.node,str(Path(args.package)/scenario_fixture(args.scenario))]
    if args.scenario in POPULATED_RESTORE_SCENARIOS:return [args.node,scenario_fixture(args.scenario)]
    return [args.node,'--test','--test-isolation=none','--test-reporter=tap',scenario_fixture(args.scenario)]

def verify_rehearsal_result(evidence, source):
    result=Path(evidence)/'result.json'
    st=result.lstat()
    if result.is_symlink() or not result.is_file() or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>1024*1024:raise RuntimeError('Invalid rehearsal result')
    value=json.loads(result.read_text())
    if value.get('status')!='passed' or value.get('restoredStores')!=16 or value.get('sourceRoot')!=str(source) or value.get('installedWrites') is not False:raise RuntimeError('Rehearsal failed or incomplete')
    return value

def verify_retained_ownership_result(evidence):
    result=Path(evidence)/'result.json';st=result.lstat()
    if result.is_symlink() or not result.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>65536:raise RuntimeError('Invalid retained-ownership result')
    value=json.loads(result.read_text())
    expected={'status','scope','restoredStores','canonicalLeaseRuns','retainedPlatformTargets','allStoresPreserved','collisionChecksPassed','noAutomaticLinking','noPrivilegedSurrogate','fullSetupProven','installedWrites'}
    if set(value)!=expected or value['status']!='passed' or value['scope']!='retained-ownership-migrations-v1' or type(value['restoredStores']) is not int or value['restoredStores']!=16 or type(value['canonicalLeaseRuns']) is not int or value['canonicalLeaseRuns']!=2 or type(value['retainedPlatformTargets']) is not int or not 1<=value['retainedPlatformTargets']<=16:raise RuntimeError('Retained-ownership proof incomplete')
    if any(value[key] is not True for key in ('allStoresPreserved','collisionChecksPassed','noAutomaticLinking','noPrivilegedSurrogate')) or value['fullSetupProven'] is not False or value['installedWrites'] is not False:raise RuntimeError('Retained-ownership proof incomplete')
    return value

def validate_nested_birth(result, expected):
    if result.returncode != 0 or not result.stdout.strip() or result.stdout.strip() != expected:
        raise RuntimeError('Nested child identity unknown or reused; no signal')

def main():
    args=argument_parser().parse_args()
    validate_original_case(args)
    (validate_mcp_arguments(args) if args.scenario in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed') else validate_sidecar_args(args))
    work_seconds,child_seconds,cleanup_seconds=scenario_bounds(args.scenario,getattr(args,'policy_cohort',None),getattr(args,'mcp_recon_70b',False),getattr(args,'mcp_recon_judge_120',False),getattr(args,'auth_profile',None))
    deadline=time.monotonic()+work_seconds
    def expired(_signal,_frame):raise TimeoutError('Owned phase deadline')
    previous_alarm=signal.signal(signal.SIGALRM,expired);signal.alarm(work_seconds)
    package=validate(args)
    if args.plan:
        signal.alarm(0);signal.signal(signal.SIGALRM,previous_alarm)
        print(json.dumps({'plan':True,'scenario':args.scenario,**({'profile':browser_profile(args),'stores':browser_stores(browser_profile(args))} if args.scenario=='codebot-rendered-parity' else {}),'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':cleanup_seconds}));return 0
    clean={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}
    evidence=prospective_evidence(package,args.scenario) if args.main_workspace else Path(tempfile.mkdtemp(prefix='owasp-ai-goat-setup-phase-')).resolve();evidence.chmod(0o700)
    source=package if args.main_workspace else evidence/'source';owner=uuid.uuid4().hex;name='owasp-ai-goat-setup-phase-'+owner[:12]
    labels={'owasp-ai-goat.test.owner':owner,'owasp-ai-goat.test.cohort':'setup-database-phase'}
    state={'version':1,'evidenceRoot':str(evidence),'containerName':name,'owner':owner,'children':[],'nativeStarted':False,'mcpRecon70b':getattr(args,'mcp_recon_70b',False),'mcpReconJudge120':getattr(args,'mcp_recon_judge_120',False),**({'mcpReconTiming':mcp_recon_timing(getattr(args,'mcp_recon_judge_120',False),True)} if getattr(args,'mcp_recon_70b',False) else {})}
    def record():
        publish_ownership(evidence/'ownership.json',state)
    def docker(argv,timeout=None):
        return subprocess.run([args.docker,'--host',args.docker_host,*argv],env=clean,capture_output=True,text=True,timeout=max(.1,min(timeout or 30,deadline-time.monotonic())))
    def members(pgid,session):
        result=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=max(.1,min(2,deadline-time.monotonic())))
        selected=[]
        for line in result.stdout.splitlines():
            pid,group,uid=map(int,line.split())
            if group!=pgid:continue
            try:
                if os.getsid(pid)!=session:raise RuntimeError('Process session changed')
            except ProcessLookupError:continue
            if uid!=os.getuid():raise RuntimeError('Foreign group member')
            selected.append(pid)
        return selected
    def stop_group(child,pgid,session):
        if members(pgid,session):os.killpg(pgid,signal.SIGTERM)
        until=min(deadline,time.monotonic()+10)
        while members(pgid,session) and time.monotonic()<until:
            child.poll();time.sleep(.05)
        if members(pgid,session):os.killpg(pgid,signal.SIGKILL)
        child.wait(timeout=max(.1,min(10,deadline-time.monotonic())))
        until=min(deadline,time.monotonic()+5)
        while members(pgid,session) and time.monotonic()<until:
            child.poll();time.sleep(.05)
        if members(pgid,session):raise RuntimeError('Owned process group remains')
    processes=OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));processes.install()
    captured=None;attempted=False;code=1;native_parent=None;sidecars=None;sidecar_env={};installation=None;auth_data=None;mcp_topology=None;email_mailpit=None
    def cleanup_nested():
        journal=evidence/'nested-processes.json'
        if not journal.exists():return
        if journal.is_symlink() or journal.stat().st_size>65536:raise RuntimeError('Invalid child journal')
        rows=json.loads(journal.read_text())
        if rows.get('owner')!=owner or rows.get('parentPid')!=native_parent or not isinstance(rows.get('groups'),list) or len(rows['groups'])>256:raise RuntimeError('Foreign child journal')
        for item in reversed(rows['groups']):
            pid=item.get('pid')
            if not isinstance(pid,int) or pid<=1 or not re.fullmatch(r'[a-f0-9-]{36}',str(item.get('id'))):raise RuntimeError('Invalid child identity')
            if not members(pid,pid):continue
            birth=subprocess.run(['/bin/ps','-p',str(pid),'-o','lstart='],env=clean,capture_output=True,text=True,timeout=max(.1,min(2,deadline-time.monotonic())))
            try:validate_nested_birth(birth,item.get('birth'))
            except RuntimeError:
                state['nestedGroupsAbsent']=False;state['nestedCleanupUnknown']=True;record();raise
            os.killpg(pid,signal.SIGKILL)
            until=min(deadline,time.monotonic()+5)
            while members(pid,pid) and time.monotonic()<until:time.sleep(.05)
            if members(pid,pid):raise RuntimeError('Nested group remains')
        state['nestedGroupsAbsent']=True
    try:
        if args.scenario=='fresh-interruption':
            private=evidence/'installation';private.mkdir(mode=0o700);st=private.stat()
            installation={'path':str(private),'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid};state['privateInstallation']=installation;record()
        if args.main_workspace and args.scenario in ('prospective-original','prospective-recovery',*POPULATED_RESTORE_SCENARIOS):
            installation=create_private_installation(package);state['privateInstallation']=installation;record()
        if args.scenario in ('main-backend-auth','main-capacity-200'):
            auth_data=create_private_installation(package);state['privateAppData']=auth_data;record()
        verify_daemon(docker,args.docker_daemon);verify_image(docker,args.image_id)
        if args.scenario=='codebot-rendered-parity' and browser_profile(args)==IPI_EMAIL_ACTUAL_PROFILE:verify_image(docker,IPI_EMAIL_MAILPIT_IMAGE)
        if inspect_owned(docker,name=name,labels=labels,image=args.image_id) is not None:raise RuntimeError('Container name occupied')
        if not args.main_workspace:
            shutil.copytree(package/'source',source,symlinks=True)
            for directory,dirs,files in os.walk(source,followlinks=False):
                if Path(directory).is_symlink():raise RuntimeError('Runtime directory symlink')
                Path(directory).chmod(Path(directory).stat().st_mode|0o700)
            (source/'node_modules').symlink_to(package/'dependencies'/'node_modules',target_is_directory=True)
        attempted=True;state.update(containerCreationAttempted=True,containerLabels=labels,imageId=args.image_id,dockerDaemon=args.docker_daemon);record()
        memory='512m' if args.scenario=='main-capacity-200' else '2048m' if args.scenario in POPULATED_RESTORE_SCENARIOS else '1024m'
        response=docker(['run','--detach','--pull','never','--name',name,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--memory',memory,'--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',args.image_id,'-c','max_connections=96' if args.scenario=='main-capacity-200' else 'max_connections=100'])
        if response.returncode:raise RuntimeError('Owned container creation failed')
        row=inspect_owned(docker,name=name,labels=labels,image=args.image_id);captured=row['Id'];state['containerId']=captured;record()
        if row['Mounts'] or row['HostConfig']['Memory']!=(536870912 if args.scenario=='main-capacity-200' else 2147483648 if args.scenario in POPULATED_RESTORE_SCENARIOS else 1073741824) or row['HostConfig']['NanoCpus']!=2000000000 or row['HostConfig']['PidsLimit']!=256 or row['HostConfig']['Tmpfs']!={'/var/lib/postgresql':'rw,size=1073741824'}:raise RuntimeError('Owned container layout mismatch')
        ports=row['NetworkSettings']['Ports']['5432/tcp']
        if len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1':raise RuntimeError('Nonloopback database binding')
        port=ports[0]['HostPort']
        for _ in range(120):
            if docker(['exec',captured,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres']).returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Owned PostgreSQL unavailable')
        if args.main_workspace:
            empty=docker(['exec',captured,'psql','-U','postgres','-Atc',"SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"])
            if empty.returncode or empty.stdout.strip()!='0':raise RuntimeError('Owned empty cluster required')
        if args.scenario=='ctf-populated':
            def sidecar_record(value):state['sidecars']=value;record()
            sidecars=OwnedSidecars(args,source,evidence,owner,docker,sidecar_record)
            sidecar_env=sidecars.start()
        env={**clean,**sidecar_env,**({'SETUP_PHASE_INSTALLATION_ROOT':installation['path']} if installation else {}),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','SETUP_DATABASE_PHASE_ISOLATED':'1','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':str(source),'SETUP_PHASE_EVIDENCE_ROOT':str(evidence),'PG_ADMIN_DATABASE_URL':f'postgresql://postgres@127.0.0.1:{port}/postgres','SETUP_PHASE_OWNER':owner,'SETUP_PHASE_SCENARIO':args.scenario,**({'ENTRY_CASE':args.entry_case} if args.scenario=='journal-bound-entry' else {}),**({'ORIGINAL_WRITER_CASE':args.original_case} if args.scenario=='inprocess-original' else {}),**({'CTF_SETUP_APPLICATION_ISOLATED':'1'} if args.scenario in ('ctf-fresh','ctf-populated') else {}),'MCP_SIDECARS_AUTOSTART':'false','PG_TLS':'disable'}
        if args.scenario=='fresh-interruption':env['SETUP_PHASE_INTERRUPTION_CASE']=args.interruption_case
        if args.scenario in ('main-backend-auth','main-capacity-200'):
            runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
            env.pop('OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE',None)
            env.update(MAIN_BACKEND_AUTH_APP_DATA=auth_data['path'],PG_MAIN_BACKEND_AUTH='1',MAIN_BACKEND_AUTH_EVIDENCE=str(evidence),OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT=str(runtime),PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',AI_PROVIDER='mock',AWS_EC2_METADATA_DISABLED='true',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
            state.update(cohort=args.scenario,sourceRoot=str(source),databasePort=int(port))
            if standalone_core(args):
                env['PG_FULL_BACKEND_STANDALONE_CORE']='1'
                state['standaloneCore']={'profile':args.auth_profile,'modelCalls':0,'sourceCopy':False}
            if standalone_core_rendered(args):
                proof=validate_captured_browser(args,source,json.loads(Path(args.manifest).read_text()))
                proof['profile']='standalone-core-rendered'
                state.update(renderedStandalone=proof,browserSha256=args.browser_sha256)
                env.update(PG_MAIN_RENDERED_STANDALONE='1',PG_FULL_BACKEND_RENDERED='1',PG_FULL_BACKEND_BROWSER=args.browser,PG_FULL_BACKEND_BROWSER_SHA256=args.browser_sha256,SS_SESSION_TTL_SECONDS='120',PLATFORM_SESSION_TTL_SECONDS='240')
            if rendered_platform(args):
                proof=validate_captured_browser(args,source,json.loads(Path(args.manifest).read_text()))
                if args.auth_profile=='rendered-bound-session':
                    proof['boundSessions']=True
                    env['PG_MAIN_BOUND_SESSIONS']='1'
                state.update(renderedPlatform=proof,browserSha256=args.browser_sha256)
                env.update(PG_MAIN_RENDERED_PLATFORM='1',PG_FULL_BACKEND_RENDERED='1',PG_FULL_BACKEND_BROWSER=args.browser,PG_FULL_BACKEND_BROWSER_SHA256=args.browser_sha256)
            if args.scenario=='main-capacity-200':
                env.update(PG_MAIN_CAPACITY_200='1',PG_FULL_BACKEND_CAPACITY='1',PG_CAPACITY_OBSERVER_URL=f'postgresql://ownership_test_admin@127.0.0.1:{port}/postgres')
                provision=docker(['exec',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1','-c','CREATE ROLE ownership_test_admin LOGIN; GRANT pg_monitor TO ownership_test_admin'])
                if provision.returncode:raise RuntimeError('Capacity observer provisioning failed')
        if args.scenario=='codebot-rendered-parity':
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
            urls={}
            for store in browser_stores(browser_profile(args)):
                sql,pairs=codebot_store_configuration(store,int(port),nonce,browser_profile(args))
                result=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
                if result.returncode:raise RuntimeError('CodeBot owned provisioning failed')
                urls.update(pairs)
            if browser_profile(args)==IPI_EMAIL_ACTUAL_PROFILE:
                email_mailpit=OwnedEmailMailpit(docker,args.docker_daemon,owner,lambda value:(state.update(mailpit=value),record()))
                email_mailpit.start()
            env=codebot_environment(args,evidence,runtime,owner,urls)
            state.update(scenario=args.scenario,cohort=(browser_profile(args) if browser_profile(args)!='codebot' else args.scenario),profile=browser_profile(args),sourceRoot=str(source),nonce=nonce,databasePort=int(port),browserSha256=args.browser_sha256)
        if args.scenario=='finflow-0055':
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700);urls={}
            for case in ('fresh','populated'):
                sql,pairs=finflow0055_store_configuration(case,int(port),nonce)
                provision=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
                if provision.returncode:raise RuntimeError('FinFlow owned provisioning failed')
                urls.update(pairs)
            env=finflow0055_environment(args,evidence,runtime,owner,urls)
            state.update(scenario=args.scenario,cohort=args.scenario,sourceRoot=str(source),nonce=nonce,databasePort=int(port),parentPid=os.getpid(),manifestSha256=args.manifest_sha256)
        if args.scenario=='finflow-admission':
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
            sql,urls=finflow_admission_store_configuration(int(port),nonce)
            provision=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
            if provision.returncode:raise RuntimeError('FinFlow admission owned provisioning failed')
            env=finflow_admission_environment(args,evidence,runtime,owner,urls)
            state.update(scenario=args.scenario,cohort=args.scenario,sourceRoot=str(source),nonce=nonce,databasePort=int(port),parentPid=os.getpid(),manifestSha256=args.manifest_sha256)
        if args.scenario=='dpi-current-owned':
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
            sql,urls=dpi_store_configuration(int(port),nonce)
            provision=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
            if provision.returncode:raise RuntimeError('DPI owned provisioning failed')
            env=dpi_environment(args,evidence,runtime,owner,urls)
            state.update(scenario=args.scenario,cohort=args.scenario,sourceRoot=str(source),nonce=nonce,databasePort=int(port),parentPid=os.getpid(),manifestSha256=args.manifest_sha256)
        if args.scenario in ('finflow-policy','finflow-traversal'):
            profile='traversal' if args.scenario=='finflow-traversal' else 'policy'
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700);urls={}
            for store in ('identity','finflow'):
                sql,pairs=finflow_policy_store_configuration(store,int(port),nonce,profile)
                provision=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
                if provision.returncode:raise RuntimeError('Policy owned provisioning failed')
                urls.update(pairs)
            env=finflow_policy_environment(args,evidence,runtime,owner,urls,profile)
            state.update(scenario=args.scenario,cohort=args.scenario,policyCohort=args.policy_cohort,sourceRoot=str(source),nonce=nonce,databasePort=int(port),parentPid=os.getpid(),manifestSha256=args.manifest_sha256)
        if args.scenario in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):
            from mcp_mounted_http_topology import resource_plan,OwnedMcpTopology
            nonce=owner[:12];runtime=evidence/'runtime';runtime.mkdir(mode=0o700);urls={}
            manifest=json.loads(Path(args.manifest).read_text());topology=manifest['mcpTopology']
            def ssh_run(argv):return subprocess.run(argv,env=clean,capture_output=True,text=True,timeout=max(.1,min(20,deadline-time.monotonic())))
            binding=verify_mcp_ssh_runtime(args,topology,ssh_run)
            def remote(argv,timeout,input=None):
                return subprocess.run(mcp_remote_argv(args,argv),input=input,env=clean,capture_output=True,text=True,timeout=max(.1,min(timeout,deadline-time.monotonic())))
            plan=resource_plan(owner,topology['runnerImage'],topology.get('mailpitImage'),(source/MCP_TEMPLATES['cli']).read_bytes(),(source/MCP_TEMPLATES['http']).read_bytes() if args.scenario=='mcp-mounted-http' else None,cohort=args.scenario)
            state['topologyEvents']=[]
            def topology_record(event,data):
                if len(state['topologyEvents'])>=100:raise RuntimeError('MCP topology journal cap')
                state['topologyEvents'].append({'event':event,'data':data});record()
            mcp_topology=OwnedMcpTopology(plan=plan,docker=docker,remote=remote,record=topology_record,remaining=lambda:deadline-time.monotonic(),daemon_id=args.docker_daemon,remote_binding=binding,evidence_root=evidence)
            mcp_topology.prepare()
            cli_token=secrets.token_urlsafe(48);http_token=secrets.token_urlsafe(48)
            file_values={'cli':{'MCP_OWNED_TARGETS_ENABLED':'true','MCP_OWNED_TARGET_TOKEN':cli_token,'MCP_OWNED_TARGET_APPARMOR_PROFILE':plan['resources']['cli']['profile'],'MCP_OWNED_TARGET_ROOT':'/sandbox/owned-targets','SANDBOX_RUNNER_PORT':'8090'},'http':{'MCP_OWNED_HTTP_TOKEN':http_token,'MCP_OWNED_HTTP_ROOT':'/sandbox/owned-http','MCP_OWNED_TARGET_APPARMOR_PROFILE':plan['resources'].get('http',{}).get('profile'),'MCP_OWNED_HTTP_PORT':'8091'},'mail':{}}
            if args.scenario in ('codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):file_values={'cli':file_values['cli']}
            ports={}
            for kind,values in file_values.items():
                file=evidence/(kind+'.env');fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'w') as handle:
                    handle.write(''.join(k+'='+v+'\n'for k,v in values.items()));handle.flush();os.fsync(handle.fileno())
                ports[kind]=mcp_topology.launch(kind,file)
            if args.scenario=='mcp-mounted-http':
                sidecar_env={'MCP_OWNED_TARGET_URL':'http://127.0.0.1:'+str(ports['cli'][8090]),'MCP_OWNED_TARGET_TOKEN':cli_token,'MCP_OWNED_HTTP_ENABLED':'true','MCP_OWNED_HTTP_URL':'http://127.0.0.1:'+str(ports['http'][8091]),'MCP_OWNED_HTTP_TOKEN':http_token,'MAILPIT_SMTP_HOST':'127.0.0.1','MAILPIT_SMTP_PORT':str(ports['mail'][1025]),'MAILPIT_API_URL':'http://127.0.0.1:'+str(ports['mail'][8025])}
            else:sidecar_env={'SANDBOX_RUNNER_URL':'http://127.0.0.1:'+str(ports['cli'][8090])}
            for store in (('identity','mcp') if args.scenario=='mcp-mounted-http' else ('identity','supply_chain')):
                sql,pairs=(mcp_store_configuration if args.scenario=='mcp-mounted-http' else codebot_current_store_configuration)(store,int(port),nonce)
                provision=subprocess.run([args.docker,'--host',args.docker_host,'exec','-i',captured,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-v','ON_ERROR_STOP=1'],input=sql,text=True,capture_output=True,env=clean,timeout=max(.1,min(30,deadline-time.monotonic())))
                if provision.returncode:raise RuntimeError('MCP owned provisioning failed')
                urls.update(pairs)
            env=(mcp_environment if args.scenario=='mcp-mounted-http' else codebot_current_environment)(args,evidence,runtime,owner,urls,sidecar_env)
            state.update(scenario=args.scenario,cohort=args.scenario,sourceRoot=str(source),nonce=nonce,databasePort=int(port),parentPid=os.getpid(),manifestSha256=args.manifest_sha256)
        if args.scenario in POPULATED_RESTORE_SCENARIOS:
            env=rehearsal_environment(env, installation, args)
            state.update(cohort=args.scenario,sourceRoot=str(source),databasePort=int(port))
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=processes.launch(scenario_command(args),name='setup-phase',cwd=(runtime if args.scenario in ('codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned') else source),env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,**({'stdin':subprocess.PIPE} if args.scenario in ('main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned') else {}))
            native_parent=child.pid
            publish_child_start(child,state,record,args.scenario)
            if args.main_workspace:
                child_deadline=min(deadline,time.monotonic()+child_seconds)
                while child.poll() is None:
                    check_native_logs(evidence,args.scenario,args)
                    if time.monotonic()>=child_deadline:raise TimeoutError('Native child deadline')
                    time.sleep(.1)
                code=child.returncode
            else:code=child.wait(timeout=max(.1,min(child_seconds,deadline-time.monotonic())))
            processes.finish(child)
        if args.main_workspace:check_native_logs(evidence,args.scenario,args,complete=code==0)
        if standalone_core(args) and code==0:
            receipt=evidence/'runtime'/('standalone-core-rendered-result.json' if standalone_core_rendered(args) else 'standalone-core-result.json');st=receipt.lstat()
            if receipt.is_symlink() or not receipt.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>65536:raise RuntimeError('Private standalone core receipt required')
            (verify_standalone_core_rendered_result if standalone_core_rendered(args) else verify_standalone_core_result)(json.loads(receipt.read_text()))
        if rendered_platform(args) and code==0:
            receipt=evidence/'runtime'/'platform-rendered-result.json';st=receipt.lstat()
            if receipt.is_symlink() or not receipt.is_file() or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>65536:raise RuntimeError('Private platform receipt required')
            verify_platform_rendered_result(json.loads(receipt.read_text()),args.auth_profile=='rendered-bound-session')
        if args.scenario=='restored-populated-upgrade' and code==0:verify_rehearsal_result(evidence,source)
        if args.scenario=='retained-ownership-migrations' and code==0:verify_retained_ownership_result(evidence)
        if args.scenario in ('codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned') and code==0:
            if args.scenario in ('finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):
                receipt=evidence/'result.json';st=receipt.lstat()
                if receipt.is_symlink() or not receipt.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>1024*1024:raise RuntimeError('Invalid FinFlow result receipt')
            if args.scenario=='codebot-rendered-parity' and browser_profile(args)!='codebot':
                receipt=evidence/'result.json';st=receipt.lstat()
                if receipt.is_symlink() or not receipt.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>1024*1024:raise RuntimeError('Invalid history browser result receipt')
            result=json.loads((evidence/'result.json').read_text())
            if args.scenario=='codebot-rendered-parity' and browser_profile(args) in ('objective-solution-content','generic-solution-content'):verify_objective_solution_content_result(result,browser_profile(args))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)==IPI_EMAIL_ACTUAL_PROFILE:
                documents=[]
                for proof_name in ('actual-model-wire.json','email-actual-captures.json'):
                    file=evidence/proof_name;st=file.lstat()
                    if file.is_symlink() or not file.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>64*1024*1024:raise RuntimeError('Email private proof required')
                    documents.append(json.loads(file.read_text()))
                verify_ipi_email_actual_result(result,*documents,json.loads(Path(args.manifest).read_text()))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)==IPI_RAG_ACTUAL_PROFILE:
                documents=[]
                for proof_name in ('actual-model-wire.json','rag-actual-captures.json'):
                    file=evidence/proof_name;st=file.lstat()
                    if file.is_symlink() or not file.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>64*1024*1024:raise RuntimeError('RAG private proof required')
                    documents.append(json.loads(file.read_text()))
                verify_ipi_rag_actual_result(result,*documents,json.loads(Path(args.manifest).read_text()))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)==XSS_BUILDER_ACTUAL_PROFILE:
                documents=[]
                for proof_name in ('actual-model-wire.json','builder-actual-captures.json','builder-lifecycle.json'):
                    file=evidence/proof_name;st=file.lstat()
                    if file.is_symlink() or not file.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>64*1024*1024:raise RuntimeError('Builder private proof required')
                    documents.append(json.loads(file.read_text()))
                verify_xss_builder_actual_result(result,*documents)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args) in XSS_REFLECTED_PROFILES:
                documents=[]
                for proof_name in ('actual-model-wire.json','reflected-captures.json')+(('reflected-prerequisites.json',) if browser_profile(args)=='xss-reflected-r3-actual' else ()):
                    file=evidence/proof_name;st=file.lstat()
                    if file.is_symlink() or not file.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>64*1024*1024:raise RuntimeError('Reflected private proof required')
                    documents.append(json.loads(file.read_text()))
                verify_xss_reflected_result(result,*documents)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args) in ('csrf-twelve-content','csrf-rag-content-lifecycle'):verify_csrf_twelve_result(result,browser_profile(args))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)==XSS_BUILDER_CONTENT_PROFILE:verify_xss_builder_content_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args) in XSS_BUILDER_RESET_PROFILES:verify_xss_builder_reset_result(result,browser_profile(args))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='xss-email-three-content':verify_xss_email_three_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='xss-stored-six-content-inert':verify_xss_stored_six_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='mcp-indirect-supply-content':verify_mcp_indirect_supply_content_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='ipi-email-five-content':verify_ipi_email_five_content_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args) in ('ipi-rag-query-content','ipi-rag-upload-clean-content','ipi-rag-injection-two-content'):verify_ipi_rag_query_content_result(result,browser_profile(args))
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='mcp-remaining-nine-content':verify_mcp_remaining_nine_content_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='mcp-audit-content':verify_mcp_audit_content_result(result)
            elif args.scenario=='codebot-rendered-parity' and browser_profile(args)=='workshop-history':verify_workshop_history_result(result)
            elif args.scenario=='finflow-0055':verify_finflow0055_result(result)
            elif args.scenario=='finflow-admission':verify_finflow_admission_result(result)
            elif args.scenario in ('finflow-policy','finflow-traversal'):
                wire=evidence/'actual-model-wire.json';w=wire.lstat()
                if wire.is_symlink() or not wire.is_file() or w.st_nlink!=1 or w.st_uid!=os.getuid() or w.st_mode&0o777!=0o600 or w.st_size>64*1024*1024:raise RuntimeError('Policy wire receipt invalid')
                if args.scenario=='finflow-traversal':verify_finflow_traversal_result(result,json.loads(wire.read_text()))
                else:verify_finflow_policy_result(result,json.loads(wire.read_text()),args.policy_cohort)
            elif args.scenario=='dpi-current-owned':
                wire=evidence/'actual-model-wire.json';w=wire.lstat()
                if wire.is_symlink() or not wire.is_file() or w.st_nlink!=1 or w.st_uid!=os.getuid() or w.st_mode&0o777!=0o600 or w.st_size>64*1024*1024:raise RuntimeError('DPI wire receipt invalid')
                verify_dpi_result(result,json.loads(wire.read_text()),json.loads(Path(args.manifest).read_text()).get('selector','all'))
            elif args.scenario in ('mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed'):
                wire=evidence/'actual-model-wire.json';w=wire.lstat()
                if wire.is_symlink() or not wire.is_file() or w.st_nlink!=1 or w.st_uid!=os.getuid() or w.st_mode&0o777!=0o600 or w.st_size>64*1024*1024:raise RuntimeError('MCP wire receipt invalid')
                if args.scenario=='mcp-mounted-http':verify_mcp_result(result,json.loads(wire.read_text()),mcp_profile(args),getattr(args,'mcp_recon_70b',False),getattr(args,'mcp_recon_judge_120',False))
                else:
                    canonical=evidence/'canonical-captures.json';c=canonical.lstat()
                    if canonical.is_symlink() or not canonical.is_file() or c.st_nlink!=1 or c.st_uid!=os.getuid() or c.st_mode&0o777!=0o600 or c.st_size>64*1024*1024:raise RuntimeError('CodeBot canonical receipt invalid')
                    history={}
                    for phase in ('before','after'):
                        path=evidence/('immutable-history-'+phase+'.json');st=path.lstat()
                        if path.is_symlink() or not path.is_file() or st.st_nlink!=1 or st.st_uid!=os.getuid() or st.st_mode&0o777!=0o600 or st.st_size>64*1024*1024:raise RuntimeError('CodeBot immutable history receipt invalid')
                        history[phase]=path.read_bytes()
                    verify_codebot_current_result(result,json.loads(wire.read_text()),json.loads(canonical.read_text()),args.scenario,history)
            elif result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('CodeBot terminal result required')
        if args.scenario=='main-capacity-200' and code==0:verify_capacity_result(evidence/'runtime')
        if args.scenario=='fresh-interruption' and code==0:
            verify_interruption_result(json.loads((evidence/'setup-phase-result.json').read_text()),args.interruption_case,str(source),installation['path'])
        state['exitCode']=code
    except BaseException as error:
        state['primaryFailure']={'type':type(error).__name__,'timeout':isinstance(error,TimeoutError)}
        raise
    finally:
        deadline=time.monotonic()+cleanup_seconds;signal.alarm(0)
        processes.mask_cleanup_signals()
        try:
            failures=[]
            try:within_cleanup(deadline,processes.cleanup,40)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                within_cleanup(deadline,cleanup_nested,20)
                if args.scenario=='codebot-rendered-parity' or captured_auth_browser(args):
                    listing=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=2)
                    rows=[tuple(map(int,line.split())) for line in listing.stdout.splitlines()]
                    state['browserCleanup']=verify_codebot_browser_cleanup(args,evidence/'runtime',state,rows)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if installation and not failures:state['privateInstallationCleanup']=within_cleanup(deadline,lambda:preserve_auth_data(installation,evidence) if args.scenario in POPULATED_RESTORE_SCENARIOS else remove_private_installation(installation),30)
                elif installation:failures.append('PrivateInstallationRetainedBecauseProcessCleanupUncertain')
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if auth_data and not failures:state['privateAppDataCleanup']=within_cleanup(deadline,lambda:preserve_auth_data(auth_data,evidence),15)
                elif auth_data:failures.append('PrivateAppDataRetainedBecauseProcessCleanupUncertain')
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if attempted:state['containerCleanup']=within_cleanup(deadline,lambda:cleanup_phase_container(docker,args,name,labels,captured),30)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if mcp_topology:
                    within_cleanup(deadline,mcp_topology.cleanup);state['topologyCleanup']={'status':'absence_verified'}
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if email_mailpit:within_cleanup(deadline,email_mailpit.cleanup,30)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if sidecars:sidecars.cleanup(lambda action:within_cleanup(deadline,action,30))
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if args.main_workspace:check_native_logs(evidence,args.scenario,args)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if args.scenario in ('main-backend-auth','main-capacity-200',*POPULATED_RESTORE_SCENARIOS,'codebot-rendered-parity','finflow-0055','finflow-admission','finflow-policy','finflow-traversal','mcp-mounted-http','codebot-current-representative','codebot-current-full-six','codebot-current-clean-fixed','dpi-current-owned'):deadline=time.monotonic()+120
                state['frozenUnchanged']=within_cleanup(deadline,lambda:validate(args))==package
            except BaseException as error:failures.append(type(error).__name__)
            state['cleanupFailures']=failures
            if failures:raise RuntimeError('Owned cleanup or frozen integrity failed')
        finally:record();processes.restore();signal.alarm(0);signal.signal(signal.SIGALRM,previous_alarm);print(json.dumps({'evidenceRoot':str(evidence),'exitCode':code}))
    return code
if __name__=='__main__':raise SystemExit(main())
