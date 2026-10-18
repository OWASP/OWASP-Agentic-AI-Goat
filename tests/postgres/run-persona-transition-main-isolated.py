#!/usr/bin/env python3
"""Closed main-only Persona password / conversation-purpose PostgreSQL qualification."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, subprocess, tempfile, time, uuid
ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
DOCKER = ['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker', '--host', 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
PRODUCT_CANONICAL_FIXTURE_SHA256 = 'cbf7a18f361aac81395f20ad5a94c5636aaa1da8d024b1062b9ee1ed165848cb'
PRICING_JOURNAL_FIXTURE_SHA256 = '90fbcce01cea934420f2a20c044896e35dca4e189ac4550ca56d8a0c4cf47e4a'
PRICING_CANONICAL_SCOPE = 'historical 0032 to 0033 pricing fresh/populated/no-op then complete canonical current tail, actual current persona/repository/coordinator with controlled graph/receipts, saved reads and lifecycle fences; no actual model, browser or native executor credit'
ACL_FOUNDATION_FIXTURE_SHA256 = 'f7ae42fcafde8d2dc0a01ec44fe405ab90bb78cf696d16535dd35924347df519'
ACL_FOUNDATION_QUALIFICATION_SCOPE = ('historical 0024 foundation and 0059 through 0100 migration successors; '
    'current v30 fresh/populated/noop, including retained historical receipts and all29 direct predecessor '
    'transitions with exact missing-key denials, preserved instructor overrides and enforcement, '
    'wrong-role snapshot rejection by the actual v30 guard, and exact receipt replay; '
    '0097 product-search purpose admission, v29-to-v30 arithmetic-only denial, fresh customer-only defaults, runtime privilege and trigger '
    'guards, session/sibling/reset fences, and immutable audit/mail evidence; database-only, '
    'no model/browser/product search/listing/stock/price effect')
SUITES = {
 'persona-product-canonical': ('tests/postgres/secureshopPersonaProductCanonical.integration.test.js', 'PERSONA_', (('IDENTITY','identity'),('FRESH','secureshop_agents'),('COMMERCE','secureshop'),('REVIEW','secureshop_review')), 1),
 'catalog-release': ('tests/postgres/workshopCatalogProvenanceRelease.integration.test.js', 'PG_WORKSHOP_CATALOG_RELEASE_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'bound-mail': ('tests/postgres/secureshopBoundMail.native.js', 'MAIL_', (('IDENTITY','identity'),('AGENTS','secureshop_agents'),('COMMERCE','secureshop'),('FRESH','secureshop_agents')), 1),
 'target-migration': ('tests/postgres/secureshopTargetMigration.integration.test.js', 'PG_SECURESHOP_TARGET_TEST_', (('IDENTITY','identity'),), 1),
 'mcp-protected': ('tests/postgres/mcpProtectedAdmission.integration.test.js', 'PG_PROTECTED_', (('IDENTITY','identity'),('RESOURCE','mcp')), 1),
 'finflow-integrated': ('tests/postgres/finflowIntegratedMigrations.integration.test.js', 'FINFLOW_', (('FRESH','identity'),('POPULATED','identity')), 1),
 'graph-validation': ('tests/postgres/graphJudgeValidationCode.integration.test.js', 'PG_GRAPH_VALIDATION_', (('IDENTITY','identity'),), 1),
 'persona-password': ('tests/postgres/secureshopBoundPersonaPassword.integration.test.js', 'PG_SECURESHOP_BOUND_PERSONA_PASSWORD_', (('COMMERCE','secureshop'),('FRESH_AGENTS','secureshop_agents'),('POPULATED_AGENTS','secureshop_agents')), 2),
 'conversation-purpose': ('tests/postgres/secureshopConversationPurpose.integration.test.js', 'PG_SECURESHOP_CONVERSATION_PURPOSE_', (('FRESH','secureshop_agents'),('POPULATED','secureshop_agents')), 1),
 'password-reset': ('tests/postgres/secureshopBoundPasswordReset.integration.test.js', 'PERSONA_', (('IDENTITY','identity'),('FRESH','secureshop_agents'),('COMMERCE','secureshop'),('ACLFRESH','secureshop_agents')), 1),
 'acl-foundation': ('tests/postgres/secureshopBoundAclFoundation.integration.test.js', 'PERSONA_', (('IDENTITY','identity'),('FRESH','secureshop_agents'),('COMMERCE','secureshop'),('ACLFRESH','secureshop_agents')), 2),
 'owned-user-lookup': ('tests/postgres/secureshopOwnedUserLookup.integration.test.js', 'PERSONA_', (('IDENTITY','identity'),('FRESH','secureshop_agents'),('COMMERCE','secureshop'),('ACLFRESH','secureshop_agents')), 1),
 'pricing-journal': ('tests/postgres/secureshopPricingJournal.integration.test.js', 'PERSONA_', (('IDENTITY','identity'),('FRESH','secureshop_agents'),('COMMERCE','secureshop'),('ACLFRESH','secureshop_agents'),('REVIEW','secureshop_review')), 1),
 'customer-profile-migration': ('tests/postgres/secureshopCustomerProfileMigration.integration.test.js', 'PG_SECURESHOP_PROFILE_', (('FRESH','secureshop_review'),('POPULATED','secureshop_review')), 1),
 'assessment-seed': ('tests/postgres/secureshopSystemRestartAssessmentSeed.integration.test.js', 'PG_SECURESHOP_SYSTEM_RESTART_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'coupon-blind-assessment-seed': ('tests/postgres/secureshopCouponBlindAssessmentSeed.integration.test.js', 'PG_SECURESHOP_COUPON_BLIND_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'v01-assessment-seed': ('tests/postgres/secureshopV01PendingCatalogSeed.integration.test.js', 'PG_SECURESHOP_V01_AUDIT_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'v03-assessment-seed': ('tests/postgres/secureshopV03PendingCatalogSeed.integration.test.js', 'PG_SECURESHOP_V03_LISTING_OPTIMIZE_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'v08-assessment-seed': ('tests/postgres/secureshopV08PendingCatalogSeed.integration.test.js', 'PG_SECURESHOP_V08_SVG_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
 'v19-assessment-seed': ('tests/postgres/secureshopV19PendingCatalogSeed.integration.test.js', 'PG_SECURESHOP_V19_FILE_SUMMARY_SEED_', (('FRESH','identity'),('POPULATED','identity')), 2),
}
def arguments(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--suite', required=True, choices=tuple(SUITES))
    parser.add_argument('--fresh-cohort', choices=('current-0016','historical-0015'))
    parser.add_argument('--pricing-cohort', choices=('blocked-denial','canonical-current'))
    gate=parser.add_mutually_exclusive_group(); gate.add_argument('--run',action='store_true'); gate.add_argument('--plan',action='store_true')
    args=parser.parse_args(argv)
    if args.fresh_cohort and args.suite!='persona-password':parser.error('--fresh-cohort is exclusive to persona-password')
    if args.pricing_cohort and args.suite!='pricing-journal':parser.error('--pricing-cohort is exclusive to pricing-journal')
    return args

def source_inventory(extra):
    paths=set(extra)
    # Only source-bearing directories, no installed environment or runtime data.
    for folder in ('server/database/postgres','server/services','server/agent-runtime','server/middleware','server/utils','server/config','server/data','db/postgres','shared'):
        for directory,dirs,files in os.walk(ROOT/folder,followlinks=False):
            if any((pathlib.Path(directory)/d).is_symlink() for d in dirs):raise RuntimeError('Source directory symlink rejected')
            dirs[:]=[d for d in dirs if not d.startswith('.') and d not in ('node_modules','logs','uploads','vector-indexes','__pycache__')]
            for name in files:
                item=pathlib.Path(directory)/name
                if name.startswith('.') or item.suffix not in ('.js','.cjs','.mjs','.sql','.json'):continue
                if item.is_symlink():raise RuntimeError('Source symlink rejected')
                paths.add(item)
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)}
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    args=arguments()
    fixture,prefix,stores,count=SUITES[args.suite]
    if args.suite=='persona-product-canonical' and sha(ROOT/fixture)!=PRODUCT_CANONICAL_FIXTURE_SHA256:
        raise RuntimeError('Product canonical fixture pin mismatch')
    if args.suite=='acl-foundation' and sha(ROOT/fixture)!=ACL_FOUNDATION_FIXTURE_SHA256:
        raise RuntimeError('ACL foundation fixture pin mismatch')
    if args.suite=='pricing-journal' and sha(ROOT/fixture)!=PRICING_JOURNAL_FIXTURE_SHA256:
        raise RuntimeError('Pricing journal fixture pin mismatch')
    if not args.run:
        plan={'plan':True,'suite':args.suite,'fixture':fixture,'stores':stores,'freshCohort':args.fresh_cohort or ('current-0016' if args.suite=='persona-password' else None),'expectedTests':count,'sourceCopies':False,'actualModel':False}
        if args.suite=='persona-product-canonical':
            plan['fixtureSha256']=PRODUCT_CANONICAL_FIXTURE_SHA256
        if args.suite=='acl-foundation':
            plan['fixtureSha256']=ACL_FOUNDATION_FIXTURE_SHA256
            plan['qualificationScope']=ACL_FOUNDATION_QUALIFICATION_SCOPE
        if args.suite=='pricing-journal':
            plan.update(allocationStarted=False,pricingCohort=args.pricing_cohort or 'blocked-denial',fixtureSha256=PRICING_JOURNAL_FIXTURE_SHA256)
            if args.pricing_cohort=='canonical-current':plan.update(qualificationScope=PRICING_CANONICAL_SCOPE,rendered=False,nativeExecutor=False,expectedArtifact='pricing-journal-result.json')
        print(json.dumps(plan))
        return 0
    helper_path = ROOT/'tests/postgres/run-secureshop-audit-central-isolated.py'
    spec = importlib.util.spec_from_file_location('persona_sessions_main_lifecycle', helper_path)
    lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(lifecycle)
    if sha(DOCKER[0]) != '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e': raise RuntimeError('Docker CLI pin mismatch')
    if sha(NODE) != NODE_SHA: raise RuntimeError('Node pin mismatch')
    evidence = pathlib.Path(tempfile.mkdtemp(prefix='persona-transition-main-', dir=None if args.suite=='pricing-journal' else ROOT/'tests/release-inputs')).resolve(); evidence.chmod(0o700)
    env = lifecycle.owned_environment(evidence, NODE)
    if not (ROOT/fixture).is_file():raise RuntimeError('Exact selected fixture missing')
    workspace=evidence/'runtime'/'workspace'; workspace.mkdir(mode=0o700)
    env['DVAIA_ISOLATED_TEST_WORKSPACE']=str(ROOT if args.suite=='persona-product-canonical' else workspace)
    if args.suite=='pricing-journal':
        env['DVAIA_ISOLATED_TEST_WORKSPACE']=str(ROOT)
        env['DVAIA_PRICING_OWNED_OUTPUT_ROOT']=str(workspace)
        env['PERSONA_PRICING_NATIVE']='1'
        env['PERSONA_PRICING_CANONICAL']='1'
        if args.pricing_cohort=='canonical-current':env.pop('PERSONA_PRICING_BLOCKED_NATIVE',None)
        else:env['PERSONA_PRICING_BLOCKED_NATIVE']='1'
    logs=evidence/'logs'; logs.mkdir(mode=0o700); env['LOGS_DIR']=str(logs)
    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               AI_PROVIDER='mock', AWS_EC2_METADATA_DISABLED='true', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
               MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false')
    def run(args, **kw): return subprocess.run(args, env=env, cwd=ROOT, check=True, capture_output=True, text=True, timeout=30, **kw)
    def daemon():
        if run(DOCKER+['info','--format','{{.ID}}']).stdout.strip() != DAEMON: raise RuntimeError('Docker daemon mismatch')
    nonce=uuid.uuid4().hex; name='dvaia-persona-transition-'+nonce[:12]; children=[]; attempted=False; container_id=None
    inventory_path=ROOT/'tests/postgres/run-mail-browser-main.py'
    spec=importlib.util.spec_from_file_location('persona_dependency_inventory',inventory_path)
    inventories=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventories)
    extra=[ROOT/'tests/helpers/secureshopAgentsMigrationView.js',ROOT/fixture,pathlib.Path(__file__).resolve(),helper_path,pathlib.Path(lifecycle.helpers.__file__),inventory_path,ROOT/'package.json',ROOT/'package-lock.json']
    if args.suite=='pricing-journal':
        extra += [ROOT/'tests/fixtures/pricingOwnedOutput.js',ROOT/'tests/fixtures/secureshopPricingJudgmentPersistence.js',ROOT/'docs/modernization/drafts/secureshop-bound-pricing/0033_bound_pricing.candidate.sql',ROOT/'tests/postgres/test_persona_acl_foundation_launcher.py']
    if args.suite in ('password-reset','owned-user-lookup'):
        extra += [ROOT/'docs/modernization/drafts/secureshop-bound-password-reset/0026_password_reset.candidate.sql',ROOT/'docs/modernization/drafts/secureshop-owned-user-lookup/0025_owned_user_lookup.candidate.sql']
        env['PERSONA_PASSWORD_RESET_NATIVE' if args.suite=='password-reset' else 'PERSONA_OWNED_USER_LOOKUP_NATIVE']='1'
        if args.suite=='owned-user-lookup':env['PERSONA_OWNED_USER_LOOKUP_EVIDENCE_PATH']=str(evidence/'owned-user-lookup-result.json')
    if args.suite=='persona-product-canonical':
        env['PERSONA_REVIEW_CANONICAL_NATIVE']='1'
    if args.suite=='acl-foundation':
        env['PERSONA_ACL_FOUNDATION_NATIVE']='1'
        env['PERSONA_ACL_REPOSITORY_NATIVE']='1'
    if args.suite=='bound-mail':
        env['MAIL_NATIVE']='1';env['MAIL_RESULT']=str(evidence/'mail-result.json')
        for folder,filename in [('secureshop-owned-mcp-registry','0035_owned_mcp_registry.sql'),('secureshop-owned-mcp-registry','0036_owned_mcp_registry_publication.sql'),('secureshop-owned-listings','0037_listing_conversation_purpose.sql'),('secureshop-owned-mail','0038_bound_lab_mail.sql'),('secureshop-owned-mail','0039_mail_reply_purpose.sql')]:
            extra.append(ROOT/'docs/modernization/drafts'/folder/filename)
    if args.suite=='v19-assessment-seed':
        extra += [ROOT/'tests/fixtures/secureshopV44CandidateCatalog.js']
    if args.suite=='catalog-release':
        extra += [ROOT/'tests/helpers/xssBoundedMigrationView.js', ROOT/'tests/helpers/workshopCatalogRelease116.js', ROOT/'tests/fixtures/workshopCatalogRelease116.json']
    if args.suite=='target-migration':
        extra += [ROOT/'tests/helpers/xssBoundedMigrationView.js']
    if args.suite=='graph-validation':
        extra += [ROOT/'tests/helpers/xssBoundedMigrationView.js', ROOT/'docs/modernization/drafts/graph-judge-validation-code.sql']
    if args.suite=='finflow-integrated':
        extra += [ROOT/'tests/helpers/xssBoundedMigrationView.js', ROOT/'tests/postgres/fixtures/finflow-v7-default-snapshots.json']
        env['FINFLOW_TRAVERSAL_ISOLATED']='1'
    if args.suite=='mcp-protected':
        extra += [ROOT/'tests/helpers/xssBoundedMigrationView.js', ROOT/'tests/helpers/mcpProtectedTargetFixture.js', ROOT/'docs/modernization/drafts/mcp-protected-recovery/protected_reconciliation.candidate.sql']
        python_executable=pathlib.Path('/usr/local/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
        if sha(python_executable)!='b08b055365df6dcd3fff0b805b688428f0f6a01839303f22c0716780155c480d':raise RuntimeError('Fixture Python pin mismatch')
        env['MCP_PROTECTED_PYTHON_EXECUTABLE']=str(python_executable)
        package_root=ROOT/'sidecars/sandbox-runner/labfs/opt/lab/packages'
        for directory,dirs,files in os.walk(ROOT/'sidecars/sandbox-runner',followlinks=False):
            if any((pathlib.Path(directory)/entry).is_symlink() for entry in dirs):raise RuntimeError('Sidecar source directory symlink rejected')
            dirs[:]=[entry for entry in dirs if not entry.startswith('.') and entry not in ('node_modules','logs','uploads','targets','__pycache__')]
            for filename in files:
                item=pathlib.Path(directory)/filename
                package_asset=item.is_relative_to(package_root)
                if not package_asset and (filename.startswith('.') or item.suffix not in ('.js','.cjs','.mjs','.json')):continue
                if item.is_symlink() or not item.is_file():raise RuntimeError('Sidecar source must be a regular file')
                extra.append(item)
    pins=source_inventory(extra)
    dependencies=inventories.inventory(ROOT/'node_modules')
    lifecycle.helpers.write_private_json(evidence/'dependencies-before.json',dependencies)
    if args.suite=='persona-password':env['SECURESHOP_PERSONA_PASSWORD_FRESH_COHORT']=args.fresh_cohort or 'current-0016'
    result={'fixture':fixture,'actualModel':False,'rendered':False,'optionalHttpServices':False,'qualificationScope':('bounded historical candidate only; database-only' if args.suite in ('password-reset','acl-foundation') else 'bounded historical transition then current tail; database-only'), 'suite':args.suite,'freshCohort':(args.fresh_cohort or 'current-0016') if args.suite=='persona-password' else None,'sourceHashes':pins,'container':name,'image':IMAGE,'daemon':DAEMON,'runtime':{'node':str(NODE),'sha256':NODE_SHA},'dockerCliSha256':sha(DOCKER[0]),'sourceRoot':str(ROOT),'dataCwd':str(ROOT)}
    if args.suite=='acl-foundation':
        result['fixtureSha256']=ACL_FOUNDATION_FIXTURE_SHA256
        result['qualificationScope']=ACL_FOUNDATION_QUALIFICATION_SCOPE
    if args.suite=='catalog-release':result['qualificationScope']='identity0046 to0047 to0048 to0049 with exact historical116 catalog, then separate current canonical tail and instructor/progress/activity/time/noop preservation; no model/browser'
    if args.suite=='customer-profile-migration':result['qualificationScope']='secureshop_review0046 fresh and populated0045 to0046 with exact retained legacy profile overlay, audit and schema-valid historical operation rows, canonical codec-valid hash-only profile receipt admission, immutability and second-run no-op; database-only, no model/browser or session-authority claim'
    if args.suite=='assessment-seed':result['qualificationScope']='current identity migrations with V04 fresh native-browser-judge disabled default, exact recognized pending checked-in-default upgrade, instructor and tenant configuration, sibling state, immutable evidence tables and second-run no-op preserved; database-only, no model/browser/Judge/effect or credit claim'
    if args.suite=='coupon-blind-assessment-seed':result['qualificationScope']='current identity migrations with V48 fresh native-browser-judge disabled default, exact recognized pending checked-in-default upgrade, instructor and tenant configuration, sibling state, immutable evidence tables and second-run no-op preserved; database-only, no model/browser/Judge/effect or credit claim; actual model/browser/Judge qualification is separately retained under fixture-local candidate admission'
    if args.suite=='v01-assessment-seed':result['qualificationScope']='current identity migrations with V01 fresh native-browser-judge default-disabled objective, exact recognized pending checked-in-default promotion, instructor and tenant configuration, sibling state, immutable evidence tables and second-run no-op preserved; normal qualified administrator enablement proved; database-only, no model/browser/Judge/effect or credit claim; actual model/browser/Judge qualification retained separately'
    if args.suite=='v03-assessment-seed':result['qualificationScope']='current identity migrations with V03 listing-image optimize fresh native-browser-judge default-disabled objective, exact recognized pending checked-in-default promotion, instructor and tenant configuration, sibling state, immutable evidence tables and second-run no-op preserved; normal qualified administrator enablement proved; database-only, no model/browser/Judge/effect or credit claim; accepted retained rendered scenario proof remains separate and its original outer cohort remains failed'
    if args.suite=='v08-assessment-seed':result['qualificationScope']='current identity migrations with V08 fresh native-browser-judge default-disabled objective, exact recognized pending checked-in-default promotion, instructor content and tenant configuration, sibling state and nonempty immutable judgment/completion/contribution evidence plus second-run no-op preserved; canonical administrator enablement denied before and normally enabled after qualification; database-only, no browser/model/Judge/effect or credit claim; genuine rendered source307 proof retained separately'
    if args.suite=='v19-assessment-seed':result['qualificationScope']='current identity migrations preserve V19 pending/default-disabled file-summary checks and qualify V44 and V29 fresh native-browser-judge/default-disabled, exact checked-in pending predecessor promotion, instructor content, tenant and sibling configuration, nonempty immutable judgment/completion/contribution/retry history and second-run no-op; canonical administrator enablement denied before qualification and enabled after; database-only, no file/model/browser/Judge/effect or credit claim'
    if args.suite=='pricing-journal':
        result['pricingCohort']=args.pricing_cohort or 'blocked-denial'
        result['fixtureSha256']=PRICING_JOURNAL_FIXTURE_SHA256
        result['qualificationScope']=PRICING_CANONICAL_SCOPE if args.pricing_cohort=='canonical-current' else 'current 0080 to 0081 Pricing blocked-evidence migration, fresh/populated/no-op and owner-bound receipt checks; current main source, owned disposable stores and output; no model/browser'
    if args.suite=='bound-mail':result['qualificationScope']='fresh agents through0038 then0039; populated0037 to0038 to0039; controlled Mail lifecycle, no model'
    if args.suite=='finflow-integrated':result['qualificationScope']='bounded identity0053 to0054 to0055 and injected rollback; database-only'
    if args.suite=='mcp-protected':result.update(pythonRuntime={'path':str(python_executable),'sha256':sha(python_executable)}, qualificationScope='identity0096 to0097 protected admission and owned loopback effects; controlled model only', optionalHttpServices=True)
    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)
    def inspect_owned():
        daemon(); ids=run(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).stdout.split()
        if not ids:
            if container_id and container_id in run(DOCKER+['ps','-aq','--no-trunc']).stdout.split():raise RuntimeError('Captured container renamed; cleanup withheld')
            return None
        if len(ids)!=1:raise RuntimeError('Ambiguous container')
        row=json.loads(run(DOCKER+['inspect',ids[0]]).stdout)[0]
        ports=row.get('HostConfig',{}).get('PortBindings',{}).get('5432/tcp',[])
        if (row['Name']!='/'+name or row['Image']!=IMAGE or row['Config'].get('Labels',{}).get('dvaia.owner')!=nonce
            or (container_id is not None and row['Id']!=container_id) or len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1'
            or row.get('HostConfig',{}).get('Memory')!=536870912
            or row.get('HostConfig',{}).get('NanoCpus')!=2000000000
            or row.get('HostConfig',{}).get('PidsLimit')!=256
            or row.get('HostConfig',{}).get('Tmpfs',{}).get('/var/lib/postgresql')!='rw,size=536870912'
            or row.get('HostConfig',{}).get('Privileged') is True
            or row.get('HostConfig',{}).get('NetworkMode')=='host'
            or '/var/lib/postgresql' not in row.get('HostConfig',{}).get('Tmpfs',{})
            or any(m.get('Type') in ('bind','volume') for m in row.get('Mounts',[]))):raise RuntimeError('Container ownership mismatch')
        return row['Id']
    def interrupted(signum, frame): raise RuntimeError('Interrupted '+str(signum))
    previous={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT)}
    try:
        save(); daemon()
        if run(DOCKER+['image','inspect',IMAGE,'--format','{{.Id}}']).stdout.strip()!=IMAGE:raise RuntimeError('Postgres image mismatch')
        if run(DOCKER+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip():raise RuntimeError('Container namespace occupied')
        attempted=True
        run(DOCKER+['run','-d','--pull','never','--name',name,'--label','dvaia.owner='+nonce,'--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=536870912',
                    '-e','POSTGRES_USER=merchant_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
                    '-p','127.0.0.1::5432',IMAGE,'-c','max_connections=64','-c','shared_buffers=16MB','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
        container_id=inspect_owned(); result['containerId']=container_id; save()
        for _ in range(80):
            probe=subprocess.run(DOCKER+['exec',container_id,'pg_isready','-h','127.0.0.1','-U','merchant_admin'],env=env,capture_output=True,timeout=5)
            if probe.returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Postgres readiness deadline')
        port=run(DOCKER+['port',container_id,'5432']).stdout.strip().rsplit(':',1)[1]
        if not port.isdecimal():raise RuntimeError('Invalid owned port')
        for family in sorted({family for _,family in stores}):
            sql=' '.join(f'CREATE ROLE dvaia_{family}_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;' for role in ('migration','runtime'))
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',sql])
        for store,family in stores:
            database=('dvaia_test_persona_'+nonce[:12]+'_'+store.lower()) if args.suite in ('password-reset','owned-user-lookup','acl-foundation','pricing-journal','persona-product-canonical') else ('dvaia_test_persona_'+store.lower()+'_'+nonce[:12])
            if args.suite=='bound-mail':database='dvaia_test_mail_'+nonce[:12]+'_'+store.lower()
            if args.suite=='graph-validation':database='dvaia_test_graph_validation_'+nonce[:12]
            if args.suite=='finflow-integrated':database='dvaia_test_finflow_traversal_identity'+('_populated' if store=='POPULATED' else '')
            if args.suite=='mcp-protected':database='dvaia_test_mcp_protected_'+store.lower()+'_'+nonce[:12]
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER dvaia_{family}_migration'])
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_{family}_migration,dvaia_{family}_runtime'])
            for role in ('migration','runtime'):env[prefix+store+'_'+role.upper()+'_URL']=f'postgresql://dvaia_{family}_{role}@127.0.0.1:{port}/{database}'
            if args.suite in ('graph-validation','target-migration'):
                for role in ('migration','runtime'):env[prefix+role.upper()+'_URL']=env.pop(prefix+store+'_'+role.upper()+'_URL')
            if args.suite=='finflow-integrated':
                names=('IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL') if store=='FRESH' else ('FINFLOW_IDENTITY_POPULATED_DATABASE_URL','FINFLOW_IDENTITY_POPULATED_MIGRATION_DATABASE_URL')
                for role,target in zip(('runtime','migration'),names):env[target]=env.pop(prefix+store+'_'+role.upper()+'_URL')
            if args.suite=='mcp-protected':
                targetPrefix='PG_GRAPH_TEST_' if store=='IDENTITY' else 'PG_MCP_'
                for role in ('runtime','migration'):env[targetPrefix+role.upper()+'_URL']=env.pop(prefix+store+'_'+role.upper()+'_URL')
        output=lifecycle.run_owned_child([str(NODE),'--test','--test-concurrency=1','--test-reporter=tap',str(ROOT/fixture)],cwd=ROOT,env=env,evidence=evidence,children=children,timeout=300 if args.suite=='acl-foundation' else 180)
        result.update(exitCode=output.returncode,stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        for field,value in [('tests',count),('pass',count),('fail',0),('cancelled',0),('skipped',0)]:
            if not re.search(r'^# '+field+' '+str(value)+r'$',output.stdout,re.M):raise RuntimeError('Unexpected TAP '+field)
        if output.returncode:raise RuntimeError('Native fixture failed')
        if args.suite=='pricing-journal' and args.pricing_cohort=='canonical-current':
            artifact=workspace/'pricing-journal-result.json'
            if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_uid!=os.getuid() or artifact.stat().st_size>1024*1024:raise RuntimeError('Original pricing journal result required')
            pricing=json.loads(artifact.read_text())
            if pricing.get('status')!='passed' or pricing.get('candidateOnly') is not False or any(pricing.get(k) is not True for k in ('registered','fresh','populated','noop','realPersonaAuthority','actualAuditAdapter','actualCoordinator','actualOwnedProductManualRead','originalSessionReadback','privateAssessmentReadback','laterSessionDenied','terminalNoReadmission','lostCommitAcknowledgementReadback','retirementRedaction','ownerDeletion','siblingPreserved')) or any(type(pricing.get(k)) is not int or pricing[k]!=0 for k in ('actualModelCalls','actualJudgeCalls')) or pricing.get('receiptProvenance')!='controlled provider/receipt only; no native executor/model':raise RuntimeError('Controlled canonical pricing journal proof incomplete')
            result.update(pricingResult=pricing,pricingResultSha256=sha(artifact))
        if args.suite=='owned-user-lookup':
            result['lookupResultSha256']=sha(evidence/'owned-user-lookup-result.json')
        if args.suite=='bound-mail':
            receipt=json.loads((evidence/'mail-result.json').read_text())
            if receipt.get('status')!='passed' or receipt.get('populatedMigrations')!=['0038_bound_lab_mail.sql'] or receipt.get('upgradeMigrations')!=['0039_mail_reply_purpose.sql']:raise RuntimeError('Mail qualification receipt incomplete')
            result['mailResultSha256']=sha(evidence/'mail-result.json')
        result['passed']=True
    except BaseException as error:
        result.update(passed=False,error=type(error).__name__+': '+str(error))
        if isinstance(error,subprocess.CalledProcessError):
            lifecycle.helpers.write_private_json(evidence/'pretest-command-failure.json',{'stdout':error.stdout,'stderr':error.stderr,'returncode':error.returncode})
    finally:
        errors=[]
        # Stop all owned children before retiring their one exact container.
        # Do not pass a name-only deletion intent to the shared helper.
        for child in reversed(children):
            try: lifecycle.helpers.stop_group(child)
            except BaseException as error: errors.append('Child cleanup: '+str(error))
        if attempted:
            try:
                daemon()
                verified=inspect_owned()
                if verified:
                    container_id=verified
                    run(DOCKER+['rm','-f',container_id])
                all_ids=run(DOCKER+['ps','-aq','--no-trunc']).stdout.split()
                if container_id and container_id in all_ids:raise RuntimeError('Captured container remains')
                if run(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).stdout.strip():raise RuntimeError('Reserved name occupied after retirement')
                result['containerAbsent']=True
            except BaseException as error:errors.append('Container cleanup withheld/failed: '+str(error))
        if not errors:
            errors.extend(lifecycle.cleanup_owned([],[],DOCKER,evidence))
        result['childGroupsAbsent']=not any('Child cleanup:' in value for value in errors)
        result['cleanupErrors']=errors
        try:
            after=source_inventory(extra)
            dependency_after=inventories.inventory(ROOT/'node_modules')
            lifecycle.helpers.write_private_json(evidence/'dependencies-after.json',dependency_after)
            result['sourceHashesAfter']=after
            result['sourceUnchanged']=after==pins
            result['dependenciesUnchanged']=dependency_after==dependencies
            if args.suite=='mcp-protected' and sha(python_executable)!=result['pythonRuntime']['sha256']:raise RuntimeError('Fixture Python changed')
        except BaseException as error:
            result['sourceUnchanged']=False;result['dependenciesUnchanged']=False
            errors.append('Postflight inventory: '+str(error))
        result['passed']=result.get('passed',False) and not errors and result['sourceUnchanged'] and result['dependenciesUnchanged']
        save()
        for s,handler in previous.items():signal.signal(s,handler)
    print(str(evidence/'result.json'))
    return 0 if result['passed'] else 1
if __name__=='__main__':sys.exit(main())
