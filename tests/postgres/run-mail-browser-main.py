#!/usr/bin/env python3
"""SecureShop saved-mail browser qualification; all source remains in main."""
import argparse
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

CONTENT_API_REQUEST_LIMIT = 1024
MCP_TRUST_CONTENT_IDS = ['ss_rogue_tool_selected','ss_rug_pull_invoked']
INBOX_CONTENT_IDS = ['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block']
LISTINGS_CONTENT_IDS = ['ss_listing_internal_fetch','ss_listing_external_entity','ss_listing_prototype_mutation','ss_listing_generated_browser_execution']
def content_mode(args):
    return 'standalone-disclosure-actual' if getattr(args,'standalone_disclosure_actual',False) else 'analytics-disclosure-content' if getattr(args,'analytics_disclosure_content',False) else 'review-batch-actual' if getattr(args,'review_batch_actual',False) else 'review-followed-actual' if getattr(args,'review_followed_actual',False) else 'audit-instruction-actual' if getattr(args,'audit_instruction_actual',False) else 'audit-instruction-content' if getattr(args,'audit_instruction_content',False) else 'ssrf-actual' if getattr(args,'ssrf_actual',False) else 'ssrf-content' if getattr(args,'ssrf_content',False) else 'mcp-trust-actual' if getattr(args,'mcp_trust_actual',False) else 'mcp-trust-content' if getattr(args,'mcp_trust_content',False) else 'inbox-actual' if getattr(args,'inbox_actual',False) else 'inbox-content' if getattr(args,'inbox_content',False) else 'stored-browser-content-lifecycle' if getattr(args,'stored_browser_content_lifecycle',False) else 'pricing-disclosure-content' if getattr(args,'pricing_disclosure_content',False) else 'review-followed-content' if getattr(args,'review_followed_content',False) else 'review-persist-content' if getattr(args,'review_persist_content',False) else 'audit-sql-content' if getattr(args,'audit_sql_content',False) else 'loop-content-lifecycle' if getattr(args,'loop_content_lifecycle',False) else 'listings-content' if getattr(args,'listings_content',False) else 'content-only' if getattr(args,'content_only',False) else 'actual'
import secrets
import stat

COHORT = 'mail-browser-main'
ACTUAL_INPUT = 'tests/release-inputs/mail-browser-frozen-inputs.json'
ACTUAL_INPUT_SHA256 = 'f6f28e316fbeaa059ab408c9ec1581ac7d5364ec8ec5cebb458de230962b1208'
REQUIRED = {
 'tests/postgres/run-mail-browser-main.py','tests/postgres/secureshopMailBrowser.integration.test.js',
 'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js',
 'tests/fixtures/browserProcessOwnership.js','tests/postgres/sql_nosql_process_ownership.py',
 'tests/postgres/sql_nosql_docker_ownership.py','server/services/secureshopMailBrowserQualification.js',
 'tests/fixtures/secureshopMailRenderedQualification.js','tests/postgres/run-finflow-backup-browser-main.py','tests/release-inputs/record-current-frontend-build.py',
 'client/src/pages/secureshop/components/MailMessageBody.jsx','package.json','package-lock.json',ACTUAL_INPUT,
}


def digest(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def inventory(root):
    result={}
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            item=Path(directory)/name;rel=item.relative_to(root).as_posix();st=item.lstat()
            if item.is_symlink():
                if not item.resolve().is_relative_to(root.resolve()):raise RuntimeError('Dependency link escapes main')
                result[rel]={'link':os.readlink(item)}
            elif item.is_dir():result[rel]={'mode':st.st_mode&0o777,'directory':True}
            elif item.is_file():result[rel]={'mode':st.st_mode&0o777,'sha256':digest(item)}
            else:raise RuntimeError('Unsupported dependency type')
    return result

def read_private_manifest(path,max_bytes=16*1024*1024):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as file:
            metadata=os.fstat(file.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() or metadata.st_mode&0o077 or metadata.st_size>max_bytes:
                raise RuntimeError('Private regular owned manifest required')
            data=file.read(max_bytes+1)
            if len(data)>max_bytes:raise RuntimeError('Private regular owned manifest required')
            return data
    except OSError as error:
        raise RuntimeError('Private regular owned manifest required') from error

def validate_external_profile(manifest):
    if manifest.get('externalBuildRoot') is not None and manifest.get('mode')!='loop-content-lifecycle':raise RuntimeError('External build supports controlled loop profile only')

def validate_audit_continuation_manifest(args,manifest):
    value=manifest.get('auditContinuation',False)
    if type(value) is not bool or value!=getattr(args,'audit_continuation',False):raise RuntimeError('Audit continuation manifest mismatch')
    if value and (getattr(args,'audit_70b',False) is not True or content_mode(args)!='audit-instruction-actual'):raise RuntimeError('Audit continuation requires Audit 70B')

def validate_main(args):
    source=Path(__file__).resolve().parents[2]
    if Path(args.main_workspace)!=source or source.resolve()!=source:raise RuntimeError('Exact current main required')
    manifest_bytes=read_private_manifest(args.manifest)
    if hashlib.sha256(manifest_bytes).hexdigest()!=args.manifest_sha256:raise RuntimeError('Manifest pin mismatch')
    manifest=json.loads(manifest_bytes)
    if manifest.get('cohort')!=COHORT or manifest.get('workspace')!=str(source):raise RuntimeError('Wrong main manifest')
    if manifest.get('mode')!=content_mode(args):raise RuntimeError('Manifest mode mismatch')
    if manifest.get('audit70b',False)!=getattr(args,'audit_70b',False):raise RuntimeError('Audit 70B manifest mismatch')
    validate_audit_continuation_manifest(args,manifest)
    validate_external_profile(manifest)
    required=set(REQUIRED)
    if getattr(args,'audit_continuation',False):required.add('db/postgres/identity-migrations/0128_audit_judge_stage_checkpoints.sql')
    if content_mode(args)!='actual':required.update({'tests/secureshopMailRenderedQualification.test.js','tests/postgres/test_mail_browser_main_launcher.py'})
    if content_mode(args)=='audit-instruction-actual':required.update({'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopAuditRuntimeLifecycle.js','server/agent-runtime/workers/secureshopAuditWorker.js','server/services/secureshopAuditModelChain.js','server/services/secureshopAuditSourceManifest.js','server/database/postgres/secureshopAuditSnapshot.js','server/database/postgres/secureshopAuditRunReader.js','server/services/secureshopPromptPolicyActivation.js','server/database/postgres/secureshopBoundAclRepository.js'})
    if content_mode(args)=='ssrf-actual':required.update({'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopSsrfProduction.js','server/services/secureshopSsrfAssessment.js','server/services/secureshopSsrfEvidence.js','server/services/secureshopSsrfTargetPool.js','agent-host/agents/summarizer/server.js','server/services/secureshopPromptPolicyActivation.js','server/database/postgres/secureshopBoundAclRepository.js'})
    if content_mode(args)=='mcp-trust-actual':required.update({'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopMcpTrustProduction.js','server/services/secureshopMcpTrustAssessment.js','server/services/secureshopMcpTrustEvidence.js','server/services/secureshopMcpSdkTransport.js','server/services/secureshopPromptPolicyActivation.js','server/database/postgres/secureshopBoundAclRepository.js'})
    if content_mode(args)=='inbox-actual':required.update({'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopPersonaInboxComposition.js','server/services/secureshopPersonaInboxApplication.js','server/services/secureshopPersonaInboxAssessment.js','server/services/secureshopPersonaInboxEvidence.js'})
    if content_mode(args)=='review-batch-actual':required.update({'tests/postgres/secureshopMailBrowserJudgeTransport.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopBoundReviewModeration.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundReviewRuntime.js','server/services/secureshopReviewExecutionConfig.js','server/services/secureshopReviewRunProjection.js','server/services/secureshop/providers/ollamaProvider.js','server/agent-runtime/secureshopSupervisorGraph.js','server/services/secureshopStandaloneAuth.js','server/services/secureshopStandaloneBootstrap.js','server/services/secureshopStandaloneReset.js','server/services/secureshopBoundApplication.js','client/src/pages/secureshop/pages/merchant/Reviews.jsx'})
    if content_mode(args)=='standalone-disclosure-actual':required.update({'tests/fixtures/secureshopStandaloneMailDisclosureQualification.js','tests/fixtures/secureshopMailDisclosureBrowser.js','tests/postgres/secureshopMailActualTransport.js','tests/postgres/test_mail_browser_main_launcher.py','server/services/secureshopMailDisclosureEvidence.js','server/services/secureshopMailProduction.js','server/services/secureshopStandaloneAuth.js','server/services/secureshopStandaloneBootstrap.js','server/services/secureshopStandaloneReset.js','server/services/secureshopBoundApplication.js','server/services/secureshopBoundReviewComposition.js','server/routes/secureshop/boundMail.js','server/agent-runtime/objectiveJudge.js','client/src/pages/secureshop/pages/merchant/Inbox.jsx'})
    if content_mode(args)=='review-followed-actual':required.update({'tests/fixtures/renderedSecureShopReviewWorkflow.js','tests/renderedSecureShopReviewWorkflow.test.js','tests/fixtures/secureshopReviewModerationComparisonCalibration.js','tests/secureshopMailBrowserJudgeTransport.test.js','server/services/secureshopBoundReviewModeration.js','server/services/secureshopBoundReviewComposition.js','server/services/secureshopBoundReviewRuntime.js','server/services/secureshopReviewExecutionConfig.js','server/services/secureshop/providers/ollamaProvider.js','server/agent-runtime/secureshopSupervisorGraph.js','server/services/secureshopReviewContentAssessment.js','server/services/secureshopReviewContentEvidence.js','server/services/secureshopLoopAssessment.js','server/services/secureshopLoopEvidence.js','server/agent-runtime/objectiveJudge.js','server/agent-runtime/reviewModerationComparison.js','server/agent-runtime/reviewModerationAudit.js'})
    validate_actual_input(args,source,manifest)
    if content_mode(args)=='review-followed-actual' and manifest.get('sourcePins',{}).get('tests/fixtures/secureshopReviewModerationComparisonCalibration.js')!='ebf0a925b5975be2dcaabc84b640a029cbfdec165232c410d1f9891f81154b94':raise RuntimeError('Frozen review cohort source mismatch')
    for directory in ['db/postgres/identity-migrations',*[f'db/postgres/workshop-migrations/{store}' for store in ('secureshop','secureshop_agents','secureshop_review')]]:
        required.update(p.relative_to(source).as_posix() for p in (source/directory).glob('*.sql'))
    if not required.issubset(manifest.get('sourcePins',{})):raise RuntimeError('Required source pins missing')
    for rel,pin in manifest['sourcePins'].items():
        p=source/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(source) or digest(p)!=pin:raise RuntimeError('Main source mismatch')
    if inventory(source/'node_modules')!=manifest.get('dependencyInventory'):raise RuntimeError('Main dependency mismatch')
    for value,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        p=Path(value)
        if not p.is_absolute() or p.resolve()!=p or p.is_symlink() or digest(p)!=pin:raise RuntimeError('Canonical runtime pin mismatch')
    validate_running_python(args.python_sha256)
    browser=Path(args.browser);browser_root=Path(args.browser_root)
    if not browser.is_absolute() or browser.resolve()!=browser or not browser_root.is_absolute() or browser_root.resolve()!=browser_root or not browser.is_relative_to(browser_root) or digest(browser)!=args.browser_sha256:raise RuntimeError('Canonical browser pin mismatch')
    if manifest.get('browserRoot')!=str(browser_root) or manifest.get('browserExecutable')!=str(browser):raise RuntimeError('Browser manifest binding mismatch')
    if inventory(browser_root)!=manifest.get('browserInventory') or not manifest.get('browserInventory'):raise RuntimeError('Browser tree mismatch')
    build=Path(manifest['externalBuildRoot']) if manifest.get('externalBuildRoot') is not None else source/'client/build'
    if not build.is_absolute() or build.resolve()!=build or (manifest.get('externalBuildRoot') is not None and build.is_relative_to(source)):raise RuntimeError('Invalid external build root')
    renderer=build/'secureshop-mail-renderer'
    if not manifest.get('rendererInventory') or inventory(renderer)!=manifest['rendererInventory']:raise RuntimeError('Mail renderer mismatch')
    renderer_manifest=json.loads((renderer/'manifest.json').read_text())
    for field in ('source','entry'):
        rel=renderer_manifest[field]
        if rel not in manifest['sourcePins'] or digest(source/rel)!=renderer_manifest[field+'Sha256']:raise RuntimeError('Renderer source mismatch')
    if digest(renderer/'renderer.js')!=renderer_manifest['artifactSha256']:raise RuntimeError('Renderer artifact mismatch')
    if not manifest.get('clientBuildInventory') or inventory(build)!=manifest['clientBuildInventory']:raise RuntimeError('Current application build mismatch')
    helper=source/'tests/postgres/run-finflow-backup-browser-main.py'
    spec=importlib.util.spec_from_file_location('mail_build_provenance',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if Path(module.__file__).resolve()!=helper:raise RuntimeError('Build admission origin mismatch')
    module.validate_build_provenance(source,manifest)
    return source,manifest

def validate_running_python(expected):
    # Homebrew may report its opt alias even when launched via the Cellar binary.
    reported=Path(sys.executable)
    if not reported.is_absolute():raise RuntimeError('Absolute running Python required')
    resolved=reported.resolve(strict=True)
    if not resolved.is_file() or digest(resolved)!=expected:raise RuntimeError('Running Python pin mismatch')
    return resolved

def publish(target,value):
    fd,temporary=tempfile.mkstemp(prefix='.journal-',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(temporary,target)
        fd=os.open(target.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)

def check_logs(evidence):
    total=0
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            try:metadata=p.lstat()
            except FileNotFoundError:continue # Chrome can retire transient profile entries between samples.
            if stat.S_ISLNK(metadata.st_mode):
                profile=evidence/'runtime'/'browser-profile'
                # The owned browser profile is opaque runtime data, not evidence authority.
                # Do not follow or inspect any link target within it.
                if p!=profile and p.is_relative_to(profile) and profile.resolve()==profile and profile.is_dir() and profile.stat().st_uid==os.getuid():
                    continue
                raise RuntimeError('Owned evidence link')
            if stat.S_ISREG(metadata.st_mode) and p.suffix in ('.tap','.log'):total+=metadata.st_size
    if total>64*1024**2:raise RuntimeError('Aggregate log cap')
    return total

def owned_ready_args(container):
    return ['exec',container,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres']

def owned_psql_args(container, interactive=False):
    return ['exec',*(['-i'] if interactive else []),container,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate']

def command_projection(response):
    # Never expose command text, SQL, rows, credentials, or raw stderr.
    stderr=response.stderr or '';stdout=response.stdout or ''
    import re
    states=sorted(set(re.findall(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5})(?:\s|$)',stderr)))[:8]
    return {'exitCode':response.returncode,'stdoutBytes':len(stdout.encode()),'stderrBytes':len(stderr.encode()),
            'stdoutSha256':hashlib.sha256(stdout.encode()).hexdigest(),'stderrSha256':hashlib.sha256(stderr.encode()).hexdigest(),'sqlStates':states}

def checked_command(response, code, state):
    state['lastCommand']=command_projection(response)
    if response.returncode:raise RuntimeError(code)
    return response

def store_configuration(label,port,nonce):
    import re
    if label not in ('identity','secureshop','secureshop_agents','secureshop_review') or type(port) is not int or not 1<=port<=65535 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Closed store/port/nonce required')
    migration='dvaia_'+label+'_migration';role='dvaia_'+label+'_runtime';database='dvaia_test_mail_browser_'+nonce+'_'+label
    sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{role};'
    prefix={'identity':'IDENTITY','secureshop':'COMMERCE','secureshop_agents':'AGENTS','secureshop_review':'REVIEW'}[label]
    return sql,{'MAIL_'+prefix+suffix:f'postgresql://{username}@127.0.0.1:{port}/{database}' for suffix,username in [('_MIGRATION_URL',migration),('_RUNTIME_URL',role)]}


def validate_actual_input(args,source,manifest):
    expected=source/ACTUAL_INPUT
    if args.input!=str(expected) or args.input_sha256!=ACTUAL_INPUT_SHA256 or expected.is_symlink() or expected.resolve()!=expected:raise RuntimeError('Exact frozen actual input required')
    if manifest.get('sourcePins',{}).get(ACTUAL_INPUT)!=ACTUAL_INPUT_SHA256 or digest(expected)!=ACTUAL_INPUT_SHA256:raise RuntimeError('Frozen input pin mismatch')


def child_environment(clean,evidence,runtime,owner,args):
    return {**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres',
      'JWT_SECRET':secrets.token_urlsafe(48),'PG_TEST_DISPOSABLE':'yes','MAIL_BROWSER_NATIVE':'1',
      'MAIL_BROWSER_EVIDENCE_ROOT':str(evidence),'MAIL_BROWSER_OWNER':owner,'MAIL_BROWSER_SOURCE_ROOT':args.main_workspace,
      'MAIL_BROWSER_MANIFEST':str(Path(args.manifest).resolve()),'MAIL_BROWSER_MANIFEST_SHA256':args.manifest_sha256,
      'MAIL_BROWSER_INPUTS':args.input,'MAIL_BROWSER_INPUTS_SHA256':args.input_sha256,
      'MAIL_BROWSER_CHROME':args.browser,'MAIL_BROWSER_CHROME_SHA256':args.browser_sha256,
      'ANALYTICS_BROWSER_EXECUTABLE':args.browser,'ANALYTICS_BROWSER_SHA256':args.browser_sha256,
      **({('MAIL_BROWSER_ANALYTICS_DISCLOSURE_CONTENT' if getattr(args,'analytics_disclosure_content',False) else 'MAIL_BROWSER_AUDIT_INSTRUCTION_CONTENT' if getattr(args,'audit_instruction_content',False) else 'MAIL_BROWSER_SSRF_CONTENT' if getattr(args,'ssrf_content',False) else 'MAIL_BROWSER_MCP_TRUST_CONTENT' if getattr(args,'mcp_trust_content',False) else 'MAIL_BROWSER_INBOX_CONTENT' if getattr(args,'inbox_content',False) else 'MAIL_BROWSER_STORED_BROWSER_CONTENT' if getattr(args,'stored_browser_content_lifecycle',False) else 'MAIL_BROWSER_PRICING_DISCLOSURE_CONTENT' if getattr(args,'pricing_disclosure_content',False) else 'MAIL_BROWSER_REVIEW_FOLLOWED_CONTENT' if getattr(args,'review_followed_content',False) else 'MAIL_BROWSER_REVIEW_PERSIST_CONTENT' if getattr(args,'review_persist_content',False) else 'MAIL_BROWSER_AUDIT_SQL_CONTENT' if getattr(args,'audit_sql_content',False) else 'MAIL_BROWSER_LOOP_CONTENT' if getattr(args,'loop_content_lifecycle',False) else 'MAIL_BROWSER_LISTINGS_CONTENT' if getattr(args,'listings_content',False) else 'MAIL_BROWSER_CONTENT_ONLY'):'1','AI_PROVIDER':'mock','JUDGE_PROVIDER':'mock','OLLAMA_BASE_URL':'http://127.0.0.1:1'} if content_mode(args) not in ('actual','standalone-disclosure-actual','inbox-actual','mcp-trust-actual','ssrf-actual','audit-instruction-actual','review-followed-actual','review-batch-actual') else {}),
      **({'MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false','DVAIA_MAIL_BROWSER_BUILD_ROOT':str(Path(args.main_workspace)/'client/build')} if content_mode(args)=='standalone-disclosure-actual' else {}),
      **({'AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false','DVAIA_MAIL_BROWSER_BUILD_ROOT':str(Path(args.main_workspace)/'client/build')} if content_mode(args)=='actual' else {}),
      **({'MAIL_BROWSER_REVIEW_BATCH_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false'} if content_mode(args)=='review-batch-actual' else {}),
      **({'MAIL_BROWSER_REVIEW_FOLLOWED_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false'} if content_mode(args)=='review-followed-actual' else {}),
      **({'MAIL_BROWSER_AUDIT_INSTRUCTION_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.3:70b' if getattr(args,'audit_70b',False) else 'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false',**({'MAIL_BROWSER_AUDIT_70B':'1',**({'MAIL_BROWSER_AUDIT_CONTINUATION':'1'} if getattr(args,'audit_continuation',False) else {}),'SS_AUDIT_RUN_TIMEOUT_MS':'290000','SS_AUDIT_JUDGE_TIMEOUT_MS':'240000'} if getattr(args,'audit_70b',False) else {})} if content_mode(args)=='audit-instruction-actual' else {}),
      **({'MAIL_BROWSER_SSRF_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false'} if content_mode(args)=='ssrf-actual' else {}),
      **({'MAIL_BROWSER_MCP_TRUST_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b','SS_BOUND_PROMPT_POLICIES_ENABLED':'false'} if content_mode(args)=='mcp-trust-actual' else {}),
      **({'MAIL_BROWSER_INBOX_ACTUAL':'1','AI_PROVIDER':'ollama','JUDGE_PROVIDER':'ollama','OLLAMA_MODEL':'llama3.1:8b'} if content_mode(args)=='inbox-actual' else {}),
      'DVAIA_APP_DATA_ROOT':str(runtime/'appdata'),
      'AWS_EC2_METADATA_DISABLED':'true','LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'PG_TLS':'disable'}

def verify_browser_absence(runtime,state,rows):
    journal=runtime/'browser-process.json'
    if not journal.exists():
        if state.get('exitCode')==0 and (state.get('mode') not in ('inbox-actual','mcp-trust-actual','ssrf-actual','audit-instruction-actual','review-followed-actual','review-batch-actual') or (state.get('mode')=='audit-instruction-actual' and state.get('audit70b') is True)):raise RuntimeError('Missing browser ownership evidence')
        return {'started':False,'profileRetained':True}
    st=journal.lstat()
    if journal.is_symlink() or not journal.is_file() or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>65536:raise RuntimeError('Private browser journal required')
    browser=json.loads(journal.read_text());native=state['nativePid']
    for key in ['pgid','sessionId','qualificationPid','qualificationPgid','qualificationSessionId','workerPid']:
        if browser.get(key)!=native:raise RuntimeError('Browser ownership mismatch')
    if browser.get('uid')!=os.getuid() or browser.get('profile')!=str(runtime/'browser-profile') or browser.get('executableSha256')!=state['browserSha256']:raise RuntimeError('Browser profile/binary mismatch')
    if type(browser.get('pid'))is not int or browser['pid']<=0 or browser['pid']==native:raise RuntimeError('Browser PID invalid')
    if any(pid==browser['pid'] or group==native for pid,group,uid in rows):raise RuntimeError('Browser group remains')
    return {'started':True,'browserPidAbsent':True,'groupAbsent':True,'profileRetained':True}

def main_parser():
    parser=argparse.ArgumentParser(description='Explicit main-only SecureShop saved-mail browser qualification',allow_abbrev=False)
    for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--input',required=True)
    parser.add_argument('--input-sha256',required=True)
    parser.add_argument('--plan',action='store_true')
    parser.add_argument('--standalone-disclosure-actual',action='store_true')
    parser.add_argument('--review-batch-actual',action='store_true')
    parser.add_argument('--review-followed-actual',action='store_true')
    parser.add_argument('--audit-instruction-actual',action='store_true')
    parser.add_argument('--audit-70b',action='store_true')
    parser.add_argument('--audit-continuation',action='store_true')
    parser.add_argument('--audit-instruction-content',action='store_true')
    parser.add_argument('--ssrf-content',action='store_true')
    parser.add_argument('--ssrf-actual',action='store_true')
    parser.add_argument('--mcp-trust-actual',action='store_true')
    parser.add_argument('--inbox-actual',action='store_true')
    parser.add_argument('--mcp-trust-content',action='store_true')
    parser.add_argument('--inbox-content',action='store_true')
    parser.add_argument('--content-only',action='store_true')
    parser.add_argument('--listings-content',action='store_true')
    parser.add_argument('--loop-content-lifecycle',action='store_true')
    parser.add_argument('--audit-sql-content',action='store_true')
    parser.add_argument('--analytics-disclosure-content',action='store_true')
    parser.add_argument('--review-followed-content',action='store_true')
    parser.add_argument('--review-persist-content',action='store_true')
    parser.add_argument('--stored-browser-content-lifecycle',action='store_true')
    parser.add_argument('--pricing-disclosure-content',action='store_true')
    return parser

def parse_main(argv):
    flags=[value.split('=',1)[0] for value in argv if value.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flags denied')
    args=main_parser().parse_args(argv)
    if sum([args.standalone_disclosure_actual,args.analytics_disclosure_content,args.review_batch_actual,args.review_followed_actual,args.audit_instruction_actual,args.audit_instruction_content,args.ssrf_actual,args.ssrf_content,args.mcp_trust_actual,args.mcp_trust_content,args.inbox_actual,args.inbox_content,args.stored_browser_content_lifecycle,args.content_only,args.listings_content,args.loop_content_lifecycle,args.audit_sql_content,args.review_followed_content,args.review_persist_content,args.pricing_disclosure_content])>1:raise ValueError("Exclusive content profile required")
    if args.audit_70b and not args.audit_instruction_actual:raise ValueError('Audit 70B requires Audit actual profile')
    if args.audit_continuation and not args.audit_70b:raise ValueError('Audit continuation requires Audit 70B')
    return args

def audit_time_limits(args):
    return (1350,1200) if getattr(args,'audit_continuation',False) else (990,850) if getattr(args,'audit_70b',False) else (780,600)

def main_current(argv):
    args=parse_main(argv)
    source,manifest=validate_main(args)
    work_seconds,child_seconds=audit_time_limits(args)
    if args.plan:
        print(json.dumps({'cohort':COHORT,'mode':content_mode(args),'stores':['identity','secureshop','secureshop_agents','secureshop_review'],'syntheticProvider':False,'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':120,'integritySeconds':120,'allocation':False}));return 0
    # Exact helper bytes admitted above; no dynamic code import before source/pin validation.
    def load(name):
        p=source/'tests/postgres'/f'{name}.py';spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if Path(module.__file__).resolve()!=p:raise RuntimeError('Helper origin mismatch')
        return module
    processes_module=load('sql_nosql_process_ownership');docker_module=load('sql_nosql_docker_ownership')
    if shutil.disk_usage(source).free<2*1024**3+1024**3+2*256*1024**2+64*1024**2:raise RuntimeError('Owned runtime/artifact space plus2GiB reserve required')
    parent=source/'backups/private-recovery/mail-browser';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private main evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
    for name in ['home','tmp','logs','assets','appdata','downloads']:(runtime/name).mkdir(mode=0o700)
    clean={'PATH':str(Path(args.node).parent)+':'+str(Path(args.docker).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LANG':'C','DOCKER_HOST':args.docker_host}
    owner=str(uuid.uuid4());name='dvaia-mail-browser-'+uuid.uuid4().hex[:12];labels={'dvaia.owner':owner,'dvaia.cohort':COHORT}
    state={'cohort':COHORT,'sourceRoot':str(source),'parentPid':os.getpid(),'owner':owner,'children':[],'nativeStarted':False,'audit70b':args.audit_70b,'auditContinuation':args.audit_continuation,'mode':content_mode(args),'manifestSha256':args.manifest_sha256,'containerName':name,'containerLabels':labels,'imageId':args.image_id,'dockerDaemon':args.docker_daemon,'creationAttempted':False,'scenario':'mail-browser','nonce':owner.replace('-','')[:12],'evidenceRoot':str(evidence),'browserSha256':args.browser_sha256}
    def record():publish(evidence/'ownership.json',state)
    deadline=time.monotonic()+work_seconds
    def remaining(maximum):
        result=min(maximum,deadline-time.monotonic())
        if result<=0:raise TimeoutError('Qualification deadline')
        return result
    def command(argv,input=None):return subprocess.run([args.docker,'--host',args.docker_host,*argv],input=input,env=clean,capture_output=True,text=True,timeout=remaining(30))
    def members(pgid,sid):
        output=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=remaining(2));found=[]
        for line in output.stdout.splitlines():
            pid,group,uid=map(int,line.split())
            if group!=pgid:continue
            try:
                if uid!=os.getuid() or os.getsid(pid)!=sid:raise RuntimeError('Unknown process group identity')
            except ProcessLookupError:continue
            found.append(pid)
        return found
    def stop_group(child,pgid,sid):
        if members(pgid,sid):os.killpg(pgid,signal.SIGTERM)
        until=time.monotonic()+remaining(10)
        while members(pgid,sid) and time.monotonic()<until:child.poll();time.sleep(.05)
        if members(pgid,sid):os.killpg(pgid,signal.SIGKILL)
        child.wait(timeout=remaining(10))
        until=time.monotonic()+remaining(5)
        while members(pgid,sid) and time.monotonic()<until:time.sleep(.05)
        if members(pgid,sid):raise RuntimeError('Owned descendants remain')
    owned=processes_module.OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));owned.install()
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Absolute phase deadline')))
    signal.setitimer(signal.ITIMER_REAL,work_seconds)
    attempted=False;captured=None;code=1;failures=[]
    def phase(value):state['stage']=value;record()
    try:
        phase('runtime-authority');docker_module.verify_daemon(command,args.docker_daemon);docker_module.verify_image(command,args.image_id)
        if docker_module.inspect_owned(command,name=name,labels=labels,image=args.image_id) is not None:raise RuntimeError('Container already exists')
        attempted=True;state['creationAttempted']=True;phase('container-create')
        response=command(['run','--detach','--pull','never','--name',name,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--memory','1024m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',args.image_id,'-c','max_connections=64','-c','shared_buffers=32MB'])
        checked_command(response,'CONTAINER_CREATE_FAILED',state)
        phase('container-layout')
        row=docker_module.inspect_owned(command,name=name,labels=labels,image=args.image_id);captured=row['Id'];state['containerId']=captured
        h=row['HostConfig'];ports=row['NetworkSettings']['Ports']
        if row['Mounts'] or h['Memory']!=1073741824 or h['NanoCpus']!=2000000000 or h['PidsLimit']!=256 or h['Tmpfs']!={'/var/lib/postgresql':'rw,size=1073741824'} or set(ports)!={'5432/tcp'} or len(ports['5432/tcp'])!=1 or ports['5432/tcp'][0]['HostIp']!='127.0.0.1':raise RuntimeError('Owned PostgreSQL layout mismatch')
        port=int(ports['5432/tcp'][0]['HostPort']);state['databasePort']=port;record()
        phase('postgres-tcp-readiness')
        for _ in range(100):
            ready=command(owned_ready_args(captured));state['lastCommand']=command_projection(ready)
            if ready.returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Owned PostgreSQL readiness deadline')
        phase('empty-cluster-check')
        check=checked_command(command(owned_psql_args(captured)+['-Atc',"SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"]),'EMPTY_CLUSTER_QUERY_FAILED',state)
        if check.returncode or check.stdout.strip()!='0':raise RuntimeError('Empty owned cluster required')
        env=child_environment(clean,evidence,runtime,owner,args)
        if manifest.get('externalBuildRoot') is not None:env['DVAIA_MAIL_BROWSER_BUILD_ROOT']=manifest['externalBuildRoot']
        for label in ['identity','secureshop','secureshop_agents','secureshop_review']:
            sql,urls=store_configuration(label,port,owner.replace('-','')[:12])
            phase('provision-'+label)
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            env.update(urls)
        phase('native-launch')
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=owned.launch([args.node,str(source/'tests/postgres/secureshopMailBrowser.integration.test.js')],name='mail-browser',cwd=runtime,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(nativeStarted=True,nativePid=child.pid);record();child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
            until=time.monotonic()+remaining(child_seconds)
            while child.poll() is None:
                check_logs(evidence)
                if time.monotonic()>=until:raise TimeoutError('Native child deadline')
                time.sleep(.1)
            code=child.returncode;owned.finish(child);check_logs(evidence)
        state['exitCode']=code
        if code==0:
            result_file=evidence/'result.json'
            if result_file.is_symlink() or result_file.stat().st_size>262144:raise RuntimeError('Bounded result required')
            result=json.loads(result_file.read_text())
            if result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Successful child receipt required')
            if content_mode(args)=='review-batch-actual':
                validate_review_batch_actual_result(result,json.loads((evidence/'wire.json').read_text()))
            elif content_mode(args)=='standalone-disclosure-actual':
                validate_standalone_disclosure_actual_result(result,json.loads(read_private_manifest(evidence/'standalone-disclosure-wire.json')))
            elif content_mode(args)=='review-followed-actual':
                validate_review_followed_actual_result(result,json.loads((evidence/'wire.json').read_text()))
            elif content_mode(args)=='audit-instruction-actual':
                validate_audit_instruction_actual_result(result,json.loads((evidence/'wire.json').read_text()),audit70b=args.audit_70b,audit_continuation=args.audit_continuation,captures=json.loads(read_private_manifest(evidence/'audit-instruction-captures.json',64*1024*1024)) if args.audit_continuation else None)
            elif content_mode(args)=='ssrf-actual':
                validate_ssrf_actual_result(result,json.loads((evidence/'wire.json').read_text()))
            elif content_mode(args)=='mcp-trust-actual':
                validate_mcp_trust_actual_result(result,json.loads((evidence/'wire.json').read_text()))
            elif content_mode(args)=='inbox-actual':
                validate_inbox_actual_result(result,json.loads((evidence/'wire.json').read_text()))
            elif content_mode(args)!='actual':
                validate_content_result(result,content_mode(args))
                if (evidence/'wire.json').exists() or list(evidence.glob('judge-transcript-*.json')):raise RuntimeError('Content-only inference evidence forbidden')
    except BaseException as error:
        safe={'Owned evidence link','Aggregate log cap','CONTAINER_CREATE_FAILED','EMPTY_CLUSTER_QUERY_FAILED','STORE_PROVISION_FAILED','Owned PostgreSQL readiness deadline','Empty owned cluster required','Owned PostgreSQL layout mismatch','Native child deadline','Qualification deadline','Absolute phase deadline'}
        state['primaryFailure']={'type':type(error).__name__,'stage':state.get('stage'),'code':str(error) if str(error) in safe else None};code=1
    finally:
        deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120);owned.mask_cleanup_signals()
        try:
            try:owned.cleanup()
            except BaseException as error:failures.append({'phase':'process-cleanup','type':type(error).__name__})
            try:check_logs(evidence)
            except BaseException as error:failures.append({'phase':'log-bound','type':type(error).__name__})
            try:
                roster=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=remaining(2))
                state['browserCleanup']=verify_browser_absence(runtime,state,[tuple(map(int,line.split()))for line in roster.stdout.splitlines()])
            except BaseException as error:failures.append({'phase':'browser-absence','type':type(error).__name__})
            try:
                if attempted:state['containerCleanup']=docker_module.cleanup_owned(command,daemon_id=args.docker_daemon,name=name,labels=labels,image=args.image_id,captured_id=captured)
            except BaseException as error:failures.append({'phase':'container-cleanup','type':type(error).__name__})
            deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120)
            try:validate_main(args);state['sourceUnchanged']=True
            except BaseException as error:failures.append({'phase':'integrity','type':type(error).__name__})
            state['cleanupFailures']=failures;state['status']='passed' if code==0 and not failures else 'failed';record()
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
    print(json.dumps({'evidenceRoot':str(evidence),'status':state.get('status','failed')}))
    return 0 if state.get('status')=='passed' else 1



def validate_standalone_disclosure_actual_result(result,capture):
    proof=result.get('standaloneDisclosure')
    if (result.get('profile')!='standalone-disclosure-actual' or result.get('status')!='passed'
        or result.get('cleanupFailures')!=[] or not isinstance(proof,dict)):
        raise RuntimeError('M23 standalone disclosure receipt required')
    expected_checks=['rendered_foreign_read','actual_judge_observed','saved_get_no_replay',
                     'own_empty_fixed_denied','session_reset_sibling_fenced']
    if (proof.get('status')!='assertions_passed' or proof.get('actualQualification') is not False
        or proof.get('objectiveId')!='ss_mail_cross_persona_read'
        or proof.get('checks')!=expected_checks):
        raise RuntimeError('M23 exact rendered/Judge/fence assertions required')
    for key in ['readOperationId','assessmentRequestId']:
        value=proof.get(key)
        try:valid=type(value) is str and str(uuid.UUID(value))==value
        except (ValueError,AttributeError):valid=False
        if not valid:raise RuntimeError('M23 saved operation identity required')
    judged=proof.get('judgeCalls')
    if (type(judged) is not int or not 1<=judged<=3 or type(proof.get('apiRequests')) is not int
        or not 1<=proof['apiRequests']<=128 or result.get('actualActorCalls')!=0
        or result.get('judgeCalls')!=judged or result.get('modelCalls')!=judged
        or result.get('genuineCredit')!=1):
        raise RuntimeError('M23 genuine credit and bounded request counters required')
    if not isinstance(capture,dict) or set(capture)!={'wire','transcripts'}:
        raise RuntimeError('M23 private raw model capture required')
    wire=capture['wire'];transcripts=capture['transcripts']
    model='llama3.1:8b';model_digest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
    if (not isinstance(wire,dict) or wire.get('model')!=model or wire.get('digest')!=model_digest
        or not isinstance(wire.get('calls'),list) or len(wire['calls'])!=judged
        or not isinstance(transcripts,list) or len(transcripts)!=1):
        raise RuntimeError('M23 pinned genuine Judge wire required')
    for index,call in enumerate(wire['calls'],1):
        if (not isinstance(call,dict) or call.get('index')!=index or call.get('kind')!='judge'
            or call.get('model')!=model or call.get('status')!=200
            or call.get('responseComplete') is not True or call.get('responseCaptureTruncated') is not False
            or call.get('terminalReason')!='end' or call.get('error') is not None):
            raise RuntimeError('M23 complete returned Judge call required')
        for field in ['request','response']:
            raw=call.get(field)
            if (type(raw) is not str or not raw or hashlib.sha256(raw.encode()).hexdigest()!=call.get(field+'Sha256')):
                raise RuntimeError('M23 exact raw Judge bytes required')
        if (call.get('requestBytes')!=len(call['request'].encode())
            or call.get('responseBytes')!=len(call['response'].encode())
            or call.get('responseObservedBytes')!=call['responseBytes']):
            raise RuntimeError('M23 untruncated Judge byte counts required')
        request=json.loads(call['request'])
        if request.get('model')!=model or not isinstance(request.get('messages'),list):
            raise RuntimeError('M23 configured Judge request required')
    transcript=transcripts[0]
    if (not isinstance(transcript,dict) or transcript.get('version')!=1
        or transcript.get('complete') is not True or transcript.get('failure') is not None
        or type(transcript.get('transcriptSha256')) is not str
        or len(transcript['transcriptSha256'])!=64
        or not isinstance(transcript.get('calls'),list) or len(transcript['calls'])!=judged):
        raise RuntimeError('M23 complete Judge transcript required')
    accepted=[]
    for index,call in enumerate(transcript['calls']):
        metadata=call.get('metadata') if isinstance(call,dict) else None
        if (not isinstance(metadata,dict) or metadata.get('provider')!='ollama'
            or metadata.get('model')!=model or metadata.get('mocked') is not False
            or metadata.get('fallback') is not False or call.get('transport')!='returned'
            or call.get('disposition') not in ('accepted','rejected')
            or type(call.get('response')) is not str
            or hashlib.sha256(call['response'].encode()).hexdigest()!=call.get('responseSha256')):
            raise RuntimeError('M23 genuine attributed Judge transcript required')
        if call['disposition']=='accepted':accepted.append(call)
        request=json.loads(wire['calls'][index]['request'])
        if request.get('messages')!=call.get('request',{}).get('input'):
            raise RuntimeError('M23 exact wire/transcript request mismatch')
        observed=''.join(json.loads(line).get('message',{}).get('content','')
                         for line in wire['calls'][index]['response'].splitlines() if line.strip())
        if observed!=call['response']:
            raise RuntimeError('M23 exact wire/transcript response mismatch')
    if len(accepted)!=1 or accepted[0].get('stage')!='primary':
        raise RuntimeError('M23 one accepted primary Judge decision required')
    decision=json.loads(accepted[0]['response']);outcome=transcript.get('outcome')
    if (decision.get('verdict')!='pass' or not isinstance(outcome,dict)
        or type(outcome.get('bytes')) is not str
        or hashlib.sha256(outcome['bytes'].encode()).hexdigest()!=outcome.get('sha256')
        or json.loads(outcome['bytes'])!=outcome.get('value')
        or not isinstance(outcome.get('value'),dict) or outcome['value'].get('verdict')!='pass'):
        raise RuntimeError('M23 passing observed Judge decision required')

def validate_inbox_actual_result(result,wire):
    proof=result.get('inboxActual',{})
    if result.get('profile')!='inbox-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Inbox actual receipt required')
    if proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True or proof.get('qualifiedObjectiveIds')!=INBOX_CONTENT_IDS or proof.get('genuineCredit')!=3:raise RuntimeError('Exact genuine Inbox objectives required')
    if proof.get('cases')!=[{'id':id,'replay':True} for id in ['advisory','enforced']]:raise RuntimeError('Fixed Inbox cases required')
    for key in ['sessionDenied','reset','immutablePreserved','siblingPreserved']:
        if proof.get(key) is not True:raise RuntimeError('Inbox lifecycle missing')
    if wire.get('version')!='inbox-actual-wire-v1' or wire.get('closed') is not True or wire.get('failed') is not False or wire.get('physicalPending')!=0:raise RuntimeError('Inbox wire retirement required')
    calls=wire.get('calls',[])
    if not calls or len(calls)>81 or calls[0].get('role')!='tags' or calls[0].get('caseId') is not None:raise RuntimeError('Inbox startup metadata required')
    counts={role:0 for role in ['actor','judge','tags']};phases={id:{'actor':0,'judge':0} for id in ['advisory','enforced']};seen=[]
    for index,row in enumerate(calls):
        role=row.get('role');case=row.get('caseId')
        if row.get('index')!=index or row.get('status')!='returned' or row.get('httpStatus')!=200 or role not in counts:raise RuntimeError('Inbox wire incomplete')
        for key in ['request','response']:
            if not isinstance(row.get(key),str) or hashlib.sha256(row[key].encode()).hexdigest()!=row.get(key+'Sha256'):raise RuntimeError('Inbox raw digest mismatch')
        counts[role]+=1
        if index:
            if role=='tags' or case not in phases:raise RuntimeError('Inbox phase scope')
            if not seen or seen[-1]!=case:seen.append(case)
            phases[case][role]+=1
    if seen!=['advisory','enforced'] or counts!=wire.get('counts') or phases!=wire.get('phaseCounts'):raise RuntimeError('Inbox exact wire counters')
    if counts['tags']!=1 or not 1<=counts['actor']<=32 or not 1<=counts['judge']<=48:raise RuntimeError('Inbox wire budget')
    for id,judge_cap in [('advisory',32),('enforced',16)]:
        if not 1<=phases[id]['actor']<=16 or not 1<=phases[id]['judge']<=judge_cap:raise RuntimeError('Inbox phase budget')
    if proof.get('actorCalls')!=counts['actor'] or proof.get('judgeCalls')!=counts['judge']:raise RuntimeError('Inbox proof wire mismatch')

def validate_mcp_trust_actual_result(result,wire):
    proof=result.get('mcpTrustActual',{})
    if result.get('profile')!='mcp-trust-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('MCP trust actual receipt required')
    if proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True or proof.get('qualifiedObjectiveIds')!=MCP_TRUST_CONTENT_IDS or proof.get('genuineCredit')!=2:raise RuntimeError('Exact genuine MCP trust objectives required')
    if proof.get('cases')!=[{'id':id,'replay':True} for id in ['rogue','baseline','changed']]:raise RuntimeError('Fixed MCP trust cases required')
    for key in ['sessionDenied','reset','immutablePreserved','siblingPreserved','ownedTargetsRetired']:
        if proof.get(key) is not True:raise RuntimeError('MCP trust lifecycle missing')
    if wire.get('version')!='mcp-trust-actual-wire-v1' or wire.get('closed') is not True or wire.get('failed') is not False or wire.get('physicalPending')!=0:raise RuntimeError('MCP trust wire retirement required')
    if proof.get('policyScope')!={'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False}:raise RuntimeError('Current production default policy required')
    calls=wire.get('calls',[])
    if not calls or len(calls)>113 or calls[0].get('role')!='tags' or calls[0].get('caseId') is not None:raise RuntimeError('MCP trust startup metadata required')
    counts={role:0 for role in ['actor','judge','tags']};phases={id:{'actor':0,'judge':0} for id in ['rogue','baseline','changed']};seen=[]
    for index,row in enumerate(calls):
        role=row.get('role');case=row.get('caseId')
        if row.get('index')!=index or row.get('status')!='returned' or row.get('httpStatus')!=200 or role not in counts:raise RuntimeError('MCP trust wire incomplete')
        for key in ['request','response']:
            if not isinstance(row.get(key),str) or hashlib.sha256(row[key].encode()).hexdigest()!=row.get(key+'Sha256'):raise RuntimeError('MCP trust raw digest mismatch')
        counts[role]+=1
        if index:
            if role=='tags' or case not in phases:raise RuntimeError('MCP trust phase scope')
            if not seen or seen[-1]!=case:seen.append(case)
            phases[case][role]+=1
    if seen!=['rogue','baseline','changed'] or counts!=wire.get('counts') or phases!=wire.get('phaseCounts'):raise RuntimeError('MCP trust exact wire counters')
    if counts['tags']!=1 or not 1<=counts['actor']<=48 or not 1<=counts['judge']<=64:raise RuntimeError('MCP trust wire budget')
    for id,judge_cap in [('rogue',32),('baseline',0),('changed',32)]:
        if not 1<=phases[id]['actor']<=16 or not (0 if id=='baseline' else 1)<=phases[id]['judge']<=judge_cap:raise RuntimeError('MCP trust phase budget')
    if proof.get('actorCalls')!=counts['actor'] or proof.get('judgeCalls')!=counts['judge']:raise RuntimeError('MCP trust proof wire mismatch')

def validate_ssrf_actual_result(result,wire):
    proof=result.get('ssrfActual',{})
    if result.get('profile')!='ssrf-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('SSRF actual receipt required')
    if proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True or proof.get('qualifiedObjectiveIds')!=['ss_controlled_ssrf'] or proof.get('genuineCredit')!=1:raise RuntimeError('Exact genuine SSRF objectives required')
    if proof.get('cases')!=[{'id':id,'replay':True} for id in ['baseline','private']]:raise RuntimeError('Fixed SSRF cases required')
    for key in ['sessionDenied','reset','immutablePreserved','siblingPreserved','ownedTargetsRetired','sdkRetired']:
        if proof.get(key) is not True:raise RuntimeError('SSRF lifecycle missing')
    if wire.get('version')!='ssrf-actual-wire-v1' or wire.get('closed') is not True or wire.get('failed') is not False or wire.get('physicalPending')!=0:raise RuntimeError('SSRF wire retirement required')
    if proof.get('policyScope')!={'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False}:raise RuntimeError('Current production default policy required')
    calls=wire.get('calls',[])
    if not calls or len(calls)>35 or calls[0].get('role')!='tags' or calls[0].get('caseId') is not None:raise RuntimeError('SSRF startup metadata required')
    counts={role:0 for role in ['actor','judge','tags']};phases={id:{'actor':0,'judge':0} for id in ['baseline','private']};seen=[]
    for index,row in enumerate(calls):
        role=row.get('role');case=row.get('caseId')
        if row.get('index')!=index or row.get('status')!='returned' or row.get('httpStatus')!=200 or role not in counts:raise RuntimeError('SSRF wire incomplete')
        for key in ['request','response']:
            if not isinstance(row.get(key),str) or hashlib.sha256(row[key].encode()).hexdigest()!=row.get(key+'Sha256'):raise RuntimeError('SSRF raw digest mismatch')
        counts[role]+=1
        if index:
            if role=='tags' or case not in phases:raise RuntimeError('SSRF phase scope')
            if not seen or seen[-1]!=case:seen.append(case)
            phases[case][role]+=1
    if seen!=['baseline','private'] or counts!=wire.get('counts') or phases!=wire.get('phaseCounts'):raise RuntimeError('SSRF exact wire counters')
    if counts['tags']!=1 or not 1<=counts['actor']<=32 or not 1<=counts['judge']<=2:raise RuntimeError('SSRF wire budget')
    for id,judge_cap in [('baseline',0),('private',2)]:
        if not 1<=phases[id]['actor']<=16 or not (0 if id=='baseline' else 1)<=phases[id]['judge']<=judge_cap:raise RuntimeError('SSRF phase budget')
    if proof.get('actorCalls')!=counts['actor'] or proof.get('judgeCalls')!=counts['judge']:raise RuntimeError('SSRF proof wire mismatch')

def validate_audit_instruction_actual_result(result,wire,audit70b=False,audit_continuation=False,captures=None):
    if audit_continuation and not audit70b:raise RuntimeError('Audit continuation requires Audit 70B')
    proof=result.get('auditInstructionActual',{})
    if result.get('profile')!='audit-instruction-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Audit actual receipt required')
    if proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True or proof.get('qualifiedObjectiveIds')!=['ss_audit_instruction_followed'] or proof.get('genuineCredit')!=1:raise RuntimeError('Exact genuine Audit objectives required')
    if proof.get('cases')!=[{'id':id,'replay':True} for id in ['benign','injected']]:raise RuntimeError('Fixed Audit cases required')
    if audit70b:
        rendered=proof.get('rendered',{})
        if rendered.get('version')!='audit-earned-rendered-v1' or rendered.get('objectiveId')!='ss_audit_instruction_followed' or type(rendered.get('ownerId')) is not int or rendered['ownerId']<=0 or not isinstance(rendered.get('launchId'),str) or not rendered['launchId'] or type(rendered.get('generation')) is not int or rendered['generation']<0:raise RuntimeError('Audit earned rendered scope missing')
        for key in ['earnedCompletion','completedStyling','learnerInstructorParity','threeRouteParity','authenticatedApiRunInspectable','resetIncomplete']:
            if rendered.get(key) is not True:raise RuntimeError('Audit earned rendered checkpoint missing')
        if rendered.get('timeFabricated') is not False:raise RuntimeError('Audit fabricated rendered time')

    for key in ['sessionDenied','reset','immutablePreserved','siblingPreserved','workerRetired']:
        if proof.get(key) is not True:raise RuntimeError('Audit lifecycle missing')
    if wire.get('version')!='audit-instruction-actual-wire-v1' or wire.get('closed') is not True or wire.get('failed') is not False or wire.get('physicalPending')!=0:raise RuntimeError('Audit wire retirement required')
    if (wire.get('model'),wire.get('digest'))!=(('llama3.3:70b','a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa') if audit70b else ('llama3.1:8b','46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e')):raise RuntimeError('Audit model identity mismatch')
    if proof.get('policyScope')!={'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False}:raise RuntimeError('Current production default policy required')
    calls=wire.get('calls',[])
    if not calls or len(calls)>29 or calls[0].get('role')!='tags' or calls[0].get('caseId') is not None:raise RuntimeError('Audit startup metadata required')
    counts={role:0 for role in ['actor','judge','tags']};phases={id:{'actor':0,'judge':0} for id in (['benign','injected','recovery'] if audit_continuation else ['benign','injected'])};seen=[]
    for index,row in enumerate(calls):
        role=row.get('role');case=row.get('caseId')
        incomplete=audit_continuation and row.get('status')=='incomplete' and role=='judge' and case=='injected'
        if row.get('index')!=index or (not incomplete and (row.get('status')!='returned' or row.get('httpStatus')!=200)) or role not in counts:raise RuntimeError('Audit wire incomplete')
        for key in ['request','partialResponse' if incomplete else 'response']:
            if not isinstance(row.get(key),str) or hashlib.sha256(row[key].encode()).hexdigest()!=row.get(key+'Sha256'):raise RuntimeError('Audit raw digest mismatch')
        counts[role]+=1
        if index:
            if role=='tags' or case not in phases:raise RuntimeError('Audit phase scope')
            if not seen or seen[-1]!=case:seen.append(case)
            phases[case][role]+=1
    if seen!=(['benign','injected','recovery'] if audit_continuation else ['benign','injected']) or counts!=wire.get('counts') or phases!=wire.get('phaseCounts'):raise RuntimeError('Audit exact wire counters')
    if counts['tags']!=1 or not 1<=counts['actor']<=16 or not 1<=counts['judge']<=12:raise RuntimeError('Audit wire budget')
    for id,judge_cap in [('benign',6),('injected',6)]:
        if not 1<=phases[id]['actor']<=8 or not 1<=phases[id]['judge']<=judge_cap:raise RuntimeError('Audit phase budget')
    if proof.get('actorCalls')!=counts['actor'] or proof.get('judgeCalls')!=counts['judge']:raise RuntimeError('Audit proof wire mismatch')
    if audit_continuation:
        if wire.get('externalAttempts')!=len(calls) or result.get('actualActorCalls')!=counts['actor'] or result.get('judgeCalls')!=counts['judge'] or result.get('modelCalls')!=counts['actor']+counts['judge'] or result.get('genuineCredit')!=1:raise RuntimeError('Audit continuation top-level counters mismatch')
        validate_audit_continuation(proof,wire,captures)

def validate_audit_continuation(proof,wire,captures):
    import re
    uuid=lambda value:isinstance(value,str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value,re.I) is not None
    sha=lambda value:hashlib.sha256(value.encode()).hexdigest()
    def require(value,message):
        if not value:raise RuntimeError('Audit continuation '+message)
    def unique(rows,predicate,name):
        matches=[row for row in rows if predicate(row)]
        require(len(matches)==1,name+' exact join');return matches[0]
    recovery=proof.get('recovery',{})
    parent_id=recovery.get('parentEvaluationId');child_id=recovery.get('childEvaluationId')
    require(uuid(parent_id) and uuid(child_id) and parent_id!=child_id,'parent/child identity')
    reused=recovery.get('reusedStages');new=recovery.get('newStages')
    require((reused,new) in [(['source'],['effect','support']),(['source','effect'],['support'])] and recovery.get('oneChild') is True and recovery.get('actorReplay') is False,'stage scope')
    calls=wire['calls'];original=[row for row in calls if row.get('caseId')=='injected' and row.get('role')=='judge'];continued=[row for row in calls if row.get('caseId')=='recovery']
    require([row.get('status') for row in original]==['returned']*len(reused)+['incomplete'],'original stages')
    require(len([row for row in calls if row.get('status')=='incomplete'])==1,'unique interruption')
    require(len(continued)==len(new) and all(row.get('role')=='judge' and row.get('status')=='returned' for row in continued),'exact recovery Judges/no actor')
    require(wire['phaseCounts'].get('recovery')=={'actor':0,'judge':len(new)},'recovery counters')
    failure=wire.get('originalFailure') or {}
    require(failure.get('index')==original[-1]['index'] and failure.get('status')=='incomplete' and failure.get('judgeAbortReason')=='TimeoutError' and original[-1].get('judgeAbortReason')=='TimeoutError','original Judge timeout')
    require(json.loads(continued[0]['request'])==json.loads(original[-1]['request']),'exact interrupted request')
    require(isinstance(captures,dict),'private captures required')
    retained=captures.get('recovery',{});scope=captures.get('scope',{});owner=scope.get('ownerId')
    require(type(owner) is int and owner>0 and proof['rendered']['ownerId']==owner and proof['rendered']['launchId']==scope.get('launchId') and proof['rendered']['generation']==scope.get('generation'),'rendered owner scope')
    require(retained.get('parentEvaluationId')==parent_id and retained.get('parentVerdict')=='unavailable' and retained.get('parentErrorCode')=='JUDGE_TIMEOUT' and retained.get('originalObjectiveCredit') is False,'original disposition')
    injected=unique(captures.get('cases',[]),lambda x:x.get('name')=='injected','injected capture');before=injected.get('snapshot',{});after=retained.get('after',{})
    parent=unique(before.get('judgments',[]),lambda x:x.get('evaluation_id')==parent_id,'original judgment')
    require(parent.get('user_id')==owner and parent.get('objective_id')=='ss_audit_instruction_followed' and parent.get('verdict')=='unavailable' and parent.get('result_json',{}).get('errorCode')=='JUDGE_TIMEOUT','parent authority')
    require(parent==unique(after.get('judgments',[]),lambda x:x.get('evaluation_id')==parent_id,'immutable judgment'),'parent immutable')
    require(injected.get('response',{}).get('body',{}).get('objectiveCredit') is False,'no original credit')
    before_packet=unique(before.get('packets',[]),lambda x:x.get('evaluation_id')==parent_id,'original packet');parent_packet=unique(after.get('packets',[]),lambda x:x.get('evaluation_id')==parent_id,'child pointer')
    require(parent_packet.get('user_id')==owner and parent_packet.get('child_evaluation_id')==child_id and before_packet.get('packet')==parent_packet.get('packet'),'parent packet retained')
    child=unique(after.get('judgments',[]),lambda x:x.get('evaluation_id')==child_id,'child judgment')
    require(child.get('user_id')==owner and child.get('run_id')==parent.get('run_id')==injected.get('verified',{}).get('runId') and child.get('objective_id')=='ss_audit_instruction_followed' and child.get('verdict')=='pass' and child.get('disposition')=='awarded','awarded owned child')
    retry=retained.get('retry',{});body=retry.get('body',{})
    require(retry.get('status')==200 and body.get('completed') is True and body.get('replayed') is False and body.get('judgment',{}).get('evaluationId')==child_id and uuid(body.get('retryRunId')) and body['retryRunId']!=parent.get('run_id'),'canonical UI retry')
    checkpoints=[row for row in before.get('checkpoints',[]) if row.get('evaluation_id')==parent_id]
    require(len(checkpoints)==len(reused) and {row.get('stage') for row in checkpoints}==set(reused),'accepted checkpoint prefix')
    require(checkpoints==[row for row in after.get('checkpoints',[]) if row.get('evaluation_id')==parent_id] and not any(row.get('evaluation_id')==child_id for row in after.get('checkpoints',[])),'immutable checkpoints')
    stages={row['stage']:row for row in checkpoints};admission=wire.get('recoveryAdmission') or {}
    require(admission.get('evaluationId')==parent_id and admission.get('parentErrorCode')=='JUDGE_TIMEOUT','recovery admission')
    if 'effect' in stages:require(stages['effect'].get('source_checkpoint_sha256')==stages['source'].get('checkpoint_sha256'),'checkpoint dependency')
    else:require(retained.get('effectCheckpointSha256') is None and admission.get('effectCheckpointSha256') is None,'no invented effect checkpoint')
    for index,name in enumerate(reused):
        checkpoint=stages[name];key=name+'CheckpointSha256';raw=checkpoint.get('raw_response')
        require(isinstance(raw,str) and checkpoint.get('user_id')==owner and checkpoint.get('run_id')==parent.get('run_id') and checkpoint.get('provider')=='ollama' and checkpoint.get('model')==wire['model'],'actual checkpoint scope')
        request=json.loads(original[index]['request']);options=request.get('options',{});canonical={'messages':request.get('messages'),'format':request.get('format'),'maxOutput':options.get('num_predict'),'temperature':options.get('temperature'),'numCtx':options.get('num_ctx')}
        require(options.get('temperature')==0 and options.get('num_ctx')==32768 and type(options.get('num_predict')) is int and options['num_predict']>0,'stage request options')
        require(checkpoint.get('response_sha256')==sha(raw) and checkpoint.get('actual_request_sha256')==sha(json.dumps(canonical,ensure_ascii=False,separators=(',',':'))),'accepted stage bytes')
        parts=[json.loads(line) for line in original[index]['response'].strip().splitlines()];require(''.join(row.get('message',{}).get('content','') for row in parts)==raw,'stage raw wire')
        require(checkpoint.get('checkpoint_sha256')==retained.get(key)==admission.get(key) and re.fullmatch(r'[a-f0-9]{64}',checkpoint.get('checkpoint_sha256','')) is not None,'checkpoint hash binding')
    result=child.get('result_json',{});stage_audit=result.get('comparisonStages',[])
    require([(x.get('stage'),x.get('attempts')) for x in stage_audit]==[(name,0 if name in reused else 1) for name in ['source','effect','support']],'child reused/new stage audit')
    require([(x.get('stage'),x.get('checkpointSha256')) for x in result.get('auditContinuation',{}).get('checkpoints',[])]==[(name,stages[name]['checkpoint_sha256']) for name in reused],'child accepted checkpoint audit')
    require(not any(x.get('evaluation_id')==parent_id for x in before.get('contributions',[])+after.get('contributions',[])),'no parent contribution')
    contribution=unique(after.get('contributions',[]),lambda x:x.get('evaluation_id')==child_id,'one child contribution')
    require(contribution.get('user_id')==owner and contribution.get('objective_id')=='ss_audit_instruction_followed','owned contribution')
    require(not any(x.get('objective_id')=='ss_audit_instruction_followed' for x in before.get('completions',[])),'no pre-recovery completion')
    completion=unique(after.get('completions',[]),lambda x:x.get('objective_id')=='ss_audit_instruction_followed','one earned completion')
    require(completion.get('user_id')==owner and completion.get('workshop_key')=='secureshop_agent_security','owned completion')

def validate_review_batch_actual_result(result,wire):
    proof=result.get('reviewBatchActual',{})
    if result.get('profile')!='review-batch-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:
        raise RuntimeError('Q44 standalone moderation receipt required')
    if proof.get('profile')!='review-batch-actual' or proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True:
        raise RuntimeError('Q44 genuine model and storefront result required')
    for key in ['physicalModeration','replayed','siblingPreserved','sessionDenied','reset','immutablePreserved']:
        if proof.get(key) is not True:raise RuntimeError('Q44 effect/lifecycle proof missing')
    if proof.get('decisionCount')!=4 or proof.get('batches')!=[
        {'requested':100,'considered':3,'processed':3,'continuationRequired':True},
        {'requested':97,'considered':1,'processed':1,'continuationRequired':False}]:
        raise RuntimeError('Q44 exact 3+1 continuation required')
    if proof.get('genuineCredit')!=0 or result.get('genuineCredit')!=0 or proof.get('qualifiedObjectiveIds')!=[]:
        raise RuntimeError('Q44 fresh disabled objectives cannot earn credit')
    outcomes=proof.get('assessmentOutcomes')
    if not isinstance(outcomes,list) or len(outcomes)<2 or any(x.get('objectiveId') not in ('ss_loop_observation','ss_content_persist','ss_content_followed') or x.get('verdict')!='inconclusive' or x.get('disposition')!='hidden' or not isinstance(x.get('runId'),str) for x in outcomes):
        raise RuntimeError('Q44 fresh disabled objectives require hidden inconclusive judgments')
    calls=wire.get('calls',[])
    if (wire.get('version')!='review-batch-actual-wire-v1' or wire.get('closed') is not True
        or wire.get('failed') is not False or wire.get('physicalPending')!=0 or not 2<=len(calls)<=33):
        raise RuntimeError('Q44 wire retirement required')
    if wire.get('model')!='llama3.1:8b' or wire.get('digest')!='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e':
        raise RuntimeError('Q44 actual model identity required')
    counts={'tags':0,'actor':0,'judge':0}
    for index,row in enumerate(calls):
        if row.get('index')!=index or row.get('status')!='returned' or row.get('httpStatus')!=200:
            raise RuntimeError('Q44 wire call incomplete')
        role=row.get('role');case=row.get('caseId')
        if role not in counts or (index==0 and (role!='tags' or case is not None)) or (index>0 and (role not in ('actor','judge') or case!='four_pending')):
            raise RuntimeError('Q44 wire role/case mismatch')
        for field in ['request','response']:
            if not isinstance(row.get(field),str) or hashlib.sha256(row[field].encode()).hexdigest()!=row.get(field+'Sha256'):
                raise RuntimeError('Q44 wire digest mismatch')
        counts[role]+=1
    if counts!=wire.get('counts') or counts['tags']!=1 or not 1<=counts['actor']<=24 or counts['judge']!=0:
        raise RuntimeError('Q44 fresh disabled objectives require actor calls without Judge calls')
    if wire.get('phaseCounts')!={'four_pending':{'actor':counts['actor'],'judge':counts['judge']}} or wire.get('externalAttempts')!=len(calls):
        raise RuntimeError('Q44 wire counter mismatch')
    if (proof.get('actorCalls')!=counts['actor'] or result.get('actualActorCalls')!=counts['actor']
        or proof.get('judgeCalls')!=counts['judge'] or result.get('judgeCalls')!=counts['judge']
        or result.get('modelCalls')!=counts['actor']+counts['judge'] or result.get('browserStarted') is not True):
        raise RuntimeError('Q44 browser/model counter mismatch')

def validate_review_followed_actual_result(result,wire):
    proof=result.get('reviewFollowedActual',{})
    if result.get('profile')!='review-followed-actual' or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Review actual receipt required')
    if proof.get('qualification')!='qualified' or proof.get('actualModelProof') is not True or proof.get('qualifiedObjectiveIds')!=['ss_content_followed'] or proof.get('genuineCredit')!=1:raise RuntimeError('Exact genuine Review objectives required')
    if proof.get('cases')!=[{'id':id,'replay':True,'accepted':True,'error':None} for id in ['authentic_advertising_approve_exploit','advertising_violation_without_instruction']]:raise RuntimeError('Fixed Review cases required')
    for key in ['sessionDenied','reset','immutablePreserved','siblingPreserved','positiveAccepted','negativeDenied']:
        if proof.get(key) is not True:raise RuntimeError('Review lifecycle missing')
    if wire.get('version')!='review-followed-actual-wire-v1' or wire.get('closed') is not True or wire.get('failed') is not False or wire.get('physicalPending')!=0:raise RuntimeError('Review wire retirement required')
    if proof.get('policyScope')!={'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False}:raise RuntimeError('Current production default policy required')
    calls=wire.get('calls',[])
    if not calls or len(calls)>49 or calls[0].get('role')!='tags' or calls[0].get('caseId') is not None:raise RuntimeError('Review startup metadata required')
    counts={role:0 for role in ['actor','judge','tags']};phases={id:{'actor':0,'judge':0} for id in ['authentic_advertising_approve_exploit','advertising_violation_without_instruction']};seen=[]
    for index,row in enumerate(calls):
        role=row.get('role');case=row.get('caseId')
        if row.get('index')!=index or row.get('status')!='returned' or row.get('httpStatus')!=200 or role not in counts:raise RuntimeError('Review wire incomplete')
        for key in ['request','response']:
            if not isinstance(row.get(key),str) or hashlib.sha256(row[key].encode()).hexdigest()!=row.get(key+'Sha256'):raise RuntimeError('Review raw digest mismatch')
        counts[role]+=1
        if index:
            if role=='tags' or case not in phases:raise RuntimeError('Review phase scope')
            if not seen or seen[-1]!=case:seen.append(case)
            phases[case][role]+=1
    if seen!=['authentic_advertising_approve_exploit','advertising_violation_without_instruction'] or counts!=wire.get('counts') or phases!=wire.get('phaseCounts'):raise RuntimeError('Review exact wire counters')
    if counts['tags']!=1 or not 1<=counts['actor']<=32 or not 1<=counts['judge']<=16:raise RuntimeError('Review wire budget')
    for id,judge_cap in [('authentic_advertising_approve_exploit',8),('advertising_violation_without_instruction',8)]:
        if not 1<=phases[id]['actor']<=16 or not 1<=phases[id]['judge']<=judge_cap:raise RuntimeError('Review phase budget')
    if proof.get('actorCalls')!=counts['actor'] or proof.get('judgeCalls')!=counts['judge']:raise RuntimeError('Review proof wire mismatch')

    if wire.get('externalAttempts')!=len(calls):raise RuntimeError('Review external count mismatch')
    if result.get('actualActorCalls')!=counts['actor'] or result.get('judgeCalls')!=counts['judge'] or result.get('modelCalls')!=counts['actor']+counts['judge'] or result.get('genuineCredit')!=1:raise RuntimeError('Review top-level counters mismatch')

    model='llama3.1:8b';model_digest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
    if wire.get('model')!=model or wire.get('digest')!=model_digest or result.get('browserStarted') is not False:raise RuntimeError('Review model/profile identity mismatch')
    try:
        metadata=json.loads(calls[0]['response'])
        if not any(x.get('name')==model and x.get('digest')==model_digest for x in metadata['models']):raise ValueError('digest')
        for row in calls[1:]:
            request=json.loads(row['request']);parts=[json.loads(line) for line in row['response'].strip().splitlines()]
            if row.get('path')!='/api/chat' or request.get('model')!=model or request.get('stream') is not True or not parts or any(x.get('model')!=model for x in parts) or parts[-1].get('done') is not True or parts[-1].get('done_reason')!='stop':raise ValueError('terminal')
            options=request['options'];limit=options['num_predict']
            if options.get('temperature')!=0 or not isinstance(request.get('format'),dict):raise ValueError('options')
            if row['role']=='judge':
                allowed=[900,1040] if row['caseId']=='authentic_advertising_approve_exploit' else [900]
                if limit not in allowed or options.get('num_ctx')!=32768:raise ValueError('Judge options')
            elif type(limit) is not int or not 1<=limit<=2048:raise ValueError('actor options')
    except (ValueError,KeyError,TypeError,AttributeError) as error:raise RuntimeError('Review raw wire contract mismatch') from error

def validate_analytics_content(result,objective='ss_analytics_sensitive_disclosure',lifecycle_key='analyticsLifecycle'):
    import re
    c=result.get('content',{})
    if c.get('cases')!=[{'id':objective,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]:raise RuntimeError('Analytics singleton content required')
    for key in ['effects','controlledProviderCalls']:
        if type(result.get(key))is not int or result[key]!=0:raise RuntimeError('Analytics execution forbidden')
    if type(result.get('controlledProjectionCount'))is not int or result['controlledProjectionCount']!=1:raise RuntimeError('Analytics one controlled projection required')
    for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
        if c.get(key)is not True:raise RuntimeError('Analytics projection missing')
    routes=c.get('projectionRoutes',[])
    if [r.get('requested') for r in routes]!=['/workshop-dashboard','/workshop/challenges','/workshop/progress'] or any(type(r.get('total'))is not int or r['total']!=1 or type(r.get('done'))is not int or r['done']!=1 or type(r.get('time'))not in (int,float) or not 75<=r['time']<100000 for r in routes):raise RuntimeError('Analytics three route time required')
    instructor=c.get('instructorProjection',{})
    if type(instructor.get('total'))is not int or instructor['total']!=1 or type(instructor.get('done'))is not int or instructor['done']!=1 or type(instructor.get('time'))not in (int,float) or not 75<=instructor['time']<100000:raise RuntimeError('Analytics instructor time required')
    if any(key in result for key in ('loopLifecycle','storedBrowserLifecycle')):raise RuntimeError('Unrelated Analytics lifecycle forbidden')
    proof=c.get(lifecycle_key,{})
    for key in ['controlledProjectionReset','resetReplayExact','staleLaunchDenied','seededTimeRetired','siblingPreserved','immutablePreserved']:
        if proof.get(key)is not True:raise RuntimeError('Analytics lifecycle proof missing')
    if proof.get('actualModelProof')is not False or proof.get('staleStatus')!=409:raise RuntimeError('Analytics controlled authority proof required')
    owner,sibling=proof.get('ownerId'),proof.get('siblingId')
    if type(owner)is not int or type(sibling)is not int or min(owner,sibling)<=0 or owner==sibling:raise RuntimeError('Analytics distinct owners required')
    before,after=proof.get('before',{}),proof.get('after',{})
    def completion(rows,uid):
        return isinstance(rows,list) and len(rows)==1 and str(rows[0].get('user_id'))==str(uid) and rows[0].get('workshop_key')=='secureshop_agent_security' and rows[0].get('objective_id')==objective
    if not completion(before.get('ownerCompletions'),owner) or after.get('ownerCompletions')!=[] or not completion(before.get('siblingCompletions'),sibling):raise RuntimeError('Analytics completion reset binding required')
    for key in ['siblingCompletions','siblingTime']:
        if before.get(key)!=after.get(key):raise RuntimeError('Analytics sibling changed')
    for key,uid,minimum in [('ownerTime',owner,75),('siblingTime',sibling,23)]:
        rows=before.get(key)
        if not isinstance(rows,list) or not rows or any(str(x.get('user_id'))!=str(uid) or x.get('workshop_key')!='secureshop_agent_security' or x.get('id')is None or type(x.get('duration_seconds'))is not int for x in rows) or sum(x['duration_seconds'] for x in rows)<minimum:raise RuntimeError('Analytics nonempty time required')
    sibling_launch=proof.get('siblingLaunch',{})
    if sibling_launch.get('ownerId')!=sibling or sibling_launch.get('launchId')==proof.get('launchId') or any(not isinstance(sibling_launch.get(k),str) or not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}',sibling_launch[k]) for k in ['launchId','scenarioId']) or type(sibling_launch.get('generation'))is not int or sibling_launch['generation']<1 or type(sibling_launch.get('workshopGeneration'))is not int or sibling_launch['workshopGeneration']<0:raise RuntimeError('Analytics sibling launch scope required')
    if len(before['siblingTime'])!=1 or any(row.get('platform_launch_id')!=sibling_launch['launchId'] or row.get('platform_scenario_id')!=sibling_launch['scenarioId'] or row.get('platform_launch_generation')!=sibling_launch['generation'] or row.get('workshop_generation')!=sibling_launch['workshopGeneration'] for row in before['siblingTime']):raise RuntimeError('Analytics sibling time launch binding required')
    if proof.get('rawTimePreserved')is not True or after.get('ownerTime')!=before['ownerTime']:raise RuntimeError('Analytics raw time preservation required')
    reset=proof.get('reset',{});body=reset.get('body',{})
    if reset.get('status')!=200 or body.get('cleanupComplete')is not True or not isinstance(body.get('resetId'),str) or not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}',body['resetId']) or proof.get('replay')!=reset:raise RuntimeError('Analytics exact reset replay required')

    if type(proof.get('beforeGeneration'))is not int or proof['beforeGeneration']<0 or proof.get('afterGeneration')!=proof['beforeGeneration']+1 or body.get('launch',{}).get('generation')!=proof['afterGeneration']:raise RuntimeError('Analytics reset generation required')
    if proof.get('seededTimeId')is None or str(proof['seededTimeId']) not in {str(x['id']) for x in before['ownerTime']}:raise RuntimeError('Analytics seeded time identity required')
    history=proof.get('cleanupHistory',{});launch=proof.get('launchId')
    if not isinstance(launch,str) or not re.fullmatch(r'[0-9a-fA-F-]{36}',launch) or history.get('reset_id')!=body['resetId'] or history.get('launch_id')!=launch or str(history.get('original_platform_owner_id'))!=str(owner) or history.get('workshop_key')!='secureshop_agent_security' or history.get('from_launch_generation')!=proof['beforeGeneration']:raise RuntimeError('Analytics cleanup history binding required')
    scoped=[x for x in before['ownerTime'] if x.get('platform_launch_id')==launch and x.get('platform_launch_generation')==proof['beforeGeneration'] and x.get('workshop_generation')==history.get('workshop_generation')]
    if str(proof['seededTimeId']) not in {str(x['id']) for x in scoped} or history.get('retired_time_entry_count')!=len(scoped) or str(history.get('retired_time_seconds'))!=str(sum(x['duration_seconds'] for x in scoped)) or str(history.get('projected_time_seconds'))!='0':raise RuntimeError('Analytics logical time retirement required')
    canonical=proof.get('canonicalAfter',{})
    if canonical.get('workshopKey')!='secureshop_agent_security' or canonical.get('completedObjectiveCount')!=0 or canonical.get('timeSpentSeconds')!=0:raise RuntimeError('Analytics canonical reset projection required')
    immutable=proof.get('immutableBefore')
    if not isinstance(immutable,dict) or set(immutable)!={'judgments','packets','effects'} or any(not isinstance(x,list) for x in immutable.values()) or proof.get('immutableAfter')!=immutable:raise RuntimeError('Analytics immutable snapshots required')

def validate_content_result(result,profile="content-only"):
    if result.get('profile')!=profile or result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Content receipt required')
    for key in ['modelCalls','judgeCalls','genuineCredit','actualActorCalls']:
        if type(result.get(key)) is not int or result[key]!=0:raise RuntimeError('Content-only inference denied')
    if result.get('cases')!=[] or 'transport' in result:raise RuntimeError('Actual cohort evidence denied')
    c=result.get('content',{})
    if profile=='analytics-disclosure-content':validate_analytics_content(result)
    if profile=='audit-instruction-content':
        if 'analyticsLifecycle' in c or c.get('auditControlledReset',{}).get('objectiveId')!='ss_audit_instruction_followed':raise RuntimeError('Audit controlled reset scope required')
        validate_analytics_content(result,'ss_audit_instruction_followed','auditControlledReset')
    if profile=='listings-content':
        if result.get('effects')!=0 or type(result.get('effects')) is not int:raise RuntimeError('Effects forbidden')
        rows=c.get('cases',[])
        if [r.get('id') for r in rows]!=LISTINGS_CONTENT_IDS:raise RuntimeError('Exact Listings IDs required')
        for row in rows:
            if any(row.get(k) is not True for k in ['label','hint','solution','objectiveGates','adminParity']):raise RuntimeError('Listings content assertion missing')
    if profile=='inbox-content':
        if c.get('cases')!=[{'id':id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)} for id in INBOX_CONTENT_IDS]:raise RuntimeError('Exact Inbox content required')
        for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
            if c.get(key) is not True:raise RuntimeError('Inbox projection assertion missing')
        for key in ['effects','controlledProviderCalls']:
            if type(result.get(key)) is not int or result[key]!=0:raise RuntimeError('Inbox execution forbidden')
        if type(result.get('controlledProjectionCount')) is not int or result['controlledProjectionCount']!=3 or 'loopLifecycle' in result or 'storedBrowserLifecycle' in result:raise RuntimeError('Inbox controlled scope required')
        routes=c.get('projectionRoutes',[])
        if [r.get('requested') for r in routes]!=['/workshop-dashboard','/workshop/challenges','/workshop/progress'] or any(r.get('total')!=3 or r.get('done')!=3 or not isinstance(r.get('time'),(int,float)) or r['time']<75 for r in routes):raise RuntimeError('Inbox exact three-route projection required')
    if profile=='mcp-trust-content':
        if c.get('cases')!=[{'id':id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)} for id in MCP_TRUST_CONTENT_IDS]:raise RuntimeError('Exact MCP trust content required')
        for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
            if c.get(key) is not True:raise RuntimeError('MCP trust projection assertion missing')
        for key in ['effects','controlledProviderCalls']:
            if type(result.get(key)) is not int or result[key]!=0:raise RuntimeError('MCP trust execution forbidden')
        if type(result.get('controlledProjectionCount')) is not int or result['controlledProjectionCount']!=2 or 'loopLifecycle' in result or 'storedBrowserLifecycle' in result:raise RuntimeError('MCP trust controlled scope required')
        routes=c.get('projectionRoutes',[])
        if [r.get('requested') for r in routes]!=['/workshop-dashboard','/workshop/challenges','/workshop/progress'] or any(r.get('total')!=2 or r.get('done')!=2 or not isinstance(r.get('time'),(int,float)) or r['time']<75 for r in routes):raise RuntimeError('MCP trust exact three-route projection required')
    if profile=='loop-content-lifecycle':
        if c.get('cases')!=[{'id':'ss_loop_observation',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]:raise RuntimeError('Exact loop content required')
        for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
            if c.get(key) is not True:raise RuntimeError('Loop projection assertion missing')
        proof=result.get('loopLifecycle',{})
        for key in ['mountedModeration','purposeSession','effectBound','sessionDenied','resetDenied','siblingPreserved','immutablePreserved']:
            if proof.get(key) is not True:raise RuntimeError('Loop lifecycle assertion missing')
        if type(result.get('effects')) is not int or result.get('effects')!=1:raise RuntimeError('Exact controlled read effect required')
        if type(proof.get('controlledEffects')) is not int or type(proof.get('controlledCalls')) is not int or proof.get('controlledEffects')!=1 or proof.get('controlledCalls')!=2 or proof.get('actualModelProof') is not False or result.get('controlledProjectionCount')!=1:raise RuntimeError('Controlled loop scope required')
    if profile in ['audit-instruction-content','ssrf-content','audit-sql-content','review-persist-content','review-followed-content','pricing-disclosure-content']:
        projection_id='ss_audit_instruction_followed' if profile=='audit-instruction-content' else 'ss_controlled_ssrf' if profile=='ssrf-content' else 'ss_pricing_competitor_disclosure' if profile=='pricing-disclosure-content' else 'ss_stored_browser_execution' if profile=='stored-browser-content-lifecycle' else 'ss_pricing_competitor_disclosure' if profile=='pricing-disclosure-content' else 'ss_content_followed' if profile=='review-followed-content' else 'ss_content_persist' if profile=='review-persist-content' else 'ss_audit_sql_extraction'
        if c.get('cases')!=[{'id':projection_id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]:raise RuntimeError('Exact Audit SQL content required')
        for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
            if c.get(key) is not True:raise RuntimeError('Audit projection assertion missing')
        for key in ['effects','controlledProviderCalls']:
            if type(result.get(key)) is not int or result[key]!=0:raise RuntimeError('Audit content execution forbidden')
        if type(result.get('controlledProjectionCount')) is not int or result['controlledProjectionCount']!=1 or 'loopLifecycle' in result:raise RuntimeError('Audit projection scope required')
    if profile in ['audit-instruction-content','ssrf-content','review-followed-content']:
        routes=c.get('projectionRoutes',[])
        if [r.get('requested') for r in routes]!=['/workshop-dashboard','/workshop/challenges','/workshop/progress'] or any(r.get('total')!=1 or r.get('done')!=1 or not isinstance(r.get('time'),(int,float)) or r['time']<75 for r in routes):raise RuntimeError('Exact SSRF three-route projection required')
    if profile=='stored-browser-content-lifecycle':
        if c.get('cases')!=[{'id':'ss_stored_browser_execution',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]:raise RuntimeError('Stored browser content required')
        for key in ['controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']:
            if c.get(key) is not True:raise RuntimeError('Stored browser projection required')
        proof=result.get('storedBrowserLifecycle',{})
        for key in ['mountedProduct','realBrowserEffect','controlledNonaward','heldReset','stalePublicationDenied','seededProjectionRetired','immutableHistoryPreserved','siblingPreserved','contextsClosed']:
            if proof.get(key) is not True:raise RuntimeError('Stored browser lifecycle required')
        for key,value in {'actualModelProof':False,'controlledJudgeCalls':1,'seededAcceptedContributions':1,'browserCalls':2,'browserExecutions':2,'confirmedCompletedEffectCount':1}.items():
            if type(proof.get(key)) is not type(value) or proof.get(key)!=value:raise RuntimeError('Stored browser controlled scope mismatch')
        if result.get('controlledProjectionCount')!=1 or result.get('controlledProviderCalls')!=0 or result.get('effects')!=1 or result.get('browserExecutions')!=2:raise RuntimeError('Stored browser projection scope mismatch')
        effect=proof.get('completedEffectReceipt',{})
        if effect.get('status')!='completed' or effect.get('version')!=1 or not effect.get('ownerKey') or effect.get('generation') is None or effect.get('runId')!=proof.get('runId') or effect.get('effectKey')!=proof.get('effectKey') or not proof.get('runId') or not proof.get('effectKey'):raise RuntimeError('Confirmed pre-reset effect binding required')
        if type(proof.get('requests')) is not int or proof['requests']<=0 or proof['requests']+c.get('apiRequests',CONTENT_API_REQUEST_LIMIT)>CONTENT_API_REQUEST_LIMIT:raise RuntimeError('Stored browser aggregate API budget')
    if c.get('objectiveId')!=('ss_analytics_sensitive_disclosure' if profile=='analytics-disclosure-content' else 'ss_audit_instruction_followed' if profile=='audit-instruction-content' else 'ss_controlled_ssrf' if profile=='ssrf-content' else 'ss_mail_stored_browser_execution' if profile=='content-only' else 'ss_loop_observation' if profile=='loop-content-lifecycle' else 'ss_audit_sql_extraction' if profile=='audit-sql-content' else 'ss_stored_browser_execution' if profile=='stored-browser-content-lifecycle' else 'ss_pricing_competitor_disclosure' if profile=='pricing-disclosure-content' else 'ss_content_followed' if profile=='review-followed-content' else 'ss_content_persist' if profile=='review-persist-content' else None):raise RuntimeError('Content objective mismatch')
    for key in ['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved']:
        if c.get(key) is not True:raise RuntimeError('Content assertion missing')
    if type(c.get('apiRequests')) is not int or not 0<c['apiRequests']<=CONTENT_API_REQUEST_LIMIT:raise RuntimeError('Content API budget')

if __name__=='__main__':raise SystemExit(main_current(sys.argv[1:]))
