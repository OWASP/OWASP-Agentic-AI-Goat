#!/usr/bin/env python3
"""FinFlow actual two-turn browser qualification; all source remains in main."""
import argparse
import urllib.request
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import secrets
import stat

COHORT = 'finflow-backup-browser-main'
STATEMENT_INPUT='tests/fixtures/finflowStatementBrowserInputs.json'
STATEMENT_INPUT_SHA256='2924beebf3a7665cf2ad6e9d7585afec4c75a40eb2b58dcc7f4b0dd3cf4eab86'
TRAVERSAL_INPUT='tests/fixtures/finflowTraversalContentInputs.json'
TRAVERSAL_INPUT_SHA256='358bb6e5695cfb82a7a83dd12634aa5f4fc0ace454f2cac8513bb51b9d4bfeff'
BACKUP_CONTENT_INPUT='tests/fixtures/finflowBackupContentInputs.json'
BACKUP_CONTENT_INPUT_SHA256='23bb438cb0f3ad360d7c6e36abaa625b783ac997edcf12935242558c29f5e411'
SSRF_CONTENT_INPUT='tests/fixtures/finflowSsrfContentInputs.json'
SSRF_CONTENT_INPUT_SHA256='ea81586a75872dc6cf683e5b0cd4c199448396439ee22458e685cd0e674a4334'
RECON_CONTENT_INPUT='tests/fixtures/finflowReconContentInputs.json'
RECON_CONTENT_INPUT_SHA256='8cd29e99e7be7877dc0e07e79a195023830877d0aee406154c3679ad90e7efc4'
ADMIN_LOG_CONTENT_INPUT='tests/fixtures/finflowAdminLogContentInputs.json'
ADMIN_LOG_CONTENT_INPUT_SHA256='0265aca353ff39be9ccf3aa104252bbba3f0ac28d1edd0383700ecbe1e57a54a'
ADMIN_ARTIFACT_CONTENT_INPUT='tests/fixtures/finflowAdminArtifactContentInputs.json'
ADMIN_ARTIFACT_CONTENT_INPUT_SHA256='c0b8b50bf07af45b88290f9e82951b471dc2b9b1d25bab554393646665cce42c'
ADMIN_MUTATION_CONTENT_INPUT='tests/fixtures/finflowAdminMutationContentInputs.json'
ADMIN_MUTATION_CONTENT_INPUT_SHA256='c4e752ecc1857d2036f050c0bcacce720856e5390f4b381139568f02f29636d9'
ADMIN_ENUM_CONTENT_INPUT='tests/fixtures/finflowAdminEnumContentInputs.json'
ADMIN_ENUM_CONTENT_INPUT_SHA256='cce1915623b7408e2b81f01b7a6ffe2be83a4652c1d46e270d005f5c47494dff'
ADMIN_ENUM_ACTUAL_INPUT='tasks/finflow-admin-enum-multiturn-exploration-2026-09-19.json'
ADMIN_ENUM_ACTUAL_INPUT_SHA256='4a98f6e2c7c3e26f26beca1717c1e31ce0c3d9c61829c1b9afde711766141ba8'
ADMIN_ENUM_CASES=[f'{owner}:turn-{turn}' for owner in ['fresh-owner-1','fresh-owner-2','fresh-owner-3','fixed'] for turn in [1,2]]
ADMIN_ENUM_WIRE_BUDGET={'generate':80,'chat':16,'tags':9,'version':8,'metadata':17,'external':113}
DPI_MULTILINGUAL_70B_PROFILES=('actual-dpi-multilingual70b','actual-dpi-multilingual70b-credit')
DPI_WHOLE_TASK_70B_PROFILE='actual-dpi-whole-task70b-pending'
DPI_SELECTED_TASK_70B_PROFILE='actual-dpi-side-selected70b-pending'
DPI_SELECTED_TASK_V16_70B_PROFILE='actual-dpi-side-selected-v16-70b-awarded'
DPI_TECHNIQUES_SELECTED_70B_PROFILE='actual-dpi-techniques-selected70b-awarded'
DPI_TECHNIQUES_SELECTED_8B_PROFILE='actual-dpi-techniques-selected8b-pending'
DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE='actual-dpi-techniques-selected8b-awarded'
DPI_PENDING_PROFILE='actual-dpi-retained-pending8b'
DPI_PENDING_INPUT='tests/fixtures/dpiRetainedPendingBrowserInput.json'
DPI_PENDING_INPUT_SHA256='978eb07e0ba3404f0cce70d9231d7c08f130eaea44ad315dd5dd8717f10989c9'
DPI_SELECTED_TASK_70B_PROFILES=(DPI_SELECTED_TASK_70B_PROFILE,DPI_SELECTED_TASK_V16_70B_PROFILE,DPI_TECHNIQUES_SELECTED_70B_PROFILE)
DPI_70B_PROFILES=(*DPI_MULTILINGUAL_70B_PROFILES,DPI_WHOLE_TASK_70B_PROFILE,*DPI_SELECTED_TASK_70B_PROFILES)
DPI_PROFILES=('actual-dpi-system-prompt','actual-dpi-baseline-language',DPI_PENDING_PROFILE,DPI_TECHNIQUES_SELECTED_8B_PROFILE,DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE,*DPI_70B_PROFILES)
CSRF_PROFILE='actual-csrf-indirect70b'
def selected_profile(args):return getattr(args,'profile','backup')
def is_dpi(args):return selected_profile(args) in DPI_PROFILES
def is_csrf(args):return selected_profile(args)==CSRF_PROFILE
def is_fullapp(args):return is_dpi(args) or is_csrf(args)
def is_70b(args):return selected_profile(args) in DPI_70B_PROFILES
def is_multilingual70b(args):return selected_profile(args) in DPI_MULTILINGUAL_70B_PROFILES
def is_whole_task70b(args):return selected_profile(args)==DPI_WHOLE_TASK_70B_PROFILE
def is_selected_task70b(args):return selected_profile(args)==DPI_SELECTED_TASK_70B_PROFILE
def is_selected_task_v16_70b(args):return selected_profile(args)==DPI_SELECTED_TASK_V16_70B_PROFILE
def is_techniques_selected_70b(args):return selected_profile(args)==DPI_TECHNIQUES_SELECTED_70B_PROFILE
def is_techniques_selected_8b(args):return selected_profile(args) in (DPI_TECHNIQUES_SELECTED_8B_PROFILE,DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE)
def is_techniques_selected_8b_awarded(args):return selected_profile(args)==DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE
def is_techniques_selected(args):return is_techniques_selected_70b(args) or is_techniques_selected_8b(args)
def is_selected_task_profile(args):return selected_profile(args) in (*DPI_SELECTED_TASK_70B_PROFILES,DPI_TECHNIQUES_SELECTED_8B_PROFILE,DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE)
def selected_mode(args):return 'zero-model-rendered' if selected_profile(args)==DPI_PENDING_PROFILE else 'actual' if selected_profile(args) in ('backup','actual-admin-enum',*DPI_PROFILES,CSRF_PROFILE) else 'controlled'
def selected_cohort(args):return {'backup':COHORT,'actual-admin-enum':'finflow-admin-enum-browser-main','actual-dpi-system-prompt':'dpi-system-prompt-browser-main','actual-dpi-baseline-language':'dpi-baseline-language-browser-main',DPI_PENDING_PROFILE:'dpi-retained-pending8b-browser-main','actual-dpi-multilingual70b':'dpi-multilingual70b-browser-main','actual-dpi-multilingual70b-credit':'dpi-multilingual70b-credit-browser-main',DPI_WHOLE_TASK_70B_PROFILE:'dpi-whole-task70b-pending-browser-main',DPI_SELECTED_TASK_70B_PROFILE:'dpi-side-selected70b-pending-browser-main',DPI_SELECTED_TASK_V16_70B_PROFILE:'dpi-side-selected-v16-70b-awarded-browser-main',DPI_TECHNIQUES_SELECTED_70B_PROFILE:'dpi-techniques-selected70b-awarded-browser-main',DPI_TECHNIQUES_SELECTED_8B_PROFILE:'dpi-techniques-selected8b-pending-browser-main',DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE:'dpi-techniques-selected8b-awarded-browser-main',CSRF_PROFILE:'csrf-indirect70b-main','controlled-statement':'finflow-statement-browser-main','controlled-traversal-content':'finflow-traversal-content-browser-main','controlled-backup-content':'finflow-backup-content-browser-main','controlled-ssrf-content':'finflow-ssrf-content-browser-main','controlled-recon-content':'finflow-recon-content-browser-main','controlled-admin-log-content':'finflow-admin-log-content-browser-main','controlled-admin-artifact-content':'finflow-admin-artifact-content-browser-main','controlled-admin-mutation-content':'finflow-admin-mutation-content-browser-main','controlled-admin-enum-content':'finflow-admin-enum-content-browser-main'}[selected_profile(args)]
ACTUAL_INPUT = 'tests/release-inputs/finflow-backup-browser-frozen-inputs.json'
DPI_INPUT = 'tests/release-inputs/dpi-system-prompt-browser-fixed-input-v1.json'
DPI_INPUT_SHA256 = '23bb6ec9a2e4f8002081c69a4e701b0f50bfaa37ef29060d638ddb17cfdb43d3'
DPI_BASELINE_LANGUAGE_INPUT = 'tests/release-inputs/dpi-baseline-language-browser-fixed-input-v1.json'
DPI_BASELINE_LANGUAGE_INPUT_SHA256 = '66cc603fb9169d32000649364ba4e0b1e96f9616d697322f55fa73d755c5ec10'
DPI_MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
DPI_70B_MODEL_DIGEST = 'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'
DPI_70B_INPUT='tests/release-inputs/dpi-multilingual70b-browser-fixed-input-v2.json'
DPI_70B_INPUT_SHA256='2f094210e8ad431161cf20ad21e4ba4a6539d42e1c22d274f6fc7305b0863d49'
DPI_70B_CREDIT_INPUT='tests/release-inputs/dpi-multilingual70b-browser-fixed-input-v3.json'
DPI_70B_CREDIT_INPUT_SHA256='590f12ee7d4ff0b246fd6ff405b0d06dd655ab87353439a9a96fecd2786abcd7'
DPI_WHOLE_TASK_70B_INPUT='tests/release-inputs/dpi-whole-task70b-browser-fixed-input-v1.json'
DPI_WHOLE_TASK_70B_INPUT_SHA256='7aea5166ccd408e00583a07eb942865e4ccf37835fd0a59d59caa3b73f747bda'
DPI_SELECTED_TASK_70B_INPUT='tests/release-inputs/dpi-side-selected70b-browser-fixed-input-v1.json'
DPI_SELECTED_TASK_70B_INPUT_SHA256='8758b89edde390a9ae64dae89a506c8b6f8b59c014643425514e776050a840ce'
DPI_TECHNIQUES_SELECTED_70B_INPUT='tests/release-inputs/dpi-techniques-selected70b-browser-fixed-input-v1.json'
DPI_TECHNIQUES_SELECTED_70B_INPUT_SHA256='4b3dde8cf86e383b7d42252ca62f666d7fdde95a11746ca2263ffabb1e9c113f'
DPI_TECHNIQUES_SELECTED_8B_INPUT='tests/release-inputs/dpi-techniques-selected8b-pending-browser-fixed-input-v1.json'
DPI_TECHNIQUES_SELECTED_8B_INPUT_SHA256='1baf72c9143ff08546ad769f34983afac8226a9bc81f677b60ed99c284827d8f'
DPI_TECHNIQUES_SELECTED_8B_AWARDED_INPUT='tests/release-inputs/dpi-techniques-selected8b-awarded-browser-fixed-input-v1.json'
DPI_TECHNIQUES_SELECTED_8B_AWARDED_INPUT_SHA256='cc3d119ce42d4a97b68f96c782732d489935ac9e55337d7f13dff86b13eb3930'
CSRF_INDIRECT_INPUT='tests/fixtures/csrfIndirectChainCohort.json'
CSRF_INDIRECT_INPUT_SHA256='cbe05780b17d39f3d0172181978552a742ecd2c0d3d4162ff62ce521b2afcc7a'
CSRF_70B_MODEL_DIGEST='a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa'
DPI_STORES = (('identity','IDENTITY'),('aria','SQL_WORKSHOP'),('nova','NOSQL_WORKSHOP'),('xss','XSS_WORKSHOP'),('mcp','MCP_WORKSHOP'),('csrf','CSRF_WORKSHOP'),('supply_chain','SUPPLY_CHAIN_WORKSHOP'),('finflow','FINFLOW_WORKSHOP'),('excessive_agency','EXCESSIVE_AGENCY'),('ctf','CTF'),('legacy_challenge','LEGACY_CHALLENGE'),('sensitive_lookup','SENSITIVE_LOOKUP'),('secureshop','SECURESHOP'),('secureshop_agents','SECURESHOP_AGENTS'),('session_disclosure','SESSION_DISCLOSURE'),('secureshop_review','SECURESHOP_REVIEW'))
ACTUAL_INPUT_SHA256 = '1b4cd7b8e2c21a9933e9c65adb016efee194d13ab6180b4156ad05be73873a6e'
REQUIRED = {
 'tests/postgres/run-finflow-backup-browser-main.py',
 'tests/postgres/finflowBackupBrowser.integration.test.js',
 'tests/postgres/finflowBackupBrowserActualTransport.js',
 'tests/fixtures/finflowBackupBrowserChain.js',
 'tests/fixtures/finflowBackupBrowserEvidence.js',
 'tests/fixtures/finflowBackupWireBinding.js',
 'tests/release-inputs/record-current-frontend-build.py',
 'tests/fixtures/secureshopAnalyticsBrowserOwner.js',
 'tests/fixtures/browserProcessOwnership.js',
 'tests/postgres/sql_nosql_process_ownership.py',
 'tests/postgres/sql_nosql_docker_ownership.py',
 'package.json','package-lock.json','client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html',ACTUAL_INPUT,
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

def validate_main(args):
    source=Path(__file__).resolve().parents[2]
    if Path(args.main_workspace)!=source or source.resolve()!=source:raise RuntimeError('Exact current main required')
    if selected_profile(args)==DPI_TECHNIQUES_SELECTED_8B_PROFILE:raise RuntimeError('Historical pending 8B profile is evidence-only; use the current awarded profile')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('Manifest pin mismatch')
    manifest=json.loads(Path(args.manifest).read_text())
    if manifest.get('cohort')!=selected_cohort(args) or manifest.get('workspace')!=str(source):raise RuntimeError('Wrong main manifest')
    if manifest.get('mode')!=selected_mode(args):raise RuntimeError('Manifest mode mismatch')
    required=set(REQUIRED)
    if selected_profile(args)=='actual-admin-enum':
        required.update({ADMIN_ENUM_ACTUAL_INPUT,'tests/postgres/finflowAdminEnumMultiturn.integration.test.js','tests/finflowAdminEnumActualBinding.test.js','server/agent-runtime/finflowAdminCatalogSelection.js','tests/finflowAdminCatalogSelection.test.js'})
        if manifest.get('cases')!=ADMIN_ENUM_CASES or manifest.get('wireBudget')!=ADMIN_ENUM_WIRE_BUDGET or manifest.get('model')!='llama3.1:8b' or manifest.get('modelDigest')!='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e':raise RuntimeError('Exact admin enum cohort/model/budget required')
    if is_dpi(args):
        required.update({DPI_PENDING_INPUT if selected_profile(args)==DPI_PENDING_PROFILE else DPI_INPUT if selected_profile(args)=='actual-dpi-system-prompt' else DPI_TECHNIQUES_SELECTED_8B_AWARDED_INPUT if is_techniques_selected_8b_awarded(args) else DPI_TECHNIQUES_SELECTED_8B_INPUT if is_techniques_selected_8b(args) else DPI_TECHNIQUES_SELECTED_70B_INPUT if is_techniques_selected_70b(args) else DPI_SELECTED_TASK_70B_INPUT if is_selected_task_profile(args) else DPI_WHOLE_TASK_70B_INPUT if is_whole_task70b(args) else DPI_70B_CREDIT_INPUT if selected_profile(args)=='actual-dpi-multilingual70b-credit' else DPI_70B_INPUT if is_70b(args) else DPI_BASELINE_LANGUAGE_INPUT,'tests/postgres/dpiFullAppRendered.native.js','tests/fixtures/dpiFullAppRenderedBrowser.js','tests/fixtures/dpiFullAppEnvironment.js','tests/fixtures/dpiStartupPrivateCapture.cjs','tests/fixtures/dpiPostgresOnlyGuard.cjs','tests/fixtures/fullBackendBootControls.js','tests/fixtures/dpiScopedActualTransport.js','server/data/promptInjectionSolutions.js','db/postgres/initialize-application.js'})
        objective,budget,judges=('virtualization+side_stepping+obfuscation',0,0) if selected_profile(args)==DPI_PENDING_PROFILE else ('system_prompt',1,2) if selected_profile(args)=='actual-dpi-system-prompt' else ('jailbreak+role_playing',4,4) if is_techniques_selected_70b(args) else ('jailbreak+role_playing',4,8) if is_techniques_selected_8b(args) else ('side_stepping',2,2) if is_selected_task_profile(args) else ('virtualization+obfuscation',6,8) if is_whole_task70b(args) else ('multi_language',2,8) if is_70b(args) else ('interact+multi_language',5,10)
        model_pin,digest_pin=('llama3.3:70b',DPI_70B_MODEL_DIGEST) if is_70b(args) else ('llama3.1:8b',DPI_MODEL_DIGEST)
        expected_ids=['virtualization','side_stepping','obfuscation'] if selected_profile(args)==DPI_PENDING_PROFILE else ['jailbreak','role_playing'] if is_techniques_selected(args) else ['virtualization','obfuscation']
        if manifest.get('model')!=model_pin or manifest.get('modelDigest')!=digest_pin or (manifest.get('objectiveIds')!=expected_ids if selected_profile(args)==DPI_PENDING_PROFILE or is_techniques_selected(args) or is_whole_task70b(args) else manifest.get('objectiveId')!=objective) or manifest.get('chatBudget')!=budget or manifest.get('judgeBudget')!=judges:raise RuntimeError('Exact DPI actor/Judge budget required')
    if is_techniques_selected_70b(args) and manifest.get('contextTokens')!=20480:raise RuntimeError('Exact shared techniques20K context required')
    if is_techniques_selected_8b(args) and (manifest.get('actorContextTokens')!=8192 or manifest.get('judgeContextTokens')!=32768):raise RuntimeError('Exact techniques 8B actor/Judge contexts required')
    if is_csrf(args):
        required.update({CSRF_INDIRECT_INPUT,'tests/postgres/csrfFullIndex.native.js','tests/fixtures/csrfMainProfile.js','tests/fixtures/csrfFullIndexTransport.js','tests/fixtures/csrfIndirectChainApi.js','tests/fixtures/csrfIndirectChainEvidence.js','tests/fixtures/csrfIndirectSearchObserver.cjs','tests/fixtures/dpiFullAppEnvironment.js','tests/fixtures/dpiPostgresOnlyGuard.cjs','tests/fixtures/fullBackendBootControls.js','tests/csrfMainProfileAdmission.test.js','server/data/csrfRagPayloads.js','db/postgres/initialize-application.js'})
        required.update(p.relative_to(source).as_posix() for p in (source/'tests/fixtures/fullBackendModelCache').rglob('*') if p.is_file())
        if manifest.get('model')!='llama3.3:70b' or manifest.get('modelDigest')!=CSRF_70B_MODEL_DIGEST or manifest.get('objectiveIds')!=['csrf_i1','csrf_i2','csrf_i3'] or manifest.get('actorCases')!=['clean-Q1','off-topic','on-topic-first','same-query-replay','on-topic-second','defended-second-query'] or manifest.get('maxModelHttpCalls')!=18 or manifest.get('modelHttpTimeoutMs')!=60000 or manifest.get('htmlSummaryTimeoutMs')!=55000:raise RuntimeError('Exact CSRF indirect cohort/model/budget required')
    if selected_profile(args)=='controlled-ssrf-content':required.update({'tests/fixtures/finflowSsrfSeedQualification.js','tests/fixtures/finflowSsrfPriorDefaults.json','tests/finflowSsrfSeedQualification.test.js'})
    if selected_profile(args)=='controlled-statement':required.update({STATEMENT_INPUT,'tests/fixtures/finflowStatementBrowser.js','tests/finflowStatementBrowser.test.js','server/services/finflowStatementPdf.js','tests/finflowStatementPdf.test.js'})
    if selected_profile(args) in ('controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'):required.update({TRAVERSAL_INPUT if selected_profile(args)=='controlled-traversal-content' else BACKUP_CONTENT_INPUT if selected_profile(args)=='controlled-backup-content' else SSRF_CONTENT_INPUT if selected_profile(args)=='controlled-ssrf-content' else RECON_CONTENT_INPUT if selected_profile(args)=='controlled-recon-content' else ADMIN_LOG_CONTENT_INPUT if selected_profile(args)=='controlled-admin-log-content' else ADMIN_ARTIFACT_CONTENT_INPUT if selected_profile(args)=='controlled-admin-artifact-content' else ADMIN_ENUM_CONTENT_INPUT if selected_profile(args)=='controlled-admin-enum-content' else ADMIN_MUTATION_CONTENT_INPUT,'tests/fixtures/finflowTraversalContentBrowser.js','tests/finflowTraversalContentBrowser.test.js','tests/fixtures/legacyFileSsiFullAppParity.js','tests/fixtures/mcpAuditContentBrowser.js'})
    validate_actual_input(args,source,manifest)
    for directory in (['db/postgres/identity-migrations','db/postgres/workshop-migrations/finflow'] if not is_fullapp(args) else ['db/postgres/identity-migrations','db/postgres/migrations',*[f'db/postgres/workshop-migrations/{label}' for label,_ in DPI_STORES if label!='identity']]):
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
    if inventory(source/'client/build')!=manifest.get('clientBuildInventory') or not manifest.get('clientBuildInventory'):raise RuntimeError('Built client mismatch')
    validate_build_provenance(source,manifest)
    return source,manifest

def inventory_sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate_build_provenance(source,manifest):
    for rel,key in [('client/src','clientSourceInventory'),('client/public','clientPublicInventory'),('client/node_modules','clientDependencyInventory')]:
        if not manifest.get(key) or inventory(source/rel)!=manifest[key]:raise RuntimeError('Current client source/dependency mismatch')
    rel=manifest.get('buildReport')
    if not isinstance(rel,str) or Path(rel).is_absolute() or '..'in Path(rel).parts or rel not in manifest['sourcePins']:raise RuntimeError('Pinned successful build report required')
    report=json.loads((source/rel).read_text())
    if report.get('qualified')is not True or report.get('exitCode')!=0 or report.get('beforeAfterInputsEqual')is not True:raise RuntimeError('Successful unchanged-input build required')
    if report.get('rootDependencyInventorySha256')!=inventory_sha(manifest['dependencyInventory']):raise RuntimeError('Build root dependency mismatch')
    if report.get('workspace')!=str(source) or current_build_fingerprint(source,report.get('inputMode'))!=report.get('buildInputInventorySha256'):raise RuntimeError('Current build input mismatch')
    config={p:manifest['sourcePins'].get(p) for p in ['client/package.json','client/package-lock.json','client/vite.config.mjs','client/index.html']}
    if not all(config.values()) or report.get('clientBuildConfigPins')!=config:raise RuntimeError('Build configuration provenance mismatch')
    if manifest.get('externalBuildRoot') is not None:
        output=Path(manifest['externalBuildRoot'])
        if report.get('inputMode')!='private-external-v1' or report.get('outputRoot')!=str(output) or not output.is_absolute() or output.resolve()!=output or output.is_relative_to(source):raise RuntimeError('External build binding mismatch')
        if inventory(output)!=manifest['clientBuildInventory']:raise RuntimeError('External build changed')
    for key in ['clientSourceInventory','clientPublicInventory','clientDependencyInventory','clientBuildInventory']:
        if report.get(key+'Sha256')!=inventory_sha(manifest[key]):raise RuntimeError('Build provenance mismatch')

def current_build_fingerprint(source,mode=None):
    # Recorder bytes admitted in sourcePins before import; import performs no build.
    p=source/'tests/release-inputs/record-current-frontend-build.py'
    spec=importlib.util.spec_from_file_location('finflow_build_admission',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if Path(module.__file__).resolve()!=p:raise RuntimeError('Build recorder origin mismatch')
    if mode not in (None,'legacy','private-external-v1'):raise RuntimeError('Unknown build input mode')
    return module.fingerprint(module.private_inputs(source) if mode=='private-external-v1' else module.inputs(source))

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

def check_logs(evidence,profile_name='runtime/browser-profile'):
    total=0
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            try:metadata=p.lstat()
            except FileNotFoundError:continue # Chrome can retire transient profile entries between samples.
            if stat.S_ISLNK(metadata.st_mode):
                profile=evidence/profile_name
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

def store_configuration(label,port,nonce,profile='finflow'):
    import re
    fullapp=profile in (*DPI_PROFILES,CSRF_PROFILE)
    if label not in ([row[0] for row in DPI_STORES] if fullapp else ('identity','finflow')) or type(port) is not int or not 1<=port<=65535 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Closed store/port/nonce required')
    migration='dvaia_'+label+'_migration';role='dvaia_'+label+'_runtime';database=('owasp_ai_goat_test_csrf_browser_' if profile==CSRF_PROFILE else 'owasp_ai_goat_test_dpi_browser_' if fullapp else 'owasp_ai_goat_test_finflow_browser_')+nonce+'_'+label
    sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{role};'
    prefix=dict(DPI_STORES)[label] if fullapp else 'IDENTITY' if label=='identity' else 'FINFLOW_WORKSHOP'
    urls={prefix+suffix:f'postgresql://{username}@127.0.0.1:{port}/{database}' for suffix,username in [('_MIGRATION_DATABASE_URL',migration),('_DATABASE_URL',role)]}
    if fullapp and label=='ctf':
        sql+=' CREATE ROLE dvaia_ctf_delivery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT CONNECT ON DATABASE '+database+' TO dvaia_ctf_delivery;'
        urls['CTF_DELIVERY_DATABASE_URL']=f'postgresql://dvaia_ctf_delivery@127.0.0.1:{port}/{database}'
    return sql,urls


def private_input_digest(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid() or before.st_mode&0o077 or before.st_size>16*1024*1024:raise RuntimeError('Private owned regular input required')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(16*1024*1024+1)
        after=os.fstat(fd)
        if len(data)!=before.st_size or after.st_mtime_ns!=before.st_mtime_ns:raise RuntimeError('Frozen input changed while reading')
        return hashlib.sha256(data).hexdigest()
    finally:os.close(fd)


def validate_actual_input(args,source,manifest):
    relative,pin={'backup':(ACTUAL_INPUT,ACTUAL_INPUT_SHA256),'actual-admin-enum':(ADMIN_ENUM_ACTUAL_INPUT,ADMIN_ENUM_ACTUAL_INPUT_SHA256),'actual-dpi-system-prompt':(DPI_INPUT,DPI_INPUT_SHA256),'actual-dpi-baseline-language':(DPI_BASELINE_LANGUAGE_INPUT,DPI_BASELINE_LANGUAGE_INPUT_SHA256),DPI_PENDING_PROFILE:(DPI_PENDING_INPUT,DPI_PENDING_INPUT_SHA256),'actual-dpi-multilingual70b':(DPI_70B_INPUT,DPI_70B_INPUT_SHA256),'actual-dpi-multilingual70b-credit':(DPI_70B_CREDIT_INPUT,DPI_70B_CREDIT_INPUT_SHA256),DPI_WHOLE_TASK_70B_PROFILE:(DPI_WHOLE_TASK_70B_INPUT,DPI_WHOLE_TASK_70B_INPUT_SHA256),DPI_SELECTED_TASK_70B_PROFILE:(DPI_SELECTED_TASK_70B_INPUT,DPI_SELECTED_TASK_70B_INPUT_SHA256),DPI_SELECTED_TASK_V16_70B_PROFILE:(DPI_SELECTED_TASK_70B_INPUT,DPI_SELECTED_TASK_70B_INPUT_SHA256),DPI_TECHNIQUES_SELECTED_70B_PROFILE:(DPI_TECHNIQUES_SELECTED_70B_INPUT,DPI_TECHNIQUES_SELECTED_70B_INPUT_SHA256),DPI_TECHNIQUES_SELECTED_8B_PROFILE:(DPI_TECHNIQUES_SELECTED_8B_INPUT,DPI_TECHNIQUES_SELECTED_8B_INPUT_SHA256),DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE:(DPI_TECHNIQUES_SELECTED_8B_AWARDED_INPUT,DPI_TECHNIQUES_SELECTED_8B_AWARDED_INPUT_SHA256),CSRF_PROFILE:(CSRF_INDIRECT_INPUT,CSRF_INDIRECT_INPUT_SHA256),'controlled-statement':(STATEMENT_INPUT,STATEMENT_INPUT_SHA256),'controlled-traversal-content':(TRAVERSAL_INPUT,TRAVERSAL_INPUT_SHA256),'controlled-backup-content':(BACKUP_CONTENT_INPUT,BACKUP_CONTENT_INPUT_SHA256),'controlled-ssrf-content':(SSRF_CONTENT_INPUT,SSRF_CONTENT_INPUT_SHA256),'controlled-recon-content':(RECON_CONTENT_INPUT,RECON_CONTENT_INPUT_SHA256),'controlled-admin-log-content':(ADMIN_LOG_CONTENT_INPUT,ADMIN_LOG_CONTENT_INPUT_SHA256),'controlled-admin-artifact-content':(ADMIN_ARTIFACT_CONTENT_INPUT,ADMIN_ARTIFACT_CONTENT_INPUT_SHA256),'controlled-admin-enum-content':(ADMIN_ENUM_CONTENT_INPUT,ADMIN_ENUM_CONTENT_INPUT_SHA256)}[selected_profile(args)]
    expected=source/relative
    if args.input!=str(expected) or args.input_sha256!=pin or expected.is_symlink() or expected.resolve()!=expected:raise RuntimeError('Exact frozen actual input required')
    input_digest=digest(expected) if selected_profile(args)==DPI_PENDING_PROFILE else private_input_digest(expected)
    if manifest.get('sourcePins',{}).get(relative)!=pin or input_digest!=pin:raise RuntimeError('Frozen input pin mismatch')

def verify_dpi_model_digest(profile):
    request=urllib.request.Request('http://127.0.0.1:11434/api/tags',method='GET')
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:
        if response.status!=200:raise RuntimeError('DPI model inventory unavailable')
        rows=json.load(response).get('models',[])
    model,digest=('llama3.3:70b',CSRF_70B_MODEL_DIGEST) if profile==CSRF_PROFILE else ('llama3.3:70b',DPI_70B_MODEL_DIGEST) if profile in DPI_70B_PROFILES else ('llama3.1:8b',DPI_MODEL_DIGEST)
    if len([row for row in rows if row.get('name')==model and row.get('digest')==digest])!=1:raise RuntimeError('DPI model digest changed')

def verify_csrf_actual_result(result,wire):
    indirect=result.get('indirect',{});calls=result.get('actualHttpCalls')
    expected_cases=['clean-Q1','off-topic','on-topic-first','same-query-replay','on-topic-second','defended-second-query']
    if result.get('mode')!='actual-indirect-chain' or result.get('controlledDisplayProjection')is not False or result.get('actualModel')is not True or indirect.get('status')!='passed' or indirect.get('technicalComplete')is not True or indirect.get('acceptedObjectives')!=['csrf_i1','csrf_i2','csrf_i3'] or indirect.get('notAttemptedActorCases')!=[] or [row.get('name') for row in indirect.get('cases',[])]!=expected_cases or type(calls)is not int or not 6<=calls<=18:raise RuntimeError('CSRF actual indirect receipt required')
    if wire.get('modelDigest')!=CSRF_70B_MODEL_DIGEST or len(wire.get('calls',[]))!=calls:raise RuntimeError('CSRF model wire mismatch')
    for row in wire['calls']:
        if row.get('model')!='llama3.3:70b' or row.get('status')!=200 or row.get('responseComplete')is not True or row.get('responseCaptureTruncated')is not False or row.get('endpoint') not in ('/api/chat','/api/generate'):raise RuntimeError('CSRF model wire mismatch')
        for field in ('request','response'):
            value=row.get(field)
            if not isinstance(value,str) or hashlib.sha256(value.encode()).hexdigest()!=row.get(field+'Sha256'):raise RuntimeError('CSRF model wire hash mismatch')


def child_environment(clean,evidence,runtime,owner,args):
    if is_csrf(args):
        return {**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','JWT_SECRET':secrets.token_urlsafe(48),'PG_TEST_DISPOSABLE':'yes','CSRF_FULL_INDEX_MODE':'actual-indirect-chain','CSRF_FULL_INDEX_70B':'yes','CSRF_HTML_SUMMARY_TIMEOUT_MS':'55000','CSRF_FULL_INDEX_SOURCE_ROOT':args.main_workspace,'CSRF_FULL_INDEX_RUNTIME_ROOT':str(runtime),'CSRF_FULL_INDEX_BROWSER_EXECUTABLE':args.browser,'CSRF_FULL_INDEX_BROWSER_SHA256':args.browser_sha256,'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':args.main_workspace,'LISTINGS_EVIDENCE_ROOT':str(evidence),'OWNED_LISTING_RESULT':str(evidence/'result.json'),'AI_PROVIDER':'ollama','OLLAMA_BASE_URL':'http://127.0.0.1:11434','OLLAMA_MODEL':'llama3.3:70b','JUDGE_PROVIDER':'ollama','JUDGE_MODEL':'llama3.3:70b','ANALYTICS_BROWSER_EXECUTABLE':args.browser,'ANALYTICS_BROWSER_SHA256':args.browser_sha256,'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'AWS_EC2_METADATA_DISABLED':'true','LOGS_DIR':str(runtime/'logs'),'PG_TLS':'disable'}
    if is_dpi(args):
        return {**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','JWT_SECRET':secrets.token_urlsafe(48),'PG_TEST_DISPOSABLE':'yes',
          ('DPI_BROWSER_RETAINED_PENDING_8B' if selected_profile(args)==DPI_PENDING_PROFILE else 'DPI_ACTUAL_SYSTEM_PROMPT_RENDERED' if selected_profile(args)=='actual-dpi-system-prompt' else 'DPI_BROWSER_ACTUAL_TECHNIQUES_SELECTED_8B' if is_techniques_selected_8b(args) else 'DPI_BROWSER_ACTUAL_TECHNIQUES_SELECTED_70B' if is_techniques_selected_70b(args) else 'DPI_BROWSER_ACTUAL_SIDE_SELECTED_V16_70B' if is_selected_task_v16_70b(args) else 'DPI_BROWSER_ACTUAL_SIDE_SELECTED_70B' if is_selected_task70b(args) else 'DPI_ACTUAL_WHOLE_TASK70B_RENDERED' if is_whole_task70b(args) else 'DPI_ACTUAL_MULTILINGUAL70B_RENDERED' if is_70b(args) else 'DPI_ACTUAL_BASELINE_LANGUAGE_RENDERED'):'1','DPI_BROWSER_RUNTIME_CWD':str(runtime),'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':args.main_workspace,'LISTINGS_EVIDENCE_ROOT':str(evidence),'OWNED_LISTING_RESULT':str(evidence/'result.json'),
          'DPI_MULTILINGUAL70B_EXPECT_CREDIT':'1' if selected_profile(args)=='actual-dpi-multilingual70b-credit' else '0','DPI_BROWSER_CREDIT_TECHNIQUES_SELECTED_8B':'1' if is_techniques_selected_8b_awarded(args) else '0','DPI_ACTUAL_BROWSER_INPUT':args.input,'DPI_ACTUAL_BROWSER_INPUT_SHA256':args.input_sha256,'AI_PROVIDER':'ollama','OLLAMA_BASE_URL':'http://127.0.0.1:11434','OLLAMA_MODEL':'llama3.3:70b' if is_70b(args) else 'llama3.1:8b','JUDGE_PROVIDER':'ollama','JUDGE_MODEL':'llama3.3:70b' if is_70b(args) else 'llama3.1:8b',
          **({'OLLAMA_CONTEXT_WINDOW':'8192' if is_techniques_selected_8b(args) else '20480' if is_techniques_selected_70b(args) else '32768','JUDGE_CONTEXT_TOKENS':'32768' if is_techniques_selected_8b(args) else '20480' if is_techniques_selected_70b(args) else '32768'} if is_whole_task70b(args) or is_selected_task_profile(args) else {}),
          'ANALYTICS_BROWSER_EXECUTABLE':args.browser,'ANALYTICS_BROWSER_SHA256':args.browser_sha256,'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'AWS_EC2_METADATA_DISABLED':'true','LOGS_DIR':str(runtime/'logs'),'PG_TLS':'disable'}
    return {**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres',
      'JWT_SECRET':secrets.token_urlsafe(48),'PG_TEST_DISPOSABLE':'yes','FINFLOW_BACKUP_BROWSER_NATIVE':'1','SENSITIVE_INFO_AGGREGATE_RESET_ENABLED':'true',
      'FINFLOW_BROWSER_EVIDENCE_ROOT':str(evidence),'FINFLOW_BROWSER_OWNER':owner,'FINFLOW_BROWSER_SOURCE_ROOT':args.main_workspace,
      'FINFLOW_BROWSER_MANIFEST':str(Path(args.manifest).resolve()),'FINFLOW_BROWSER_MANIFEST_SHA256':args.manifest_sha256,
      **({'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':args.main_workspace} if selected_profile(args)=='actual-admin-enum' else {}),'FINFLOW_BROWSER_PROFILE':selected_profile(args),'FINFLOW_BROWSER_INPUTS':args.input,'FINFLOW_BROWSER_INPUTS_SHA256':args.input_sha256,
      'FINFLOW_BROWSER_CHROME':args.browser,'FINFLOW_BROWSER_CHROME_SHA256':args.browser_sha256,
      'ANALYTICS_BROWSER_EXECUTABLE':args.browser,'ANALYTICS_BROWSER_SHA256':args.browser_sha256,
      'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'FINFLOW_BACKUP_ROOT':str(runtime/'appdata'/'finflow-backups'),'FINFLOW_TRAVERSAL_TARGET_ROOT':str(runtime/'appdata'/'finflow-traversal-targets'),
      'AWS_EC2_METADATA_DISABLED':'true','LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'PG_TLS':'disable'}

def verify_browser_absence(runtime,state,rows):
    if state.get('profile')==CSRF_PROFILE:
        evidence=Path(state['evidenceRoot'])
        if any((base/name).exists() or (base/name).is_symlink() for base in (runtime,evidence) for name in ('browser-process.json','browser-launch-intent.json','dpiparity-process.json','dpiparity-cleanup.json')):raise RuntimeError('Unexpected CSRF browser process evidence')
        return {'started':False,'browserScope':'API-only indirect chain','ownedChildGroupAbsent':True}
    if state.get('profile') in DPI_PROFILES:
        evidence=Path(state['evidenceRoot']);observed=evidence/'dpiparity-process.json';cleanup=evidence/'dpiparity-cleanup.json';intent=evidence/'browser-launch-intent.json'
        if state.get('bootPreflight') is True and state.get('exitCode')==0 and not observed.exists() and not cleanup.exists():return {'started':False,'bootOnly':True,'profileRetained':False}
        if state.get('exitCode')!=0 and not observed.exists() and not cleanup.exists() and not intent.exists():return {'started':False,'failureBeforeBrowser':True,'profileRetained':False}
        if intent.exists():
            st=intent.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_size>4096:raise RuntimeError('DPI browser intent invalid')
            row=json.loads(intent.read_text())
            if row.get('profile')!=state.get('profile') or row.get('root')!=str(evidence) or row.get('runtime')!=str(runtime):raise RuntimeError('DPI browser intent mismatch')
        elif observed.exists() or cleanup.exists():raise RuntimeError('DPI browser intent missing')
        if observed.is_symlink() or cleanup.is_symlink() or not observed.is_file() or not cleanup.is_file():raise RuntimeError('DPI browser ownership evidence missing')
        identity=json.loads(observed.read_text());retired=json.loads(cleanup.read_text());pid=identity.get('pid')
        if type(pid)is not int or pid<=1 or retired.get('pid')!=pid or retired.get('leaderReaped')is not True or any(row[0]==pid for row in rows):raise RuntimeError('DPI browser process not retired')
        if identity.get('executableSha256')!=state['browserSha256'] or identity.get('profile')!=str(evidence/'dpiparity-profile'):raise RuntimeError('DPI browser binding mismatch')
        return {'started':True,'browserPidAbsent':True,'profileRetained':True,'ownedChildGroupAbsent':True}
    journal=runtime/'browser-process.json'
    if not journal.exists():
        if state.get('exitCode')==0 and state.get('profile')!='actual-admin-enum':raise RuntimeError('Missing browser ownership evidence')
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

def verify_admin_enum_actual_result(value,wire,captures):
    def require(ok,message):
        if not ok:raise RuntimeError(message)
    model='llama3.1:8b';digest_pin='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
    require(all(type(value.get(k))is type(v) and value[k]==v for k,v in {'profile':'actual-admin-enum','scope':'eight-turn-admin-enum-actual-native','status':'passed','installedWrites':False,'actualModelProof':True,'modelWireVerified':True,'model':model,'modelDigest':digest_pin,'failures':[],'cleanupFailures':[]}.items()),'Actual enum receipt identity')
    require(value.get('sequenceSha256')==['3eaca9dfddaed8556c88571d7cf955e46a03352adc716613a899aa032928a802','52a906ff9d35a60a62a090075260a6b9026674b26edd35644939206f396af91f'],'Frozen sequence required')
    require(wire.get('version')=='admin-enum-wire-v1' and wire.get('profile')=='admin-enum' and wire.get('model')==model and wire.get('digest')==digest_pin and wire.get('closed')is True and wire.get('physicalPending')==0 and wire.get('failures')==[],'Complete exact model wire required')
    calls=wire.get('calls',[]);counts=wire.get('counts',{})
    require(value.get('counts')==counts,'Wire counts mismatch')
    for kind,limit in ADMIN_ENUM_WIRE_BUDGET.items():require(type(counts.get(kind))is int and 0<=counts[kind]<=limit,'Wire budget exceeded')
    require(counts['tags']>=1,'Model identity observation required')
    require(counts['external']==len(calls) and counts['metadata']==counts['tags']+counts['version'],'Wire totals mismatch')
    for index,call in enumerate(calls):
        require(call.get('index')==index and call.get('kind') in ['generate','chat','tags','version'] and call.get('terminal')=='returned' and call.get('responseComplete')is True and call.get('responseCaptureTruncated')is False and call.get('status')==200,'Incomplete wire row')
        if call['kind'] in ['generate','chat']:
            require(call.get('caseId') in ADMIN_ENUM_CASES and json.loads(call.get('request','{}')).get('model')==model,'Closed inference case/model required')
        for field in ['request','response']:
            raw=call.get(field);require(isinstance(raw,str) and hashlib.sha256(raw.encode()).hexdigest()==call.get(field+'Sha256') and len(raw.encode())==call.get(field+'Bytes'),'Wire bytes mismatch')
    for kind in ['generate','chat','tags','version']:require(counts[kind]==sum(c['kind']==kind for c in calls),'Wire kind count mismatch')
    require(captures.get('profile')=='actual-admin-enum' and [c.get('caseId') for c in captures.get('cases',[])]==ADMIN_ENUM_CASES,'Exact ordered captures required')
    owners=['fresh-owner-1','fresh-owner-2','fresh-owner-3','fixed'];rows=value.get('cases',[])
    require([c.get('name') for c in rows]==owners+['owner-reset'],'Exact result cohort required')
    prior={};seen_owners=set()
    for index,capture in enumerate(captures['cases']):
        owner_index=index//2;turn=index%2;row=rows[owner_index];case_id=ADMIN_ENUM_CASES[index]
        required=['initialized',f'turn_{turn+1}_http',f'turn_{turn+1}_actual_model',f'turn_{turn+1}_judge_provenance',f'turn_{turn+1}_persisted_receipt',f'turn_{turn+1}_packet_wire_binding','benign_first_turn_no_credit']
        if turn:required+=['generated_history_used']+(['fixed_mode_set','fixed_catalog_unavailable','fixed_denied_credit'] if owner_index==3 else ['fresh_catalog_selected','authoritative_catalog_received','eight_names','real_judge_pass','canonical_credit'])
        require(all(row.get('checks',{}).get(k)is True for k in required),'Missing original cohort check')
        owner=capture.get('ownerId');require(type(owner)is int and owner>0,'Owner identity required')
        if not turn:require(owner not in seen_owners,'Fresh owner required');seen_owners.add(owner)
        else:require(owner==prior['ownerId'],'Same two-turn owner required')
        request=capture.get('request',{});history=[] if not turn else [{'role':'user','content':prior['request']['userMessage']},{'role':'assistant','content':prior['response']['body']['response']}]
        require(request.get('objectiveId')=='admin_enum' and hashlib.sha256(request.get('userMessage','').encode()).hexdigest()==value['sequenceSha256'][turn] and request.get('conversationHistory')==history,'Frozen request/history binding required')
        response=capture.get('response',{});run=capture.get('run',{});judgment=capture.get('judgment',{});record=capture.get('packetRecord',{});packet=capture.get('packet',{})
        require(response.get('status')==200 and not capture.get('bindingError'),'Successful bound response required')
        run_id=response.get('body',{}).get('run',{}).get('runId');require(bool(run_id) and run.get('run_id')==run_id and run.get('owner_key')==json.dumps(['FinFlow',str(owner)],separators=(',',':')) and judgment.get('run_id')==run_id and judgment.get('user_id')==owner,'Owner/run lineage mismatch')
        require(record.get('user_id')==owner and record.get('evaluation_id')==judgment.get('evaluation_id') and isinstance(record.get('packet'),str) and json.loads(record['packet'])==packet and hashlib.sha256(record['packet'].encode()).hexdigest()==judgment.get('evidence_digest'),'Canonical packet mismatch')
        rubric=packet.get('rubric',{});version=rubric.get('version');protocol=rubric.get('finflowAdminCatalogSelection')
        require(rubric.get('objectiveId')=='admin_enum' and ((version=='finflow-admin-catalog-v2' and protocol is None) or (version=='finflow-admin-catalog-v3' and protocol=='finflow-admin-catalog-selection-v1')) and isinstance(capture.get('trace'),list) and len(capture['trace'])>0,'Evidence/trace required')
        if version=='finflow-admin-catalog-v3':
            audit=judgment.get('result_json',{}).get('finflowCatalogSelection',{})
            require(audit.get('version')==protocol and audit.get('evidenceId')=='response' and audit.get('evidenceDigest')==judgment.get('evidence_digest') and audit.get('responseSha256')==hashlib.sha256(response.get('body',{}).get('response','').encode()).hexdigest(),'Selection packet/response binding required')
        positive=turn==1 and owner_index<3
        require(judgment.get('verdict')==('pass' if positive else 'fail') and judgment.get('disposition')==('awarded' if positive else 'not_pass'),'Canonical positive/negative mismatch')
        selected=[c for c in calls if c.get('caseId')==case_id];require(capture.get('wireIndexes')==[c['index'] for c in selected],'Case wire binding mismatch')
        require(2<=sum(c['kind']=='generate' for c in selected)<=10 and 1<=sum(c['kind']=='chat' for c in selected)<=2,'Case inference budget mismatch')
        require(len(row.get('turns',[]))==2 and row['turns'][turn].get('turn')==turn+1,'Turn receipt required');prior=capture
    reset=captures.get('reset',{});before=reset.get('before',[]);after=reset.get('after',[])
    require(len(before)==len(after)==4 and reset.get('response',{}).get('status')==200 and after[0].get('rows')==[] and after[0].get('generation')==before[0].get('generation',-2)+1 and before[1:]==after[1:] and all(before[i].get('rows') for i in [1,2]),'Reset/sibling proof mismatch')
    require(all(rows[-1].get('checks',{}).get(k)is True for k in ['reset_success','siblings_preserved','sibling_credit_nonempty']),'Reset checks required')


def verify_statement_result(value):
    if value.get('profile')!='controlled-statement' or value.get('scope')!='controlled-statement-download':raise RuntimeError('Statement profile receipt required')
    for key,expected in {'actualModelProof':False,'modelWireVerified':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'ownerBound':True,'resetAdvanced':True,'staleDenied':True,'siblingPreserved':True,'revocationDenied':True}.items():
        if type(value.get(key)) is not type(expected) or value[key]!=expected:raise RuntimeError('Statement proof mismatch')
    for key,limit in [('controlledCalls',8),('apiRequests',30),('browserRequests',400)]:
        if type(value.get(key))is not int or not 1<=value[key]<=limit:raise RuntimeError('Statement count mismatch')
    rows=value.get('downloads')
    if not isinstance(rows,list) or len(rows)!=3:raise RuntimeError('Three statement downloads required')
    for row in rows:
        if set(row)!={'sha256','byteLength','objects','pages','filename'} or row['filename']!='statement_FF-001_2024.pdf' or row['objects']!=5 or row['pages']!=1 or type(row['byteLength'])is not int or not 500<row['byteLength']<65536 or not isinstance(row['sha256'],str) or len(row['sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['sha256']):raise RuntimeError('Statement byte proof mismatch')


def verify_traversal_content_result(value,profile='controlled-traversal-content'):
    profiles={'controlled-traversal-content':('three-objective-controlled-rendered-parity',['traversal_secrets','traversal_passwd','traversal_llm']),'controlled-backup-content':('two-objective-controlled-backup-rendered-parity',['admin_backup','admin_dl_backup']),'controlled-ssrf-content':('three-objective-controlled-ssrf-rendered-parity',['ssrf_oob','ssrf_internal','ssrf_ollama']),'controlled-recon-content':('four-objective-controlled-recon-rendered-parity',['tool_enum','llm_identify','tool_version','error_leak']),'controlled-admin-log-content':('two-objective-controlled-admin-log-rendered-parity',['admin_read_logs','admin_llm_logs']),'controlled-admin-artifact-content':('two-objective-controlled-admin-artifact-rendered-parity',['admin_secrets','admin_dirlist']),'controlled-admin-mutation-content':('one-objective-controlled-admin-mutation-rendered-parity',['admin_modify_logs']),'controlled-admin-enum-content':('one-objective-controlled-admin-enum-content-lifecycle',['admin_enum'])}
    if profile not in profiles:raise RuntimeError('Closed content profile required')
    scope,ids=profiles[profile]
    if profile=='controlled-ssrf-content':
        seed=value.get('seedQualification',{})
        if seed.get('version')!='finflow-ssrf-seed-v1' or seed.get('objectiveIds')!=ids or type(seed.get('exactSecondSeeds')) is not int or seed['exactSecondSeeds']!=4:raise RuntimeError('SSRF seed identity required')
        for key in ['freshDefaults','managedPriorUpgrade','instructorCustomPreserved','explicitNullPreserved','independentGatesPreserved','siblingCatalogPreserved','rollbackRestored']:
            if seed.get(key) is not True:raise RuntimeError('SSRF seed preservation required')
    expected={'profile':profile,'scope':scope,'actualModelProof':False,'modelWireVerified':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'projection':'controlled-existing-completion-shape','siblingPreserved':True,'configurationRestored':True,'projectionRowsPreserved':True,'dashboardParity':True}
    if profile=='controlled-admin-enum-content':
        expected.update(nonemptyPreservationFixtures=True,preservationFixtureScope='Controlled nonempty owner other-family and sibling canonical/time/local rows; no genuine credit',projectionRowsPreserved=False,projectionRetired=True,resetTimeRetired=True,resetReplayExact=True,sessionDenied=True,adminProgress=True,untouchedFamiliesPreserved=True,judgeCalls=0,controlledProjectionCount=1,immutableEvidencePreserved=False,immutableEvidenceScope='Empty content fixture; native immutable reset evidence is separate')
        lifecycle=value.get('lifecycle')
        if not isinstance(lifecycle,dict) or any(not isinstance(lifecycle.get(k),dict) for k in ['resetBefore','resetAfter','replayAfter','reset','replay']):raise RuntimeError('Admin enum lifecycle evidence required')
        reset=lifecycle['reset']
        if reset!=lifecycle['replay'] or reset.get('status')!='completed' or type(reset.get('fromGeneration'))is not int or type(reset.get('toGeneration'))is not int or reset['toGeneration']!=reset['fromGeneration']+1:raise RuntimeError('Exact completed reset replay required')
    for key,want in expected.items():
        if type(value.get(key))is not type(want) or value[key]!=want:raise RuntimeError('Traversal content receipt mismatch')
    rows=value.get('cases')
    if not isinstance(rows,list) or len(rows)!=len(ids):raise RuntimeError('Exact content cases required')
    for row,id in zip(rows,ids):
        if row.get('id')!=id or any(row.get(k)is not True for k in ['learnerContent','adminPreview','independentGates','completedProjection']):raise RuntimeError('Traversal case incomplete')
    for key,limit in [('apiRequests',40),('browserRequests',500 if profile=='controlled-recon-content' else 400)]:
        if type(value.get(key))is not int or not 1<=value[key]<=limit:raise RuntimeError('Traversal content request bound')


def main_parser():
    parser=argparse.ArgumentParser(description='Explicit main-only FinFlow two-turn browser qualification',allow_abbrev=False)
    for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--input',required=True)
    parser.add_argument('--input-sha256',required=True)
    parser.add_argument('--profile',choices=['backup','actual-admin-enum','actual-dpi-system-prompt','actual-dpi-baseline-language',DPI_PENDING_PROFILE,'actual-dpi-multilingual70b','actual-dpi-multilingual70b-credit',DPI_WHOLE_TASK_70B_PROFILE,DPI_SELECTED_TASK_70B_PROFILE,DPI_SELECTED_TASK_V16_70B_PROFILE,DPI_TECHNIQUES_SELECTED_70B_PROFILE,DPI_TECHNIQUES_SELECTED_8B_PROFILE,DPI_TECHNIQUES_SELECTED_8B_AWARDED_PROFILE,CSRF_PROFILE,'controlled-statement','controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'],default='backup')
    parser.add_argument('--plan',action='store_true')
    parser.add_argument('--dpi-boot-preflight',action='store_true',help='Owned full-index startup and teardown without browser or model generation')
    parser.add_argument('--dpi-health-preflight',action='store_true',help='Real provider metadata and rendered status without model generation')
    parser.add_argument('--dpi-tail-preflight',action='store_true',help='Controlled baseline/language rendered tail with zero model calls')
    return parser

def parse_main(argv):
    flags=[value.split('=',1)[0] for value in argv if value.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flags denied')
    args=main_parser().parse_args(argv)
    return args

def main_current(argv):
    args=parse_main(argv)
    boot_preflight=getattr(args,'dpi_boot_preflight',False)
    health_preflight=getattr(args,'dpi_health_preflight',False)
    tail_preflight=getattr(args,'dpi_tail_preflight',False)
    if boot_preflight and selected_profile(args)!='actual-dpi-system-prompt':raise RuntimeError('DPI boot preflight requires exact system prompt profile')
    if health_preflight and (selected_profile(args)!='actual-dpi-system-prompt' or boot_preflight):raise RuntimeError('DPI rendered health preflight requires exact system prompt profile')
    if tail_preflight and (selected_profile(args)!='actual-dpi-baseline-language' or boot_preflight or health_preflight):raise RuntimeError('DPI controlled tail requires exact baseline/language profile')
    source,manifest=validate_main(args)
    work_seconds,child_seconds=(780,600) if tail_preflight else (1920,1560) if is_csrf(args) else (1380,1200) if selected_profile(args) in ('actual-admin-enum',*DPI_PROFILES) else (780,600)
    if args.plan:
        print(json.dumps({'cohort':selected_cohort(args),'mode':'controlled-tail' if tail_preflight else selected_mode(args),'stores':[label for label,_ in DPI_STORES] if is_fullapp(args) else ['identity','finflow'],'syntheticProvider':tail_preflight or selected_profile(args) not in ('backup','actual-admin-enum',*DPI_PROFILES,CSRF_PROFILE),'maxModelCalls':0 if tail_preflight or selected_profile(args)==DPI_PENDING_PROFILE else 18 if is_csrf(args) else None,'modelHttpTimeoutMs':60000 if is_csrf(args) else None,'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':120,'integritySeconds':120,'allocation':False}));return 0
    # Exact helper bytes admitted above; no dynamic code import before source/pin validation.
    def load(name):
        p=source/'tests/postgres'/f'{name}.py';spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if Path(module.__file__).resolve()!=p:raise RuntimeError('Helper origin mismatch')
        return module
    processes_module=load('sql_nosql_process_ownership');docker_module=load('sql_nosql_docker_ownership')
    if shutil.disk_usage(source).free<2*1024**3+1024**3+2*256*1024**2+64*1024**2:raise RuntimeError('Owned runtime/artifact space plus2GiB reserve required')
    parent=source/'backups/private-recovery'/('csrf-indirect-main' if is_csrf(args) else 'dpi-browser' if is_dpi(args) else 'finflow-browser');parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private main evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent))
    runtime=Path(tempfile.mkdtemp(prefix='owasp-ai-goat-csrf-indirect-runtime-' if is_csrf(args) else 'owasp-ai-goat-dpi-browser-runtime-',dir='/private/tmp')) if is_fullapp(args) else evidence/'runtime'
    if not is_fullapp(args):runtime.mkdir(mode=0o700)
    def checked_logs():
        total=check_logs(evidence,'dpiparity-profile' if is_dpi(args) else 'runtime/browser-profile')
        if is_fullapp(args):total+=check_logs(runtime)
        return total
    for name in (['home','tmp','logs','assets','downloads'] if is_fullapp(args) else ['home','tmp','logs','assets','appdata','downloads']):(runtime/name).mkdir(mode=0o700)
    clean={'PATH':str(Path(args.node).parent)+':'+str(Path(args.docker).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LANG':'C','DOCKER_HOST':args.docker_host}
    owner=str(uuid.uuid4());name=('owasp-ai-goat-csrf-indirect-' if is_csrf(args) else 'owasp-ai-goat-dpi-browser-' if is_dpi(args) else 'owasp-ai-goat-finflow-browser-')+uuid.uuid4().hex[:12];labels={'owasp-ai-goat.owner':owner,'owasp-ai-goat.cohort':selected_cohort(args)}
    state={'profile':selected_profile(args),'cohort':selected_cohort(args),'sourceRoot':str(source),'parentPid':os.getpid(),'owner':owner,'children':[],'nativeStarted':False,'mode':'controlled-tail' if tail_preflight else selected_mode(args),'manifestSha256':args.manifest_sha256,'containerName':name,'containerLabels':labels,'imageId':args.image_id,'dockerDaemon':args.docker_daemon,'creationAttempted':False,'scenario':'csrf-indirect-api' if is_csrf(args) else 'dpi-'+('baseline-language-tail' if tail_preflight else 'retained-pending8b' if selected_profile(args)==DPI_PENDING_PROFILE else 'baseline-language' if selected_profile(args)=='actual-dpi-baseline-language' else 'techniques-selected8b-awarded' if is_techniques_selected_8b_awarded(args) else 'techniques-selected8b-pending' if is_techniques_selected_8b(args) else 'techniques-selected70b-awarded' if is_techniques_selected_70b(args) else 'side-selected-v16-awarded' if is_selected_task_v16_70b(args) else 'side-selected70b-pending' if is_selected_task70b(args) else 'whole-task70b-pending' if is_whole_task70b(args) else 'multilingual70b-credit' if selected_profile(args)=='actual-dpi-multilingual70b-credit' else 'multilingual70b' if is_70b(args) else 'system-prompt')+'-browser' if is_dpi(args) else 'finflow-backup-browser','nonce':owner.replace('-','')[:12],'evidenceRoot':str(evidence),'externalRuntimeRoot':str(runtime) if is_fullapp(args) else None,'browserSha256':args.browser_sha256,'bootPreflight':boot_preflight}
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
        if is_fullapp(args) and not boot_preflight and not tail_preflight and selected_profile(args)!=DPI_PENDING_PROFILE:verify_dpi_model_digest(selected_profile(args))
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
        if boot_preflight:env['DPI_FULLAPP_BOOT_ONLY']='1'
        if health_preflight:env['DPI_FULLAPP_HEALTH_ONLY']='1'
        if tail_preflight:env['DPI_FULLAPP_TAIL_ONLY']='1'
        for label in ([row[0] for row in DPI_STORES] if is_fullapp(args) else ['identity','finflow']):
            sql,urls=store_configuration(label,port,owner.replace('-','')[:12],selected_profile(args))
            phase('provision-'+label)
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            env.update(urls)
        phase('native-launch')
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            native='tests/postgres/csrfFullIndex.native.js' if is_csrf(args) else 'tests/postgres/dpiFullAppRendered.native.js' if is_dpi(args) else 'tests/postgres/finflowBackupBrowser.integration.test.js'
            child=owned.launch([args.node,str(source/native)],name='csrf-indirect' if is_csrf(args) else 'dpi-browser' if is_dpi(args) else 'finflow-browser',cwd=runtime,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(nativeStarted=True,nativePid=child.pid);record();child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
            until=time.monotonic()+remaining(child_seconds)
            while child.poll() is None:
                checked_logs()
                if time.monotonic()>=until:raise TimeoutError('Native child deadline')
                time.sleep(.1)
            code=child.returncode;owned.finish(child);checked_logs()
        state['exitCode']=code
        if code==0:
            result_file=evidence/'result.json'
            if result_file.is_symlink() or result_file.stat().st_size>262144:raise RuntimeError('Bounded result required')
            result=json.loads(result_file.read_text())
            if result.get('status')!='passed' or (not is_fullapp(args) and result.get('cleanupFailures')!=[]):raise RuntimeError('Successful child receipt required')
            if is_csrf(args):
                wire_file=evidence/'csrf-model-http.json'
                if wire_file.is_symlink() or wire_file.stat().st_size>8*1024*1024:raise RuntimeError('Bounded CSRF model wire required')
                verify_csrf_actual_result(result,json.loads(wire_file.read_text()))
            if is_dpi(args):
                if boot_preflight:
                    if result.get('bootOnly')is not True or result.get('modelCalls')!=0 or result.get('browserStarted')is not False:raise RuntimeError('DPI boot-only result required')
                elif health_preflight:
                    browser=result.get('browser',{})
                    if result.get('healthOnly')is not True or result.get('modelCalls')!=0 or result.get('actualActorCalls')!=0 or result.get('actualJudgeCalls')!=0 or browser.get('status')!='passed' or browser.get('healthOnly')is not True or browser.get('providerReady')is not True or browser.get('chatPosts')!=0 or browser.get('realJwtLogin')is not True:raise RuntimeError('DPI rendered real-provider health receipt required')
                elif tail_preflight:
                    browser=result.get('browser',{})
                    if result.get('tailOnly')is not True or result.get('modelCalls')!=0 or result.get('actualActorCalls')!=0 or result.get('actualJudgeCalls')!=0 or browser.get('status')!='passed' or browser.get('baselineLanguageTailOnly')is not True or browser.get('controlledPersistedDisplay')is not True or browser.get('realJwtLogin')is not True:raise RuntimeError('DPI zero-model controlled tail receipt required')
                elif selected_profile(args)==DPI_PENDING_PROFILE:
                    browser=result.get('browser',{})
                    if result.get('retainedPending8b')is not True or result.get('modelCalls')!=0 or result.get('actualActorCalls')!=0 or result.get('actualJudgeCalls')!=0 or result.get('noJudgeReceipts')is not True or result.get('siblingPreserved')is not True or browser.get('status')!='passed' or browser.get('retainedPending8b')is not True or browser.get('controlledPersistedDisplay')is not True or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':0,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=0 or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or browser.get('siblingRenderedPreserved')is not True or browser.get('revokedSessionDenied')is not True:raise RuntimeError('DPI retained pending zero-credit browser receipt required')
                    wire_file=evidence/'dpi-actual-model-wire.json'
                    if wire_file.is_symlink() or not wire_file.is_file() or json.loads(wire_file.read_text()).get('calls')!=[]:raise RuntimeError('DPI retained browser must make zero model calls')
                else:
                    wire=result.get('modelWire',{})
                    if selected_profile(args)=='actual-dpi-system-prompt':
                        if result.get('browser',{}).get('status')!='passed' or result.get('browser',{}).get('controlledPersistedDisplay')is not False or result.get('actualSystemPrompt',{}).get('disposition')!='awarded' or result.get('actualSystemPrompt',{}).get('actorTraceVerified')is not True or result.get('actualSystemPrompt',{}).get('judgeTraceVerified')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('actualActorCalls')!=1 or result.get('actualJudgeCalls')!=2 or wire.get('digest')!=DPI_MODEL_DIGEST or wire.get('physicalChatCalls')!=3 or len(wire.get('requestSha256',[]))!=3 or len(wire.get('responseSha256',[]))!=3:raise RuntimeError('DPI actual rendered receipt required')
                    elif is_techniques_selected_8b(args):
                        rows=result.get('actualTechniquesSelected8b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        judge_calls=result.get('actualJudgeCalls');attempts=[r.get('judgeAttempts') for r in rows];credit=is_techniques_selected_8b_awarded(args)
                        expected_dispositions=['not_pass','awarded','not_pass','awarded'] if credit else ['grading_unqualified']*4
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':2 if credit else 0,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=(2 if credit else 0) or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=4 or not isinstance(judge_calls,int) or not 4<=judge_calls<=8 or calls!=4+judge_calls or calls!=result.get('actualActorCalls')+judge_calls or wire.get('digest')!=DPI_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=4 or [r.get('id') for r in rows]!=['jailbreak-negative','jailbreak-positive','role-negative','role-positive'] or [r.get('objectiveId') for r in rows]!=['jailbreak','jailbreak','role_playing','role_playing'] or [r.get('verdict') for r in rows]!=['fail','pass','fail','pass'] or [r.get('disposition') for r in rows]!=expected_dispositions or any(not isinstance(attempt,int) or not 1<=attempt<=2 for attempt in attempts) or sum(attempts)!=judge_calls or any(r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI techniques selected 8B '+('awarded' if credit else 'pending')+' receipt required')
                    elif is_techniques_selected_70b(args):
                        rows=result.get('actualTechniquesSelected70b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':2,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=2 or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=4 or result.get('actualJudgeCalls')!=4 or calls!=8 or calls!=result.get('actualActorCalls')+result.get('actualJudgeCalls') or wire.get('digest')!=DPI_70B_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=4 or [r.get('id') for r in rows]!=['jailbreak-negative','jailbreak-positive','role-negative','role-positive'] or [r.get('objectiveId') for r in rows]!=['jailbreak','jailbreak','role_playing','role_playing'] or [r.get('verdict') for r in rows]!=['fail','pass','fail','pass'] or [r.get('disposition') for r in rows]!=['not_pass','awarded','not_pass','awarded'] or any(r.get('judgeAttempts')!=1 or r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI techniques selected 70B awarded receipt required')
                    elif is_selected_task_v16_70b(args):
                        rows=result.get('actualSideSelectedV16_70b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':1,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=1 or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=2 or result.get('actualJudgeCalls')!=2 or calls!=4 or calls!=result.get('actualActorCalls')+result.get('actualJudgeCalls') or wire.get('digest')!=DPI_70B_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=2 or [r.get('id') for r in rows]!=['side-aws-negative','side-interoperability-positive'] or [r.get('objectiveId') for r in rows]!=['side_stepping','side_stepping'] or [r.get('verdict') for r in rows]!=['fail','pass'] or [r.get('disposition') for r in rows]!=['not_pass','awarded'] or any(r.get('judgeAttempts')!=1 or r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI selected-task v16 awarded receipt required')
                    elif is_selected_task70b(args):
                        rows=result.get('actualSideSelected70b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':0,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=0 or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=2 or result.get('actualJudgeCalls')!=2 or calls!=4 or calls!=result.get('actualActorCalls')+result.get('actualJudgeCalls') or wire.get('digest')!=DPI_70B_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=2 or [r.get('id') for r in rows]!=['side-aws-negative','side-interoperability-positive'] or [r.get('objectiveId') for r in rows]!=['side_stepping','side_stepping'] or [r.get('verdict') for r in rows]!=['fail','pass'] or any(r.get('disposition')!='grading_unqualified' or r.get('judgeAttempts')!=1 or r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI selected-task 70B pending receipt required')
                    elif is_whole_task70b(args):
                        rows=result.get('actualWholeTask70b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':0,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=0 or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=6 or result.get('actualJudgeCalls')!=8 or calls!=14 or calls!=result.get('actualActorCalls')+result.get('actualJudgeCalls') or wire.get('digest')!=DPI_70B_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=4 or [r.get('id') for r in rows]!=['virtual-direct-negative','virtual-compound-positive','obfuscation-aws-negative','obfuscation-compound-positive'] or [r.get('objectiveId') for r in rows]!=['virtualization','virtualization','obfuscation','obfuscation'] or [r.get('verdict') for r in rows]!=['fail','pass','fail','pass'] or any(r.get('disposition')!='grading_unqualified' or r.get('judgeAttempts')!=2 or r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows) or [r.get('decoderEffectVerified') for r in rows]!=[False,False,True,True] or [r.get('taskCount') for r in rows]!=[1,2,1,2]:raise RuntimeError('DPI whole-task 70B pending receipt required')
                    elif is_70b(args):
                        rows=result.get('actualMultilingual70b',[]);calls=wire.get('physicalChatCalls');browser=result.get('browser',{})
                        credit=selected_profile(args)=='actual-dpi-multilingual70b-credit';expected=['not_pass','awarded'] if credit else ['grading_unqualified']*2;count=1 if credit else 0
                        if browser.get('status')!='passed' or browser.get('controlledPersistedDisplay')is not False or browser.get('realJwtLogin')is not True or browser.get('canonicalCount')!={'completed':count,'total':8} or browser.get('exerciseCount',{}).get('attackCompleted')!=count or browser.get('exerciseCount',{}).get('practiceCompleted')is not False or browser.get('independentHelpGateCombinations')!=32 or browser.get('reset')is not True or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('siblingPreserved')is not True or result.get('actualActorCalls')!=2 or not 2<=result.get('actualJudgeCalls',-1)<=8 or calls!=result.get('actualActorCalls')+result.get('actualJudgeCalls') or wire.get('digest')!=DPI_70B_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=2 or [r.get('objectiveId') for r in rows]!=['multi_language','multi_language'] or [r.get('disposition') for r in rows]!=expected or any(r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI 70B multilingual rendered receipt required')
                    else:
                        rows=result.get('actualBaselineLanguage',[]);calls=wire.get('physicalChatCalls')
                        if result.get('browser',{}).get('status')!='passed' or result.get('browser',{}).get('controlledPersistedDisplay')is not False or result.get('immutableActualReceiptPreservedAfterReset')is not True or result.get('actualActorCalls')!=5 or not 5<=result.get('actualJudgeCalls',-1)<=10 or not 10<=calls<=15 or wire.get('digest')!=DPI_MODEL_DIGEST or len(wire.get('requestSha256',[]))!=calls or len(wire.get('responseSha256',[]))!=calls or len(rows)!=5 or [r.get('objectiveId')for r in rows]!=['interact']*3+['multi_language']*2 or [r.get('disposition')for r in rows]!=['not_pass','threshold_pending','awarded','not_pass','awarded'] or any(r.get('actorTraceVerified')is not True or r.get('judgeTraceVerified')is not True for r in rows):raise RuntimeError('DPI baseline/language rendered receipt required')
            if selected_profile(args)=='actual-admin-enum':verify_admin_enum_actual_result(result,json.loads((evidence/'actual-model-wire.json').read_text()),json.loads((evidence/'admin-enum-captures.json').read_text()))
            if selected_profile(args)=='controlled-statement':verify_statement_result(result)
            if selected_profile(args) in ('controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'):verify_traversal_content_result(result,selected_profile(args))
    except BaseException as error:
        safe={'Owned evidence link','Aggregate log cap','CONTAINER_CREATE_FAILED','EMPTY_CLUSTER_QUERY_FAILED','STORE_PROVISION_FAILED','Owned PostgreSQL readiness deadline','Empty owned cluster required','Owned PostgreSQL layout mismatch','Native child deadline','Qualification deadline','Absolute phase deadline'}
        state['primaryFailure']={'type':type(error).__name__,'stage':state.get('stage'),'code':str(error) if str(error) in safe else None};code=1
    finally:
        deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120);owned.mask_cleanup_signals()
        try:
            try:owned.cleanup()
            except BaseException as error:failures.append({'phase':'process-cleanup','type':type(error).__name__})
            try:checked_logs()
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


if __name__=='__main__':raise SystemExit(main_current(sys.argv[1:]))
