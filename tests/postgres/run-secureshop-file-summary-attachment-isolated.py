#!/usr/bin/env python3
"""Zero-model V19 attachment persona-lease qualification over disposable PostgreSQL."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = '892ce14315b9d1af8cc8f0019dcca031e6d0bfbadf643321c1cf3c03addebb4f'
FIXTURE = 'tests/postgres/secureshopFileSummaryAttachment.native.js'
FIXTURE_SHA256 = 'dd48e23f6ef9c65601c27d538851b4c1026dab83d9c4b28061d38f0dff486bb0'
MIGRATION_FIXTURE = 'tests/postgres/secureshopFilesPrincipalMigration.native.js'
MIGRATION_FIXTURE_SHA256 = '3e8541068aa58a13617011267de94ae3de088fe3c078568c31be3e16e87d9c89'
ATTACHMENT = 'server/services/secureshopFileSummaryAttachment.js'
ATTACHMENT_SHA256 = '356c12a11fb06f2530acb69f3470b902cb50d072fd72c612b65b94a0a4a6e4f6'
RUNNER = 'server/services/secureshopBoundAgentRunner.js'
RUNNER_SHA256 = 'a2d57f78fec86d90c898d8e9ccaf00c02f473a0cada681d5c62d71dab8895282'
CLEANUP = 'server/services/secureshopCleanupComposition.js'
CLEANUP_SHA256 = '3185a0f3647be5815b3af9409411ff63aadbc59511c8188b319b0d86002efccf'
FILES = 'sidecars/sandbox-runner/secureshopFiles.js'
FILES_SHA256 = '6c2d65cb3c0a7688d5f85a48029c9b7d1d77407c67fcd1325f1e14340d59fc77'
LAUNCHES = 'server/database/postgres/secureshopLaunchRepository.js'
LAUNCHES_SHA256 = '20e12b45b0b08fd67cb6d1e319e0cbf394f42d208cdb92f38064359572b82b71'
MIGRATION = 'db/postgres/identity-migrations/0151_secureshop_files_principal_admission.sql'
MIGRATION_SHA256 = '7c752c8c03798b47227235607205c1ba4a236569eea2130573694a2808121407'
FILE_CLEANUP = 'server/services/secureshopFileTargetCleanup.js'
FILE_CLEANUP_SHA256 = '6167b6099ea4c34a33f25aa2c9de251800c784f234706409467bb42fe75cd87a'
SUITE = 'v19-attachment-lease'
PREFIX = 'V19_ATTACHMENT_'
STORES = (('IDENTITY', 'identity'), ('POPULATED', 'identity'), ('UNKNOWN', 'identity'), ('AGENTS', 'secureshop_agents'),
 ('COMMERCE', 'secureshop'), ('REVIEW', 'secureshop_review'))
SCOPE = ('production file-summary attachment with actual BoundAgentRunner, PostgreSQL launch/persona/scene authority and controlled mode token; one cross-store lease, '
 'physical write/read and retained read, no nested advisory-lock wait; platform-owner debt remains fail-closed; shop files reservations bind immutable tenant execution principals, exact replay, same-principal debt across sessions, tenant aggregate capacity, and fail-closed historical scope; '
 'native default-tenant distinct-principal files, canonical reset isolation and fresh rebootstrap, plus peer tenant merchant membership, seed projection, real login/bootstrap, catalog preparation and physical file proof; controlled fixture only, no model/browser/Judge/credit claim')

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def pins(): return {'fixtureSha256': sha(ROOT/FIXTURE), 'attachmentSha256': sha(ROOT/ATTACHMENT),
 'migrationFixtureSha256':sha(ROOT/MIGRATION_FIXTURE),'migrationSha256':sha(ROOT/MIGRATION),
 'runnerSha256': sha(ROOT/RUNNER), 'cleanupSha256':sha(ROOT/CLEANUP),
 'filesSha256':sha(ROOT/FILES),'launchesSha256':sha(ROOT/LAUNCHES),
 'fileCleanupSha256':sha(ROOT/FILE_CLEANUP),
 'sharedLauncherSha256': sha(SHARED)}
def validate_sources():
 actual=pins()
 expected={'fixtureSha256':FIXTURE_SHA256,'migrationFixtureSha256':MIGRATION_FIXTURE_SHA256,
  'migrationSha256':MIGRATION_SHA256,'attachmentSha256':ATTACHMENT_SHA256,'runnerSha256':RUNNER_SHA256,
  'cleanupSha256':CLEANUP_SHA256,'filesSha256':FILES_SHA256,'launchesSha256':LAUNCHES_SHA256,
  'fileCleanupSha256':FILE_CLEANUP_SHA256,
  'sharedLauncherSha256':SHARED_SHA256}
 if actual != expected: raise RuntimeError('V19 attachment native source pin mismatch')
 return actual
def validate_fixture_contract():
 source=(ROOT/FIXTURE).read_text()
 required=("process.env.PG_TEST_DISPOSABLE !== 'yes'",
  "assert.equal(await fs.realpath(process.cwd()), sourceRoot)",
  "assert.notEqual(isolatedWorkspace, sourceRoot)",
  "{ code: 'CLEANUP_REQUIRED' }",
  "cleanup.launchResetCoordinator.reset",
  "files.openExistingReservedTarget(retainedBinding), { code: 'TARGET_RETIRED' }",
  "Independent owner remains unchanged.",
  "JOIN secureshop_auth.execution_sessions e ON e.session_id=s.shop_execution_session_id",
  "principalANext.trusted", "principalARefreshed = await bootstrap",
  "await assertStored(principalBFile)", "SET seed_merchant_id=$2",
  "catalog.prepareTarget({ scope: peer.trusted, persona: peer.actor.user })",
  "^\\/owasp_ai_goat_test_persona_(identity|agents|commerce|review)_[a-f0-9]{12}$")
 if any(value not in source for value in required): raise RuntimeError('V19 attachment launcher/fixture contract mismatch')
 return True
def configure(shared, *, run):
 shared.SUITES={SUITE:(FIXTURE,PREFIX,STORES,3)}
 shared.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=run,plan=not run)
 original=shared.source_inventory
 def inventory(extra): return original([*extra,ROOT/MIGRATION_FIXTURE,Path(__file__).resolve(),ROOT/'tests/postgres/test_secureshop_file_summary_attachment_launcher.py'])
 shared.source_inventory=inventory
 return shared
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 validate_fixture_contract(); exact=pins() if args.plan else validate_sources()
 if not args.run:
  print(json.dumps({'plan':True,'suite':SUITE,'fixture':FIXTURE,**exact,'stores':STORES,
   'expectedTests':3,'sourceCopies':False,'actualModel':False,'browser':False,
   'qualificationScope':SCOPE,'allocationStarted':False}));return 0
 spec=importlib.util.spec_from_file_location('v19_attachment_owned_persona_launcher',SHARED)
 shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);return configure(shared,run=True).main()
if __name__=='__main__':sys.exit(main())
