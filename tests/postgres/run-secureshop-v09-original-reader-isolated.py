#!/usr/bin/env python3
"""V09 original-reader qualification over one owned disposable agents store."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]
SHARED=ROOT/'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256='892ce14315b9d1af8cc8f0019dcca031e6d0bfbadf643321c1cf3c03addebb4f'
FIXTURE='tests/postgres/secureshopV09OriginalReader.integration.test.js'
FIXTURE_SHA256='36b93040d4e329941ef377635bde691fd37dfaa525db287969df22930abee7b6'
PINNED={
 'server/services/secureshopMailHtmlInjectionOriginalReader.js':'086899d0f72c35f9aeeca455fbb75ac75b005131ea9b3b07ef80a99785485e23',
 'server/database/postgres/secureshopBoundConversationsRepository.js':'e60f56e8183ff569837b04dbfed8ac2b4ea75918c1e6a36ca90d1e221683dc11',
 'server/database/postgres/secureshopTurnRequestsRepository.js':'fe761f3b625c67bed124ea9cfd691f2e1557653854191156bb82ba20044ea680',
 'server/database/postgres/secureshopAgentsDb.js':'01ae7bf03abf91bf52dfb9326ecc3125741f06fe9407e36bb3e3987bc26fe840',
}
SUITE='v09-original-reader';PREFIX='PG_SECURESHOP_V09_ORIGINAL_READER_';STORES=(('FRESH','secureshop_agents'),)
SCOPE=('real agents conversation and turn-request repositories; exact persisted completed merchant role-chat proposal, '
 'message hash and selected trace IDs; wrong owner/session/request and missing trace rejected; agents-store source attribution only, '
 'no model/browser/mail effect/Judge/progress or objective-credit claim')
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def validate_sources():
 expected={FIXTURE:FIXTURE_SHA256,str(SHARED.relative_to(ROOT)):SHARED_SHA256,**PINNED}
 for relative,digest in expected.items():
  if sha(ROOT/relative)!=digest:raise RuntimeError('V09 original-reader qualification source pin mismatch: '+relative)
def configure(shared,*,run):
 shared.SUITES={SUITE:(FIXTURE,PREFIX,STORES,1)}
 shared.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=run,plan=not run)
 original=shared.source_inventory
 def inventory(extra):return original([*extra,Path(__file__).resolve(),ROOT/'tests/postgres/test_secureshop_v09_original_reader_launcher.py'])
 shared.source_inventory=inventory;return shared
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 validate_sources()
 if not args.run:
  print(json.dumps({'plan':True,'suite':SUITE,'fixture':FIXTURE,'fixtureSha256':FIXTURE_SHA256,'sharedLauncherSha256':SHARED_SHA256,'sourcePins':PINNED,'stores':STORES,'expectedTests':1,'sourceCopies':False,'actualModel':False,'renderedBrowser':False,'objectiveCredit':False,'qualificationScope':SCOPE,'allocationStarted':False}));return 0
 spec=importlib.util.spec_from_file_location('v09_original_reader_owned_launcher',SHARED);shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);return configure(shared,run=True).main()
if __name__=='__main__':sys.exit(main())
