#!/usr/bin/env python3
"""V09 database-only seed qualification over the owned disposable PG lifecycle."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = 'a90145068bffab08475b058054b309ed44bb99e0eea8d6658b252b702f07eb1e'
FIXTURE = 'tests/postgres/secureshopV09PendingCatalogSeed.integration.test.js'
FIXTURE_SHA256 = '6f11b34309ade804488a8c4a1540fa5f2ace5e90ab6f5b247fc6fcebf7258048'
SEED = 'server/database/postgres/secureshopAssessmentSeed.js'
SEED_SHA256 = 'c92f07a112ba5670bc43dd5e58d380d16492b5e793ade0d1afd9e1292cf28726'
SUITE = 'v09-assessment-seed'
PREFIX = 'PG_SECURESHOP_V09_MAIL_HTML_SEED_'
STORES = (('FRESH', 'identity'), ('POPULATED', 'identity'))
SCOPE = ('V09 exact qualified/default-disabled mail HTML objective; fresh/populated/second-run no-op; '
 'instructor content, tenant configuration, sibling state and immutable judgment/completion/contribution evidence preserved; '
 'qualified administrator enablement admitted only through the canonical catalog; database-only, no mail send/model/browser/Judge/effect or credit claim; '
 'agent original-reader repository qualification remains a separate agents-store requirement')

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def validate_sources():
 for relative, expected in ((FIXTURE,FIXTURE_SHA256),(SEED,SEED_SHA256),(str(SHARED.relative_to(ROOT)),SHARED_SHA256)):
  if sha(ROOT/relative) != expected: raise RuntimeError('V09 seed qualification source pin mismatch: '+relative)
def configure(shared, *, run):
 shared.SUITES={SUITE:(FIXTURE,PREFIX,STORES,2)}
 shared.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=run,plan=not run)
 original=shared.source_inventory
 def inventory(extra): return original([*extra,Path(__file__).resolve(),ROOT/'tests/postgres/test_secureshop_v09_seed_launcher.py'])
 shared.source_inventory=inventory
 return shared
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__); modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 validate_sources()
 if not args.run:
  print(json.dumps({'plan':True,'suite':SUITE,'fixture':FIXTURE,'fixtureSha256':FIXTURE_SHA256,'seedSha256':SEED_SHA256,'sharedLauncherSha256':SHARED_SHA256,'stores':STORES,'expectedTests':2,'sourceCopies':False,'actualModel':False,'qualificationScope':SCOPE,'allocationStarted':False}));return 0
 spec=importlib.util.spec_from_file_location('v09_seed_owned_persona_launcher',SHARED);shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);return configure(shared,run=True).main()
if __name__=='__main__':sys.exit(main())
