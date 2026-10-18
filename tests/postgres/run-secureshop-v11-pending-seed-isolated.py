#!/usr/bin/env python3
"""V11 database-only held promotion seed qualification over owned disposable PostgreSQL."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = 'a90145068bffab08475b058054b309ed44bb99e0eea8d6658b252b702f07eb1e'
FIXTURE = 'tests/postgres/secureshopV11PendingCatalogSeed.integration.test.js'
FIXTURE_SHA256 = '25e31c7333dbae61cb56840f90c7066216257fc41545365bacfd0c1b164351a4'
SEED = 'server/database/postgres/secureshopAssessmentSeed.js'
SEED_SHA256 = '3e269a4441197809b806fd66df02c5d535e7755226bb85e389450275282b1b2a'
SUITE = 'v11-assessment-seed'
PREFIX = 'PG_SECURESHOP_V11_MAIL_AGENT_SEED_'
STORES = (('FRESH', 'identity'), ('POPULATED', 'identity'))
SCOPE = ('HELD V11 eventual native-browser-judge/default-disabled catalog promotion only after accepted actual qualification; '
 'fresh exact default, exact pending checked-in predecessor, populated instructor content, tenant configuration/history, sibling state, '
 'nonempty immutable judgment/completion/contribution/retry rows and second-run no-op preserved; canonical administrator denial-before '
 'and enablement-after transition; database-only, no agent/model/browser/Judge/effect/credit or current V11 qualification claim')

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def validate_sources():
 for relative, expected in ((FIXTURE,FIXTURE_SHA256),(SEED,SEED_SHA256),(str(SHARED.relative_to(ROOT)),SHARED_SHA256)):
  if sha(ROOT/relative) != expected: raise RuntimeError('V11 seed qualification source pin mismatch: '+relative)
def scope_result_saves(source):
 old="def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)"
 new="def save(): lifecycle.helpers.write_private_json(evidence/'result.json', {**result,'qualificationScope':V11_QUALIFICATION_SCOPE})"
 if source.count(old)!=1: raise RuntimeError('V11 exact result save seam changed; no allocation started')
 return source.replace(old,new)
def load_shared():
 spec=importlib.util.spec_from_file_location('v11_seed_owned_persona_launcher',SHARED);shared=importlib.util.module_from_spec(spec)
 exec(compile(scope_result_saves(SHARED.read_text()),str(SHARED),'exec'),shared.__dict__);shared.V11_QUALIFICATION_SCOPE=SCOPE
 return shared
def configure(shared, *, run):
 shared.SUITES={SUITE:(FIXTURE,PREFIX,STORES,2)}
 shared.arguments=lambda:SimpleNamespace(suite=SUITE,fresh_cohort=None,run=run,plan=not run)
 original=shared.source_inventory
 def inventory(extra): return original([*extra,Path(__file__).resolve(),ROOT/'tests/postgres/test_secureshop_v11_seed_launcher.py'])
 shared.source_inventory=inventory
 return shared
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__); modes=parser.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 validate_sources()
 if not args.run:
  print(json.dumps({'plan':True,'suite':SUITE,'fixture':FIXTURE,'fixtureSha256':FIXTURE_SHA256,'seedSha256':SEED_SHA256,'sharedLauncherSha256':SHARED_SHA256,'stores':STORES,'expectedTests':2,'sourceCopies':False,'actualModel':False,'qualificationScope':SCOPE,'allocationStarted':False}));return 0
 return configure(load_shared(),run=True).main()
if __name__=='__main__':sys.exit(main())
