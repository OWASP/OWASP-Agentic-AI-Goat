#!/usr/bin/env python3
"""Dedicated two-store V51 catalog qualification; no shared launcher edits."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json,pathlib
ROOT=next(p for p in pathlib.Path(__file__).resolve().parents if (p/'package.json').is_file())
PINS={'server/config/secureshopCurriculum.js': '6939136100f5c526e1a92a229a07cc2d982f8e238fa28df66c51fefc9497c91c', 'server/services/secureshopAnalyticsNlSqlEvidence.js': '5bc6d50fa131eacb90dadb0462f1755fd24127ab5983361c7d52e16107422c3a', 'tests/postgres/run-persona-transition-main-isolated.py': '892ce14315b9d1af8cc8f0019dcca031e6d0bfbadf643321c1cf3c03addebb4f', 'tests/postgres/secureshopV51PendingCatalogSeed.integration.test.js': '4a027d2f942f405cc8b3e069f96bf1fe63cedb691b8ce1908ff79cab5494f71c'}
FIXTURE='tests/postgres/secureshopV51PendingCatalogSeed.integration.test.js'
PREFIX='PG_SECURESHOP_V51_NL_SQL_SEED_'
STORES=(('FRESH','identity'),('POPULATED','identity'))
QUALIFICATION_SCOPE='V51 exact native-model/default-disabled NL-to-SQL catalog; fresh/populated/second-no-op, qualified administrator enable permitted, recognized exact pending source promoted and foreign/instructor provenance denied, exact before-first-reseed instructor content and tenant configuration/history plus V20 immutable sibling judgment/completion/contribution preserved; database only, no actor/model/browser/Judge/SQL effect or objective-credit qualification'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def installed():return {p:(ROOT/p).is_file() and sha(ROOT/p)==expected for p,expected in PINS.items()}
def scope_result_saves(source):
 # This exact pinned save seam is used for both success and failure evidence.
 old="def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)"
 new="def save(): lifecycle.helpers.write_private_json(evidence/'result.json', {**result,'qualificationScope':V51_QUALIFICATION_SCOPE})"
 if source.count(old)!=1:raise RuntimeError('Exact result save seam changed; no allocation started')
 return source.replace(old,new)
def main(argv=None):
 parser=argparse.ArgumentParser();gate=parser.add_mutually_exclusive_group();gate.add_argument('--plan',action='store_true');gate.add_argument('--run',action='store_true');args=parser.parse_args(argv)
 state=installed()
 if not args.run:
  print(json.dumps({'plan':True,'allocationStarted':False,'suite':'v51-assessment-seed','fixture':FIXTURE,'stores':STORES,'expectedTests':2,
   'sourcePins':PINS,'installedMatches':state,'qualificationScope':QUALIFICATION_SCOPE,'actualModel':False,'rendered':False}));return 0
 if not all(state.values()):raise RuntimeError('V51 installed source/fixture pin mismatch; no allocation started')
 shared=ROOT/'tests/postgres/run-persona-transition-main-isolated.py'
 spec=importlib.util.spec_from_file_location('v51_catalog_owned_lifecycle',shared);module=importlib.util.module_from_spec(spec);source=scope_result_saves(shared.read_text());exec(compile(source,str(shared),'exec'),module.__dict__);module.V51_QUALIFICATION_SCOPE=QUALIFICATION_SCOPE
 module.SUITES={'v51-assessment-seed':(FIXTURE,PREFIX,STORES,2)}
 original_inventory=module.source_inventory
 def inventory(extra):return original_inventory([*extra,pathlib.Path(__file__).resolve(),*[ROOT/p for p in PINS]])
 module.source_inventory=inventory
 # Preserve the established environment, daemon/image/runtime ownership,
 # bounded resources, exact TAP counts, source freeze and owned cleanup.
 old=sys.argv;sys.argv=[str(shared),'--suite','v51-assessment-seed','--run']
 try:return module.main()
 finally:sys.argv=old
if __name__=='__main__':sys.exit(main())
