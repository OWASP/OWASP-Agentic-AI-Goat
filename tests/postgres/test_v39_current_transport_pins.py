"""Actual current V39 profile only; no process, browser or model startup."""
import importlib.util,sys
from pathlib import Path
import unittest
from unittest.mock import patch
def load():
 p=Path(__file__).with_name('run-owned-mcp-assembly-isolated.py');sys.path.insert(0,str(p.parent))
 s=importlib.util.spec_from_file_location('v39_current_source_pins',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class CurrentTransportPins(unittest.TestCase):
 def setUp(self):self.m=load()
 def test_current_profile_complete_pins(self):self.assertEqual(self.m.verify_v39_prospective_sources(self.m.SOURCE),self.m.V39_PROSPECTIVE_PINS)
 def test_historical_pins_unchanged_and_closed(self):
  self.assertEqual(self.m.V39_PAIR_PINS['tests/postgres/secureshopMailActualTransport.js'],'7cc26a404b645ff99c9448a7b9df66f14a86b06dc1babb6f1c6a5fdfad08ce45')
  self.assertEqual(self.m.V39_PAIR_PINS['tests/secureshopMailActualTransportV39PairBudget.test.js'],'5f9f14028b79e675dc20aee505a061caa5c03e58cc7ac2ac4b183b4aabf6c57a')
  with self.assertRaises(RuntimeError):self.m.verify_v39_pair_sources(self.m.SOURCE)
 def test_each_active_override_still_fails_closed(self):
  real=self.m.sha
  for name in ('tests/postgres/secureshopMailActualTransport.js','tests/secureshopMailActualTransportV39PairBudget.test.js'):
   with self.subTest(name=name),patch.object(self.m,'sha',side_effect=lambda p,n=name:'0'*64 if Path(p)==self.m.SOURCE/n else real(p)):
    with self.assertRaises(RuntimeError):self.m.verify_v39_prospective_sources(self.m.SOURCE)
if __name__=='__main__':unittest.main()
