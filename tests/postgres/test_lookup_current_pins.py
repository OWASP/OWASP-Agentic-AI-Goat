"""Current original Lookup pin gate; no browser, database or model."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
def load():
 p=Path(__file__).with_name('run-secureshop-user-lookup-browser.py')
 s=importlib.util.spec_from_file_location('lookup_actual_pin_control',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class LookupCurrentPins(unittest.TestCase):
 def setUp(self):self.l=load()
 def test_current_complete_nine_pin_gate(self):
  self.assertEqual(len(self.l.PINS),9);self.l.validate_pins()
 def test_each_stale_member_denied(self):
  real=self.l.digest
  for member in self.l.PINS:
   with self.subTest(member=member),patch.object(self.l,'digest',side_effect=lambda p,m=member:'0'*64 if Path(p)==self.l.ROOT/m else real(p)):
    with self.assertRaisesRegex(RuntimeError,'frozen source mismatch'):self.l.validate_pins()
 def test_gate_precedes_main_load(self):
  with patch.object(self.l,'validate_pins',side_effect=RuntimeError('controlled stale')),patch.object(self.l,'load') as launch:
   with self.assertRaisesRegex(RuntimeError,'controlled stale'):self.l.main(['--plan'])
   launch.assert_not_called()
 def test_original_selection_stays_closed_to_diagnostics(self):
  args=['--cohort',self.l.COHORT,'--user-lookup-test-no-sandbox','--user-lookup-disclosure']
  self.assertEqual(self.l.arguments(args),[args[0],args[1],args[3]])
  for bad in (args[:-1],args+[args[-1]],['--cohort','customer-checkout-browser',*args[2:]]):
   with self.assertRaises(RuntimeError):self.l.arguments(bad)
if __name__=='__main__':unittest.main()
