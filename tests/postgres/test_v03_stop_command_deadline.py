"""Actual extracted driver calculation against actual guest deadline validator; no guest IO."""
import ast
import importlib.util
import json
import math
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'tests/postgres/ownedSystemConfigPhaseDriver.js').read_text()
body = source.split('  const cleanupDeadline=()=>{', 1)[1].split('\n  };', 1)[0]
guest = ROOT / 'tests/postgres/owned_system_private_http_channel.py'
tree = ast.parse(guest.read_text())

def accepted(deadline, now):
    scope = {'math': math, 'time': SimpleNamespace(monotonic=lambda: now), 'MAX_SECONDS': 120}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('require', 'check_deadline')]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(guest), 'exec'), scope)
    try: scope['check_deadline'](deadline); return True
    except RuntimeError: return False

def calculate(start, end, revoked=True):
    program = "const combinedOwner={isRevoked:()=>"+json.dumps(revoked)+"};const error=x=>Error(x);"
    program += "const clock={mapRetirementInterval:kind=>{if(kind!=='diagnosticCleanupMs')throw Error('kind');return "+json.dumps({'startedAtMs':start,'deadlineMs':end})+";}};"
    program += 'const cleanupDeadline=()=>{'+body+'};console.log(JSON.stringify(cleanupDeadline()-1));'
    result = subprocess.run(['node', '-e', program], cwd=ROOT, capture_output=True, text=True, timeout=10)
    if result.returncode: raise RuntimeError('driver denied')
    return json.loads(result.stdout)

class StopDeadline(unittest.TestCase):
    def test_real_guest_rejects_old600s_accepts_fixed_command(self):
        self.assertFalse(accepted(1599, 1000))
        self.assertEqual(calculate(1000000,1600000),1119)
        self.assertTrue(accepted(calculate(1000000,1600000),1000))
    def test_delay_consumes_same_bound_and_expiry_denies(self):
        deadline=calculate(1000000,1600000)
        self.assertTrue(accepted(deadline,1050))
        self.assertFalse(accepted(deadline,1120))
        self.assertEqual(calculate(1000000,1600000),deadline)
    def test_short_phase_remains_limiting_and_revocation_required(self):
        self.assertEqual(calculate(1000000,1050000),1049)
        self.assertFalse(accepted(calculate(1000000,1050000),1050))
        with self.assertRaises(RuntimeError): calculate(1000000,1600000,False)
    def test_mapped_clock_offsets_do_not_change120s_cap(self):
        for offset in (-50000,99899,400000):
            start=1000000+offset
            deadline=calculate(start,start+600000)
            self.assertTrue(accepted(deadline,start/1000))
            self.assertLessEqual(deadline-start/1000,120)

if __name__=='__main__': unittest.main()
