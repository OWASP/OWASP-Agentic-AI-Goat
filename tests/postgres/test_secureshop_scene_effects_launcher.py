"""Controlled parser/provenance contracts, never native concurrency evidence."""
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('scene_effects_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class SceneEffectsLauncher(unittest.TestCase):
    def tap(self):
        parent, *children = L.SCENE_EFFECTS_ASSERTIONS
        return '\n'.join(['TAP version 13', '# Subtest: ' + parent]
            + [f'    # Subtest: {name}\n    ok {i} - {name}' for i, name in enumerate(children, 1)]
            + ['    1..6', 'ok 1 - ' + parent, '1..1', '# tests 7', '# pass 7',
               '# fail 0', '# skipped 0', '# cancelled 0']) + '\n'

    def test_selected_fixture_titles_and_receipt_are_exact(self):
        source = (ROOT / L.SCENE_EFFECTS_TEST).read_text()
        titles = re.findall(r"(?:t\.)?test\('([^']+)'", source)
        self.assertEqual(set(titles), set(L.SCENE_EFFECTS_ASSERTIONS))
        self.assertEqual(len(titles), 7)
        self.assertIn('selectedSceneEffectLease: true', source)
        self.assertIn('selectedSceneEffectLease', L.SCENE_EFFECTS_RECEIPT_FLAGS)

    def test_nested_tap_admits_only_complete_seven_passes(self):
        self.assertEqual(L.scene_effects_tap_counts(self.tap())['pass'], 7)
        name = 'selected-scene lease serializes a real scene switch across a local review commit'
        for raw in [self.tap().replace(name, 'different assertion'),
                    self.tap().replace('    ok 2 - ', '    not ok 2 - '),
                    self.tap().replace('# skipped 0', '# skipped 1'),
                    self.tap().replace('# tests 7', '# tests 8').replace('# pass 7', '# pass 8')]:
            with self.subTest(raw=raw[-100:]), self.assertRaises(RuntimeError):
                L.scene_effects_tap_counts(raw)

    def test_closed_receipt_requires_real_race_assertion_flag(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'receipt.json'
            value = dict.fromkeys(L.SCENE_EFFECTS_RECEIPT_FLAGS, True)
            value['scope'] = L.SCENE_EFFECTS_RECEIPT_SCOPE
            def check(row):
                target.write_text(json.dumps(row)); target.chmod(0o600)
                return L.scene_effects_receipt(target)
            self.assertEqual(check(value), value)
            for row in [{k: v for k, v in value.items() if k != 'selectedSceneEffectLease'},
                        {**value, 'selectedSceneEffectLease': False}, {**value, 'unexpected': True}]:
                with self.assertRaises(RuntimeError):
                    check(row)

    def test_runtime_closure_includes_selected_scene_lease(self):
        with patch.object(L, 'dependency_inventory', return_value={}):
            value = L.source_snapshot(ROOT, str(ROOT / 'unused-node'), 'scene-effects')
        self.assertIn('server/database/postgres/secureshopSelectedSceneEffect.js', value['sourcePins'])


if __name__ == '__main__':
    unittest.main()
