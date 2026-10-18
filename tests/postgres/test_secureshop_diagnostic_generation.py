"""Resource-free controls for the graded diagnostic generation join."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secureshop_diagnostic_generation import (
    MAX_SAFE_GENERATION,
    same_scene_generation,
)


class SceneGenerationJoinTest(unittest.TestCase):
    def test_canonical_integer_matches_postgresql_decimal(self):
        for value in (1, 42, MAX_SAFE_GENERATION):
            with self.subTest(value=value):
                self.assertTrue(same_scene_generation(value, str(value)))

    def test_packet_requires_positive_safe_integer(self):
        for value in (False, True, 0, -1, 1.0, '1', None,
                      MAX_SAFE_GENERATION + 1):
            with self.subTest(value=value):
                self.assertFalse(same_scene_generation(value, '1'))

    def test_sql_requires_canonical_decimal_string(self):
        for value in (1, True, None, '', '0', '-1', '+1', '01', ' 1',
                      '1 ', '1.0', '1e0', '１', '2'):
            with self.subTest(value=value):
                self.assertFalse(same_scene_generation(1, value))


if __name__ == '__main__':
    unittest.main()
