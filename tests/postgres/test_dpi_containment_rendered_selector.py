import pathlib, subprocess, sys, unittest
LAUNCHER = pathlib.Path(__file__).with_name('run-listings-integrated-isolated.py')
class Selector(unittest.TestCase):
    def rejected(self, *flags):
        result = subprocess.run([sys.executable, '-B', str(LAUNCHER), '--docker-host', 'invalid-test-socket',
                                 '--dpi-containment-rendered', *flags], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        return result.stderr + result.stdout
    def test_baseline_selector_is_exclusive(self):
        self.assertIn('exclusive with baseline selector', self.rejected('--dpi-rendered'))
    def test_inference_and_effect_branches_rejected_before_resources(self):
        for flag in ['--actual8b', '--actual-grading', '--actual-grading-browser', '--production-assembly', '--saved-evidence']:
            with self.subTest(flag=flag):
                self.assertIn('cannot enable model or Listings effect branches', self.rejected(flag))
    def test_visual_selector_exclusive_and_model_free(self):
        for flag in ['--dpi-containment-rendered', '--dpi-rendered', '--actual8b', '--actual-grading', '--actual-grading-browser', '--production-assembly', '--saved-evidence']:
            with self.subTest(flag=flag):
                result = subprocess.run([sys.executable, '-B', str(LAUNCHER), '--docker-host', 'invalid-test-socket', '--dpi-containment-visual', flag], capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('exclusive' if flag.startswith('--dpi-') else 'cannot enable model or Listings effect branches', result.stderr + result.stdout)
