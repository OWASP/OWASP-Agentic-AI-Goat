import unittest

from tests.postgres import run_bound_review_with_inspector as coordinator


class FixedBoundReviewCoordinatorTest(unittest.TestCase):
    def test_only_named_browser_and_source_storage_suites_are_admitted(self):
        for suite in ('persona-sessions', 'product-summary-browser', 'manual-rag-browser',
                      'manual-rag-fixed-browser', 'manual-rag-paired-browser', 'manual-rag-source', 'manual-private-model',
                      'manual-ranking-model', 'review-moderation-recovery', 'analytics-resource', 'tool-output-actual', 'direct-injection-actual'):
            coordinator.validate_arguments(['--main-checkout', '--run',
                '--current-host-profile', 'goat-q', '--suite', suite])
        for arguments in ([], ['--run', '--suite', 'product-summary-browser'],
                          ['--main-checkout', '--run', '--current-host-profile',
                           'goat-q', '--suite', 'composition'],
                          ['--main-checkout', '--run', '--current-host-profile',
                           'goat-q', '--suite', 'manual-rag-browser', '--suite',
                           'product-summary-browser']):
            with self.assertRaises(RuntimeError):
                coordinator.validate_arguments(arguments)


if __name__ == '__main__':
    unittest.main()
