"""
Standalone test runner using Python standard library unittest.
Runs all test modules in the tests/ directory.
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    print("=" * 60)
    print("Running Local AI Security Log Analyzer Test Suite")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover tests or load explicitly
    import tests.test_splitter as ts
    import tests.test_merger as tm
    import tests.test_analyzer_parser as tap
    import tests.test_e2e_pipeline as tep

    # Wrap pytest-style test functions into unittest.FunctionTestCase
    for mod in (ts, tm, tap, tep):
        for name in dir(mod):
            if name.startswith("test_"):
                fn = getattr(mod, name)
                if callable(fn):
                    suite.addTest(unittest.FunctionTestCase(fn, description=f"{mod.__name__}.{name}"))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\nAll tests passed successfully! [OK]")
        sys.exit(0)
    else:
        print(f"\n{len(result.failures)} failures, {len(result.errors)} errors. [FAIL]")
        sys.exit(1)
