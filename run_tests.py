"""统一测试入口：发现 tests/ 下全部 unittest 用例并运行。

用法：python run_tests.py
退出码 0 表示全部通过。纯标准库，无需 pytest。
"""

from __future__ import annotations

import sys
import unittest


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="tests", pattern="test_*.py",
                           top_level_dir=".")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
