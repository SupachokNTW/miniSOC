"""Detection-as-Code CI check: validate every rule in rules/ and run its YAML tests.

Usage:  python tests/run_rule_tests.py      (exit code 1 on any failure)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engine import load_rules, run_rule_tests  # noqa: E402


def main():
    rules, errors = load_rules()
    failed = 0
    for err in errors:
        print(f"INVALID  {err['file']}: {err['error']}")
        failed += 1
    for rule in rules:
        if not rule.tests:
            print(f"WARN     {rule.id}: no tests")
            continue
        for result in run_rule_tests(rule):
            status = "PASS" if result["passed"] else "FAIL"
            failed += 0 if result["passed"] else 1
            print(f"{status}     {rule.id}: {result['name']} -> {result['detail'][:110]}")
    print(f"\n{len(rules)} rules, {len(errors)} invalid, {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
