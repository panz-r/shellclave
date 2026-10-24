"""Qualify arithmetic truth proofs against the pinned execution model."""

import argparse
import os
import subprocess
import unittest


class ArithmeticCommands(unittest.TestCase):
    def truth(self, expression):
        source = "((" + expression + "))"
        result = subprocess.run([self.probe, "--truth", source],
                                capture_output=True, check=True, timeout=10)
        return int(result.stdout)

    def status(self, expression, syntax_only=False):
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        for name in ("BASHOPTS", "SHELLOPTS", "POSIXLY_CORRECT", "BASH_COMPAT"):
            environment.pop(name, None)
        options = ["-n"] if syntax_only else []
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-p", *options, "-c",
             "((" + expression + "))"], capture_output=True,
            env=environment, timeout=10).returncode

    def test_safe_proofs_match_bash(self):
        for expression in (
                "", "0", "1", "-1", "2 + 3 > 4", "2 + 3 * 4 == 14",
                "2 ** 3 ** 2 == 512", "-2 ** 2 == 4",
                "0x10 == 020 && 16#ff == 255 && 64#_ == 63",
                "2#1 == 1 && 2#01 == 1 && 10#010 == 10 && 16#0f == 15",
                "00010 == 8 && 0X0f == 15 && 0\\\nx10 == 16",
                "~0 == -1", "-7 / 3 == -2 && -7 % 3 == -1",
                "(1 << 4) == 16 && (16 >> 2) == 4", "0 && (1/0)",
                "1<<(2)", "8>>(1)", "1<(2)", "2>(1)",
                "1 || (1/0)", "1 ? 7 : 1/0", "0 ? 1/0 : 0", "1, 0",
                "$((1 + 2)) == 3", "$(( ))", "1 + +2", "1 - -1",
                "1--2 == 3 && 1++2 == 3 && --1 == 1 && ++1 == 1",
                "1---2 == -1 && 1+++2 == 3"):
            with self.subTest(expression=expression):
                truth = self.truth(expression)
                self.assertIn(truth, (1, 2))
                self.assertEqual(self.status(expression), 1 if truth == 1 else 0)

    def test_invalid_leading_zero_bases_are_runtime_errors(self):
        for expression in ("02#1", "010#1", "016#f", "064#1", "0002#1",
                           "0\\\n2#1", "02\\\n#1", "02#\\\n1", "0\\\n16#f",
                           "(02#1)"):
            with self.subTest(expression=expression):
                self.assertEqual(self.status(expression, syntax_only=True), 0)
                self.assertEqual(self.status(expression), 1)

    def test_arithmetic_whitespace(self):
        for expression in (" \t\n", "\\\n", "\t1\n+\t1\n",
                           "1 +\\\n\t1 == 2"):
            with self.subTest(expression=expression):
                truth = self.truth(expression)
                self.assertIn(truth, (1, 2))
                self.assertEqual(self.status(expression), 1 if truth == 1 else 0)

        # Bash frames these commands successfully but rejects the bytes while
        # evaluating arithmetic, including in operands skipped by evaluation.
        for byte in ("\r", "\v", "\f"):
            for template in ("{}", "{}1", "1{}+1", "1+{}1", "1{}",
                             "0 && 1{}", "1 || 1{}", "1 ? 7 : 1{}"):
                expression = template.format(byte)
                with self.subTest(expression=expression):
                    self.assertEqual(self.status(expression, syntax_only=True), 0)
                    self.assertEqual(self.status(expression), 1)

    def test_uncertain_arithmetic_remains_unproven(self):
        for expression in ("1/0", "(1/0), 1", "0 && $((1/0))",
                           "1 || $((1/0))", "1 ? 7 : $((1/0))",
                           "9223372036854775807 + 1",
                           "9223372036854775808", "2 ** 1000000000",
                           "1 << 64", "-1 >> 1", "2 ** -1"):
            with self.subTest(expression=expression):
                self.assertEqual(self.truth(expression), 0)

    def test_binary_operator_proofs(self):
        for operator in ("||", "&&", "|", "^", "&", "==", "!=", "<=", ">=",
                         "<<", ">>", "<", ">", "+", "-", "**", "*", "/", "%"):
            for left, right in ((0, 1), (1, 1), (3, 2), (7, 3)):
                expression = f"{left} {operator} {right}"
                with self.subTest(expression=expression):
                    truth = self.truth(expression)
                    self.assertIn(truth, (1, 2))
                    self.assertEqual(self.status(expression),
                                     1 if truth == 1 else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    ArithmeticCommands.bash = args.bash
    ArithmeticCommands.probe = args.probe
    unittest.main(argv=[__file__])
