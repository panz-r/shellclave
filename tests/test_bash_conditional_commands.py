"""Qualify unary conditional grammar and truth against the pinned Bash."""

import argparse
import os
import subprocess
import unittest


class ConditionalCommands(unittest.TestCase):
    def bash_result(self, source, syntax=False):
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        for name in ("BASHOPTS", "SHELLOPTS", "POSIXLY_CORRECT", "BASH_COMPAT"):
            environment.pop(name, None)
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-p", "-O", "extglob",
             *(["-n"] if syntax else []), "-c", source], env=environment,
            capture_output=True, timeout=10)

    def probe_result(self, source, mode="--truth"):
        result = subprocess.run([self.probe, mode, source],
                                capture_output=True, check=True, timeout=10)
        return int(result.stdout)

    def test_literal_truth(self):
        for operand in ("x", "''", '""', "'-n'", "'!'", "*", "{,}",
                        "日本", "$'a\\0tail'", "$'\\0tail'", "'a b'",
                        "'\\'", "'x]]y'", "\\!", "'\r'", "'\v'", "'\f'",
                        "{", "}", "arr[0]=x", "@(a|b)"):
            for predicate in ("", "-n ", "-z "):
                for negations in ("", "! ", "! ! "):
                    source = "[[ " + negations + predicate + operand + " ]]"
                    with self.subTest(source=source):
                        self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                        truth = self.probe_result(source)
                        self.assertIn(truth, (1, 2))
                        self.assertEqual(self.bash_result(source).returncode,
                                         0 if truth == 2 else 1)

    def test_extglob_operands(self):
        words = ("@(left|right)", "pre@(@(if|for|case)|tail)suffix",
                 "@($value)", "@($((1)))", "@($(printf x))",
                 "@($(<file))", "@(<(printf x))", "@($'x')",
                 "@($(printf x | cat))", "@('$(printf x)')",
                 "'@($(printf x))'", '"@($(printf x))"',
                 r"\@\(left\|right\)")
        for word in words:
            for source in ("printf " + word, "[[ -n " + word + " ]]"):
                with self.subTest(source=source):
                    self.assertEqual(
                        self.bash_result(source, syntax=True).returncode, 0)
                    self.assertEqual(
                        self.probe_result(source, "--status"), 0)

    def test_grammar_outcomes(self):
        # Public source outcomes: COMPLETE=0, INCOMPLETE=1, INVALID=2,
        # TRUNCATED=3, UNSUPPORTED=4.
        for source in ("[[ ]]", "[[ -n ]]", "[[ -z ]]", "[[ ! ]]",
                       "[[ -n\nx ]]", "[[ x y ]]", "[[ '-n' x ]]",
                       "[[ -n x ]]word", "[[;", "[[>",
                       "[[ -n $(|) ]]", "[[ # ignored\n-n $(|) ]]",
                       "[[ x # $(|)\n]]"):
            with self.subTest(source=source):
                self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 2)
        for source in ("[[ -f file ]]", "[[ -\\\nf file ]]", "[[ x == y ]]", "[[ x =~ y ]]",
                       "[[ 1 -eq 1 ]]", "[[ (x) ]]", "[[ x && y ]]",
                       "[[ x || y ]]"):
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 4)

    def test_newline_boundaries(self):
        # A bare word consumes its next token directly. Explicit unary
        # predicates skip newlines after their operand instead.
        for negation in ("", "! ", "! ! "):
            for operand in ("x", "''", "'-n'"):
                for boundary in ("\n", " # note\n"):
                    source = "[[ " + negation + operand + boundary + "]]"
                    with self.subTest(source=source):
                        self.assertNotEqual(
                            self.bash_result(source, syntax=True).returncode, 0)
                        self.assertEqual(
                            self.probe_result(source, "--status"), 2)
            for predicate, operand in (("-n", "x"), ("-z", "''")):
                for boundary in ("\n", " # note\n"):
                    source = ("[[ " + negation + predicate + " " + operand +
                              boundary + "]]")
                    with self.subTest(source=source):
                        self.assertEqual(
                            self.bash_result(source, syntax=True).returncode, 0)
                        self.assertEqual(
                            self.probe_result(source, "--status"), 0)
                        truth = self.probe_result(source)
                        self.assertEqual(
                            self.bash_result(source).returncode,
                            0 if truth == 2 else 1)
        for source in ("[[\nx ]]", "[[ !\nx ]]", "[[ 'x\n' ]]",
                       "[[ x \\\n ]]"):
            with self.subTest(source=source):
                self.assertEqual(
                    self.bash_result(source, syntax=True).returncode, 0)
                truth = self.probe_result(source)
                self.assertEqual(self.bash_result(source).returncode,
                                 0 if truth == 2 else 1)
        for source in ("[[ x\n", "[[ ! x\n", "[[ x # note"):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 2)
        for source in ("[[ x ", "[[ ! x ", "[[ -n x\n",
                       "[[ -z '' # note\n", "[[ -n x # note"):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 1)

    def test_comments(self):
        for comment in ("$(|)", "$(", "` ' \" ]]",
                        "<(cat) $comment $((7)) ${bad"):
            for template, truth in (
                    ("[[ # {comment}\n-n x ]]", 2),
                    ("[[ ! # {comment}\n-n x ]]", 1),
                    ("[[ -n x # {comment}\n]]", 2)):
                source = template.format(comment=comment)
                with self.subTest(source=source):
                    self.assertEqual(
                        self.bash_result(source, syntax=True).returncode, 0)
                    self.assertEqual(self.bash_result(source).returncode,
                                     0 if truth == 2 else 1)
                    self.assertEqual(self.probe_result(source, "--status"), 0)
                    self.assertEqual(self.probe_result(source), truth)
        for source in (
                'printf \'%s\' "$([[ -n x # $(|)\n]])"',
                "[[ # ' comment\n-n $(printf value) # $(|)\n]]"):
            with self.subTest(source=source):
                self.assertEqual(
                    self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 0)
        for tail in ("[[ # $(|)", "[[ ! # $(|)",
                     "[[ -n x # $(|)", "[[ -n x # $(|)\n"):
            source = "printf before; " + tail
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 1)

    def test_continued_operators(self):
        for source in ("[[ -\\\nn x ]]", "[[ ! -\\\nz '' ]]"):
            with self.subTest(source=source):
                truth = self.probe_result(source)
                self.assertEqual(self.bash_result(source).returncode,
                                 0 if truth == 2 else 1)
        source = "[[ -\\\nf ]]"
        self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)
        # The wider predicate grammar is outside this model, including its
        # malformed instances; it must never be accepted as a bare string.
        self.assertEqual(self.probe_result(source, "--status"), 4)

    def test_expansion_and_setup(self):
        for source in ("[[ -z $missing ]]", "[[ -n $(printf x) ]]",
                       "[[ -n <(printf x) ]]", "[[ -n $((1)) ]]",
                       "[[ -n ~ ]]", "[[ -n \\\n~ ]]"):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source), 0)
        result = self.bash_result("[[ -n $(printf side >&2; printf value) ]] 2>&1")
        self.assertEqual((result.returncode, result.stdout), (0, b"side"))
        result = self.bash_result("[[ -n $(printf side >&2; printf value) ]] <&99")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"side", result.stderr)
        self.assertEqual(self.bash_result("[[ -n $(false) ]]").returncode, 1)
        self.assertEqual(self.bash_result("[[ -n <() ]]").returncode, 1)
        self.assertEqual(self.bash_result("HOME=; [[ -z ~ ]]").returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    ConditionalCommands.bash = args.bash
    ConditionalCommands.probe = args.probe
    unittest.main(argv=[__file__])
