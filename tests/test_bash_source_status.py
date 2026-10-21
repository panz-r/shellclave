"""Qualify source statuses with Bash -n and fixed builtin-only EOF fixtures."""

import argparse
import os
import subprocess
import unittest


class SourceStatusContract(unittest.TestCase):
    def classify(self, source):
        result = subprocess.run([self.probe, "--probe"], input=source,
                                capture_output=True, check=True, timeout=10)
        return int(result.stdout)

    def syntax(self, source):
        # -n reads the entire source but never runs a command or substitution.
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        return subprocess.run([self.bash, "--noprofile", "--norc", "-p", "-n"],
                              input=source, capture_output=True,
                              env=environment, timeout=10).returncode

    def test_supported_and_unsupported_valid_sources(self):
        cases = [
            (b"printf ok", 0),
            (b"echo before #comment \\\necho after", 0),
            (b": #comment \\\na=(x)", 4),
            (b": #comment \\\n{ :; }", 0),
            (b": | time :", 0), (b": |& time :", 0),
            (b": |\ntime :", 0), (b": | #comment\ntime :", 0),
            (b": | #comment \\\ntime :", 0), (b": |\\\ntime :", 0),
            (b": | time {", 0), (b": |& time {", 0),
            (b": |\ntime {", 0), (b": |\ntime -p -- {", 0),
            (b': |&\n"time" {', 0), (b": |\n\n\\time {", 0),
            (b': |&\ntime"" {', 0), (b"echo $(: |\ntime {)", 0),
            (b": |\ntime", 0),
            ("printf '%s' '日本'".encode(), 0),
            ("printf '%s' 日本".encode(), 0),
            ("printf '%s' $'日本'".encode(), 4),
            (b"if true; then :; fi", 4),
            (b"case x in x) :;; esac", 4),
            (b"f() { :; }", 4),
            (b"foo.bar() { :; }", 4),
            (b"foo-bar() { :; }", 4),
            (b"1f() { :; }", 4),
            (b'"f"() { :; }', 4),
            (b"f\\ g() { :; }", 4),
            (b"[[ -f input ]]", 4),
            (b"((1 + 2))", 4),
            (b"echo ${x!}", 4),
            (b"echo ${x:}", 4),
            (b"echo $[1 + (2)]", 4),
            (b"echo ok; !\ntrue", 4),
            (b"!", 4), (b"! ! ", 4), (b"!; :", 4), (b"! &", 4),
            (b"{ !; }", 4), (b"( !; )", 4), (b"echo $(!;)", 4),
            (b"echo `!`", 4), (b"time !", 0), (b"! time", 0),
            (b": > !", 0), (b": >!", 0), (b"> !", 0), (b": < !", 0),
            (b": 2>& !", 0), (b"{ :; } > !", 0), (b"( : ) < !", 0),
            (b": <<< !", 0), (b": > \\\n!", 0),
            (b"a=(x)", 4), (b"a+=(x)", 4), (b"declare a=(x)", 4),
            (b"a\\\n=(x)", 4), (b"a=\\\n(x)", 4), (b"a+\\\n=(x)", 4),
            (b"declare a[0]\\\n=(x)", 4),
            (b"typeset a=(x)", 4), (b"local a=(x)", 4),
            (b"export a=(x)", 4), (b"readonly a=(x)", 4),
            (b"de\\\nclare a=(x)", 4), (b"x=1 declare a=(x)", 4),
            (b">out declare a=(x)", 4),
            (b"declare x a=(x)", 4), (b"declare -- a=(x)", 4),
            (b"echo a[0]=x", 0), (b'echo "a=(x)"', 0),
            (b">out !", 0),
            (b">out {", 0), (b">out { }", 0), (b"2>&1 {", 0),
            (b">out ! {", 0), (b">out \\\n{", 0),
            (b">out {; { :; }", 0), (b"{ :; } >out", 0),
            (b"a[0]=x a=(x)", 4), (b'a[0]="x" a=(x)', 4),
            (b"a[0]+=x a=(x)", 4), (b'a[0]=x"" a=(x)', 4),
            (b"a[0]=$x a=(x)", 4), (b"a[0]=$(printf x) a=(x)", 4),
            (b"a[0]=x\\\ny a=(x)", 4),
            (b"a[0]=x declare a=(x)", 4), (b"a[0]=x export a=(x)", 4),
            (b"echo $(a[0]=x a=(x))", 4),
            (b'echo "\\$(whoami)"', 0),
            (b"echo '\\$(whoami)'", 0),
            (b"echo \\$\\(whoami\\)", 0), (b"echo \\\\$(whoami)", 0),
            (b"echo \"$((1+))\"", 0),
            (b"read -nwrong value <<<payload", 0),
            (b"printf '\x01'", 4),
            (b"printf '\x7f'", 4),
            ("cat <<'EOF'\n日本\nEOF\n".encode(), 0),
            (b'cat <<$"EOF"\npayload\nEOF\n', 4),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), expected)

    def test_time_token_history(self):
        # Expectations are keyed to logical LF tokens, not physical lines.
        # | and |& differ in Bash's two-token reserved-word lookbehind.
        gaps = [
            (b" ", False, False),
            (b"\n", False, True),
            (b"\n\n", True, True),
            (b" #comment\n", False, True),
            (b"\n#comment\n", True, True),
            (b"\\\n", False, False),
            (b"\n\\\n", False, True),
            (b"\\\n\n", False, True),
            (b" #comment \\\n", False, True),
            (b"\n#comment \\\n", True, True),
            (b"\n\\\n\n", True, True),
            (b"\n \t", False, True),
        ]
        spellings = [(b"time", True), (b"ti\\\nme", True),
                     (b'"time"', False), (b"\\time", False),
                     (b'time""', False)]
        for operator in (b"|", b"|&"):
            for gap, after_pipe, after_pipe_both in gaps:
                for word, plain in spellings:
                    for operand in (b":", b"{"):
                        source = b": " + operator + gap + word + b" " + operand
                        reserved = after_pipe if operator == b"|" else after_pipe_both
                        invalid = plain and reserved
                        with self.subTest(source=source):
                            self.assertEqual(self.syntax(source), 2 if invalid else 0)
                            self.assertEqual(self.classify(source), 2 if invalid else 0)

    def test_syntax_errors(self):
        cases = [
            b": |&\ntime :", b": |\n\ntime :",
            b": |\n#comment\ntime :", b": |& #comment \\\ntime :",
            b": |&\n\\\ntime :", b"echo before; : |&\ntime -p -- :",
            b"echo $(: |&\ntime :)", b"cat <(: |\n\ntime :)",
            b": |&\ntime",
            b"cat /workspace/before.txt\ncat <<\ncat /workspace/not-a-read.txt",
            b"cat >\nfile", b"cat <<#comment", b"echo && ;",
            b"echo $(echo &&)", b"{ :; )", b"echo )",
            b"! | :", b"! && :", b"! || :", b"( ! )", b"echo $(!)",
            b"echo a=(x)", b": a+=(y)", b": >a=(x)", b"{ :; } >a=(x)",
            b'de"clare" a=(x)', b'declare"" a=(x)',
            b"command declare a=(x)", b"builtin declare a=(x)",
            b"declare >out a=(x)",
            b">out ! a=(x)", b"x=1 ! a=(x)",
            b"echo a\\\n=(x)", b": >a=\\\n(x)",
            b"echo \\$(whoami)", b"echo \\$((1+2))", b"\\$(whoami)",
            b"echo x\\$(whoami)", b"echo before; echo \\$(whoami)",
            b": >\\$(whoami)", b"{ :; } >\\$(whoami)",
            b">out { :; }", b"a[0]=x : a=(x)",
            b"echo $(: <<)", b"echo $(: <<EOF &&)", b"echo $(: <<EOF >)",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertNotEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 2)

    def test_heredoc_data_encoding_preserves_failures(self):
        for body in (b"ascii", "é".encode(), "日本".encode()):
            for delimiter in (b"END", "éEOF".encode()):
                prefix = b"cat <<'" + delimiter + b"'\n" + body + b"\n" + delimiter + b"\n"
                for tail in (b"cat <<\n", b"cat <<#comment", b"cat <<;",
                             b"cat <<&& :", b"cat <<)", b"cat << < file"):
                    with self.subTest(body=body, delimiter=delimiter, tail=tail):
                        source = prefix + tail
                        self.assertEqual(self.syntax(source), 2)
                        self.assertEqual(self.classify(source), 2)
                self.assertEqual(self.classify(prefix + b"cat <<"), 1)
                self.assertEqual(self.classify(prefix + b"cat <<'unfinished"), 1)
                self.assertEqual(self.classify(prefix + b":"), 0)
                # Unknown code remains unknown even after a known bad header.
                self.assertEqual(self.classify(prefix + "cat <<\nprintf é".encode()), 2)
                self.assertEqual(self.classify(prefix + "cat <<\nprintf $'é'".encode()), 4)
                self.assertEqual(self.classify(prefix + "cat <<\nprintf 'é'".encode()), 2)

    def test_redirect_operators_are_complete_lexical_units(self):
        invalid = [b"<<<<x", b"<<<>x", b">>&x", b"<>&3", b">><x", b"<<< >x"]
        valid = [b"<file", b">file", b">>file", b"<>file", b">|file",
                 b"<&0", b">&1", b"<<<word", b"<<<<(:)", b"> >(printf x)"]
        for prefix in (b"", b"2", b"{fd}"):
            for head, tail in [(b": ", b""), (b"{ :; } ", b""), (b"echo $(: ", b")")]:
                for operators, syntax, status in [(invalid, 2, 2), (valid, 0, 0)]:
                    for operator in operators:
                        source = head + prefix + operator + tail
                        with self.subTest(source=source):
                            self.assertEqual(self.syntax(source), syntax)
                            self.assertEqual(self.classify(source), status)

    def test_indexed_assignment_and_document_word_roles(self):
        for source in [b"a[1 + 2]=x", b"a[1 + 2]=x printf x",
                       b"a\\\n[1 + 2]\\\n=\\\nx printf x",
                       b"declare a[1 + 2]=x", b"echo a[1 + 2]=x",
                       b": <<<x {", b": <<<x }", b"time <<<x {",
                       b"{ : <<<x }; }", b": <<'Q' {\npayload\nQ\n"]:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 0)
        for source in [b"a[1 + 2]=x a=(x)", b"x=1 a[1 + 2]=x a=(x)",
                       b"a[1 + 2]=x declare a=(x)", b"declare a[1 + 2]=x a=(x)"]:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 4)
        for source in [b"a[1 + 2]=x : a=(x)", b"declare >out a[1 + 2]=x a=(x)"]:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 2)
                self.assertEqual(self.classify(source), 2)

    def test_mixed_unknown_is_not_a_validity_claim(self):
        cases = ["printf '%s' $'日本'\ncat <<\n".encode(),
                 b"if true; then :; fi\ncat <<\n"]
        for source in cases:
            with self.subTest(source=source):
                self.assertNotEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 4)

    def test_fixed_executor_locale(self):
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        for operation in (b"LC_ALL=POSIX", b"LC_ALL=POSIX printf ok",
                          b"export LC_ALL=POSIX", b"declare LC_ALL=POSIX",
                          b"unset LC_ALL", b"read LC_ALL <<<POSIX",
                          b"printf -v LC_ALL %s POSIX", b"printf '%n' LC_ALL",
                          b"getopts a LC_ALL -a"):
            with self.subTest(operation=operation):
                reference = subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-c",
                     b"readonly LC_ALL; " + operation +
                     b"; printf '\\nLC_ALL=%s\\n' \"$LC_ALL\""], env=environment,
                    capture_output=True, timeout=10)
                self.assertIn(b"readonly", reference.stderr)
                # Some builtins continue after a rejected assignment and can
                # return zero. Assert the fixed variable, not their status.
                if reference.returncode == 0:
                    self.assertTrue(reference.stdout.endswith(b"\nLC_ALL=C\n"))

    def test_literal_word_bytes_match_reference_argv(self):
        words = ["'日本'".encode(), '"日本"'.encode(),
                 "pre'日本'\".txt\"".encode(), b"'\x80\xff\xc0\xaf'",
                 b'"\x80\xff\xc0\xaf"', "'é'\"\\$\"'文'".encode(),
                 '"a\\\n日本"'.encode(), b"''\"\xe6\"''",
                 "'é'".encode(), "'é'".encode(),
                 "'é\\'".encode(), b"'\x80\xff\\'",
                 "pre'é\\'\".txt\"".encode(), '"é\\q"'.encode(),
                 '"é\\\\"'.encode(), '"é\\\"q"'.encode(), '"é\\`q"'.encode()]
        payload = bytes(range(128, 256))
        words += [payload, b"'" + payload + b"'", b'"' + payload + b'"',
                  "日本".encode(), "résumé.txt".encode(),
                  "pre日'本'\".txt\"".encode(), "\\日本".encode(),
                  "日\\\n本".encode(), "日本\\ word".encode(),
                  "$日本".encode(), "日本=value".encode(),
                  "if日本".encode(), "日本if".encode(),
                  "日本.if".encode(), "日本''if".encode(),
                  "日本-while".encode(), "日本/in".encode(),
                  b"x.if", b"x''while", "日本$'ascii'case".encode()]

        def netstring(value):
            return str(len(value)).encode() + b":" + value + b","

        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            if locale != "C":
                charmap = subprocess.run(["locale", "charmap"],
                                         env=environment, capture_output=True,
                                         check=True, timeout=10).stdout.strip()
                self.assertEqual(charmap.upper().replace(b"-", b""), b"UTF8")
            for word in words:
                source = b"printf '%s\\0' " + word
                with self.subTest(locale=locale, word=word):
                    reference = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; " + source], env=environment,
                        capture_output=True, check=True, timeout=10).stdout
                    self.assertTrue(reference.endswith(b"\0"))
                    self.assertEqual(reference.count(b"\0"), 1)
                    expected = netstring(b"".join(netstring(v) for v in
                                                 (b"printf", b"%s\\0",
                                                  reference[:-1])))
                    actual = subprocess.run([self.probe, "--argv"],
                                            input=source, capture_output=True,
                                            check=True, timeout=10).stdout
                    self.assertEqual(actual, expected)
                    self.assertEqual(self.classify(source), 0)

    def test_quoted_backslash_list_boundaries(self):
        for first in ("é".encode(), b"\xe9"):
            source = b"printf '%s\\0' '" + first + b"\\'; printf '%s\\0' 'a\\'"
            self.assertEqual(self.classify(source), 0)
            self.assertEqual(self.syntax(source), 0)
            for locale in ("C", "C.UTF-8"):
                environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
                result = subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-c", source],
                    env=environment, capture_output=True, check=True, timeout=10)
                self.assertEqual(result.stdout, first + b"\\\0a\\\0")
            for tail in (b"", b"; printf '", b" &&"):
                incomplete = b"printf '" + first + b"\\" + (b"'" if tail else b"") + tail
                self.assertEqual(self.classify(incomplete), 1)

    def test_unquoted_word_roles(self):
        cases = [
            ("name=日; printf '%s' $name日本", "日日本"),
            ("printf '%s' $日本", "$日本"),
            ("unset v; printf '%s' ${v:-日本}", "日本"),
            ("v=日本語; printf '%s' ${v#日本}", "語"),
            ("v=日本語; printf '%s' ${v/日本/文}", "文語"),
            ("exec 3<<<payload; read 日本 IFS fd <&3; IFS= read -r value <&3; printf '%s' \"$value\"", "payload"),
        ]
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for source, expected in cases:
                with self.subTest(locale=locale, source=source):
                    self.assertEqual(self.classify(source.encode()), 0)
                    reference = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         "readonly LC_ALL; " + source], env=environment,
                        capture_output=True, check=True, timeout=10)
                    self.assertEqual(reference.stdout, expected.encode())

    def test_invalid_high_byte_read_target_preserves_input(self):
        source = (b"readonly LC_ALL; exec 3<<<payload; read '\xe9' IFS fd <&3; "
                  b"status=$?; IFS= read -r remaining <&3; "
                  b"printf 'read=%s;remaining=%s\\n' \"$status\" \"$remaining\"")
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            result = subprocess.run(
                [self.bash, "--noprofile", "--norc", "-p", "-c", source],
                env=environment, capture_output=True, check=True, timeout=10)
            self.assertEqual(result.stdout, b"read=1;remaining=payload\n")
            self.assertIn(b"not a valid identifier", result.stderr)

    def test_indexed_assignment_prefixes_do_not_prove_syntax_errors(self):
        for source in [b"a[1 + (2)]=x", b"a[1 + (2)]=x printf ok",
                       b"a[$(printf 1) + (2)]=x",
                       b"a\\\n[1 + (2)]=x", b"a[${v:-]} + (2)]=x",
                       b"a[${v:-[} + (2)]=x",
                       b"a[${v:-${w:-]}} + (2)]=x",
                       b"a[${v:-$(printf ])} + (2)]=x",
                       b"a[<(printf ]) + (2)]=x",
                       b"a[>(printf [) + (2)]=x",
                       b"a[${indices[0]:-]} + (2)]=x",
                       b"a[$\\\n{v:-]} + (2)]=x",
                       b"a[<\\\n(printf ]) + (2)]=x",
                       b"a\\\n[$\\\n{v:-]} + (2)]\\\n=\\\nx"]:
            self.assertEqual(self.syntax(source), 0)
            self.assertEqual(self.classify(source), 0)
            for end in range(len(source) + 1):
                with self.subTest(source=source, end=end):
                    self.assertNotEqual(self.classify(source[:end]), 2)
        for source in [b"a[1 + (", b"a[1 + (2", b"a[1 + (2)",
                       b"a[1 + (2)]", b"a[${v:-[}"]:
            self.assertEqual(self.classify(source), 4)
        for source in [b"a[${v:-]", b"a[<(printf ]", b"a[>(printf ["]:
            self.assertEqual(self.classify(source), 1)
        for source in [b"a=(x\\ y)", b"declare a=(x\\ y)", b"a[\\(]=(x\\ y)"]:
            self.assertEqual(self.syntax(source), 0)
            self.assertEqual(self.classify(source), 4)
        self.assertEqual(self.classify(b"a[\\(]=(x"), 4)
        for source in [b"declare a[1 + (2)]=x", b"echo a[1 + (2)]=x"]:
            self.assertNotEqual(self.syntax(source), 0)
            self.assertEqual(self.classify(source), 2)

    def test_nested_parameter_subscript_is_an_assignment(self):
        # Fixed builtin-only execution qualifies the assignment role; -n
        # alone cannot distinguish it from a command with assignment-like argv.
        source = b"v=0; a[${v:-]}]=x"
        self.assertEqual(self.syntax(source), 0)
        self.assertEqual(self.classify(source), 0)
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-p", "-c",
             source + b"; declare -p a"],
            capture_output=True, env=dict(os.environ, BASH_ENV="", ENV="",
                                          LC_ALL="C"), timeout=10, check=True)
        self.assertEqual(result.stdout, b'declare -a a=([0]="x")\n')

    def test_declaration_operand_boundaries_against_execution(self):
        # -n proves syntax, not argv boundaries. Fixed builtin-only execution
        # establishes that declaration operands are ordinary words here.
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        for name in [b"declare", b"typeset", b"export", b"readonly", b"local"]:
            for quoted in (False, True):
                operand = b"'a[1 + 2]=x'" if quoted else b"a[1 + 2]=x"
                source = name + b" " + operand
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 0)
                program = b"f() { " + source + b"; }; f" if name == b"local" else source
                result = subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-x", "-c", program],
                    capture_output=True, env=environment, timeout=10)
                expected = b"'a[1 + 2]=x'" if quoted else b"'a[1' + '2]=x'"
                self.assertIn(name + b" " + expected, result.stderr)
                if not quoted:
                    self.assertNotEqual(result.returncode, 0)

    def test_implicit_child_heredoc_eof(self):
        # These fixed programs use builtins only. Bash -n defers parsing some
        # backtick children, so confirm actual success and warning emission.
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL="C")
        for source in [b'printf "[%s]\\n" "$(: <<EOF)"',
                       b'printf "[%s]\\n" "`: <<EOF`"',
                       b'printf "[%s]\\n" "`: <<EOF\npayload\n`"',
                       b'printf "[%s]\\n" "`: <<EOF; !`"']:
            with self.subTest(source=source):
                result = subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-c", source],
                    capture_output=True, env=environment, timeout=10)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"[]\n")
                self.assertIn(b"here-document", result.stderr)
                self.assertNotIn(b"syntax error", result.stderr)
                self.assertEqual(self.classify(source), 4)
        self.assertEqual(self.classify(b": <(: <<EOF)"), 4)
        self.assertEqual(self.classify(b"echo `: <<`"), 2)

    def test_incomplete_is_not_a_complete_source_verdict(self):
        self.assertEqual(self.classify(b"cat <<"), 1)
        self.assertEqual(self.classify(b"cat <<EOF\npayload\n"), 1)
        # Bash accepts a received EOF as an implicit heredoc end, with a warning.
        self.assertEqual(self.syntax(b"cat <<EOF\npayload\n"), 0)
        self.assertEqual(self.classify(b"echo 'unfinished"), 1)
        self.assertNotEqual(self.syntax(b"echo 'unfinished"), 0)
        self.assertEqual(self.classify(b"echo $(!"), 1)
        self.assertEqual(self.classify(b"( !"), 1)
        # Array interiors are unclassified, including appendable declarations.
        self.assertEqual(self.classify(b"a=("), 4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    SourceStatusContract.bash = args.bash
    SourceStatusContract.probe = args.probe
    unittest.main(argv=[__file__])
