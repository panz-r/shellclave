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
            ("printf '%s' $'日本'".encode(), 0),
            (b"if true; then :; fi", 4),
            (b"case x in x) :;; esac", 4),
            (b"f() { :; }", 4),
            (b"foo.bar() { :; }", 4),
            (b"foo-bar() { :; }", 4),
            (b"1f() { :; }", 4),
            (b'"f"() { :; }', 4),
            (b"f\\ g() { :; }", 4),
            (b"[[ -f input ]]", 4),
            (b"((1 + 2))", 0),
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

    def test_arithmetic_command_framing(self):
        complete = [b"(( ))", b"((1 << 2))", b"((1+))",
                    b"(( $(printf 1) ))", b"(( '1' ))",
                    b"((printf ok); printf tail)", b"( (printf ok) )",
                    b"(\\\n(1))", b"((1) )", b"time ! ((1)) >out",
                    b"echo \"$( ((1 << 2)); printf ok)\"",
                    b"cat <<EOF\n$( ((1 << 2)); printf ok)\nEOF\n"]
        invalid = [b"((1)) word", b"((1))((2))", b"((1));;",
                   b"(( $(printf &&) ))", b"((1)) > ;",
                   b"echo ((1))", b"x=1 ((1))", b">out ((1))"]
        for cases, syntax, status in ((complete, 0, 0), (invalid, 2, 2)):
            for source in cases:
                with self.subTest(source=source):
                    self.assertEqual(self.syntax(source), syntax)
                    self.assertEqual(self.classify(source), status)
        for source in (b"((", b"((1", b"((1)", b"printf ok; ((1+"):
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 2)
                self.assertEqual(self.classify(source), 1)

    def test_arithmetic_child_byte_domains(self):
        cases = [
            ("(( $(printf 1; : 日本) ))".encode(), 0, 0),
            ("(( $(printf '%s' '日本') ))".encode(), 0, 0),
            ("(( $(printf 1 #日本\n) ))".encode(), 0, 0),
            ("(( `printf '%s' 日本` ))".encode(), 0, 0),
            (b"(( $(printf '%s' \xff) ))", 0, 0),
            (b"(( $(printf 1 #\xff\n) ))", 0, 0),
            ("(( $(printf 日本 &&) ))".encode(), 2, 2),
            ("(( $(printf 日本) )) word".encode(), 2, 2),
            ("(( $(printf 日本".encode(), 2, 1),
            ("(( `printf 日本".encode(), 2, 1),
            ("((日本))".encode(), 0, 4),
            ("((日本".encode(), 2, 4),
        ]
        for source, syntax, status in cases:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), syntax)
                self.assertEqual(self.classify(source), status)

    def test_keyword_fragments_are_ordinary_words(self):
        cases = [
            b"fi$(printf x)", b"if$(printf x) then",
            b"then<(printf x)", b"done>(printf x)",
            b"esac`printf x`", b"fi$((1))", b"$(printf x)fi",
            b"<(printf x)done", b"`printf x`else",
            b"f\\\ni\\\n$(printf x)", b"$(printf x)\\\nfi",
            b"time -p fi$(printf x)", b"! fi$(printf x) | cat",
            b"true && fi$(printf x)", b"{ fi$(printf x); }",
            b"( fi$(printf x) )", b"cat >fi$(printf x)",
            b"echo $(fi$(printf x))",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 0)

    def test_comment_byte_domains(self):
        payloads = ["日本 if while case $(false) >phantom <<MISSING ' \"".encode(),
                    bytes(range(128, 256)),
                    "line\u2028separator\u0085data".encode()]
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for payload in payloads:
                cases = [
                    (b"# " + payload, b""),
                    (b"# " + payload + b"\nprintf ok", b"ok"),
                    (b"printf ok # " + payload, b"ok"),
                    (b"printf before # " + payload + b" \\\nprintf after", b"beforeafter"),
                    (b'printf "%s" "$(printf inner # ' + payload + b'\n)"', b"inner"),
                    (b'printf "%s" "`printf inner # ' + payload + b'\n`"', b"inner"),
                    (b"read -r value <<EOF # " + payload +
                     b'\npayload\nEOF\nprintf "%s" "$value"', b"payload"),
                ]
                for source, expected in cases:
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(self.classify(source), 0)
                        reference = subprocess.run(
                            [self.bash, "--noprofile", "--norc", "-p", "-c",
                             b"readonly LC_ALL; " + source], env=environment,
                            capture_output=True, check=True, timeout=10)
                        self.assertEqual(reference.stdout, expected)
        cases = [
            ("printf ok && # 日本".encode(), 1),
            ("# 日本\ncat <<\n".encode(), 2),
            ("cat <<# 日本".encode(), 2),
            ("# 日本\nprintf $'日'".encode(), 0),
            ("# 日本\nprintf $((日))".encode(), 4),
            ("# 日本\nif true; then :; fi".encode(), 4),
            ("printf %s word#日本 \\#日本 '#日本' ${v#日本}".encode(), 0),
            (b"# \x80\x00", 5),
            (b"# \x80\x01", 4),
            (b"# \x80\x7f", 4),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(self.classify(source), expected)
                if expected == 2:
                    self.assertNotEqual(self.syntax(source), 0)

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
                # Literal byte forms preserve the bad-header diagnosis;
                # restricted code remains unknown.
                self.assertEqual(self.classify(prefix + "cat <<\nprintf é".encode()), 2)
                self.assertEqual(self.classify(prefix + "cat <<\nprintf $'é'".encode()), 2)
                self.assertEqual(self.classify(prefix + "cat <<\nprintf $((é))".encode()), 4)
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
        cases = ["printf '%s' $((日本))\ncat <<\n".encode(),
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
                  b"$'" + payload + b"'",
                  "日本".encode(), "résumé.txt".encode(),
                  "pre日'本'\".txt\"".encode(), "\\日本".encode(),
                  "日\\\n本".encode(), "日本\\ word".encode(),
                  "$日本".encode(), "日本=value".encode(),
                  "if日本".encode(), "日本if".encode(),
                  "日本.if".encode(), "日本''if".encode(),
                  "日本-while".encode(), "日本/in".encode(),
                  b"x.if", b"x''while", "日本$'ascii'case".encode(),
                  "$'日本'".encode(), "$'日\\t本'".encode(),
                  "$'résumé.txt'".encode(), "pre$'日\\x41'\"本\"".encode(),
                  "$'é\\'日\\\\本'".encode(), "$'\\日本'".encode(),
                  b"$'\x80\xff\xc0\xaf'", "$'\\cé'".encode(),
                  b"$'\\c\xff'", "$'日\\\n本'".encode(),
                  "$'日本\\u0041'".encode(),
                  "$'日本\\444(printf child)'".encode(),
                  "$'日本\\540printf child\\540'".encode(),
                  "$'日本\\534'".encode(),
                  "$'before\\0after'".encode(), "pre$'before\\0after'post".encode(),
                  "$'\\0'".encode(), "$'\\0ignored'after".encode(),
                  "$'a\\000b'".encode(), "$'a\\400b'".encode(),
                  "$'a\\x00b'".encode(), "$'a\\c@b'".encode(),
                  "$'a\\u0000b'".encode(), "$'a\\U00000000b'".encode(),
                  "$'a\\0b'$'c\\0d'e".encode(), "$\\\n'a\\0b'c".encode(),
                  "$'日本\\0ignored'語".encode(), "$'a\\0\\u65e5'".encode(),
                  "$'a\\0\\U000065e5'".encode(), "$'a\\0\\c\\'discarded'X".encode(),
                  "$'a\\0$(printf phantom)`printf phantom`*?{a,b}'".encode(),
                  "$'日本$(printf phantom)`printf phantom`*?'".encode(),
                  '"$\'日本\'"'.encode()]
        # A backslash control operand consumes its doubled spelling; an
        # apostrophe protected by that operand remains literal word data.
        for prefix in (b"", b"ascii", "日本".encode()):
            for count in range(1, 7):
                fragment = b"$'" + prefix + b"\\c" + b"\\" * count
                words.append(fragment + b"X'")
                if count % 2 == 0:
                    words.append(fragment + b"'")
            words += [b"$'" + prefix + b"\\c\\'X'",
                      b"$'" + prefix + b"\\c\\''",
                      b"pre$'" + prefix + b"\\c\\\\'\"tail\""]

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

    def test_ansi_control_escape_incomplete_quotes(self):
        for prefix in (b"ascii", "日本".encode()):
            for count in (1, 3, 5):
                source = b"printf $'" + prefix + b"\\c" + b"\\" * count + b"'"
                with self.subTest(source=source):
                    self.assertNotEqual(self.syntax(source), 0)
                    self.assertEqual(self.classify(source), 1)

    def test_ansi_byte_contexts(self):
        cases = [
            ("value=$'日本\\t語'; printf '%s' \"$value\"", "日本\t語"),
            ("unset v; printf '%s' ${v:-$'日本'}", "日本"),
            ('unset v; printf \'%s\' "${v:-$\'日本\\t語\'}"', "日本\t語"),
            ('unset v; printf \'%s\' "${v:-$\'日本$(printf child)\'}"', "日本child"),
            ("v=日本語; printf '%s' ${v#$'日本'}", "語"),
            ("v=日本語; printf '%s' ${v/$'日本'/$'文'}", "文語"),
            ('printf \'%s\' "$(printf %s $\'日本\')"', "日本"),
            ("cat < <(printf %s $'日本')", "日本"),
            ("printf '%s' `printf %s $'日本'`", "日本"),
            ("cat <<$'日本'\npayload\n日本\n", "payload\n"),
            ("value=pre$'a\\0b'post; printf '%s' \"$value\"", "preapost"),
            ("unset v; printf '%s' ${v:-$'a\\0$(printf phantom)'}", "a"),
            ('v=abc; printf \'%s\' "${v#$\'a\\0b\'}"', "bc"),
            ('v=abc; printf \'%s\' "${v/$\'a\\0b\'/$\'z\\0t\'}"', "zbc"),
            ('printf \'%s\' "$(printf %s $\'a\\0b\')"', "a"),
            ("cat < <(printf %s $'a\\0b')", "a"),
            ("cat <<$'END\\0ignored'\npayload\nEND\n", "payload\n"),
            ("cat <<$'\\0ignored'\npayload\n\n", "payload\n"),
            ("cat <<$'E\\0ignored'X$'Y\\0ignored'W\npayload\nEXYW\n", "payload\n"),
        ]
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for source, expected in cases:
                with self.subTest(locale=locale, source=source):
                    self.assertEqual(self.classify(source.encode()), 0)
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         "readonly LC_ALL; " + source], env=environment,
                        capture_output=True, check=True, timeout=10)
                    self.assertEqual(result.stdout, expected.encode())
        for source in ["printf $(( $'日本' ))", "printf ${v:$'日本'}",
                       "printf ${v[$'日本']}", "a[$'日本']=x",
                       'printf "${v:-$\'日本\\x24(printf child)\'}"']:
            with self.subTest(source=source):
                self.assertEqual(self.classify(source.encode()), 4)
        self.assertEqual(self.classify("printf $'日本'\ncat <<\n".encode()), 2)

    def test_ansi_nul_parameter_boundary(self):
        # Grammar recognition stays separate from unsupported Bash runtime
        # substitution errors. Ordinary unquoted/pattern contexts are above.
        cases = [b'printf "${v:-$\'a\\0b\'}"',
                 b'printf "${v:+$\'a\\0b\'}"',
                 b'printf "${v:-$\'a\\0$(printf phantom)\'}"']
        patterns = (b"${v#INNER}", b"${v##INNER}", b"${v%INNER}",
                    b"${v%%INNER}", b"${v/INNER/x}", b"${v/x/INNER}",
                    b"${v^INNER}", b"${v^^INNER}", b"${v,INNER}",
                    b"${v,,INNER}")
        for pattern in patterns:
            for operator in (b"-", b":-", b"+", b":+"):
                inner = b"${u" + operator + b"$'a\\0b'}"
                cases.append(b'printf %s "' +
                             pattern.replace(b"INNER", inner) + b'"')
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(self.syntax(source), 0)
                self.assertEqual(self.classify(source), 0)
                result = subprocess.run([self.probe, "--argv"], input=source,
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)

    def test_nested_parameter_quote_context(self):
        cases = (
            (b'printf %s "${v#${u:-$\'$(printf a >&2)\'}}"', b"abc", b"a"),
            (b'printf %s "${v/x/${u:+$\'$(printf a >&2)\'}}"', b"abc", b"a"),
            (b"printf %s ${v#${u:-$'$(printf a >&2)'}}", b"abc", b""),
            (b'printf %s "${v#$\'$(printf a >&2)\'}"', b"abc", b""),
            (b"cat <<EOF\n${v#${u:-$'a\\0b'}}\nEOF", b"bc\n", b""),
            (b"cat <<EOF\n${v#${u:-$'$(printf a >&2)'}}\nEOF", b"abc\n", b"a"),
            (b"cat <<EOF\n${v#${u:-$'a\\0$(printf a >&2)'}}\nEOF", b"bc\n", b""),
            (b"cat <<EOF\n${v#${u:-$'$(printf a >&2)b\\0tail'}}\nEOF", b"abc\n", b"a"),
            (b"cat <<EOF\n${v#${u:-$'$(printf a)b\\0tail'}}\nEOF", b"c\n", b""),
            (b"cat <<EOF\n${v#${u:-$'${w:-$(printf a)}b\\0tail'}}\nEOF", b"c\n", b""),
        )
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for source, output, diagnostic in cases:
                with self.subTest(locale=locale, source=source):
                    initial = (b"u=x; " if b"${u:+" in source
                               else b"unset u; ")
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; unset w; v=abc; " + initial + source],
                        env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, output)
                    self.assertEqual(result.stderr, diagnostic)
                    self.assertEqual(self.classify(source), 0)

    def test_nested_ansi_escape_translation(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for context in ("default", "pattern", "heredoc", "clipped"):
                for depth in (1, 2):
                    for count in range(9):
                        operand = (b"${w:-" * depth + b"\\" * count +
                                   b"$(printf child >&2)" + b"}" * depth)
                        fragment = (b"$'" + operand +
                                    (b"\\0$(printf phantom >&2)"
                                     if context == "clipped" else b"") + b"'")
                        if context == "default":
                            source = b'printf %s "${v:-' + fragment + b'}"'
                            initial = b"unset v u w; "
                        else:
                            word = b"${v#${u:-" + fragment + b"}}"
                            source = (b'printf %s "' + word + b'"'
                                      if context == "pattern" else
                                      b"cat <<EOF\n" + word + b"\nEOF\n")
                            initial = b"v=abc; unset u w; "
                        with self.subTest(locale=locale, context=context,
                                          depth=depth, count=count):
                            result = subprocess.run(
                                [self.bash, "--noprofile", "--norc", "-p", "-c",
                                 b"readonly LC_ALL; " + initial + source],
                                env=environment, capture_output=True, timeout=10)
                            executed = count % 4 in (0, 3)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr,
                                             b"child" if executed else b"")
                            if context == "default":
                                output = (b"\\" * ((count + 1) // 4) +
                                          (b"" if executed else
                                           b"$(printf child >&2)"))
                            else:
                                output = (b"abc" if context == "pattern"
                                          else b"abc\n")
                            self.assertEqual(result.stdout, output)
                            self.assertEqual(self.classify(source), 0)

    def test_parameter_word_expansion_phases(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for context in ("heredoc-pattern", "shell-pattern-default",
                            "quoted-default", "quoted-nested-pattern",
                            "unquoted", "heredoc-direct-pattern"):
                for opener, closer in ((b"$(", b")"), (b"`", b"`"),
                                       (b"<(", b")"), (b">(", b")")):
                    # Escaping only the opening backtick has different raw
                    # pairing and can be a Bash substitution error.
                    for count in range(1 if opener == b"`" else 9):
                        for clipped in (False, True):
                            if clipped and context in (
                                    "shell-pattern-default", "quoted-default",
                                    "quoted-nested-pattern"):
                                # The existing double-quoted NUL contract
                                # declines semantic evaluation separately.
                                continue
                            fragment = (b"$'" + b"\\" * count + opener +
                                        b"printf child >&2" + closer +
                                        (b"a\\0$(printf phantom >&2)"
                                         if clipped else b"") + b"'")
                            if context == "quoted-default":
                                source = b'echo "${0:+' + fragment + b'}"'
                            elif context == "heredoc-direct-pattern":
                                source = (b"cat <<EOF\n${0#" + fragment +
                                          b"}\nEOF\n")
                            else:
                                nested = (b"${0#" + fragment + b"}"
                                          if context != "shell-pattern-default"
                                          else fragment)
                                word = b"${0#${0:+" + nested + b"}}"
                                source = (b"cat <<EOF\n" + word + b"\nEOF\n"
                                          if context == "heredoc-pattern" else
                                          b"echo " + word if context == "unquoted"
                                          else b'echo "' + word + b'"')
                            active = (context in ("heredoc-pattern",
                                                  "shell-pattern-default") or
                                      context == "quoted-default" and
                                      opener in (b"$(", b"`"))
                            executed = active and count % 4 in (0, 3)
                            with self.subTest(locale=locale, context=context,
                                              opener=opener, count=count,
                                              clipped=clipped):
                                self.assertEqual(self.syntax(source), 0)
                                result = subprocess.run(
                                    [self.bash, "--noprofile", "--norc", "-p", "-c",
                                     b"readonly LC_ALL; " + source,
                                     b"shellclave-phase"],
                                    env=environment, capture_output=True,
                                    timeout=10)
                                self.assertEqual(result.returncode, 0,
                                                 result.stderr)
                                self.assertEqual(result.stderr,
                                                 b"child" if executed else b"")
                                self.assertEqual(self.classify(source), 0)

        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for source, executed in (
                    (b'echo "${0#$\'<(printf child >&2)\\n\'}"', False),
                    (b'echo "${0:+$\'<(printf child >&2)\\n\'}"', False),
                    (b'echo "${0#${0:+$\'<(printf child >&2)\\n\'}}"', True)):
                with self.subTest(locale=locale, source=source):
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; " + source, b"shellclave-phase"],
                        env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"child" if executed else b"")
                    self.assertEqual(self.classify(source), 0)
            for word in (
                    b"${0%${u:-${0%%$'$(printf child >&2)'}}}",
                    b"${0#${u-${0/x/$'`printf child >&2`'}}}",
                    b"${0#${0+${0^^$'$(printf child >&2)'}}}"):
                source = b"cat <<EOF\n" + word + b"\nEOF\n"
                with self.subTest(locale=locale, word=word):
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; unset u; " + source,
                         b"shellclave-phase"],
                        env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"child")
                    self.assertEqual(self.classify(source), 0)

    def test_quotes_in_reexpanded_ansi_values(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for heredoc in (False, True):
                for nested in (False, True):
                    for clipped in (False, True) if heredoc else (False,):
                        for opener in (b"<(", b">("):
                            for count in range(9):
                                value = (b'"' + b"\\" * count + opener +
                                         b'printf child >&2)"')
                                if nested:
                                    value = b"${0:+" + value + b"}"
                                fragment = (b"$'" + value +
                                            (b"\\0tail" if clipped else b"") +
                                            b"'")
                                word = b"${0#${0:+" + fragment + b"}}"
                                source = (b"cat <<EOF\n" + word + b"\nEOF\n"
                                          if heredoc else b'echo "' + word + b'"')
                                with self.subTest(locale=locale, source=source):
                                    self.assertEqual(self.syntax(source), 0)
                                    result = subprocess.run(
                                        [self.bash, "--noprofile", "--norc",
                                         "-p", "-c", b"readonly LC_ALL; " + source,
                                         b"shellclave-quotes"], env=environment,
                                        capture_output=True, timeout=10)
                                    self.assertEqual(result.returncode, 0,
                                                     result.stderr)
                                    self.assertEqual(result.stderr, b"")
                                    self.assertEqual(self.classify(source), 0)
            for value in (
                    b'"<(printf literal $(printf child >&2))"',
                    b'">(printf literal `printf child >&2`)"',
                    b'"<(printf literal)"<(printf child >&2)',
                    b'">(printf literal)">(printf child >&2)'):
                for heredoc in (False, True):
                    fragment = b"$'" + value + (b"\\0tail" if heredoc else b"") + b"'"
                    word = b"${0#${0:+" + fragment + b"}}"
                    source = (b"cat <<EOF\n" + word + b"\nEOF\n"
                              if heredoc else b'echo "' + word + b'"')
                    with self.subTest(locale=locale, source=source):
                        result = subprocess.run(
                            [self.bash, "--noprofile", "--norc", "-p", "-c",
                             b"readonly LC_ALL; " + source, b"shellclave-quotes"],
                            env=environment, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, b"child")
                        self.assertEqual(self.classify(source), 0)

    def test_heredoc_word_pattern_phase_boundaries(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for operator in (b"0:+", b"u:-"):
                for opener, closer in ((b"$(", b")"), (b"`", b"`"),
                                       (b"<(", b")"), (b">(", b")")):
                    for clipped in (False, True):
                        fragment = (b"$'" + opener + b"printf child >&2" +
                                    closer + (b"\\0tail" if clipped else b"") +
                                    b"'")
                        word = (b"${" + operator + b"${0#${0:+" + fragment +
                                b"}}}")
                        source = b"cat <<EOF\n" + word + b"\nEOF\n"
                        with self.subTest(locale=locale, operator=operator,
                                          opener=opener, clipped=clipped):
                            self.assertEqual(self.syntax(source), 0)
                            result = subprocess.run(
                                [self.bash, "--noprofile", "--norc", "-p",
                                 "-c", b"readonly LC_ALL; unset u; " + source,
                                 b"shellclave-phase"], env=environment,
                                capture_output=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr, b"")
                            self.assertEqual(self.classify(source), 0)

            cases = (
                (b"${0:+${0#${0#${0:+$'$(printf child >&2)'}}}}}", b""),
                (b"${0#${0:+${0#${0#$'$(printf child >&2)'}}}}", b""),
                (b"${0#${0:+${0:+${0#$'$(printf child >&2)'}}}}", b""),
                (b"${0#${0:+${0#${0:+$'$(printf child >&2)'}}}}", b"child"),
                (b"${0:+${0#${0:+$'$(printf literal >&2)'}}}"
                 b"${0#${0:+${0#$'$(printf child >&2)'}}}", b"child"),
                (b"${0:+$'$(printf direct >&2)'}", b"direct"),
                (b"${0#${0:+${0#$'$(printf child >&2)'}}}", b"child"),
            )
            for word, diagnostic in cases:
                source = b"cat <<EOF\n" + word + b"\nEOF\n"
                with self.subTest(locale=locale, word=word):
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; " + source,
                         b"shellclave-phase"], env=environment,
                        capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, diagnostic)
                    self.assertEqual(self.classify(source), 0)

    def test_heredoc_quote_inheritance_through_patterns(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for opener, closer in ((b"$(", b")"), (b"`", b"`"),
                                   (b"<(", b")"), (b">(", b")")):
                child = opener + b"printf child >&2" + closer
                for pattern in (b"0#", b"0##", b"0%", b"0%%", b"0/",
                                b"0/x/", b"0^", b"0^^", b"0,", b"0,,"):
                    for clipped in (False, True):
                        fragment = (b"$'" + child +
                                    (b"\\0tail" if clipped else b"") + b"'")
                        word = (b'${0:+"${' + pattern + b"${0:+" + fragment +
                                b'}}"}')
                        source = b"cat <<EOF\n" + word + b"\nEOF\n"
                        with self.subTest(locale=locale, source=source):
                            self.assertEqual(self.syntax(source), 0)
                            result = subprocess.run(
                                [self.bash, "--noprofile", "--norc", "-p", "-c",
                                 b"readonly LC_ALL; " + source,
                                 b"shellclave-phase"], env=environment,
                                capture_output=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr, b"")
                            self.assertEqual(self.classify(source), 0)
                fragment = b"$'" + child + b"'"
                active = b"${0#${0:+${0#" + fragment + b"}}}"
                quoted = b'${0:+"${0#${0:+' + fragment + b'}}"}'
                controls = (
                    (b'${0#"${0:+' + fragment + b'}"}',
                     opener in (b"$(", b"`")),
                    (b'${0:+"${0#"${0:+' + fragment + b'}"}"}',
                     opener in (b"$(", b"`")),
                    (b'${0:+"${0#${0:+' + child + b'}}"}', True),
                    (quoted + active, True),
                    (b'${0:+"${0##${0:+${0%${0:+' + fragment + b'}}}}"}',
                     False),
                )
                for word, executed in controls:
                    source = b"cat <<EOF\n" + word + b"\nEOF\n"
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(self.syntax(source), 0)
                        result = subprocess.run(
                            [self.bash, "--noprofile", "--norc", "-p", "-c",
                             b"readonly LC_ALL; " + source, b"shellclave-phase"],
                            env=environment, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr,
                                         b"child" if executed else b"")
                        self.assertEqual(self.classify(source), 0)

    def test_ansi_data_around_children(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for escape in (b"\\n", b"\\t", b"\\x61"):
                for before in (False, True):
                    for opener, closer in ((b"$(", b")"), (b"`", b"`")):
                        child = opener + b"printf child >&2" + closer
                        fragment = (b"$'" + (escape if before else b"") +
                                    child + (b"" if before else escape) + b"'")
                        sources = (
                            (b'echo "${0:+' + fragment + b'}"', True),
                            (b'echo "${0#${0:+' + fragment + b'}}"', True),
                            (b"cat <<EOF\n${0#${0:+${0#" + fragment +
                             b"}}}\nEOF\n", True),
                            (b'echo "${0#' + fragment + b'}"', False),
                            (b"echo ${0#${0:+${0#" + fragment + b"}}}", False),
                        )
                        for source, executed in sources:
                            with self.subTest(locale=locale, source=source):
                                self.assertEqual(self.syntax(source), 0)
                                result = subprocess.run(
                                    [self.bash, "--noprofile", "--norc", "-p",
                                     "-c", b"readonly LC_ALL; " + source,
                                     b"shellclave-phase"], env=environment,
                                    capture_output=True, timeout=10)
                                self.assertEqual(result.returncode, 0,
                                                 result.stderr)
                                self.assertEqual(result.stderr,
                                                 b"child" if executed else b"")
                                self.assertEqual(self.classify(source), 0)
            for child in (b"$(printf ch\\x69ld >&2)",
                          b"`printf ch\\x69ld >&2`"):
                for source in (
                        b'echo "${0:+$\'' + child + b"'}\"",
                        b'echo "${0#${0:+$\'' + child + b"'}}\"",
                        b"cat <<EOF\n${0#${0:+${0#$'" + child +
                        b"\\0tail'}}}\nEOF\n"):
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(self.syntax(source), 0)
                        result = subprocess.run(
                            [self.bash, "--noprofile", "--norc", "-p", "-c",
                             b"readonly LC_ALL; " + source, b"shellclave-phase"],
                            env=environment, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, b"child")
                        self.assertEqual(self.classify(source), 4)

    def test_ansi_child_source_translation(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for context in ("default", "pattern", "clipped"):
                for count in range(5):
                    child = (b'$(echo "' + b"\\" * count +
                             b'$(printf child >&2)")')
                    fragment = (b"$'" + child +
                                (b"\\0tail" if context == "clipped" else b"") +
                                b"'")
                    if context == "default":
                        source = b'echo "${v:-' + fragment + b'}"'
                        initial = b"unset v u; "
                    else:
                        word = b"${v#${u:-" + fragment + b"}}"
                        source = (b'echo "' + word + b'"'
                                  if context == "pattern" else
                                  b"cat <<EOF\n" + word + b"\nEOF\n")
                        initial = b"v=abc; unset u; "
                    with self.subTest(locale=locale, context=context,
                                      count=count):
                        self.assertEqual(self.syntax(source), 0)
                        result = subprocess.run(
                            [self.bash, "--noprofile", "--norc", "-p", "-c",
                             b"readonly LC_ALL; " + initial + source],
                            env=environment, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr,
                                         b"child" if count % 4 in (0, 3) else b"")
                        self.assertEqual(self.classify(source),
                                         0 if count < 2 else 4)

    def test_ansi_fragment_boundary_syntax(self):
        joined = (
            (b'echo "${0:+$\'$\'(printf child >&2)}"', b"child"),
            (b'echo "${0#${0:+<$\'(printf child >&2)\'}}"', b"child"),
            (b'echo "${0#${0:+>$\'(printf child >&2)\'}}"', b"child"),
            (b'echo "${0:+$\'$\'$\'(printf child >&2)\'}"', b"child"),
            (b'echo "${0:+$\'$\'$\'\'(printf child >&2)}"', b"child"),
            (b'echo "${0:+$\'$\'""(printf child >&2)}"', b"child"),
            (b'echo "${0:+$\'$\'\\\n(printf child >&2)}"', b"child"),
            (b'echo "${0:+$\'$\'PATH}"', b""),
            (b'echo "${0:+$\'$\'0}"', b""),
            (b'echo "${0:+$\'$\'$\'{PATH}\'}"', b""),
            (b'echo "${0:+$\'$\'$\'((1 + 2))\'}"', b""),
            (b'echo "${0:+$\'${PATH:-\'value}}"', b""),
            (b"cat <<EOF\n${0#${0:+$'$\\0tail'(printf child >&2)}}\n"
             b"EOF\n", b"child"),
        )
        literal = (
            b'echo "${0:+$\'\\$\'(printf child >&2)}"',
            b'echo "${0:+$\'$\' (printf child >&2)}"',
            b'echo "${0:+$$\'(printf child >&2)\'}"',
        )
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for source, diagnostic in joined:
                with self.subTest(locale=locale, source=source):
                    self.assertEqual(self.syntax(source), 0)
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; " + source,
                         b"shellclave-phase"], env=environment,
                        capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, diagnostic)
                    self.assertEqual(self.classify(source), 4)
            for source in literal:
                with self.subTest(locale=locale, source=source):
                    self.assertEqual(self.syntax(source), 0)
                    result = subprocess.run(
                        [self.bash, "--noprofile", "--norc", "-p", "-c",
                         b"readonly LC_ALL; " + source,
                         b"shellclave-phase"], env=environment,
                        capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(self.classify(source), 0)

    def test_empty_quotes_at_translated_boundaries(self):
        contexts = (
            (b'echo "${0:+%s}"', True),
            (b'echo "${0#${0:+%s}}"', False),
            (b'echo "${0#"${0:+%s}"}"', True),
            (b'cat <<EOF\n${0#${0:+%s}}\nEOF\n', False),
            (b'cat <<EOF\n${0#"${0:+%s}"}\nEOF\n', False),
        )
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for prefix in (b"$", b"<", b">"):
                for quotes in (b'""', b'""""', b'"\\\n"'):
                    operand = (b"$'" + prefix + b"'" + quotes +
                               b"(printf child >&2)")
                    for template, shell_quoted_default in contexts:
                        source = template.replace(b"%s", operand)
                        reconstructed = shell_quoted_default and prefix == b"$"
                        with self.subTest(locale=locale, source=source):
                            self.assertEqual(self.syntax(source), 0)
                            result = subprocess.run(
                                [self.bash, "--noprofile", "--norc", "-p", "-c",
                                 b"readonly LC_ALL; " + source,
                                 b"shellclave-boundary"], env=environment,
                                capture_output=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr,
                                             b"child" if reconstructed else b"")
                            self.assertEqual(self.classify(source),
                                             4 if reconstructed else 0)

    def test_quoted_heredoc_pattern_phases(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)
            for opener, closer in ((b"$(", b")"), (b"`", b"`"),
                                   (b"<(", b")"), (b">(", b")")):
                for clipped in (False, True):
                    fragment = (b"$'" + opener + b"printf child >&2" + closer +
                                (b"\\0tail" if clipped else b"") + b"'")
                    inner = b"${0:+${0#" + fragment + b"}}"
                    for quoted in (False, True):
                        word = b"${0#" + (b'"' + inner + b'"'
                                          if quoted else inner) + b"}"
                        source = b"cat <<EOF\n" + word + b"\nEOF\n"
                        with self.subTest(locale=locale, source=source):
                            self.assertEqual(self.syntax(source), 0)
                            result = subprocess.run(
                                [self.bash, "--noprofile", "--norc", "-p", "-c",
                                 b"readonly LC_ALL; " + source,
                                 b"shellclave-phase"], env=environment,
                                capture_output=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr,
                                             b"" if quoted else b"child")
                            self.assertEqual(self.classify(source), 0)
            source = (b'cat <<EOF\n${0#"${0:+${0#$\'$(printf literal >&2)\'}}"}'
                      b"${0#${0:+${0#$'$(printf child >&2)'}}}\nEOF\n")
            result = subprocess.run(
                [self.bash, "--noprofile", "--norc", "-p", "-c",
                 b"readonly LC_ALL; " + source, b"shellclave-phase"],
                env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"child")
            self.assertEqual(self.classify(source), 0)

    def test_ansi_decoded_parameter_syntax(self):
        for locale in ("C", "C.UTF-8"):
            environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale)

            def expand(source):
                return subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-c",
                     b"readonly LC_ALL; unset v; " + source],
                    env=environment, capture_output=True, check=True,
                    timeout=10).stdout

            for prefix in (b"ascii", "日本".encode()):
                for opener in (b"\\044", b"\\444", b"\\x24",
                               b"\\u0024", b"\\U00000024"):
                    source = (b"printf '%s' \"${v:-$'" + prefix + opener +
                              b"(printf child)'}\"")
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(expand(source), prefix + b"child")
                        self.assertEqual(self.classify(source), 4)
                for opener in (b"\\140", b"\\540", b"\\x60"):
                    source = (b"printf '%s' \"${v:-$'" + prefix + opener +
                              b"printf child" + opener + b"'}\"")
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(expand(source), prefix + b"child")
                        self.assertEqual(self.classify(source), 4)
                for residue in range(4):
                    count = 8 + residue
                    fragment = b"\\" * count + b"$(printf child)"
                    source = (b"printf '%s' \"${v:-$'" + prefix + fragment +
                              b"'}\"")
                    output = (b"child" if residue in (0, 3)
                              else b"$(printf child)")
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(expand(source), prefix +
                                         b"\\" * ((count + 1) // 4) + output)
                        self.assertEqual(self.classify(source), 0)
            for byte in b"$<>()":
                escape = ("\\%03o" % (byte + 256)).encode()
                for quote in (b"$'", b"$\\\n'"):
                    source = b"printf '%s' \"${v:-" + quote + escape + b"'}\""
                    with self.subTest(locale=locale, source=source):
                        self.assertEqual(expand(source), bytes([byte]))
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
