"""Qualify conditional grammar and predicate truth against the pinned Bash."""

import argparse
import os
import shlex
import socket
import subprocess
import tempfile
import unittest


class ConditionalCommands(unittest.TestCase):
    def bash_result(self, source, syntax=False, locale="C"):
        environment = dict(os.environ, BASH_ENV="", ENV="", LC_ALL=locale,
                           HOME="/model-home")
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

    def test_file_predicates(self):
        for op in ("-e", "-a", "-f", "-d", "-L", "-h", "-s", "-b", "-c", "-p", "-S",
                   "-r", "-w", "-x", "-u", "-g", "-k", "-O", "-G", "-N"):
            for negation in ("", "! "):
                source = f"[[ {negation}{op} '' ]]"
                with self.subTest(source=source):
                    self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                    truth = self.probe_result(source)
                    self.assertEqual(self.bash_result(source).returncode,
                                     0 if truth == 2 else 1)
                    for form in (f"test {negation}{op} ''",
                                 f"[ {negation}{op} '' ]"):
                        # Three-argument ! -a '' selects binary conjunction.
                        expected = bool(negation) and op != "-a"
                        self.assertEqual(self.bash_result(form).returncode,
                                         0 if expected else 1)
            self.assertEqual(self.probe_result(f"[[ {op} some-path ]]"), 0)
        self.assertEqual(self.bash_result("test -a ''").returncode, 1)
        self.assertEqual(self.bash_result("[ -a '' ]").returncode, 1)
        with tempfile.TemporaryDirectory() as directory:
            regular = os.path.join(directory, "data")
            empty = os.path.join(directory, "empty")
            fifo = os.path.join(directory, "fifo")
            link = os.path.join(directory, "link")
            # Exercise a pathname longer than Linux's Unix socket bind limit.
            socket_directory = os.path.join(directory, "s" * 100)
            os.mkdir(socket_directory)
            sockpath = os.path.join(socket_directory, "socket")
            with open(regular, "w", encoding="ascii") as stream:
                stream.write("x")
            with open(empty, "w", encoding="ascii"):
                pass
            os.mkfifo(fifo)
            os.symlink(regular, link)
            fixtures = [("-s", regular, True), ("-s", empty, False),
                        ("-s", link, True), ("-p", fifo, True),
                        ("-b", regular, False), ("-c", regular, False),
                        ("-c", "/dev/null", True)]
            with socket.socket(socket.AF_UNIX) as sock:
                # Unix socket pathname limits apply to the bind argument,
                # so avoid including a potentially long TMPDIR prefix.
                previous_cwd = os.getcwd()
                os.chdir(socket_directory)
                try:
                    try:
                        sock.bind("socket")
                    except PermissionError:
                        pass  # Some sandboxes prohibit Unix socket endpoints.
                    else:
                        fixtures.append(("-S", sockpath, True))
                finally:
                    os.chdir(previous_cwd)
                for op, path, expected in fixtures:
                    for form in (f"[[ {op} {shlex.quote(path)} ]]",
                                 f"test {op} {shlex.quote(path)}",
                                 f"[ {op} {shlex.quote(path)} ]"):
                        with self.subTest(source=form):
                            self.assertEqual(self.bash_result(form).returncode,
                                             0 if expected else 1)
                    self.assertEqual(self.probe_result(
                        f"[[ {op} {shlex.quote(path)} ]]"), 0)

    def test_access_mode_ownership_and_timestamps(self):
        def check(op, path, expected):
            quoted = shlex.quote(path)
            for form in (f"[[ {op} {quoted} ]]", f"test {op} {quoted}",
                         f"[ {op} {quoted} ]"):
                with self.subTest(source=form):
                    self.assertEqual(self.bash_result(form).returncode,
                                     0 if expected else 1)
            # Metadata and access remain runtime facts, even for a concrete
            # pathname whose fixture state is known to this test process.
            self.assertEqual(self.probe_result(f"[[ {op} {quoted} ]]"), 0)

        with tempfile.TemporaryDirectory() as directory:
            regular = os.path.join(directory, "data")
            link = os.path.join(directory, "link")
            missing = os.path.join(directory, "missing")
            with open(regular, "w", encoding="ascii") as stream:
                stream.write("x")
            os.symlink(regular, link)
            for op in ("-r", "-w", "-x", "-u", "-g", "-k", "-O", "-G", "-N"):
                check(op, missing, False)
            for mode in (0o000, 0o600, 0o700, 0o100, 0o7600):
                os.chmod(regular, mode)
                for path in (regular, link):
                    for op, access in (("-r", os.R_OK), ("-w", os.W_OK),
                                       ("-x", os.X_OK)):
                        # Effective access accounts for root privileges and
                        # supplementary groups; chmod(000) alone is insufficient.
                        check(op, path, os.access(path, access, effective_ids=True))
                    for op, bit in (("-u", 0o4000), ("-g", 0o2000), ("-k", 0o1000)):
                        check(op, path, bool(os.stat(path).st_mode & bit))
                    metadata = os.stat(path)
                    check("-O", path, metadata.st_uid == os.geteuid())
                    check("-G", path, metadata.st_gid == os.getegid())
            # Restore ordinary permissions before exercising timestamp changes.
            os.chmod(regular, 0o600)
            check("-x", directory, os.access(directory, os.X_OK, effective_ids=True))
            os.chmod(directory, 0o1700)
            check("-k", directory, True)
            base = 1_700_000_000_000_000_000
            second = 1_000_000_000

            def check_timestamps(set_times):
                cases = ((base, base + 2 * second), (base, base),
                         (base + 2 * second, base),
                         (base, base + 1), (base + 1, base))
                for atime, mtime in cases:
                    with self.subTest(atime=atime, mtime=mtime):
                        set_times(regular, ns=(atime, mtime))
                        metadata = os.stat(regular)
                        # Integer nanosecond fields report stored timestamps;
                        # filesystem precision can round the requested values.
                        # Stat and predicate queries leave file contents unread.
                        expected = metadata.st_mtime_ns > metadata.st_atime_ns
                        for path in (regular, link):
                            check("-N", path, expected)

            def set_whole_seconds(path, *, ns):
                # Exercise rounding even when TMPDIR preserves nanoseconds.
                os.utime(path, ns=tuple(value // second * second for value in ns))

            for name, setter in (("native", os.utime),
                                 ("whole-second", set_whole_seconds)):
                with self.subTest(timestamp_setter=name):
                    check_timestamps(setter)

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

    def test_exact_comparisons(self):
        pairs = (("x", '"x"'), ("x", '"y"'), ("''", '""'),
                 ("'*'", '"*"'), ("x", '"*"'),
                 ("日本", '"日本"'), ("日本", '"日本語"'),
                 ("'-n'", '"-n"'), ("'!'", '"!"'),
                 ("xy", "'x'" + '"y"'),
                 ("x", "$'x\\0tail'"), ("''", "$'\\0tail'"),
                 ("'a b'", '"a b"'), ("'\\'", '"\\\\"'))
        for left, right in pairs:
            for operator in ("=", "==", "!="):
                for negate in ("", "! ", "! ! "):
                    source = f"[[ {negate}{left} {operator} {right} ]]"
                    with self.subTest(source=source):
                        self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                        truth = self.probe_result(source)
                        self.assertIn(truth, (1, 2))
                        self.assertEqual(self.bash_result(source).returncode,
                                         0 if truth == 2 else 1)
        for source in ('[[ x == "x" # $(|)\n]]',
                       '[[ x == "x"\n]]',
                       '[[ x =\\\n= "x" ]]',
                       '[[ x !\\\n= "y" ]]'):
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source).returncode, 0)
                self.assertEqual(self.probe_result(source), 2)
        for source in ('[[ x == ]]', '[[ x != ]]', '[[ x = ]]',
                       '[[ x\n== "x" ]]', '[[ x ==\n"x" ]]',
                       '[[ x == # note\n"x" ]]', '[[ -n == "x" ]]',
                       '[[ x == "$(|)" ]]', '[[ $(|) == "x" ]]'):
            with self.subTest(source=source):
                self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 2)
        for source in ('[[ x == $value ]]', '[[ x == "${value}"* ]]',
                       '[[ x == ? ]]', '[[ x == [xy] ]]',
                       '[[ x == @(x|y) ]]', '[[ x == *(x) ]]',
                       '[[ x == ~/* ]]'):
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 4)
        for source in ('[[ x == ', '[[ x == "', '[[ x == "$(printf x',
                       '[[ x == "x" # $(|)'):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 1)
        # The producer is asynchronous. The subprocess deadline bounds this
        # check without imposing a scheduler-dependent deadline on its read.
        result = self.bash_result(
            '[[ <(printf x) == "$(read -r -u63 -n1 value || exit 1; printf "%s" "$value" >&2)" ]] 2>&1')
        self.assertEqual(result.stdout, b"x")

    def test_mixed_literal_comparisons(self):
        forms = (
            ('"$value".txt', lambda value: value + '.txt'),
            ('release-"$value"', lambda value: 'release-' + value),
            ('pre"$value"post', lambda value: 'pre' + value + 'post'),
            ('"$value""${value:-fallback}".txt',
             lambda value: value + (value or 'fallback') + '.txt'),
            ('"$(printf %s "$value")".txt', lambda value: value + '.txt'),
            ('"$value"\\*.txt', lambda value: value + '*.txt'),
            ('~"$value"', lambda value: '~' + value),
            ('name=prefix:~"$value"', lambda value: 'name=prefix:~' + value),
            ("$'\\0discard'\"$value\".txt", lambda value: value + '.txt'),
        )
        available = subprocess.run(['locale', '-a'], capture_output=True,
                                   text=True, check=True, timeout=10).stdout.splitlines()
        utf8 = next((name for name in available
                     if 'utf8' in name.lower().replace('-', '')), None)
        self.assertIsNotNone(utf8, 'install a UTF-8 locale for Bash conformance')
        for locale in ('C', utf8):
            for word, expanded in forms:
                for value in ('', '日本*?[()]'):
                    right = expanded(value)
                    for left in (right, right + '!'):
                        for operator in ('=', '==', '!='):
                            for negate in ('', '! '):
                                source = f'[[ {negate}"$left" {operator} {word} ]]'
                                with self.subTest(source=source, value=value,
                                                  left=left, locale=locale):
                                    self.assertEqual(self.probe_result(source, '--status'), 0)
                                    resolved = subprocess.run(
                                        [self.probe, '--resolved', source, left, right],
                                        capture_output=True, check=True, timeout=10)
                                    truth = int(resolved.stdout)
                                    expected = ((left == right) != (operator == '!=')) != bool(negate)
                                    self.assertEqual(truth, 2 if expected else 1)
                                    setup = f'left={shlex.quote(left)}; value={shlex.quote(value)}; '
                                    self.assertEqual(self.bash_result(setup + source, locale=locale).returncode,
                                                     0 if expected else 1)
        for word in ('"$value"*', '"$value"?', '"$value"[ab]',
                     '"$value"[', '"$value"@(a|b)', 'pre$value.txt',
                     '"$value"${other}', '"$value"$(printf x)',
                     '"$value"`printf x`', '"$value"<(printf x)',
                     '~/"$value"', 'name=~/"$value"', 'name=~:"$value"'):
            source = f'[[ x == {word} ]]'
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, '--status'), 4)
        for received, completion in (
                ('[[ x == pre"$value', '".txt ]]'),
                ('[[ x == pre"$(printf x', ')".txt ]]'),
                ('[[ x == pre"$value".txt ]', ']')):
            with self.subTest(received=received):
                self.assertEqual(self.probe_result(received, '--status'), 1)
                self.assertEqual(self.probe_result(received + completion, '--status'), 0)
        source = '[[ x == pre"$(|)".txt ]]'
        self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)
        self.assertEqual(self.probe_result(source, '--status'), 2)

    def test_star_patterns(self):
        cases = (
            ('x', 'x', True), ('x', 'y', False),
            ('x', '""x', True), ('x', 'x""', True), ('x', r'\x', True),
            ('file.txt', '*.txt', True), ('file.c', '*.txt', False),
            ('/workspace/a/b', '/workspace/*', True),
            ('temporary-one', '"temporary-"*', True),
            ('abc', 'a*b*c', True), ('abbc', 'a*b*c', True),
            ('ab', 'a*b*c', False), ('a', 'a*a', False),
            ('aa', 'a*a', True), ('aa', '*a*a*', True),
            ('aba', 'a*b*a', True), ("''", '*', True),
            ("''", "**''***", True), ("'.a/b\nc'", '*', True),
            ("'*abc'", r'\**', True), ('abc', r'\**', False),
            ("'a*bc'", "a$'*'*", True), ('x', "$'\\0tail'*", True),
            ("'a?b.txt'", "'a?b'*", True), ("'a[b.txt'", r'a\[*', True),
            ('日本.txt', '日本*', True),
            ("$'\\xc3\\xa9'", "*$'\\xa9'", True),
            ("$'\\xc3\\xa9'", "$'\\xc3'*$'\\xa9'", True),
            ("$'\\xff.txt'", '*.txt', True),
            ("'abc'", "*'\\'", False),
            ("'a\\bc'", "*'\\'*", True),
        )
        available = subprocess.run(['locale', '-a'], capture_output=True,
                                   text=True, check=True, timeout=10).stdout.splitlines()
        utf8 = next((name for name in available
                     if 'utf8' in name.lower().replace('-', '')), None)
        self.assertIsNotNone(utf8, 'install a UTF-8 locale for Bash conformance')
        self.assertEqual(self.bash_result(
            "value=$'\\xc3\\xa9'; [[ ${#value} == 1 ]]", locale=utf8).returncode, 0)
        # Matching must agree without consulting or changing the analyzer's locale.
        for locale in ('C', utf8):
            for left, right, matches in cases:
                for operator in ('=', '==', '!='):
                    for negate in ('', '! '):
                        source = f'[[ {negate}{left} {operator} {right} ]]'
                        with self.subTest(locale=locale, source=source):
                            truth = (matches != (operator == '!=')) != bool(negate)
                            self.assertEqual(self.bash_result(source, locale=locale).returncode,
                                             0 if truth else 1)
                            self.assertEqual(self.probe_result(source), 2 if truth else 1)

    def test_tilde_comparisons(self):
        cases = (
            ("name=~", "name=/model-home", True),
            ("name+=~", "name+=/model-home", True),
            ("name=prefix:~", "name=prefix:/model-home", True),
            ("name='prefix':~", "name=prefix:/model-home", True),
            ("arr[0]=~", "arr[0]=/model-home", True),
            ("arr['0']+=~", "arr[0]+=/model-home", True),
            ("a[:~/x]=~", "a[:/model-home/x]=/model-home", True),
            ("a[=~/x]=~", "a[=/model-home/x]=~", True),
            ("na\\\nme=\\\n~", "name=/model-home", True),
            ("name=prefix:\\\n~", "name=prefix:/model-home", True),
            ("name='~'", "name=~", False),
            ('name="~"', "name=~", False),
            ("name=\\~", "name=~", False),
            ("name=~''", "name=~", False),
            ('name=~""/x', "name=~/x", False),
            ("~''", "~", False),
            ("name\\=~", "name=~", False),
            ("1name=~", "1name=~", False),
            ("name:~", "name:~", False),
            ("name=x=~", "name=x=~", False),
            ("*", "*", False),
            ("{a,b}", "{a,b}", False),
            ("@(a|b)", "@(a|b)", False),
        )
        for word, value, dynamic in cases:
            for operator in ("=", "==", "!="):
                for negate in ("", "! "):
                    source = f"[[ {negate}{word} {operator} '{value}' ]]"
                    with self.subTest(source=source):
                        truth = (operator != "!=") != bool(negate)
                        self.assertEqual(self.bash_result(source).returncode,
                                         0 if truth else 1)
                        self.assertEqual(self.probe_result(source),
                                         0 if dynamic else 2 if truth else 1)

    def test_token_prefixes(self):
        pairs = (
            ('[[ x ]', ']'),
            ('[[ file.txt == *.txt ]', ']'),
            ('[[ file.txt == *\\', '\n.txt ]]'),
            ('[[ file.txt == "file"* # comment\n]', ']'),
            ('[[ x ]\\', '\n]'),
            ('[[ x ]\\\n', ']'),
            ('[[ x \\', '\n]]'),
            ('[[ x ]]\\', '\n;'),
            ('[[ -n x ]', ']'),
            ('[[ -n x ]\\', '\n]'),
            ('[[ -n x ]\\\n', ']'),
            ('[[ -n x \\', '\n]]'),
            ('[[ -n x ]]\\', '\n;'),
            ("[[ -z '' ]", ']'),
            ("[[ -z '' ]\\", '\n]'),
            ("[[ -z '' ]\\\n", ']'),
            ("[[ -z '' \\", '\n]]'),
            ("[[ -z '' ]]\\", '\n;'),
            ('[[ ! x ]', ']'),
            ('[[ ! x ]\\', '\n]'),
            ('[[ ! x ]\\\n', ']'),
            ('[[ ! x \\', '\n]]'),
            ('[[ ! x ]]\\', '\n;'),
            ('[[ x == "x" ]', ']'),
            ('[[ x == "x" ]\\', '\n]'),
            ('[[ x == "x" ]\\\n', ']'),
            ('[[ x == "x" \\', '\n]]'),
            ('[[ x == "x" ]]\\', '\n;'),
            ('[[ ! x != "y" ]', ']'),
            ('[[ ! x != "y" ]\\', '\n]'),
            ('[[ ! x != "y" ]\\\n', ']'),
            ('[[ ! x != "y" \\', '\n]]'),
            ('[[ ! x != "y" ]]\\', '\n;'),
            ('[[ x !', '= "y" ]]'),
            ('[[ x !\\', '\n= "y" ]]'),
            ('[[ x =\\', '\n= "x" ]]'),
            ('[[ x ==\\', '\n "x" ]]'),
            ('[[ x !=\\', '\n "y" ]]'),
            ('[[ x \\', '\n== "x" ]]'),
        )
        for received, completion in pairs:
            with self.subTest(received=received):
                self.assertEqual(self.probe_result(received, "--status"), 1)
                complete = received + completion
                self.assertEqual(self.bash_result(complete, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(complete, "--status"), 0)
                truth = self.probe_result(complete)
                self.assertEqual(self.bash_result(complete).returncode,
                                 0 if truth == 2 else 1)
                if not received.endswith("\\"):
                    for wrapper in ('printf "$(%s)"', 'cat <(%s)'):
                        closed = wrapper % received
                        self.assertNotEqual(self.bash_result(closed, syntax=True).returncode, 0)
                        self.assertEqual(self.probe_result(closed, "--status"), 2)
        for source in ('[[ x ] ]]', '[[ x == "x" ] ]]', '[[ x ]x', '[[ x \\x', '[[ x\n]', '[[ x == "x" "]"'):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 2)
        for source in ('[[ x ! ', '[[ x =~', '[[ x == "x" &&'):
            with self.subTest(source=source):
                self.assertEqual(self.probe_result(source, "--status"), 4)

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
        for source in ("[[ file -nt other ]]", "[[ file -\\\nnt other ]]", "[[ x == ? ]]", "[[ x =~ y ]]",
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
        self.assertEqual(self.probe_result(source, "--status"), 2)
        self.assertEqual(self.probe_result("[[ -\\\nf path ]]", "--status"), 0)

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
