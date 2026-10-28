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

    def test_numeric_predicates(self):
        pairs = (("2", "2"), ("-2", "1"), ("010", "8"),
                 ("2#10", "2"), ("'2 + 3'", "5"), ("''", "0"),
                 ("' +10 '", "10"), ("7", "3"), ("$((2+3))", "5"),
                 ("1$((2))", "12"), ("'~+0'", "-1"), ("~+0''", "-1"))
        # Operand decoding is shared by the six comparisons. Qualify every
        # spelling with equality, then every operator/negation on <, = and >.
        comparisons = [(left, right, "-eq", "") for left, right in pairs]
        comparisons.extend(
            (left, right, operator, negate)
            for left, right in (("-2", "1"), ("-2", "-2"), ("1", "-2"))
            for operator in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge")
            for negate in ("", "! "))
        for left, right, operator, negate in comparisons:
            source = f"[[ {negate}{left} {operator} {right} ]]"
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                truth = self.probe_result(source)
                self.assertIn(truth, (1, 2))
                self.assertEqual(self.bash_result(source).returncode,
                                 0 if truth == 2 else 1)
        for operand in ("-1", "2147483648", "invalid", "''"):
            for negate in ("", "! "):
                source = f"[[ {negate}-t {operand} ]]"
                with self.subTest(source=source):
                    truth = self.probe_result(source)
                    status = self.bash_result(source).returncode
                    self.assertEqual(status == 0, truth == 2)
        for operand in ("count", '\"$count\"'):
            self.assertEqual(self.probe_result(f"[[ {operand} -gt 0 ]]"), 0)

    def test_numeric_tilde_expansion(self):
        for word in ("~+0", "~-0", "~+0/$((1))"):
            source = f"[[ {word} -eq -1 ]]"
            self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
            self.assertNotEqual(self.bash_result(source).returncode, 0)
            self.assertEqual(self.probe_result(source), 0)
        self.assertEqual(self.bash_result("HOME=3; [[ ~ -eq 3 ]]").returncode, 0)

    def test_numeric_mutation_boundary(self):
        mutations = (
            ("++count", 6), ("--count", 4), ("'++ count'", 6),
            ("'count ++'", 6), ("'0&&++count'", 5),
            ("'1||count--'", 5), ("'0?++count:1'", 5),
            ("'+'+count", 6), ("+\\\n+count", 6),
        )
        for operand, final in mutations:
            source = f"[[ {operand} -eq 0 ]]"
            with self.subTest(source=source):
                result = self.bash_result(
                    "count=5; " + source + "; printf '%s' \"$count\"")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b'')
                self.assertEqual(result.stdout, str(final).encode())
                self.assertEqual(self.probe_result(source, "--status"), 0)
                rejected = subprocess.run([self.probe, "--truth", source],
                                          capture_output=True, timeout=10)
                self.assertEqual(rejected.returncode, 1)
        for operand in ("++2", "--2", "'1--2'", "'1++2'", "'0&&count'",
                        "'1||count'"):
            source = f"[[ {operand} -eq 2 ]]"
            with self.subTest(pure=source):
                truth = self.probe_result(source)
                self.assertEqual(self.bash_result(source).returncode,
                                 0 if truth == 2 else 1)
        for operand in ("'count + +1'", "'- -count'", "'--(count)'",
                        "'++(count)'"):
            source = f"[[ {operand} -eq 5 ]]"
            with self.subTest(scalar=source):
                result = self.bash_result(
                    "count=5; " + source + "; printf '%s' \"$count\"")
                self.assertEqual(result.stderr, b'')
                self.assertEqual(result.stdout, b'5')
                self.assertEqual(self.probe_result(source), 0)

    def test_nested_pattern_default_reexpansion(self):
        for fallback, expected in ((3, 0), (4, 1)):
            source = ("unset u; v=3; fallback=" + str(fallback) +
                      '; [[ "${v#${u:-$\'$fallback\'}}" -eq 0 ]]')
            self.assertEqual(self.bash_result(source).returncode, expected)

    def test_builtin_arguments_precede_failed_redirection(self):
        for command in ('test "${count:?expanded-before-setup}" -eq 0',
                        '[ "${count:?expanded-before-setup}" -eq 0 ]'):
            result = self.bash_result('unset count; ' + command + ' 1>&- 2>&1')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'expanded-before-setup', result.stderr)
            self.assertNotIn(b'Bad file descriptor', result.stderr)

    def test_parameter_operand_quote_context(self):
        cases = (
            ('"${1:-$fallback}"', '3'),
            ('"${1:-\'$fallback\'}"', "'3'"),
            ("${1:-'$fallback'}", '$fallback'),
            ('"${10:-$fallback}"', '3'),
        )
        for word, expected in cases:
            with self.subTest(word=word):
                result = self.bash_result("fallback=3; set --; printf '%s' " + word)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.decode(), expected)
        result = self.bash_result(
            "fallback=3; set -- '$fallbackx'; printf '%s' \"${1#'$fallback'}\"")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'x')

    def test_builtin_integer_comparison_reference(self):
        pairs = (("2", "2"), ("-2", "1"), ("010", "10"),
                 ("' +10 '", "10"), ("9223372036854775807", "0"),
                 ("-9223372036854775808", "0"),
                 ("9223372036854775808", "0"), ("''", "0"),
                 ("invalid", "1"), ("2#10", "2"))
        for left, right in pairs:
            for operator in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
                for form in (f"test {left} {operator} {right}",
                             f"[ {left} {operator} {right} ]"):
                    with self.subTest(source=form):
                        status = self.bash_result(form).returncode
                        self.assertIn(status, (0, 1, 2))
                        # Observe the builtin's continuation through the public
                        # graph's scalar-presence facts, without running source.
                        source = ("unset __shellclave_numeric_result; { " + form +
                                  "; } && __shellclave_numeric_result=; "
                                  "[[ -v __shellclave_numeric_result ]]")
                        self.assertEqual(self.probe_result(source),
                                         2 if status == 0 else 1)

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

    def test_comparison_operand_expansion_contexts(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("item*", "item-one", "unit?", "unita", "tag[ab]", "taga",
                         "{left,right}", "left", "right"):
                with open(os.path.join(directory, name), "w", encoding="ascii"):
                    pass
            prefix = "cd " + shlex.quote(directory) + "; "
            for word, builtin_status in (("item*", 2), ("unit?", 2), ("tag[ab]", 1),
                                         ("{left,right}", 2)):
                quoted = shlex.quote(word)
                forms = ((f"[[ {word} -ef {quoted} ]]", 0),
                         (f"test {word} -ef {quoted}", builtin_status),
                         (f"[ {word} -ef {quoted} ]", builtin_status),
                         (f"test {quoted} -ef {quoted}", 0),
                         (f"[ {quoted} -ef {quoted} ]", 0))
                for source, expected in forms:
                    with self.subTest(source=source):
                        self.assertEqual(self.bash_result(prefix + source).returncode, expected)
                        self.assertEqual(self.probe_result(source, "--status"), 0)

    def test_binary_filesystem_reference(self):
        # Qualify Bash's comparisons, including its asymmetric treatment of
        # missing files.
        with tempfile.TemporaryDirectory() as directory:
            first = os.path.join(directory, "first")
            second = os.path.join(directory, "second")
            link = os.path.join(directory, "link")
            hardlink = os.path.join(directory, "hardlink")
            dangling = os.path.join(directory, "dangling")
            missing = os.path.join(directory, "missing")
            for path in (first, second):
                with open(path, "w", encoding="ascii"):
                    pass
            os.symlink(first, link)
            os.link(first, hardlink)
            os.symlink(missing, dangling)
            os.utime(first, ns=(1_700_000_000_000_000_000,) * 2)
            os.utime(second, ns=(1_700_000_002_000_000_000,) * 2)
            first_time = os.stat(first).st_mtime_ns
            second_time = os.stat(second).st_mtime_ns
            cases = ((first, second, first_time > second_time,
                      first_time < second_time, False),
                     (first, link, False, False, True),
                     (first, hardlink, False, False, True),
                     (first, dangling, True, False, False),
                     (dangling, first, False, True, False),
                     (first, missing, True, False, False),
                     (missing, first, False, True, False),
                     (missing, missing, False, False, False))
            for left, right, newer, older, same in cases:
                for op, expected in (("-nt", newer), ("-ot", older),
                                     ("-ef", same)):
                    expression = f"{shlex.quote(left)} {op} {shlex.quote(right)}"
                    for source in (f"[[ {expression} ]]", f"test {expression}",
                                   f"[ {expression} ]"):
                        with self.subTest(source=source):
                            self.assertEqual(self.bash_result(source).returncode,
                                             0 if expected else 1)
                    self.assertEqual(self.probe_result(f"[[ {expression} ]]"), 0)

    def test_compound_conditional_reference(self):
        cases = (("[[ -n x || -n $(printf unexpected >&2) ]]", 0, b""),
                 ("[[ -z x && -n $(printf unexpected >&2) ]]", 1, b""),
                 ("[[ -n x && -n $(printf reached >&2; printf x) ]]", 0, b"reached"),
                 ("[[ -z x || -n $(printf reached >&2; printf x) ]]", 0, b"reached"),
                 ("[[ -n x || -z x && -z x ]]", 0, b""),
                 ("[[ ( -n x || -z x ) && -z x ]]", 1, b""),
                 ("[[ ! ( -n x && -z x ) ]]", 0, b""),
                 # Builtin arguments are expanded before test's expression
                 # grammar is evaluated, unlike [['s conditional operands.
                 ("test -z x -a -n $(printf reached >&2; printf x)", 1, b"reached"),
                 ("[ -n x -o -n $(printf reached >&2; printf x) ]", 0, b"reached"))
        for source, status, stderr in cases:
            with self.subTest(source=source):
                result = self.bash_result(source)
                self.assertEqual((result.returncode, result.stderr), (status, stderr))
                if source.startswith("[["):
                    expected = 0 if stderr else 2 if status == 0 else 1
                    self.assertEqual(self.probe_result(source), expected)
        # Shell grammar is checked even where evaluation would short-circuit.
        for source in ("[[ -n x || ( -n ) ]]", "[[ -z x && ( -n ) ]]"):
            with self.subTest(source=source):
                self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)

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

    def test_compound_descriptor_order(self):
        with tempfile.TemporaryDirectory() as directory:
            present = os.path.join(directory, "present")
            with open(present, "w", encoding="ascii"):
                pass
            for exists, path in ((True, present),
                                 (False, os.path.join(directory, "absent"))):
                predicate = f"-e {shlex.quote(path)}"
                prefixes = (
                    (f'{predicate} && -n "$(printf x)"', exists),
                    (f'! ( {predicate} && -n "$(printf x)" )', not exists),
                    (f'{predicate} && ( {predicate} && -n "$(printf x)" )', exists),
                    (f'{predicate} && ( -z x && -n "$(printf skipped)" )', False),
                    (f'{predicate} && ( -n x || -n "$(printf skipped)" )', exists),
                )
                for prefix, truth in prefixes:
                    # Reserve fd 63 for a here-string and leave fd 62 for the
                    # process substitution. The surrounding subprocess deadline
                    # bounds the asynchronous producer without timing the read.
                    source = (
                        'exec 63<<<seed 62<&-; '
                        f'[[ ( {prefix} ) || '
                        '-n "$(read -r -u63 -n1 before; printf \'%s\' "$before" >&2)"'
                        '<(printf pipe)'
                        '"$(read -r -u62 -n1 after; printf \'%s\' "$after" >&2)" ]] 2>&1')
                    with self.subTest(source=source):
                        result = self.bash_result(source)
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(result.stderr, b"")
                        self.assertEqual(result.stdout, b"" if truth else b"sp")
                        self.assertEqual(self.probe_result(source, "--status"), 0)

    def test_compound_literal_truth(self):
        primaries = ("-n x", "-z x", "-n ''", "! -n ''", "x == 'x'",
                     "a.txt == *.txt", "'' -nt target", "target -ot ''",
                     "'' -ef target", "'&&'", "'('", "!(x)")
        for left in primaries:
            for right in primaries:
                for op in ("&&", "||"):
                    source = f"[[ ( {left} ) {op} ( {right} ) ]]"
                    with self.subTest(source=source):
                        reference = self.bash_result(source)
                        self.assertIn(reference.returncode, (0, 1))
                        self.assertEqual(self.probe_result(source),
                                         2 if reference.returncode == 0 else 1)

    def test_compound_operator_prefixes(self):
        for left in ("x", "-n x", "(x)", "( -n x && -z '' )"):
            for received_op, suffix in (("&", "& y ]]"), ("|", "| y ]]"),
                                        ("&\\", "\n& y ]]"), ("|\\", "\n| y ]]"),
                                        ("&\\\n", "& y ]]"), ("|\\\n", "| y ]]")):
                received = f"[[ {left} {received_op}"
                with self.subTest(received=received):
                    self.assertEqual(self.probe_result(received, "--status"), 1)
                    if not received.endswith("\\"):
                        for wrapper in ('printf "$(%s)"', 'cat <(%s)'):
                            closed = wrapper % received
                            self.assertNotEqual(self.bash_result(closed, syntax=True).returncode, 0)
                            self.assertEqual(self.probe_result(closed, "--status"), 2)
                    complete = received + suffix
                    reference = self.bash_result(complete)
                    self.assertIn(reference.returncode, (0, 1))
                    self.assertEqual(self.probe_result(complete),
                                     2 if reference.returncode == 0 else 1)
            for op in ("&", "|", "&=", "|&"):
                source = f"[[ {left} {op} y ]]"
                with self.subTest(committed=source):
                    self.assertNotEqual(self.bash_result(source, syntax=True).returncode, 0)
                    self.assertEqual(self.probe_result(source, "--status"), 2)

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
        # Cover each fragment form with empty/nonempty values and both match
        # outcomes. Operator aliases and negation compose with a representative
        # mixed operand; they do not need a Cartesian product with every form.
        comparisons = [(word, expanded, '==', '') for word, expanded in forms]
        word, expanded = forms[2]
        comparisons.extend(
            (word, expanded, operator, negate)
            for operator in ('=', '==', '!=')
            for negate in ('', '! ', '! ! ')
            if (operator, negate) != ('==', ''))
        for word, expanded, operator, negate in comparisons:
            source = f'[[ {negate}"$left" {operator} {word} ]]'
            with self.subTest(source=source):
                # Source framing is independent of callback values and locale.
                self.assertEqual(self.probe_result(source, '--status'), 0)
            for value in ('', '日本*?[()]'):
                right = expanded(value)
                for left in (right, right + '!'):
                    with self.subTest(source=source, value=value, left=left):
                        resolved = subprocess.run(
                            [self.probe, '--resolved', source, left, right],
                            capture_output=True, check=True, timeout=10)
                        truth = int(resolved.stdout)
                        expected = ((left == right) != (operator == '!=')) != (negate == '! ')
                        self.assertEqual(truth, 2 if expected else 1)
                        setup = f'left={shlex.quote(left)}; value={shlex.quote(value)}; '
                        for locale in ('C', utf8):
                            with self.subTest(locale=locale):
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
        # Pattern decoding/matching has one implementation for all aliases.
        # Keep every pattern and byte-boundary case in both reference locales;
        # exercise aliases and negation on matching and nonmatching suffixes.
        comparisons = [(left, right, matches, '==', '')
                       for left, right, matches in cases]
        comparisons.extend(
            (left, '*.txt', matches, operator, negate)
            for left, matches in (('file.txt', True), ('file.c', False))
            for operator in ('=', '==', '!=')
            for negate in ('', '! ')
            if (operator, negate) != ('==', ''))
        for left, right, matches, operator, negate in comparisons:
            source = f'[[ {negate}{left} {operator} {right} ]]'
            with self.subTest(source=source):
                truth = (matches != (operator == '!=')) != bool(negate)
                # The probe does not receive the reference shell's locale.
                self.assertEqual(self.probe_result(source), 2 if truth else 1)
                for locale in ('C', utf8):
                    with self.subTest(locale=locale):
                        self.assertEqual(self.bash_result(source, locale=locale).returncode,
                                         0 if truth else 1)

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

    def test_grouped_draft_prefixes(self):
        pairs = (
            ('[[ ( -n value )', ' ]]'),
            ('[[ ! ( -n value', ' ) ]]'),
            ('[[ ! ( ! ( left -nt right )', ' ) ]]'),
            ('[[ ! ( -n value ) ]', ']'),
            ('[[ ! ( ! ( -n "value', '" ) ) ]]'),
            ('[[ ! ( -n "$(printf child', ')" ) ]]'),
        )
        for received, completion in pairs:
            with self.subTest(received=received):
                self.assertEqual(self.probe_result(received, "--status"), 1)
                complete = received + completion
                self.assertEqual(self.bash_result(complete, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(complete, "--status"), 0)
                reference = self.bash_result(complete)
                self.assertIn(reference.returncode, (0, 1))
                truth = self.probe_result(complete)
                if truth:
                    self.assertEqual(reference.returncode, 0 if truth == 2 else 1)

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
        self.assertEqual(self.probe_result('[[ x ! ', "--status"), 2)
        self.assertEqual(self.probe_result('[[ x =~', "--status"), 4)

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
        for source in ("[[ x == ? ]]", "[[ x =~ y ]]", "[[ x < y ]]"):
            with self.subTest(source=source):
                self.assertEqual(self.bash_result(source, syntax=True).returncode, 0)
                self.assertEqual(self.probe_result(source, "--status"), 4)

    def test_binary_operator_word_boundaries(self):
        # A process-substitution fragment concatenates with the operator's
        # spelling. Only a standalone lexical word can select the comparison.
        for operator in ("=", "==", "!=", "-nt", "-ot", "-ef"):
            continued = "\\\n".join(operator)
            for spelling in (operator, continued, operator + "\\\n"):
                for fragment in ("<(printf child)", ">(printf child)",
                                 "<\\\n(printf child)"):
                    expression = f"left {spelling}{fragment}"
                    for wrapper in ("[[ %s ]]", "[[ x || ( %s ) ]]",
                                    'printf "$([[ %s ]])"', "cat <([[ %s ]])"):
                        wrapped = wrapper % expression
                        with self.subTest(source=wrapped):
                            self.assertTrue(self.bash_result(wrapped, syntax=True).stderr)
                            self.assertEqual(self.probe_result(wrapped, "--status"), 2)
                    separated = f"[[ left {spelling} {fragment} ]]"
                    with self.subTest(separated=separated):
                        self.assertFalse(self.bash_result(separated, syntax=True).stderr)
                        # Dynamic unquoted string-pattern RHSs remain outside
                        # the supported subset; filesystem operands admit them.
                        expected = 0 if operator.startswith("-") else 4
                        self.assertEqual(self.probe_result(separated, "--status"), expected)
        for source in ("[[ left -nt<(printf child", "[[ left ==>(printf child"):
            with self.subTest(unfinished=source):
                self.assertEqual(self.probe_result(source, "--status"), 2)

    def test_misplaced_supported_operators(self):
        for primary in ("x", "-n x", "x -nt y", "x == y"):
            for operator in ("=", "==", "!=", "-nt", "-ot", "-ef", "-n", "-z",
                             "-v", "-e", "-a", "-h", "-N", "!", "("):
                # A bare word can consume a binary operator as its primary.
                if primary == "x" and operator in ("=", "==", "!=", "-nt", "-ot", "-ef"):
                    continue
                source = f"[[ {primary} {operator} z ]]"
                with self.subTest(source=source):
                    reference = self.bash_result(source, syntax=True)
                    # Bash can diagnose malformed [[ grammar while returning
                    # zero from -n. The diagnostic establishes rejection.
                    self.assertTrue(reference.stderr)
                    self.assertEqual(self.probe_result(source, "--status"), 2)
        for source in ("[[ x -nt y -o\\\nt z ]]", "[[ -n x =\\\n= y ]]",
                       "[[ x !\\\n y ]]", "[[ x '-nt' y ]]",
                       "[[ -n x '==' y ]]", "[[ ( x -nt y -ot z ) ]]",
                       "[[ x && -n x == y ]]"):
            for wrapper in ("%s", "{ %s; }", 'printf "$(%s)"', "cat <(%s)"):
                wrapped = wrapper % source
                with self.subTest(source=wrapped):
                    self.assertTrue(self.bash_result(wrapped, syntax=True).stderr)
                    self.assertEqual(self.probe_result(wrapped, "--status"), 2)
        for source in ("[[ x =~ y ]]", "[[ x < y ]]", "[[ x > y ]]"):
            with self.subTest(unsupported=source):
                reference = self.bash_result(source, syntax=True)
                self.assertEqual(reference.returncode, 0)
                self.assertFalse(reference.stderr)
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
