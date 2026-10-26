"""Qualify scalar presence and builtin test composition against pinned Bash."""

import argparse
import os
import shlex
import subprocess
import tempfile
import unittest


class VariablePresence(unittest.TestCase):
    def bash_result(self, source, locale="C"):
        environment = dict(os.environ, LC_ALL=locale, BASH_ENV="", ENV="")
        for name in ("POSIXLY_CORRECT", "BASH_COMPAT", "BASH_XTRACEFD",
                     "BASHOPTS", "SHELLOPTS", "CONFIG", "A", "B", "C",
                     "FUNCNAME", "GROUPS", "BASH_ARGC", "BASH_ARGV",
                     "BASH_SOURCE", "BASH_LINENO"):
            environment.pop(name, None)
        startup = "readonly LC_ALL POSIXLY_CORRECT BASH_COMPAT BASH_XTRACEFD; "
        return subprocess.run([self.bash, "--noprofile", "--norc", "-p", "-c",
                               startup + source], env=environment,
                              capture_output=True, timeout=10)

    def model(self, source, builtin=False):
        result = subprocess.run([self.probe, "--test" if builtin else "--truth", source],
                                capture_output=True, check=True, timeout=10)
        return int(result.stdout)

    def qualify(self, source, *, builtin=False, known=True, locale="C"):
        with self.subTest(source=source, builtin=builtin, locale=locale):
            expected = 2 if self.bash_result(source, locale).returncode == 0 else 1
            actual = self.model(source, builtin)
            self.assertIn(actual, (1, 2) if known else (0, 1, 2))
            if actual:
                self.assertEqual(actual, expected)

    def test_presence_and_scope(self):
        locales = subprocess.run(["locale", "-a"], capture_output=True, text=True,
                                 check=True, timeout=10).stdout.splitlines()
        utf8 = next((name for name in locales
                     if "utf8" in name.lower().replace("-", "")), None)
        self.assertIsNotNone(utf8, "install a UTF-8 locale for Bash conformance")
        setup = ("unset CONFIG; ", "CONFIG=; ", "CONFIG=value; ",
                 "CONFIG=; unset CONFIG; ", "unset CONFIG; declare CONFIG; ",
                 "unset CONFIG; export CONFIG; ", "export CONFIG=; ",
                 "unset CONFIG; CONFIG= :; ", "CONFIG=; ( unset CONFIG ); ",
                 "unset CONFIG; { CONFIG=; }; ",
                 "CONFIG=; printf '%s' \"$(unset CONFIG)\"; ",
                 "unset CONFIG; printf -v CONFIG %s ''; ")
        for locale in ("C", utf8):
            for before in setup:
                for name in ("CONFIG", "'CON'\"FIG\"", "$'CONFIG\\0discard'"):
                    for negate in ("", "! "):
                        self.qualify(before + f"[[ {negate}-v {name} ]]", locale=locale)
                        self.qualify(before + f"test {negate}-v {name}",
                                     builtin=True, locale=locale)
                        self.qualify(before + f"[ {negate}-v {name} ]",
                                     builtin=True, locale=locale)

    def test_initial_presence(self):
        for name in ("LC_ALL", "UID", "EUID", "PPID", "SHELLOPTS", "BASHOPTS",
                     "POSIXLY_CORRECT", "BASH_COMPAT", "BASH_XTRACEFD"):
            self.qualify(f"[[ -v {name} ]]")
            self.qualify(f"test -v {name}", builtin=True)

    def test_nonassignable_variables(self):
        names = ("FUNCNAME", "GROUPS", "BASH_ARGC", "BASH_ARGV",
                 "BASH_SOURCE", "BASH_LINENO")
        writers = ("{name}=value", "declare {name}=value", "export {name}=value",
                   "printf -v {name} %s value", "printf -v{name} %s value",
                   "printf '%n' {name}", "read -n0 {name}", "getopts a {name} -a")
        for name in names:
            for template in writers:
                write = template.format(name=name)
                self.qualify(f"{write}; [[ -v {name} ]]", known=False)
                # Establish either presence on its feasible branch, then
                # verify that an ignored write does not change the observation.
                self.qualify(f"[[ ! -v {name} ]] && {{ {write}; [[ -v {name} ]]; }}",
                             builtin=True, known=False)
                if name in ("FUNCNAME", "GROUPS"):
                    self.qualify(f"unset {name}; {write}; [[ -v {name} ]]")
            self.qualify(f"{name}=value test -v {name}", builtin=True, known=False)
            self.qualify(f"{name}=value result=$( [[ -v {name} ]] )",
                         builtin=True, known=False)
            self.qualify(f"unset {name}; read -n0 {name}; [[ -v {name} ]]",
                         known=name in ("FUNCNAME", "GROUPS"))
        for mode in ("", "-n0 ", "-t0 "):
            absent = "! " if mode == "-t0 " else ""
            self.qualify("unset first IFS last; "
                         f"read {mode}first FUNCNAME IFS last <<<payload; "
                         f"[[ {absent}-v first ]] && [[ ! -v IFS ]] && [[ ! -v last ]]")
        for source in (
                "unset count; printf -v FUNCNAME '%n' count; [[ -v count ]]",
                "unset output; printf -v output '%n' FUNCNAME; [[ -v output ]]",
                "OPTARG=; getopts a FUNCNAME -a; [[ -v OPTIND ]]",
                "[[ ! -v FUNCNAME ]] && { (unset FUNCNAME); read -n0 FUNCNAME; "
                "[[ -v FUNCNAME ]]; }",
                "[[ ! -v FUNCNAME ]] && { result=$(unset FUNCNAME); "
                "read -n0 FUNCNAME; [[ -v FUNCNAME ]]; }",
                "{ unset FUNCNAME; }; read -n0 FUNCNAME; [[ -v FUNCNAME ]]",
                "unset FUNCNAME; unset FUNCNAME; "
                "FUNCNAME=value result=$( [[ -v FUNCNAME ]] ); [[ -v FUNCNAME ]]",
                "unset FUNCNAME; FUNCNAME=value test -v FUNCNAME && [[ ! -v FUNCNAME ]]",
        ):
            self.qualify(source)
        self.qualify("OPTARG=; getopts a FUNCNAME -a; [[ ! -v OPTARG ]]", known=False)

    def test_recursive_presence_correlations(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (directory, os.path.join(directory, "missing")):
                before = ("unset MODE; "
                          f"test -d {shlex.quote(path)} && MODE=; "
                          "[[ -v MODE ]] || :; ")
                for selection in ("test x", "! test ''", "test '' || :"):
                    for negate in ("", "! "):
                        self.qualify(before + selection + "; "
                                     f"result=$( [[ {negate}-v MODE ]] )",
                                     builtin=True, known=False)

    def test_opaque_unsets_and_ignored_prefixes(self):
        for name in ("FUNCNAME", "GROUPS"):
            for operands in (f'"$target" {name}', f'{name} "$target"',
                             f'"$target" {name} "$target" {name}'):
                self.qualify(f"target=unused; unset -- {operands}; read -n0 {name}; "
                             f"[[ -v {name} ]]")
            self.qualify(f"{name}=value unset {name}; read -n0 {name}; "
                         f"[[ -v {name} ]]")
            self.qualify(f"unset {name}; {name}=value unset {name}; "
                         f"[[ ! -v {name} ]]")
            for target in (name, "unused"):
                self.qualify(f"target={target}; unset \"$target\"; "
                             f"read -n0 {name}; [[ -v {name} ]]", known=False)
                self.qualify(f"target={target}; unset \"$target\"; "
                             f"{name}=value test -v {name}",
                             builtin=True, known=False)
                self.qualify(f"target={target}; unset \"$target\"; "
                             f"result=$(read -n0 {name}); [[ -v {name} ]]",
                             known=False)
            for scope in ("( {name}=value unset {name} )",
                          "result=$({name}=value unset {name})",
                          "{{ {name}=value unset {name}; }}"):
                self.qualify(scope.format(name=name) +
                             f"; read -n0 {name}; [[ -v {name} ]]", known=False)
        for source in (
                'unset CONFIG; CONFIG=value unset "$target" CONFIG; [[ ! -v CONFIG ]]',
                'unset FUNCNAME; FUNCNAME=value unset "$target" FUNCNAME; [[ ! -v FUNCNAME ]]',
                'format=%s; printf -- "$format" value; read -n0 FUNCNAME',
                'target=unused; read -n0 -- "$target"; read -n0 FUNCNAME',
        ):
            self.qualify(source, builtin=True, known=False)
        for target in ("unused", "-f", "-invalid"):
            self.qualify(f"target={target}; unset \"$target\" FUNCNAME; "
                         "read -n0 FUNCNAME; [[ -v FUNCNAME ]]", known=False)

    def test_cd_entry_correlations(self):
        # Existing/missing directories make both branches concrete in Bash;
        # the graph conservatively retains both filesystem-test outcomes.
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing")
            for first in (directory, missing):
                before = ("unset PWD OLDPWD MARK; "
                          f"test -d {shlex.quote(first)} && {{ PWD=; MARK=; }}; ")
                for second in (directory, missing):
                    joined = before + f"test -d {shlex.quote(second)} && PWD=; "
                    for ending in (
                            "cd / && [[ -v OLDPWD ]]",
                            "PWD= cd / && [[ -v OLDPWD ]]",
                            "{ cd / && [[ -v OLDPWD ]]; } && [[ -v OLDPWD ]]",
                            "( cd / && [[ -v OLDPWD ]] ) && [[ -v PWD ]]",
                            "result=$( cd / && [[ -v OLDPWD ]] ) && [[ -v PWD ]]",
                            "cd / && [[ -v MARK ]] && [[ -v OLDPWD ]]",
                            "cd / && [[ ! -v OLDPWD ]] && [[ -v MARK ]]",
                    ):
                        # Compare whole-list status, rather than the truth of
                        # its last condition only on paths which reach it.
                        self.qualify(joined + ending, builtin=True, known=False)
        self.qualify("unset PWD; OLDPWD=; cd '' || [[ -v OLDPWD ]]")

    def test_compound_builtin_grammar(self):
        expressions = (
            "-v A -o -v B", "-v A -a -v B", "! -v A -a -v B",
            "-v A -a -v B -o ! -v A",
            "'(' -v A -o -v B ')' -a ! -v A",
            "'(' '(' -v A ')' ')'", "'(' '!' ')'",
            "'(' '(' -v = x ')' ')'", "'(' ! ')'", "'(' ')'",
            "-v", "'-v' A", "-v = -v", "-v -a x", "! -v",
            "-n -v -a -v B", "-v A -o -n 日本", "-v A -a -z ''",
            "'(' -v A ')' -o '(' -v B -a ! -v C ')'",
            "! '(' -v A -o -v B ')'", "-v A extra", "-v A extra extra",
        )
        for before in ("unset A B C; ", "unset A C; B=; ", "A=; B=; C=; "):
            for expression in expressions:
                self.qualify(before + "test " + expression, builtin=True)
                self.qualify(before + "[ " + expression + " ]", builtin=True)
        for source in ("[", "[ -v A", "[ -v A missing-close", "[ ]", "test"):
            self.qualify(source, builtin=True)

    def test_prefixes_descriptors_and_errors(self):
        for source in (
                "unset CONFIG; CONFIG= test -v CONFIG && [[ ! -v CONFIG ]]",
                "unset CONFIG; CONFIG= builtin test -v CONFIG && [[ ! -v CONFIG ]]",
                "unset CONFIG; CONFIG= export CONFIG; [[ -v CONFIG ]]",
                "exec {fd}>&1 && { exec {fd}>&-; [[ -v fd ]]; }",
                "exec {fd}>&1 && { unset fd; [[ ! -v fd ]]; }",
                "unset CONFIG; CONFIG=; read -n-invalid CONFIG; [[ -v CONFIG ]]",
                "unset PWD OLDPWD; cd / && [[ -v OLDPWD ]]",
                "PWD=; cd / && [[ -v OLDPWD ]]",
                "unset PWD OLDPWD; PWD= cd / && [[ -v OLDPWD ]]",
                "unset A B; A= B=$( [[ -v A ]] ) && [[ -v B ]]",
                "unset A; A= : \"$( [[ -v A ]] )\"; [[ -v A ]]",
                "unset A; read -n0 A; [[ -v A ]]",
                "unset A; read -r A <<<payload; [[ -v A ]]",
                "unset fd; true {fd}>&1 9>&- 1>&9 || [[ -v fd ]]",
                "unset fd; true 9>&- 1>&9 {fd}>&1 || [[ -v fd ]]",
                "unset fd; ( true {fd}>&1 9>&- 1>&9 ); [[ -v fd ]]",
                "unset fd; { true; } {fd}>&1 9>&- 1>&9 || [[ -v fd ]]",
                "[[ -v UID ]]", "unset UID; [[ -v UID ]]",
                "[[ -v LC_ALL ]]", "[[ ! -v POSIXLY_CORRECT ]]",
                "CONFIG=; : \"$( [[ -v CONFIG ]] )\"; [[ -v CONFIG ]]",
                "unset CONFIG; : \"$( [[ -v CONFIG ]] )\"; [[ -v CONFIG ]]",
        ):
            self.qualify(source)
        for source in ("test x -o 1 -eq invalid", "test '' -a 1 -eq invalid"):
            self.assertEqual(self.bash_result(source).returncode, 2)
            self.qualify(source, builtin=True, known=False)
        source = "test x -o -n \"$(printf marker >&2)\""
        self.assertEqual(self.bash_result(source).stderr, b"marker")
        self.qualify(source, builtin=True)
        for target in ("bad-name", "UID"):
            self.qualify(f"OPTARG=sentinel; getopts a {target} -a; "
                         "[[ -v OPTARG ]]", known=False)
        for spec in ("a", "--", "-x"):
            for before in ("unset OPTARG; ", "OPTARG=sentinel; "):
                self.qualify(before + f"spec={shlex.quote(spec)}; "
                             "getopts \"$spec\" OPTARG -a; [[ -v OPTARG ]]",
                             known=False)
            self.qualify(f"unset DEST; spec={shlex.quote(spec)}; "
                         "getopts \"$spec\" DEST -a; [[ -v DEST ]]", known=False)
        self.qualify('unset DEST; getopts "a$spec" DEST -a; [[ -v DEST ]]')

    def test_parenthesized_invocation_argument(self):
        # Bash 5.3.20's posixtest(1) uses invocation-wide argv[1]. The
        # three-argument parenthesis shortcut instead uses the local operand.
        expressions = (
            "'' -o '(' x ')'", "x -a '(' '' ')'",
            "'' -o '(' x ')' -o '(' x ')'",
            "x -a '(' '' ')' -a '(' '' ')'",
            "x -a '(' '' -o '(' '' ')' ')'",
            "'' -o '(' x -a '(' x ')' ')'",
            "'' = '' -a '(' x ')'", "x = x -a '(' '' ')'",
            "'(' '' ')'", "'(' x ')'", "'(' -v ')'",
            "'' -o '(' -v ')'", "x -a '(' '' ')' -a -v CONFIG",
        )
        for expression in expressions:
            for command, close in (("test", ""), ("[", " ]")):
                for pipeline_negate in ("", "! "):
                    for builtin_negate in ("", "! "):
                        self.qualify("CONFIG=; " + pipeline_negate + command + " " +
                                     builtin_negate + expression + close,
                                     builtin=True)

    def test_terminal_operand_grammar(self):
        expressions = (
            "-t", "-t 1", "-t -1", "-t ' +01 '", "-t ''", "-t invalid",
            "-t 9223372036854775807", "-t -9223372036854775808",
            "-t 9223372036854775808", "-t -9223372036854775809",
            "-t -o x", "-t -a ''", "-t -o -v CONFIG", "-t -a -v CONFIG",
            "-t 1 -o -v CONFIG", "-t invalid -o -v CONFIG",
            "x -o -t invalid", "! -t invalid", "'(' -t -o ')'",
            "'(' -t -o -v CONFIG ')'", "! '(' -t -o -v CONFIG ')'",
            "'(' '(' -t invalid ')' ')' -o -v CONFIG",
            "'(' -t -a ')' -o -v CONFIG",
        )
        for before in ("unset CONFIG; ", "CONFIG=; "):
            for expression in expressions:
                for command, close in (("test", ""), ("[", " ]")):
                    self.qualify(before + command + " " + expression + close,
                                 builtin=True, known=False)
        for command, close in (("test", ""), ("[", " ]")):
            source = "CONFIG=; " + command + " -t invalid -o -v CONFIG" + close
            self.assertEqual(self.bash_result(source).returncode, 2)
            self.qualify(source, builtin=True)
            self.qualify("CONFIG=; " + command + " -t -o -v CONFIG" + close,
                         builtin=True)

    def test_parenthesized_admission_errors(self):
        # The builtin's argument error precedes the single-quoted -v operand.
        # Ordinary command substitutions still run while preparing argv.
        errors = (
            "'(' -t -o ')' -o -v 'a[$(printf lookup-%s marker >&2)]'",
            "'(' -t -a ')' -o -v 'a[$(printf lookup-%s marker >&2)]'",
            "! '(' -t -o ')' -a -v 'a[$(printf lookup-%s marker >&2)]'",
            "x -a '(' -t -o ')' -o -v 'a[$(printf lookup-%s marker >&2)]'",
            "'(' '(' -t -o ')' ')' -o -v 'a[$(printf lookup-%s marker >&2)]'",
            "'(' -v 'a[$(printf lookup-%s marker >&2)]' extra ')' -o -v CONFIG",
            "'(' '(' -v 'a[$(printf lookup-%s marker >&2)]' ')' ')'",
            "'(' -t invalid ')' -o -v 'a[$(printf lookup-%s marker >&2)]'",
            "'(' -t -o ')' -o -v \"a[$(printf expansion-%s marker >&2)]\"",
        )
        for expression in errors:
            for command, close in (("test", ""), ("[", " ]")):
                source = "CONFIG=; " + command + " " + expression + close
                with self.subTest(source=source):
                    result = self.bash_result(source)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(b"lookup-marker", result.stderr)
                    self.assertEqual(b"expansion-marker" in result.stderr,
                                     "expansion-%s" in expression)
                    self.qualify(source, builtin=True)
                    self.qualify("! " + command + " " + expression + close,
                                 builtin=True)
        for expression in (
                "'(' -v -o 'a[$(printf lookup-%s marker >&2)]' ')'",
                "'(' ! 'a[$(printf lookup-%s marker >&2)]' ')' -o -v CONFIG",
                "'(' -v CONFIG -a -n x ')'",
                "'(' '(' -v CONFIG ')' -a -n x ')'",
        ):
            for command, close in (("test", ""), ("[", " ]")):
                source = "CONFIG=; " + command + " " + expression + close
                self.assertNotIn(b"lookup-marker", self.bash_result(source).stderr)
                self.qualify(source, builtin=True)

    def test_dynamic_terminal_parenthesized_error(self):
        expression = "-t \"$FD\" '(' -v 'a[$(printf lookup-%s marker >&2)]' extra ')'"
        for command, close in (("test", ""), ("[", " ]")):
            for value in ("1", "invalid", "-a", "-o"):
                source = "FD=" + shlex.quote(value) + "; " + command + " " + expression + close
                with self.subTest(source=source):
                    result = self.bash_result(source)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(b"lookup-marker", result.stderr)
                    self.qualify(source, builtin=True)

    def test_getopts_destination_presence(self):
        outcomes = (("a", "-a"), ("a:", "-a value"), ("a:", "-a ''"),
                    ("a", ""), ("a", "-b"), ("a:", "-a"))
        for silent in (False, True):
            for optstring, arguments in outcomes:
                optstring = (":" if silent else "") + optstring
                for target in ("OPTARG", "'OPT'\"ARG\"", "$'OPTARG'", "DEST"):
                    name = "DEST" if target == "DEST" else "OPTARG"
                    for before in (f"unset {name}; ", f"{name}=sentinel; "):
                        self.qualify(before + f"getopts {shlex.quote(optstring)} "
                                     f"{target} {arguments}; [[ -v {name} ]]",
                                     known=silent or name == "DEST")
        # These non-silent errors clear OPTARG after assigning the aliased
        # destination, unlike normal options and end-of-options.
        for optstring, arguments in (("a", "-b"), ("a:", "-a")):
            source = (f"unset OPTARG; getopts {optstring} OPTARG {arguments}; "
                      "[[ -v OPTARG ]]")
            self.assertEqual(self.bash_result(source).returncode, 1)
        for source in (
                "unset OPTARG; getopts -- :a OPTARG -b; [[ -v OPTARG ]]",
                "unset OPTARG; getopts :a OPT\\\nARG -b; [[ -v OPTARG ]]",
                "unset OPTARG; command builtin getopts :a OPTARG -b; "
                "[[ -v OPTARG ]]",
                "unset OPTARG; OPTARG= getopts :a OPTARG -b; [[ -v OPTARG ]]",
                "unset OPTARG; ( getopts :a OPTARG -b ); [[ -v OPTARG ]]",
                "unset OPTARG; { getopts :a OPTARG -b; }; [[ -v OPTARG ]]",
                "unset OPTARG; getopts -x :a OPTARG; [[ -v OPTARG ]]",
                "OPTARG=; getopts -x :a OPTARG; [[ -v OPTARG ]]",
                "unset OPTARG; getopts :a OPTARG -b 9>&- 0<&9; "
                "[[ -v OPTARG ]]",
        ):
            self.qualify(source)
        for spec in ("", "a", "a:"):
            for marker in ("", "-- "):
                self.qualify(f"unset OPTARG; spec={shlex.quote(spec)}; "
                             f'getopts {marker}":$spec" OPTARG -b; '
                             '[[ -v OPTARG ]]')
        self.qualify('unset OPTARG; getopts "a$spec" OPTARG -b; '
                     '[[ -v OPTARG ]]', known=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", required=True)
    parser.add_argument("--probe", required=True)
    args, remaining = parser.parse_known_args()
    VariablePresence.bash = args.bash
    VariablePresence.probe = args.probe
    unittest.main(argv=[__file__, *remaining])
