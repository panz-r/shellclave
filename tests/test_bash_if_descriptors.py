"""Qualify the descriptor model of `if` against pinned Bash.

Generated scripts open, close and fail to open descriptors, and read a line
from them, in conditions and in the lists of nested `if`, `elif` and `else`.
A read in a condition decides the branch by whether it found a line. After each script two `cat`
commands read descriptors 3 and 4. When the graph builder models the script,
every file Bash actually reads there must be a file the graph gives that `cat`
a READ edge from. Scripts it declines to model are counted, not judged."""

import argparse
import os
import random
import re
import subprocess
import tempfile
import unittest

FILES = ("fa", "fb", "fc", "fd")
FDS = (3, 4)
# A read in a condition fails at end of file and on a closed descriptor, and
# the branch that runs follows.
FIXED = (
    "exec 3<fa 4<fb; if read -u3 line; then exec 3<fb; else exec 3<fc; fi",
    "exec 3<fa 4<fb; read -u3 line; "
    "if read -u3 line; then exec 3<fb; else exec 3<fc; fi",
    "exec 3<fa 4<fb; exec 4<&-; "
    "if read -u4 line; then exec 3<fb; else exec 3<fc; fi",
    "exec 3<fa 4<fb; read -u3 line; if read -u3 line; then exec 3<fb; "
    "elif read -u4 line; then exec 3<fc; else exec 3<fd; fi",
    "exec 3<fa 4<fb; exec 4<&-; if exec 4<nofile; then :; "
    "else if read -u4 line; then true; else exec 3<fc; fi; fi",
    "exec 3<fa 4<fb; read -u3 line; read -u4 line; "
    "if read -u3 line; then exec 4<fc; elif read -u4 line; then exec 4<fd; "
    "else exec 3<fb; exec 4<fa; fi",
)


class IfDescriptors(unittest.TestCase):
    def simple(self, rng):
        kind, fd, name = rng.random(), rng.choice(FDS), rng.choice(FILES)
        if kind < 0.5:
            return f"exec {fd}<{name}"
        if kind < 0.7:
            return f"exec {fd}<&-"
        if kind < 0.75:
            return f"exec {fd}<nofile{rng.randint(0, 1)}"
        if kind < 0.85:
            return f"read -u{fd} line"
        if kind < 0.9:
            return rng.choice(["exit", "exit 1"])
        if kind < 0.93:
            return f"exec {fd}<{name} &"
        return rng.choice([":", "true", "false"])

    def condition(self, rng):
        kind, fd, name = rng.random(), rng.choice(FDS), rng.choice(FILES)
        if kind < 0.4:
            return f"exec {fd}<{name}"
        if kind < 0.55:
            return f"exec {fd}<nofile"
        if kind < 0.8:
            return f"read -u{fd} line"
        return rng.choice(["true", "false", "[ -e fa ]", "[ -e nofile ]"])

    def lists(self, rng, depth):
        return "; ".join(self.statement(rng, depth + 1)
                         for _ in range(rng.randint(1, 2)))

    def statement(self, rng, depth):
        if depth < 2 and rng.random() < 0.35:
            text = f"if {self.condition(rng)}; then {self.lists(rng, depth)}"
            if rng.random() < 0.4:
                text += (f"; elif {self.condition(rng)}; then "
                         f"{self.lists(rng, depth)}")
            if rng.random() < 0.6:
                text += f"; else {self.lists(rng, depth)}"
            return text + "; fi"
        return self.simple(rng)

    def wrapped(self, rng):
        """A top-level statement, sometimes run in a subshell, a pipeline or
        the background, or with a redirect of its own on its `fi`."""
        text = self.statement(rng, 0)
        kind = rng.random()
        if kind < 0.15:
            return f"( {text} )"
        if kind < 0.25:
            return f"{{ {text}; }} | cat >/dev/null"
        if kind < 0.3:
            return f"( {text} ) &"
        if kind < 0.4 and text.startswith("if "):
            return f"{text} {rng.choice(FDS)}<{rng.choice(FILES)}"
        if kind < 0.45 and text.startswith("if "):
            return f"! {text}"
        return text

    def script(self, rng):
        body = "; ".join(self.wrapped(rng) for _ in range(rng.randint(1, 3)))
        return "exec 3<fa 4<fb; " + body

    def observed(self, source):
        probe = source + ("; for n in 3 4; do if { true <&$n; } 2>/dev/null; "
                          'then echo "fd$n=$(cat <&$n 2>/dev/null)"; '
                          'else echo "fd$n=closed"; fi; done')
        environment = dict(os.environ, LC_ALL="C", BASH_ENV="", ENV="")
        result = subprocess.run([self.bash, "--noprofile", "--norc", "-p",
                                 "-c", probe], capture_output=True, text=True,
                                env=environment, timeout=10, cwd=self.directory)
        seen = {}
        for line in result.stdout.splitlines():
            match = re.match(r"fd(\d)=(.*)", line)
            if match:
                seen[int(match.group(1))] = match.group(2)
        return seen

    def reports(self, sources, directory=None):
        """The probe's report for each source, from one process."""
        command = [self.probe, "--batch"] + ([directory] if directory else [])
        result = subprocess.run(
            command, input=b"".join(source.encode() + b"\0"
                                    for source in sources),
            capture_output=True, timeout=120)
        blocks = result.stdout.decode().split("--\n")[:-1]
        self.assertEqual(len(blocks), len(sources))
        return [block.splitlines() for block in blocks]

    def model(self, lines):
        if not lines or lines[0] != "rc=0":
            return None
        commands, files, reads, required = [], {}, [], []
        for line in lines[1:]:
            parts = line.split()
            if parts[0] == "cmd" and parts[2] == "cat":
                commands.append(int(parts[1]))
            elif parts[0] == "file":
                files[int(parts[1])] = parts[2]
            elif parts[0] == "edge" and parts[3] == "READ":
                reads.append((int(parts[1]), int(parts[2])))
            elif parts[0] == "edge" and parts[-1] == "required":
                required.append(files.get(int(parts[1])))
        # An open the graph requires must succeed for a safe run; a script
        # whose requirement cannot hold here is outside the contract.
        if any(name and name.startswith("nofile") for name in required):
            return None
        return {fd: {files[a] for a, b in reads if b == command and a in files}
                for fd, command in zip(FDS, commands[-2:])}

    def test_cat_reads_are_covered(self):
        rng = random.Random(20260)
        modeled = 0
        with tempfile.TemporaryDirectory() as directory:
            self.directory = directory
            for name in FILES:
                with open(os.path.join(directory, name), "w") as handle:
                    handle.write(name[1:] + "\n")
            sources = FIXED + tuple(self.script(rng)
                                    for _ in range(self.count))
            models = self.reports([source + "; cat <&3; cat <&4"
                                   for source in sources])
            for source, lines in zip(sources, models):
                graph = self.model(lines)
                if graph is None:
                    continue
                modeled += 1
                seen = self.observed(source)
                for fd in FDS:
                    if seen.get(fd) not in (None, "", "closed"):
                        with self.subTest(source=source, fd=fd):
                            self.assertIn("f" + seen[fd], graph[fd])
        self.assertGreater(modeled, self.count // 4)


    def cwd_simple(self, rng, root):
        kind, name = rng.random(), rng.choice(("d1", "d2", "d3"))
        if kind < 0.35:
            return f"cd {root}/{name} || exit"
        if kind < 0.5:
            return f"cd {root}/{name}"
        if kind < 0.6:
            return f"cd {root}/nodir"
        if kind < 0.7:
            return "cd .."
        return rng.choice([":", "true"])

    def cwd_condition(self, rng, root):
        kind, name = rng.random(), rng.choice(("d1", "d2", "d3"))
        if kind < 0.45:
            return f"cd {root}/{name}"
        if kind < 0.7:
            return f"cd {root}/nodir"
        return rng.choice(["true", "false"])

    def cwd_statement(self, rng, root, depth):
        if depth < 2 and rng.random() < 0.4:
            parts = [f"if {self.cwd_condition(rng, root)}; then "
                     + self.cwd_list(rng, root, depth)]
            if rng.random() < 0.4:
                parts.append(f"elif {self.cwd_condition(rng, root)}; then "
                             + self.cwd_list(rng, root, depth))
            if rng.random() < 0.6:
                parts.append("else " + self.cwd_list(rng, root, depth))
            return "; ".join(parts) + "; fi"
        return self.cwd_simple(rng, root)

    def cwd_list(self, rng, root, depth):
        return "; ".join(self.cwd_statement(rng, root, depth + 1)
                         for _ in range(rng.randint(1, 2)))

    def test_known_directory_matches_bash(self):
        # Where the graph knows the working directory of the command after the
        # `if`, Bash is there.
        rng = random.Random(77)
        known = 0
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            for name in ("d1", "d2", "d3"):
                os.mkdir(os.path.join(root, name))
            bodies = ["; ".join(self.cwd_statement(rng, root, 0)
                                for _ in range(rng.randint(1, 3)))
                      for _ in range(self.count // 2)]
            sources = [f"{body}; echo end" for body in bodies]
            for body, source, lines in zip(bodies, sources,
                                           self.reports(sources, root)):
                if not lines or lines[0] != "rc=0":
                    continue
                last = [line.split() for line in lines
                        if line.startswith("cwd ")][-1]
                if last[2] == "unknown":
                    continue
                known += 1
                environment = dict(os.environ, LC_ALL="C", BASH_ENV="", ENV="")
                run = subprocess.run(
                    [self.bash, "--noprofile", "--norc", "-p", "-c",
                     body + "; pwd -P"], capture_output=True, text=True,
                    env=environment, cwd=root, timeout=10)
                lines = run.stdout.splitlines()
                if run.returncode == 0 and lines:
                    with self.subTest(source=source):
                        self.assertEqual(os.path.realpath(last[2]),
                                         os.path.realpath(lines[-1]))
        self.assertGreater(known, 20)

    def test_graph_never_accepts_what_bash_rejects(self):
        # Random strings of the words and operators `if` is built from. Bash
        # reads a list for its syntax before running any of it, `-n` stops
        # there; whatever it rejects the graph builder must not model.
        words = ["if", "then", "elif", "else", "fi", "a", "b", ";", "\n",
                 "&&", "||", "|", "&", "(", ")", "{", "}", "!", "time",
                 "x=1", ">f", "$(", "'", "\""]
        rng = random.Random(11)
        environment = dict(os.environ, LC_ALL="C", BASH_ENV="", ENV="")
        accepted = 0
        sources = [" ".join(rng.choice(words)
                            for _ in range(rng.randint(2, 12)))
                   for _ in range(self.count)]
        for source, lines in zip(sources, self.reports(sources)):
            invalid = subprocess.run(
                [self.bash, "--noprofile", "--norc", "-p", "-n"],
                input=source, capture_output=True, text=True,
                env=environment, timeout=10).returncode != 0
            modeled = lines[0] == "rc=0"
            accepted += modeled
            with self.subTest(source=source):
                self.assertFalse(invalid and modeled)
        self.assertGreater(accepted, 0)

    def status(self, source):
        return self.reports([source])[0][0]

    def test_condition_consumes_the_status_of_a_read(self):
        # A read of a closed descriptor fails. The `if` branches on that, so
        # the graph models it, and Bash takes the `else` list.
        branching = ("exec 3<fa 4<fb; exec 4<&-; "
                     "if read -u4 line; then exec 3<fb; else exec 3<fc; fi")
        self.assertEqual(self.status(branching), "rc=0")
        with tempfile.TemporaryDirectory() as directory:
            self.directory = directory
            for name in FILES:
                with open(os.path.join(directory, name), "w") as handle:
                    handle.write(name[1:] + "\n")
            self.assertEqual(self.observed(branching)[3], "c")
        # Nothing consumes the status of this read: a shell-level failure the
        # graph cannot represent. In a condition only the read that ends the
        # list is the one the `if` branches on.
        for source in (
                "exec 3<fa; exec 4<&-; read -u4 line; exec 3<fc",
                "exec 4<&-; if read -u4 line; true; then :; fi",
                "exec 4<&-; if read -u4 line | cat; then :; fi",
                "exec 4<&-; if { read -u4 line; true; }; then :; fi",
                "exec 4<&-; if :; then read -u4 line; fi"):
            with self.subTest(source=source):
                self.assertNotEqual(self.status(source), "rc=0")
        for source in (
                "exec 4<&-; if read -u4 line; then :; fi",
                "exec 4<&-; if { read -u4 line; }; then :; fi",
                "exec 4<&-; if :; then read -u4 line; fi && :"):
            with self.subTest(source=source):
                self.assertEqual(self.status(source), "rc=0")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bash", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--count", type=int, default=3000)
    args, remaining = parser.parse_known_args()
    IfDescriptors.bash = args.bash
    IfDescriptors.probe = args.probe
    IfDescriptors.count = args.count
    unittest.main(argv=[__file__, *remaining])
