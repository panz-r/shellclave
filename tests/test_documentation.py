"""Keep the public getting-started path executable and locally navigable."""

import argparse
import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "shellsplit/README.md",
    *sorted((ROOT / "docs").glob("*.md")),
]


def prose(document):
    return re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", document,
                  flags=re.MULTILINE | re.DOTALL)


def anchors(document):
    result = set()
    duplicates = {}
    for title in re.findall(r"^#{1,6}\s+(.+)$", prose(document), re.MULTILINE):
        title = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = duplicates.get(title, 0)
        duplicates[title] = count + 1
        result.add(title if count == 0 else "{}-{}".format(title, count))
    return result


class DocumentationContract(unittest.TestCase):
    def test_migration_redirect_spellings(self):
        migration = (ROOT / "docs/migration.md").read_text(encoding="utf-8")
        examples = set(re.findall(r"`([^`\n]+)`", migration))
        # Markdown code spans preserve backslashes rather than decoding
        # Unicode escapes. These examples must contain literal shell operators.
        for suffix in ("x", ""):
            with self.subTest(suffix=suffix):
                self.assertIn(">>&" + suffix, examples)
                self.assertNotIn(r">>\u0026" + suffix, examples)

    def test_readme_contains_compiled_excerpt(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = "<!-- gate-example:start -->\n```c\n"
        end = "```\n<!-- gate-example:end -->"
        self.assertEqual(readme.count(start), 1)
        self.assertEqual(readme.count(end), 1)
        block = readme.split(start, 1)[1].split(end, 1)[0]
        source = (ROOT / "examples/gate_policy.c").read_text(encoding="utf-8")
        source_start = "/* gate-example:start */\n"
        source_end = "/* gate-example:end */"
        self.assertEqual(source.count(source_start), 1)
        self.assertEqual(source.count(source_end), 1)
        self.assertEqual(block, source.split(source_start, 1)[1].split(
            source_end, 1)[0])

    def test_complete_example_output(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        sample = re.search(r"Example output:\n\n```text\n(.*?)\n```",
                           readme, re.DOTALL)
        self.assertIsNotNone(sample)
        output = subprocess.run([str(self.example)], check=True, text=True,
                                capture_output=True, timeout=10).stdout.splitlines()
        self.assertEqual(sample.group(1).splitlines(), output)

    def test_source_example_output(self):
        output = subprocess.run([str(self.source_example)], check=True, text=True,
                                capture_output=True, timeout=10).stdout.splitlines()
        expected = [
            "ordinary: analysis available; application authorization required",
            "malformed heredoc: syntax error; reject before dispatch",
            "quoted text: analysis available; application authorization required",
            "unquoted text: analysis available; application authorization required",
            "ANSI-C text: analysis available; application authorization required",
            "unsupported code bytes: explicit exact-source approval required",
            "unsupported grammar: explicit exact-source approval required",
            "unsupported semantics: explicit exact-source approval required",
            "unfinished document: incomplete input; request completion",
            "NUL input: invalid input representation; reject before dispatch",
        ]
        self.assertEqual(output, expected)

    def test_table_columns(self):
        for document in DOCUMENTS:
            width = None
            for number, line in enumerate(prose(document.read_text(
                    encoding="utf-8")).splitlines(), 1):
                if not line.startswith("|"):
                    width = None
                    continue
                # GFM table separators apply inside code spans too.
                columns = len(re.split(r"(?<!\\)\|", line)) - 2
                with self.subTest(document=str(document.relative_to(ROOT)),
                                  line=number):
                    self.assertTrue(line.endswith("|"))
                    if width is None:
                        width = columns
                    self.assertEqual(columns, width,
                                     "escape literal | characters in table cells")

    def test_local_links(self):
        for document in DOCUMENTS:
            for link in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)",
                                   prose(document.read_text(encoding="utf-8"))):
                with self.subTest(document=str(document.relative_to(ROOT)),
                                  link=link):
                    target = urlsplit(link)
                    if target.scheme or target.netloc:
                        continue
                    path = (document.parent / unquote(target.path)).resolve()
                    self.assertTrue(path.exists(), "missing target: {}".format(path))
                    if target.fragment and path.suffix == ".md":
                        self.assertIn(unquote(target.fragment), anchors(
                            path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--example", type=Path, required=True)
    parser.add_argument("--source-example", type=Path, required=True)
    arguments, remaining = parser.parse_known_args()
    DocumentationContract.example = arguments.example.resolve()
    DocumentationContract.source_example = arguments.source_example.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
