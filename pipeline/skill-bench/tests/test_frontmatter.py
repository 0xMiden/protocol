import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from skillbench import frontmatter  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_scalars_booleans_and_body(self):
        meta, body = frontmatter.parse(
            "---\nname: masm-padding\ndescription: \"Use when: padding\"\ndisable-model-invocation: true\n---\n\n# Body\n"
        )
        self.assertEqual(meta, {"name": "masm-padding", "description": "Use when: padding", "disable-model-invocation": True})
        self.assertEqual(body.strip(), "# Body")

    def test_folded_block_scalar(self):
        meta, _ = frontmatter.parse("---\ndescription: >\n  first line\n  second line\nname: x\n---\n")
        self.assertEqual(meta["description"], "first line second line")
        self.assertEqual(meta["name"], "x")

    def test_lists(self):
        meta, _ = frontmatter.parse("---\ntools: [Read, Grep]\nskills:\n  - one\n  - two\n---\n")
        self.assertEqual(meta["tools"], ["Read", "Grep"])
        self.assertEqual(meta["skills"], ["one", "two"])

    def test_no_frontmatter(self):
        self.assertEqual(frontmatter.parse("# just a doc\n"), ({}, "# just a doc\n"))

    def test_unterminated_frontmatter_is_treated_as_body(self):
        text = "---\nname: x\n"
        self.assertEqual(frontmatter.parse(text), ({}, text))


class AsListTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(frontmatter.as_list("Read, Grep , Glob"), ["Read", "Grep", "Glob"])
        self.assertEqual(frontmatter.as_list(["Read", " Bash "]), ["Read", "Bash"])
        self.assertEqual(frontmatter.as_list(None), [])


if __name__ == "__main__":
    unittest.main()
