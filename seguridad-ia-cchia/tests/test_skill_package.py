from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))


class SkillPackageTests(unittest.TestCase):
    def test_skill_frontmatter_is_minimal_and_discoverable(self):
        text = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        _, frontmatter, _ = text.split("---", 2)
        metadata = yaml.safe_load(frontmatter)
        self.assertEqual({"name", "description"}, set(metadata))
        self.assertEqual("seguridad-ia-cchia", metadata["name"])
        self.assertIn("CCHIA Checks", metadata["description"])

    def test_openai_interface_references_the_skill(self):
        interface = yaml.safe_load(
            (SKILL_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )["interface"]
        self.assertIn("$seguridad-ia-cchia", interface["default_prompt"])
        self.assertGreaterEqual(len(interface["short_description"]), 25)
        self.assertLessEqual(len(interface["short_description"]), 64)

    def test_all_json_schemas_are_parseable_and_versioned(self):
        schemas = list((SKILL_ROOT / "schemas").glob("*.json"))
        self.assertGreaterEqual(len(schemas), 5)
        for path in schemas:
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", value["$schema"])
            self.assertIn("$id", value)
            self.assertIn("title", value)
            Draft202012Validator.check_schema(value)


if __name__ == "__main__":
    unittest.main()
