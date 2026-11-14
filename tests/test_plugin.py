"""Tests for the security-tiers plugin. Stdlib unittest — no test dependencies."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

MANIFEST = textwrap.dedent(
    """
    version: 1
    settings:
      default_tier: low
      rotate_advice_from: money
      type_passwords_from: money
      one_caution_per_item: true
    tiers:
      throwaway:
        rule: "no fuss at all"
    items:
      - match: ["*OPENROUTER*", "*MY_TEST*"]
        tier: low
        note: "prepaid inference"
      - match: ["*MY_TEST*"]
        tier: throwaway
        note: "one-off"
      - match: ["*KRAKEN*", "*AWS_*"]
        tier: money
        note: "moves money"
      - match: ["id_ed25519*", "*PRIVATE*KEY*"]
        tier: root
        note: "key material"
    """
)


def load_plugin(home: Path):
    os.environ["HERMES_HOME"] = str(home)
    spec = importlib.util.spec_from_file_location(f"st_{home.name}", ROOT / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PluginTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="st-test-"))
        (self.home / "security-tiers.yaml").write_text(MANIFEST, encoding="utf-8")
        self.m = load_plugin(self.home)

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_manifest_path_follows_home(self):
        self.assertEqual(self.m.manifest_path(), self.home / "security-tiers.yaml")

    def test_glob_match(self):
        self.assertEqual(self.m.classify("OPENROUTER_API_KEY")["tier"], "low")
        self.assertEqual(self.m.classify("KRAKEN_API_KEY")["tier"], "money")

    def test_highest_matching_tier_wins(self):
        # MY_TEST matches both a low row and a throwaway row; low outranks throwaway
        result = self.m.classify("MY_TEST_KEY")
        self.assertEqual(result["tier"], "low")

    def test_basename_is_matched_too(self):
        self.assertEqual(self.m.classify("/home/someone/.ssh/id_ed25519")["tier"], "root")

    def test_unmatched_takes_default_tier(self):
        result = self.m.classify("SOMETHING_NOBODY_LISTED")
        self.assertEqual(result["tier"], "low")
        self.assertIsNone(result["matched"])

    def test_default_tier_is_configurable(self):
        text = MANIFEST.replace("default_tier: low", "default_tier: money")
        (self.home / "security-tiers.yaml").write_text(text, encoding="utf-8")
        self.assertEqual(self.m.classify("UNLISTED_THING")["tier"], "money")

    def test_rules_override_and_fall_back(self):
        rules = self.m.rules()
        self.assertEqual(rules["throwaway"], "no fuss at all")  # from the manifest
        self.assertIn("Env or vault", rules["money"])            # built-in default

    def test_section_carries_settings_and_inventory(self):
        text = self.m.render_section()
        self.assertIn("tiered policy", text)
        self.assertIn("advise rotating a credential below `money`", text)
        self.assertIn("KRAKEN", text)
        self.assertLessEqual(len(text), 3900)

    def test_section_empty_without_manifest(self):
        (self.home / "security-tiers.yaml").unlink()
        self.assertEqual(self.m.render_section(), "")

    def test_add_appends_and_preserves_comments(self):
        path = self.home / "security-tiers.yaml"
        path.write_text("# keep me\n" + MANIFEST, encoding="utf-8")
        out = self.m._append_item("DEEPSEEK", "low", "prepaid", None)
        self.assertTrue(out["success"])
        body = path.read_text(encoding="utf-8")
        self.assertIn("# keep me", body)
        self.assertIn("DEEPSEEK", body)
        self.assertTrue(Path(out["backup"]).exists())
        self.assertEqual(self.m.classify("DEEPSEEK_API_KEY")["tier"], "low")

    def test_tool_handler_shapes(self):
        import json

        self.assertTrue(json.loads(self.m._handler({"action": "list"}))["count"] >= 4)
        self.assertEqual(json.loads(self.m._handler(
            {"action": "classify", "item": "AWS_SECRET_ACCESS_KEY"}))["tier"], "money")
        self.assertFalse(json.loads(self.m._handler({"action": "classify"}))["success"])


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="st-setup-"))
        (self.home / ".env").write_text(
            "OPENROUTER_API_KEY=x\nKRAKEN_API_KEY=y\nCF_API_TOKEN=z\nSOME_TEST_KEY=q\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_probe_returns_findings(self):
        import setup

        findings = []
        setup.probe(findings)
        ids = {f["id"] for f in findings}
        self.assertIn("listeners", ids)
        self.assertIn("users", ids)
        self.assertIn(setup.ambient(findings), ("low", "elevated", "high"))

    def test_discovery_finds_env_credentials_without_values(self):
        import setup

        (self.home / ".env").write_text(
            "OPENROUTER_API_KEY=sk-or-v1-SENTINEL\nKRAKEN_API_KEY=k-SENTINEL\n"
            "CF_API_TOKEN=cf-SENTINEL\nSOME_TEST_KEY=test-SENTINEL\n", encoding="utf-8")
        os.environ["HERMES_HOME"] = str(self.home)
        creds = {c["name"]: c for c in setup.discover()}
        self.assertIn("OPENROUTER_API_KEY", creds)
        self.assertEqual(creds["KRAKEN_API_KEY"]["tier"], "money")
        self.assertEqual(creds["CF_API_TOKEN"]["tier"], "root")
        self.assertEqual(creds["SOME_TEST_KEY"]["tier"], "throwaway")
        blob = json.dumps(creds)
        for sentinel in ("sk-or-v1-SENTINEL", "k-SENTINEL", "cf-SENTINEL", "test-SENTINEL"):
            self.assertNotIn(sentinel, blob)

    def test_generated_manifest_loads_in_plugin(self):
        import setup

        os.environ["HERMES_HOME"] = str(self.home)
        findings = []
        setup.probe(findings)
        creds = setup.discover()
        answers = setup.proposed_answers(findings, creds)
        text = setup.render_manifest(answers, findings, creds)
        (self.home / "security-tiers.yaml").write_text(text, encoding="utf-8")

        m = load_plugin(self.home)
        self.assertEqual(m.classify("KRAKEN_API_KEY")["tier"], "money")
        self.assertEqual(m.classify("CF_API_TOKEN")["tier"], "root")
        self.assertEqual(m.classify("id_rsa")["tier"], "root")       # structural rule
        self.assertEqual(m.classify("MY_TEST_KEY")["tier"], "throwaway")
        self.assertGreater(len(m.render_section()), 500)

    def test_answer_mapping(self):
        import setup

        self.assertEqual(setup._SETTINGS_FROM_ANSWER["type_passwords"]["everything"], "none")
        self.assertEqual(setup._SETTINGS_FROM_ANSWER["rotate"]["never"], "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
