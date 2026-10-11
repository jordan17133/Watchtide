"""Public portfolio copy contracts, not a website deployment or indexing test."""

import json
import unittest
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / "docs/portfolio/watchtide-content.json"


class PortfolioContentTests(unittest.TestCase):
    def setUp(self):
        self.content = json.loads(CONTENT.read_text(encoding="utf-8"))

    def test_identity_and_scope_are_explicit(self):
        self.assertEqual(self.content["schema_version"], 1)
        self.assertEqual(self.content["slug"], "watchtide")
        self.assertEqual(self.content["author"], "Jordan Carven-Bellace")
        self.assertIn("Home lab", self.content["project_type"])
        self.assertIn("AI-assisted", self.content["implementation_context"])
        date.fromisoformat(self.content["content_updated"])

    def test_every_numeric_result_has_a_dated_source_and_qualification(self):
        self.assertEqual(len(self.content["evidence_cards"]), 5)
        for card in self.content["evidence_cards"]:
            with self.subTest(title=card["title"]):
                date.fromisoformat(card["evidence_date"])
                self.assertGreater(len(card["qualification"]), 50)
                path = Path(card["source_path"])
                self.assertFalse(path.is_absolute())
                self.assertNotIn("..", path.parts)
                self.assertTrue((ROOT / path).is_file())

    def test_preview_uses_actual_historical_export_time(self):
        snapshot = json.loads((ROOT / "console/data/snapshot.json").read_text(encoding="utf-8"))
        image = self.content["image"]
        self.assertEqual(image["snapshot_exported_utc"], snapshot["generated_utc"])
        datetime.fromisoformat(image["snapshot_exported_utc"].replace("Z", "+00:00"))
        self.assertIn("historical", image["alt"])
        self.assertEqual((image["width"], image["height"]), (1200, 630))
        self.assertTrue((ROOT / "console/og-image.png").is_file())

    def test_website_destination_is_preparation_not_fake_deployment(self):
        handoff = self.content["destination_handoff"]
        self.assertEqual(handoff["integration_status"], "prepared_only")
        self.assertEqual(handoff["deployment_status"], "not_verified_here")
        self.assertEqual(handoff["indexing_status"], "not_verified_here")
        self.assertEqual(handoff["suggested_route"], "/projects/watchtide")
        self.assertIn("Separate portfolio", handoff["owner"])

    def test_urls_use_only_expected_public_destinations(self):
        allowed = {"github.com", "jordan17133.github.io", "jordan-portfolio-alpha.vercel.app"}
        urls = [*self.content["links"].values(), self.content["image"]["url"],
                self.content["destination_handoff"]["website"]]
        for url in urls:
            parsed = urlparse(url)
            self.assertEqual(parsed.scheme, "https")
            self.assertIn(parsed.hostname, allowed)
            self.assertIsNone(parsed.username)
            self.assertIsNone(parsed.password)
            self.assertFalse(parsed.query)

    def test_article_and_listing_preserve_important_boundaries(self):
        article = (ROOT / "docs/portfolio/watchtide-case-study.md").read_text(encoding="utf-8")
        kit = (ROOT / "docs/portfolio/watchtide-publication-kit.md").read_text(encoding="utf-8")
        for phrase in ("Historical rule reviews do not classify future events",
                       "37,605", "same-instance", "Two benign Sysmon records",
                       "installed-engine validation remains", "AI assistance"):
            self.assertTrue(phrase.lower() in article.lower(), f"Missing article qualification: {phrase}")
        self.assertIn("does not guarantee", kit)
        self.assertIn("No website setting was changed here", kit)
        self.assertIn("developers.google.com/search/docs/", kit)

    def test_snapshot_figures_are_not_declared_current_metrics(self):
        self.assertNotIn("current_metrics", self.content)
        self.assertNotIn("live_metrics", self.content)
        self.assertGreaterEqual(len(self.content["open_gates"]), 6)
        self.assertLessEqual(len(self.content["seo"]["description"]), 170)


if __name__ == "__main__":
    unittest.main()
