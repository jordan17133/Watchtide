"""Project-name contracts; these do not refresh or render Power BI."""

import ast
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PBI = ROOT / "powerbi"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class ReportIdentityTests(unittest.TestCase):
    def test_project_and_model_links_resolve(self):
        project = read(PBI / "Watchtide.pbip")
        report = PBI / project["artifacts"][0]["report"]["path"]
        self.assertEqual(report.name, "Watchtide.Report")
        model = report / read(report / "definition.pbir")["datasetReference"]["byPath"]["path"]
        self.assertEqual(model.resolve(), (PBI / "Watchtide.SemanticModel").resolve())
        self.assertTrue(model.is_dir())

    def test_display_names_and_logical_identities_are_preserved(self):
        for folder, identity in (("Watchtide.Report", "3cb7ab3d-c746-41e3-af01-d53325d4ddfb"),
                                 ("Watchtide.SemanticModel", "b52920c5-a136-42d4-93b2-1efd4870289e")):
            platform = read(PBI / folder / ".platform")
            self.assertEqual(platform["metadata"]["displayName"], "Watchtide")
            self.assertEqual(platform["config"]["logicalId"], identity)

    def test_six_existing_pages_remain(self):
        pages = PBI / "Watchtide.Report/definition/pages"
        order = read(pages / "pages.json")["pageOrder"]
        names = [read(pages / page / "page.json")["displayName"] for page in order]
        self.assertEqual(names, ["SOC Overview", "Endpoint Posture", "ATT&CK Coverage",
                                 "Cases", "Pipeline Health", "Network Detection"])

    def test_database_connection_was_not_implicitly_migrated(self):
        tables = list((PBI / "Watchtide.SemanticModel/definition/tables").glob("*.tmdl"))
        self.assertEqual(len(tables), 18)
        for path in tables:
            self.assertIn('Sql.Database("localhost", "SentinelGridWarehouse")', path.read_text(encoding="utf-8"))

    def test_report_helpers_use_current_paths_without_executing_generators(self):
        for name in ("build_model.py", "build_report.py", "validate_report.py"):
            source = (PBI / "tools" / name).read_text(encoding="utf-8")
            ast.parse(source)
            self.assertNotIn('"SentinelGrid.Report"', source)
            self.assertNotIn('"SentinelGrid.SemanticModel"', source)
            self.assertIn('"Watchtide.', source)


if __name__ == "__main__":
    unittest.main()
