"""Current pickup contracts; historical evidence is preserved, not treated as current."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return (ROOT / path).read_text(encoding="utf-8")


def section(document, title):
    marker = f"## {title}\n"
    if document.count(marker) != 1:
        raise ValueError("Current section must exist exactly once")
    return document.split(marker, 1)[1].split("\n## ", 1)[0]


class CurrentDocumentationTests(unittest.TestCase):
    def test_current_snapshot_precedes_explicit_historical_updates(self):
        status = text("STATUS.md")
        self.assertLess(status.index("## Current Snapshot"), status.index("## Historical Updates"))
        current = section(status, "Current Snapshot")
        self.assertIn("owner-reported", current)
        self.assertIn("docs/current-state-reconciliation.md", current)
        for stale in ("automatic watchdog is not deployed", "visual delivery remains unconfirmed",
                      "blocked-traffic records are not yet collected"):
            self.assertNotIn(stale, current)

    def test_old_results_remain_separately_labeled(self):
        status = text("STATUS.md")
        for title in ("Historical Updates", "October 7 Pickup Sequence (Historical)",
                      "October 7 Milestones (Historical)", "October 6 Hardening Baseline (Historical)"):
            section(status, title)
        self.assertIn("the automatic watchdog is not deployed", section(status, "Historical Updates"))

    def test_missing_or_duplicate_current_heading_is_rejected(self):
        status = text("STATUS.md")
        for changed in (status.replace("## Current Snapshot", "## Old Snapshot"),
                        status + "\n## Current Snapshot\nconflict\n"):
            with self.assertRaises(ValueError):
                section(changed, "Current Snapshot")

    def test_execution_order_keeps_review_ahead_of_tcp_and_wider_capture(self):
        order = section(text("STATUS.md"), "Pickup And Execution Order")
        self.assertLess(order.index("Review the deployed watchdog"), order.index("Complete offline TCP"))
        self.assertLess(order.index("Complete offline TCP"), order.index("Useful routine telemetry"))

    def test_active_runbook_has_current_vm_commands(self):
        runbook = text("SentinelGrid-Build-Runbook.md")
        for command in ("Checkpoint-VM -Name 'Watchtide'", "Stop-VM -Name 'Watchtide'",
                        "Start-VM -Name 'Watchtide'"):
            self.assertIn(command, runbook)
        self.assertNotRegex(runbook, r"(?:-Name|-VMName)\s+['\"]?SentinelGrid-Wazuh")
        self.assertIn("keys-only", runbook)
        self.assertTrue("owner reports deleting all five checkpoints" in runbook.lower(),
                        "Current rollback availability must not inherit old checkpoint proof")

    def test_manual_preview_is_not_described_as_undeployed_runner(self):
        runbook = text("SentinelGrid-Build-Runbook.md")
        self.assertIn("warehouse.collection_watchdog --dry-run", runbook)
        self.assertNotIn("no automatic watchdog/delivery is deployed", runbook)
        self.assertNotIn("visual delivery remains unconfirmed", runbook)

    def test_active_roadmap_points_to_current_snapshot(self):
        current = section(text("ROADMAP.md"), "Current Execution Order")
        self.assertIn("STATUS.md#current-snapshot", current)
        self.assertIn("Review the deployed monitoring", current)
        self.assertNotIn("No monitor task or state-writing/delivery runner is deployed", current)

    def test_reconciliation_preserves_unfinished_evidence_gates(self):
        report = " ".join(text("docs/current-state-reconciliation.md").split())
        for boundary in ("not installed-engine negative validation", "not an administration key",
                         "not continuous Suricata", "No fresh Power BI render",
                         "notification-policy gap", "or that it survived a real reboot"):
            self.assertTrue(boundary in report, f"Missing evidence boundary: {boundary}")

    def test_current_navigation_anchor_targets_exist(self):
        files = ("README.md", "STATUS.md", "ROADMAP.md", "SentinelGrid-Build-Runbook.md",
                 "docs/current-state-reconciliation.md")
        for source in files:
            for target, anchor in re.findall(r"\]\(([^)\s]+\.md)#([^)\s]+)\)", text(source)):
                destination = (ROOT / source).parent / target
                headings = re.findall(r"^#+\s+(.+)$", destination.read_text(encoding="utf-8"), re.MULTILINE)
                anchors = {re.sub(r"[^\w -]", "", h.lower()).replace(" ", "-") for h in headings}
                with self.subTest(source=source, target=target, anchor=anchor):
                    self.assertIn(anchor, anchors)


if __name__ == "__main__":
    unittest.main()
