"""Synthetic inventories and hostile archives; no downloads, SQL or SOC changes."""

import hashlib
import io
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from suricata import review_rule_library as feed
from warehouse import inventory_detection_rules as alerts


def make_archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(payload) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = "/etc/passwd"
            archive.addfile(member, io.BytesIO(payload) if member.isfile() else None)
    return buffer.getvalue()


class AlertInventoryTests(unittest.TestCase):
    def row(self, rule_id=1, count=2, review=None):
        return {"rule_id": rule_id, "alert_count": count, "lowest_observed_level": 3,
                "highest_observed_level": 15, "historical_rule_review": review,
                "historical_report": "triage/history.md" if review else None,
                "description": "Pattern | <private> [link](https://example.test)",
                "rule_groups": "sysmon,windows", "last_alert_utc": "2026-10-07T00:00:00Z"}

    def test_all_types_count_and_historical_verdict_is_not_inherited(self):
        result = alerts.build_inventory([self.row(review="Old benign cluster"), self.row(2)], {"rules": []})
        self.assertEqual(result["summary"]["observed_rule_types"], 2)
        self.assertEqual(result["summary"]["alerts"], 4)
        self.assertEqual(result["summary"]["types_with_historical_review"], 1)
        self.assertTrue(all(r["current_alert_verdict"].startswith("Not adjudicated") for r in result["rules"]))

    def test_catalog_absence_is_not_missing_detection(self):
        result = alerts.build_inventory([self.row()], {"rules": []})
        self.assertIsNone(result["rules"][0]["historical_catalog"])
        self.assertIn("not evidence", result["catalog_limit"])

    def test_catalog_errors_fail_closed(self):
        with self.assertRaises(ValueError):
            alerts.build_inventory([], {"errors": ["bad export"], "rules": []})

    def test_duplicate_observed_id_is_rejected(self):
        with self.assertRaises(ValueError):
            alerts.build_inventory([self.row(), self.row()], {"rules": []})

    def test_nonpositive_counts_are_rejected(self):
        with self.assertRaises(ValueError):
            alerts.build_inventory([self.row(count=0)], {"rules": []})

    def test_level_bands_and_out_of_range(self):
        self.assertEqual([alerts.severity(n) for n in (6, 7, 11, 12, 14, 15)],
                         ["Low", "Medium", "Medium", "High", "High", "Critical"])
        with self.assertRaises(ValueError):
            alerts.severity(16)

    def test_markdown_escapes_private_event_text(self):
        text = alerts.markdown_inventory(alerts.build_inventory([self.row()], {"rules": []}))
        self.assertIn(r"\|", text)
        self.assertIn("&lt;private&gt;", text)
        self.assertNotIn("[link](", text.replace(r"\[", "ESCAPED"))

    def test_private_output_rejects_escape_and_existing_file(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(Path, "home", return_value=Path(temp)):
            folder = Path(temp) / ".watchtide-private"
            folder.mkdir()
            with self.assertRaises(ValueError):
                alerts.private_output(folder / ".." / "public.json")
            file = folder / "existing.json"
            file.touch()
            with self.assertRaises(ValueError):
                alerts.private_output(file)
            self.assertEqual(alerts.private_output(folder / "new.json"), folder / "new.json")


class ArchiveReviewTests(unittest.TestCase):
    def parser(self, none=False):
        def parse(text, group):
            if none:
                return None
            rule = types.SimpleNamespace(id=(1, 100))
            record = {"gid": 1, "sid": 100, "rev": 1, "msg": "test", "action": "alert",
                      "proto": "icmp", "classtype": "misc-activity", "noalert": False,
                      "enabled": not text.lstrip().startswith("#"), "flowbits": []}

            class Rule(dict):
                id = rule.id

            return Rule(record)
        return types.SimpleNamespace(actions=("alert", "drop", "pass"), parse=parse)

    def review(self, entries, parser=None):
        data = make_archive(entries)
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "library.tar.gz"
            file.write_bytes(data)
            return feed.review_archive(file, hashlib.sha256(data).hexdigest(), parser or self.parser())

    def test_disabled_and_deleted_entries_are_not_deployed_counts(self):
        result = self.review([
            ("rules/test.rules", b"alert test\n# alert control\n", tarfile.REGTYPE),
            ("rules/emerging-deleted.rules", b"# alert old\n", tarfile.REGTYPE),
        ])
        self.assertEqual(result["summary"]["parsed_rule_entries"], 3)
        self.assertEqual(result["summary"]["vendor_uncommented_outside_deleted_files"], 1)
        self.assertEqual(result["summary"]["vendor_commented_outside_deleted_files"], 1)
        self.assertFalse(result["rules_deployed"])
        self.assertFalse(result["engine_syntax_tested"])

    def test_filename_drop_does_not_determine_action(self):
        result = self.review([("rules/drop.rules", b"alert test\n", tarfile.REGTYPE)])
        self.assertEqual(result["summary"]["actions_outside_deleted_files"], {"alert": 1})

    def test_duplicate_sid_is_reported_not_silently_deduplicated(self):
        result = self.review([("rules/test.rules", b"alert one\nalert two\n", tarfile.REGTYPE)])
        self.assertEqual(result["summary"]["duplicate_gid_sid_pairs"], 1)
        self.assertEqual(result["summary"]["parsed_rule_entries"], 2)

    def test_link_member_rejected_without_extraction(self):
        with self.assertRaises(ValueError):
            self.review([("rules/link", b"", tarfile.SYMTYPE)])

    def test_traversal_absolute_windows_and_duplicate_names_rejected(self):
        for name in ("../outside.rules", "/etc/test.rules", "C:/test.rules", "rules\\test.rules"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.review([(name, b"alert test\n", tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            self.review([("test.rules", b"", tarfile.REGTYPE)] * 2)

    def test_expansion_and_member_count_limits(self):
        for limit in ("MAX_MEMBER_BYTES", "MAX_TOTAL_BYTES", "MAX_MEMBERS"):
            with patch.object(feed, limit, 0), self.assertRaises(ValueError):
                self.review([("test.rules", b"alert test\n", tarfile.REGTYPE)])

    def test_unparsed_candidate_fails_closed(self):
        with self.assertRaises(ValueError):
            list(feed.parse_statements("alert bad", "test.rules", self.parser(none=True)))

    def test_unfinished_continuation_rejected(self):
        with self.assertRaises(ValueError):
            list(feed.parse_statements("alert test \\", "test.rules", self.parser()))

    def test_oversized_statement_rejected(self):
        with patch.object(feed, "MAX_STATEMENT_BYTES", 2), self.assertRaises(ValueError):
            list(feed.parse_statements("alert test", "test.rules", self.parser()))

    def test_wrong_parser_archive_hash_never_executes(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "bad.tar.gz"
            file.write_bytes(b"unreviewed")
            with patch("builtins.exec") as execute, self.assertRaises(ValueError):
                feed.load_pinned_parser(file)
            execute.assert_not_called()

    def test_wrong_rule_archive_hash_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "rules.tar.gz"
            file.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                feed.verified_bytes(file, "0" * 64)

    def test_empty_library_rejected(self):
        with self.assertRaises(ValueError):
            self.review([("LICENSE", b"license text", tarfile.REGTYPE)])


if __name__ == "__main__":
    unittest.main()
