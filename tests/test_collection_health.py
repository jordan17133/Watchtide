"""Synthetic collection checks; no live database, schedule or notification."""

import copy
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from warehouse import check_collection_health as health


NOW = datetime(2026, 10, 7, 22, 30)


def snapshot():
    return {"as_of_utc": NOW, "last_success_utc": NOW - timedelta(minutes=5),
            "latest_run": {"status": "succeeded", "started_at_utc": NOW - timedelta(minutes=5),
                           "finished_at_utc": NOW - timedelta(minutes=5)},
            "agents": [{"agent_id": "001", "latest_alert_utc": NOW - timedelta(minutes=10), "latest_rule_id": 92032}]}


class CollectionHealthTests(unittest.TestCase):
    def result(self, data=None, ids=None):
        return health.build_health(data or snapshot(), ids or ["001"])

    def test_recent_observations_do_not_claim_heartbeat_or_complete_coverage(self):
        result = self.result()
        self.assertEqual(result["state"], "recent_observations")
        self.assertEqual(result["connection_state"], "not_tested")
        self.assertIn("not a heartbeat", result["limits"][0])

    def test_successful_loader_cannot_hide_silent_endpoint(self):
        data = snapshot()
        data["agents"][0]["latest_alert_utc"] = NOW - timedelta(hours=11)
        self.assertEqual(self.result(data)["state"], "attention")
        self.assertEqual(self.result(data)["checks"][0]["state"], "recent")

    def test_latest_disconnection_is_not_recent_collection_proof(self):
        data = snapshot(); data["agents"][0]["latest_rule_id"] = 504
        self.assertEqual(self.result(data)["checks"][-1]["state"], "attention")

    def test_stale_loader_detected_with_recent_endpoint(self):
        data = snapshot(); data["last_success_utc"] = NOW - timedelta(minutes=31)
        self.assertEqual(self.result(data)["state"], "attention")

    def test_failed_loader_detected_even_after_recent_success(self):
        data = snapshot(); data["latest_run"]["status"] = "failed"
        self.assertEqual(self.result(data)["state"], "attention")

    def test_old_running_job_needs_review(self):
        data = snapshot(); data["latest_run"].update(status="running", started_at_utc=NOW - timedelta(minutes=31))
        self.assertEqual(self.result(data)["state"], "attention")

    def test_current_running_job_is_not_reported_failed(self):
        data = snapshot(); data["latest_run"]["status"] = "running"
        self.assertEqual(self.result(data)["state"], "recent_observations")

    def test_no_agent_data_is_unknown_not_clean(self):
        data = snapshot(); data["agents"][0].update(latest_alert_utc=None, latest_rule_id=None)
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_no_success_or_load_history_is_unknown(self):
        data = snapshot(); data.update(last_success_utc=None, latest_run=None)
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_future_timestamps_flag_clock_uncertainty(self):
        data = snapshot(); data["agents"][0]["latest_alert_utc"] = NOW + timedelta(minutes=6)
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_small_clock_skew_is_not_a_negative_age(self):
        data = snapshot(); data["agents"][0]["latest_alert_utc"] = NOW + timedelta(seconds=30)
        self.assertEqual(self.result(data)["checks"][-1]["age_minutes"], 0)

    def test_boundary_and_fractional_staleness(self):
        self.assertEqual(health.freshness(NOW - timedelta(minutes=30), health.utc(NOW), timedelta(minutes=30))["state"], "recent")
        self.assertEqual(health.freshness(NOW - timedelta(minutes=30, seconds=1), health.utc(NOW), timedelta(minutes=30))["state"], "stale")

    def test_aware_timestamps_normalized_to_utc(self):
        self.assertEqual(health.utc(NOW.replace(tzinfo=timezone.utc)), health.utc(NOW))

    def test_unknown_loader_outcome_not_green(self):
        data = snapshot(); data["latest_run"]["status"] = "unexpected"
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_missing_success_finish_not_green(self):
        data = snapshot(); data["latest_run"]["finished_at_utc"] = None
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_multiple_agents_evaluated_independently(self):
        data = snapshot(); second = copy.deepcopy(data["agents"][0]); second.update(agent_id="002", latest_alert_utc=None)
        data["agents"].append(second)
        self.assertEqual(self.result(data, ["001", "002"])["state"], "unknown")

    def test_snapshot_must_match_requested_agents(self):
        with self.assertRaises(ValueError): self.result(snapshot(), ["002"])

    def test_duplicate_snapshot_agent_rejected(self):
        data = snapshot(); data["agents"].append(copy.deepcopy(data["agents"][0]))
        with self.assertRaises(ValueError): self.result(data)

    def test_invalid_ids_and_thresholds_rejected(self):
        for ids, age in (([], 30), (["001", "001"], 30), (["001;DROP"], 30), (["1"], 30),
                         (["001"], 4), (["001"], 241), (["001"], True), (["001"], 30.1)):
            with self.subTest(ids=ids, age=age), self.assertRaises(ValueError): health.validate_inputs(ids, age)

    def test_cli_database_failure_redacts_driver_details(self):
        output = io.StringIO()
        with patch.object(health, "read_snapshot", side_effect=RuntimeError("Password=secret;Server=private")), redirect_stdout(output):
            self.assertEqual(health.main([]), 2)
        self.assertNotIn("secret", output.getvalue())
        self.assertNotIn("Server=", output.getvalue())

    def test_cli_invalid_input_does_not_contact_sql(self):
        with patch.object(health, "read_snapshot") as read, redirect_stdout(io.StringIO()):
            self.assertEqual(health.main(["--agent-id", "bad"]), 2)
        read.assert_not_called()

    def test_cli_attention_exit_code(self):
        data = snapshot(); data["latest_run"]["status"] = "failed"
        with patch.object(health, "read_snapshot", return_value=data), redirect_stdout(io.StringIO()):
            self.assertEqual(health.main([]), 1)

    def test_cli_recent_exit_code(self):
        with patch.object(health, "read_snapshot", return_value=snapshot()), redirect_stdout(io.StringIO()):
            self.assertEqual(health.main([]), 0)

    def test_read_snapshot_only_selects_with_bound_agent_and_closes(self):
        cursor = Mock(); cursor.execute.return_value = cursor
        cursor.fetchone.side_effect = [(NOW, NOW), ("succeeded", NOW, NOW), (NOW, 92032)]
        connection = Mock(); connection.cursor.return_value = cursor
        driver = Mock(); driver.connect.return_value = connection
        with patch.dict("sys.modules", {"pyodbc": driver}):
            result = health.read_snapshot(["001"])
        self.assertEqual(result["agents"][0]["agent_id"], "001")
        self.assertTrue(all(call.args[0].strip().startswith("SELECT") for call in cursor.execute.call_args_list))
        self.assertEqual(cursor.execute.call_args_list[-1].args[1], "001")
        self.assertEqual(connection.timeout, 15)
        connection.close.assert_called_once()

    def test_query_failure_still_closes_connection(self):
        connection = Mock(); connection.cursor.return_value.execute.side_effect = RuntimeError("SQL unavailable")
        driver = Mock(); driver.connect.return_value = connection
        with patch.dict("sys.modules", {"pyodbc": driver}), self.assertRaises(RuntimeError): health.read_snapshot(["001"])
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
