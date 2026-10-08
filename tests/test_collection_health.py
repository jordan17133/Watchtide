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
            "agents": [{"agent_id": "001", "latest_alert_utc": NOW - timedelta(minutes=10), "latest_rule_id": 92032,
                        "queue_warning_count": 0, "latest_queue_warning_utc": None, "latest_queue_recovery_utc": None,
                        "sysmon_error_count": 0, "latest_sysmon_error_utc": None, "source_alerts": []}]}


class CollectionHealthTests(unittest.TestCase):
    def result(self, data=None, ids=None):
        return health.build_health(data or snapshot(), ids or ["001"])

    def check(self, name, data=None):
        return next(c for c in self.result(data)["checks"] if c["check"] == name)

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
        self.assertEqual(self.check("endpoint_alert_observation", data)["state"], "attention")

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
        self.assertEqual(self.check("endpoint_alert_observation", data)["age_minutes"], 0)

    def test_recent_queue_warning_needs_review_despite_fresh_alerts(self):
        data = snapshot(); data["agents"][0].update(queue_warning_count=5, latest_queue_warning_utc=NOW - timedelta(hours=2))
        result = self.result(data)
        self.assertEqual(result["state"], "attention")
        self.assertEqual(self.check("agent_queue_warnings", data)["warning_count"], 5)

    def test_recovery_message_does_not_claim_missing_events_recovered(self):
        data = snapshot(); data["agents"][0].update(queue_warning_count=1,
            latest_queue_warning_utc=NOW - timedelta(hours=2), latest_queue_recovery_utc=NOW - timedelta(hours=1))
        result = self.result(data)
        self.assertEqual(result["state"], "attention")
        self.assertTrue(self.check("agent_queue_warnings", data)["recovery_message_after_warning"])
        self.assertTrue(any("do not prove lost events" in limit for limit in result["limits"]))

    def test_older_recovery_is_not_a_recovery_after_warning(self):
        data = snapshot(); data["agents"][0].update(queue_warning_count=1,
            latest_queue_warning_utc=NOW - timedelta(hours=1), latest_queue_recovery_utc=NOW - timedelta(hours=2))
        self.assertFalse(self.check("agent_queue_warnings", data)["recovery_message_after_warning"])

    def test_absent_queue_evidence_is_unknown(self):
        data = snapshot(); del data["agents"][0]["queue_warning_count"]
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_no_recent_warning_is_not_proof_of_complete_source_health(self):
        result = self.result()
        self.assertEqual(self.check("agent_queue_warnings")["state"], "no_recent_warning_observed")
        self.assertEqual(result["connection_state"], "not_tested")

    def test_queue_signal_clocks_and_window_fail_unknown(self):
        for when in (NOW + timedelta(minutes=6), NOW - timedelta(hours=25)):
            data = snapshot(); data["agents"][0].update(queue_warning_count=1, latest_queue_warning_utc=when)
            with self.subTest(when=when):
                self.assertEqual(self.result(data)["state"], "unknown")

    def test_invalid_queue_counts_and_inconsistent_evidence_fail(self):
        for count, when in ((True, NOW), (-1, NOW), (1, None), (0, NOW), (1.5, NOW)):
            data = snapshot(); data["agents"][0].update(queue_warning_count=count, latest_queue_warning_utc=when)
            with self.subTest(count=count, when=when), self.assertRaises(ValueError):
                self.result(data)

    def test_sysmon_errors_need_review_despite_recent_loader_and_endpoint(self):
        data = snapshot(); data["agents"][0].update(sysmon_error_count=40, latest_sysmon_error_utc=NOW - timedelta(hours=2))
        self.assertEqual(self.result(data)["state"], "attention")
        self.assertEqual(self.check("sysmon_error_observation", data)["error_record_count"], 40)

    def test_no_sysmon_errors_do_not_prove_source_collection(self):
        check = self.check("sysmon_error_observation")
        self.assertEqual(check["state"], "no_recent_error_observed")
        self.assertIn("does not prove", check["reason"])

    def test_missing_sysmon_evidence_stays_unknown(self):
        data = snapshot(); del data["agents"][0]["sysmon_error_count"]
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_invalid_sysmon_evidence_rejected(self):
        for count, latest in ((True, NOW), (-1, NOW), (1, None), (0, NOW), (1.5, NOW)):
            data = snapshot(); data["agents"][0].update(sysmon_error_count=count, latest_sysmon_error_utc=latest)
            with self.subTest(count=count, latest=latest), self.assertRaises(ValueError):
                self.result(data)

    def test_sysmon_clocks_and_window_stay_unknown(self):
        for latest in (NOW + timedelta(minutes=6), NOW - timedelta(hours=25)):
            data = snapshot(); data["agents"][0].update(sysmon_error_count=1, latest_sysmon_error_utc=latest)
            with self.subTest(latest=latest):
                self.assertEqual(self.check("sysmon_error_observation", data)["state"], "unknown")

    def test_source_observations_do_not_flag_a_quiet_source_disconnected(self):
        data = snapshot(); data["agents"][0]["source_alerts"] = [
            {"channel": "Security", "alert_count": 5, "latest_alert_utc": NOW - timedelta(hours=2)}]
        observed = self.result(data)["source_observations"][0]["sources"]
        self.assertEqual(next(s for s in observed if s["source"] == "security")["state"], "observed_in_window")
        self.assertEqual(next(s for s in observed if s["source"] == "sysmon")["state"], "no_alert_observation")
        self.assertEqual(self.result(data)["state"], "recent_observations")

    def test_unknown_channels_are_not_printed_or_assumed_to_be_fim(self):
        data = snapshot(); data["agents"][0]["source_alerts"] = [
            {"channel": "private-test-channel", "alert_count": 2, "latest_alert_utc": NOW},
            {"channel": None, "alert_count": 3, "latest_alert_utc": NOW}]
        result = self.result(data)
        self.assertNotIn("private-test-channel", str(result))
        observed = result["source_observations"][0]["sources"]
        self.assertEqual(next(s for s in observed if s["source"] == "uncategorized")["alert_count"], 3)
        self.assertEqual(next(s for s in observed if s["source"] == "other")["alert_count"], 2)

    def test_multiple_other_channels_merge_counts_and_latest_time(self):
        data = snapshot(); data["agents"][0]["source_alerts"] = [
            {"channel": "other-a", "alert_count": 2, "latest_alert_utc": NOW - timedelta(minutes=2)},
            {"channel": "other-b", "alert_count": 3, "latest_alert_utc": NOW - timedelta(minutes=1)}]
        observed = self.result(data)["source_observations"][0]["sources"]
        other = next(s for s in observed if s["source"] == "other")
        self.assertEqual(other["alert_count"], 5)
        self.assertEqual(other["last_alert_age_minutes"], 1)

    def test_missing_source_query_is_explicitly_unavailable(self):
        data = snapshot(); del data["agents"][0]["source_alerts"]
        self.assertEqual(self.result(data)["source_observations"][0]["state"], "unknown")
        self.assertEqual(self.result(data)["state"], "unknown")

    def test_invalid_source_counts_and_timestamps_rejected(self):
        for count, latest in ((True, NOW), (0, NOW), (-1, NOW), (1, None),
                              (1, NOW + timedelta(minutes=6)), (1, NOW - timedelta(hours=25))):
            data = snapshot(); data["agents"][0]["source_alerts"] = [
                {"channel": "System", "alert_count": count, "latest_alert_utc": latest}]
            with self.subTest(count=count, latest=latest), self.assertRaises(ValueError):
                self.result(data)

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
        cursor.fetchone.side_effect = [(NOW, NOW), ("succeeded", NOW, NOW), (NOW, 92032), (0, None, None), (0, None)]
        cursor.fetchall.return_value = [("System", 5, NOW)]
        connection = Mock(); connection.cursor.return_value = cursor
        driver = Mock(); driver.connect.return_value = connection
        with patch.dict("sys.modules", {"pyodbc": driver}):
            result = health.read_snapshot(["001"])
        self.assertEqual(result["agents"][0]["agent_id"], "001")
        self.assertTrue(all(call.args[0].strip().startswith("SELECT") for call in cursor.execute.call_args_list))
        self.assertEqual(cursor.execute.call_args_list[-1].args[1], "001")
        self.assertEqual(cursor.execute.call_args_list[-1].args[2], NOW)
        self.assertIn("rule_id IN (202, 203, 204, 205)", cursor.execute.call_args_list[3].args[0])
        self.assertIn("win_event_id = 255", cursor.execute.call_args_list[4].args[0])
        self.assertEqual(cursor.execute.call_args_list[4].args[2], "Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(cursor.execute.call_args_list[4].args[3], NOW)
        self.assertEqual(result["agents"][0]["source_alerts"][0]["alert_count"], 5)
        self.assertTrue(all("JSON_VALUE" not in c.args[0] for c in cursor.execute.call_args_list))
        self.assertEqual(connection.timeout, 15)
        connection.close.assert_called_once()

    def test_query_failure_still_closes_connection(self):
        connection = Mock(); connection.cursor.return_value.execute.side_effect = RuntimeError("SQL unavailable")
        driver = Mock(); driver.connect.return_value = connection
        with patch.dict("sys.modules", {"pyodbc": driver}), self.assertRaises(RuntimeError): health.read_snapshot(["001"])
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
