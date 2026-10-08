"""Notification planning only: no popups, private state writes or scheduler."""

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from warehouse import health_notifications as notices


NOW = datetime(2026, 10, 7, 22, 30, tzinfo=timezone.utc)


def report(now=NOW, state="recent_observations"):
    checks = [{"check": "scheduled_loader_success", "state": "recent", "age_minutes": 5}]
    if state != "recent_observations":
        checks.append({"check": "agent_queue_warnings", "agent_id": "001", "state": state,
                       "warning_count": 5, "reason": "Private details must not enter a notice"})
    return {"as_of_utc": now.isoformat(), "state": state, "checks": checks}


class HealthNoticeTests(unittest.TestCase):
    def accepted_warning(self, now=NOW):
        plan = notices.plan_notice(report(now, "attention"), None, now)
        return notices.record_attempt(plan, True, now)

    def test_first_recent_observation_is_silent(self):
        plan = notices.plan_notice(report(), None, NOW)
        self.assertIsNone(plan["notice"])
        self.assertEqual(plan["reason"], "no_open_warning")

    def test_first_attention_plans_only_a_generic_kind_and_digest(self):
        plan = notices.plan_notice(report(state="attention"), None, NOW)
        self.assertEqual(set(plan["notice"]), {"kind", "fingerprint"})
        self.assertEqual(plan["notice"]["kind"], "attention")
        self.assertEqual(len(plan["notice"]["fingerprint"]), 64)
        self.assertNotIn("Private details", json.dumps(plan))
        self.assertNotIn('"agent_id"', json.dumps(plan))

    def test_unavailable_database_can_plan_unknown_without_raw_exception(self):
        data = {"state": "unknown", "as_of_utc": NOW.isoformat(), "reason": "Password=private"}
        plan = notices.plan_notice(data, None, NOW)
        self.assertEqual(plan["notice"]["kind"], "unknown")
        self.assertNotIn("Password", str(plan))

    def test_duplicate_warning_is_suppressed_inside_cooldown(self):
        later = NOW + timedelta(minutes=10)
        plan = notices.plan_notice(report(later, "attention"), self.accepted_warning(), later)
        self.assertIsNone(plan["notice"])
        self.assertEqual(plan["reason"], "reminder_cooldown")

    def test_age_and_count_changes_do_not_create_new_notifications(self):
        later = NOW + timedelta(minutes=10)
        data = report(later, "attention")
        data["checks"][0]["age_minutes"] = 10
        data["checks"][1]["warning_count"] = 6
        plan = notices.plan_notice(data, self.accepted_warning(), later)
        self.assertIsNone(plan["notice"])

    def test_ongoing_warning_can_have_an_hourly_reminder(self):
        later = NOW + timedelta(minutes=60)
        plan = notices.plan_notice(report(later, "attention"), self.accepted_warning(), later)
        self.assertEqual(plan["notice"]["kind"], "attention")

    def test_new_problem_can_notify_before_reminder_cooldown(self):
        later = NOW + timedelta(minutes=10)
        data = report(later, "attention")
        data["checks"].append({"check": "sysmon_error_observation", "agent_id": "001", "state": "attention"})
        self.assertIsNotNone(notices.plan_notice(data, self.accepted_warning(), later)["notice"])

    def test_chattering_state_changes_have_attempt_cooldown(self):
        later = NOW + timedelta(minutes=1)
        data = report(later, "unknown")
        plan = notices.plan_notice(data, self.accepted_warning(), later)
        self.assertIsNone(plan["notice"])
        self.assertEqual(plan["reason"], "attempt_cooldown")

    def test_recovery_waits_for_short_cooldown_then_sends_once(self):
        state = self.accepted_warning()
        soon = NOW + timedelta(minutes=1)
        pending = notices.plan_notice(report(soon), state, soon)
        self.assertIsNone(pending["notice"])
        self.assertTrue(pending["state"]["warning_notified"])
        later = NOW + timedelta(minutes=5)
        recovery = notices.plan_notice(report(later), pending["state"], later)
        self.assertEqual(recovery["notice"]["kind"], "recovery")
        state = notices.record_attempt(recovery, True, later)
        self.assertIsNone(notices.plan_notice(report(later), state, later)["notice"])

    def test_failed_first_attempt_does_not_create_a_recovery_notice(self):
        plan = notices.plan_notice(report(state="attention"), None, NOW)
        state = notices.record_attempt(plan, False, NOW)
        later = NOW + timedelta(minutes=5)
        self.assertIsNone(notices.plan_notice(report(later), state, later)["notice"])

    def test_failed_delivery_has_retry_backoff_but_not_success_ack(self):
        plan = notices.plan_notice(report(state="attention"), None, NOW)
        state = notices.record_attempt(plan, False, NOW)
        self.assertIsNone(state["last_notice_utc"])
        soon = NOW + timedelta(minutes=1)
        self.assertIsNone(notices.plan_notice(report(soon, "attention"), state, soon)["notice"])
        later = NOW + timedelta(minutes=5)
        self.assertIsNotNone(notices.plan_notice(report(later, "attention"), state, later)["notice"])

    def test_failed_recovery_remains_pending(self):
        later = NOW + timedelta(minutes=5)
        recovery = notices.plan_notice(report(later), self.accepted_warning(), later)
        state = notices.record_attempt(recovery, False, later)
        self.assertTrue(state["warning_notified"])
        retry = later + timedelta(minutes=5)
        self.assertEqual(notices.plan_notice(report(retry), state, retry)["notice"]["kind"], "recovery")

    def test_state_roundtrip_preserves_deduplication_without_claiming_actual_reboot(self):
        state = json.loads(json.dumps(self.accepted_warning()))
        later = NOW + timedelta(minutes=10)
        self.assertIsNone(notices.plan_notice(report(later, "attention"), state, later)["notice"])

    def test_planning_does_not_mutate_inputs(self):
        data, state = report(state="attention"), notices.initial_state()
        original = copy.deepcopy((data, state))
        notices.plan_notice(data, state, NOW)
        self.assertEqual((data, state), original)

    def test_backwards_clock_stops_instead_of_bypassing_cooldown(self):
        with self.assertRaises(ValueError):
            notices.plan_notice(report(NOW - timedelta(seconds=1)), self.accepted_warning(), NOW - timedelta(seconds=1))

    def test_old_future_and_naive_health_times_rejected(self):
        for stamp in ((NOW - timedelta(minutes=6)).isoformat(),
                      (NOW + timedelta(minutes=6)).isoformat(), "2026-10-07T22:30:00"):
            data = report(); data["as_of_utc"] = stamp
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                notices.plan_notice(data, None, NOW)

    def test_unsupported_or_corrupt_state_is_not_reset_silently(self):
        for update in ({"version": 2}, {"version": True}, {"extra": "private"},
                       {"warning_notified": True}, {"last_notice_kind": "attention"},
                       {"last_notice_fingerprint": "a" * 64}):
            state = {**notices.initial_state(), **update}
            with self.subTest(update=update), self.assertRaises(ValueError):
                notices.plan_notice(report(), state, NOW)

    def test_malformed_and_duplicate_checks_are_rejected(self):
        for check in ({"check": "private-query", "state": "attention"},
                      {"check": "agent_queue_warnings", "agent_id": "private", "state": "attention"},
                      {"check": "agent_queue_warnings", "state": "not-a-state"}):
            data = report(state="attention"); data["checks"].append(check)
            with self.subTest(check=check), self.assertRaises(ValueError):
                notices.plan_notice(data, None, NOW)
        data = report(); data["checks"].append(copy.deepcopy(data["checks"][0]))
        with self.assertRaises(ValueError): notices.plan_notice(data, None, NOW)

    def test_nonstring_notice_fields_are_rejected(self):
        for field in ("kind", "fingerprint"):
            for invalid in (42, [], {}):
                plan = notices.plan_notice(report(state="attention"), None, NOW)
                plan["notice"][field] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    notices.record_attempt(plan, True, NOW)
                state = self.accepted_warning()
                state["last_notice_" + field] = invalid
                with self.assertRaises(ValueError):
                    notices.plan_notice(report(), state, NOW)

    def test_overall_state_must_agree_with_checks(self):
        data = report(state="attention"); data["state"] = "recent_observations"
        with self.assertRaises(ValueError): notices.plan_notice(data, None, NOW)

    def test_intervals_are_bounded(self):
        for cooldown, retry in ((True, 5), (4, 5), (1441, 5), (60, 0), (60, 61), (5, 10)):
            with self.subTest(cooldown=cooldown, retry=retry), self.assertRaises(ValueError):
                notices.plan_notice(report(), None, NOW, cooldown, retry)

    def test_empty_and_expired_delivery_attempts_are_rejected(self):
        plan = notices.plan_notice(report(), None, NOW)
        with self.assertRaises(ValueError): notices.record_attempt(plan, True, NOW)
        plan = notices.plan_notice(report(state="attention"), None, NOW)
        with self.assertRaises(ValueError): notices.record_attempt(plan, True, NOW + timedelta(minutes=6))
        with self.assertRaises(ValueError): notices.record_attempt(plan, "yes", NOW)

    def test_cli_preview_never_delivers_or_saves_state(self):
        data = report(datetime.now(timezone.utc), "attention")
        output = io.StringIO()
        with patch.object(notices.health, "read_snapshot"), patch.object(notices.health, "build_health", return_value=data), \
             redirect_stdout(output):
            self.assertEqual(notices.main([]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["planned_kind"], "attention")
        self.assertFalse(result["delivery_attempted"])
        self.assertFalse(result["state_saved"])
        self.assertFalse(result["schedule_created"])

    def test_cli_sql_failure_plans_unknown_without_printing_connection_data(self):
        output = io.StringIO()
        with patch.object(notices.health, "read_snapshot", side_effect=RuntimeError("Password=private;Server=private")), \
             redirect_stdout(output):
            self.assertEqual(notices.main([]), 2)
        self.assertEqual(json.loads(output.getvalue())["planned_kind"], "unknown")
        self.assertNotIn("Password", output.getvalue())

    def test_cli_invalid_agent_does_not_read_sql(self):
        with patch.object(notices.health, "read_snapshot") as read, redirect_stdout(io.StringIO()):
            self.assertEqual(notices.main(["--agent-id", "private"]), 2)
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
