"""Watchdog runner tests: fake popups and temporary folders only. No real notifications, no SQL."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO = Path(os.environ.get("WATCHTIDE_REPO", r"C:\Users\SOC-USER\Desktop\SIEM-SOC"))
HERE = Path(__file__).resolve().parent
for entry in (str(REPO), str(HERE)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

try:  # inside the SOC repo, after deployment
    from warehouse import collection_watchdog as wd  # noqa: E402
except ImportError:  # the draft folder, before deployment
    import collection_watchdog as wd  # noqa: E402
from warehouse import health_notifications as notices  # noqa: E402

T0 = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
M = timedelta(minutes=1)


def report(now, state="recent_observations"):
    checks = [{"check": "scheduled_loader_success", "state": "recent", "age_minutes": 5}]
    if state == "attention":
        checks.append({"check": "endpoint_alert_observation", "agent_id": "001", "state": "stale",
                       "age_minutes": 41, "reason": "Password=private C:\\Users\\SOC-USER"})
    elif state == "unknown":
        checks.append({"check": "source_alert_query", "agent_id": "001", "state": "unknown"})
    return {"as_of_utc": now.isoformat(), "state": state, "checks": checks}


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.sent, self.accept = [], True

    def tearDown(self):
        self.temp.cleanup()

    def notify(self, kind):
        self.sent.append(kind)
        return self.accept

    def run_at(self, now, state="recent_observations", dry_run=False, read=None):
        return wd.run_once(now, read or (lambda: report(now, state)), self.notify, self.dir, dry_run=dry_run)

    def confirm_and_deliver(self):
        self.run_at(T0, "attention")
        return self.run_at(T0 + 15 * M, "attention")

    def files(self):
        return {p.name: p.read_bytes() for p in self.dir.iterdir()}

    # --- normal behavior -------------------------------------------------------------
    def test_healthy_first_run_is_silent_and_saves_valid_state(self):
        result = self.run_at(T0)
        self.assertEqual(result["action"], "none")
        self.assertEqual(self.sent, [])
        state = json.loads((self.dir / wd.NOTICE_STATE).read_text())
        notices.checked_state(state, T0)

    def test_new_problem_is_held_until_a_second_sighting(self):
        result = self.run_at(T0, "attention")
        self.assertEqual(result["action"], "held_for_confirmation")
        self.assertEqual(self.sent, [])
        self.assertTrue((self.dir / wd.CONFIRM_STATE).exists())

    def test_second_sighting_fifteen_minutes_later_delivers_once(self):
        result = self.confirm_and_deliver()
        self.assertEqual(result["action"], "delivered")
        self.assertEqual(self.sent, ["attention"])
        self.assertFalse((self.dir / wd.CONFIRM_STATE).exists())
        self.assertTrue(json.loads((self.dir / wd.NOTICE_STATE).read_text())["warning_notified"])

    def test_two_runs_a_minute_apart_do_not_confirm(self):
        self.run_at(T0, "attention")
        self.assertEqual(self.run_at(T0 + M, "attention")["action"], "held_for_confirmation")
        self.assertEqual(self.sent, [])
        self.assertEqual(self.run_at(T0 + 15 * M, "attention")["action"], "delivered")

    def test_problem_that_clears_before_confirmation_never_notifies(self):
        self.run_at(T0, "attention")
        self.assertEqual(self.run_at(T0 + 15 * M)["action"], "none")
        self.assertFalse((self.dir / wd.CONFIRM_STATE).exists())
        self.assertEqual(self.run_at(T0 + 30 * M, "attention")["action"], "held_for_confirmation")
        self.assertEqual(self.sent, [])

    def test_sighting_after_a_long_gap_restarts_confirmation(self):
        self.run_at(T0, "attention")
        self.assertEqual(self.run_at(T0 + 60 * M, "attention")["action"], "held_for_confirmation")
        self.assertEqual(self.sent, [])
        self.assertEqual(self.run_at(T0 + 75 * M, "attention")["action"], "delivered")

    def test_growing_outage_confirms_on_the_second_sighting(self):
        # 2026-10-08: another check went stale between runs, restarting confirmation.
        self.run_at(T0, "attention")
        grown = report(T0 + 15 * M, "attention")
        grown["checks"].append({"check": "agent_queue_warnings", "agent_id": "001", "state": "attention"})
        self.assertEqual(self.run_at(T0 + 15 * M, read=lambda: grown)["action"], "delivered")
        self.assertEqual(self.sent, ["attention"])

    def test_unknown_then_attention_does_not_confirm_across_kinds(self):
        self.run_at(T0, "unknown")
        self.assertEqual(self.run_at(T0 + 15 * M, "attention")["action"], "held_for_confirmation")
        self.assertEqual(self.run_at(T0 + 30 * M, "attention")["action"], "delivered")
        self.assertEqual(self.sent, ["attention"])

    def test_one_unreadable_check_during_an_open_outage_stays_quiet(self):
        # 2026-10-09: one slow read flipped attention -> unknown -> attention, two extra popups per blip.
        self.confirm_and_deliver()
        unavailable = lambda now: (lambda: {"state": "unknown", "as_of_utc": now.isoformat()})
        self.assertEqual(self.run_at(T0 + 30 * M, read=unavailable(T0 + 30 * M))["action"], "held_for_confirmation")
        self.assertEqual(self.run_at(T0 + 45 * M, "attention")["reason"], "reminder_cooldown")
        self.assertEqual(self.sent, ["attention"])

    def test_an_open_outage_that_stays_unreadable_does_pop_up(self):
        self.confirm_and_deliver()
        unavailable = lambda now: (lambda: {"state": "unknown", "as_of_utc": now.isoformat()})
        self.run_at(T0 + 30 * M, read=unavailable(T0 + 30 * M))
        self.assertEqual(self.run_at(T0 + 45 * M, read=unavailable(T0 + 45 * M))["action"], "delivered")
        self.assertEqual(self.sent, ["attention", "unknown"])

    def test_unchanged_problem_reminds_only_after_four_hours(self):
        self.confirm_and_deliver()
        self.assertEqual(self.run_at(T0 + 75 * M, "attention")["reason"], "reminder_cooldown")
        self.assertEqual(self.run_at(T0 + (15 + 239) * M, "attention")["action"], "none")
        self.assertEqual(self.run_at(T0 + (15 + 241) * M, "attention")["action"], "delivered")
        self.assertEqual(self.sent, ["attention", "attention"])

    def test_recovery_is_sent_once_without_confirmation(self):
        self.confirm_and_deliver()
        self.assertEqual(self.run_at(T0 + 30 * M)["action"], "delivered")
        self.assertEqual(self.run_at(T0 + 45 * M)["action"], "none")
        self.assertEqual(self.sent, ["attention", "recovery"])

    def test_failed_delivery_retries_after_five_minutes_without_reconfirming(self):
        self.accept = False
        self.run_at(T0, "attention")
        self.assertEqual(self.run_at(T0 + 15 * M, "attention")["action"], "delivery_failed")
        self.assertEqual(self.run_at(T0 + 17 * M, "attention")["reason"], "attempt_cooldown")
        self.assertTrue(json.loads((self.dir / wd.CONFIRM_STATE).read_text())["confirmed"])
        self.accept = True
        self.assertEqual(self.run_at(T0 + 21 * M, "attention")["action"], "delivered")
        self.assertEqual(self.sent, ["attention", "attention"])

    def test_unavailable_database_warns_as_unknown_after_confirmation(self):
        unavailable = lambda now: (lambda: {"state": "unknown", "as_of_utc": now.isoformat()})
        self.run_at(T0, read=unavailable(T0))
        result = self.run_at(T0 + 15 * M, read=unavailable(T0 + 15 * M))
        self.assertEqual((result["action"], result["kind"]), ("delivered", "unknown"))

    def test_inconsistent_report_is_treated_as_unavailable(self):
        bad = report(T0, "attention")
        bad["state"] = "recent_observations"
        result = self.run_at(T0, read=lambda: bad)
        self.assertIn("report_rejected", result["events"])
        self.assertEqual((result["health"], result["action"]), ("unknown", "held_for_confirmation"))

    # --- safety ----------------------------------------------------------------------
    def test_corrupt_state_is_quarantined_not_deleted(self):
        (self.dir / wd.NOTICE_STATE).write_text("{not json")
        result = self.run_at(T0)
        self.assertTrue(any(e.startswith("notice_state_rejected:") for e in result["events"]))
        self.assertEqual(len(list(self.dir.glob(wd.NOTICE_STATE + ".rejected-*"))), 1)
        notices.checked_state(json.loads((self.dir / wd.NOTICE_STATE).read_text()), T0)

    def test_future_dated_state_is_quarantined(self):
        state = notices.initial_state()
        state["last_observed_utc"] = (T0 + 60 * M).isoformat()
        (self.dir / wd.NOTICE_STATE).write_text(json.dumps(state))
        self.assertTrue(any(e.startswith("notice_state_rejected:") for e in self.run_at(T0)["events"]))

    def test_dry_run_writes_nothing_and_never_notifies(self):
        self.run_at(T0, "attention")
        before = self.files()
        result = self.run_at(T0 + 15 * M, "attention", dry_run=True)
        self.assertEqual(result["action"], "would_deliver")
        self.assertEqual(self.files(), before)
        self.assertEqual(self.sent, [])

    def test_second_concurrent_run_is_refused(self):
        with wd.run_lock(self.dir):
            with self.assertRaises(wd.Busy):
                with wd.run_lock(self.dir):
                    pass
        with wd.run_lock(self.dir):  # released after the first holder exits
            pass

    def test_no_private_text_reaches_state_log_or_notifier(self):
        self.confirm_and_deliver()
        blob = b"".join(self.files().values()) + "".join(self.sent).encode()
        for secret in (b"Password", b"someone", b"Users"):
            self.assertNotIn(secret, blob)

    def test_saves_leave_no_temporary_files(self):
        for step in range(4):
            self.run_at(T0 + 15 * step * M, "attention")
        self.assertEqual(list(self.dir.glob("*.tmp")), [])

    def test_run_log_is_bounded(self):
        with mock.patch.object(wd, "LOG_MAX_LINES", 5):
            for step in range(8):
                self.run_at(T0 + 15 * step * M)
        self.assertEqual(len((self.dir / wd.RUN_LOG).read_text().splitlines()), 5)

    # --- diagnostics when a check fails ------------------------------------------------
    def test_failed_health_read_logs_type_and_sqlstate_but_not_the_message(self):
        class FakeOperationalError(Exception):
            pass
        boom = FakeOperationalError("HYT00", "[ODBC] Query timeout expired; Server=windows-endpoint;Password=secret")
        with mock.patch.object(wd.health, "read_snapshot", side_effect=boom):
            failed = wd.read_report()
        self.assertEqual((failed["state"], failed["error"]), ("unknown", "FakeOperationalError:HYT00"))
        result = wd.run_once(T0, lambda: dict(failed, as_of_utc=T0.isoformat()), self.notify, self.dir)
        self.assertIn("health_read_error:FakeOperationalError:HYT00", result["events"])
        blob = b"".join(self.files().values())
        for secret in (b"Password", b"timeout expired", b"Server="):
            self.assertNotIn(secret, blob)

    def test_error_label_keeps_only_safe_parts(self):
        self.assertEqual(wd.error_label(RuntimeError("Driver said Password=x")), "RuntimeError")
        self.assertEqual(wd.error_label(OSError("08001", "connect failed")), "OSError:08001")
        self.assertEqual(wd.error_label(ValueError("hyt00")), "ValueError")

    def test_each_run_logs_how_long_each_check_took(self):
        result = self.run_sec(T0, [])
        self.assertIsInstance(result["timing"]["health_read_s"], float)
        self.assertIsInstance(result["timing"]["security_s"], float)
        logged = json.loads((self.dir / wd.RUN_LOG).read_text().splitlines()[-1])
        self.assertEqual(set(logged["timing"]), {"health_read_s", "security_s"})
        self.assertIsNone(self.run_at(T0 + 15 * M)["timing"]["security_s"])  # no security reader given

    def test_unrecognized_error_labels_are_not_logged_raw(self):
        bad = lambda: {"state": "unknown", "as_of_utc": T0.isoformat(), "error": "x; Remove-Item y"}
        result = wd.run_once(T0, bad, self.notify, self.dir)
        self.assertIn("health_read_error:unrecognized", result["events"])

    # --- security tier ----------------------------------------------------------------
    @staticmethod
    def sec_alert(doc, rule, level, loaded):
        return {"doc_id": doc, "rule_id": rule, "rule_level": level, "loaded_at_utc": loaded.isoformat()}

    def run_sec(self, now, candidates, dry_run=False, reviewed=(92213,)):
        read_security = lambda state: {"as_of_utc": now.isoformat(), "candidates": candidates,
                                       "reviewed_rule_ids": list(reviewed), "truncated": False}
        return wd.run_once(now, lambda: report(now), self.notify, self.dir, dry_run=dry_run,
                           read_security=read_security)

    def test_security_first_run_is_a_silent_baseline(self):
        result = self.run_sec(T0, [self.sec_alert("h1", 62123, 12, T0 - 10 * M)])
        self.assertEqual(result["security"]["action"], "baseline")
        self.assertEqual(self.sent, [])

    def test_security_alert_pops_the_security_kind_without_two_strikes(self):
        self.run_sec(T0, [])
        result = self.run_sec(T0 + 15 * M, [self.sec_alert("a1", 100110, 12, T0 + 5 * M)])
        self.assertEqual(result["security"]["action"], "delivered")
        self.assertEqual(self.sent, ["security"])

    def test_security_failure_never_breaks_the_health_check(self):
        def broken(state):
            raise RuntimeError("Driver error with Password=x")
        result = wd.run_once(T0, lambda: report(T0), self.notify, self.dir, read_security=broken)
        self.assertEqual(result["action"], "none")
        self.assertIn("security_error:RuntimeError", result["events"])
        self.assertTrue((self.dir / wd.NOTICE_STATE).exists())
        self.assertNotIn(b"Password", b"".join(self.files().values()))

    def test_security_delivery_failure_retries_next_run(self):
        self.run_sec(T0, [])
        hit = [self.sec_alert("a1", 100110, 12, T0 + 5 * M)]
        self.accept = False
        self.assertEqual(self.run_sec(T0 + 15 * M, hit)["security"]["action"], "delivery_failed")
        self.accept = True
        self.assertEqual(self.run_sec(T0 + 30 * M, hit)["security"]["action"], "delivered")
        self.assertEqual(self.run_sec(T0 + 45 * M, hit)["security"]["action"], "none")

    def test_security_dry_run_writes_nothing(self):
        self.run_sec(T0, [])
        before = self.files()
        result = self.run_sec(T0 + 15 * M, [self.sec_alert("a1", 100110, 12, T0 + 5 * M)], dry_run=True)
        self.assertEqual(result["security"]["action"], "would_deliver")
        self.assertEqual(self.files(), before)
        self.assertEqual(self.sent, [])

    # --- notifier transport ----------------------------------------------------------
    def notifier_file(self):
        path = self.dir / "Show-WatchtideNotification.ps1"
        path.write_text("# stand-in")
        return path

    def test_notifier_sends_only_a_fixed_kind(self):
        done = subprocess.CompletedProcess([], 0, stdout='{"api_accepted":true}\n', stderr="")
        with mock.patch.object(wd.subprocess, "run", return_value=done) as run:
            self.assertTrue(wd.deliver("attention", notifier=self.notifier_file()))
        command = run.call_args.args[0][-1]
        self.assertIn("-Kind Attention", command)
        self.assertIn("-Mode Library", command)

    def test_notifier_timeout_or_failure_counts_as_not_delivered(self):
        path = self.notifier_file()
        with mock.patch.object(wd.subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell", 30)):
            self.assertFalse(wd.deliver("attention", notifier=path))
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="error")
        with mock.patch.object(wd.subprocess, "run", return_value=failed):
            self.assertFalse(wd.deliver("recovery", notifier=path))
        garbled = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
        with mock.patch.object(wd.subprocess, "run", return_value=garbled):
            self.assertFalse(wd.deliver("unknown", notifier=path))

    def test_notifier_rejects_unsupported_kinds_and_missing_helper(self):
        for kind in ("test", "Attention", "attention; Remove-Item x"):
            with self.assertRaises(ValueError):
                wd.deliver(kind, notifier=self.notifier_file())
        self.assertFalse(wd.deliver("attention", notifier=self.dir / "missing.ps1"))


if __name__ == "__main__":
    unittest.main()
