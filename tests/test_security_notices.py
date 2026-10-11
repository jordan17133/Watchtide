"""Security notice planning: pure tests. No SQL, no popups."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(os.environ.get("WATCHTIDE_REPO", r"C:\Users\SOC-USER\Desktop\SIEM-SOC"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from warehouse import security_notices as sec  # noqa: E402

T0 = datetime(2026, 10, 8, 18, 0, tzinfo=timezone.utc)
M = timedelta(minutes=1)
REVIEWED = (92213, 91823, 92058, 100110)


def alert(doc, rule, level, loaded):
    return {"doc_id": doc, "rule_id": rule, "rule_level": level, "loaded_at_utc": loaded.isoformat()}


def snap(now, candidates, reviewed=REVIEWED):
    return {"as_of_utc": now.isoformat(), "candidates": candidates,
            "reviewed_rule_ids": list(reviewed), "truncated": False}


def baseline(now=T0, history=()):
    return sec.plan_security(snap(now, list(history)), None, now)["state_on_success"]


class SecurityNoticeTests(unittest.TestCase):
    def plan(self, now, candidates, state, reviewed=REVIEWED):
        return sec.plan_security(snap(now, candidates, reviewed), state, now)

    def test_watchlist_matches_the_documented_rules(self):
        self.assertEqual(sec.WATCHLIST, frozenset({100110, 100111, 100112, 100113, 62123, *range(100130, 100137)}))

    def test_first_run_is_a_baseline_that_never_notifies_about_history(self):
        history = [alert("h1", 100110, 12, T0 - 60 * M), alert("h2", 62123, 12, T0 - 30 * M)]
        plan = sec.plan_security(snap(T0, history), None, T0)
        self.assertEqual((plan["notice"], plan["reason"]), (False, "baseline"))
        self.assertEqual(set(plan["state_on_success"]["seen"]), {"h1", "h2"})
        self.assertEqual(plan["state_on_success"]["checkpoint_utc"], (T0 - 30 * M).isoformat())

    def test_new_watchlist_alert_notifies(self):
        plan = self.plan(T0 + 15 * M, [alert("a1", 100110, 12, T0 + 10 * M)], baseline())
        self.assertTrue(plan["notice"])
        self.assertEqual(plan["summary"]["watchlist_rules"], [100110])

    def test_persistence_rules_notify_despite_level_10(self):
        for rule in (100112, 100113):
            self.assertTrue(self.plan(T0 + 15 * M, [alert("p1", rule, 10, T0 + 5 * M)], baseline())["notice"])

    def test_already_seen_alert_does_not_notify_twice(self):
        first = self.plan(T0 + 15 * M, [alert("a1", 100110, 12, T0 + 10 * M)], baseline())
        again = self.plan(T0 + 30 * M, [alert("a1", 100110, 12, T0 + 10 * M)], first["state_on_success"])
        self.assertFalse(again["notice"])

    def test_late_loaded_alert_inside_the_overlap_is_still_seen(self):
        state = baseline(T0, [alert("h1", 92213, 15, T0)])
        late = alert("late", 62123, 12, T0 - 10 * M)  # committed after the last read, older load time
        self.assertTrue(self.plan(T0 + 15 * M, [late], state)["notice"])

    def test_reviewed_critical_noise_never_notifies(self):
        plan = self.plan(T0 + 15 * M, [alert(f"n{i}", 92213, 15, T0 + i * M) for i in range(1, 10)], baseline())
        self.assertFalse(plan["notice"])
        self.assertEqual(plan["summary"]["new_candidates"], 9)

    def test_health_and_noncritical_rules_do_not_notify(self):
        candidates = [alert("q1", 204, 12, T0 + M), alert("q2", 99999, 11, T0 + 2 * M)]
        self.assertFalse(self.plan(T0 + 15 * M, candidates, baseline())["notice"])

    def test_unreviewed_critical_notifies_once_then_reminds_after_seven_days(self):
        first = self.plan(T0 + 15 * M, [alert("u1", 77777, 13, T0 + 5 * M)], baseline())
        self.assertEqual((first["notice"], first["summary"]["unreviewed_rules"]), (True, [77777]))
        day = T0 + timedelta(days=1)
        quiet = self.plan(day, [alert("u2", 77777, 13, day - M)], first["state_on_success"])
        self.assertFalse(quiet["notice"])
        week = T0 + timedelta(days=8)
        state = dict(quiet["state_on_success"], checkpoint_utc=(week - 20 * M).isoformat())
        self.assertTrue(self.plan(week, [alert("u3", 77777, 13, week - M)], state)["notice"])

    def test_reviewing_a_rule_silences_it(self):
        plan = self.plan(T0 + 15 * M, [alert("u1", 77777, 13, T0 + 5 * M)], baseline(), REVIEWED + (77777,))
        self.assertFalse(plan["notice"])

    def test_failed_delivery_keeps_the_trigger_for_retry(self):
        candidates = [alert("noise", 92213, 15, T0 + 2 * M), alert("hit", 100110, 12, T0 + 5 * M)]
        plan = self.plan(T0 + 15 * M, candidates, baseline())
        failed = plan["state_on_failure"]
        self.assertIn("noise", failed["seen"])
        self.assertNotIn("hit", failed["seen"])
        self.assertLessEqual(failed["checkpoint_utc"], (T0 + 5 * M).isoformat())
        retry = self.plan(T0 + 30 * M, candidates, failed)
        self.assertTrue(retry["notice"])
        self.assertIn("hit", retry["state_on_success"]["seen"])

    def test_reminder_clock_only_starts_on_successful_delivery(self):
        plan = self.plan(T0 + 15 * M, [alert("u1", 77777, 13, T0 + 5 * M)], baseline())
        self.assertEqual(plan["state_on_failure"]["unreviewed_notified"], {})
        self.assertIn("77777", plan["state_on_success"]["unreviewed_notified"])

    def test_seen_set_is_pruned_to_the_read_window(self):
        state = baseline(T0, [alert("old", 92213, 15, T0 - 6 * 60 * M), alert("recent", 92213, 15, T0)])
        later = T0 + 3 * 60 * M
        plan = self.plan(later, [alert("new", 92213, 15, later - M)], state)
        self.assertEqual(set(plan["state_on_success"]["seen"]), {"new"})

    def test_window_start_is_bounded_to_24_hours(self):
        old = {"version": 1, "checkpoint_utc": (T0 - timedelta(days=3)).isoformat(), "seen": {}, "unreviewed_notified": {}}
        self.assertEqual(sec.window_start(old, T0), T0 - timedelta(hours=24))
        recent = dict(old, checkpoint_utc=T0.isoformat())
        self.assertEqual(sec.window_start(recent, T0 + 15 * M), T0 - 30 * M)

    def test_future_checkpoint_and_bad_state_are_rejected(self):
        bad = [{"version": 1, "checkpoint_utc": (T0 + 60 * M).isoformat(), "seen": {}, "unreviewed_notified": {}},
               {"version": 2, "checkpoint_utc": T0.isoformat(), "seen": {}, "unreviewed_notified": {}},
               {"version": 1, "checkpoint_utc": T0.isoformat(), "seen": {"bad id;": T0.isoformat()}, "unreviewed_notified": {}}]
        for state in bad:
            with self.assertRaises(ValueError):
                sec.checked_state(state, T0)

    def test_malformed_candidates_and_stale_snapshots_are_rejected(self):
        for candidate in ({"doc_id": "x y", "rule_id": 1, "rule_level": 12, "loaded_at_utc": T0.isoformat()},
                          {"doc_id": "ok", "rule_id": "1", "rule_level": 12, "loaded_at_utc": T0.isoformat()},
                          {"doc_id": "ok", "rule_id": 1, "rule_level": 99, "loaded_at_utc": T0.isoformat()}):
            with self.assertRaises(ValueError):
                self.plan(T0, [candidate], baseline())
        with self.assertRaises(ValueError):
            sec.plan_security(snap(T0 - 10 * M, []), baseline(), T0)

    def test_summary_carries_only_rule_ids_and_counts(self):
        plan = self.plan(T0 + 15 * M, [alert("a1", 100110, 12, T0 + 5 * M)], baseline())
        self.assertEqual(set(plan["summary"]), {"new_candidates", "watchlist_alerts", "watchlist_rules",
                                                "unreviewed_rules", "truncated"})


if __name__ == "__main__":
    unittest.main()
