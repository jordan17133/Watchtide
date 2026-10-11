"""Security alert notices: decide when a new high-priority detection deserves a local popup.

Two tiers, both read-only against SQL:
  A. Watchlist, always notify: secret or credential files, automation scheduled scripts, Startup folder,
     Run keys, Defender malware detection, and the ransomware recovery-wipe rules. Every new
     occurrence.
  B. Unreviewed critical: a level 12+ rule with no review in sg.rule_triage or sg.case_rules.
     Notify once; remind after 7 days only if it is still unreviewed and fires again. Reviewing
     the rule (a triage record or a case link) silences it.
Agent queue health rules (202-205) are left to the collection watchdog.

New alerts are tracked by load time (loaded_at_utc) with an overlap window and per-document
de-duplication, so alerts that reach the warehouse late are still seen. The first run sets a
baseline and does not notify about history. A popup carries one fixed generic text; rule
details stay on this PC:
    .venv\\Scripts\\python.exe -B -m warehouse.security_notices --show
"""

import argparse
import re
from datetime import timedelta

from warehouse import check_collection_health as health
from warehouse import health_notifications as notices


WATCHLIST = frozenset({100110, 100111, 100112, 100113, 62123} | set(range(100130, 100137)))
CRITICAL_LEVEL = 12
HEALTH_RULES = frozenset({202, 203, 204, 205})
OVERLAP = timedelta(minutes=30)       # re-read recent loads so a slow loader commit is not missed
PRUNE_MARGIN = timedelta(minutes=15)
MAX_LOOKBACK = timedelta(hours=24)
REVIEW_REMINDER = timedelta(days=7)
MAX_CANDIDATES = 2000
STATE_KEYS = {"version", "checkpoint_utc", "seen", "unreviewed_notified"}
DOC_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")


def window_start(state, now):
    if state is None:
        return now - MAX_LOOKBACK
    return max(notices.timestamp(state["checkpoint_utc"]) - OVERLAP, now - MAX_LOOKBACK)


def checked_state(state, now):
    if state is None:
        return None
    if not isinstance(state, dict) or set(state) != STATE_KEYS or state["version"] != 1:
        raise ValueError("Unsupported security state")
    if notices.timestamp(state["checkpoint_utc"]) > now + health.CLOCK_ALLOWANCE:
        raise ValueError("Security checkpoint is in the future")
    if not isinstance(state["seen"], dict) or not isinstance(state["unreviewed_notified"], dict):
        raise ValueError("Unsupported security state")
    for doc_id, loaded in state["seen"].items():
        if not isinstance(doc_id, str) or not DOC_ID.fullmatch(doc_id):
            raise ValueError("Invalid document identity")
        notices.timestamp(loaded)
    for rule, when in state["unreviewed_notified"].items():
        if not isinstance(rule, str) or not re.fullmatch(r"[0-9]{1,9}", rule):
            raise ValueError("Invalid rule identity")
        if notices.timestamp(when) > now + health.CLOCK_ALLOWANCE:
            raise ValueError("Reminder clock moved backwards")
    return state


def checked_candidates(snapshot):
    candidates = snapshot["candidates"]
    if not isinstance(candidates, list):
        raise ValueError("Candidates are missing")
    for item in candidates:
        if (not isinstance(item, dict) or set(item) != {"doc_id", "rule_id", "rule_level", "loaded_at_utc"} or
                not isinstance(item["doc_id"], str) or not DOC_ID.fullmatch(item["doc_id"]) or
                type(item["rule_id"]) is not int or type(item["rule_level"]) is not int or
                not 0 <= item["rule_level"] <= 16):
            raise ValueError("Unsupported alert candidate")
        notices.timestamp(item["loaded_at_utc"])
    reviewed = snapshot["reviewed_rule_ids"]
    if not isinstance(reviewed, list) or any(type(rule) is not int for rule in reviewed):
        raise ValueError("Unsupported review list")
    return candidates, set(reviewed)


def plan_security(snapshot, state, now):
    """Pure decision. Returns the notice flag, a redacted summary and the next state for
    success and for failed delivery (failed delivery keeps the triggering alerts unseen)."""
    now = health.utc(now)
    if abs(notices.timestamp(snapshot["as_of_utc"]) - now) > health.CLOCK_ALLOWANCE:
        raise ValueError("Security snapshot is not current")
    state = checked_state(state, now)
    candidates, reviewed = checked_candidates(snapshot)
    latest = max((notices.timestamp(c["loaded_at_utc"]) for c in candidates), default=None)
    summary = {"new_candidates": 0, "watchlist_alerts": 0, "watchlist_rules": [],
               "unreviewed_rules": [], "truncated": bool(snapshot.get("truncated"))}

    if state is None:
        baseline = {"version": 1, "checkpoint_utc": (latest or now).isoformat(),
                    "seen": {c["doc_id"]: c["loaded_at_utc"] for c in candidates}, "unreviewed_notified": {}}
        return {"notice": False, "reason": "baseline", "summary": summary,
                "state_on_success": baseline, "state_on_failure": baseline}

    fresh = [c for c in candidates if c["doc_id"] not in state["seen"]]
    watch = [c for c in fresh if c["rule_id"] in WATCHLIST]
    unreviewed = set()
    for c in fresh:
        rule = c["rule_id"]
        if (c["rule_level"] >= CRITICAL_LEVEL and rule not in WATCHLIST and rule not in HEALTH_RULES
                and rule not in reviewed):
            last = state["unreviewed_notified"].get(str(rule))
            if last is None or now - notices.timestamp(last) >= REVIEW_REMINDER:
                unreviewed.add(rule)
    triggers = [c for c in fresh if c["rule_id"] in WATCHLIST or c["rule_id"] in unreviewed]
    summary.update(new_candidates=len(fresh), watchlist_alerts=len(watch),
                   watchlist_rules=sorted({c["rule_id"] for c in watch}), unreviewed_rules=sorted(unreviewed))

    advanced = max(notices.timestamp(state["checkpoint_utc"]), latest) if latest else notices.timestamp(state["checkpoint_utc"])

    def next_state(delivered):
        checkpoint = advanced
        if triggers and not delivered:
            # Keep the earliest unsent alert inside the next read window so it is retried.
            checkpoint = min(advanced, min(notices.timestamp(c["loaded_at_utc"]) for c in triggers))
        keep_after = checkpoint - OVERLAP - PRUNE_MARGIN
        seen = {d: t for d, t in state["seen"].items() if notices.timestamp(t) >= keep_after}
        trigger_ids = {c["doc_id"] for c in triggers}
        for c in fresh:
            if delivered or c["doc_id"] not in trigger_ids:
                seen[c["doc_id"]] = c["loaded_at_utc"]
        reminded = dict(state["unreviewed_notified"])
        if delivered:
            reminded.update({str(rule): now.isoformat() for rule in unreviewed})
        return {"version": 1, "checkpoint_utc": checkpoint.isoformat(), "seen": seen,
                "unreviewed_notified": reminded}

    return {"notice": bool(triggers), "reason": "notice_due" if triggers else "nothing_new",
            "summary": summary, "state_on_success": next_state(True), "state_on_failure": next_state(False)}


def read_snapshot(state):
    """Read-only, parameterized SELECTs within the existing connection limits."""
    import pyodbc

    connection = pyodbc.connect(health.CONNECTION, timeout=5, autocommit=True)
    try:
        connection.timeout = 15
        cursor = connection.cursor()
        now = health.utc(cursor.execute("SELECT SYSUTCDATETIME()").fetchone()[0])
        start = window_start(state, now).replace(tzinfo=None)
        watch = sorted(WATCHLIST)
        rows = cursor.execute(f"""
            SELECT TOP ({MAX_CANDIDATES + 1}) doc_id, rule_id, rule_level, loaded_at_utc
            FROM sg.alerts
            WHERE loaded_at_utc > ? AND (rule_level >= ? OR rule_id IN ({",".join("?" * len(watch))}))
            ORDER BY loaded_at_utc, doc_id
        """, start, CRITICAL_LEVEL, *watch).fetchall()
        reviewed = cursor.execute("SELECT rule_id FROM sg.rule_triage UNION SELECT rule_id FROM sg.case_rules").fetchall()
        return {"as_of_utc": now.isoformat(),
                "candidates": [{"doc_id": r[0], "rule_id": int(r[1]), "rule_level": int(r[2]),
                                "loaded_at_utc": health.utc(r[3]).isoformat()} for r in rows[:MAX_CANDIDATES]],
                "truncated": len(rows) > MAX_CANDIDATES,
                "reviewed_rule_ids": sorted({int(r[0]) for r in reviewed})}
    finally:
        connection.close()


def show_recent(hours=24):
    """Print notify-worthy alerts from the last hours to this terminal only."""
    import pyodbc

    connection = pyodbc.connect(health.CONNECTION, timeout=5, autocommit=True)
    try:
        connection.timeout = 15
        watch = sorted(WATCHLIST)
        rows = connection.cursor().execute(f"""
            SELECT TOP (200) a.loaded_at_utc, a.alert_ts_utc, a.rule_id, a.rule_level, a.rule_description,
                   CASE WHEN a.rule_id IN ({",".join("?" * len(watch))}) THEN 'watchlist' ELSE 'unreviewed' END
            FROM sg.alerts a
            WHERE a.loaded_at_utc > DATEADD(hour, -?, SYSUTCDATETIME())
              AND (a.rule_id IN ({",".join("?" * len(watch))})
                   OR (a.rule_level >= ? AND a.rule_id NOT IN (202, 203, 204, 205)
                       AND NOT EXISTS (SELECT 1 FROM sg.rule_triage t WHERE t.rule_id = a.rule_id)
                       AND NOT EXISTS (SELECT 1 FROM sg.case_rules c WHERE c.rule_id = a.rule_id)))
            ORDER BY a.loaded_at_utc DESC
        """, *watch, hours, *watch, CRITICAL_LEVEL).fetchall()
    finally:
        connection.close()
    if not rows:
        print(f"No watchlist or unreviewed critical alerts loaded in the last {hours} hours.")
    for loaded, happened, rule, level, description, tier in rows:
        print(f"{happened:%Y-%m-%d %H:%M} UTC  rule {rule} (level {level}, {tier})  {description}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--show", action="store_true", help="list notify-worthy alerts on this terminal")
    parser.add_argument("--hours", type=int, default=24, choices=range(1, 169), metavar="1-168")
    args = parser.parse_args(argv)
    if not args.show:
        parser.print_help()
        return 0
    show_recent(args.hours)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
