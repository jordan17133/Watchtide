"""Read-only warehouse freshness check, not an agent heartbeat or notification job.

Run from the repository root with -m warehouse.check_collection_health.
Exit 0 means recent observations, 1 needs review, and 2 means unavailable or
unknown evidence. No scheduling, delivery, configuration changes or raw logs.
"""

import argparse
import json
import re
from datetime import datetime, timedelta, timezone


CONNECTION = (
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;"
    "Database=SentinelGridWarehouse;Trusted_Connection=yes;TrustServerCertificate=yes"
)
CLOCK_ALLOWANCE = timedelta(minutes=5)
LIMITS = [
    "Alert freshness is not a heartbeat; a quiet endpoint can trigger review.",
    "Recent alerts do not prove every source is collected or that no events were lost.",
    "Agent authentication, Indexer freshness and Power BI refresh are separate checks.",
    "This command does not schedule monitoring or deliver notifications.",
]


def validate_inputs(agent_ids, max_age_minutes):
    if not agent_ids or len(agent_ids) > 16 or len(set(agent_ids)) != len(agent_ids):
        raise ValueError("Expected one to sixteen distinct agent IDs")
    if any(not re.fullmatch(r"[0-9]{3}", agent_id) for agent_id in agent_ids):
        raise ValueError("Expected three-digit enrolled agent IDs")
    if isinstance(max_age_minutes, bool) or not isinstance(max_age_minutes, int) or not 5 <= max_age_minutes <= 240:
        raise ValueError("Freshness limit must be 5 to 240 minutes")


def utc(value):
    if not isinstance(value, datetime):
        raise ValueError("Expected a database UTC timestamp")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def freshness(value, now, threshold):
    if value is None:
        return {"state": "unknown", "age_minutes": None, "reason": "No retained timestamp"}
    delta = now - utc(value)
    if delta < -CLOCK_ALLOWANCE:
        return {"state": "unknown", "age_minutes": None, "reason": "Timestamp is in the future; check clocks"}
    age = max(0, delta.total_seconds() / 60)
    return {"state": "stale" if delta > threshold else "recent", "age_minutes": round(age, 2)}


def build_health(snapshot, agent_ids, max_age_minutes=30):
    validate_inputs(agent_ids, max_age_minutes)
    now = utc(snapshot["as_of_utc"])
    threshold = timedelta(minutes=max_age_minutes)
    checks = [{"check": "scheduled_loader_success", **freshness(snapshot["last_success_utc"], now, threshold)}]
    run = snapshot["latest_run"]
    if run is None:
        checks.append({"check": "latest_loader_outcome", "state": "unknown", "reason": "No load history"})
    elif run["status"] == "failed":
        checks.append({"check": "latest_loader_outcome", "state": "attention", "reason": "Latest load failed"})
    elif run["status"] == "running":
        checks.append({"check": "running_loader_age", **freshness(run["started_at_utc"], now, threshold)})
    elif run["status"] != "succeeded" or run.get("finished_at_utc") is None:
        checks.append({"check": "latest_loader_outcome", "state": "unknown", "reason": "Incomplete load outcome"})
    else:
        checks.append({"check": "latest_loader_outcome", **freshness(run["finished_at_utc"], now, threshold)})

    agents = snapshot["agents"]
    if len(agents) != len(agent_ids) or {r["agent_id"] for r in agents} != set(agent_ids):
        raise ValueError("Snapshot does not match the requested agent set")
    for row in agents:
        check = {"check": "endpoint_alert_observation", "agent_id": row["agent_id"],
                 **freshness(row["latest_alert_utc"], now, threshold)}
        if row["latest_rule_id"] == 504:
            check.update(state="attention", reason="Latest retained record reports disconnection")
        checks.append(check)
    states = {check["state"] for check in checks}
    state = "attention" if states & {"stale", "attention"} else "unknown" if "unknown" in states else "recent_observations"
    return {"as_of_utc": now.isoformat(), "state": state, "max_age_minutes": max_age_minutes,
            "checks": checks, "connection_state": "not_tested", "limits": list(LIMITS)}


def read_snapshot(agent_ids):
    import pyodbc

    connection = pyodbc.connect(CONNECTION, timeout=5, autocommit=True)
    try:
        connection.timeout = 15
        cursor = connection.cursor()
        row = cursor.execute("""
            SELECT SYSUTCDATETIME(),
                   (SELECT MAX(finished_at_utc) FROM sg.load_runs WHERE status = 'succeeded')
        """).fetchone()
        snapshot = {"as_of_utc": row[0], "last_success_utc": row[1], "agents": []}
        row = cursor.execute("""
            SELECT TOP (1) status, started_at_utc, finished_at_utc
            FROM sg.load_runs ORDER BY run_id DESC
        """).fetchone()
        snapshot["latest_run"] = None if row is None else dict(zip(
            ("status", "started_at_utc", "finished_at_utc"), row))
        for agent_id in agent_ids:
            row = cursor.execute("""
                SELECT TOP (1) alert_ts_utc, rule_id
                FROM sg.alerts WHERE agent_id = ? ORDER BY alert_ts_utc DESC, doc_id DESC
            """, agent_id).fetchone()
            snapshot["agents"].append({"agent_id": agent_id,
                                      "latest_alert_utc": None if row is None else row[0],
                                      "latest_rule_id": None if row is None else row[1]})
        return snapshot
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", action="append", help="Enrolled ID; repeat for additional agents. Default: 001")
    parser.add_argument("--max-age-minutes", type=int, default=30)
    args = parser.parse_args(argv)
    agent_ids = args.agent_id or ["001"]
    try:
        validate_inputs(agent_ids, args.max_age_minutes)
        result = build_health(read_snapshot(agent_ids), agent_ids, args.max_age_minutes)
    except Exception:
        # Driver exceptions may include connection details; never print them here.
        result = {"state": "unknown", "reason": "Collection check unavailable; inspect privately",
                  "connection_state": "not_tested", "limits": list(LIMITS)}
    print(json.dumps(result, indent=2))
    return {"recent_observations": 0, "attention": 1, "unknown": 2}[result["state"]]


if __name__ == "__main__":
    raise SystemExit(main())
