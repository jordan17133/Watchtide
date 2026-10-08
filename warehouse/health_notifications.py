"""Pure local-notice planning and read-only preview; no delivery, files or schedule.

The eventual runner must lock/save private state and record the transport result.
An accepted notification API call is not proof the user saw the notification.
"""

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from warehouse import check_collection_health as health


CHECKS = {"scheduled_loader_success", "latest_loader_outcome", "running_loader_age",
          "endpoint_alert_observation", "agent_queue_warnings", "sysmon_error_observation", "source_alert_query"}
CHECK_STATES = {"recent", "stale", "attention", "unknown", "no_recent_warning_observed", "no_recent_error_observed", "available"}
STATE_KEYS = {"version", "last_observed_utc", "last_attempt_utc", "last_notice_utc",
              "last_notice_kind", "last_notice_fingerprint", "warning_notified"}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Expected an aware ISO timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Expected an aware ISO timestamp")
    return result.astimezone(timezone.utc)


def initial_state():
    return {"version": 1, "last_observed_utc": None, "last_attempt_utc": None,
            "last_notice_utc": None, "last_notice_kind": None,
            "last_notice_fingerprint": None, "warning_notified": False}


def checked_state(previous, now):
    state = initial_state() if previous is None else dict(previous)
    if set(state) != STATE_KEYS or type(state["version"]) is not int or state["version"] != 1:
        raise ValueError("Unsupported notice state")
    if type(state["warning_notified"]) is not bool:
        raise ValueError("Invalid warning state")
    for key in ("last_observed_utc", "last_attempt_utc", "last_notice_utc"):
        if state[key] is not None and timestamp(state[key]) > now:
            raise ValueError("Notice clock moved backwards")
    accepted = state["last_notice_utc"] is not None
    if (accepted and (state["last_notice_kind"] is None or state["last_notice_fingerprint"] is None)) or (
            not accepted and (state["last_notice_kind"] is not None or state["last_notice_fingerprint"] is not None)):
        raise ValueError("Incomplete accepted-notice state")
    if state["last_attempt_utc"] is not None and state["last_observed_utc"] is None:
        raise ValueError("Notification attempt has no observation")
    if accepted:
        if not isinstance(state["last_notice_kind"], str) or not isinstance(state["last_notice_fingerprint"], str) or (
                state["last_notice_kind"] not in {"attention", "unknown", "recovery"}) or not re.fullmatch(
                r"[0-9a-f]{64}", state["last_notice_fingerprint"]):
            raise ValueError("Invalid accepted-notice state")
        if state["last_attempt_utc"] is None or timestamp(state["last_notice_utc"]) > timestamp(state["last_attempt_utc"]):
            raise ValueError("Accepted notice has no matching attempt")
    if state["warning_notified"] != (accepted and state["last_notice_kind"] != "recovery"):
        raise ValueError("Inconsistent recovery state")
    return state


def problem_fingerprint(report):
    state = report["state"]
    checks = report.get("checks")
    if state == "unknown" and checks is None:
        return hashlib.sha256(b"collection_check_unavailable").hexdigest()
    if not isinstance(checks, list) or not checks:
        raise ValueError("Health checks are missing")
    problems, seen, states = [], set(), set()
    for check in checks:
        name, value = check["check"], check["state"]
        agent = check.get("agent_id", "")
        if name not in CHECKS or value not in CHECK_STATES or not isinstance(agent, str) or (
                agent and not re.fullmatch(r"[0-9]{3}", agent)):
            raise ValueError("Unsupported health check")
        key = (name, agent)
        if key in seen:
            raise ValueError("Duplicate health check")
        seen.add(key)
        states.add(value)
        if value in {"stale", "attention", "unknown"}:
            problems.append((name, agent, value))
    expected = "attention" if states & {"stale", "attention"} else "unknown" if "unknown" in states else "recent_observations"
    if state != expected:
        raise ValueError("Inconsistent health state")
    # Stable check identities exclude changing ages/counts and all raw descriptions.
    return hashlib.sha256(json.dumps(sorted(problems), separators=(",", ":")).encode()).hexdigest()


def plan_notice(report, previous, now, cooldown_minutes=60, retry_minutes=5):
    now = health.utc(now)
    for value, low, high in ((cooldown_minutes, 5, 1440), (retry_minutes, 1, 60)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("Invalid notification interval")
    if retry_minutes > cooldown_minutes:
        raise ValueError("Retry interval exceeds reminder cooldown")
    state = checked_state(previous, now)
    observed = timestamp(report["as_of_utc"])
    if observed < now - health.CLOCK_ALLOWANCE or observed > now + health.CLOCK_ALLOWANCE:
        raise ValueError("Health observation is not current")
    kind = report["state"]
    if kind not in {"recent_observations", "attention", "unknown"}:
        raise ValueError("Unsupported health state")
    fingerprint = problem_fingerprint(report)
    state["last_observed_utc"] = now.isoformat()
    if kind == "recent_observations":
        if not state["warning_notified"]:
            return {"state": state, "notice": None, "reason": "no_open_warning"}
        kind = "recovery"
    if state["last_attempt_utc"] is not None and now - timestamp(state["last_attempt_utc"]) < timedelta(minutes=retry_minutes):
        return {"state": state, "notice": None, "reason": "attempt_cooldown"}
    if kind != "recovery" and kind == state["last_notice_kind"] and fingerprint == state["last_notice_fingerprint"] and (
            now - timestamp(state["last_notice_utc"]) < timedelta(minutes=cooldown_minutes)):
        return {"state": state, "notice": None, "reason": "reminder_cooldown"}
    return {"state": state, "notice": {"kind": kind, "fingerprint": fingerprint}, "reason": "notice_due"}


def record_attempt(plan, accepted, now):
    now = health.utc(now)
    state = checked_state(plan["state"], now)
    notice = plan["notice"]
    if type(accepted) is not bool or not notice or set(notice) != {"kind", "fingerprint"} or (
            not isinstance(notice["kind"], str) or not isinstance(notice["fingerprint"], str) or
            notice["kind"] not in {"attention", "unknown", "recovery"} or
            not re.fullmatch(r"[0-9a-f]{64}", notice["fingerprint"])):
        raise ValueError("Invalid notification attempt")
    if state["last_observed_utc"] is None or now - timestamp(state["last_observed_utc"]) > health.CLOCK_ALLOWANCE:
        raise ValueError("Notification plan expired")
    if notice["kind"] == "recovery" and not state["warning_notified"]:
        raise ValueError("Recovery has no accepted warning")
    state["last_attempt_utc"] = now.isoformat()
    if accepted:
        state.update(last_notice_utc=now.isoformat(), last_notice_kind=notice["kind"],
                     last_notice_fingerprint=notice["fingerprint"], warning_notified=notice["kind"] != "recovery")
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", action="append")
    args = parser.parse_args(argv)
    try:
        agents = args.agent_id or ["001"]
        health.validate_inputs(agents, 30)
        try:
            report = health.build_health(health.read_snapshot(agents), agents)
        except Exception:
            report = {"state": "unknown", "as_of_utc": datetime.now(timezone.utc).isoformat()}
        plan = plan_notice(report, None, datetime.now(timezone.utc))
        result = {"health_state": report["state"], "planned_kind": (plan["notice"] or {}).get("kind"),
                  "state_saved": False, "delivery_attempted": False, "schedule_created": False}
    except Exception:
        result = {"health_state": "unknown", "planned_kind": None, "preview_unavailable": True,
                  "state_saved": False, "delivery_attempted": False, "schedule_created": False}
    print(json.dumps(result, indent=2))
    return {"recent_observations": 0, "attention": 1, "unknown": 2}[result["health_state"]]


if __name__ == "__main__":
    raise SystemExit(main())
