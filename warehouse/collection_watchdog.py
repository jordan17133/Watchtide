"""Watchtide collection watchdog: one bounded pass of check -> plan -> confirm -> notify -> save.

Task Scheduler runs this as the logged-on owner every 15 minutes (pythonw.exe, no window).
It reuses the existing pieces: check_collection_health (read-only SQL), health_notifications
(when to warn), security_notices (which new detections deserve a popup) and
windows/Show-WatchtideNotification.ps1 (fixed generic texts). It adds only an OS-released run
lock, atomic private state, a two-sighting confirmation for new health problems, a bounded
notifier call and a redacted run log. A security-tier failure never undoes the health result.

It never restarts or fixes anything, changes Wazuh, SQL, firewall or schedules, uses
administrator rights or SSH, sends data off this PC, or puts raw logs, users or paths in a
notification. It cannot warn while this PC is off or if its own scheduled task stops.

Usage (from the repository root):
    .venv\\Scripts\\python.exe -B -m warehouse.collection_watchdog --dry-run
        read-only: plan and print; no popup, no state, no log
    .venv\\Scripts\\pythonw.exe -B -m warehouse.collection_watchdog
        what the scheduled task runs
"""

import argparse
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from warehouse import check_collection_health as health
from warehouse import health_notifications as notices
from warehouse import security_notices as security

try:
    import msvcrt
except ImportError:  # The watchdog is Windows-only; the import guard keeps tooling readable.
    msvcrt = None


AGENTS = ["001"]
MAX_AGE_MINUTES = 30        # 7-day history: one normal quiet gap >= 30 min (59 min on Oct 3)
REMINDER_MINUTES = 240      # unchanged-problem reminder; the planner's own default is 60
RETRY_MINUTES = 5           # minimum spacing between delivery attempts
CONFIRM_MIN_GAP = timedelta(minutes=10)   # two manual runs a minute apart cannot confirm
CONFIRM_WINDOW = timedelta(minutes=45)    # a sighting older than this starts confirmation over
NOTIFY_TIMEOUT_SECONDS = 30
RUN_BUDGET_SECONDS = 120    # logged if exceeded; Task Scheduler enforces a hard 5-minute stop
LOG_MAX_LINES = 2000

STATE_DIR = Path.home() / ".watchtide-private" / "watchdog"
NOTICE_STATE = "notice-state.json"      # planner-owned state, health_notifications format
CONFIRM_STATE = "confirm-state.json"    # runner-owned: a problem seen once, not yet confirmed
SECURITY_STATE = "security-state.json"  # security_notices checkpoint, seen alerts, reminders
LOCK_NAME = "run.lock"
RUN_LOG = "runs.jsonl"
NOTIFIER = Path(__file__).resolve().parents[1] / "windows" / "Show-WatchtideNotification.ps1"
KIND_TEXT = {"attention": "Attention", "unknown": "Unknown", "recovery": "Recovery", "security": "Security"}
CONFIRM_KEYS = {"version", "fingerprint", "kind", "first_seen_utc", "confirmed"}
SQLSTATE = re.compile(r"[0-9A-Z]{5}")
ERROR_LABEL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(:[0-9A-Z]{5})?")


def error_label(exc):
    """Exception type plus a standard 5-character SQLSTATE (e.g. HYT00 = timeout) when present.
    Never the message: driver messages can carry connection details."""
    label = type(exc).__name__
    code = exc.args[0] if exc.args else None
    if isinstance(code, str) and SQLSTATE.fullmatch(code):
        label += ":" + code
    return label if ERROR_LABEL.fullmatch(label) else "unrecognized"


class Busy(Exception):
    """Another run holds the lock."""


@contextmanager
def run_lock(directory):
    """Exclusive, non-blocking lock that Windows releases if the process dies."""
    if msvcrt is None:
        raise RuntimeError("The watchdog runs on Windows only")
    fd = os.open(directory / LOCK_NAME, os.O_RDWR | os.O_CREAT)
    try:
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            raise Busy() from None
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def read_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path, value):
    """Write to a temporary file, flush to disk, then replace: never a half-written state."""
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def quarantine(path, now):
    """Keep a rejected state file for inspection instead of deleting or silently reusing it."""
    target = path.with_name(f"{path.name}.rejected-{now:%Y%m%dT%H%M%SZ}")
    os.replace(path, target)
    return target.name


def load_notice_state(directory, now, events, dry_run):
    path = directory / NOTICE_STATE
    try:
        state = read_json(path)
        return None if state is None else notices.checked_state(state, now)
    except (ValueError, TypeError, KeyError, AttributeError):
        events.append("notice_state_rejected" if dry_run else "notice_state_rejected:" + quarantine(path, now))
        return None


def load_confirm(directory, now, events, dry_run):
    path = directory / CONFIRM_STATE
    try:
        value = read_json(path)
        if value is None:
            return None
        if (not isinstance(value, dict) or set(value) != CONFIRM_KEYS or value["version"] != 1 or
                not isinstance(value["fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["fingerprint"]) or
                value["kind"] not in {"attention", "unknown"} or type(value["confirmed"]) is not bool):
            raise ValueError("Unsupported confirmation state")
        if notices.timestamp(value["first_seen_utc"]) > now + health.CLOCK_ALLOWANCE:
            raise ValueError("Confirmation clock moved backwards")
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        events.append("confirm_state_rejected" if dry_run else "confirm_state_rejected:" + quarantine(path, now))
        return None


def read_report(agents=None):
    agents = agents or AGENTS
    try:
        return health.build_health(health.read_snapshot(agents), agents, MAX_AGE_MINUTES)
    except Exception as exc:
        # Driver messages can include connection details; keep only the type and SQLSTATE.
        return {"state": "unknown", "as_of_utc": datetime.now(timezone.utc).isoformat(),
                "error": error_label(exc)}


def deliver(kind, notifier=None, timeout=NOTIFY_TIMEOUT_SECONDS):
    """Show one fixed generic notice. True only if the Windows API accepted it."""
    if kind not in KIND_TEXT:
        raise ValueError("Unsupported notice kind")
    notifier = Path(notifier or NOTIFIER)
    if "'" in str(notifier) or not notifier.is_file():
        return False
    command = (f"$ErrorActionPreference='Stop'; . '{notifier}' -Mode Library; "
               f"Show-WatchtideLocalNotification -Kind {KIND_TEXT[kind]} | ConvertTo-Json -Compress")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned",
             "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    try:
        return json.loads(lines[-1]).get("api_accepted") is True
    except (IndexError, ValueError, AttributeError):
        return False


def decide(plan, previous, pending, now):
    """Return (deliver_now, new_pending). New warnings, and an open warning changing kind, need
    two sightings of the same kind 10-45 minutes apart."""
    notice = plan["notice"]
    if notice is None:
        # Problem gone before confirmation, or waiting on a cooldown: keep only a confirmed retry.
        keep = pending if (pending and pending["confirmed"] and plan["reason"] == "attempt_cooldown") else None
        return False, keep
    kind, fingerprint = notice["kind"], notice["fingerprint"]
    if kind == "recovery":
        return True, None
    if previous and previous["warning_notified"] and previous["last_notice_kind"] == kind:
        # Reminder, or more checks failing in the kind of problem already reported.
        return True, None
    # A new problem, or an open one changing kind: one slow, unreadable read during an outage
    # flipped attention -> unknown -> attention and popped twice per blip (2026-10-09).
    if pending and pending["kind"] == kind:
        # Match the kind, not the exact failing checks: as an outage grows, more checks go
        # stale, and that must not restart its own confirmation (2026-10-08: a 15-minute delay).
        current = dict(pending, fingerprint=fingerprint)
        if pending["confirmed"]:
            return True, current
        elapsed = now - notices.timestamp(pending["first_seen_utc"])
        if CONFIRM_MIN_GAP <= elapsed <= CONFIRM_WINDOW:
            return True, dict(current, confirmed=True)
        if elapsed < CONFIRM_MIN_GAP:
            return False, current
    return False, {"version": 1, "fingerprint": fingerprint, "kind": kind,
                   "first_seen_utc": now.isoformat(), "confirmed": False}


def append_log(directory, entry):
    path = directory / RUN_LOG
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > LOG_MAX_LINES:
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temporary.write_text("\n".join(lines[-LOG_MAX_LINES:]) + "\n", encoding="utf-8")
        os.replace(temporary, path)


def run_security(now, read_security, notify, directory, dry_run, events):
    """Security tier pass: separate state, same lock, log and notifier. No two-strike rule:
    a detection is a discrete event, not a flapping health signal."""
    path = directory / SECURITY_STATE
    try:
        state = security.checked_state(read_json(path), now)
    except (ValueError, TypeError, KeyError, AttributeError):
        events.append("security_state_rejected" if dry_run else "security_state_rejected:" + quarantine(path, now))
        state = None
    plan = security.plan_security(read_security(state), state, now)
    if not plan["notice"]:
        action, next_state = ("baseline" if plan["reason"] == "baseline" else "none"), plan["state_on_success"]
    elif dry_run:
        action, next_state = "would_deliver", None
    else:
        accepted = notify("security")
        action = "delivered" if accepted else "delivery_failed"
        next_state = plan["state_on_success"] if accepted else plan["state_on_failure"]
    if not dry_run:
        write_json_atomic(path, next_state)
    return {"action": action, "reason": plan["reason"], **plan["summary"]}


def run_once(now, read, notify, directory, dry_run=False, read_security=None):
    """One pass. read() returns a health report; notify(kind) returns True if accepted.
    read_security(state), when given, returns a security snapshot for the security tier."""
    started = datetime.now(timezone.utc)
    now = health.utc(now)
    directory = Path(directory)
    events = []
    clock = time.monotonic()
    report = read()
    timing = {"health_read_s": round(time.monotonic() - clock, 1), "security_s": None}
    if isinstance(report, dict) and "error" in report:
        label = report["error"]
        events.append("health_read_error:" + (label if isinstance(label, str) and ERROR_LABEL.fullmatch(label)
                                              else "unrecognized"))
    previous = load_notice_state(directory, now, events, dry_run)
    pending = load_confirm(directory, now, events, dry_run)
    try:
        plan = notices.plan_notice(report, previous, now, REMINDER_MINUTES, RETRY_MINUTES)
    except ValueError:
        # An inconsistent or out-of-date report is unavailable evidence, not a healthy one.
        events.append("report_rejected")
        report = {"state": "unknown", "as_of_utc": now.isoformat()}
        plan = notices.plan_notice(report, previous, now, REMINDER_MINUTES, RETRY_MINUTES)

    deliver_now, pending = decide(plan, previous, pending, now)
    kind = (plan["notice"] or {}).get("kind")
    state, action = plan["state"], "none"
    if plan["notice"] and not deliver_now:
        action = "held_for_confirmation"
    elif deliver_now and dry_run:
        action = "would_deliver"
    elif deliver_now:
        accepted = notify(kind)
        state = notices.record_attempt(plan, accepted, now)
        action = "delivered" if accepted else "delivery_failed"
        if accepted:
            pending = None

    if not dry_run:
        write_json_atomic(directory / NOTICE_STATE, state)
        if pending is None:
            if (directory / CONFIRM_STATE).exists():
                (directory / CONFIRM_STATE).unlink()
        else:
            write_json_atomic(directory / CONFIRM_STATE, pending)

    security_result = None
    if read_security is not None:
        clock = time.monotonic()
        try:
            security_result = run_security(now, read_security, notify, directory, dry_run, events)
        except Exception as exc:
            # Isolated: a security-tier failure never undoes the saved health result.
            events.append("security_error:" + error_label(exc))
            security_result = {"action": "error"}
        timing["security_s"] = round(time.monotonic() - clock, 1)

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    if elapsed > RUN_BUDGET_SECONDS:
        events.append("over_budget")
    result = {"utc": now.isoformat(), "health": report["state"], "reason": plan["reason"],
              "action": action, "kind": kind, "events": events, "dry_run": dry_run, "timing": timing}
    if security_result is not None:
        result["security"] = security_result
    if not dry_run:
        append_log(directory, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="read-only: plan and print, never notify or save")
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc)
    try:
        if args.dry_run:
            result = run_once(now, read_report, lambda kind: False, STATE_DIR, dry_run=True,
                              read_security=security.read_snapshot)
        else:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            with run_lock(STATE_DIR):
                result = run_once(now, read_report, deliver, STATE_DIR, read_security=security.read_snapshot)
    except Busy:
        return 3
    except Exception as exc:
        # Record the error type only; messages can carry connection details.
        result = {"utc": now.isoformat(), "action": "runner_error", "error": error_label(exc)}
        if not args.dry_run:
            try:
                append_log(STATE_DIR, result)
            except OSError:
                pass
        print(json.dumps(result))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
