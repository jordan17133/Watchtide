"""Generate fixed offline TCP fixtures privately; never send, sniff or run a sensor.

Run as a module from the source. Use the existing reviewed Scapy dependency and
an empty, owner-protected output folder; actual Suricata validation is separate.
"""

import argparse
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from warehouse.inventory_detection_rules import private_output


RULE = Path(__file__).with_name("rules") / "watchtide-tcp-lesson.rules"
BASE_TIME = 1767225600
SID = 9000002
CASES = {
    "burst": {"offsets": [0, 1, 2, 3], "expected_alerts": 1},
    "repeat_burst": {"offsets": list(range(8)), "expected_alerts": 1},
    "below_threshold": {"offsets": [0, 1, 2], "expected_alerts": 0},
    "slow_requests": {"offsets": [0, 4, 8, 12], "expected_alerts": 0},
    "split_sources": {"offsets": [0, 1, 2, 3], "expected_alerts": 0},
    "ack_control": {"offsets": [0, 1, 2, 3], "expected_alerts": 0},
    "same_port_burst": {"offsets": [0, 1, 2, 3], "expected_alerts": 1},
}


def packet_fixtures():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapWriter

    fixtures = {}
    for name, case in CASES.items():
        stream = io.BytesIO()
        writer = PcapWriter(stream, linktype=1, sync=True)
        try:
            for index, offset in enumerate(case["offsets"]):
                source = "192.0.2.11" if name == "split_sources" and index % 2 else "192.0.2.10"
                flags = "A" if name == "ack_control" else "S"
                port = 21000 if name == "same_port_burst" else 21000 + index
                packet = (Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
                          / IP(src=source, dst="192.0.2.20", id=index + 1)
                          / TCP(sport=40000 + index, dport=port, flags=flags, seq=1000 + index))
                packet.time = BASE_TIME + offset
                writer.write(packet)
            fixtures[name + ".pcap"] = stream.getvalue()
        finally:
            writer.close()
    return fixtures


def prepare(directory):
    directory = Path(directory)
    fixtures = packet_fixtures()
    fixtures["lesson.rules"] = RULE.read_bytes()
    plan = {
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Synthetic offline TCP lesson, not observed home activity",
        "signature_id": SID,
        "target_engine_version": "8.0.7",
        "engine_tested": False, "packets_sent": False, "live_capture_enabled": False,
        "cases": {name: {"packet_count": len(case["offsets"]),
                         "expected_alerts": case["expected_alerts"]} for name, case in CASES.items()},
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in fixtures.items()},
        "limits": ["Expected counts require actual installed-engine verification.",
                   "Counts measure matching SYN packets, not distinct ports or malicious intent.",
                   "Each fixture needs a separate fresh engine process to reset threshold state.",
                   "This does not install rules or feed Wazuh, SQL or Power BI."],
    }
    fixtures["lesson-plan.json"] = (json.dumps(plan, indent=2) + "\n").encode("ascii")
    # Validate every fresh private target before writing; never overwrite an earlier lesson.
    paths = {name: private_output(directory / name) for name in fixtures}
    for name, path in paths.items():
        with path.open("xb") as stream:
            stream.write(fixtures[name])
    return {"fixture_files": len(CASES), "packets_in_files": sum(len(c["offsets"]) for c in CASES.values()),
            "engine_tested": False, "packets_sent": False, "live_capture_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = prepare(args.directory)
    except Exception:
        print("TCP_LESSON_PREPARATION_STOPPED: inspect local dependencies/private output; do not overwrite a partial job.")
        return 1
    print(json.dumps(result, indent=2))
    print("OFFLINE_TCP_FIXTURES_PREPARED; Suricata engine results remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
