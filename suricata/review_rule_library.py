"""Inspect staged rule data without extracting it or changing the SOC.

Uses only the reviewed, SHA-256-pinned OISF parser from the official 1.3.3
source archive. Field extraction is NOT a Suricata 8 engine syntax test.
The parser package is neither installed nor added to the SOC environment.
"""

import argparse
import hashlib
import json
import tarfile
import types
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from warehouse.inventory_detection_rules import private_output, write_inventory


PARSER_ARCHIVE_SHA256 = "02d7f44db882cf7e020b085943c9c2f906471ac0e69ec36461f2d073d866ad65"
PARSER_MEMBER = "suricata-update-1.3.3/suricata/update/rule.py"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 24 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
MAX_MEMBERS = 1024
MAX_STATEMENT_BYTES = 128 * 1024


def verified_bytes(path, expected_hash):
    path = Path(path)
    if path.is_symlink() or path.is_junction() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive is linked or exceeds the compressed size budget")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_hash.lower():
        raise ValueError("Archive does not match the reviewed SHA-256")
    return data


def reviewed_members(archive):
    members, names, total = [], set(), 0
    for member in archive:
        name = PurePosixPath(member.name)
        if (name.is_absolute() or ".." in name.parts or "\\" in member.name
                or ":" in member.name or not member.name or member.name in names):
            raise ValueError("Unsafe or duplicate archive member name")
        if not member.isfile() and not member.isdir():
            raise ValueError("Archive contains a link, device or unsupported member")
        total += member.size
        if member.size < 0 or member.size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("Archive exceeds the expanded size budget")
        members.append(member)
        names.add(member.name)
        if len(members) > MAX_MEMBERS:
            raise ValueError("Archive exceeds the member count budget")
    return members


def load_pinned_parser(path):
    import io

    data = verified_bytes(path, PARSER_ARCHIVE_SHA256)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = reviewed_members(archive)
        matches = [member for member in members if member.name == PARSER_MEMBER and member.isfile()]
        if len(matches) != 1:
            raise ValueError("Pinned parser module is missing")
        source = archive.extractfile(matches[0]).read()
    # Execute only this already reviewed, hash-pinned upstream module, not setup.py.
    module = types.ModuleType("watchtide_reviewed_oisf_rule_parser")
    exec(compile(source, PARSER_MEMBER, "exec"), module.__dict__)
    return module


def parse_statements(text, group, parser):
    pending = ""
    for line_number, line in enumerate(text.splitlines(), 1):
        continued = line.rstrip().endswith("\\")
        pending += line.rstrip()[:-1] + " " if continued else line
        if len(pending) > MAX_STATEMENT_BYTES:
            raise ValueError("Rule statement exceeds the review size budget")
        if continued:
            continue
        candidate = pending.lstrip("# \t").split(None, 1)
        is_rule = bool(candidate) and candidate[0] in {
            *parser.actions, "rejectsrc", "rejectdst", "rejectboth",
        }
        if is_rule:
            try:
                rule = parser.parse(pending, group=group)
                if rule is None:
                    raise ValueError("Unparsed rule")
            except Exception as error:
                raise ValueError(f"Rule field review stopped at {group}:{line_number}") from error
            yield rule
        pending = ""
    if pending:
        raise ValueError("Unfinished continued rule")


def review_archive(path, expected_hash, parser):
    import io

    data = verified_bytes(path, expected_hash)
    groups, inventory, identities = [], [], Counter()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = reviewed_members(archive)
        for member in members:
            if not member.isfile() or not member.name.endswith(".rules"):
                continue
            payload = archive.extractfile(member).read()
            rules = list(parse_statements(payload.decode("utf-8"), member.name, parser))
            excluded = PurePosixPath(member.name).name.endswith("deleted.rules")
            groups.append({
                "file": member.name, "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "parsed_rules": len(rules),
                "vendor_uncommented": sum(bool(r["enabled"]) for r in rules),
                "updater_default_excluded": excluded,
            })
            for rule in rules:
                record = {key: rule[key] for key in (
                    "gid", "sid", "rev", "msg", "action", "proto", "classtype", "noalert",
                )}
                record.update({"file": member.name, "vendor_uncommented": rule["enabled"],
                               "updater_default_excluded": excluded,
                               "flowbits": rule["flowbits"]})
                inventory.append(record)
                identities[rule.id] += 1
    if not groups or not inventory:
        raise ValueError("No reviewable rule library in archive")
    eligible = [r for r in inventory if not r["updater_default_excluded"]]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "archive_sha256": expected_hash.lower(), "archive_bytes": len(data),
        "parser": {"name": "OISF suricata-update", "version": "1.3.3",
                   "source_archive_sha256": PARSER_ARCHIVE_SHA256, "installed": False},
        "summary": {
            "rule_files": len(groups), "parsed_rule_entries": len(inventory),
            "unique_gid_sid_pairs": len(identities),
            "duplicate_gid_sid_pairs": sum(count > 1 for count in identities.values()),
            "entries_outside_deleted_files": len(eligible),
            "vendor_uncommented_outside_deleted_files": sum(r["vendor_uncommented"] for r in eligible),
            "vendor_commented_outside_deleted_files": sum(not r["vendor_uncommented"] for r in eligible),
            "actions_outside_deleted_files": dict(Counter(r["action"] for r in eligible)),
            "uncommented_dependency_noalert_entries": sum(r["vendor_uncommented"] and r["noalert"] for r in eligible),
        },
        "engine_syntax_tested": False, "rules_deployed": False,
        "capture_started": False, "rules_modified": False,
        "limits": ["Local SHA-256 pins the downloaded snapshot; it is not a vendor signature",
                   "Field parsing is not engine compatibility or detection validation",
                   "Uncommented means vendor file state, not loaded in this SOC",
                   "No deduplication, category selection or dependency resolution applied"],
        "groups": groups, "rules": inventory,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--parser-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    private_output(args.output)
    result = review_archive(args.archive, args.archive_sha256, load_pinned_parser(args.parser_archive))
    write_inventory(result, args.output)
    print(json.dumps(result["summary"], indent=2))
    print("PRIVATE_RULE_LIBRARY_REVIEW_WRITTEN_NOT_DEPLOYED")


if __name__ == "__main__":
    main()
