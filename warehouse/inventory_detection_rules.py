"""Read-only alert-type inventory; detailed output belongs in protected storage.

This does not adjudicate alerts, deploy rules or refresh the historical catalog.
Run from the repository root; SQL uses the analyst's existing Windows identity.
"""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


CONNECTION = (
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;"
    "Database=SentinelGridWarehouse;Trusted_Connection=yes;TrustServerCertificate=yes"
)
QUERY = """
SELECT a.rule_id, COUNT_BIG(*) AS alert_count,
       MIN(a.rule_level) AS lowest_observed_level,
       MAX(a.rule_level) AS highest_observed_level,
       MIN(a.alert_ts_utc) AS first_alert_utc, MAX(a.alert_ts_utc) AS last_alert_utc,
       r.description, r.rule_groups,
       t.verdict AS historical_rule_review, t.report_path AS historical_report
FROM sg.alerts AS a
LEFT JOIN sg.rules AS r ON r.rule_id = a.rule_id
LEFT JOIN sg.rule_triage AS t ON t.rule_id = a.rule_id
GROUP BY a.rule_id, r.description, r.rule_groups, t.verdict, t.report_path
ORDER BY MAX(a.rule_level) DESC, COUNT_BIG(*) DESC, a.rule_id
"""


def severity(level):
    if not 0 <= level <= 15:
        raise ValueError("Unexpected Wazuh severity")
    return "Critical" if level == 15 else "High" if level >= 12 else "Medium" if level >= 7 else "Low"


def build_inventory(rows, catalog):
    if catalog.get("errors"):
        raise ValueError("Historical catalog contains export errors")
    mapped = {int(rule["rule_id"]): rule for rule in catalog["rules"]}
    records, seen = [], set()
    for row in rows:
        record = dict(row)
        rule_id = int(record["rule_id"])
        if rule_id in seen:
            raise ValueError("Duplicate observed rule ID")
        seen.add(rule_id)
        record["rule_id"] = rule_id
        if record["alert_count"] <= 0:
            raise ValueError("Observed rule has no alerts")
        record["priority_band"] = severity(record["highest_observed_level"])
        if record["lowest_observed_level"] > record["highest_observed_level"]:
            raise ValueError("Inconsistent observed severity range")
        severity(record["lowest_observed_level"])
        source = mapped.get(rule_id)
        record["historical_catalog"] = None if source is None else {
            "rule_file": source["file"], "local": bool(source.get("local")),
            "techniques": source["techniques"],
        }
        record["current_alert_verdict"] = "Not adjudicated by this inventory"
        records.append(record)
    records.sort(key=lambda r: (-r["highest_observed_level"], -r["alert_count"], r["rule_id"]))
    bands = Counter(record["priority_band"] for record in records)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "All rule IDs observed in the retained SQL warehouse, not all installed rules",
        "summary": {
            "alerts": sum(r["alert_count"] for r in records), "observed_rule_types": len(records),
            "rule_types_by_highest_level": dict(bands),
            "types_with_historical_review": sum(bool(r.get("historical_rule_review")) for r in records),
            "types_without_historical_review": sum(not r.get("historical_rule_review") for r in records),
            "types_present_in_historical_mapped_catalog": sum(r["historical_catalog"] is not None for r in records),
        },
        "catalog_exported_at_utc": catalog.get("exported_at_utc"),
        "catalog_wazuh_version": catalog.get("wazuh_version"),
        "catalog_mapped_rules": len(catalog["rules"]),
        "catalog_limit": "MITRE-tagged export only; absent IDs are not evidence of missing detection",
        "rules": records,
    }


def read_rows():
    import pyodbc

    connection = pyodbc.connect(CONNECTION, timeout=5, autocommit=True)
    try:
        connection.timeout = 15
        cursor = connection.cursor()
        cursor.execute(QUERY)
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        connection.close()


def private_output(path):
    """Require a pre-protected, existing private parent; never overwrite evidence."""
    path = Path(path).absolute()
    root = Path.home() / ".watchtide-private"
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.is_junction():
            raise ValueError("Output or a parent is a reparse point")
    path = path.resolve()
    if not path.is_relative_to(root) or not path.parent.is_dir():
        raise ValueError("Output needs an existing protected folder under ~/.watchtide-private")
    if path.exists():
        raise ValueError("Output already exists; preserve previous evidence")
    return path


def json_value(value):
    if isinstance(value, datetime):
        return value.isoformat() + ("Z" if value.tzinfo is None else "")
    raise TypeError(type(value).__name__)


def write_inventory(result, output):
    output = private_output(output)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, default=json_value)
        stream.write("\n")


def markdown_inventory(result):
    def cell(value):
        text = "" if value is None else str(value)
        for old, new in (("\\", "\\\\"), ("|", "\\|"), ("<", "&lt;"),
                         (">", "&gt;"), ("[", "\\["), ("`", "\\`")):
            text = text.replace(old, new)
        return " ".join(text.split())

    summary = result["summary"]
    lines = [
        "# Private Alert-Type Inventory", "",
        f"Generated UTC: {result['generated_at_utc']}", "",
        f"{summary['alerts']:,} retained alerts; {summary['observed_rule_types']} observed rule IDs.", "",
        "Every row is an observed pattern, not a confirmed attack. Historical rule reviews",
        "do not adjudicate current alerts. Counts span retained history, not just today.", "",
        "Descriptions may contain private event fields. Keep this entire file out of Git.", "",
        "| Rule | Highest Level | Count | Description | Groups | Historical Review | Last Alert UTC |",
        "|---|---|---|---|---|---|---|",
    ]
    for record in result["rules"]:
        fields = (record["rule_id"], record["highest_observed_level"], record["alert_count"],
                  record.get("description"), record.get("rule_groups"),
                  record.get("historical_report") or "No historical rule review",
                  record["last_alert_utc"])
        lines.append("| " + " | ".join(cell(field) for field in fields) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("warehouse/data/attack-catalog.json"))
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh JSON file in a pre-protected private folder")
    parser.add_argument("--markdown", type=Path,
                        help="Optional fresh private Markdown inventory")
    args = parser.parse_args()
    private_output(args.output)
    if args.markdown:
        private_output(args.markdown)
        if args.markdown.resolve() == args.output.resolve():
            raise ValueError("JSON and Markdown output paths must differ")
    catalog = json.loads(args.catalog.read_text(encoding="utf-8-sig"))
    result = build_inventory(read_rows(), catalog)
    write_inventory(result, args.output)
    if args.markdown:
        with private_output(args.markdown).open("x", encoding="utf-8") as stream:
            stream.write(markdown_inventory(result))
    print(json.dumps(result["summary"], indent=2))
    print("PRIVATE_ALERT_TYPE_INVENTORY_WRITTEN")


if __name__ == "__main__":
    main()
