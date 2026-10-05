"""Validate PBIR definitions against Microsoft's referenced JSON schemas.

Reads definitions only, not imported telemetry. Does not refresh Power BI.
Install powerbi/tools/requirements.txt in your validation environment first.
"""

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import urlopen

from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


REPORT = Path(__file__).resolve().parents[1] / "SentinelGrid.Report" / "definition"
SCHEMA_PREFIX = "/json-schemas/fabric/item/report/definition/"


def main(report=REPORT, page=None):
    report = Path(report).resolve()
    target = report / "pages" / page if page else report
    if not target.resolve().is_relative_to(report):
        raise ValueError("Page must remain within the report directory")
    schemas = {}

    def retrieve(uri):
        url = urlsplit(uri)
        if url.scheme != "https" or url.hostname != "developer.microsoft.com" or not url.path.startswith(SCHEMA_PREFIX):
            raise ValueError("Only Microsoft's report-definition schemas may be fetched")
        if uri not in schemas:
            try:
                with urlopen(uri, timeout=20) as response:
                    schemas[uri] = json.load(response)
            except HTTPError as error:
                if error.code != 404:
                    raise
                # Microsoft's source repository can precede its schema CDN.
                source = "https://raw.githubusercontent.com/microsoft/json-schemas/main" + url.path.removeprefix("/json-schemas")
                with urlopen(source, timeout=20) as response:
                    schemas[uri] = json.load(response)
        return Resource.from_contents(schemas[uri], default_specification=DRAFT7)

    registry = Registry(retrieve=retrieve)
    checked = 0
    failures = []
    for path in sorted(target.rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        if "$schema" not in document:
            raise ValueError(f"Missing schema in {path.name}")
        schema = retrieve(document["$schema"]).contents
        validator = validator_for(schema)
        validator.check_schema(schema)
        for error in validator(schema, registry=registry).iter_errors(document):
            location = "/".join(str(p) for p in error.absolute_path)
            failures.append(f"{path.relative_to(report)}:{location}: {error.message}")
        checked += 1
    if not checked:
        raise ValueError("No report definitions found")
    if failures:
        raise ValueError("\n".join(failures))
    print(f"MICROSOFT_PBIR_SCHEMAS_PASSED: {checked} definitions")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--page", help="Validate one generated page and its visuals")
    args = parser.parse_args()
    main(args.report, args.page)
