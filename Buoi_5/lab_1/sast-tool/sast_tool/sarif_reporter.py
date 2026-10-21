"""Serialize a SARIF 2.1.0 report for SARIF Viewer."""

from pathlib import Path

import attr
import jsonpickle
from sarif_om import (
    ArtifactLocation, Location, Message, PhysicalLocation, Region,
    Result, Run, SarifLog, Tool, ToolComponent,
)


def _schema_value(value):
    """Use SARIF metadata names and omit optional unset/default fields."""
    if attr.has(type(value)):
        result = {}
        for field in attr.fields(type(value)):
            item = getattr(value, field.name)
            if item is None or item == field.default:
                continue
            key = field.metadata.get("schema_property_name", field.name)
            result[key] = _schema_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_schema_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _schema_value(item) for key, item in value.items()}
    return value


class SarifReporter:
    def generate_report(self, issues, output_file="report.sarif",
                        analyzed_file="input.py"):
        uri = Path(analyzed_file).resolve().as_uri()
        levels = {"high": "error", "medium": "warning", "low": "note"}
        results = []
        for issue in issues:
            results.append(Result(
                rule_id=issue["type"],
                level=levels.get(issue.get("severity"), "warning"),
                message=Message(text=issue["message"]),
                locations=[Location(physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(uri=uri),
                    region=Region(
                        start_line=issue["lineno"],
                        start_column=issue["col_offset"] + 1,
                    ),
                ))],
            ))
        run = Run(
            tool=Tool(driver=ToolComponent(name="PySAST", version="1.0.0")),
            results=results, column_kind="unicodeCodePoints",
        )
        log = SarifLog(
            schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
            version="2.1.0", runs=[run],
        )
        Path(output_file).write_text(
            jsonpickle.encode(
                _schema_value(log), unpicklable=False, indent=2
            ) + "\n",
            encoding="utf-8",
        )
