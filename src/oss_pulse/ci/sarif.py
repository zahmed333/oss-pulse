"""SARIF 2.1.0: GitHub code scanning, the Azure DevOps "Scans" tab, and most security
dashboards read it."""

from __future__ import annotations

import json

from oss_pulse.ci.finding import CiFinding
from oss_pulse.safe_text import visible
from oss_pulse.supplychain.rules import RULES

INFORMATION_URI = "https://github.com/zahmed333/oss-pulse"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def _rule_descriptor(rule_id: str) -> dict:
    rule = RULES.get(rule_id)
    descriptor = {"id": rule_id, "name": rule_id.replace("-", "")}
    if rule:
        descriptor |= {
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.why},
            "help": {"text": f"{rule.why} Seen in: {rule.seen_in}" if rule.seen_in else rule.why},
            "helpUri": f"{INFORMATION_URI}/blob/main/docs/RULES.md",
            "properties": {
                "tags": ["security", "supply-chain", rule.category],
                "security-severity": SECURITY_SEVERITY[rule.severity],
            },
        }
    return descriptor


def _result(f: CiFinding) -> dict:
    region = {"startLine": f.line} if f.line else {}
    location = {"artifactLocation": {"uri": f.path.replace("\\", "/")}}
    if region:
        location["region"] = region
    return {
        "ruleId": f.rule_id,
        "level": LEVEL[f.severity],
        "message": {"text": visible(f"{f.message} Evidence: {f.evidence}")},
        "locations": [{"physicalLocation": location}],
        "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "subject": f.subject},
    }


def render_sarif(findings: list[CiFinding], *, version: str) -> str:
    rule_ids = sorted({f.rule_id for f in findings})
    run = {
        "tool": {
            "driver": {
                "name": "oss-pulse",
                "version": version,
                "informationUri": INFORMATION_URI,
                "rules": [_rule_descriptor(r) for r in rule_ids],
            }
        },
        "results": [_result(f) for f in findings],
    }
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)
