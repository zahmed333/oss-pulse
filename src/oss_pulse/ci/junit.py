"""JUnit XML: every CI system can show it as test results (Azure DevOps Tests tab, GitLab
merge request widget, Jenkins JUnit plugin, CircleCI, Buildkite)."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from oss_pulse.ci.finding import CiFinding
from oss_pulse.safe_text import visible


def render_junit(findings: list[CiFinding], *, suite: str, fail_on: str) -> str:
    failing = [f for f in findings if f.at_or_above(fail_on)]
    root = ET.Element("testsuites", name="oss-pulse")
    testsuite = ET.SubElement(
        root,
        "testsuite",
        name=suite,
        tests=str(len(findings) + 1),
        failures=str(len(failing)),
        errors="0",
        skipped="0",
    )
    ET.SubElement(testsuite, "testcase", classname="oss-pulse", name=f"{suite} completed")
    for f in findings:
        where = f"{f.path}:{f.line}" if f.line else f.path
        case = ET.SubElement(
            testsuite,
            "testcase",
            classname=f"oss-pulse.{f.rule_id}",
            name=visible(f"{f.rule_id} {f.subject} {where}"),
            file=visible(f.path),
        )
        body = visible(f"{f.message}\nevidence: {f.evidence}")
        if f.at_or_above(fail_on):
            failure = ET.SubElement(
                case, "failure", message=visible(f.title), type=f"{f.severity} {f.rule_id}"
            )
            failure.text = body
        else:
            ET.SubElement(case, "system-out").text = f"{f.severity}: {body}"
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"
