"""CI outputs: provider detection, annotation escaping, JUnit, SARIF and the Azure DevOps
pull-request comment."""

import json
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx

from oss_pulse.ci import providers
from oss_pulse.ci.finding import CiFinding, split_location
from oss_pulse.ci.junit import render_junit
from oss_pulse.ci.pull_request import MARKER, AzurePullRequest, upsert_comment
from oss_pulse.ci.sarif import render_sarif
from oss_pulse.safe_text import visible

HOSTILE = "x]1;y\n##vso[task.setvariable variable=SECRET]stolen\n::error::fake %"


def finding(severity="high", evidence="eval(x)", detail="detail", line=8):
    return CiFinding(
        "AUTO-VSCODE",
        severity,
        "Runs on open",
        detail,
        ".vscode/tasks.json",
        line,
        evidence,
        "repo",
    )


def test_detects_each_ci_system():
    assert providers.detect({"TF_BUILD": "True"}) == providers.AZURE
    assert providers.detect({"GITHUB_ACTIONS": "true"}) == providers.GITHUB
    assert providers.detect({"GITLAB_CI": "true"}) == providers.GITLAB
    assert providers.detect({"JENKINS_URL": "http://ci"}) == providers.JENKINS
    assert providers.detect({}) == providers.GENERIC


def test_location_with_and_without_line():
    assert split_location(".vscode/tasks.json:8") == (".vscode/tasks.json", 8)
    assert split_location("requirements.txt") == ("requirements.txt", None)


def test_azure_annotation_points_at_file_and_line():
    [line] = providers.annotations([finding()], providers.AZURE, "high")
    assert line.startswith("##vso[task.logissue type=error;sourcepath=.vscode/tasks.json;")
    assert "linenumber=8" in line and "code=AUTO-VSCODE" in line


def test_below_threshold_is_a_warning():
    [line] = providers.annotations([finding("medium")], providers.AZURE, "high")
    assert "type=warning" in line


def test_hostile_text_cannot_issue_pipeline_commands():
    hostile = finding(detail=HOSTILE)
    for provider in (providers.AZURE, providers.GITHUB, providers.GENERIC):
        [line] = providers.annotations([hostile], provider, "high")
        assert "\n" not in line and "\r" not in line
        assert "##vso[task.setvariable" not in line
    [azure] = providers.annotations([hostile], providers.AZURE, "high")
    assert azure.count("##vso[") == 1 and azure.count("]") == 1


def test_visible_neutralises_azure_commands_anywhere_in_a_line():
    out = visible("ok ##vso[task.setvariable variable=x]1 ##[group]g ## heading")
    assert "##vso[" not in out and "##[" not in out
    assert "## heading" in out


def test_junit_marks_findings_at_threshold_as_failures():
    xml = render_junit([finding("high"), finding("low")], suite="oss-pulse scan", fail_on="high")
    suite = ET.fromstring(xml.split("\n", 1)[1])[0]
    assert suite.get("tests") == "3" and suite.get("failures") == "1"
    assert len(suite.findall(".//failure")) == 1


def test_junit_survives_hostile_text():
    xml = render_junit([finding(detail=HOSTILE)], suite="s", fail_on="high")
    ET.fromstring(xml.split("\n", 1)[1])
    assert "##vso[task.setvariable" not in xml


def test_sarif_has_rules_levels_and_locations():
    doc = json.loads(render_sarif([finding("critical")], version="0.1.0"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "AUTO-VSCODE"
    result = run["results"][0]
    assert result["level"] == "error"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == ".vscode/tasks.json"
    assert location["region"]["startLine"] == 8


ENV = {
    "SYSTEM_COLLECTIONURI": "https://dev.azure.com/contoso/",
    "SYSTEM_TEAMPROJECT": "billing",
    "BUILD_REPOSITORY_ID": "repo-1",
    "SYSTEM_PULLREQUEST_PULLREQUESTID": "42",
    "SYSTEM_ACCESSTOKEN": "token",
}


def azure_api(existing_threads):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.content))
        assert request.headers["authorization"] == "Bearer token"
        if request.method == "GET":
            return httpx.Response(200, json={"value": existing_threads})
        return httpx.Response(200, json={})

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_pull_request_comment_is_created_once():
    client, calls = azure_api([])
    pr = AzurePullRequest.from_env(ENV)
    assert upsert_comment(pr, "report", client) == "created"
    method, path, body = calls[-1]
    assert method == "POST"
    assert path == "/contoso/billing/_apis/git/repositories/repo-1/pullRequests/42/threads"
    assert MARKER in json.loads(body)["comments"][0]["content"]


def test_pull_request_comment_is_updated_in_place():
    existing = [{"id": 7, "comments": [{"id": 1, "content": f"{MARKER}\nold"}]}]
    client, calls = azure_api(existing)
    assert upsert_comment(AzurePullRequest.from_env(ENV), "new", client) == "updated"
    method, path, _ = calls[-1]
    assert method == "PATCH" and path.endswith("/threads/7/comments/1")


def test_templates_are_valid_yaml():
    import yaml

    root = Path(__file__).resolve().parents[1]
    for template in ("ci/azure-pipelines/oss-pulse.yml", "ci/gitlab/oss-pulse.gitlab-ci.yml"):
        assert yaml.safe_load((root / template).read_text())
