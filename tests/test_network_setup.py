"""Locked-down networks: endpoint overrides, skipping sources, and `oss-pulse doctor`."""

import httpx
from fakes import FakeInternet, scenario

from oss_pulse import endpoints
from oss_pulse.check import run_check
from oss_pulse.doctor import pypi_reachable, render, run_doctor
from oss_pulse.ingest.github_api import API, GitHubClient


def test_endpoint_can_point_at_a_mirror(monkeypatch):
    monkeypatch.setenv("OSS_PULSE_GITHUB_API_URL", "https://github.contoso.com/api/v3/")
    assert endpoints.url("github") == "https://github.contoso.com/api/v3"
    monkeypatch.delenv("OSS_PULSE_GITHUB_API_URL")
    assert endpoints.url("github") == "https://api.github.com"


def test_skip_list_from_environment(monkeypatch):
    monkeypatch.setenv("OSS_PULSE_SKIP", "osv, scorecard")
    assert endpoints.skipped_from_env() == {"osv", "scorecard"}


def test_doctor_reports_blocked_hosts_and_suggests_skip():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host in {"api.osv.dev", "api.securityscorecards.dev"}:
            raise httpx.ConnectError("blocked", request=request)
        return httpx.Response(200)

    probes = run_doctor(httpx.Client(transport=httpx.MockTransport(handler)))
    blocked = {p.endpoint.key for p in probes if not p.reachable}
    assert blocked == {"osv", "scorecard"}
    assert pypi_reachable(probes)
    assert "--skip osv,scorecard" in render(probes)


def test_doctor_treats_a_proxy_refusal_as_unreachable():
    probes = run_doctor(
        httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(407)))
    )
    assert not pypi_reachable(probes)


def test_skipped_sources_are_reported_and_not_contacted(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("healthy-lib\n")
    net = FakeInternet(scenario())
    contacted = []

    def recording(request: httpx.Request) -> httpx.Response:
        contacted.append(request.url.host)
        return net(request)

    transport = httpx.MockTransport(recording)
    gh = GitHubClient(tmp_path / "gh", client=httpx.Client(base_url=API, transport=transport))
    result = run_check(
        requirements,
        tmp_path / "lake",
        gh=gh,
        http=httpx.Client(transport=transport),
        skip={"github", "osv", "scorecard"},
    )
    assert not {"api.github.com", "api.osv.dev", "api.securityscorecards.dev"} & set(contacted)
    skipped = [s for s in result.unavailable_signals if "skipped" in s]
    assert len(skipped) == 3
