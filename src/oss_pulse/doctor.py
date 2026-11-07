"""`oss-pulse doctor`: which services this machine can reach, and what is lost without each."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from oss_pulse.endpoints import ENDPOINTS, SKIPPABLE, Endpoint

PROBE_TIMEOUT = httpx.Timeout(8.0)
PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE")


@dataclass(frozen=True)
class Probe:
    endpoint: Endpoint
    reachable: bool
    detail: str


def _probe_request(endpoint: Endpoint) -> tuple[str, str, dict | None]:
    base = endpoint.url
    requests = {
        "pypi": ("GET", f"{base}/pip/json", None),
        "integrity": ("GET", f"{base}/pip/24.0/pip-24.0.tar.gz/provenance", None),
        "files": ("GET", f"{base}/", None),
        "github": ("GET", f"{base}/rate_limit", None),
        "osv": (
            "POST",
            f"{base}/v1/query",
            {"package": {"name": "pip", "ecosystem": "PyPI"}, "version": "24.0"},
        ),
        "scorecard": ("GET", f"{base}/projects/github.com/pypa/pip", None),
        "popular": ("HEAD", base, None),
    }
    return requests[endpoint.key]


def probe(endpoint: Endpoint, client: httpx.Client) -> Probe:
    method, url, body = _probe_request(endpoint)
    try:
        response = client.request(method, url, json=body)
    except httpx.HTTPError as exc:
        return Probe(endpoint, False, type(exc).__name__)
    if response.status_code in (407, 502, 503, 504):
        return Probe(endpoint, False, f"HTTP {response.status_code}")
    return Probe(endpoint, True, f"HTTP {response.status_code}")


def run_doctor(client: httpx.Client | None = None) -> list[Probe]:
    owns_client = client is None
    client = client or httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=True)
    try:
        return [probe(endpoint, client) for endpoint in ENDPOINTS.values()]
    finally:
        if owns_client:
            client.close()


def render(probes: list[Probe]) -> str:
    lines = ["oss-pulse doctor", ""]
    for p in probes:
        status = "ok" if p.reachable else "unreachable"
        consequence = p.endpoint.used_for if p.reachable else p.endpoint.if_unreachable
        lines.append(f"  {status:<12} {p.endpoint.key:<10} {consequence}")
        lines.append(f"  {'':<12} {'':<10} {p.endpoint.url} ({p.detail})")
    lines += ["", "Settings in effect:"]
    for name in PROXY_VARIABLES:
        lines.append(f"  {name:<14} {'set' if os.environ.get(name) else 'not set'}")
    overrides = [e.env_var for e in ENDPOINTS.values() if os.environ.get(e.env_var)]
    lines.append(f"  overrides      {', '.join(overrides) or 'none'}")
    lines.append(f"  OSS_PULSE_SKIP {os.environ.get('OSS_PULSE_SKIP') or 'not set'}")
    blocked = [p.endpoint.key for p in probes if not p.reachable and p.endpoint.key in SKIPPABLE]
    if blocked:
        lines += [
            "",
            "To avoid waiting on timeouts, skip what this machine can't reach:",
            f"  oss-pulse check requirements.txt --skip {','.join(blocked)}",
        ]
    return "\n".join(lines) + "\n"


def pypi_reachable(probes: list[Probe]) -> bool:
    return any(p.endpoint.key == "pypi" and p.reachable for p in probes)
