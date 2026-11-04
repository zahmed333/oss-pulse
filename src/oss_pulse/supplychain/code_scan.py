"""Static code heuristics shared by the release-artifact scanner and the repository scanner.

Design rules:
  * Never execute, import or unpickle anything. Files are bytes -> text -> regex/AST.
  * Every hit carries file, line and a short evidence snippet so a human can verify it.
  * Precision over recall on *popular* libraries: patterns that legitimate libraries use
    (reading ~/.aws/credentials, calling git in setup.py) are only flagged at high
    severity in combination with an exfiltration signal, or downgraded.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from oss_pulse.supplychain.rules import rule

MAX_TEXT_BYTES = 2_000_000

TEXT_EXT = {
    ".py",
    ".pyw",
    ".pth",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".json",
    ".cfg",
    ".toml",
    ".yml",
    ".yaml",
    ".rb",
    ".pl",
}
MEDIA_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".bmp",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".svgz",
    ".mp3",
    ".mp4",
}
BINARY_MAGIC = {
    b"\x7fELF": "ELF",
    b"MZ": "Windows PE",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O universal",
}
# Media files must start with one of these; JS/Python inside a ".png" is a disguise.
MEDIA_MAGIC = (
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"\x00\x00\x01\x00",
    b"BM",
    b"RIFF",
    b"wOFF",
    b"wOF2",
    b"\x00\x01\x00\x00",
    b"OTTO",
    b"ID3",
    b"\x00\x00\x00",
)

# Legitimate, well-known .pth files that contain `import` lines.
PTH_ALLOWLIST = {
    "distutils-precedence.pth",
    "_virtualenv.pth",
    "coverage.pth",
    "_editable_impl",
    "__editable__",
}

RE = {
    "obf_py": re.compile(
        r"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?[\w.]*?"
        r"(?:b64decode|b32decode|b16decode|a85decode|decompress|marshal\.loads|fromhex|"
        r"codecs\.decode|rot13|\[::-1\])",
        re.I,
    ),
    "obf_js": re.compile(
        r"\b(?:eval|new\s+Function)\s*\(\s*(?:atob|Buffer\.from|unescape|"
        r"decodeURIComponent|String\.fromCharCode)"
    ),
    "dl_shell": re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    "dl_ps": re.compile(
        r"(?:Invoke-Expression|\biex\b\s*\(|DownloadString\s*\(|"
        r"powershell[^\n]*\s-(?:e|enc|encodedcommand)\s)",
        re.I,
    ),
    "py_download": re.compile(
        r"\b(?:urlretrieve|urlopen|requests\.(?:get|post)|httpx\.get|"
        r"urllib3\.request)\s*\("
    ),
    "py_exec": re.compile(
        r"\b(?:exec|eval)\s*\(|subprocess\.|os\.system\s*\(|os\.popen\s*\(|"
        r"os\.chmod\s*\("
    ),
    # Case-sensitive and path-anchored: generic words like "cookies" are everywhere.
    "wallet_browser": re.compile(
        r"(?:wallet\.dat\b|Exodus[/\\]exodus\.wallet|Electrum[/\\]wallets|\.solana[/\\]id\.json"
        r"|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa"
        r"|egjidjbpglichdcondbcbdnbeeppgdph|ibnejdfjmmkpcnlpebklmnkoeoihofec"
        r"|[/\\]Login Data\b|[/\\]Local State\b|[/\\]Network[/\\]Cookies\b"
        r"|Library/Keychains/|Local Extension Settings[/\\])"
    ),
    "cloud_creds": re.compile(
        r"(?:\.ssh/id_(?:rsa|ed25519|ecdsa)|\.aws/credentials|\.pypirc"
        r"|\.npmrc|\.git-credentials|\.docker/config\.json|\.kube/config"
        r"|gcloud/credentials)"
    ),
    # Serialising the environment (copying it for a subprocess is normal and not matched).
    "envdump": re.compile(
        r"(?:json\.dumps|pickle\.dumps|base64\.b64encode|str|repr)\s*\(\s*"
        r"(?:dict\s*\(\s*)?os\.environ\b(?!\s*\[|\.get)"
        r"|JSON\.stringify\s*\(\s*process\.env\s*\)"
    ),
    "exfil": re.compile(
        r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|pastebin\.com/raw"
        r"|transfer\.sh|ngrok(?:-free)?\.(?:io|app|dev)|webhook\.site|requestbin|pipedream\.net"
        r"|\boast\.(?:fun|pro|me|live|site|online)|interact\.sh|burpcollaborator|trycloudflare\.com)",
        re.I,
    ),
    # A hard-coded public IP URL is suspicious but has legitimate uses: medium on its own.
    "raw_ip_url": re.compile(
        r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|"
        r"172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/"
    ),
    "clipboard": re.compile(
        r"\b(?:pyperclip|clipboard\.(?:paste|copy)|navigator\.clipboard"
        r"|pbpaste|xclip|GetClipboardData)"
    ),
    "wallet_addr": re.compile(
        r"\b(?:bc1[a-z0-9]{25,59}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|T[1-9A-HJ-NP-Za-km-z]{33})\b"
    ),
    "hidden_ws": re.compile(r"[ \t]{180,}\S"),
}


@dataclass(frozen=True)
class Hit:
    rule_id: str
    file: str
    line: int
    evidence: str
    severity: str | None = None  # override the rule's default
    detail: str = ""

    @property
    def effective_severity(self) -> str:
        return self.severity or rule(self.rule_id).severity


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int, width: int = 140) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start : end if end != -1 else None].strip()
    if len(line) > width:  # centre the snippet on the match for very long lines
        rel = pos - start
        line = line[max(0, rel - width // 2) : rel + width // 2]
    return line


def _first(pattern: re.Pattern, text: str):
    return pattern.search(text)


def _hit(rule_id: str, file: str, text: str, m: re.Match, **kw) -> Hit:
    return Hit(rule_id, file, _line_of(text, m.start()), _snippet(text, m.start()), **kw)


# ------------------------------------------------------------------ setup.py (AST)

_NET_CALLS = {
    "urlopen",
    "urlretrieve",
    "socket",
    "create_connection",
    "HTTPConnection",
    "HTTPSConnection",
    "get",
    "post",
    "request",
}
_NET_MODULES = {"urllib", "requests", "httpx", "socket", "http", "urllib3", "aiohttp"}
_CMD_CALLS = {
    "system",
    "popen",
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    "exec",
    "eval",
    "startfile",
}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_setup_py(file: str, text: str) -> list[Hit]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    hits: list[Hit] = []
    lines = text.splitlines()

    def ev(node: ast.AST) -> str:
        return lines[node.lineno - 1].strip()[:140] if 0 < node.lineno <= len(lines) else ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        leaf, root = name.rsplit(".", 1)[-1], name.split(".", 1)[0]
        if leaf == "setup" and any(k.arg == "cmdclass" for k in node.keywords):
            hits.append(Hit("CODE-CMDCLASS", file, node.lineno, ev(node)))
        if root in _NET_MODULES and leaf in _NET_CALLS:
            hits.append(
                Hit(
                    "CODE-SETUP",
                    file,
                    node.lineno,
                    ev(node),
                    severity="high",
                    detail="network access at install time",
                )
            )
        elif leaf in _CMD_CALLS and (
            root in {"os", "subprocess", "exec", "eval"} or name in {"exec", "eval"}
        ):
            hits.append(
                Hit(
                    "CODE-SETUP",
                    file,
                    node.lineno,
                    ev(node),
                    severity="medium",
                    detail="runs commands at install time",
                )
            )
    return hits


# ------------------------------------------------------------------- generic text


def scan_text(file: str, text: str, context: str) -> list[Hit]:
    """Regex heuristics for any source-like file. context: sdist | wheel | repo."""
    hits: list[Hit] = []
    name = PurePosixPath(file).name
    is_py = name.endswith((".py", ".pyw", ".pth"))
    is_js = name.endswith((".js", ".cjs", ".mjs", ".ts"))
    minified = name.endswith(".min.js") or "/dist/" in f"/{file}" or "/build/" in f"/{file}"
    install_time = name in {"setup.py", "__init__.py"} or name.endswith(".pth")

    if is_py and (m := _first(RE["obf_py"], text)):
        hits.append(_hit("CODE-OBF", file, text, m))
    if is_js and not minified and (m := _first(RE["obf_js"], text)):
        hits.append(_hit("CODE-JSOBF", file, text, m))
    for key in ("dl_shell", "dl_ps"):
        if m := _first(RE[key], text):
            hits.append(_hit("CODE-DLEXEC", file, text, m))
            break
    if (
        is_py
        and install_time
        and (d := _first(RE["py_download"], text))
        and _first(RE["py_exec"], text)
    ):
        hits.append(_hit("CODE-DLEXEC", file, text, d, detail="downloads then executes"))

    exfil = _first(RE["exfil"], text)
    if exfil:
        hits.append(_hit("CODE-EXFIL", file, text, exfil))
    elif m := _first(RE["raw_ip_url"], text):
        hits.append(
            _hit(
                "CODE-EXFIL",
                file,
                text,
                m,
                severity="medium",
                detail="hard-coded public IP address URL",
            )
        )
    if m := _first(RE["wallet_browser"], text):
        hits.append(_hit("CODE-SECRETS", file, text, m, detail="browser or crypto-wallet data"))
    elif (m := _first(RE["cloud_creds"], text)) and (exfil or _first(RE["envdump"], text)):
        hits.append(
            _hit(
                "CODE-SECRETS",
                file,
                text,
                m,
                detail="credential file access in a file that also sends data out",
            )
        )
    if m := _first(RE["envdump"], text):
        hits.append(_hit("CODE-ENVDUMP", file, text, m))
    if (m := _first(RE["clipboard"], text)) and _first(RE["wallet_addr"], text):
        hits.append(_hit("CODE-CLIP", file, text, m))
    if not minified and (m := _first(RE["hidden_ws"], text)):
        hits.append(_hit("CODE-HIDDEN", file, text, m, detail="code hidden after long whitespace"))
    if (
        is_js
        and not minified
        and context == "repo"
        and any(len(ln) > 5000 for ln in text.splitlines())
    ):
        hits.append(
            Hit(
                "CODE-JSOBF",
                file,
                1,
                "single line longer than 5,000 characters",
                severity="medium",
                detail="very long line outside build output",
            )
        )

    if name == "setup.py":
        hits.extend(scan_setup_py(file, text))
    if name.endswith(".pth") and not any(a in name for a in PTH_ALLOWLIST):
        for i, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("import ", "import\t")):
                hits.append(Hit("CODE-PTH", file, i, line.strip()[:140]))
                break
    return hits


NOT_INSTALLED = re.compile(
    r"(?:^|/)(?:tests?|testing|docs?|examples?|benchmarks?|\.github)/"
    r"|(?:^|/)(?:test_[^/]*|[^/]*_test|conftest)\.py$"
)


def scan_file(file: str, data: bytes, context: str) -> list[Hit]:
    """Entry point: classify bytes, then run the right heuristics.

    In release artifacts, tests/docs/examples are neither installed nor executed by pip,
    so they are skipped (setup.py and .pth files are always scanned)."""
    suffix = PurePosixPath(file).suffix.lower()
    if context in {"sdist", "wheel"} and NOT_INSTALLED.search(file):
        return []
    head = data[:8]

    if suffix in MEDIA_EXT:
        if data and not head.startswith(MEDIA_MAGIC):
            sample = data[:4000].decode("utf-8", "ignore")
            if re.search(r"\b(?:function|require\(|import |eval\(|exec\(|child_process)", sample):
                return [
                    Hit(
                        "CODE-HIDDEN",
                        file,
                        1,
                        sample.strip()[:140],
                        detail=f"script content inside a {suffix} file",
                    )
                ]
        return []

    for magic, kind in BINARY_MAGIC.items():
        if head.startswith(magic):
            if context in {"sdist", "repo"} and not (magic == b"MZ" and len(data) < 1024):
                return [Hit("CODE-BIN", file, 1, f"{kind} executable ({len(data):,} bytes)")]
            return []

    if len(data) > MAX_TEXT_BYTES:
        return []
    if suffix not in TEXT_EXT and PurePosixPath(file).name not in {"Makefile", "Dockerfile"}:
        return []
    return scan_text(file, data.decode("utf-8", "replace"), context)
