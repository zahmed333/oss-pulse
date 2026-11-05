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
    """The line containing `pos`; a very long line is cut to `width` around the match."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start : end if end != -1 else None].strip()
    if len(line) > width:
        rel = pos - start
        line = line[max(0, rel - width // 2) : rel + width // 2]
    return line


def _hit(rule_id: str, file: str, text: str, m: re.Match, **kw) -> Hit:
    return Hit(rule_id, file, _line_of(text, m.start()), _snippet(text, m.start()), **kw)


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


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    context: str

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    @property
    def is_python(self) -> bool:
        return self.name.endswith((".py", ".pyw", ".pth"))

    @property
    def is_javascript(self) -> bool:
        return self.name.endswith((".js", ".cjs", ".mjs", ".ts"))

    @property
    def is_build_output(self) -> bool:
        wrapped = f"/{self.path}"
        return self.name.endswith(".min.js") or "/dist/" in wrapped or "/build/" in wrapped

    @property
    def runs_at_install(self) -> bool:
        return self.name in {"setup.py", "__init__.py"} or self.name.endswith(".pth")

    def find(self, pattern: str) -> re.Match | None:
        return RE[pattern].search(self.text)

    def hit(self, rule_id: str, match: re.Match, **extra) -> Hit:
        return _hit(rule_id, self.path, self.text, match, **extra)


def _python_obfuscation(src: SourceFile) -> list[Hit]:
    if src.is_python and (m := src.find("obf_py")):
        return [src.hit("CODE-OBF", m)]
    return []


def _javascript_obfuscation(src: SourceFile) -> list[Hit]:
    if src.is_javascript and not src.is_build_output and (m := src.find("obf_js")):
        return [src.hit("CODE-JSOBF", m)]
    return []


def _shell_download_and_run(src: SourceFile) -> list[Hit]:
    m = src.find("dl_shell") or src.find("dl_ps")
    return [src.hit("CODE-DLEXEC", m)] if m else []


def _python_download_and_run_at_install(src: SourceFile) -> list[Hit]:
    if not (src.is_python and src.runs_at_install):
        return []
    download = src.find("py_download")
    if download and src.find("py_exec"):
        return [src.hit("CODE-DLEXEC", download, detail="downloads then executes")]
    return []


def _exfiltration_endpoint(src: SourceFile) -> list[Hit]:
    if m := src.find("exfil"):
        return [src.hit("CODE-EXFIL", m)]
    if m := src.find("raw_ip_url"):
        return [
            src.hit("CODE-EXFIL", m, severity="medium", detail="hard-coded public IP address URL")
        ]
    return []


def _secret_theft(src: SourceFile) -> list[Hit]:
    if m := src.find("wallet_browser"):
        return [src.hit("CODE-SECRETS", m, detail="browser or crypto-wallet data")]
    sends_data_out = src.find("exfil") or src.find("envdump")
    if (m := src.find("cloud_creds")) and sends_data_out:
        detail = "credential file access in a file that also sends data out"
        return [src.hit("CODE-SECRETS", m, detail=detail)]
    return []


def _environment_dump(src: SourceFile) -> list[Hit]:
    m = src.find("envdump")
    return [src.hit("CODE-ENVDUMP", m)] if m else []


def _clipboard_wallet_swap(src: SourceFile) -> list[Hit]:
    if (m := src.find("clipboard")) and src.find("wallet_addr"):
        return [src.hit("CODE-CLIP", m)]
    return []


def _code_hidden_after_whitespace(src: SourceFile) -> list[Hit]:
    if not src.is_build_output and (m := src.find("hidden_ws")):
        return [src.hit("CODE-HIDDEN", m, detail="code hidden after long whitespace")]
    return []


LONG_LINE = 5000


def _very_long_javascript_line(src: SourceFile) -> list[Hit]:
    if not (src.is_javascript and not src.is_build_output and src.context == "repo"):
        return []
    if any(len(line) > LONG_LINE for line in src.text.splitlines()):
        evidence = f"single line longer than {LONG_LINE:,} characters"
        detail = "very long line outside build output"
        return [Hit("CODE-JSOBF", src.path, 1, evidence, severity="medium", detail=detail)]
    return []


def _setup_py_install_hooks(src: SourceFile) -> list[Hit]:
    return scan_setup_py(src.path, src.text) if src.name == "setup.py" else []


def _executable_pth_file(src: SourceFile) -> list[Hit]:
    if not src.name.endswith(".pth") or any(known in src.name for known in PTH_ALLOWLIST):
        return []
    for number, line in enumerate(src.text.splitlines(), 1):
        if line.lstrip().startswith(("import ", "import\t")):
            return [Hit("CODE-PTH", src.path, number, line.strip()[:140])]
    return []


TEXT_CHECKS = (
    _python_obfuscation,
    _javascript_obfuscation,
    _shell_download_and_run,
    _python_download_and_run_at_install,
    _exfiltration_endpoint,
    _secret_theft,
    _environment_dump,
    _clipboard_wallet_swap,
    _code_hidden_after_whitespace,
    _very_long_javascript_line,
    _setup_py_install_hooks,
    _executable_pth_file,
)


def scan_text(file: str, text: str, context: str) -> list[Hit]:
    """Run every text check on a source-like file. context: sdist | wheel | repo."""
    src = SourceFile(file, text, context)
    return [hit for check in TEXT_CHECKS for hit in check(src)]


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
