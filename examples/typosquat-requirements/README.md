# oss-pulse demo: lookalike package names

Not a real project. `requirements.txt` asks for `reqeusts` and `python-dateutils`, one edit away from `requests` and `python-dateutil`. The versions are made up and can't exist on PyPI, so `pip install -r` fails instead of installing someone else's package.

```sh
oss-pulse scan examples/typosquat-requirements
```
