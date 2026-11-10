# Examples you can scan

Each folder copies the shape of a real attack and is harmless: nothing in it steals, downloads or installs anything. They exist so you can see what oss-pulse says before you need it for real.

```sh
oss-pulse scan examples/take-home
```

| Folder | What it imitates | Verdict |
|---|---|---|
| [take-home](take-home) | A fake recruiter's coding test: a VS Code task runs a "font" that is JavaScript when the folder opens (Contagious Interview) | hold |
| [npm-install-hook](npm-install-hook) | A `postinstall` script that decodes and runs hidden code during `npm install` (Shai-Hulud, Nx) | hold |
| [typosquat-requirements](typosquat-requirements) | `reqeusts` and `python-dateutils` in a requirements file | hold |
| [hijackable-workflow](hijackable-workflow) | A GitHub Actions workflow a pull request can take over (Nx, Ultralytics) | hold |
| [clean-project](clean-project) | An ordinary small project | clear |

`tests/test_examples.py` checks every row of this table, and that no example contains code that reads secrets or sends data anywhere.
