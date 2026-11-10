# oss-pulse demo: a workflow a pull request can take over

Not a real project, and GitHub doesn't run workflows from this subfolder. The workflow runs on `pull_request_target` (which has the repository's secrets), checks out the pull request's own code, and puts the pull request title into a shell command. Those are the patterns behind the Nx (2025) and Ultralytics (2024) compromises.

```sh
oss-pulse scan examples/hijackable-workflow
```
