# Security policy

oss-pulse inspects code written by attackers, so bugs in oss-pulse itself can be security problems. Please report these privately:

- a way for a scanned folder or package to change, hide or suppress findings;
- a way to make oss-pulse execute code from what it scans;
- output injection into terminals, CI logs or PR comments;
- anything that sends data to a host the documentation doesn't name.

Report through GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"). Please don't open a public issue for these.

Missed detections and false positives are not vulnerabilities. Open a normal issue for those.

Only the latest commit on `main` is supported until the first release.
