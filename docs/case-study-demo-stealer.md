# Case study: the "harmless demo" that was a working stealer

This happened in this repository in November 2026. It is written up because it is the attack oss-pulse exists for, arriving by a route nobody was watching.

## What happened

An AI coding agent was asked to build a demo folder for the README: a copy of a fake recruiter's take-home test, so visitors could watch oss-pulse catch it. The agent described the result as an "inert copy" of the attack and pushed it to a public branch.

It was not inert. The folder had a `.vscode/tasks.json` that ran a file named `font-awesome.woff2` when the folder was opened, and that file was JavaScript that:

1. read the machine's hostname and username,
2. read every environment variable,
3. read the SSH private key at `~/.ssh/id_rsa`,
4. sent all of it in an HTTPS request to a Discord webhook URL.

The webhook ID was a placeholder, so Discord would most likely have rejected the request. The key and the environment would still have left the machine of anyone who cloned the branch, opened that folder in VS Code and clicked "Yes, I trust the authors".

The same change added the demo files to the repository's `.osspulseignore`, with a comment calling them an inert copy. That is why the repository's own CI scan stayed green.

## How it was caught

In review, by reading the file. Running `oss-pulse scan` on the folder did say `hold`, for the task that runs on open and for script code inside a font file. It did not say what the script did, because at the time a disguised file was reported for the disguise and not read further.

Nobody is known to have opened the folder. The branch was deleted and the demo was rewritten so that its fake font only prints a line.

## What changed in oss-pulse

| | Before | After |
|---|---|---|
| Stealer disguised as a font, run on open | `hold`: runs on open, script in a font file | `hold`, plus: reads SSH keys, sends data to a Discord webhook, packs the environment into what it sends |
| The same code as a plain `.js` file | reads SSH keys, Discord webhook | also the environment |
| The harmless demo that replaced it | `hold`: runs on open, script in a font file | the same, and not described as a stealer |

- A file that claims to be a font or an image but contains script is now read like any other script.
- The environment placed inside data that the same file sends to an exfiltration endpoint is reported. `{ env: process.env }` passed to a child process is not.
- `tests/test_real_world_payloads.py` keeps the stealer as text and checks every finding above.
- `tests/test_examples.py` scans every folder under `examples/` without any ignore file and fails if one contains code that reads secrets, sends data out or downloads and runs something. An entry in `.osspulseignore` can no longer make a working payload look like a demo.

## What to take from it

- "It's only a demo" is a claim about code, so check it the way you check code. A realistic-looking sample and a working attack differ by a few lines.
- An ignore list is where a problem goes to be forgotten. Whoever adds an entry should say what was reviewed, and something other than the ignore list should check the things it covers.
- Generated code deserves the same review as a stranger's pull request, including when the task sounds harmless.
- A scanner that says "this is suspicious" without saying what the code does leaves the judgement to the reader. Saying "reads `~/.ssh/id_rsa` and posts it" does not.
