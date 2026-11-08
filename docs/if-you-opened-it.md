# If you already opened it

oss-pulse said hold, but you had already opened the folder in VS Code, trusted it, or ran `npm install`, `pip install` or the project itself. Assume the code ran. These steps are in order of urgency; do the first ones from a different device if you can.

## Right away

1. Disconnect the machine from the network (Wi-Fi off, cable out). This stops anything still running from sending more data.
2. From another device, move cryptocurrency out of any wallet that was on the machine, browser extension wallets included (MetaMask, Phantom and others). Use a new wallet whose recovery phrase was never on that machine. Fake job interviews that run code on open are usually after wallets.
3. From another device, sign out of all sessions and change passwords for email, GitHub, cloud accounts (AWS, Azure, Google Cloud) and your password manager. Turn on two-factor authentication where it is off.

## Next, before you use the machine again

4. Revoke and replace keys and tokens that were on it: SSH keys (`~/.ssh`), GitHub and npm tokens, cloud credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`), `.env` files and anything in `~/.npmrc`, `~/.pypirc` or `~/.docker/config.json`.
5. Browsers save passwords, cookies and sessions on disk. Treat every saved password as known to someone else and change the important ones.
6. The safest fix for the machine is to back up your documents (not programs or scripts), wipe it and reinstall the operating system. Malware from these campaigns often installs itself to start again at login.

## Report it

7. If it came through a job offer, report the posting on the site where you found it (LinkedIn, Upwork, the job board), and tell the company it claims to come from: they may not know their name is being used.
8. If you work for a company and used a work machine or work credentials, tell your security team now. They would rather hear it early.
9. Help others: report the repository to GitHub (the "Report repository" link on its page) and, if a package was involved, to the registry (PyPI's "Report project as malware").

## What oss-pulse can't tell you

oss-pulse reads files; it does not look at what is running on your machine. A clean scan of the folder afterwards does not mean nothing happened, because the code may have downloaded more code that isn't in the folder. If in doubt, follow the steps above.
