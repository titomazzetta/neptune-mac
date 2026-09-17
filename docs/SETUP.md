# Setup & contributor notes

How to clone, run, and push Neptune — including the setup gotchas hit during
development, so nobody has to rediscover them.

## Run it (users)

```bash
git clone https://github.com/titomazzetta/neptune-mac.git
cd neptune-mac/scripts
chmod +x *.sh
xattr -d com.apple.quarantine *.sh 2>/dev/null   # only if macOS quarantines them

./neptune.sh          # full read-only suite → one report on your Desktop
```

Never run these with `sudo`. They prompt for elevation only where needed and
refuse to run as root on purpose.

## Develop it (contributors / agents)

```bash
git clone git@github.com:titomazzetta/neptune-mac.git   # SSH
# or: git clone https://github.com/titomazzetta/neptune-mac.git   # HTTPS
cd neptune-mac
./tests/lint.sh       # mirrors CI: shellcheck + syntax + bash 3.2 gate
```

Read `CLAUDE.md` (rules), `docs/PHILOSOPHY.md` (vision), and `docs/DEVLOG.md`
(engineering history) before changing code.

## Pushing — the gotchas (learned the hard way)

These tripped up the initial setup; documented so they don't again.

- **Branch name.** The repo uses `main`, and CI triggers on `main`. If your local
  default is `master`, rename before the first push: `git branch -M main`.

- **SSH vs HTTPS auth.** Pick one and make git match it:
  - **SSH:** the key must be registered with GitHub (`gh ssh-key add
    ~/.ssh/id_rsa.pub --title "<machine>"`) *and* loaded in the agent
    (`ssh-add ~/.ssh/id_rsa`). Test with `ssh -T git@github.com` — success prints
    "Hi <user>!". If the remote is SSH, the URL looks like
    `git@github.com:titomazzetta/neptune-mac.git`.
  - **HTTPS:** password auth does NOT work (GitHub removed it). Either use a
    Personal Access Token as the password, or — simplest — run
    `gh auth setup-git` once to wire your `gh` login into git as a credential
    helper. HTTPS remote URL: `https://github.com/titomazzetta/neptune-mac.git`.
  - Switch a remote between the two with:
    `git remote set-url origin <url>`

- **`gh repo create` uses SSH by default.** If you authenticated `gh` over HTTPS,
  the auto-added remote will fail to push until you either register an SSH key or
  switch the remote to HTTPS (above).

- **Quarantine flag.** Files downloaded via browser get
  `com.apple.quarantine` and macOS may block execution. Clear with
  `xattr -d com.apple.quarantine <file>`. (Cloned-via-git files are not
  quarantined — this only affects zip/browser downloads.)

## CI

Every push to `main` (and every PR) runs `.github/workflows/ci.yml`:
shellcheck (`--severity=warning`), `bash -n` syntax checks, a bash-3.2
compatibility gate, and a guard that the destructive scripts still contain their
confirmation prompts. Get it green locally with `./tests/lint.sh` before pushing.

## Auth is never committed

SSH keys, tokens, and `gh` sessions live on your machine, never in this repo.
Nothing here contains credentials, and nothing should.
