# Setup & contributor notes

How to clone, run, and push Neptune — including the setup gotchas hit during
development, so nobody has to rediscover them.

## Run it (users)

```bash
git clone https://github.com/titomazzetta/neptune-mac.git
cd neptune-mac/scripts
./neptune.sh          # full read-only suite → one report on your Desktop
./neptune.sh --html   # ...plus the readable report (needs the Command Line Tools)
```

Downloaded a release tarball instead of cloning? Verify it first, then clear
the quarantine flag the browser added:

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify neptune-mac-v1.0.0.tar.gz --repo titomazzetta/neptune-mac
xattr -dr com.apple.quarantine neptune-mac-v1.0.0
```

Never run these with `sudo`. They prompt for elevation only where needed and
refuse to run as root on purpose.

## Develop it (contributors / agents)

```bash
git clone git@github.com:titomazzetta/neptune-mac.git   # SSH
# or: git clone https://github.com/titomazzetta/neptune-mac.git   # HTTPS
cd neptune-mac
./tests/lint.sh       # mirrors CI: syntax, shellcheck, bash 3.2 gates, guardrails,
                      # python tests, blast radius, unit tests
./tests/macos.sh      # on a Mac: the platform assumptions (bash 3.2, BWK awk, codesign)
./scripts/neptune.sh --replay tests/fixtures/findings-2026-09-18.txt --html --out /tmp/np
                      # render a real run without scanning anything
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

Every push to `main` and every PR runs `.github/workflows/ci.yml`:

- **Linux:** `tests/lint.sh` — everything above.
- **Workflows:** actionlint, and a gate that every action is pinned to a commit SHA.
- **macOS:** the unit, blast-radius and renderer suites under `/bin/bash` 3.2 and
  BWK awk, `tests/macos.sh`, and a real end-to-end `neptune.sh --html --json
  --sanitize` run on the runner, checked by `tests/e2e_assert.py`. The sanitized
  report is uploaded as a build artifact.

Tagging `vX.Y.Z` runs `.github/workflows/release.yml`: the tests again, then a
tarball, `SHA256SUMS`, a signed build-provenance attestation, and the GitHub
release. The tag must match `NEPTUNE_VERSION` and have a `CHANGELOG.md` section.

Get it green locally with `./tests/lint.sh` before pushing.

## Auth is never committed

SSH keys, tokens, and `gh` sessions live on your machine, never in this repo.
Nothing here contains credentials, and nothing should.
