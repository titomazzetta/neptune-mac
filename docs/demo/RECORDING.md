# Recording the demo

Maintainer notes, moved out of the README so the README can stay about the tool.
The asciinema cast is the source of truth; the GIF is rendered from it.


## How to record it (maintainer notes)

**Record the cast — this is the source of truth.**

```bash
brew install asciinema agg

# -i 2 caps dead air at 2s. A real ./neptune.sh run spends minutes inside
# lsof sweeps, mdls, traceroute and `brew update`; without this the demo is
# 90% waiting. --cols/--rows keep it legible when scaled down in a README.
asciinema rec docs/demo/neptune-demo.cast \
  -i 2 --cols 100 --rows 30 \
  -c "./scripts/neptune.sh"
```

**Scrub it before committing.** This is the step that matters. A live Neptune
run prints your hostname, your username in every `/Users/...` path, your gateway
and LAN addresses, your full installed-app inventory, and every open listener
port on the machine — a tidy reconnaissance profile of your own Mac. The cast is
plain JSON, so it can be read and sed'd before it ever leaves the machine:

```bash
less docs/demo/neptune-demo.cast          # actually read it
sed -i '' -e "s/$(hostname -s)/demo-mac/g" \
          -e "s|/Users/$USER|/Users/demo|g" \
          docs/demo/neptune-demo.cast
```

Then re-read it and check the addresses by eye. Use the same placeholder
conventions as `docs/sample-report.txt` so the two artifacts agree. Recording on
a scratch user account avoids most of this.

**Generate the inline GIF from the cast** — derived, never recorded separately,
so the two can't drift:

```bash
agg docs/demo/neptune-demo.cast docs/demo/neptune-demo.gif --font-size 14
```

**Then** uncomment the embed block in the README and fill in the asciinema ID (or drop
the badge line entirely and ship GIF-only — see the trade-off below).

**Keep it short.** Target 45–90 seconds. If a full suite run won't compress into
that, record a single scan (`./scripts/redflag_scan.sh`) plus the final digest
instead — one scan that clearly finds something beats five that scroll past.




## Why both formats (asciinema vs GIF)

Record **asciinema, publish both** — the GIF generated from the cast.

**GitHub will not render an asciinema player inline.** The badge is a clickable
thumbnail that navigates off-site. Since the stated reason for having a demo is
that reviewers skim, a demo behind a click is a demo most of them won't watch. A
GIF autoplays in the README and costs zero clicks. That alone settles the
*embed* question in the GIF's favor.

But the GIF is a bad *source* artifact: several MB of pixels in a repo that's
otherwise 2,600 lines of readable text, with no selectable output, no diff, and
no way to confirm what it leaks without watching it frame by frame. The `.cast`
is JSON — small enough to sit in the repo permanently, diffable, greppable, and
**auditable before publishing**, which is the whole reason the scrub step above
is even feasible. For a tool whose pitch is "it's all bash you can read," an
opaque binary blob as the only demo artifact is off-message.

So: cast is the source, GIF is the render, `agg` regenerates one from the other.
The skimmer gets autoplay; the reviewer gets something they can verify; and the
artifact you have to trust is the one you can read.

**If you only want to maintain one:** ship the GIF. Inline beats auditable when
the audience is a hiring manager with thirty seconds — just keep it under ~3 MB
and scrub the terminal contents before recording rather than after.



