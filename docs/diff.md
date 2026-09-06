# The parity diff

The analyzer says a thing will break on a real HTTPS origin. The harness gives
you a real HTTPS origin. This answers the only question that matters about a
prediction: **did it happen?**

```
notlocalhost http://localhost:3000 --json before.json
notlocalhost up --yes
notlocalhost https://app.myproject.localhost --json after.json
notlocalhost down

notlocalhost diff before.json after.json
```

Two documents in, one out. No browser, no project, no network — so it is fast,
and it runs anywhere the reports do, including a CI job that never had a
browser.

---

## What it tells you

Five categories, printed in the order they matter.

### Whether the two runs can be compared at all

First, not in a footnote. A diff between a thorough run and a shallow one is a
list of things the second did not look at, and dressing that up as progress is
the failure this whole project is about.

It says so when the runs used different schema versions, when only one used
`--flow`, when one recorded no requests, or when the request counts differ by
more than half. Everything below inherits that doubt.

### What localhost was hiding

Present on the real origin, absent locally. **Nothing else in the document is
news.** Mixed content that loads happily on `http://localhost` and is blocked
on HTTPS shows up here, and it is the reason the harness exists.

### Predicted, then observed

A prediction and its confirmation are not the same finding. Locally the tool
derives the defect from a header — `cookie.samesite-none-without-secure`. On the
real origin Chrome refuses the cookie and it is reported as an observation —
`cookie.rejected-by-browser`. Those are one event seen twice, and subtracting
one list from the other would report a prediction "resolved" at the exact moment
it came true.

**A confirmation has to be news.** Chrome refuses a `SameSite=None` cookie on
localhost as readily as on a real origin, so that rejection is often present in
both runs. Counting it would claim the real origin revealed something it did
not, so an observation that was already there is reported as unchanged instead.

### Unchanged by the move to HTTPS

Still broken, and HTTPS was never going to fix it. A severity that changed
between runs is noted.

### Gone — and whether that means anything

Split in two, because the difference is the whole point:

- **with no observation to explain it** — either the move fixed it, or this run
  did not reach the code that produced it. A finding can vanish because nothing
  looked, so this is stated as a question rather than a win.
- **never about your application** — the port-sharing hazard exists because
  every port on localhost shares one cookie jar. A real origin has its own.
  Its absence afterwards is arithmetic, and claiming it as a fix would be
  flattery. Each one is listed with the reason it cannot apply.

---

## Exit code

`0` unless something appeared **only** on the real origin, at or above
`--fail-on` (default `will-break`).

Confirmations do not fail a build. The analyzer already reported those, and a
pipeline should not break twice for one defect. What fails a build is a defect
the developer has not seen before.

```
notlocalhost diff before.json after.json --fail-on may-break
notlocalhost diff before.json after.json --json parity.json --quiet
```

---

## How findings are matched

By rule id **and subject** — the cookie name, origin or URL the finding is
about. Two `cookie.missing-secure` findings about different cookies are
different findings, and one rejected cookie confirms the prediction about that
cookie and no other.

A report containing a finding with no id, or a severity the tool does not know,
is refused up front and names which of the two documents it came from. The
alternative is a crash several screens later with no clue where the bad
document originated.

---

## Honest limitations

- **It compares two runs, not two worlds.** Both inherit every limitation of
  the analyzer: coverage of findings equals coverage of the run.
- **Differences are evidence, not proof.** The comparability check catches the
  crude mismatches — a missing `--flow`, a run that loaded almost nothing. It
  cannot tell that two runs of similar size visited different routes.
- **A category is only as good as its list.** Findings that cannot occur on a
  real origin are recognised from a fixed list. A rule added later without an
  entry will show up as "gone, with no observation to explain it" rather than
  as not applicable — which is the safe direction to be wrong in, but it is
  still wrong.
- **The confirmation map is hand-written.** It knows which observations confirm
  which predictions. A new prediction with no entry will be reported as
  unexplained rather than confirmed.
