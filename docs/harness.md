# The harness

The analyzer predicts what breaks on a real origin. The harness gives you a
real origin, so the predictions become observations.

```
notlocalhost init      # look at the project, write a plan, change nothing
notlocalhost up        # serve it over HTTPS on a real hostname
notlocalhost down      # put the machine back
notlocalhost doctor    # say what is true about this machine, change nothing
```

It is opt-in and separate on purpose. `notlocalhost <url>` installs nothing and
touches nothing; that is the whole reason it is safe to run without thinking.
The harness is the part that asks for something, so it asks explicitly.

---

## Two tiers, and the choice is not cosmetic

`init` picks a tier. Most people want the first one and never think about it
again.

### `--tier localhost` (the default)

Hostnames under `.localhost`, served over real HTTPS.

**Needs no administrator rights at all.** RFC 6761 reserves `localhost` as a
special-use name, so `app.myproject.localhost` resolves to loopback with no
resolver, no hosts file and no DNS. On Windows the certificate authority goes
in the per-user trust store, which Chrome and Edge honour and which needs no
elevation.

This confirms most of what the analyzer predicts:

- `Secure` cookies are actually set, instead of being silently impossible
- `SameSite=None; Secure` is actually delivered instead of dropped
- Secure-context APIs run on a name that is not `localhost`
- Mixed content is actually blocked

### `--tier test` (one prompt, once)

Hostnames under a real registrable domain — `app.myproject.test` — which needs
a line in the hosts file, and therefore one elevation prompt.

It buys exactly one thing, and nothing else:

**A parent-domain cookie scope.** `Domain=myproject.test` produces a cookie that
`app.myproject.test` and `api.myproject.test` both read. That is a real
same-site topology, and it is the only way to observe the cookie findings that
matter most — whether a session survives the move from one host to another.

We verified against Chrome that this **cannot** be done under `.localhost`, in
either direction: `Domain=localhost` from a subdomain is rejected, and
`Domain=.localhost` from bare `localhost` is accepted but stored host-only, so
it reaches nothing new. The reproduction is in
Chrome, in both directions.

So the tier choice is really one question: **do you need to see cookies cross
between subdomains?** If not, take the default and never type a password.

---

## What `up` changes, and how each part is undone

`up` prints this before it does anything, and stops unless you pass `--yes`.

| What changes | Undone by |
|---|---|
| A certificate authority, trusted for this machine | `down` removes it by its exact fingerprint and verifies it is gone from the store |
| Lines in the hosts file (`--tier test` only) | `down` removes exactly the marked block and asserts the file matches its digest from before the change |
| A proxy on ports 80 and 443 -- or whichever ports you give `up` -- while it is running | `down` stops it. Nothing is installed as a service |
| A `.notlocalhost/` directory in your project | `down --purge` deletes it |

**Only one thing can put a certificate in your trust store, and it asks first.**
Caddy's internal issuer installs its own root automatically the first time it
serves TLS, which would mean a certificate authority arriving on the machine
without anyone agreeing to it and without this tool recording it -- so `down`
would neither know to remove it nor be able to. The generated Caddyfile sets
`skip_install_trust` to prevent that. Trust is installed by one code path, only
when you asked for it, and only after the certificate has been written to the
record `down` reads.

Three things are worth knowing about how that reversal is built.

**The record of what happened is kept separately from what you asked for.**
`config.json` is intent and is safe to commit. `state.json` is debt — what was
actually done to this machine. `down` reads the second, because the two diverge
the moment something fails halfway.

**Restoration is proven, not assumed.** The hosts file's digest is recorded
before it is touched, and `down` asserts the file matches that digest
afterwards. Nothing in the existing file is normalised — not blank lines, not
line endings, not alignment — because tidying a file is itself an unrecoverable
change: removal has no way to know what was tidied away.

**If someone else edited the file while the harness was up**, `down` removes
only our block, keeps their lines, and reports the mismatch with the path to
the backup. Silently reverting someone's work and silently refusing to clean up
are both worse than saying what happened.

---

## `doctor`

More useful than `init`, because it is what you run when something has already
gone wrong.

It **changes nothing** — not a file, not a store, not a port. That is checked in
CI on every platform by digesting the hosts file before and after. It has to be
safe to run on a machine you are nervous about, because that is the machine
people run it on.

It reports four things by name, because local HTTPS breaks in exactly four
places: name resolution, certificate trust, a port already bound, and policy.

```
notlocalhost doctor
notlocalhost doctor --json     # for a script
```

It exits `1` when something is genuinely blocking, so you can branch on it.
Needing elevation is a fact about the machine, not a failure, and exits `0`.

---

## When the machine is locked down

Most documentation assumes you own your laptop. Plenty of people do not. This
section is about what actually happens then, and it is deliberately blunt:
some of it cannot be worked around, and pretending otherwise wastes your
afternoon.

### Group policy forbids installing a root certificate

On Windows, `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`
with its flag set means only administrators may add a root. `doctor` names this
case specifically rather than reporting a generic trust failure.

**This cannot be worked around locally, and you should not try.** The policy
exists because a trusted root can sign a certificate for any hostname; that is
exactly why it is worth protecting.

What still works:

- The **analyzer** works completely. It installs nothing and needs no trust.
- The harness still serves HTTPS. The certificate is real but untrusted, so the
  browser shows an interstitial you must click through on each new hostname.
  Cookie behaviour, secure contexts and mixed-content blocking are all correct
  behind that interstitial, because the browser treats the origin as HTTPS
  regardless of whether it likes the issuer.

What genuinely does not work: anything depending on a clean TLS state, and
service workers, which most browsers refuse to register on a page with a
certificate error.

Your realistic option is to ask whoever manages the machine for a development
CA, which is a normal request with a normal answer.

### You have no administrator rights

Usually fine, and better than most people expect.

- **Windows:** everything works. The per-user trust store needs no elevation,
  and Windows does not reserve ports below 1024. Only `--tier test` needs a
  prompt, for the hosts file.
- **macOS and Linux:** the certificate authority and binding ports 80 and 443
  both need elevation. Run the proxy on high ports instead — `up` accepts
  different ports — and accept that your URLs carry a port number. Everything
  the analyzer checks still holds; `https://app.myproject.localhost:8443` is
  the same origin scheme-wise as one on 443.
- On Linux, Chrome reads its own NSS database at `~/.pki/nssdb`, which needs no
  root. Chrome-only trust is available even where system-wide trust is not.

  That database is written by `certutil`, which ships **separately from the
  browser** and is missing on a lot of otherwise complete systems:

  ```
  Debian, Ubuntu   sudo apt install libnss3-tools
  Fedora, RHEL     sudo dnf install nss-tools
  Arch             sudo pacman -S nss
  ```

  Without it `up` stops at the trust step and says so, naming the package.
  Nothing is created and nothing is left behind -- the proxy is still stopped
  by `down`. The harness will also serve HTTPS without it; the certificate is
  real but untrusted, so the browser warns once per hostname.

### Port 443 is already bound

Common on Windows, where IIS or the World Wide Web Publishing Service claims it
by default, and on machines running Docker Desktop or another proxy.

`doctor` reports which port and how to find the holder:

```
netstat -ano | findstr ":443"     # Windows, then look up the PID
sudo lsof -i :443                 # macOS and Linux
```

Stop the holder, or run the harness on other ports:

```
notlocalhost up --yes --http-port 8080 --https-port 8443
```

Nothing about the analysis depends on 443 specifically. A port number in the URL
does not change the origin's scheme, so cookies, secure contexts and
mixed-content rules all behave exactly as they would on 443.

### A proxy or TLS-inspecting appliance sits in front of everything

Corporate middleboxes re-sign traffic with their own CA. That does not affect
loopback traffic, so the harness is unaffected — but it does mean your machine
already trusts an organisation-wide root, which is worth knowing when you are
weighing whether one more development root matters.

### Nothing here is irreversible

Every change is recorded and every reversal is verified. If `down` cannot undo
something, it says so, tells you which step, and gives you the exact command to
finish it by hand. The failure mode is being told, not being left with a
surprise.

---

## Honest limitations

- **The full install-and-removal cycle is proven on Linux and Windows, and not
  on macOS.** Linux runs it on every push: install, verify, remove, verify, and
  confirm the store holds exactly as many roots as before. Windows has been run
  the same way by hand. macOS has not been run anywhere.

  It is not for want of trying. Changing certificate trust settings on macOS
  raises a confirmation dialog, and a continuous-integration runner has no
  interactive session for one to appear on -- so the command does not fail, it
  waits until it is killed. The same is true of adding a root to the Windows
  per-user store, through two unrelated mechanisms. On a real desktop these
  prompt and you answer them; in a headless environment they cannot be
  answered at all.

  So on macOS, treat `down`'s report as the thing to check rather than the
  thing to trust, and look at your own keychain the first time. If it leaves
  something behind, `down` prints the exact command to remove it.

- The harness proves behaviour **on the origin it creates**. That origin is a
  faithful HTTPS origin on a real hostname, but it is not your production
  environment, and it cannot tell you anything about your CDN, your load
  balancer or your reverse proxy's own header handling.
- `--tier localhost` cannot express a parent-domain cookie scope. Not a
  limitation of this tool: nothing can, and we verified it.
- Caddy is downloaded into your project unless you already have one. It is
  checked against its published digest before it is executed, but you are still
  running a binary this tool fetched. Install Caddy yourself if you would rather
  your package manager owned that decision.
- The certificate authority is trusted for your whole user account, not just
  this project. That is how trust stores work; it is not something the harness
  chooses.
- `up` starts a proxy and returns. It is not a supervisor: if the proxy dies,
  nothing restarts it. `doctor` will tell you it is not running.
