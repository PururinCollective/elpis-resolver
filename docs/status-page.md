# 📊 Status page

A read-only web interface showing what the resolver is doing. Off by default;
two lines switch it on:

```
webgui: yes
webgui-password: choose-something
```

Then open `http://127.0.0.1:8082/`.

**On this page:**
[What it shows](#-what-it-shows) ·
[Which build](#-knowing-which-build-you-are-looking-at) ·
[ML-DSA](#-ml-dsa-active-and-available) ·
[What the browser remembers](#-what-the-browser-remembers) ·
[Host addresses](#-where-the-host-addresses-come-from) ·
[Reaching it safely](#-reaching-it-safely) ·
[The password](#-the-password) ·
[What it cannot do](#-what-it-cannot-do)

## 🪟 What it shows

Windows open from the desktop icons. Drag them by the title bar, resize from
the bottom-right grip, tile them from the toolbar.

<sub>A window whose content doesn't fit grows to show it, as far as the desktop
allows; once you size a window yourself it keeps the size you gave it. The
desktop you leave is the desktop you come back to: which windows are open,
where, how big, which is in front and which Task Manager pane was showing are
all remembered by the browser. **Reset** in the toolbar forgets the lot.</sub>

| | |
|---|---|
| **Task Manager** | CPU, memory, network and queries in one window: a rail of live sparklines on the left, the one you pick drawn large on the right |
| **Overview** | cache hit rate, response time from cache and upstream, queries and SERVFAIL per second, every counter the resolver keeps (queries over DoT among them), and how this host looks from outside: public IPv4 and IPv6, AS number and name |
| **CPU** | processor time as a share of one core, the CPU model, the worker count, which SIMD kernels were selected, the compiler and the CPU the binary was built for, and how long the resolver and the machine have been up |
| **Memory** | resident size over time against the memory the resolver may use (so the line reads as a share of the ceiling, not of its own peak), and each cache's entries, bytes, budget and hit rate |
| **Network** | bytes in and out per second, and the addresses actually bound |
| **Queries** | queries per second, SERVFAIL and bogus per second, cache hits against upstream queries |
| **Root servers** | the roots ranked by the round trip this resolver has actually measured, with how often each was asked and how often it failed to answer |
| **Top names** | most queried, those ending in SERVFAIL, those failing DNSSEC validation |
| **Top clients** | busiest clients, clients handed SERVFAIL, clients asking for bogus names, and upstream servers that stopped answering |
| **Held servers** | servers held down by `server-hold-down`: the zone, the question types held, a countdown to the next try, how long it's been silent, how many lookups in the zone were turned away, and the client and name whose query set the hold off (and the latest one, when different). A server that answers again stays listed for ten minutes, marked as answering. See [a zone whose servers never answer](troubleshooting.md#-a-zone-whose-servers-never-answer) |
| **DoT servers** | DNS over TLS to authoritative servers (`authoritative-dot`): servers available, failed and given up, connections open, and the share of upstream queries answered over DoT; tests started and answered; why tests failed (refused, no reply, closed, no X25519, no TLS 1.3, ALPN refused, other TLS errors); queries and answers over DoT, plain resends after no reply, handshakes. Then the servers that answered over DoT, most answers first: zone, where each stands now (available and for how long, or failed and when the next retry is due), last handshake time, cipher suite, last used |
| **Log** | recent warnings and errors, newest first; it keeps the size you give it and holds your scroll position while new entries arrive |
| **About** | the version and release name, edition and operator, the commit and compiler it was built with and the CPU it was built for, uptime, and which ML-DSA parameter sets are live |
| **Layout** | the desktop as one line, to carry an arrangement to another browser |

**The counts are exact, not sampled.**

<sub>Sampling was tried first and is useless here: a resolver answering a few
hundred queries a second gives too few samples to rank anything, which is
exactly when someone is looking. What makes counting every query affordable is
that the tables are keyed on the hashed wire name and raw client address: a
name is turned into characters once, the first time it's seen, and every query
after that finds the slot by hash and adds one.</sub>

> [!NOTE]
> Counting still costs something, so nothing is counted at all while
> `webgui: no`.

## 🔖 Knowing which build you are looking at

The About window carries the version, the release name, and the commit `make`
built from:

```
version   2.4.0
release   Intrinsic Future
build     v2.4.0
```

| Built from | build reads |
|---|---|
| a release tag | `v2.4.0` |
| any other commit | branch and commit, `main@bcc97d252fac` |
| a tarball, no git | *not a git checkout* |

Quote it in a bug report and there's no ambiguity about what was running.

<sub>The same facts are available without logging in, over DNS, to a client
the access-control list admits. See
[asking a resolver what it is](configuration.md#-asking-a-resolver-what-it-is):
`nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1`</sub>

## 🧬 ML-DSA, active and available

All three ML-DSA verifiers are always compiled in. About reports whether the
DNSSEC algorithm number each answers to means anything to anyone else:

| | |
|---|---|
| **active** | the number is one others use too. `draft-westerbaan-dnssec-mldsa` assigns 18 to ML-DSA-44, and the deployed test zones sign with it |
| **available** | built in and ready, but on a placeholder in unassigned space that's interoperable with nothing |

<sub>The draft registers no number for ML-DSA-65 and ML-DSA-87, so they default
to placeholders and read *available*. Override one (`mldsa65-algorithm: 25`)
and it reads *active*, because setting it can only mean the number has been
agreed with whoever is on the other end.</sub>

## 💾 What the browser remembers

The window layout and the light/dark choice live in the browser's
`localStorage`, never in a cookie, and **nothing about the layout ever reaches
the server.**

<sub>The page asks `/api/status` for a fresh snapshot every second, and a cookie
would ride along on every one of those requests, uploading window coordinates
to a resolver that has no use for them.</sub>

| | so |
|---|---|
| **It's per origin** | the same resolver through an SSH tunnel at `127.0.0.1:8082` and directly at `[fd00:1::53]:8082` gives you two independent desktops |
| **It's per browser** | no account behind it: the layout doesn't follow you to another machine, and a private window starts on the defaults every time |

- **Carrying a layout across:** the **Layout** window prints the arrangement as
  one line, which the same window in another browser takes back. The text is
  made and read entirely in the browser and never sent anywhere.
- **Storage blocked?** A private window, site data blocked: the page opens on
  its defaults and simply doesn't remember. Nothing breaks.
- **A big-screen layout on a small screen** is fitted to the desktop it finds:
  windows shrink to fit and are pulled back on screen, each remembering the
  size it would rather be, so widening the browser gives it back.

## 🌐 Where the host addresses come from

| field | from |
|---|---|
| public IPv4 and IPv6 | the addresses the kernel picks to leave the box by |
| AS number and name | Team Cymru's origin lookup, resolved through this resolver's own recursion like any other query, refreshed hourly |

<sub>Until the answer arrives the fields read *looking up...*; on a host with
no route out they stay that way.</sub>

The **root server ranking** is the resolver's live opinion, from the same
infrastructure cache it uses to decide who to ask next, not a startup probe.

<sub>A root it hasn't had occasion to ask yet is listed as *not asked yet*,
rather than shown with the optimistic starting estimate, which isn't a
measurement.</sub>

## 🔐 Reaching it safely

The page speaks plain HTTP and binds loopback. Three ways to reach it, least
work first:

```
 1. SSH tunnel      your browser ──ssh -L 8082──────────────► resolver  127.0.0.1:8082
 2. VPN             your browser ──VPN──────────────────────► resolver  [fd00:1::53]:8082
 3. reverse proxy   your browser ──HTTPS──► nginx / apache ──► resolver  127.0.0.1:8082
```

> [!NOTE]
> Elpis carries a TLS client, for
> [DNS over TLS to authoritative servers](configuration.md#-dns-over-tls-to-authoritative-servers),
> but no TLS server, and it shouldn't have one. Terminating TLS means a
> certificate parser and a private key in the address space of the process
> answering DNS: a lot of attack surface to add for a status page.

### 1. SSH tunnel

Nothing to configure, and the encryption is already there.

```bash
ssh -L 8082:127.0.0.1:8082 user@resolver
```

Then `http://127.0.0.1:8082/` on your own machine.

### 2. Over a VPN

Put the VPN address in `webgui-listen`, and keep the port off every other
interface:

```
webgui-listen: [fd00:1::53]@8082
```

### 3. Behind a reverse proxy

The one to use for a real certificate, and it shares the one you already have:

```nginx
location / {
    proxy_pass http://127.0.0.1:8082;
    proxy_set_header Host $host;
}
```

<sub>nginx holds the key, Elpis stays on loopback, and the certificate is the
same one the rest of the host uses. Nothing has to be copied or kept in
step.</sub>

It doesn't need the whole host. Mounted under a path of its own (Apache here):

```apache
ProxyPass /elpis/ http://127.0.0.1:8082/
```

<sub>Every request the page makes is relative to the address it was loaded
from, and the session cookie is scoped to that path, so Elpis never needs to
know the prefix and never hands its session to the rest of the host. Mounting
it without the trailing slash, `ProxyPass /elpis http://127.0.0.1:8082`, works
too.</sub>

## 🔑 The password

| config | what happens |
|---|---|
| neither set | user `admin`, password generated at startup and printed to stderr, once |
| plaintext password | hashed with PBKDF2-SHA256, and the config is rewritten so the plaintext doesn't survive the first start |
| already a hash | used as it is |

The generated password is printed like this, only this once:

```
WARN  status page: no webgui-password set, generated one for user 'admin': 93c48e3c9819a6fc21d7a1f3
WARN  status page: this is printed once -- put it in the config to keep it, or it changes on the next restart
```

<sub>Rewriting the config is best effort. It's written to a temporary file and
renamed, so a failure part way can't leave a truncated config behind. If the
file can't be written at all, the hash is still what's used, and you're told
the plaintext is still on disk.</sub>

### When the config cannot be rewritten

```
WARN  status page: /opt/elpis-resolver/bin/elpis.conf is not writable, so the
      password stays in plaintext on disk (it is hashed in memory)
WARN  status page: hash it yourself and paste the result in --
      /opt/elpis-resolver/bin/elpis --hash-password
```

> [!IMPORTANT]
> Under the shipped systemd unit this is expected, and **`chown` won't fix it.**
> `ProtectSystem=strict` and `ReadOnlyPaths=/opt/elpis-resolver/bin` make the
> install read-only *inside the service's mount namespace*, whatever the file's
> owner and mode say. (That's why `runuser -u elpis -- touch` in the same
> directory succeeds: it runs outside that namespace.)

This is the right way round: a resolver that can't rewrite its own config is
one whose config a compromise of it can't rewrite either. So hash the password
somewhere the sandbox isn't:

```bash
/opt/elpis-resolver/bin/elpis --hash-password
```

It reads one line from stdin, so the password stays out of your shell history,
and prints a line to paste in:

```
webgui-password: $pbkdf2-sha256$120000$19fabb8f...$89b97ecc...
```

Paste it, restart, and there's nothing left to rewrite and no warning.

<sub>A password can also be given as an argument,
`elpis --hash-password 'secret'`: convenient in a provisioning script, careless
at a shell prompt. Adding `ReadWritePaths=/opt/elpis-resolver/bin` to the unit
so the rewrite succeeds once trades a permanent hole for a one-time
convenience, and isn't recommended.</sub>

**Login safety:** the password and the user name are both checked in constant
time, so neither can be probed by timing. Sessions are 32 random bytes in an
`HttpOnly`, `SameSite=Strict` cookie, and last eight hours.

## 🚫 What it cannot do

**There is no endpoint that writes anything.** The resolver can't be
reconfigured, flushed, or made to resolve anything from this page. The only
routes are the page itself, a login, a logout, and one JSON snapshot.

<sub>It runs on its own thread, serving one connection at a time, with a hard
timeout on every socket and a cap on request size. A client that opens a
connection and never finishes its request ties up the page for a few seconds
and nothing else: during exactly that, the resolver answered 20 of 20 test
queries in 0.2 seconds.</sub>

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
