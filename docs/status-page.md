# Status page

A read-only web interface showing what the resolver is doing. It is off by
default; two lines switch it on:

```
webgui: yes
webgui-password: choose-something
```

Then open `http://127.0.0.1:8082/`.

## What it shows

Windows open from the desktop icons. They can be dragged by the title bar,
resized from the grip in the bottom right corner, and tiled from the toolbar.
A window whose content does not fit grows to show it, as far as the desktop
allows; once you size a window yourself it keeps the size you gave it.

The desktop you leave is the desktop you come back to: which windows are open,
where, how big, which is in front and which Task Manager pane was showing are
all remembered by the browser. **Reset** in the toolbar forgets the lot and
puts the defaults back.

| | |
|---|---|
| **Task Manager** | CPU, memory, network and queries in one window — a rail of live sparklines on the left, the one you pick drawn large on the right |
| **Overview** | cache hit rate, response time answered from cache and resolved upstream, queries and SERVFAIL per second, every counter the resolver keeps, and how this host looks from outside: public IPv4 and IPv6, AS number and AS name |
| **CPU** | processor time as a share of one core, the processor's model name, the worker count, which SIMD kernels were selected, the compiler and the CPU the binary was built for, and how long both the resolver and the machine under it have been up |
| **Memory** | resident size over time against the memory the resolver may use, so the line reads as a share of the ceiling rather than of its own peak, and each cache's entries, bytes used, budget and hit rate |
| **Network** | bytes in and out per second, and the addresses actually bound |
| **Queries** | queries per second, SERVFAIL and bogus per second, cache hits against upstream queries |
| **Root servers** | the roots ranked by the round trip this resolver has actually measured, with how often each was asked and how often it failed to answer |
| **Top names** | most queried, those ending in SERVFAIL, those failing DNSSEC validation |
| **Top clients** | busiest clients, clients being handed SERVFAIL, clients asking for bogus names, and upstream servers that stopped answering |
| **Log** | the recent warnings and errors, newest first; it keeps the size you give it and holds your scroll position while new entries arrive |
| **About** | edition and operator, version, the commit and compiler the binary was built with and the CPU it was built for, uptime, and which ML-DSA parameter sets are live |
| **Layout** | the desktop as one line, to carry an arrangement to another browser |

The counts are exact, not sampled. Sampling was tried first and it is useless
here: a resolver answering a few hundred queries a second gives too few samples
to rank anything, and that is precisely when someone is looking at the page.
What makes counting every query affordable is that the tables are keyed on the
hashed wire name and raw client address — a name is turned into characters once,
the first time it is seen, and every query after that finds the slot by hash and
adds one.

That still costs something, so nothing is counted at all while `webgui: no`.

## Knowing which build you are looking at

The About window carries the commit the binary was built from, captured by
`make` and shown next to the version:

```
version   1.0.0
build     b7d28e0ea6c9
```

A `-dirty` suffix means the working tree had uncommitted changes when it was
built, so the commit alone does not describe the binary. Built outside a git
checkout — from a release tarball — the field reads *not a git checkout*.
Quote this line in a bug report and there is no ambiguity about what was
running.

The same facts are available without logging in, over DNS, from a client the
access-control list admits — see
[asking a resolver what it is](configuration.md#asking-a-resolver-what-it-is):

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

## ML-DSA, active and available

All three ML-DSA verifiers are compiled in unconditionally, so what About
reports is not whether the code exists but whether the DNSSEC algorithm number
it answers to means anything to anyone else:

| | |
|---|---|
| **active** | the number is one others use too. `draft-westerbaan-dnssec-mldsa` assigns 18 to ML-DSA-44 and the deployed test zones sign with it |
| **available** | built in and ready, but sitting on a placeholder in unassigned space that is interoperable with nothing |

The draft registers no number for ML-DSA-65 and ML-DSA-87, so they default to
placeholders and read *available*. Override one — `mldsa65-algorithm: 25` —
and it reads *active*, because setting it can only mean the number has been
agreed with whoever is on the other end.

## What the browser remembers

The window layout and the light/dark choice live in the browser's
`localStorage`, not in a cookie. The page asks `/api/status` for a fresh
snapshot every second, and a cookie would be attached to every one of those
requests — uploading window coordinates to a resolver that has no use for
them. Nothing about the layout ever reaches the server.

Two consequences worth knowing:

*It is per origin.* Reaching the same resolver through an SSH tunnel at
`127.0.0.1:8082` and directly at `[fd00:1::53]:8082` gives you two independent
desktops, because the browser treats them as two different sites.

*It is per browser.* There is no account behind it, so the layout does not
follow you to another machine, and a private window starts on the defaults
every time. The **Layout** window is the way across: it prints the whole
arrangement as one line, which the same window on another browser will take
back. The text is produced and read entirely in the browser and is never sent
anywhere.

If storage is unavailable — a private window, site data blocked — the page
opens on its defaults and simply does not remember. Nothing breaks.

A layout saved on a large screen and reopened on a small one is fitted to the
desktop it finds: windows are shrunk to what will fit and pulled back on
screen, and each remembers the size it would rather be, so widening the browser
gives it back.

## Where the host addresses come from

The public IPv4 and IPv6 on the Overview are the addresses the kernel picks to
leave the box by, and the AS number and name come from Team Cymru's origin
lookup — resolved through this resolver's own recursion, like any other query,
and refreshed once an hour. Until the answer arrives the fields read
*looking up...*; on a host with no route out they stay that way.

The root server ranking is the resolver's live opinion, taken from the same
infrastructure cache it uses to decide who to ask next — not a startup probe.
A root it has not had occasion to ask yet is listed as *not asked yet* rather
than shown with the optimistic starting estimate, which is not a measurement.

## Reaching it safely

The page speaks plain HTTP and binds loopback. There is no TLS in the resolver
and there should not be: terminating TLS means a TLS stack, a certificate
parser and a key in the address space of the process answering DNS, which is a
great deal of attack surface to add for a status page. Three ways to reach it,
in order of how little work they are:

**SSH tunnel** — nothing to configure, and the encryption is already there.

```bash
ssh -L 8082:127.0.0.1:8082 user@resolver
```

Then `http://127.0.0.1:8082/` on your own machine.

**Over a VPN** — put the VPN address in `webgui-listen`, and keep the port off
every other interface:

```
webgui-listen: [fd00:1::53]@8082
```

**Behind a reverse proxy** — this is the one to use if you want a real
certificate, and it shares the certificate you already have:

```nginx
location / {
    proxy_pass http://127.0.0.1:8082;
    proxy_set_header Host $host;
}
```

nginx holds the key, Elpis stays on loopback, and the certificate is the same
one the rest of the host uses. Nothing has to be copied or kept in step.

## The password

| config | what happens |
|---|---|
| neither set | user `admin`, password generated at startup and printed to stderr, once |
| plaintext password | hashed with PBKDF2-SHA256, and the config file is rewritten so the plaintext does not survive the first start |
| already a hash | used as it is |

The generated password is printed like this, and only this once:

```
WARN  status page: no webgui-password set, generated one for user 'admin': 93c48e3c9819a6fc21d7a1f3
WARN  status page: this is printed once -- put it in the config to keep it, or it changes on the next restart
```

Rewriting the config is best effort. It is written to a temporary file and
renamed, so a failure part way cannot leave a truncated config behind; if the
file cannot be written at all, the hash is still what gets used and you are
told the plaintext is still on disk.

### When the config cannot be rewritten

```
WARN  status page: /opt/elpis-resolver/bin/elpis.conf is not writable, so the
      password stays in plaintext on disk (it is hashed in memory)
WARN  status page: hash it yourself and paste the result in --
      /opt/elpis-resolver/bin/elpis --hash-password
```

Under the shipped systemd unit this is expected, and it is not a permissions
problem — `chown` will not fix it. `ProtectSystem=strict` and
`ReadOnlyPaths=/opt/elpis-resolver/bin` make the install read-only *inside the
service's mount namespace*, whatever the file's owner and mode say. That is why
`runuser -u elpis -- touch` in the same directory succeeds: it runs outside
that namespace.

This is the right way round. A resolver that cannot rewrite its own config is a
resolver whose config a compromise of it cannot rewrite either. So hash the
password somewhere the sandbox is not:

```bash
/opt/elpis-resolver/bin/elpis --hash-password
```

It reads one line from stdin — so the password stays out of your shell history
— and prints a line to paste in:

```
webgui-password: $pbkdf2-sha256$120000$19fabb8f...$89b97ecc...
```

Put that in the config, restart, and there is nothing left to rewrite and no
warning. A password can also be given as an argument,
`elpis --hash-password 'secret'`, which is convenient in a provisioning script
and careless at a shell prompt.

The alternative — adding `ReadWritePaths=/opt/elpis-resolver/bin` to the unit
so the rewrite succeeds once — trades a permanent hole for a one-time
convenience. It is not recommended.

Passwords are checked in constant time, and so is the user name, so neither can
be probed by timing. Sessions are 32 random bytes in an `HttpOnly`,
`SameSite=Strict` cookie and last eight hours.

## What it cannot do

There is no endpoint that writes anything. The resolver cannot be reconfigured,
flushed, or made to resolve anything from this page — the only routes are the
page itself, a login, a logout, and one JSON snapshot.

It runs on its own thread, serving one connection at a time with a hard timeout
on every socket and a cap on request size. A client that opens a connection and
never finishes its request ties up the page for a few seconds and nothing else:
during exactly that, the resolver answered 20 of 20 test queries in 0.2
seconds.

---

[Caching](caching.md) · [Configuration](configuration.md) ·
[DNSSEC](dnssec.md) · [Internals](internals.md) · [Troubleshooting](troubleshooting.md)
