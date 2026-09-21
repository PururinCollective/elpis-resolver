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

| | |
|---|---|
| **Task Manager** | CPU, memory, network and queries in one window — a rail of live sparklines on the left, the one you pick drawn large on the right |
| **Overview** | cache hit rate, response time answered from cache and resolved upstream, queries and SERVFAIL per second, every counter the resolver keeps, and how this host looks from outside: public IPv4 and IPv6, AS number and AS name |
| **CPU** | processor time as a share of one core, the processor's model name, the worker count, which SIMD kernels were selected, and how long both the resolver and the machine under it have been up |
| **Memory** | resident size over time against the memory the resolver may use, so the line reads as a share of the ceiling rather than of its own peak, and each cache's entries, bytes used, budget and hit rate |
| **Network** | bytes in and out per second, and the addresses actually bound |
| **Queries** | queries per second, SERVFAIL and bogus per second, cache hits against upstream queries |
| **Root servers** | the roots ranked by the round trip this resolver has actually measured, with how often each was asked and how often it failed to answer |
| **Top names** | most queried, those ending in SERVFAIL, those failing DNSSEC validation |
| **Top clients** | busiest clients, clients being handed SERVFAIL, clients asking for bogus names, and upstream servers that stopped answering |
| **Log** | the recent warnings and errors, newest first; it keeps the size you give it and holds your scroll position while new entries arrive |
| **About** | version, the commit the binary was built from, uptime, and which ML-DSA parameter sets are live |

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
