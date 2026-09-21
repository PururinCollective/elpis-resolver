# Status page

A read-only web interface showing what the resolver is doing. It is off by
default; two lines switch it on:

```
webgui: yes
webgui-password: choose-something
```

Then open `http://127.0.0.1:8082/`.

## What it shows

Windows open from the desktop icons and can be dragged, resized and tiled.

| | |
|---|---|
| **Overview** | cache hit rate, response time answered from cache and resolved upstream, queries and SERVFAIL per second, and every counter the resolver keeps |
| **CPU** | processor time as a share of one core, with the worker count and which SIMD kernels were selected |
| **Memory** | resident size over time, and each cache's entries, bytes used, budget and hit rate |
| **Network** | bytes in and out per second, and the addresses actually bound |
| **Queries** | queries per second, SERVFAIL and bogus per second, cache hits against upstream queries |
| **Top names** | most queried, those ending in SERVFAIL, those failing DNSSEC validation |
| **Top clients** | busiest clients, clients being handed SERVFAIL, clients asking for bogus names, and upstream servers that stopped answering |
| **Log** | the recent warnings and errors, newest first |

The counts are exact, not sampled. Sampling was tried first and it is useless
here: a resolver answering a few hundred queries a second gives too few samples
to rank anything, and that is precisely when someone is looking at the page.
What makes counting every query affordable is that the tables are keyed on the
hashed wire name and raw client address — a name is turned into characters once,
the first time it is seen, and every query after that finds the slot by hash and
adds one.

That still costs something, so nothing is counted at all while `webgui: no`.

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
