# Configuration

Where the config file lives, what the settings do, and how to run it.

## The config file

`elpis.conf` is looked for next to the binary; then one directory up if the
binary sits in a `bin/` directory; then in `/etc/elpis/`, then in `/etc/`. The
first that exists wins.

In practice the first one is what you get: `make` seeds `bin/elpis.conf` from
the copy shipped in the source tree and never overwrites it afterwards, so the
shipped file stays a reference and `bin/elpis.conf` is the one you edit. It
survives rebuilds and `make clean`; `make distclean` is what removes it.

Without any config at all the defaults are a working recursive resolver on
`127.0.0.1:5335`. (Not 5353 — that is mDNS, and avahi-daemon holds it on most
Linux hosts; because both sides set `SO_REUSEADDR` the clash is silent rather
than an error.) Every setting is documented in the file at its default value,
so a config that is entirely comments behaves exactly like no config.

```
listen: 127.0.0.1@5335
access-control: 127.0.0.0/8 allow

cache-size: auto           # or 2G
serve-stale: 86400         # RFC 8767
prefetch: yes
prefetch-threshold: 10     # refresh with 10% of the TTL left
refresh-nxdomain-confirmations: 3

dnssec: yes
root-zone-transfer: no     # yes = pull every TLD delegation at startup

dns64: no
dns64-prefix: 64:ff9b::/96

forward-zone: internal.example 10.0.0.53@5335   # recursive upstream
stub-zone: corp.example 10.1.0.53               # iterative, treated as authority
```

Behind AdGuard Home, point its upstream at `127.0.0.1:5335` and leave Elpis on
loopback.

### Privileged ports

If a `listen` line asks for a port below the system's privileged threshold
(1024, or whatever `net.ipv4.ip_unprivileged_port_start` says), Elpis checks
for the right to bind it *before* opening any socket and, if it is missing,
says so with the port named and the ways to fix it:

```
FATAL cannot listen on 0.0.0.0:53: port 53 is privileged on this system
      (ports below 1024 need root or CAP_NET_BIND_SERVICE), and this
      process is uid 1000 with neither
FATAL   pick one:
FATAL     - grant the capability once: sudo setcap cap_net_bind_service=+ep /usr/local/sbin/elpis
FATAL     - start as root and set 'user:' in elpis.conf so it drops privilege after binding
FATAL     - listen on an unprivileged port instead, e.g. 'listen: 127.0.0.1@5335'
FATAL     - or lower the range system-wide: sysctl net.ipv4.ip_unprivileged_port_start=53
```

Sockets are bound before privileges are dropped, so `user:` works with either
of the first two. Running as root with no `user:` configured is allowed but
warned about once.

### Listening on everything

Two lines, and that is the whole of it:

```
listen: 0.0.0.0@53
listen: [::]@53
```

Both are needed. Every IPv6 listener sets `IPV6_V6ONLY`, so `[::]` carries
IPv6 only — it will not pick up IPv4 the way a dual-stack socket does. That is
deliberate: a dual-stack socket reports IPv4 peers as v4-mapped addresses,
which would make `access-control` rules quietly ambiguous about which family
they matched.

Listing a specific address *as well as* the wildcard is redundant — the kernel
prefers the specific socket, so it works, but it costs descriptors for nothing
and Elpis says so. Startup names every socket it actually bound, which is the
first thing to check when a client cannot reach it:

```
INFO    bound udp 0.0.0.0:53
INFO    bound tcp 0.0.0.0:53
INFO    bound udp [::]:53
INFO    bound tcp [::]:53
INFO  listening with 8 workers
```

## Asking a resolver what it is

Every Elpis answers one TXT name about itself, so identifying a running
resolver does not require logging into it:

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

```
elpis.sakurako.oomuro   text = "elpis=1.0.0" "edition=community"
                               "build=c662164779b7" "uptime=3601"
                               "workers=8" "simd=avx2" "dnssec=validating"
```

`dig +short TXT elpis.sakurako.oomuro @127.0.0.1` does the same thing.

Only clients the access-control list already admits get an answer. The default
name sits in an undelegated TLD on purpose: nothing on the public internet can
ever own it, so the probe answers only someone querying this resolver
**directly**, and no scan of the DNS will turn it up.

### Telling deployments apart

`edition:` is how a community install is distinguished from a commercial one:

```
edition: commercial
operator: Example ISP, AS64500
```

Both are free text and **self-declared — nothing verifies them**. Anyone can
write `edition: commercial` in their own config file. That is fine for what
this is for: labelling your own fleet, and letting support see what it is
looking at without a screen-share. It is not a licence check, and should not be
relied on as one. If you need a claim that cannot be forged, the field has to
carry a signature from whoever issues it, which this does not do.

`community`, `commercial`, `homelab` and `evaluation` are the values worth
being consistent about; anything else is accepted.

For a claim somebody else should believe, add a signed licence — see
[Signed licences](licensing.md). When one verifies it sets the edition and
`edition:` is ignored, and the probe reports `licence=verified` alongside the
organisation, serial and expiry. Without one, the absence of `licence=verified`
is what tells you the edition is only self-declared.

### What it will not tell you

No IP address is ever in the answer, whatever the configuration says. Elpis
knows its own public IPv4, IPv6 and AS — the status page shows them — and an
unauthenticated UDP probe is the wrong way to hand them out. Behind a
forwarder it would disclose an address the querier could not otherwise see,
and on a public resolver it would let anyone who can reach the port map the
operator's upstream. Ask the status page, which is behind a login.

The OS, kernel release and hostname are off by default for the same reason
version banners usually are — a kernel release is a CVE lookup key, and a
hostname tends to describe somebody's network:

```
identity-system: yes
```

turns them on, adding `"system=Linux 7.0.0-31-generic x86_64"` and
`"host=resolver1"`. Reasonable on a resolver only your own machines can reach;
think before setting it on anything facing outward.

### Turning it off, or hiding it

```
identity-name: whoami.internal.example    # a name only you know
identity: no                              # no probe at all
```

With `identity: no` the name answers NXDOMAIN exactly like any name that does
not exist, so nothing reveals that the feature was ever there.

## Hashing a status page password

```bash
elpis --hash-password            # reads one line from stdin
elpis --hash-password 'secret'   # or takes it as an argument
```

Prints a `webgui-password:` line to paste into the config. The resolver does
this for itself when it can write the config file, but a properly sandboxed
deployment does not let it — see
[when the config cannot be rewritten](status-page.md#when-the-config-cannot-be-rewritten).

## Running it

```
SIGHUP    reopen the log, rotate the DNS cookie secret
SIGUSR1   print statistics
SIGUSR2   flush the caches (root hints are kept)
SIGTERM   shut down
```

`-t` checks the configuration and exits. `-d` stays in the foreground. `-v`
raises verbosity, repeatable.

---

[Caching](caching.md) · [DNSSEC](dnssec.md) · [Internals](internals.md) · [Troubleshooting](troubleshooting.md)
