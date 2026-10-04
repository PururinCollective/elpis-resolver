# Configuration

Where the config file lives, what the settings do, and how to run it.

## The config file

`elpis.conf` is looked for next to the binary; then one directory up if the
binary sits in a `bin/` directory; then in `/etc/elpis/`, then in `/etc/`. The
first that exists wins.

In practice the first one is what you get: `make` seeds `bin/elpis.conf` from
the copy shipped in the source tree, so the shipped file stays a reference and
`bin/elpis.conf` is the one you edit. It survives rebuilds and `make clean`;
`make distclean` is what removes it.

### When the shipped defaults change

A pull that changes `elpis.conf` — a new setting, a new default, better
comments — is merged into `bin/elpis.conf` by the next `make`, the way git
merges a branch. What changed in the shipped file is applied, and what you
changed in yours is kept:

```
  merged the new shipped defaults into bin/elpis.conf (+16 -0 lines);
  your edits are kept, and the previous copy is bin/elpis.conf.bak
```

The merge needs to know which shipped defaults your copy came from, and keeps
them in `bin/elpis.conf.shipped`. A tree built before that file existed finds
them in git history the first time: the committed `elpis.conf` closest to
yours. Outside a git checkout it cannot, so that first time nothing is merged,
and later changes are.

Where the shipped file and yours changed the same lines, nothing is guessed.
`bin/elpis.conf` is left exactly as it is, and still in use. The merge with the
conflicts marked goes to `bin/elpis.conf.new`, and every `make` says so until
you have dealt with it:

```
  WARNING: the new shipped defaults in elpis.conf conflict with
  WARNING: your edits in bin/elpis.conf, in 1 place(s).
  WARNING: bin/elpis.conf is unchanged and still in use.
  WARNING: The merge, with the conflicts marked, is bin/elpis.conf.new
  WARNING: -- see line(s) 251
```

Each conflict shows your lines, the defaults you started from, and the new
ones:

```
<<<<<<< bin/elpis.conf (yours)
query-timeout: 800                     # per upstream attempt, milliseconds
||||||| bin/elpis.conf.shipped (defaults you started from)
query-timeout: 1200                    # per upstream attempt, milliseconds
=======
query-timeout: 1500                    # per upstream attempt, milliseconds
>>>>>>> elpis.conf (new defaults)
```

Keep what you want, remove the marker lines, and copy the result over
`bin/elpis.conf`. Or edit `bin/elpis.conf` by hand. Saving it is what tells the
next `make` you are done, so keeping your own side of every conflict works too.
A config with markers left in it is refused by `contrib/elpis-update.sh`
rather than restarted with: Elpis would skip those lines as bad settings.

The merge is `diff3` from GNU diffutils, or `git merge-file` where there is no
`diff3`; see `tools/conf-merge.sh`.

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

`identity-name:` is a licensed setting — see [Signed licences](licensing.md).
Without a valid licence the line is ignored with a warning and the default
name is used. `identity: no` is not gated.

With `identity: no` the name answers NXDOMAIN exactly like any name that does
not exist, so nothing reveals that the feature was ever there.

## Outbound source addresses

The kernel picks one source address per family, so every query leaves from it
and that is the only address the outside world sees. To use more than one,
repeat the setting — up to eight per family:

```
outgoing-interface: 2402:4e20:bab1::1001
outgoing-interface: 2402:4e20:bab1::1111
```

They are used round-robin across the outbound socket pool. An off-path
attacker forging a reply then has to guess the source address as well as the
port and the message ID.

## EDNS Client Subnet

```
ecs: yes
ecs-ip-type: client
```

A content network picks a server near whoever asks, and without ECS the one
asking is Elpis. That is right when Elpis sits beside its clients, and wrong
when it does not. If AdGuard Home in Malaysia lists an Elpis in Singapore as
one of its upstreams, every question it sends there gets Singapore's servers.
With ECS on, part of an address goes with each query, so the network can answer
for where the client really is. That part is a /24 for IPv4 or a /56 for IPv6,
never a whole address.

`ecs-ip-type` says whose address is sent:

| value | what the authority is sent |
|---|---|
| `client` | the client's subnet (the default) |
| `this` | this resolver's own public subnet, the same for every client |
| `none` | a /0, which asks for an answer tailored to nobody |

With `client`, the subnet comes from the client's own ECS option when it sends
one. Otherwise it comes from the address the query arrived from. A private,
CGNAT or loopback address says nothing about where a client is, so a client
with one gets this resolver's own subnet instead. So does a client that sends a
/0 to opt out. This resolver's own address is the one the status page shows. It
is looked up a few seconds after startup, and until then those clients are
sent no subnet at all.

`this` suits Elpis behind a forwarder or a NAT whose egress is somewhere else.
`none` suits `forward-zone` to a public resolver that would otherwise add a
subnet of its own from Elpis's address.

```
ecs-ipv4-prefix: 24      # 0 to 32; 0 sends no IPv4 subnet
ecs-ipv6-prefix: 56      # 0 to 128
ecs-zone: tbcache.com    # repeatable; only names under these zones
```

A client that sends a longer prefix than these is cut down to them. With no
`ecs-zone:` lines, a subnet can go to the servers of any zone below the TLDs.

### Behind AdGuard Home

If AdGuard Home reaches Elpis across the internet, nothing is needed on its
side: the address Elpis sees is AdGuard's public one, which is where its
clients are. If it reaches Elpis over a VPN or a private network, the address
Elpis sees is a private one. Then turn on **Use EDNS Client Subnet** in
AdGuard's DNS settings, with **Use custom IP for EDNS** set to the site's
public address, so the subnet arrives in the query itself.

Firefox's own DNS over HTTPS puts `0.0.0.0/0` on every query, asking not to
have its subnet used. AdGuard Home ignores that and adds the client's subnet
after it, so the query reaches Elpis with two ECS options. Elpis uses the last
one: the subnet AdGuard added.

### What it costs

- **Privacy.** A prefix of each client's address goes to every authority that
  takes one. The root and the TLDs are never sent one. A server that answers
  without saying how it used the subnet, as a server that ignores ECS does, is
  sent none for the next hour. `ecs-zone` narrows it further. (With `none`
  the /0 keeps going regardless, since its job is to stop a forwarder adding a
  subnet of its own.)
- **Cache.** An answer an authority tailored to one subnet (a SCOPE above 0 in
  its reply) is cached for that subnet alone, and each subnet asks for its own.
  Most authorities give every subnet the same answer, and those answers stay
  shared. The statistics count both: `ecs sent=` and `tailored=`.

### Checking it

Google's `o-o.myaddr.l.google.com` answers with the subnet it was sent:

```bash
dig @127.0.0.1 -p 5335 o-o.myaddr.l.google.com TXT +subnet=175.139.1.0/24
```

The reply should carry `"edns0-client-subnet 175.139.1.0/24"`. With `this`, it
shows this resolver's own subnet; with `none`, `"edns0-client-subnet was not
used"`.

## Names asked without case randomisation

```
use-0x20: yes
caps-exempt: dnsprobe.online    # repeatable
```

With `use-0x20` on, Elpis randomises the case of every name it sends upstream
over UDP (`wWw.ExAmPlE.cOm`). The authority answers with the name exactly as
it was sent, so an attacker forging a reply has to guess the case pattern as
well. DNS names are case-insensitive, so the answer is the same.

A server that drops randomised names is caught automatically: it is asked once
in lowercase, and if that is answered, it is remembered and the log says so.
That does not work for a server that answers a randomised name correctly but
does something else with it. `dnsprobe.online`, which runs the DNS leak test at
publicdns.info, records which resolver asked for each test name, but only if
the name arrives in lowercase. Through Elpis the test never sees a resolver at
all. The same happens with Google Public DNS, which randomises too. Nothing in
the answers shows this, so the zone has to be named.

`caps-exempt` names a zone whose names always go out as asked. It is matched
against the name being sent, so it covers the zone and every name below it,
whichever server is asked. Up to 32 entries. The shipped config lists `dnsprobe.online`. The
name is Unbound's, and Elpis also accepts Unbound's `use-caps-for-id` for
`use-0x20`.

## DNS over TLS to authoritative servers

```
authoritative-dot: opportunistic     # default: no
authoritative-dot-ttl: 24h
authoritative-dot-retry: 1h
authoritative-dot-max-try: 24        # 0 = never give up
```

Everything Elpis asks the root, the TLDs and the authoritative servers goes
over plain DNS on port 53, readable by anyone on the path. With
`authoritative-dot: opportunistic`, Elpis tries DNS over TLS on port 853 with
each server it uses, as RFC 9539 describes, and keeps using it with the
servers that answer there.

| a server that | is asked |
|---|---|
| has not been tried | plain, as always, with a copy over DoT that nobody waits for: that is the test |
| answered over DoT | over DoT only, on one connection per worker that is kept open, for `authoritative-dot-ttl` after its last DoT answer |
| failed over DoT, or never answered there | plain, and tested again every `authoritative-dot-retry` |
| failed `authoritative-dot-max-try` retries | plain, for good |

So the first query to a server is no slower than before, and a server that
takes DoT never sees a name in the clear again. A server that answers over DoT
is chosen ahead of one that does not, however much faster the other is: most
answers come from the cache, so a slower server costs little, and the name
stays out of sight. A server that is failing or held down is not chosen for
that, and no plain copy of a question asked over DoT goes to anyone else.

If a DoT query goes unanswered for as long as the server usually takes, the
same question goes plain to the same server. If that is answered, DoT is
marked failed for the server. A connection that is refused, fails its
handshake, or ends with a TLS alert is marked failed at once, and its queries
go plain straight away. A connection that had worked and is merely closed
under its queries has only lost them: they go again over a fresh one.

`yes` is not accepted: it is kept for a strict mode, one day, that would rather
fail than ask in the clear. Durations take `s`, `m`, `h` and `d`. The ttl and
the retry run from a minute to a week, the retry is at most the ttl, and
`authoritative-dot-max-try` is at most 255. Forwarders and stub zones are left
alone: they are configuration, and asked the way it says.

### What it protects, and what it does not

The connection is encrypted but not authenticated. An NS record gives a name
and an address, not an identity a certificate could be checked against, so the
certificate is not checked; the server's Finished message is, which proves the
two ends derived the same keys. That stops someone watching the path from
reading what is asked. It does nothing against someone who can sit on the path,
who could read it or simply block port 853 -- and blocking only pushes Elpis
back to plain DNS, which is where it was without this.

The authoritative server itself still sees every question, and an ECS subnet
if one is sent. DNSSEC is unchanged: an answer over DoT is trusted no more than
a plain one. Queries over DoT are padded to a multiple of 128 bytes (RFC
8467), so their length gives less away.

### What it costs

- **Few servers offer it yet.** Most authorities drop connections to port 853
  without a reply, so most tests end in a 3-second timeout. That is a socket
  and a timer, not a wait: nobody is waiting on a test. At most 16 handshakes
  are in progress per worker.
- **Connections.** One per server per worker, closed after 15 s unused, at most
  256 per worker. About 1.2 KB of TLS state each, plus buffers that are freed
  while it idles.
- **CPU.** An X25519 key exchange per handshake, about 0.3 ms. Records are
  ChaCha20-Poly1305, or AES-128-GCM where the CPU has AES-NI.

### Checking it

The status page's **DoT servers** window lists every server that has answered
over DoT, where each stands now, and why tests failed. `b.root-servers.net`
and Facebook's authoritative servers take DoT, so asking for a few of
Facebook's names shows it working:

```bash
dig @127.0.0.1 -p 5335 www.facebook.com A
dig @127.0.0.1 -p 5335 www.whatsapp.com A
```

The first query to each server goes plain; once the test is answered, the
window lists the server as available, and later queries to it go over DoT.

## Zones whose servers misbehave

```
quirk: example.net drops-svcb
quirk: cimb.com.my none
```

Some zones drop HTTPS queries at a firewall, or sit behind a load balancer
that answers only the types it balances. A quirk says how a zone misbehaves, so
Elpis answers "no data" instead of timing out into SERVFAIL. A built-in list
covers the zones known to need one. These lines add to it, and `none` switches
a built-in entry off. See [quirks](quirks.md) for the flags, the built-in list,
and how to find a zone that needs one.

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
