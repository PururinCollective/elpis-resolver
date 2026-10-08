# 🔧 Configuration

Where the config lives, what the settings do, and how to run it.

**On this page:**
[The config file](#-the-config-file) ·
[Asking a resolver what it is](#-asking-a-resolver-what-it-is) ·
[Outbound source addresses](#-outbound-source-addresses) ·
[EDNS Client Subnet](#-edns-client-subnet) ·
[Case randomisation](#-names-asked-without-case-randomisation) ·
[DNS over TLS to authoritative servers](#-dns-over-tls-to-authoritative-servers) ·
[Quirks](#-zones-whose-servers-misbehave) ·
[Status page password](#-hashing-a-status-page-password) ·
[Running it](#-running-it)

## 📄 The config file

The first `elpis.conf` found wins:

```
 1. beside the binary                 bin/elpis.conf
 2. one level up, if that is bin/     elpis.conf
 3. /etc/elpis/elpis.conf
 4. /etc/elpis.conf
```

In practice it's the first: `make` seeds `bin/elpis.conf` from the copy in the
source tree, so the shipped file stays a reference and `bin/elpis.conf` is the
one you edit. It survives rebuilds and `make clean`; `make distclean` removes it.

**No config at all** is a working recursive resolver on `127.0.0.1:5335`.
Every setting is in the file at its default, so a config that is all comments
behaves exactly like no config.

<sub>Not 5353: that's mDNS, and avahi-daemon holds it on most Linux hosts.
Both sides set `SO_REUSEADDR`, so the clash would be silent rather than an
error.</sub>

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

### When the shipped defaults change

A pull that changes `elpis.conf` (a new setting, a new default, better
comments) is merged into `bin/elpis.conf` by the next `make`, the way git
merges a branch:

```
 elpis.conf (new shipped)  ─┐
 elpis.conf.shipped (old)  ─┼──►  3-way merge  ──►  bin/elpis.conf  (your edits kept)
 bin/elpis.conf (yours)    ─┘                  └─►  bin/elpis.conf.new  (only on a conflict)
```

```
  merged the new shipped defaults into bin/elpis.conf (+16 -0 lines);
  your edits are kept, and the previous copy is bin/elpis.conf.bak
```

<sub>The merge needs the shipped defaults your copy came from, kept in
`bin/elpis.conf.shipped`. A tree built before that file existed finds them in
git history the first time: the committed `elpis.conf` closest to yours.
Outside a git checkout it can't, so that first time nothing is merged, and
later changes are. The merge is `diff3` from GNU diffutils, or
`git merge-file` where there is no `diff3`; see `tools/conf-merge.sh`.</sub>

**Where both changed the same lines, nothing is guessed.** `bin/elpis.conf` is
left exactly as it is, and still in use. The merge with the conflicts marked
goes to `bin/elpis.conf.new`, and every `make` says so until you deal with it:

```
  WARNING: the new shipped defaults in elpis.conf conflict with
  WARNING: your edits in bin/elpis.conf, in 1 place(s).
  WARNING: bin/elpis.conf is unchanged and still in use.
  WARNING: The merge, with the conflicts marked, is bin/elpis.conf.new
  WARNING: -- see line(s) 251
```

Each conflict shows your lines, the defaults you started from, and the new ones:

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
`bin/elpis.conf`, or edit `bin/elpis.conf` by hand. Saving it tells the next
`make` you're done, so keeping your own side of every conflict works too.

> [!WARNING]
> A config with markers left in it is refused by `contrib/elpis-update.sh`
> rather than restarted with: Elpis would skip those lines as bad settings.

### Privileged ports

A `listen` port below the system's privileged threshold (1024, or whatever
`net.ipv4.ip_unprivileged_port_start` says) is checked *before* any socket is
opened. If the right to bind it is missing, Elpis says so and how to fix it:

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

<sub>Sockets are bound before privileges are dropped, so `user:` works with
either of the first two. Running as root with no `user:` is allowed, and warned
about once.</sub>

### Listening on everything

Two lines, and both are needed:

```
listen: 0.0.0.0@53
listen: [::]@53
```

Every IPv6 listener sets `IPV6_V6ONLY`, so `[::]` carries IPv6 only.

<sub>That's deliberate: a dual-stack socket reports IPv4 peers as v4-mapped
addresses, which would make `access-control` rules quietly ambiguous about
which family they matched. Listing a specific address *as well as* the wildcard
works (the kernel prefers the specific socket), but costs descriptors for
nothing, and Elpis says so.</sub>

Startup names every socket it actually bound. Check that first when a client
can't reach it:

```
INFO    bound udp 0.0.0.0:53
INFO    bound tcp 0.0.0.0:53
INFO    bound udp [::]:53
INFO    bound tcp [::]:53
INFO  listening with 8 workers
```

### Listening on one address

A specific address doesn't have to be up when Elpis starts. That's normal at
boot in a container or a VM: DHCP can finish after the service starts, and a
new IPv6 address is unusable for a second or two while duplicate address
detection runs. Elpis binds it anyway and answers as soon as it arrives:

```
WARN  listen 192.168.1.5:53: this host does not have that address yet; bound
      anyway, and it answers as soon as the address comes up (if it never
      does, check the address)
```

If it never comes up, check the address for a typo. `webgui-listen` works the
same way.

<sub>This is `IP_FREEBIND` on Linux (`IP_BINDANY` on FreeBSD, which needs
root), the same thing unbound's `ip-freebind` does. Earlier builds failed here
with "Cannot assign requested address" and exited, and needed a restart once
the machine was up.</sub>

### Taking systemd-resolved's place on 127.0.0.53

On a host where Elpis is the resolver, it can answer on the address
systemd-resolved's stub used, so everything that expects `127.0.0.53` keeps
working:

```
listen: 127.0.0.53@53      # or 0.0.0.0@53, which covers it
```

```
 before:  programs ──► 127.0.0.53 ──► systemd-resolved ──► upstream
 after:   programs ──► 127.0.0.53 ──► Elpis ──► root, TLDs, authorities
```

Resolved has to be out of the way first, and `/etc/resolv.conf`, a link into
`/run/systemd/resolve`, has to become a file of its own, because nothing writes
there once resolved is gone. One command does both, and installs the unit:

```bash
sudo RESOLVED=replace /opt/elpis-resolver/contrib/elpis-install.sh
```

It masks resolved, keeps the old `resolv.conf` as `/etc/resolv.conf.elpis-bak`,
and writes:

```
nameserver 127.0.0.53
options edns0 trust-ad
```

<sub>All of `127.0.0.0/8` is local on Linux, so no address needs adding. Replies
leave from `127.0.0.53` whether Elpis listens there or on the wildcard, as glibc
expects. `trust-ad` lets programs that ask see Elpis's DNSSEC verdict, as
resolved's own file did. `DRY_RUN=1` shows what the script would do first. The
script is for a git clone, `/opt/elpis-resolver` by recommendation; with a
precompiled binary, do the same steps by hand.</sub>

## 🪪 Asking a resolver what it is

Every Elpis answers one TXT name about itself, so you can identify it without
logging in:

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
dig +short TXT elpis.sakurako.oomuro @127.0.0.1     # the same
```

```
elpis.sakurako.oomuro   text = "elpis=2.4.5" "codename=Celestial Cascade"
                               "edition=community" "build=v2.4.5"
                               "uptime=3601" "workers=8" "simd=avx2"
                               "dnssec=validating"
```

<sub>`codename=` is the release's name, from 2.4.0 on, beside its version.</sub>

- Only clients the access-control list already admits get an answer.
- The default name sits in an undelegated TLD on purpose: nothing on the public
  internet can ever own it, so the probe answers only someone asking **this
  resolver directly**, and no scan of the DNS turns it up.

### Telling deployments apart

`edition:` labels a community install versus a commercial one:

```
edition: commercial
operator: Example ISP, AS64500
```

> [!IMPORTANT]
> Both are free text and **self-declared: nothing verifies them.** Anyone can
> write `edition: commercial` in their own config. That's fine for labelling
> your own fleet, and for support to see what it's looking at without a
> screen-share. It is not a licence check.

`community`, `commercial`, `homelab` and `evaluation` are the values worth
being consistent about; anything else is accepted.

For a claim somebody else should believe, add a [signed licence](licensing.md).
When one verifies, it sets the edition (`edition:` is then ignored), and the
probe reports `licence=verified` with the organisation, serial and expiry.

<sub>Without one, the absence of `licence=verified` is what tells you the
edition is only self-declared.</sub>

### What it will not tell you

**No IP address is ever in the answer**, whatever the config says.

<sub>Elpis knows its own public IPv4, IPv6 and AS (the status page shows them),
and an unauthenticated UDP probe is the wrong way to hand them out. Behind a
forwarder it would disclose an address the asker couldn't otherwise see; on a
public resolver it would let anyone who can reach the port map the operator's
upstream. Ask the status page, which is behind a login.</sub>

**The OS, kernel and hostname are off by default**, like version banners
usually are: a kernel release is a CVE lookup key, and a hostname tends to
describe somebody's network.

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

| setting | licence needed? |
|---|---|
| `identity-name:` | yes, see [Signed licences](licensing.md). Without a valid one the line is ignored with a warning and the default name is used. |
| `identity: no` | no |

<sub>With `identity: no` the name answers NXDOMAIN exactly like any name that
doesn't exist, so nothing reveals the feature was ever there.</sub>

## 🛫 Outbound source addresses

The kernel picks one source address per family, so every query leaves from it.
To use more, repeat the setting, up to eight per family:

```
outgoing-interface: 2402:4e20:bab1::1001
outgoing-interface: 2402:4e20:bab1::1111
```

They're used round-robin across the outbound socket pool.

<sub>An off-path attacker forging a reply then has to guess the source address
as well as the port and the message ID.</sub>

An address that isn't up yet when Elpis starts, which is normal at boot, is
tried again until it is, and queries start leaving from it then:

```
WARN  outgoing-interface 2402:4e20:bab1::1001: this host does not have that
      address yet; upstream queries start leaving from it as soon as it comes
      up (if it never does, check the address)
INFO  outgoing-interface 2402:4e20:bab1::1001 is up; upstream queries leave
      from it now
```

<sub>Tried after 1 s, 2, 4 and 8, then every 10 s. Earlier builds gave up on it
at startup: an IPv4 address made Elpis exit, and an IPv6 one quietly left it
asking nothing over IPv6 until a restart. These sockets don't use
`IP_FREEBIND` the way listeners do, because on Linux an IPv6 socket with it
sends from an address the host doesn't have.</sub>

## 📍 EDNS Client Subnet

```
ecs: yes
ecs-ip-type: client
```

A content network picks a server near whoever asks. Without ECS, the one
asking is Elpis.

```
 client in Malaysia ──► AdGuard (MY) ──► Elpis (SG) ──► CDN
                                                         │
          without ECS:  "the asker is in Singapore"  ────┤──► Singapore servers
          with ECS:     "for 175.139.1.0/24"         ────┘──► Malaysian servers
```

With ECS on, part of an address goes with each query: a /24 for IPv4 or a /56
for IPv6, never a whole address.

| `ecs-ip-type` | what the authority is sent |
|---|---|
| `client` | the client's subnet (the default) |
| `this` | this resolver's own public subnet, the same for every client |
| `none` | a /0, which asks for an answer tailored to nobody |

- **`client`** takes the subnet from the client's own ECS option when it sends
  one, otherwise from the address the query came from.
  <br><sub>A private, CGNAT or loopback address says nothing about where a
  client is, so such a client gets this resolver's own subnet instead. So does a
  client that sends a /0 to opt out. That address is the one the status page
  shows; it's looked up a few seconds after startup, and until then those
  clients are sent no subnet at all.</sub>
- **`this`** suits Elpis behind a forwarder or a NAT whose egress is somewhere else.
- **`none`** suits `forward-zone` to a public resolver that would otherwise add
  a subnet of its own from Elpis's address.

```
ecs-ipv4-prefix: 24      # 0 to 32; 0 sends no IPv4 subnet
ecs-ipv6-prefix: 56      # 0 to 128
ecs-zone: tbcache.com    # repeatable; only names under these zones
```

<sub>A client that sends a longer prefix is cut down to these. With no
`ecs-zone:` lines, a subnet can go to the servers of any zone below the
TLDs.</sub>

### Behind AdGuard Home

| AdGuard reaches Elpis | what to do |
|---|---|
| across the internet | nothing: Elpis sees AdGuard's public address, which is where its clients are |
| over a VPN or private network | in AdGuard's DNS settings, turn on **Use EDNS Client Subnet** with **Use custom IP for EDNS** set to the site's public address |

> [!NOTE]
> Firefox's own DNS over HTTPS puts `0.0.0.0/0` on every query, asking not to
> have its subnet used. AdGuard Home ignores that and adds the client's subnet
> after it, so the query reaches Elpis with two ECS options. Elpis uses the
> last one: the subnet AdGuard added.

### What it costs

- **Privacy.** A prefix of each client's address goes to every authority that
  takes one. The root and the TLDs are never sent one. A server that answers
  without saying how it used the subnet (as one that ignores ECS does) is sent
  none for the next hour. `ecs-zone` narrows it further.
  <br><sub>With `none` the /0 keeps going regardless: its job is to stop a
  forwarder adding a subnet of its own.</sub>
- **Cache.** An answer tailored to one subnet (SCOPE above 0) is cached for
  that subnet alone, and each subnet asks for its own. Most authorities give
  every subnet the same answer, and those stay shared. The statistics count
  both: `ecs sent=` and `tailored=`.

### Checking it

Google's `o-o.myaddr.l.google.com` answers with the subnet it was sent:

```bash
dig @127.0.0.1 -p 5335 o-o.myaddr.l.google.com TXT +subnet=175.139.1.0/24
```

| `ecs-ip-type` | the reply carries |
|---|---|
| `client` | `"edns0-client-subnet 175.139.1.0/24"` |
| `this` | this resolver's own subnet |
| `none` | `"edns0-client-subnet was not used"` |

## 🔠 Names asked without case randomisation

```
use-0x20: yes
caps-exempt: dnsprobe.online    # repeatable
```

With `use-0x20` on, every name Elpis sends upstream over UDP has its case
randomised: `wWw.ExAmPlE.cOm`. The server answers with the name exactly as
sent, so someone forging a reply has to guess the case pattern too. DNS names
are case-insensitive, so the answer is the same.

| a server that | what happens |
|---|---|
| drops randomised names | caught automatically: asked once in lowercase, remembered if that's answered, and logged |
| answers randomised names, but misuses them | has to be named in `caps-exempt` |

> [!NOTE]
> `dnsprobe.online`, behind the DNS leak test at publicdns.info, records which
> resolver asked for each test name, but only when the name arrives in
> lowercase. Through Elpis the test never saw a resolver at all, and the same
> happens with Google Public DNS, which randomises too. Nothing in the answers
> shows this, so the zone has to be named.

`caps-exempt` names a zone whose names always go out as asked. It's matched
against the name being sent, so it covers the zone and every name below it,
whichever server is asked. Up to 32 entries; the shipped config lists
`dnsprobe.online`.

<sub>The name is Unbound's. Elpis also accepts Unbound's `use-caps-for-id` for
`use-0x20`.</sub>

## 🔒 DNS over TLS to authoritative servers

```
authoritative-dot: opportunistic     # default: no
authoritative-dot-ttl: 24h
authoritative-dot-retry: 1h
authoritative-dot-max-try: 24        # 0 = never give up
```

Plain DNS to the root, the TLDs and the authoritative servers is readable by
anyone on the path. With `authoritative-dot: opportunistic`, Elpis tries DNS
over TLS on port 853 with each server it uses (RFC 9539), and keeps using it
with the servers that answer there.

```
        first query
             │
             ▼
     ┌───────────────┐     DoT answers     ┌───────────────┐
     │    testing    │ ──────────────────► │   available   │◄─┐ each DoT answer
     │  plain + DoT  │                     │   DoT only    │──┘ renews the ttl
     └───────────────┘                     └───────┬───────┘
         ▲       │ refused, no reply,              │ DoT fails
   retry │       │ TLS error                       ▼
   due   │       │                         ┌───────────────┐
         │       └───────────────────────► │    failed     │
         └──────────────────────────────── │  plain only   │
                                           └───────┬───────┘
                                                   │ max-try retries failed
                                                   ▼
                                           ┌───────────────┐
                                           │   given up    │
                                           │ never retried │
                                           └───────────────┘
```

| a server that | is asked |
|---|---|
| has not been tried | plain, as always, with a copy over DoT that nobody waits for: that is the test |
| answered over DoT | over DoT only, on one kept-open connection per worker, for `authoritative-dot-ttl` after its last DoT answer |
| failed over DoT, or never answered there | plain, and tested again every `authoritative-dot-retry` |
| failed `authoritative-dot-max-try` retries | plain, for good |

**The first query to a server is no slower than before**, and a server that
takes DoT never sees a name in the clear again.

- **DoT servers come first.** A server that answers over DoT is chosen ahead of
  one that doesn't, however much faster the other is.
  <br><sub>Most answers come from the cache, so a slower server costs little,
  and the name stays out of sight. A server that is failing or held down isn't
  chosen for that, and no plain copy of a question asked over DoT goes to
  anyone else.</sub>
- **No reply over DoT?** The same question goes plain to the same server once
  the usual timeout passes. If plain answers, DoT is marked failed.
- **Refused, a failed handshake, or a TLS alert** marks DoT failed at once, and
  the queries go plain straight away.
- **A working connection closed under its queries** has only lost them: they
  go again over a fresh one.

<sub>`yes` is not accepted: it's kept for a strict mode, one day, that would
rather fail than ask in the clear. Durations take `s`, `m`, `h` and `d`. The
ttl and the retry run from a minute to a week, the retry is at most the ttl,
and `authoritative-dot-max-try` is at most 255. Forwarders and stub zones are
left alone: they're configuration, and asked the way it says.</sub>

### What it protects, and what it does not

> [!IMPORTANT]
> **Encrypted, not authenticated.** It stops someone *watching* the path from
> reading what is asked. It does nothing against someone *sitting on* the path,
> who could read it or simply block port 853, and blocking only pushes Elpis
> back to plain DNS, which is where it was without this.

<sub>An NS record gives a name and an address, not an identity a certificate
could be checked against, so the certificate isn't checked. The server's
Finished message is, which proves the two ends derived the same keys.</sub>

- The authoritative server itself still sees every question, and an ECS subnet
  if one is sent.
- DNSSEC is unchanged: an answer over DoT is trusted no more than a plain one.
- Queries over DoT are padded to a multiple of 128 bytes (RFC 8467), so their
  length gives less away.

### What it costs

| | |
|---|---|
| **Few servers offer it yet** | Most authorities drop connections to port 853 without a reply, so most tests end in a 3-second timeout. That's a socket and a timer, not a wait: nobody is waiting on a test. At most 16 handshakes are in progress per worker. |
| **Connections** | One per server per worker, closed after 15 s unused, at most 256 per worker. About 1.2 KB of TLS state each, plus buffers freed while it idles. |
| **CPU** | An X25519 key exchange per handshake, about 0.3 ms. Records are ChaCha20-Poly1305, or AES-128-GCM where the CPU has AES-NI. |

### Checking it

The status page's **DoT servers** window lists every server that has answered
over DoT, where each stands now, and why tests failed. `b.root-servers.net`
and Facebook's authoritative servers take DoT, so a few of Facebook's names
show it working:

```bash
dig @127.0.0.1 -p 5335 www.facebook.com A
dig @127.0.0.1 -p 5335 www.whatsapp.com A
```

<sub>The first query to each server goes plain. Once the test is answered, the
window lists the server as available, and later queries to it go over DoT.
dnscheck.tools shows **ADoX** when it works.</sub>

## 🧩 Zones whose servers misbehave

```
quirk: example.net drops-svcb
quirk: cimb.com.my none
```

Some zones drop HTTPS queries at a firewall, or sit behind a load balancer that
answers only the types it balances. A quirk says how a zone misbehaves, so
Elpis answers "no data" instead of timing out into SERVFAIL.

<sub>A built-in list covers the zones known to need one. These lines add to it,
and `none` switches a built-in entry off. See [quirks](quirks.md) for the
flags, the built-in list, and how to find a zone that needs one.</sub>

## 🔑 Hashing a status page password

```bash
elpis --hash-password            # reads one line from stdin
elpis --hash-password 'secret'   # or takes it as an argument
```

Prints a `webgui-password:` line to paste into the config.

<sub>The resolver does this for itself when it can write the config file, but
a properly sandboxed deployment doesn't let it. See
[when the config cannot be rewritten](status-page.md#when-the-config-cannot-be-rewritten).</sub>

## 🏃 Running it

| Signal | Does |
|---|---|
| `SIGHUP` | reopen the log, rotate the DNS cookie secret |
| `SIGUSR1` | print statistics |
| `SIGUSR2` | flush the caches (root hints are kept) |
| `SIGTERM` | shut down |

| Flag | Does |
|---|---|
| `-t` | check the configuration and exit: `0` when it is clean, `1` when any setting has a bad value |
| `-d` | stay in the foreground |
| `-v` | more verbose; repeatable |
| `-V` | print the version and the release name |

### Checking the config

`elpis -t` names each line it refuses, and the check fails:

```
ERROR elpis.conf:2: bad value for 'access-control': 'bogus'
WARN  elpis.conf: 1 configuration error(s); defaults kept for those settings
...
ERROR configuration check failed: 1 error(s) in elpis.conf
```

A normal start logs the same lines and keeps going, with the default for each
setting it refused, so one typo doesn't take DNS away. For `access-control`,
the default means refusing the clients that line was meant to let in. Run
`elpis -t` before a restart; `contrib/elpis-update.sh` does, and won't restart
on a config that fails it.

> [!NOTE]
> Up to 2.4.5, `-t` printed `configuration OK` and exited `0` even after
> refusing a line, so a check before a restart let a bad value through. An
> unknown setting is still only a warning (`unknown setting '...' (ignored)`)
> and doesn't fail the check, so a misspelt name passes: read the warnings too.

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
