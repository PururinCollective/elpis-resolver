# 🩺 Troubleshooting

The failures that look alike from the outside, and what Elpis logs so you don't
have to guess.

| Symptom | Go to |
|---|---|
| The client times out | [The query arrives but no answer comes back](#-the-query-arrives-but-no-answer-comes-back) |
| One zone always fails, slowly | [A zone whose servers never answer](#-a-zone-whose-servers-never-answer) |
| SERVFAIL, and `bogus answer` in the log | [A name answered SERVFAIL as bogus](#-a-name-answered-servfail-as-bogus) |
| DoT is on, but nothing goes over it | [DoT not being used](#-dot-not-being-used) |
| Elpis won't start: something holds the port | [Something else on port 53](#-something-else-on-port-53) |
| `dropped` counts climbing | [Malformed input](#-malformed-input) |

> [!TIP]
> Before reporting anything, get the exact build. The About window on the
> [status page](status-page.md) shows the release and commit, and so does the
> identity probe:
> `dig @127.0.0.1 -p 5335 elpis.sakurako.oomuro TXT`

## 📭 The query arrives but no answer comes back

A resolver that can't route its reply looks exactly like one that isn't
listening: the client times out either way. Elpis tells them apart. **Every
failed `sendmsg` is logged** with the destination, the source address it tried,
and the kernel's reason:

```
WARN  could not send the reply to [2001:db8::5]:34766 from [2001:db8::1]:0:
      No route to host -- the query arrived but this host cannot route the
      answer back
```

If that line appears, it's routing, not DNS: `ip -6 route get <client>` and see
what the kernel says.

<sub>Replies normally go out from whatever address the query arrived on, which
is what a multi-homed host wants. On a container whose global address sits on
one interface while the default route sits on another, the kernel rejects that
combination outright. Rather than lose the answer, Elpis drops the pinned source
and retries, letting the kernel choose; for an on-link client it picks the same
address anyway.</sub>

**Outbound, the root probe answers the same question** before it sends anything:

```
INFO  root probe: IPv4 queries will leave from 192.168.88.118:39698
INFO  root probe: IPv6 queries will leave from [2001:db8::1]:53539
INFO  root probe: 26 of 26 addresses answered (IPv4 13/13, IPv6 13/13), 3 rounds
```

That's a route lookup, not a packet, so it costs nothing, and it separates *no
route for that family* from *the packets leave and nothing comes back*. A host
with no IPv6 route says so plainly:

```
INFO  root probe: no IPv6 route to the root servers (Network is unreachable)
```

> [!NOTE]
> Having an address isn't the same as having a route. An interface can hold a
> global IPv6 address and still carry no outbound traffic: `ifconfig` showing
> millions of RX packets against a few hundred TX is the signature. Use
> `outgoing-interface:` to pin the source address when the kernel's own choice
> is wrong.

## 🔇 A zone whose servers never answer

Some authorities drop every query from some networks.

> [!NOTE]
> `spectrum.com` is delegated to `ns1`–`ns4.charter.com`. In September 2026
> those servers answered no DNS query from our Malaysian test network, though
> they still answered ping, and public resolvers in the same region failed on
> them too. Every new name under it used to cost sixteen queries and the whole
> `query-total-timeout` before its SERVFAIL, and a steady stream of such names
> was a third of all upstream traffic.

**A server silent for 10 seconds and three queries, while others kept
answering, is held for `server-hold-down` seconds** (30 by default):

```
 query ──► server silent ×3, 10 s ──► HELD (30 s)  ──► one query lets through ──► back?
                                         │
                       whole zone held ──┴──► SERVFAIL at once, EDE 22 (No Reachable Authority)
```

- Counted on the status page as **cut short by a hold**, and as `held=` in the
  SIGUSR1 statistics.
- The **Held servers** window lists each server held, what for, when it's next
  tried, and which client's query set the hold off.
- **Holds are per question type**: a server that drops only HTTPS is still
  asked for A.
- **Silence while nothing else answers doesn't count**, so an outage on this
  host's own link holds nobody.
  <br><sub>An outage further along the path can, and a zone behind it may then
  fail for up to `server-hold-down` seconds after the path is back.</sub>
- `server-hold-down: 0` turns holds off.

> [!TIP]
> A hold makes a failure cheaper, but the answer is still SERVFAIL. When the
> zone is also served somewhere that does answer (as `spectrum.com` is by
> Akamai), a `stub-zone:` pointing at those servers gets real answers.

## 🚫 A name answered SERVFAIL as bogus

When an answer fails DNSSEC validation, the client gets SERVFAIL and the log gets
one line saying which RRset failed and why:

```
dnssec: bogus answer for imap-mail.outlook.com. A: atm.outlook.mira.tm.svc.cloud.microsoft. A,
8 records; RRSIG 24236/ECDSAP256SHA256 by cloud.microsoft.: failed the signature check;
keys cloud.microsoft.: 61899 28146 24236; 5 of 64 signature checks spent (EDE 6 DNSSEC Bogus); replying SERVFAIL
```

Reading it, left to right:

```
 question ─► the RRset that failed ─► each signature and what stopped it ─► the signer's key tags ─► the EDE sent
             (may be another name,
              in a CNAME chain)
```

| The line says | What it means |
|---|---|
| `no key with that tag` | The zone signed with a key its DNSKEY set doesn't hold. Usually a key rollover done too fast, or an out-of-date DNSKEY set. |
| `expired N s ago`, `not valid for another N s` | The signature's dates. If every zone shows this, check this host's clock. |
| `failed the signature check` | The key is there and the dates are fine, but the signature doesn't match the data. It was changed on the way, or the answer mixes records from two replies. |
| `N of 64 signature checks spent` at 64 | The answer used up the checks one answer may take (the KeyTrap limit, CVE-2023-50387) before it was proven. |
| `has no signature, and no unsigned delegation was proven` | A record with no signature, in a zone that's signed as far as the chain of trust can tell. |
| `NSEC/NSEC3 records, which do not prove` | A "no such name" or "no such data" whose proof doesn't cover the question. |
| `DS says ... digest does not match` | The parent's DS and the child's DNSKEY disagree: the zone's own mistake, usually after a key change at the registrar. |

> [!TIP]
> Zone or here? Ask a validating public resolver the same question. If 1.1.1.1
> answers it with AD set, the zone is fine, and the log line is the thing to
> report. `dig +cd +dnssec name @127.0.0.1` shows the records Elpis received,
> unchecked.

## 🔒 DoT not being used

With `authoritative-dot: opportunistic` on, open the status page's **DoT
servers** window:

| You see | It means |
|---|---|
| tests climbing, almost all **no reply** | normal: most authoritative servers drop port 853 without answering |
| **refused** climbing fast | an outbound firewall rejecting TCP/853, or servers that refuse it |
| no tests at all | the setting isn't on (`elpis -t` prints it), or every query is answered from cache, forwarded, or sent to a stub zone, none of which are tested |
| a server **failed**, retry in … | it answered over DoT once, then stopped; it's asked plain and tested again every `authoritative-dot-retry` |
| a server **given up** | `authoritative-dot-max-try` retries failed; plain from now on, until a restart or its cache entry is evicted |

<sub>dnscheck.tools shows ADoX when its test names reach a DoT-capable server
over TLS. `make tls-probe && bin/elpis-tls-probe <server address> <zone> SOA`
tries one server by hand.</sub>

## 🔌 Something else on port 53

Before opening any socket, Elpis asks the kernel who already listens on the
addresses it was told to bind, and names the process:

```
FATAL dnsmasq (pid 812) is already listening on 0.0.0.0:53/udp,
      which conflicts with 'listen: 0.0.0.0:53'
FATAL   command: /usr/sbin/dnsmasq --conf-file=/etc/dnsmasq.conf
FATAL   stop it, or move elpis to another port
```

> [!WARNING]
> This check isn't cosmetic. Elpis sets `SO_REUSEADDR`, and **as root, Linux
> lets a UDP socket bind a port another process already holds, with no error.**
> On a systemd-resolved host, a bind to `0.0.0.0:53`, and even to
> `127.0.0.53:53` itself, succeeds silently while resolved keeps running, and
> the kernel then splits arriving queries between the two at random. Waiting
> for `bind()` to complain would mean waiting forever.

**systemd-resolved is handled automatically**, since it's the one case both
common and safely fixable. Running as root, on a port it holds:

```
WARN  systemd-resolved (pid 460) is listening on 127.0.0.53:53,
      which conflicts with 'listen: 0.0.0.0:53'
INFO  stopping systemd-resolved so the port can be bound cleanly
INFO  systemd-resolved stopped
WARN  /etc/resolv.conf still points at the systemd-resolved stub (127.0.0.53),
      which is no longer listening -- this host cannot resolve names until you
      repoint it
WARN  systemd-resolved will come back on reboot; make it permanent with
      'systemctl disable --now systemd-resolved'
INFO  listening with 8 workers
```

- `stop-systemd-resolved: no` makes it refuse instead.
- Nothing else is ever stopped: an unrelated daemon on the port is reported and
  Elpis exits.

<sub>Under the shipped systemd unit it runs as `elpis`, not root, so it can't
stop anything. The unit uses `Conflicts=systemd-resolved.service` and lets
systemd do it. Stopping elpis starts resolved again, so the host isn't left with
no resolver, unless resolved is disabled, in which case it stays off. A restart,
or a crash that `Restart=` recovers from, leaves it stopped.</sub>

## 🧹 Malformed input

Dropped and counted. Every structural rule in RFC 1035 §4 is checked before
anything reaches the cache:

- compression pointers must aim strictly backwards
- rdlength must fit, and counts must match
- no trailing bytes
- per-type rdata layout must parse

Each drop is counted by reason and logged at a rate limit, so a hostile peer
can't turn the log into its own amplifier:

```
queries=6094088 hits=5332228 (87.5%) recursions=761860 upstream=865
dropped 1503: spoof=1421 rdata=61 compress=21
```

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
