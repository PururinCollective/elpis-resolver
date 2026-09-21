# Troubleshooting

The failure modes that are hard to tell apart from the outside, and what
Elpis logs so you do not have to guess.

Before reporting any of them, get the exact build: the About window on the
[status page](status-page.md) shows the commit `make` built from, and a
`-dirty` suffix if the tree had uncommitted changes at the time.

## The query arrives but no answer comes back

A resolver that cannot route its reply looks exactly like one that is not
listening: the client times out either way. Elpis separates the two. Every
failed `sendmsg` is logged with the destination, the source address it tried,
and the kernel's reason:

```
WARN  could not send the reply to [2001:db8::5]:34766 from [2001:db8::1]:0:
      No route to host -- the query arrived but this host cannot route the
      answer back
```

If that line appears, the problem is routing, not DNS — `ip -6 route get`
the client address and see what the kernel says.

Replies are normally sent from whatever address the query arrived on, which is
what a multi-homed host wants. On a container whose global address sits on one
interface while the default route sits on another, the kernel rejects that
combination outright. Rather than lose the answer, Elpis drops the pinned
source and retries, letting the kernel choose; for an on-link client it picks
the same address anyway.

The same question applies outbound, so the root probe answers it before it
sends anything:

```
INFO  root probe: IPv4 queries will leave from 192.168.88.118:39698
INFO  root probe: IPv6 queries will leave from [2001:db8::1]:53539
INFO  root probe: 26 of 26 addresses answered (IPv4 13/13, IPv6 13/13), 3 rounds
```

That is a route lookup, not a packet, so it costs nothing and it distinguishes
*this host has no route for that family* from *the packets leave and nothing
comes back*. A host with no IPv6 route says so plainly:

```
INFO  root probe: no IPv6 route to the root servers (Network is unreachable)
```

Having an address is not the same as having a route. An interface can hold a
global IPv6 address and still carry no outbound traffic — `ifconfig` showing
millions of RX packets against a few hundred TX on that interface is the
signature. Use `outgoing-interface:` to pin the source address Elpis sends
from when the kernel's own choice is wrong.

## Something else on port 53

Before opening any socket, Elpis asks the kernel who is already listening on
the addresses it was told to bind, and names the process:

```
FATAL dnsmasq (pid 812) is already listening on 0.0.0.0:53/udp,
      which conflicts with 'listen: 0.0.0.0:53'
FATAL   command: /usr/sbin/dnsmasq --conf-file=/etc/dnsmasq.conf
FATAL   stop it, or move elpis to another port
```

This check is not cosmetic. Elpis sets `SO_REUSEADDR`, and **as root, Linux
lets a UDP socket bind a port another process already holds — with no error**.
Verified on a systemd-resolved host: a bind to `0.0.0.0:53`, and even to
`127.0.0.53:53` itself, succeeds silently while resolved keeps running, and
the kernel then splits arriving queries between the two at random. Waiting for
`bind()` to complain would mean waiting forever.

systemd-resolved is the one case handled automatically, since it is the one
that is both common and safely fixable. Running as root, on a port it holds:

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

Set `stop-systemd-resolved: no` to have it refuse instead. Nothing else is
ever stopped — an unrelated daemon on the port is reported and Elpis exits.
Under the shipped systemd unit it runs as `elpis`, not root, so it cannot stop
anything; the unit uses `Conflicts=systemd-resolved.service` and lets systemd
do it.

## Malformed input

Malformed input is dropped and counted. Every structural rule in RFC 1035 §4 is
checked before anything reaches the cache: compression pointers must aim
strictly backwards, rdlength must fit, counts must match, no trailing bytes,
per-type rdata layout must parse. Each drop is counted by reason and logged at
a rate limit, so a hostile peer cannot turn the log into its own amplifier.

```
queries=6094088 hits=5332228 (87.5%) recursions=761860 upstream=865
dropped 1503: spoof=1421 rdata=61 compress=21
```

---

[Caching](caching.md) · [Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Internals](internals.md)
