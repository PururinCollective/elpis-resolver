# Mesh

Instances you run, telling each other what their clients ask, so a restarted
or newly started one is warm in seconds without writing anything to disk.

## What it is for

A [checkpoint](caching.md#surviving-a-restart) brings a restarted instance
back warm, but it is a file of what your clients looked up, and an operator
with a no-log policy will not keep one. It also does nothing for an instance
that has just been created.

With the mesh on, an instance that starts asks the others it can reach for
the questions their clients ask most, merges those with its own checkpoint if
it has one, and resolves the lot before its clients ask. The lists travel in
memory, over an encrypted connection, and nothing is written anywhere.

Measured on one host with three instances. The only one with clients was
restarted with no checkpoint and no bridges of its own; the other two, which
it had warmed earlier, dialled it back and sent it their lists:

| 60 sites (A, AAAA and HTTPS at once) | median | 90th percentile | slowest |
|---|---|---|---|
| cold, the first time | 95 ms | 576 ms | 1,065 ms |
| after the restart, warmed from its peers | 0 ms | 1 ms | 158 ms |

It was warm four and a half seconds after it started.

## Setting it up

Make one key and give every instance the same copy, readable by root alone:

```bash
elpis --gen-psk | sudo tee /etc/elpis/mesh.psk > /dev/null
```

```bash
sudo chmod 600 /etc/elpis/mesh.psk
```

Then, in each instance's `elpis.conf`:

```
mesh: yes
mesh-psk: /etc/elpis/mesh.psk
mesh-listen: 0.0.0.0@7878          # and/or [::]@7878
mesh-peer: 192.0.2.1@7878          # a bridge: one or more instances to dial
```

On one network segment `mesh-peer:` can be left out: the instances find each
other by multicast (below). Across segments, give each one a bridge on the
other side. The key is read, and the port bound, before privileges are
dropped, so the key file can belong to root. The mesh port is TCP; open it
only to your own instances. Listen on each address family your instances
reach each other over.

## How instances find each other

Three ways, and all three only say where to dial: the handshake is what lets
anyone in.

A **bridge** is an instance named in `mesh-peer:`. Each instance dials its
bridges, and every connected pair tells each other about the other instances
they are connected to (peer exchange). Instance #4 needs to know only instance
#1; it learns about #2 and #3 from #1 and dials them itself.

An address only a private network can reach is passed only to peers that are
on a private network themselves, a loopback address only to peers on loopback,
and an IPv6 link-local address to nobody, since nobody else could use it. Two
instances that dial each other at the same moment keep one connection and
close the other, and both ends agree on which without negotiating. An instance
that dials itself notices from the node id in the handshake and does not do it
again.

**On the local segment**, with `mesh-lsd: yes` (the default once the mesh is
on), each instance that takes connections announces itself by multicast when
it starts and every thirty seconds after, and the others dial it. The groups
are elpis's own, not BitTorrent's LSD group, so torrent clients never see
them: `239.255.78.78` (administratively scoped) and `ff12::7878` (link-local),
UDP port 7878, with a hop limit of 1, so they never leave the segment. Each
family announces only if the instance listens on it somewhere other than
loopback.

An announcement is 44 bytes: a magic string, the version, the mesh port, the
node id, and a 16-byte HMAC-SHA256 tag under a key derived from the PSK. An
announcement from another mesh or a stranger fails the tag and is dropped
without a word, so a network shared with other meshes, or with anyone else,
costs nothing. A copy replayed from another address can make an instance dial
that address at the announced port now and then, and the handshake fails
there. An instance heard on both IPv4 and IPv6, or reached through a bridge as
well, ends up with one connection: they are matched by node id, not address.

Measured on one host: with no `mesh-peer:` anywhere, an instance started next
to one with clients was found by multicast, sent that one's list, and warm
four and a half seconds after it started, its slowest answer 1 ms. One with a
different key, on the same segment, was never dialled and never logged.

## What travels, and when

**Lists carry names, never answers.** Each list entry is a question and two
numbers: how often it is asked, and how long it took to resolve cold.
Everything received is resolved and validated on the receiving instance like
any client query, so the worst a peer can do is spend some of your warm-up on
names nobody here wanted. (Answers travel only with `mesh-lookup:`, below.)

**Only popular names.** A name goes on a list only after clients asked for it
`mesh-share-min-hits` times (5 by default), so one person's one-off lookups
never leave the instance. `mesh-share: no` makes an instance take lists without
giving any.

**Only at startup.** An instance asks for lists during its first five minutes,
and a peer answers any one instance at most once a minute. Lists received in
the first three seconds are merged with the checkpoint and ranked together;
any that arrive later are warmed in turn, and a name already cached is skipped.
A peer's counts weigh half of the instance's own.

**Knowledge outlives the instance that gathered it.** A name warmed from a list
starts with half the count the list carried. If the only instance your clients
use restarts, the siblings it warmed hand its names back at a quarter of the
weight, and those fade over a few restarts unless clients ask for them again.

The trade-off is that every instance holding the key learns which names are
popular on the others. Give the key only to your own instances.

## Asking a peer on a miss

With `mesh-lookup: yes`, the mesh does more than warm restarts. A client
question that misses the cache is also sent to one nearby peer's cache while
this instance resolves it as usual, and whichever answers first goes to the
client. A lookup can make an answer sooner and never later.

- **Only a near peer is asked:** one whose round trip, measured on the mesh
  connection, is within `mesh-lookup-rtt` (10 ms by default). A peer far away
  is slower than resolving, and a CDN may have answered it for another place.
- **Only a peer that probably has it:** every half minute each instance sends
  its near peers a digest of its cache, a Bloom filter at ten bits an entry
  (about one false positive in a hundred, up to 2 MiB). A miss nobody can
  answer is never sent anywhere.
- **Only answers a client could be given:** A, AAAA and HTTPS questions, never
  with CD set, and only NOERROR, with records or without (NODATA). Never
  NXDOMAIN, never stale, and never with under three seconds to live; a second
  is taken off for the trip.
- **Trust, then verify.** A peer's answer goes to the client without AD,
  because this instance did not validate it. The same question is then
  resolved here at once, and this instance's own answer replaces the peer's in
  the cache, with AD where it validates. If our own resolution finds no answer
  where the peer had one, the peer's answer is dropped, the question is not
  sent to peers again for ten minutes, and the log says so:
  `mesh: a peer's answer for NAME TYPE was not confirmed here (NXDOMAIN); dropped`.

Lookups are UDP, straight from the workers to the peer's mesh port. Each
datagram is sealed with ChaCha20-Poly1305 under a key the answering instance
chose and handed to its peers inside the Noise session. That gives lookups the
session's forward secrecy, and the key is replaced every hour. A peer answers
only source addresses that belong to one of its live mesh connections, so a
lookup replayed from a forged address cannot aim an answer, many times its
size, at anyone else.

Measured on one host, with warm-up off so every fast answer came from a peer.
The question list is the same 60 sites, which one instance had resolved:

| 60 sites (A, AAAA and HTTPS at once) | median | 90th percentile |
|---|---|---|
| the instance that resolved them, cold | 214 ms | 683 ms |
| a second instance, asking the first on each miss | 0 ms | 348 ms |

The remaining tail is answers that had gone stale on the first instance, which
peers never share. Under real traffic a busy instance keeps those refreshed.
The mesh log line `mesh lookups: asked=… found=… used=… answered-for-peers=…`
(SIGUSR1) shows how often it pays.

## Encryption

Every connection is TCP under the Noise protocol framework,
`Noise_NNpsk0_25519_ChaChaPoly_SHA256`:

```
-> psk, e     initiator: an ephemeral X25519 key, under a key from the PSK
<- e, ee      responder: its own, and a Diffie-Hellman between the two
```

- **Knowing the key is the authentication.** Without it a peer cannot get past
  the first message, and the attempt is logged as
  `refused ...: handshake failed (a different mesh-psk?)`, at most once a
  minute. The instance dialling with the wrong key logs the same hint about
  its bridge.
- **Forward secrecy** comes from the ephemeral keys: each connection has its
  own, and none is kept afterwards.
- **The post-quantum hedge is the key itself.** Noise mixes the PSK into every
  session key, so an attacker who records traffic now and breaks X25519 later
  with a quantum computer still needs the PSK to read it. This is the same
  approach WireGuard takes with its optional PSK. A post-quantum key exchange
  (ML-KEM) would matter for instances that share no secret, which the mesh does
  not support.
- **Nothing is signed.** The handshake needs none, so no signing code is
  compiled into the resolver.

X25519 and ChaCha20-Poly1305 are implemented in this tree like the rest of the
cryptography, but unlike the DNSSEC verifiers they handle secrets, so they run
in constant time. Both are checked against the RFC 7748 and RFC 8439 test
vectors, and the handshake byte for byte against an independent implementation
of the Noise specification.

## The protocol

On the wire every message is a two-byte length and then that many bytes. The
two handshake messages each carry a hello: a version byte, a flags byte (bit 0:
this instance answers list requests), the port it takes connections on (0 for
none) and a random 16-byte node id. After the handshake, each message is
encrypted, and inside it is a type byte and a body:

| type | body |
|---|---|
| 1 `LIST_REQ` | u32: the most names wanted |
| 2 `LIST_PART` | entries: u32 hits, u16 ms, u8 DO/CD bits, u16 type, u8 length, name in wire form |
| 3 `LIST_END` | u32: how many entries were sent |
| 4 `PEERS` | u8 count, then per peer: u8 4 or 6, the address, u16 port |
| 5 `PING`, 6 `PONG` | u64 token |

A message of an unknown type is skipped, so a later version can add more. A
connection that sends nothing for two minutes is closed; `PING` goes every
thirty seconds.

---

[Caching](caching.md) · [Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Troubleshooting](troubleshooting.md)
