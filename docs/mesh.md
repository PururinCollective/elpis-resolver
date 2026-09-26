# Mesh

The mesh connects elpis instances you run. They tell each other which names
their clients ask for most. When one of them restarts, or a new one starts,
it gets those names from the others and is warm in seconds. Nothing is written
to disk.

## At a glance

- **The mesh is a group of your own instances.** They find each other, keep
  encrypted connections open, and help each other warm up.
- **One shared key lets an instance in.** Every instance in the mesh has a copy
  of the same key file, the PSK. Think of it as the mesh's password.
- **Community instances need only the key.** This is the easy way, and the
  right place to start.
- **Signed instances also hold a certificate** from whoever issues licences for
  your builds. A signed instance learns only from other signed instances, so a
  leaked key alone cannot feed it anything. Add signing later, if you need it.

What you get, measured on one host with three instances. The only one with
clients was restarted with no [checkpoint](caching.md#surviving-a-restart); the
other two sent it their lists:

| 60 sites (A, AAAA and HTTPS at once) | median | 90th percentile | slowest |
|---|---|---|---|
| cold, the first time | 95 ms | 576 ms | 1,065 ms |
| after the restart, warmed from its peers | 0 ms | 1 ms | 158 ms |

It was warm four and a half seconds after it started.

## Words used on this page

| word | what it means |
|---|---|
| instance | one running elpis resolver |
| peer | another instance this one is connected to |
| PSK, mesh key | the key file every instance in the mesh shares (`mesh.psk`) |
| bridge | an instance that another one dials first (`mesh-peer:`) |
| community instance | an instance with only the PSK |
| signed instance | an instance that also has an instance key and a certificate for it |
| issuer | whoever holds `issuer.key` and signs licences and certificates, usually whoever builds and hands out the binaries |
| certificate | one `mesh-cert: elpism1...` line from the issuer, for one instance key |

## Before you start

- **Every instance needs a build with mesh version 2.** That is this version.
  Older builds cannot connect to it, so update all of your instances together.
- **The paths below are the usual ones:** the program at
  `/opt/elpis-resolver/bin/elpis`, its config at
  `/opt/elpis-resolver/bin/elpis.conf`, and the keys in `/etc/elpis/`. Change
  them if yours differ.
- **The systemd steps need systemd 247 or later:** Debian 11, Ubuntu 22.04,
  RHEL 9, or newer.

## Quick start: a community mesh

### Step 1: make the mesh key

Do this once, on any machine that has elpis:

```bash
(umask 077; /opt/elpis-resolver/bin/elpis --gen-psk > mesh.psk)
```

This makes `mesh.psk` in the current directory, readable only by you. Anyone
who has this file can join your mesh, so treat it like a password.

### Step 2: copy the key to every instance

For each instance:

```bash
scp mesh.psk admin@resolver1:
```

Then, on that instance (and on the machine where you made the key, if it is
an instance too, only this):

```bash
sudo install -D -m 600 mesh.psk /etc/elpis/mesh.psk && rm mesh.psk
```

The key is now in `/etc/elpis/mesh.psk`, readable only by root.

### Step 3: let the service read the key

The shipped systemd unit runs elpis as its own user, never as root, so elpis
cannot read a file that only root can read. systemd reads it instead and hands
elpis a private copy. Add a small drop-in file for this:

```bash
sudo mkdir -p /etc/systemd/system/elpis.service.d
printf '[Service]\nLoadCredential=mesh.psk:/etc/elpis/mesh.psk\n' | \
    sudo tee /etc/systemd/system/elpis.service.d/mesh.conf
sudo systemctl daemon-reload
```

The shipped unit ([contrib/elpis.service](../contrib/elpis.service)) has the
same line, commented out. Use one or the other, not both. The drop-in stays in
place when you reinstall the unit.

If you start elpis as root yourself, without systemd, skip this step. elpis
reads the key before it drops to its `user:`, so give the full path in step 4
instead: `mesh-psk: /etc/elpis/mesh.psk`.

### Step 4: turn the mesh on

Add these lines to `/opt/elpis-resolver/bin/elpis.conf` on every instance:

```
mesh: yes
mesh-psk: mesh.psk
mesh-listen: 0.0.0.0@7878
```

`mesh-psk: mesh.psk` is the name from step 3, not a path. Use `[::]@7878` as
well, or instead, if your instances reach each other over IPv6.

On every instance except the first, also add a bridge: the address of one
instance that is already running.

```
mesh-peer: 192.0.2.1@7878
```

One bridge is enough. An instance learns about the others through it. On one
local network you can leave `mesh-peer:` out: instances there find each other
by themselves.

### Step 5: restart and check

```bash
sudo systemctl restart elpis
sudo journalctl -u elpis -n 50 | grep mesh
```

You should see lines like these:

```
mesh: a community instance; takes lists, answers and lookups from any peer
mesh: node 5c1e20aa, 1 listener, 1 bridge, local discovery on IPv4
mesh: up with 192.0.2.1:7878 (node 8a03f4c2, we dialled; community)
```

`up with` means the two instances are connected. The **Mesh Network** window
on the [status page](status-page.md) shows the same thing, with a row for each
peer.

**Firewall:** open port 7878, TCP and UDP, between your instances, and to
nobody else. TCP carries the connections. UDP carries lookups
(`mesh-lookup:`) and, on a local network, discovery.

If something is not right, see [When something goes wrong](#when-something-goes-wrong).

## Signed and community instances

The PSK decides who is in the mesh. Inside the mesh there are two kinds of
instance:

- **Community:** it has the PSK and nothing else.
- **Signed:** it also has an instance key and a certificate for that key from
  your licence issuer. It proves it holds the key every time it connects.

Both kinds work together in one mesh, but they trust each other differently.
What an instance knows (its name lists, answers and lookups) only goes one way:

| from ↓ / to → | signed | community |
|---|---|---|
| signed | yes | yes |
| community | no | yes |

- **A signed instance learns only from signed peers.** It never asks a
  community peer for anything. It still answers community peers when they ask.
- **A community instance learns from everyone.**

So a signed instance cannot be fed wrong data by an instance that only has the
PSK. That is the main reason to sign: if the PSK leaks, or you share a mesh
with people you trust less, your signed instances stay safe.

A peer counts as signed only when all of these are true. If any is false, the
peer is community, whatever its config says about itself (`edition:` in a
config file counts for nothing here).

- Its certificate was signed by the issuer this build knows.
- The certificate has not expired.
- The certificate is for the key the peer just proved it holds. A certificate
  copied from someone else's `elpis.conf` does not work without their key file.
- The certificate names your own organisation, or one you list in
  `mesh-trust-org:`.

A community instance learns from everyone anyway, so for it "signed" is only
information to show you. A stock build has no issuer key and cannot check
certificates at all, so to it every peer is community. That is fine.

## Signed instances, step by step

Signing an instance takes three parts, done by different people:

| who | what | how often |
|---|---|---|
| the issuer | makes the issuer key, and signs certificates | the key once; a certificate per request |
| each organisation | makes one instance key, and asks the issuer for a certificate | once |
| each signed instance | copies two files, adds two lines to its config | once per instance |

If you run everything yourself, you are all three.

### Part 1: the issuer, once

The issuer needs a source checkout of elpis. Build the licence tool and make
the issuer key:

```bash
make licence-tool
./bin/elpis-licence keygen issuer.key
```

It prints the **public key**, 64 hex characters, like `6cd740f1...dd6315`.
The public key is not secret: give it to everyone who builds elpis for the
mesh.

`issuer.key` is secret, and it is everything. Anyone who has it can sign
certificates and licences that your builds will believe. Keep it off your
servers and out of git, and keep a backup. The tool also keeps
`issuer.key.serial` next to it, to number what it signs. Keep the two files
together.

### Part 1b: every machine that builds elpis

A build checks certificates against the issuer's public key, so the key has to
be in the build. Put it in `local.mk`, in the top directory of the source tree:

```bash
echo 'LICENCE_ISSUER = 6cd740f1...dd6315' | sudo tee /opt/elpis-resolver/local.mk
```

Then rebuild the way you usually do: [elpis-update](../contrib/elpis-update.sh),
or `make` and a restart. `local.mk` stays when you pull updates, and builds run
with sudo still read it. Check that the key is in the new build:

```bash
/opt/elpis-resolver/bin/elpis -V
```

```
elpis 2.0.2
licence issuer: 6cd740f1...dd6315
```

`licence issuer: none` means the key did not reach the build. Check the file
name and the spelling.

Every signed instance needs such a build. A community instance does not, but
with one it can show which of its peers are signed.

### Part 2: each organisation, once

On one of your instances, make the instance key:

```bash
sudo sh -c 'umask 077; /opt/elpis-resolver/bin/elpis --mesh-keygen > /etc/elpis/mesh.key'
```

The key goes into `/etc/elpis/mesh.key`, and its public half is printed on the
screen:

```
public key, for the licence issuer to certify:

  6d3fa91c...
```

Send two things to the issuer: that public key, and your organisation's name
exactly as you want it on the certificate, for example `Pururin Collective`.
Neither is secret.

The issuer signs it:

```bash
./bin/elpis-licence issue --key issuer.key --org "Pururin Collective" \
    --mesh-key 6d3fa91c... --days 365
```

```
mesh certificate for "Pururin Collective", serial 3, key 6d3fa91c..., expires 2027-09-27
add this line to that instance's elpis.conf:

mesh-cert: elpism1.AQAAAAMAAAAA...
```

The issuer sends you back that `mesh-cert:` line. It is not secret either:
without `mesh.key` it is useless.

**One key for the whole organisation.** A certificate belongs to a key, not to
a machine. So you can put the same `mesh.key` and the same `mesh-cert:` line on
every instance you run, just like the PSK. That is one request to the issuer,
not one per instance. The cost: if `mesh.key` leaks, someone can join as your
organisation until the certificate expires, and to retire one instance you
must replace the key on all of them. If that matters to you, make a key for
each instance instead, and repeat Part 2 for each one.

### Part 3: each signed instance

1. **Copy the instance key** to the instance. Skip this on the instance where
   you made it. There, first take a copy you can send, owned by you:

   ```bash
   sudo install -m 600 -o "$USER" /etc/elpis/mesh.key ~/mesh.key
   ```

   Send `~/mesh.key` to each other instance with `scp`, as in step 2, then
   delete your copy. On each instance that receives it:

   ```bash
   sudo install -D -m 600 mesh.key /etc/elpis/mesh.key && rm mesh.key
   ```

2. **Let the service read it.** Replace the drop-in from step 3 with one that
   passes both keys:

   ```bash
   printf '[Service]\nLoadCredential=mesh.psk:/etc/elpis/mesh.psk\nLoadCredential=mesh.key:/etc/elpis/mesh.key\n' | \
       sudo tee /etc/systemd/system/elpis.service.d/mesh.conf
   sudo systemctl daemon-reload
   ```

3. **Add the two lines** to `elpis.conf`, next to the mesh lines from step 4:

   ```
   mesh-key: mesh.key
   mesh-cert: elpism1.AQAAAAMAAAAA...
   ```

   Started as root without systemd, use the full path instead:
   `mesh-key: /etc/elpis/mesh.key`.

4. **Restart and check:**

   ```bash
   sudo systemctl restart elpis
   sudo journalctl -u elpis -n 50 | grep mesh
   ```

   ```
   mesh: signed, for "Pururin Collective" (certificate 3, expires 2027-09-27); takes lists, answers and lookups from signed peers only
   mesh: up with 192.0.2.1:7878 (node 8a03f4c2, we dialled; signed, "Pururin Collective", certificate 2)
   ```

   On the status page, the Mesh Network window says **signed** for this
   instance, and flags each signed peer with `C`.

If the log says `... this instance joins as a community one` instead, it tells
you why:

| the log says | what to do |
|---|---|
| `this build carries no licence issuer key to check mesh-cert: against` | the build lacks the issuer's public key: do Part 1b, and check `elpis -V` |
| `mesh-cert: needs mesh-key:, the key it was issued for` | add `mesh-key: mesh.key`, and its `LoadCredential=` line |
| `mesh-cert: does not verify: ...` | the line was cut short when you pasted it, or the certificate is from another issuer than the key in this build |
| `mesh-cert: was issued for another key than the one in mesh.key` | this `mesh.key` is not the one the certificate was made for: copy the right file |
| `mesh-cert: expired on ...` | ask the issuer for a new certificate for the same public key; `mesh.key` stays as it is |

## Two organisations in one mesh

1. Both organisations use the same PSK, so they are in the same mesh.
2. Both organisations' builds carry the same issuer key (Part 1b). A build can
   check only its own issuer's certificates. Another issuer's certificates look
   like community to it.
3. Each organisation trusts the other's name, in `elpis.conf` on its signed
   instances:

   ```
   mesh-trust-org: Another ISP, AS64501
   ```

The name must match the certificate exactly, letter for letter.
`elpis-licence verify` shows the name on a certificate. You can repeat the line
for more organisations. Until you add it, the other organisation's signed
instances appear as community, and the log says why:

```
mesh: up with 192.0.2.7:7878 (node 5c1e20aa, it dialled; community: its
certificate is not taken, it is for "Another ISP, AS64501", not an organisation trusted here)
```

## Signed instances only

To keep community instances out completely, add this on your signed instances:

```
mesh-require-licence: yes
```

The instance must be signed itself, or its mesh stays off. A community
instance that tries to connect is turned away:

```
mesh: refused 192.0.2.9:40112: no certificate: a community instance, and this mesh takes signed ones only
```

The community instance logs `it did not let us in (a mesh of signed instances
only?)`.

## When something goes wrong

| the log says | what it means | what to do |
|---|---|---|
| `cannot read /etc/elpis/mesh.psk: Permission denied. elpis is not running as root, ...` | the config gives a path, but the service cannot read the file | do step 3, and write `mesh-psk: mesh.psk` in the config |
| `'mesh-psk: mesh.psk' names a systemd credential, and elpis was given none` | the config names a credential, but systemd did not pass it | do step 3, and run `sudo systemctl daemon-reload` |
| `handshake failed (a different mesh-psk, ...)`, or on the dialling side `closed during the handshake (a different mesh-psk, ...)` | the two instances have different key files, or one runs a build from before mesh version 2 | copy the same `mesh.psk` to both; update both |
| `it did not let us in (a mesh of signed instances only?)` | the other instance has `mesh-require-licence: yes`, and this one is not signed | sign this instance, or remove that setting there |
| `community: its certificate is not taken, it is for "...", not an organisation trusted here` | the peer is signed by another organisation | add `mesh-trust-org:` for it, if you trust it |
| `community: its certificate is not taken, it is for a key the peer did not prove` | the peer shows a certificate that belongs to another key | the peer has the wrong `mesh.key`, or copied someone's certificate |
| `no 'mesh-listen:', no 'mesh-peer:' and 'mesh-lsd: no', so there is no one to talk to` | the mesh has nothing to connect to | add `mesh-listen:` or `mesh-peer:` (step 4) |
| no `up with` line at all | the instances cannot reach each other | check the firewall (port 7878, TCP and UDP) and the `mesh-peer:` address |

---

## How it works

The rest of this page explains the details. You do not need it to set up a
mesh.

### How instances find each other

There are three ways. All three only say where to dial. The handshake decides
who gets in.

**Bridges.** Each instance dials the bridges in its `mesh-peer:`. Connected
instances also tell each other about the other instances they know (peer
exchange). So instance #4 only needs to know instance #1. It learns about #2
and #3 from #1, and dials them itself.

Some addresses are only useful to some peers, so they are passed on carefully:

- An address only a private network can reach is passed only to peers that are
  on a private network themselves.
- A loopback address is passed only to peers on loopback.
- An IPv6 link-local address is passed to nobody.

If two instances dial each other at the same moment, they keep one connection
and close the other. Both ends agree on which one without talking about it.
An instance that dials itself sees its own node id in the handshake, and does
not do it again.

**Local network discovery.** With `mesh-lsd: yes`, the default once the mesh
is on, each instance that takes connections announces itself by multicast
when it starts, and every thirty seconds after that. The others hear it and
dial it.

- The groups are elpis's own, not BitTorrent's, so torrent clients never see
  them: `239.255.78.78` and `ff12::7878`, on UDP port 7878.
- The hop limit is 1, so the announcements never leave the local network.
- An instance announces on IPv4 or IPv6 only if it listens on that family
  somewhere other than loopback.

An announcement is 44 bytes: a magic string, the version, the mesh port, the
node id, and a 16-byte HMAC-SHA256 tag made with a key derived from the PSK.
An announcement from another mesh, or from a stranger, fails the tag and is
ignored without a log line. So sharing a network with other meshes costs
nothing. A copy replayed from another address can make an instance dial that
address now and then, and the handshake fails there. An instance heard on both
IPv4 and IPv6, or also reached through a bridge, still gets only one
connection, because connections are matched by node id, not by address.

Measured on one host, with no `mesh-peer:` anywhere: a new instance started
next to one with clients was found by multicast, got that one's list, and was
warm four and a half seconds after it started. Its slowest answer was 1 ms. An
instance with a different key on the same network was never dialled and never
logged.

### What is shared, and when

- **Lists carry names, not answers.** Each entry is a question and two numbers:
  how often it is asked, and how long it took to resolve cold. The instance
  that receives a list resolves and validates every name itself, like any
  client query. So the worst a list can do is spend some of your warm-up on
  names nobody here wanted. Answers are shared only with `mesh-lookup:` and
  `mesh-share-answers:`, below.
- **Only popular names are shared.** A name goes on a list only after clients
  asked for it `mesh-share-min-hits` times (5 by default). One person's one-off
  lookups never leave the instance. With `mesh-share: no`, an instance takes
  lists but gives none.
- **Lists are asked for only at startup.** An instance asks for lists during
  its first five minutes. A peer answers any one instance at most once a
  minute. Lists that arrive in the first three seconds are merged with the
  checkpoint and ranked together. Lists that arrive later are warmed in turn,
  and names already in the cache are skipped. A peer's counts weigh half as
  much as the instance's own.
- **What was learned survives the instance that learned it.** A name warmed
  from a list starts with half the count the list carried. If the only instance
  your clients use restarts, the instances it warmed hand its names back, at a
  quarter of the weight. Those names fade over a few restarts unless clients
  ask for them again.

The cost: every instance that holds the PSK learns which names are popular on
the others. Give the PSK only to instances you trust with that.

### Asking a peer on a miss

With `mesh-lookup: yes`, the mesh does more than warm restarts. When a client
question is not in the cache, the instance also sends it to one nearby peer,
while it resolves the question as usual. Whichever answer comes first goes to
the client. So a lookup can only make an answer faster, never slower.

- **Only a near peer is asked:** one whose round trip is within
  `mesh-lookup-rtt` (10 ms by default). The lowest round trip measured on the
  connection counts, since a busy moment only ever adds delay. A far peer is
  slower than resolving, and a CDN may have given it an answer meant for
  another place.
- **Only a peer that probably has the answer is asked.** Every thirty seconds,
  each instance sends its near peers a digest of its cache: a Bloom filter with
  ten bits per entry, about one false match in a hundred, at most 2 MiB. A
  miss that no peer can answer is not sent anywhere.
- **Only answers a client could be given:** A, AAAA and HTTPS questions, never
  with CD set, and only NOERROR, with records or without (NODATA). Never
  NXDOMAIN, never stale, and never with less than three seconds to live. One
  second is taken off for the trip. A peer passes on only its own answers,
  never one it got from another peer and has not checked yet.
- **Trust, then check.** A peer's answer goes to the client without AD,
  because this instance did not validate it. Then this instance resolves the
  same question at once. Its own answer replaces the peer's in the cache, with
  AD if it validates. If its own resolution finds no answer where the peer had
  one, the peer's answer is dropped, the question is not sent to peers again
  for ten minutes, and the log says:
  `mesh: a peer's answer for NAME TYPE was not confirmed here (NXDOMAIN); dropped`.
- **A signed instance asks only signed peers.**

Lookups are UDP, sent straight from the workers to the peer's mesh port. Each
one is sealed with ChaCha20-Poly1305 under a key that the answering instance
chose and sent to its peers over the encrypted connection. So lookups have the
same forward secrecy as the connection, and the key changes every hour. A peer
answers only addresses that belong to one of its mesh connections. So a lookup
replayed from a forged address cannot send a large answer to someone else.

Measured on one host, with warm-up off, so every fast answer came from a peer.
The same 60 sites, which one instance had resolved:

| 60 sites (A, AAAA and HTTPS at once) | median | 90th percentile |
|---|---|---|
| the instance that resolved them, cold | 214 ms | 683 ms |
| a second instance, asking the first on each miss | 0 ms | 348 ms |

The slow part that remains is answers that had gone stale on the first
instance. Peers never share stale answers. With real traffic, a busy instance
keeps them fresh. The log line
`mesh lookups: asked=… found=… used=… answered-for-peers=…` (on SIGUSR1) shows
how often it helps.

### Answers with the list

With `mesh-share-answers: yes` on both ends, a restarting instance asks a
nearby peer for its answers as well as its names. The answers go into the
cache as they arrive, a few milliseconds after the connection comes up. So a
client that asks in the first seconds gets an answer at once, instead of
waiting for the warm-up to reach that name. Most names are unsigned, so this
covers most of what a restart would otherwise wait for.

- **Only unsigned answers.** A peer sends an answer only if its own validator
  proved the name unsigned, so DNSSEC could not have protected it anyway. A
  signed name gets no stand-in: it waits for this instance's own answer. So a
  validating client sees AD exactly where it would without the mesh. A name
  that fails validation, such as dnscheck.tools' `badsig` names, never gets a
  NOERROR answer, so it is never sent either.
- **Only what a browser waits for:** A, AAAA and HTTPS, and only NOERROR, with
  records, or as NODATA with the zone's SOA. Never NXDOMAIN, never for a
  question asked with CD, and never with less than ten seconds left.
- **Only first-hand answers.** A peer sends only answers it resolved itself.
  An answer it got from another peer, and has not checked, is never passed on,
  by a list or by a lookup. So one bad answer cannot spread through the mesh.
- **Only from a near peer.** Answers are asked for only once the peer's round
  trip is known to be within `mesh-lookup-rtt`. In practice that means the
  same site, with the same way out to the internet. A CDN answers according to
  where the resolver asking it is, so a far peer's answer could send your
  clients to the wrong servers. A far peer still sends its names.
- **A signed instance takes answers only from signed peers.**
- **Checked, then replaced.** A peer's answer goes out without AD, stays for
  ten minutes at most, and is never served stale. The warm-up resolves the same
  names here. The first client served a peer's answer also starts a check at
  once. This instance's own answer then replaces the peer's. If its own finds
  nothing, the peer's answer is dropped, and the question is not asked of peers
  for ten minutes. A peer's answer never replaces a live answer of this
  instance's own.
- **A peer whose answers keep failing is cut off.** When ten of a peer's
  answers have failed their check, and that is more than a quarter of those
  checked, the rest of its answers are dropped. It is asked for no more
  answers, and sent no more lookups, for as long as this instance runs. The log
  says so: `mesh: 12 of 40 answers from 192.0.2.7:7878 failed their check here; ...`.
  An honest peer's answer fails only when a name breaks between its resolution
  and this one.

The check cannot catch a wrong address for a name that does resolve. Two
honest answers from a CDN often share no address, so a different answer is
not a sign of a forged one. A forged address stays until the warm-up, or a
client's check, replaces it. That is the same trust `mesh-lookup` gives a peer
one name at a time, here given to a whole list at once. So turn it on only
among instances you run. If the PSK might reach people you trust less, make
your instances signed: a signed instance takes answers only from other signed
instances.

Measured on one host. One instance resolved the 60 sites. A second one, with
the first as its bridge and no checkpoint, was restarted and asked for all 60
one second after it started. With answers, it took 145 of the first
instance's answers, and its own resolution confirmed every one of them later.
The last two rows slow the warm-up to 20 names a second. That way the 180
questions take nine seconds, as a list of 1,800 would at the default
`warm-rate`:

| 60 sites (A, AAAA and HTTPS at once) | median | 90th percentile | slowest | within 5 ms |
|---|---|---|---|---|
| names only | 0 ms | 171 ms | 901 ms | 51 |
| names and answers | 0 ms | 24 ms | 651 ms | 52 |
| names only, warm-up at 20 a second | 22 ms | 305 ms | 903 ms | 26 |
| names and answers, warm-up at 20 a second | 0 ms | 52 ms | 743 ms | 46 |

The slow ones that remain are signed names, which get no stand-in on purpose,
and CDN answers that had less than ten seconds left on the first instance.

### Encryption

Every connection is TCP, encrypted with the Noise protocol framework,
`Noise_XXpsk0_25519_ChaChaPoly_SHA256`:

```
-> psk, e            dialler: an ephemeral X25519 key, under a key from the PSK
<- e, ee, s, es      the other: its own, a Diffie-Hellman between the two, and
                     its static key, proved with a second Diffie-Hellman
-> s, se             dialler: its static key, proved the same way
```

- **The PSK is what lets an instance in.** Without it, a peer cannot get past
  the first message. The attempt is logged as
  `refused ...: handshake failed (a different mesh-psk, ...)`, at most once a
  minute. The instance that dialled with the wrong key logs the same hint about
  its bridge.
- **Each side proves a static key.** A signed instance uses the key its
  certificate names. A community instance makes a new one each time it starts,
  and forgets it when it stops. So there is nothing to make, copy or keep.
- **Forward secrecy** comes from the ephemeral keys. Each connection has its
  own, and none is kept afterwards.
- **The PSK is also the protection against a future quantum computer.** Noise
  mixes the PSK into every session key. So an attacker who records traffic now
  and breaks X25519 later still needs the PSK to read it. WireGuard does the
  same with its optional PSK. A post-quantum key exchange (ML-KEM) would matter
  only for instances that share no secret, and the mesh always has one.
- **Nothing is signed during the handshake.** The handshake needs no
  signatures, so no signing code is built into the resolver.

X25519 and ChaCha20-Poly1305 are implemented in this tree, like the rest of the
cryptography. Unlike the DNSSEC verifiers, they handle secrets, so they run in
constant time. Both are checked against the RFC 7748 and RFC 8439 test
vectors, and the handshake byte for byte against an independent implementation
of the Noise specification.

### What a certificate proves, and what it does not

- **A leaked PSK is not enough to be signed.** That also takes an instance key
  that the issuer certified. With the issuer key kept safe, nobody else can make
  one.
- **A copied certificate is useless.** Each side does a Diffie-Hellman with its
  private key. A certificate taken from someone's `elpis.conf` names a key the
  thief does not have, so it is not accepted: `it is for a key the peer did not
  prove`.
- **Expiry retires a key.** An expired certificate makes an instance community,
  and keeps it out of a mesh of signed instances only. That is safe: the mesh
  only makes answers faster, so a lapsed certificate costs speed, never an
  answer.
- **It does not vouch for the program.** A patched build can remove its own
  checks, as [licensing.md](licensing.md) explains. But it still cannot prove a
  key it does not have. So a certificate says "the issuer handed out this key",
  not "this software is unmodified".

The instance key is a key-agreement key (X25519), not a signing key, so the
resolver still contains no signing code. A certificate is its own kind of
token, signed in its own context. A licence can never pass as a certificate,
and a certificate can never pass as a licence.

### Watching it on the status page

The status page's **Mesh Network** window shows the mesh as this instance sees
it, in four tabs:

- **General:** whether this instance is signed or community, which
  organisations count as signed, and counts of lists, lookups and answers:
  taken from peers, confirmed and dropped.
- **Trackers:** the bridges, peer exchange and local discovery, and every
  address heard of.
- **Peers:** each peer's host name, address, port, version and flags.
- **Content:** the most recent names asked and answered, lists, answers and
  warm-ups.

The flags in the Peers tab:

| flag | meaning |
|---|---|
| `B`, `X`, `L` | how the peer was found: a bridge, peer exchange, local discovery |
| `I`, `O` | it dialled us, or we dialled it |
| `C` | signed: its certificate checked out, for an organisation trusted here |
| `N` | this instance is signed and the peer is not, so we take nothing from it |
| `U` | it shows a certificate that this build cannot check (no issuer key) |
| `K`, `D` | we hold its lookup key, and its cache digest |
| `S` | it shares its list of names |
| `A` | we asked it for its answers too |
| `R` | its answers are refused: too many failed their check |

A `!` next to a peer's name means it showed a certificate that was not
accepted. Hover over the name to see why. Peers send each other their host
name and version for this window, in a message that older versions skip. The
Content tab keeps the last 256 exchanges in memory, and only while the status
page is on. It is the same kind of information as the Top names window, and it
is never written anywhere. See [Status page](status-page.md).

### The protocol

This is mesh version 2. Version 1, from before signed and community instances
could share a mesh, used `NNpsk0` and cannot complete a handshake with
version 2. Every instance in a mesh needs the same version.

On the wire, every message is a two-byte length and then that many bytes.
Handshake message 1 carries nothing. Messages 2 and 3 each carry a hello, then
a two-byte length and the sender's certificate, or a length of 0 and no
certificate. A hello is a version byte (2), a flags byte (bit 0: this instance
answers list requests), the port it takes connections on (0 for none), and a
random 16-byte node id. After the handshake, every message is encrypted.
Inside, each one is a type byte and a body:

| type | body |
|---|---|
| 1 `LIST_REQ` | u32: the most names wanted |
| 2 `LIST_PART` | entries: u32 hits, u16 ms, u8 DO/CD bits, u16 type, u8 length, name in wire form |
| 3 `LIST_END` | u32: how many entries were sent |
| 4 `PEERS` | u8 count, then per peer: u8 4 or 6, the address, u16 port, its 16-byte node id |
| 5 `PING`, 6 `PONG` | u64 token |
| 7 `LOOKUP_KEY` | u32 key id, 32-byte key: the key to seal lookups to the sender with |
| 8 `DIGEST` | u32 sequence, u32 bits, u8 probes, u32 total bytes, u32 offset, then that part of the Bloom filter |
| 9 `INFO` | three strings, each a length byte and its bytes: host name, version, build |
| 10 `ANSWERS_REQ` | u32: the most answers wanted |
| 11 `ANSWERS` | entries: u8 DO bit, u16 length, a DNS response with its question |
| 12 `ANSWERS_END` | u32: how many entries were sent |
| 13 `NO_DIGEST` | nothing: the sender takes nothing from us, so our digests would go unread |

A message of an unknown type is skipped, so a later version can add more. A
connection that sends nothing for two minutes is closed. `PING` goes every
thirty seconds, and sooner while a new peer's round trip still looks too far.

---

[Caching](caching.md) · [Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Licensing](licensing.md) · [Troubleshooting](troubleshooting.md)
