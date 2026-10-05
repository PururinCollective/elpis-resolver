# 🧩 Zones whose servers misbehave

Most of the DNS answers every question, one way or another. Some zones don't:
a firewall in front of the servers drops query types it was never taught, or a
load balancer answers the types it balances and ignores the rest.

```
 browser asks:   A ✔     AAAA ✔     HTTPS ✘ … silence … SERVFAIL, seconds later
```

Resolved by the book, that ends in SERVFAIL for a question with a perfectly good
answer: *there is nothing of that type here.*

> [!NOTE]
> Browsers ask for the HTTPS record of every site they open, alongside A and
> AAAA. A zone that drops HTTPS queries makes every visit wait for that lookup
> to time out before the browser gives up on it.

Elpis deals with it in two ways.

## 📭 Answers that can only mean "no data"

Two kinds of reply from a zone's own servers say nothing at all:

| reply | looks like |
|---|---|
| **An empty reply** | NOERROR, no record in it, no SOA, not authoritative |
| **A referral back to the zone itself** | the zone's own NS records, not authoritative, nothing else |

A load balancer sends one of these for a type it doesn't handle. **If every
server of the zone has been asked, none gave a real answer, and at least one
gave one of these two, the answer is "no data".** 1.1.1.1 answers the same way.

<sub>Elpis used to treat both as a broken server, try the next one, and go round
the servers three times before giving up with SERVFAIL.</sub>

## 📋 The quirk list

Some zones have to be named in advance, because what they do can't be told
apart from a dead server without waiting:

| Quirk | What the zone's servers do | What Elpis does instead |
|---|---|---|
| `drops-svcb` | Never answer HTTPS or SVCB queries, though every older type works | Answers HTTPS and SVCB with "no data" straight away, without asking |
| `empty-nodata` | Give the empty reply above for types they don't serve | Takes the first such reply as "no data" |
| `selfref-nodata` | Refer back to the zone itself for types they don't serve | Takes the first such reply as "no data" |

<sub>A quirk covers the zone it names and everything below it that the same
servers answer for. It's matched against the zone being asked (the delegation),
not the name in the question.</sub>

### Built in

The list is in [`src/quirks.c`](../src/quirks.c). Each entry records what was
seen:

| Zone | Quirk | Seen |
|---|---|---|
| `cimb.com.my` | `drops-svcb` | HTTPS, SVCB and unknown types dropped; SERVFAIL after 2.6 s |
| `tnb.com.my` | `drops-svcb` | the same firewall behaviour |
| `bpi.com.ph` | `drops-svcb` | the same, on Globe-hosted servers |
| `m1.com.sg` | `empty-nodata` | the parent lists only the two servers that answer HTTPS with an empty reply |
| `kemenkeu.go.id` | `selfref-nodata` | `www` answers A, and refers every other type back to itself |

### Adding your own, or switching one off

```
quirk: example.net drops-svcb
quirk: gslb.example.org empty-nodata selfref-nodata
quirk: cimb.com.my none
```

- `none` switches off a built-in entry for the same zone.
- An entry for a parent zone does not override a deeper built-in one.
- The startup log lists the configured entries.

## 🔐 DNSSEC still has the last word

A "no data" made up this way carries no proof, so it goes through the validator
like any other answer:

| zone | result |
|---|---|
| unsigned | served as insecure, without AD |
| signed | refused: a signed zone's "no data" always comes with an SOA and an NSEC or NSEC3 proving it, so the answer is SERVFAIL, as it would have been anyway |

> [!IMPORTANT]
> No quirk can make a signed zone's answer insecure. That's why
> `agrobank.com.my` isn't on the list: its servers drop HTTPS queries like
> CIMB's, but the zone is signed, so nothing here can answer for it.

## 🔍 Finding one

When a site fails for one query type and works for others, ask each of the
zone's servers directly, one type at a time:

```bash
dig +short NS example.com
dig +norec @ns1.example.com www.example.com A
dig +norec @ns1.example.com www.example.com HTTPS
dig +norec @ns1.example.com www.example.com TYPE65534
```

| you see | it is |
|---|---|
| A times out on every type | the server is down; no quirk will help |
| A works, HTTPS or `TYPE65534` times out | `drops-svcb` |
| `status: NOERROR`, no `aa` flag, nothing in any section | `empty-nodata` |
| `status: NOERROR`, no `aa` flag, only the zone's own NS records in the authority section | `selfref-nodata` |

> [!TIP]
> Check the zone is unsigned (`dig DS example.com +short` prints nothing) before
> adding an entry. Remove an entry once the zone is fixed: a quirk that's no
> longer needed only ever costs answers.

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
