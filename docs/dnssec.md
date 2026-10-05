# 🔐 DNSSEC

Validation, the algorithms implemented, and the standards followed.

## ✅ Validation

Every answer is checked back to the IANA root keys. Data that fails gets
SERVFAIL and an extended DNS error. **It is never handed to the client.**

```
   .  root key (KSK-2017 20326, KSK-2024 38696)
   │   signs
   ▼
  com.   DS ──► DNSKEY ──► RRSIG
   │   signs
   ▼
  example.com.   DS ──► DNSKEY ──► RRSIG ──► www.example.com  A  ✅
```

| | supported |
|---|---|
| **Signatures** | RSA (1024–4096), ECDSA P-256/P-384, Ed25519, **ML-DSA-44/65/87** (FIPS 204), all implemented from scratch |
| **Denial of existence** | NSEC and NSEC3, including opt-out and the RFC 9276 iteration cap |
| **On failure** | SERVFAIL with an extended error, and one log line saying [which RRset failed and why](troubleshooting.md#-a-name-answered-servfail-as-bogus) |

### Insecure is not bogus

Every RRset is judged against **the zone that actually served it**. That
matters most for records that arrive with no signature at all:

| unsigned record from | verdict |
|---|---|
| an unsigned zone (a CNAME leaving a signed zone for one, as half the CDN-hosted internet does) | insecure, served without AD |
| a zone that *is* signed | the stripping attack: refused with `RRSIGs Missing` |

<sub>The two are told apart by provenance: the resolver records which zone
produced each record as it accepts it, so the question is answered from fact
rather than inferred from whatever else shares the message.</sub>

## 🧬 Post-quantum downgrade

A zone can be signed with two algorithms at once, say ECDSA P-256 and
ML-DSA-44, while it moves from one to the other.

> [!WARNING]
> RFC 6840 has a validator accept **any one** valid path. That makes the zone
> exactly as strong as the weaker one: whoever can forge P-256 (which a quantum
> computer would) signs the DNSKEY set or an answer with it, and is believed.

So **when a zone's DS names a post-quantum algorithm Elpis implements, only
that path counts.** A post-quantum key must authenticate the DNSKEY set, and
from then on only the post-quantum keys sign for the zone. 1.1.1.1 applies the
same rule.

- A correctly signed zone isn't affected: it already has to sign every RRset
  with each algorithm in its DNSKEY set (RFC 4035 section 2.2).
- `harden-pq-downgrade: no` goes back to any valid path.

`downgrade.mldsa44.dnstest.dev`, its ML-DSA path broken and its P-256 path
intact, is SERVFAIL with `DNSSEC Bogus`, and the log says why:

```
dnssec: bogus answer for downgrade.mldsa44.dnstest.dev. A: DS says
29402/ECDSAP256SHA256/2 matches; 47303/ALG18/2 matches -- the DS of
downgrade.mldsa44.dnstest.dev. names a post-quantum algorithm, so only
post-quantum signatures count (harden-pq-downgrade) --
downgrade.mldsa44.dnstest.dev. DNSKEY, 2 records; RRSIG 47303/ALG18 by
downgrade.mldsa44.dnstest.dev.: failed the signature check; ... (EDE 6 DNSSEC
Bogus); replying SERVFAIL
```

## 🔑 Root key sentinels

RFC 8509 lets anyone ask a validating resolver whether it trusts a given root
key, by looking up a name whose first label is
`root-key-sentinel-is-ta-NNNNN` or `root-key-sentinel-not-ta-NNNNN` (a key
tag, five digits).

For a signed A or AAAA answer, with CD clear:

| label | key is a trust anchor here | key is not |
|---|---|---|
| `is-ta-NNNNN` | answered as usual | SERVFAIL |
| `not-ta-NNNNN` | SERVFAIL | answered as usual |

Both root keys are compiled in, **KSK-2017 (20326)** and **KSK-2024 (38696)**:
`not-ta-20326` and `not-ta-38696` are SERVFAIL, and `is-ta-38696` resolves.

<sub>That's how dnstest.dev's rollover check sees that Elpis trusts KSK-2024,
which signs the root from 11 October 2026. `root-key-sentinel: no` turns it
off.</sub>

## 🍪 Query authentication

- **DNS cookies (RFC 7873/9018) in both directions.** Outbound queries carry
  one, so an off-path attacker can't forge a reply. Incoming cookies are
  verified; with `require-cookie` on, a client echoing a cookie that doesn't
  check out gets BADCOOKIE and a fresh one rather than an answer.
- **Replies must match** on transaction ID, source port, the exact 0x20 casing
  of the question, and the server address.
- **Over DoT** ([authoritative-dot](configuration.md#-dns-over-tls-to-authoritative-servers)),
  the TLS session itself shuts out an off-path attacker. An answer over DoT
  still goes through every check above and through DNSSEC, and is trusted no
  more than a plain one.

## 📜 Standards

| | RFCs |
|---|---|
| Core | 1034, 1035, 2181, 2308, 3596, 3597, 4343, 5452, 6891, 7766, 9619 |
| Security | 4033–4035, 4470, 5155, 6605, 6840, 7873, 8080, 8624, 8914, 9018, 9276, 9715 |
| Behaviour | 6052, 6147, 6303, 6672, 6761, 6762, 7686, 8020, 8482, 8509, 8767, 9156, 9210, 9471, 9520 |
| Transport to authorities | 7858, 8446 (TLS 1.3), 8467, 9539 |

> [!NOTE]
> **ML-DSA numbers.** Verification follows FIPS 204, and the DNSSEC side follows
> `draft-westerbaan-dnssec-mldsa`, which gives ML-DSA-44 algorithm number 18:
> the number the public test zones sign with, and the default here. IANA hasn't
> made it final, and the draft assigns nothing to the 65 and 87 parameter sets,
> so all three are settings rather than constants. Point `mldsa44-algorithm` at
> whatever your zone publishes.
> <br><sub>The draft's worked example is in the test suite, so the key tag, the
> DS digest and a real RRSIG are checked on every build.</sub>

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
